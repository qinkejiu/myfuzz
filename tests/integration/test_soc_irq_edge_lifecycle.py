"""Item 5, real run: a composed SoC whose interrupt source is edge-shaped.

The companion plan-level module (``tests/composition/test_soc_interrupt_triggers``)
proves the converter is planned, rendered, published and audited.  This module
proves the composition still *runs*: a real Ibex executes the generated program
against a real Verilator build of the composed SoC whose novagpio interrupt is
declared ``rising_edge``, and the whole loop closes through
``soc_irq_edge_detect`` -- source event, controller pending, CLAIM, ISR, the
profile's declared clear, COMPLETE, return.

The negative case is the latch.  A converted source emits a one-cycle *pulse*,
and ``soc_irq_controller``'s pending bit follows its input level by default, so
without ``LATCH_MASK`` the event is gone long before the CPU can claim it.  The
same plan is therefore rendered a second time with ``LATCH_MASK`` cleared,
everything else identical - same program image, same stimulus, same build flags.
That run must show the peripheral latching the condition while the controller
never sees it: pending 0, no claim, no handler.

The converter's *edge direction* is deliberately not the SoC-level negative.
The generated program's own declared register accesses (its reads of the
peripheral status and its clears) produce transitions in both directions, so no
edge direction is isolable at SoC level; asserting one direction "does not fire"
here would be a false claim.  Direction semantics are pinned exactly where the
stimulus is fully controlled, in
``tests/protocols/test_soc_irq_edge_detect_rtl.py``.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_boot_program import (
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    ExternalEvent,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
)


ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
OUTPUT_ROOT = ROOT / "runs/soc-irq-edge-lifecycle"
SCRATCH = ROOT / "runs/irq-trigger-tests"

IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"

CYCLES = 20000
RAM_BASE = 0x8000_0000
RAM_SIZE = 0x1_0000
MMIO_BASE = 0x4000_0000
MMIO_LIMIT = 0x10_0000


def _patched_profile(name: str, **changes) -> str:
    document = json.loads((ROOT / GPIO_PROFILE).read_text(encoding="utf-8"))
    sources = document.get("interrupts")
    if not isinstance(sources, list) or not sources:
        raise AssertionError("the novagpio example profile declares no interrupt source")
    for key, value in changes.items():
        sources[0][key] = value
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return str(path.relative_to(ROOT))


_MEMORY_KEY = re.compile(r"^u_mem_(\d+)\[(\d+)\]$")


def _memory_words(result) -> dict[int, int]:
    """The 8-byte words the runtime read back from the RAM instance."""
    words: dict[int, int] = {}
    for name, value in result.observations.items():
        match = _MEMORY_KEY.match(name)
        if match and int(match.group(1)) == 1:
            words[int(match.group(2))] = int(value)
    return words


def read32(result, address: int, *, ram_base: int = RAM_BASE) -> int:
    """Read one 32-bit RAM word out of the runtime's hierarchical readback."""
    words = _memory_words(result)
    offset = int(address) - ram_base
    index, lane = divmod(offset, 8)
    if index not in words:
        raise AssertionError(
            "the runtime read back no RAM word %d (address 0x%08x); observations: %s"
            % (index, address, sorted(result.observations)[:12]))
    return (words[index] >> (lane * 8)) & 0xFFFF_FFFF


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real edge-interrupt lifecycle")
class SocIrqEdgeLifecycleTests(unittest.TestCase):
    """One real build per case; both cases share one generated program image."""

    @classmethod
    def setUpClass(cls) -> None:
        started = time.monotonic()
        cls.notes: list[str] = []
        cls.timings: dict[str, float] = {}
        cls.blocker: str | None = None
        cls.builds: dict[str, object] = {}
        cls.results: dict[str, object] = {}
        try:
            cls._prepare()
        except Exception as error:  # noqa: BLE001 - reported by setUp
            cls.blocker = f"{type(error).__name__}: {error}"
        cls.wall = time.monotonic() - started

    @classmethod
    def _prepare(cls) -> None:
        verilator = shutil.which("verilator")
        if verilator is None:
            raise AssertionError("Verilator is required for the real edge lifecycle")

        profile_path = _patched_profile("edge-lifecycle-rising", trigger="rising_edge")
        document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
        for item in document["memory"]:
            if item["region_id"] == "rom0":
                item["base"] = int(load_component_profile(
                    ROOT / IBEX_PROFILE).cpu.reset_vector)
        # Only the converted source is composed: with one source the controller's
        # numbering, the vector position and the generated program's claim are
        # all unambiguous, so the run's evidence is about the converter rather
        # than about which of several sources happened to be served first.
        document["peripherals"] = [{"instance_id": "gpio0", "profile": profile_path,
                                    "parameters": {}}]
        document["request_id"] = "ibex-novagpio-edge-interrupt-lifecycle"

        profiles: dict = {}
        references = [document["cpu"]["profile"]] + [item["profile"]
                                                     for item in document["peripherals"]]
        for relative in sorted(set(references)):
            profile = load_component_profile(ROOT / relative)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        request = load_composition_request(document, profiles=profiles)

        composition_started = time.monotonic()
        plan = build_composition(request, base_dir=ROOT)
        cls.timings["compose_s"] = time.monotonic() - composition_started
        cls.plan = plan

        sources = list(plan.interrupt_document["sources"])
        if len(sources) != 1 or sources[0]["instance_id"] != "gpio0":
            raise AssertionError("expected exactly the gpio0 source, got %r" % sources)
        cls.source = sources[0]
        normalizer = cls.source["normalizer"]
        if normalizer.get("kind") != "edge_detect":
            raise AssertionError("the declared rising edge produced no converter: %r"
                                 % (normalizer,))
        if int(normalizer["edge_parameter"]) != 0:
            raise AssertionError("the rising-edge converter is not EDGE=0: %r" % (normalizer,))

        render_started = time.monotonic()
        cls.top_text = render_composition(plan)["myfuzz_soc_top.sv"]
        records = source_list(plan)
        cls.sources = [item["path"] for item in records if item["role"] != "include_root"]
        cls.include_roots = sorted({item["path"] for item in records
                                    if item["role"] == "include_root"})
        cls.timings["render_s"] = time.monotonic() - render_started

        if ".EDGE(0), .PULSE_CYCLES(1), .RESET_LEVEL(0)) u_irq_src_1" not in cls.top_text:
            raise AssertionError("the rendered top has no rising-edge converter:\n"
                                 + "\n".join(line for line in cls.top_text.splitlines()
                                             if "soc_irq_edge_detect" in line
                                             or ".EDGE(" in line))
        if ".LATCH_MASK(1'b1)" not in cls.top_text:
            raise AssertionError("the converted source was rendered unlatched; a "
                                 "one-cycle pulse would be dropped")
        # The mutated top is the negative case: same plan, same program, same
        # stimulus, same build flags, only the latch is removed.
        cls.mutated_top = cls.top_text.replace(".LATCH_MASK(1'b1)",
                                               ".LATCH_MASK(1'b0)", 1)
        if cls.mutated_top == cls.top_text:
            raise AssertionError("the latch mutation changed nothing")

        program = build_boot_program(plan)
        cls.program = program
        cls.layout = {str(item["name"]): int(item["offset"])
                      for item in program.document["report"]["layout"]}
        cls.trigger = dict(program.document["trigger"])
        cls.positive = program
        cls.negative = build_boot_program(plan, request=ProgramRequest(enable_interrupts=False))
        cls.mask = 1 << (int(cls.source["source_id"]) % 32)
        cls.pending_bit = 1 << int(cls.source["source_id"])

        images = OUTPUT_ROOT / "images"
        if images.exists():
            shutil.rmtree(images)
        images.mkdir(parents=True, exist_ok=True)
        image = images / "boot_program.hex"
        image.write_text(image_hex(program.image), encoding="utf-8")

        tool = verilator
        flags = [f"-I{ROOT / item}" for item in cls.include_roots]
        for instance in plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        if flags:
            wrapper = images / "verilator_with_profile_flags.sh"
            wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n"
                               % (verilator, " ".join(flags)), encoding="utf-8")
            wrapper.chmod(0o755)
            tool = wrapper.as_posix()
            cls.notes.append("the build used the plan's declared include roots/defines")

        for label, text in (("latched", cls.top_text), ("unlatched", cls.mutated_top)):
            started = time.monotonic()
            cls.builds[label] = cls._build_runtime(label, text, image, tool)
            cls.timings[f"build_{label}_s"] = time.monotonic() - started

        cls.results["latched"] = cls._run("latched", cls.builds["latched"], program, 0xE1)
        cls.results["unlatched"] = cls._run("unlatched", cls.builds["unlatched"], program, 0xE2)

    @classmethod
    def _build_runtime(cls, label: str, top_text: str, image: Path, tool: str):
        output = OUTPUT_ROOT / label
        last: Exception | None = None
        for attempt in (1, 2):
            if output.exists():
                shutil.rmtree(output)
            try:
                return build_profile_runtime(cls.plan, output_dir=output, base_dir=ROOT,
                                             top_text=top_text, sources=cls.sources,
                                             boot_image=image, verilator=tool)
            except SocRuntimeError as error:
                last = error
                print("MYFUZZ_SOC_EDGE_NOTE build %s attempt %d failed: %s"
                      % (label, attempt, str(error)[:300]))
                if "runtime-build-failed" not in str(error):
                    raise
        raise last

    @classmethod
    def _run(cls, label: str, build, program, request_id: int):
        trigger = dict(program.document["trigger"])
        events = tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                     value=int(item["value"]))
                       for item in trigger["events"])
        sample = RuntimeSample(request_id=request_id, raw=(0,) * CYCLES, events=events)
        started = time.monotonic()
        result = run_sample(build, sample)
        print("MYFUZZ_SOC_EDGE_RUN case=%s status=%s cycles=%d wall_s=%.2f reason=%s"
              % (label, result.status, result.cycles, time.monotonic() - started, result.reason))
        return result

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail("the edge-interrupt lifecycle could not be prepared: %s" % self.blocker)

    # -- helpers -----------------------------------------------------------

    def report(self, result, name: str) -> int:
        return read32(result, self.program.report_address + self.layout[name])

    def promised(self, result, name: str) -> int:
        """The value the generated program promised for one observation."""
        self.assertIn(name, self.program.observations,
                      "the program promises no %s observation" % name)
        return int(self.program.observations[name])

    def controller_base(self) -> int:
        return int(self.plan.interrupt_document["controller"]["window"]["base"])

    # -- the checks --------------------------------------------------------

    def test_the_composition_declares_the_converter_it_runs(self) -> None:
        self.assertEqual("rising_edge", self.source["trigger"])
        self.assertEqual("edge_detect", self.source["normalizer"]["kind"])
        self.assertEqual("one-event-per-edge", self.source["normalizer"]["capture"])
        self.assertIn("src/myfuzz/protocols/rtl/soc_irq_edge_detect.sv", self.sources)
        self.assertEqual(["rising_edge"],
                         self.plan.interrupt_document["trigger_support"]["edge_detected"])

    def test_the_positive_run_closes_the_loop_through_the_converter(self) -> None:
        result = self.results["latched"]
        self.assertEqual("OK", result.status, result.reason)
        self.assertEqual(self.promised(result, "completion_flag"),
                         read32(result, self.program.flag_address),
                         "the generated program did not report completion")
        promised_claim = self.promised(result, "claim_id")
        self.assertEqual(int(self.source["source_id"]), promised_claim,
                         "the generated program did not promise the converted source's id")
        self.assertEqual(promised_claim, self.report(result, "claim_id"),
                         "CLAIM did not return the converted source's id")
        self.assertGreaterEqual(self.report(result, "handler_entries"), 1,
                                "the ISR never ran for the converted source")
        # Bitmap bit k is source id k and bit 0 is reserved, so a source's own
        # pending bit is exactly its source id (soc_irq_controller.sv).
        self.assertEqual(self.pending_bit,
                         self.report(result, "pending_word_0_before_claim")
                         & self.pending_bit,
                         "the converted source was never pending")
        self.assertEqual(self.promised(result, "cause_after_clear"),
                         self.report(result, "cause_after_clear"),
                         "the declared clear did not clear the converted source")
        self.assertEqual(1, self.report(result, "complete_accepted"),
                         "the controller did not accept COMPLETE")
        self.assertEqual(0, self.report(result, "final_in_service"),
                         "a source was left in service")

    def test_removing_the_latch_drops_the_converted_event(self) -> None:
        """The latch is load-bearing, not decorative.

        Both builds run the same program and the same stimulus.  The only
        difference is that the second build's controller follows the source
        level instead of latching it, so the one-cycle pulse from
        ``soc_irq_edge_detect`` is gone before the CPU can claim it.  The
        peripheral still latches the condition, which is what makes this a
        statement about the interrupt path and not about the stimulus.
        """
        result = self.results["unlatched"]
        self.assertEqual("OK", result.status, result.reason)
        self.assertEqual(1, self.report(result, "status_latched_by_poll"),
                         "the peripheral did not latch the condition in the negative run")
        self.assertEqual(0, self.report(result, "pending_word_0_before_claim")
                         & self.pending_bit,
                         "the controller pended an event the converter never held")
        self.assertEqual(0, self.report(result, "claim_id"),
                         "an unlatched one-cycle pulse was somehow claimed")
        self.assertEqual(0, self.report(result, "handler_entries"),
                         "the ISR ran for an event the pulse carried away")
        self.assertEqual(0, self.report(result, "loop_closed"),
                         "the unlatched build reported a closed interrupt loop")
        # The run still finished: the CPU ran its program to the end and only the
        # interrupt never arrived, so the mutation is visible as a missing event
        # rather than as a hang or a crash.
        self.assertGreater(result.cycles, 0)
        self.assertEqual(1, self.report(result, "main_completed"),
                         "the program did not run to completion in the negative run")

    def test_both_builds_are_distinct_artifacts_of_the_same_plan(self) -> None:
        """The negative is a real second build, not a re-run of the first."""
        latched = self.builds["latched"]
        unlatched = self.builds["unlatched"]
        self.assertNotEqual(latched.executable, unlatched.executable)
        self.assertNotEqual(latched.build_hash, unlatched.build_hash,
                            "the two tops compiled to the same build hash")
        self.assertEqual(latched.boot_image, unlatched.boot_image)
        self.assertEqual(latched.raw_width, unlatched.raw_width)

    @classmethod
    def tearDownClass(cls) -> None:
        print("\nMYFUZZ_SOC_EDGE_TIMING %s wall_s=%.1f"
              % (" ".join("%s=%.1f" % item for item in sorted(cls.timings.items())), cls.wall))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
