"""Step 8 integration: the real interrupt lifecycle on a composed SoC.

The plan's step 8 asks for evidence that a real CPU boots, a real peripheral
becomes pending, a real generic controller notifies, the CPU itself claims the
source over MMIO, clears the peripheral condition through the profile's declared
operation, completes the claim and returns, and that the whole loop leaves the
RAM record the program promised.

This module builds exactly that composition (Ibex + novagpio, using
``examples/soc_generation/request-ibex.json`` when it exists and otherwise
composing one from ``configs/cpus/ibex/component_profile.json`` plus
``examples/soc_generation/profiles/novagpio.json``), renders the top, generates
the boot program, writes it as a ``$readmemh`` image, builds the profile runtime
with ``soc_runtime.build_profile_runtime`` and runs samples.

The tests are opt-in through ``MYFUZZ_SOC_REAL=1``.  When the flag is set
nothing skips: an unavailable or broken Ibex profile, a missing Verilator, a
render or build failure is a *failure* naming that exact reason (the class
records it as a blocker and every test fails with it), never a silent pass.

Two runs are compared, and they differ only in the request the program is
generated from:

* positive - the full program: peripheral enable, controller ENABLE, mie/mstatus
  and the handler; the loop must close.
* negative - ``ProgramRequest(enable_interrupts=False)``: the controller's
  ENABLE keeps its reset value 0 while the handler, mtvec, peripheral setup and
  trigger are unchanged.  The source is sampled and pends, the CPU still sees
  both the peripheral condition and the controller's pending bit, but no claim
  may happen -- which is what shows the claim comes from the real notification
  path and not from the program's own bookkeeping.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_boot_program import (
    COMPLETION_FLAG,
    REPORT_FIELDS,
    ProgramRequest,
    build_boot_program,
    image_hex,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    MAX_OBSERVED_WORDS,
    ExternalEvent,
    PeerStimulusEvent,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
)

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
OUTPUT_ROOT = ROOT / "runs/soc-interrupt-lifecycle"
IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"

#: One sample: the trigger is scheduled at cycles 2048/3072 by the generated
#: program, so the run has to outlast it by a comfortable margin.  The runtime
#: refuses samples longer than MAX_CYCLES (65536).
CYCLES = 20000
RAM_BASE = 0x8000_0000
RAM_SIZE = 0x1_0000
MMIO_BASE = 0x4000_0000
MMIO_LIMIT = 0x10_0000

_MEMORY_KEY = re.compile(r"^u_mem_(\d+)\[(\d+)\]$")


def _controller_register_name(plan, offset: int) -> str:
    """The plan's register name for one window-local controller offset."""
    for register in plan.interrupt_document["controller"]["register_map"]:
        if int(register["offset"]) == offset:
            return str(register["name"])
    return "unknown offset"


def _memory_words(result) -> dict[int, int]:
    """The 8-byte words the runtime read back from each memory instance."""
    words: dict[int, int] = {}
    for name, value in result.observations.items():
        match = _MEMORY_KEY.match(name)
        if match:
            words[int(match.group(2))] = int(value)
    return words


def read32(result, address: int, *, ram_base: int = RAM_BASE) -> int:
    """Read one 32-bit RAM word out of the runtime's hierarchical readback."""
    words = _memory_words(result)
    offset = address - ram_base
    index, lane = divmod(offset, 8)
    if index not in words:
        raise AssertionError(
            "the runtime read back no word %d (address 0x%08x); observations: %s"
            % (index, address, sorted(result.observations)))
    return (words[index] >> (lane * 8)) & 0xFFFF_FFFF


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real interrupt lifecycle")
class SocInterruptLifecycleTests(unittest.TestCase):
    """The real closed loop, plus the negative that isolates the notification."""

    blocker: str | None = None
    plan = None
    positive = None
    negative = None
    build = None
    negative_image = None
    timings: dict = {}
    notes: list = []
    #: Subclasses use the same preparation path for a second topology while
    #: selecting a different generated-program request.
    positive_request = ProgramRequest()
    negative_request = ProgramRequest(enable_interrupts=False)

    # -- preparation -------------------------------------------------------

    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        try:
            cls._prepare()
        except Exception as error:                # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        for relative in (IBEX_PROFILE, GPIO_PROFILE):
            path = ROOT / relative
            if not path.is_file():
                raise AssertionError(f"missing composition input {relative}")
        verilator = shutil.which("verilator")
        if verilator is None:
            raise AssertionError("Verilator is required for the real interrupt lifecycle")

        document = cls._request_document(None)
        profiles: dict = {}
        references = [document["cpu"]["profile"]] + [item["profile"]
                                                     for item in document["peripherals"]]
        for relative in sorted(set(references) | {IBEX_PROFILE, GPIO_PROFILE}):
            path = ROOT / relative
            if not path.is_file():
                raise AssertionError(f"missing component profile {relative}")
            profile = load_component_profile(path)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        cpu_profile = profiles[document["cpu"]["profile"]]
        if cpu_profile.cpu is None:
            raise AssertionError(f"{IBEX_PROFILE}: no cpu contract")
        reset_vector = int(cpu_profile.cpu.reset_vector)

        document = cls._request_document(reset_vector)
        request = load_composition_request(document, profiles=profiles)
        cls.request_document = document
        started = time.monotonic()
        cls.plan = build_composition(request, base_dir=ROOT)
        cls.timings["compose_s"] = time.monotonic() - started

        controller = cls.plan.interrupt_document["controller"]
        if not controller.get("present"):
            raise AssertionError("the composed plan instantiates no interrupt controller")
        sources = list(cls.plan.interrupt_document["sources"])
        if not sources:
            raise AssertionError("the composed plan declares no interrupt source")
        cls.source = sources[0]
        if cls.source["instance_id"] != "gpio0":
            raise AssertionError(
                "expected the novagpio source to be the one exercised, got %s"
                % cls.source["instance_id"])

        started = time.monotonic()
        files = render_composition(cls.plan)
        cls.top_text = files["myfuzz_soc_top.sv"]
        records = source_list(cls.plan)
        cls.sources = [item["path"] for item in records if item["role"] != "include_root"]
        cls.include_roots = sorted({item["path"] for item in records
                                    if item["role"] == "include_root"})
        cls.timings["render_s"] = time.monotonic() - started

        cls.positive = build_boot_program(cls.plan, request=cls.positive_request)
        cls.negative = build_boot_program(cls.plan, request=cls.negative_request)

        # The runtime refuses a non-empty output directory, so the images live
        # beside the build directory rather than inside it.
        output = OUTPUT_ROOT / cls.plan.plan_hash.split(":", 1)[1][:16]
        images = OUTPUT_ROOT / (output.name + "-images")
        for directory in (output, images):
            if directory.exists():
                shutil.rmtree(directory)
        images.mkdir(parents=True, exist_ok=True)
        image = images / "boot_program.hex"
        image.write_text(image_hex(cls.positive.image), encoding="utf-8")
        cls.negative_image = images / "boot_program_no_enable.hex"
        cls.negative_image.write_text(image_hex(cls.negative.image), encoding="utf-8")

        # soc_runtime.build_profile_runtime does not pass the profile's declared
        # include roots or defines to Verilator, and a CPU closure with
        # cross-directory `include directives cannot be compiled without them.
        # The runtime accepts the tool path, so the declared flags are supplied
        # through a tiny wrapper instead of editing the runtime or the DUT.
        tool = verilator
        flags = [f"-I{ROOT / item}" for item in cls.include_roots]
        for instance in cls.plan.instances:
            elaboration = getattr(instance.profile.source, "elaboration", None)
            for name, value in getattr(elaboration, "defines", ()) or ():
                flags.append(f"-D{name}={value}")
        if flags:
            wrapper = images / "verilator_with_profile_flags.sh"
            wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n"
                               % (verilator, " ".join(flags)), encoding="utf-8")
            wrapper.chmod(0o755)
            tool = wrapper.as_posix()
            cls.notes.append(
                "the build used a wrapper adding the plan's declared include roots/defines "
                "(%s); build_profile_runtime has no flag for them" % " ".join(flags))

        started = time.monotonic()
        cls.build = cls._build_runtime(output, image, tool)
        cls.timings["build_s"] = time.monotonic() - started

        # The controller numbers bitmap bit k as source id 32*j+k with bit 0
        # reserved, so a source's own bit is id % 32 (soc_irq_controller.sv 4-5).
        cls.mask = 1 << (int(cls.source["source_id"]) % 32)
        cls.observations_layout = dict(REPORT_FIELDS)

    @classmethod
    def _build_runtime(cls, output: Path, image: Path, tool: str):
        """Compile the composed SoC, retrying once on a transient tool failure.

        The runtime refuses a non-empty output directory, so every attempt
        starts from a fresh one.  A genuine RTL or compile error fails both times
        and is still reported with its (runtime-truncated) diagnostics; the retry
        exists because a concurrent heavy build on the same host can kill the
        C++ stage, which says nothing about this composition.
        """
        last: Exception | None = None
        for attempt in (1, 2):
            if output.exists():
                shutil.rmtree(output)
            try:
                return build_profile_runtime(cls.plan, output_dir=output, base_dir=ROOT,
                                             top_text=cls.top_text, sources=cls.sources,
                                             boot_image=image, verilator=tool)
            except SocRuntimeError as error:
                last = error
                print("MYFUZZ_SOC_INTERRUPT_NOTE build attempt %d failed: %s"
                      % (attempt, str(error)[:300]))
                if "runtime-build-failed" not in str(error):
                    raise
        raise last

    @staticmethod
    def _request_document(reset_vector: int | None) -> dict:
        """The Ibex + novagpio request, or the checked-in one when present.

        The ROM region is anchored at the CPU profile's own reset vector so the
        declared entry is the first byte of the region, exactly as the memory
        model loads an image.  ``reset_vector`` is ``None`` for the first pass,
        which only reads the request to discover the profile paths.
        """
        path = ROOT / REQUEST_FILE
        if path.is_file():
            document = json.loads(path.read_text(encoding="utf-8"))
            if reset_vector is not None:
                for region in document["memory"]:
                    if region["region_id"] == "rom0":
                        region["base"] = reset_vector
            document["peripherals"] = [
                item for item in document["peripherals"]
                if item["profile"] == GPIO_PROFILE or item["instance_id"] != "gpio0"]
            if not any(item["instance_id"] == "gpio0"
                       for item in document["peripherals"]):
                document["peripherals"].append(
                    {"instance_id": "gpio0", "profile": GPIO_PROFILE, "parameters": {}})
            if reset_vector is None:
                return document
            document["request_id"] = "ibex-novagpio-interrupt-lifecycle"
            return document
        if reset_vector is None:
            return {"cpu": {"profile": IBEX_PROFILE},
                    "peripherals": [{"profile": GPIO_PROFILE}]}
        return {
            "schema_version": "composition_request.v1",
            "request_id": "ibex-novagpio-interrupt-lifecycle",
            "cpu": {"instance_id": "cpu0", "profile": IBEX_PROFILE, "parameters": {}},
            "peripherals": [{"instance_id": "gpio0", "profile": GPIO_PROFILE,
                             "parameters": {}}],
            "memory": [
                {"region_id": "rom0", "base": reset_vector, "size": 0x8000,
                 "permissions": {"read": True, "write": False, "execute": True},
                 "physical_memory_id": "boot_rom", "initialization_policy": "rom"},
                {"region_id": "ram0", "base": RAM_BASE, "size": RAM_SIZE,
                 "permissions": {"read": True, "write": True, "execute": True},
                 "physical_memory_id": "main_ram", "initialization_policy": "on_demand"},
            ],
            "address_policy": {"mmio_base": MMIO_BASE, "mmio_limit": MMIO_LIMIT,
                               "alignment": 4096},
            "clock": {"domain": "core", "frequency_hz": 50_000_000},
            "reset": {"domain": "sys_rst", "polarity": "active_low", "synchronous": True},
            "test_modes": ["cpu_only"],
            "provenance": {"author": "tests/integration/test_soc_interrupt_lifecycle.py",
                           "purpose": "step 8 real interrupt lifecycle"},
        }

    @classmethod
    def _peripheral_base(cls, instance_id: str) -> int:
        for record in cls.plan.target_records:
            if record.get("instance_id") == instance_id:
                return int(record["window"]["base"])
        raise AssertionError(f"the plan has no MMIO window for {instance_id}")

    @classmethod
    def tearDownClass(cls):
        total = time.monotonic() - cls.started
        if cls.blocker is None:
            print("\nMYFUZZ_SOC_INTERRUPT_TIMING compose_s=%.1f render_s=%.1f build_s=%.1f "
                  "wall_s=%.1f" % (cls.timings.get("compose_s", 0.0),
                                   cls.timings.get("render_s", 0.0),
                                   cls.timings.get("build_s", 0.0), total))
        else:
            print("\nMYFUZZ_SOC_INTERRUPT_BLOCKED %s" % cls.blocker)

    def setUp(self):
        if self.blocker is not None:
            self.fail("the interrupt lifecycle could not be prepared: %s" % self.blocker)

    # -- running -----------------------------------------------------------

    def sample(self, program, request_id: int) -> RuntimeSample:
        trigger = program.document["trigger"]
        events = tuple(ExternalEvent(slot=int(item["slot"]), cycle=int(item["cycle"]),
                                     value=int(item["value"]))
                       for item in trigger["events"])
        peer_events = tuple(PeerStimulusEvent(slot=int(item["slot"]),
                                              cycle=int(item["cycle"]),
                                              payload=int(item["payload"]))
                            for item in trigger.get("peer_events", ()))
        self.assertTrue(events or peer_events,
                        "the program declares no external or peer trigger events")
        slot_names = [item["name"] for item in self.runtime_transfer_slots()]
        for item in trigger["events"]:
            self.assertEqual(slot_names[int(item["slot"])], item["name"],
                             "the trigger slot index is not the runtime's own slot")
        return RuntimeSample(request_id=request_id, raw=(0,) * CYCLES,
                             events=events, peer_events=peer_events)

    def runtime_transfer_slots(self) -> list:
        """The runtime's external input slots, in the order it applies them."""
        records: list[dict] = []
        for instance in self.plan.instances:
            for entry in instance.dispositions:
                if entry.disposition != "external" or entry.direction != "input":
                    continue
                span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
                    f"_{entry.bit_hi}_{entry.bit_lo}"
                records.append({"name": f"{entry.instance_id}__{entry.port}{span}"})
        records.sort(key=lambda item: item["name"])
        return records

    def run_program(self, program, *, case: str, request_id: int, build=None):
        started = time.monotonic()
        result = run_sample(build or self.build, self.sample(program, request_id))
        elapsed = time.monotonic() - started
        self.timings.setdefault("runs", []).append(
            {"case": case, "wall_s": elapsed, "status": result.status})
        print("MYFUZZ_SOC_INTERRUPT_RUN case=%s status=%s cycles=%d wall_s=%.2f reason=%s"
              % (case, result.status, result.cycles, elapsed, result.reason))
        for name, value in sorted(result.observations.items()):
            print("MYFUZZ_SOC_INTERRUPT_OBS case=%s %s=%d" % (case, name, value))
        for name, offset in sorted(self.observations_layout.items(), key=lambda item: item[1]):
            address = program.report_address + offset
            try:
                value = read32(result, address)
            except AssertionError:
                continue
            print("MYFUZZ_SOC_INTERRUPT_REPORT case=%s %s=0x%08x (%d)"
                  % (case, name, value, value))
        self.assertEqual("OK", result.status,
                         "%s: the run must complete, not %s (%s)"
                         % (case, result.status, result.reason))
        self.assertTrue(result.cycles > 0, "%s: no cycle was executed" % case)
        return result

    def assert_promises(self, program, result, *, case: str) -> None:
        """Every value the program promised is in RAM where it promised it."""
        missing = []
        for name, value in program.observations.items():
            if name == "completion_flag":
                address = program.flag_address
            else:
                address = program.report_address + self.observations_layout[name]
            actual = read32(result, address)
            if actual != value:
                missing.append("%s: 0x%08x promised %d, read %d" % (name, address, value, actual))
        if missing:
            self.fail("%s: the program did not record what it promises:\n  %s\n%s"
                      % (case, "\n  ".join(missing), self.cpu_fault(result)))

    def cpu_fault(self, result) -> str:
        """What the CPU's own crash dump says about a run that did not close.

        The pinned Ibex publishes ``crash_dump_o`` = {current_pc, next_pc,
        last_data_addr, exception_pc (mepc), exception_addr (mtval)}.  Two
        failures this test must name precisely, because both are outside the
        program that is being tested:

        * an access to the interrupt controller's window answered with an error:
          the controller decodes a window-local offset
          (``soc_irq_controller.sv``, ``word_index = req_addr_i[...:2]``) while
          the profile renderer feeds it the global router address
          (``soc_profile_renderer.py``, ``.req_addr_i(t_addr[target])``);
        * a machine-mode CSR instruction refused with an illegal instruction,
          which is what happens when the CPU's asynchronous-reset CSR file never
          sees a reset edge: the runtime's generated testbench initialises
          ``rst_ni`` to 0 and only raises it
          (``soc_runtime.render_profile_testbench``), while the matrix testbench
          asserts a real pulse (``soc_matrix_smoke.py`` line 1575 and 1901).

        Returns "" when the crash dump shows no fault at all.
        """
        raw = result.observations.get("cpu0__crash_dump_o")
        if raw is None:
            return ""
        fields = [(raw >> (32 * (4 - index))) & 0xFFFF_FFFF for index in range(5)]
        names = ("current_pc", "next_pc", "last_data_addr", "exception_pc(mepc)",
                 "exception_addr(mtval)")
        mepc = fields[names.index("exception_pc(mepc)")]
        mtval = fields[names.index("exception_addr(mtval)")]
        recorded = read32(result, self.positive.report_address
                          + self.observations_layout["error_cause"])
        # The generated handler records every exception it takes in error_cause.
        # An interrupt is not a fault: for an interrupt the CPU leaves mtval
        # untouched (0 here) and does not advance mepc, so a trap is only
        # reported when the program itself recorded an exception cause, or when
        # a fault happened before the handler was installed (non-zero mtval).
        if recorded == 0 and (mepc == 0 or mtval == 0):
            return ""
        text = ["  CPU crash dump: " + ", ".join("%s=0x%08x" % (name, value)
                                                for name, value in zip(names, fields))]
        word = self.program_word(self.positive, mepc)
        if word is not None and word == mtval:
            text.append(
                "  the CPU refused the instruction at 0x%08x (word 0x%08x) with an illegal "
                "instruction: that is a machine-mode CSR/system instruction executed while "
                "the CPU is not in machine mode.  The core's privilege and CSR state only "
                "takes its reset value when the reset input sees a real 1->0 edge; %s"
                % (mepc, mtval, self.reset_edge_note()))
            return "\n".join(text)
        controller = self.plan.interrupt_document["controller"]["window"]
        base = int(controller["base"])
        for label in ("last_data_addr", "exception_addr(mtval)"):
            value = fields[names.index(label)]
            if base <= value < base + int(controller["size"]):
                text.append(
                    "  the faulting address 0x%08x is inside the interrupt controller "
                    "window 0x%08x..0x%08x (offset 0x%x, register %s): the controller was "
                    "answered with an error by the generated SoC, so the CPU never "
                    "reaches CLAIM/COMPLETE; the controller's register decode expects a "
                    "window-local offset while the fabric forwards the global address"
                    % (value, base, base + int(controller["size"]), value - base,
                       _controller_register_name(self.plan, value - base)))
                break
        return "\n".join(text)

    @staticmethod
    def program_word(program, address: int):
        """The program word at an absolute address, from the generated image."""
        rom_base = int(program.document["entry"]["rom_base"])
        offset = address - rom_base
        if offset < 0 or offset + 4 > len(program.image):
            return None
        return int.from_bytes(program.image[offset:offset + 4], "little")

    def reset_edge_note(self) -> str:
        """Whether the generated testbench gives the DUT a real reset pulse."""
        if self.build is None:
            return "the testbench could not be built"
        text = Path(self.build.testbench_path).read_text(encoding="utf-8")
        if re.search(r"logic rst_ni = 1'b1", text):
            return "this testbench does initialise rst_ni to 1 and assert it"
        return ("the generated testbench declares 'logic rst_ni = 1'b0;' and only raises "
                "it, so the DUT never sees that edge (the matrix testbench does assert a "
                "real pulse: soc_matrix_smoke.py line 1575 and 1901)")

    # -- the tests ---------------------------------------------------------

    def test_the_positive_run_closes_the_whole_interrupt_loop(self) -> None:
        program = self.positive
        result = self.run_program(program, case="positive", request_id=1)
        # Root-cause check first: the CPU must execute mtvec/mie/mstatus and the
        # MMIO accesses without taking any trap.  A fault here names the exact
        # DUT-side reason instead of only the missing observations.
        fault = self.cpu_fault(result)
        self.assertEqual("", fault,
                         "positive: the CPU faulted before the loop could close:\n%s" % fault)
        self.assert_promises(program, result, case="positive")

        flag = read32(result, program.flag_address)
        report = program.report_address
        layout = self.observations_layout
        claim_id = read32(result, report + layout["claim_id"])
        handler_entries = read32(result, report + layout["handler_entries"])
        pending = read32(result, report + layout["pending_before_claim"])
        cause_before = read32(result, report + layout["cause_before_clear"])
        cause_after = read32(result, report + layout["cause_after_clear"])
        complete = read32(result, report + layout["complete_accepted"])
        in_service = read32(result, report + layout["final_in_service"])
        prologue = read32(result, report + layout["prologue_cycle"])
        loop_closed = read32(result, report + layout["loop_closed"])

        # 1. the CPU executed: it stamped its own cycle counter and wrote RAM.
        self.assertGreater(prologue, 0, "mcycle stamp: the CPU executed the program")
        self.assertEqual(COMPLETION_FLAG, flag, "the completion flag is in RAM")
        self.assertEqual(1, loop_closed, "the ISR closed the loop")

        # 2. the peripheral's interrupt became pending: the ISR read the
        #    peripheral's own status register and its declared cause bit was set.
        self.assertNotEqual(0, cause_before,
                            "the peripheral condition was latched before the clear")
        # 3. the controller notified and sampled that source as pending before
        #    the claim (the CPU read the controller's PENDING word itself).
        self.assertEqual(self.mask, pending,
                         "the controller's pending bit for source %s"
                         % self.source["source_id"])
        self.assertGreaterEqual(handler_entries, 1,
                                "the CPU took the controller's notification (ISR entry)")

        # 4. the CPU claimed a source id from the plan's own source table.
        plan_ids = [int(item["source_id"]) for item in
                    self.plan.interrupt_document["sources"]]
        self.assertIn(claim_id, plan_ids,
                      "claimed id %d is not one of the plan's source ids %s"
                      % (claim_id, plan_ids))
        self.assertEqual(int(self.source["source_id"]), claim_id)
        self.assertEqual(0, read32(result, report + layout["unknown_claim"]),
                         "the claimed id was identified through the plan")

        # 5. the ISR cleared the peripheral condition through the profile's
        #    declared clear operation: the cause bit reads back zero.
        self.assertEqual(0, cause_after,
                         "the declared clear operation emptied the peripheral condition")
        self.assertEqual(0, read32(result, report + layout["status_raw_after_clear"]),
                         "the peripheral status register reads zero after the clear")

        # 6. COMPLETE was accepted: the controller left service for that id.
        self.assertEqual(1, complete, "COMPLETE was accepted for the claimed id")
        self.assertEqual(0, in_service, "the controller has no source in service")

    def test_the_negative_run_without_controller_enable_never_claims(self) -> None:
        program = self.negative
        build = replace(self.build, boot_image=self.negative_image.resolve())
        result = self.run_program(program, case="negative", request_id=2, build=build)
        self.assert_promises(program, result, case="negative")

        report = program.report_address
        layout = self.observations_layout
        claim_id = read32(result, report + layout["claim_id"])
        handler_entries = read32(result, report + layout["handler_entries"])
        loop_closed = read32(result, report + layout["loop_closed"])
        in_service = read32(result, report + layout["final_in_service"])
        main_completed = read32(result, report + layout["main_completed"])
        flag = read32(result, program.flag_address)
        latched = read32(result, report + layout["status_latched_by_poll"])
        pending = read32(result, report + layout["pending_seen_by_main"])

        # The CPU really executed the same program...
        self.assertEqual(1, main_completed, "the CPU executed the main flow")
        self.assertEqual(COMPLETION_FLAG, flag, "the CPU wrote the completion flag")
        # ... the peripheral really latched the same event ...
        self.assertNotEqual(0, latched,
                            "the peripheral condition became set in this run too")
        # ... and the controller really sampled it as pending ...
        self.assertEqual(self.mask, pending,
                         "the controller's pending bit was set while ENABLE kept its "
                         "reset value")
        # ... yet with ENABLE at its reset value nothing was claimed or completed.
        self.assertEqual(0, claim_id, "no source may be claimed without enable")
        self.assertEqual(0, handler_entries, "the handler must never be entered")
        self.assertEqual(0, loop_closed, "no loop may close without enable")
        self.assertEqual(0, in_service, "nothing is left in service")

    def test_the_unmapped_access_scenario_records_a_fabric_error(self) -> None:
        """Requirement 8: the error path has a scenario, not just a claim.

        The program performs one load from an address no declared window decodes;
        the fabric must answer with an error, the CPU must take a load access
        fault, the generated handler must record the cause and skip the
        instruction, and the interrupt loop must still close afterwards.
        """
        program = build_boot_program(self.plan,
                                     request=ProgramRequest(expect_error_access=True))
        scenario = program.document["error_scenario"]
        self.assertIsNotNone(scenario)
        image = self.negative_image.parent / "boot_program_error_access.hex"
        image.write_text(image_hex(program.image), encoding="utf-8")
        build = replace(self.build, boot_image=image.resolve())
        result = self.run_program(program, case="error-access", request_id=3, build=build)
        layout = self.observations_layout
        report = program.report_address
        self.assertEqual(1, read32(result, report + layout["error_access_requested"]),
                         "the program recorded that it performed the access")
        self.assertEqual(5, read32(result, report + layout["error_cause"]),
                         "mcause 5 = load access fault, recorded by the generated handler")
        self.assertEqual(COMPLETION_FLAG, read32(result, program.flag_address),
                         "the handler skipped the faulting instruction and the program ran on")
        self.assert_promises(program, result, case="error-access")
        self.assertEqual(1, read32(result, report + layout["loop_closed"]),
                         "the interrupt loop still closed in this run")

    def test_the_composition_and_program_are_what_the_plan_declares(self) -> None:
        document = self.positive.document
        self.assertEqual(self.plan.plan_hash, document["plan_hash"])
        controller = self.plan.interrupt_document["controller"]
        self.assertEqual(controller["window"]["base"],
                         document["controller"]["base"])
        self.assertEqual(controller["register_map"][0]["offset"],
                         document["controller"]["registers_used"]["CLAIM"])
        enabled = [item for item in document["sources"]
                   if item["controller_enable"]["enabled"]]
        self.assertEqual(1, len(enabled),
                         "the program enables exactly the one source it triggers, so the "
                         "claimed id cannot depend on another source's activity")
        self.assertEqual(int(self.source["source_id"]), int(enabled[0]["source_id"]))
        self.assertEqual(int(self.source["source_id"]),
                         int(self.positive.observations["claim_id"]))
        trigger = document["trigger"]
        self.assertEqual("external_event_plan", trigger["kind"])
        self.assertEqual([], trigger["mmio_writes"])
        for pin in trigger["pins"]:
            self.assertTrue(pin.startswith("gpio0__"),
                            "the trigger drives the source component's own declared pins")
        trigger_cycles = [int(item["cycle"]) for item in trigger["events"]]
        self.assertLess(max(trigger_cycles), CYCLES,
                        "the trigger must happen inside the sample window")
        self.assertGreaterEqual(MAX_OBSERVED_WORDS * 8,
                                document["memory"]["report_address"]
                                - document["memory"]["ram_base"]
                                + document["memory"]["report_bytes"],
                                "the report record must be inside the runtime readback")
        if self.notes:
            print("MYFUZZ_SOC_INTERRUPT_NOTE %s" % "; ".join(self.notes))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real interrupt lifecycle")
class SocInterruptMultiSourceLifecycleTests(SocInterruptLifecycleTests):
    """The same real CPU path with two independent GPIO sources.

    This deliberately reuses the base preparation and evidence checks.  Only
    the request document and the generated-program mode change, which keeps the
    comparison focused on the generic controller's multi-source service rather
    than on a second harness implementation.
    """

    positive_request = ProgramRequest(exercise_all_sources=True)
    negative_request = ProgramRequest(exercise_all_sources=True,
                                      enable_interrupts=False)

    @staticmethod
    def _request_document(reset_vector: int | None) -> dict:
        path = ROOT / REQUEST_FILE
        document = json.loads(path.read_text(encoding="utf-8"))
        if reset_vector is not None:
            for region in document["memory"]:
                if region["region_id"] == "rom0":
                    region["base"] = reset_vector
        gpio_profile = GPIO_PROFILE
        document["request_id"] = "ibex-two-novagpio-interrupt-lifecycle"
        document["peripherals"] = [
            {"instance_id": "gpio0", "profile": gpio_profile, "parameters": {}},
            {"instance_id": "gpio1", "profile": gpio_profile, "parameters": {},
             "address": 0x4000_1000},
        ]
        return document

    def test_the_composition_and_program_are_what_the_plan_declares(self) -> None:
        document = self.positive.document
        source_ids = [int(item["source_id"])
                      for item in self.plan.interrupt_document["sources"]]
        enabled = [item for item in document["sources"]
                   if item["controller_enable"]["enabled"]]
        self.assertEqual(source_ids, [int(item["source_id"]) for item in enabled])
        self.assertEqual(source_ids, [int(item)
                                      for item in document["trigger"]["source_ids"]])
        observations = document["report"]["observations"]
        self.assertEqual(1, observations["all_sources_closed"])
        self.assertEqual(len(source_ids), observations["interrupt_completions"])
        self.assertIn("isr multi-source ledger", "\n".join(document["steps"]))
        self.assertEqual([], document["trigger"]["mmio_writes"])

    def test_staggered_multi_source_events_are_serviced(self) -> None:
        """A second run proves distinct arrival windows are not merged."""
        program = build_boot_program(
            self.plan, request=ProgramRequest(exercise_all_sources=True,
                                              stagger_sources=True))
        cycles_by_pin: dict[str, list[int]] = {}
        for event in program.document["trigger"]["events"]:
            cycles_by_pin.setdefault(str(event["name"]), []).append(int(event["cycle"]))
        self.assertGreaterEqual(len({max(values) for values in cycles_by_pin.values()}), 2)
        image = self.negative_image.parent / "boot_program_multi_staggered.hex"
        image.write_text(image_hex(program.image), encoding="utf-8")
        build = replace(self.build, boot_image=image.resolve())
        result = self.run_program(program, case="staggered", request_id=4, build=build)
        self.assert_promises(program, result, case="staggered")
        report = program.report_address
        self.assertEqual(len(self.plan.interrupt_document["sources"]),
                         read32(result, report + self.observations_layout[
                             "interrupt_completions"]))
        self.assertEqual(1, read32(result, report + self.observations_layout[
            "all_sources_closed"]))


if __name__ == "__main__":
    unittest.main()
