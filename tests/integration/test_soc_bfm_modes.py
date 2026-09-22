"""Priority item 1: the synthetic bus master and the contention mode.

The profile-driven composition path gains the two bus-owner profiles that
``input_constraints.DRIVE_PROFILES`` always declared but no generated structure
could serve:

* ``bfm_isolated``  - the CPU is held in reset for the whole test through a
  rendered constant and the synthetic ``fuzz_mmio`` master owns the bus;
* ``contention``    - both masters are real: the CPU executes and the synthetic
  master offers MMIO transactions, and the arbiter decides who owns each one.

The real-runtime half is opt-in through ``MYFUZZ_SOC_REAL=1`` and follows
``test_soc_matrix_runtime.py``: when the flag is set nothing may skip.  Every
runtime test drives the generated top through ``soc_runtime`` with raw samples
whose synthetic fields sit at the offsets the compiled ``soc_stimulus.v1``
document records, and asserts observable evidence only:

* the real peripheral side effect of a BFM write (``gpio0__gpio_out_o``);
* the BFM's own counters (completions, recorded errors, busy drops);
* the fabric's own ``rsp_source_id`` attribution per declared source;
* the CPU's observation ports, which do not advance while it is held.

The structural half runs without the flag: it checks the plan, the stimulus
document, the rendered RTL, the generated testbench and the independent audit,
including the required lane-swap fault injection.
"""
from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.composition.soc_composition import build_composition, composition_document
from myfuzz.composition.soc_profile_renderer import (
    CPU_HELD_CONSTANT,
    CPU_RESET_NET,
    render_composition,
    source_list,
)
from myfuzz.composition.soc_runtime import (
    RuntimeSample,
    build_profile_runtime,
    render_profile_testbench,
    run_sample,
)
from myfuzz.composition.soc_structure_audit import FAIL, audit_structure

from tests.composition.soc_generation_fixture import ROOT, example_plan, example_request

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
OUTPUT_ROOT = ROOT / "runs/soc-bfm-modes"

#: The example peripheral every BFM sample targets, and its DATA_OUT register.
GPIO_TARGET = "gpio0_win"
GPIO_DATA_OUT = 0x00
#: The example CPU's declared observation encoding (examples/soc_generation/rtl):
#: 0x01 is its reset/boot state, 0x03 the polling state it only reaches after a
#: real fetch handshake.  The tests assert equality with these values because the
#: example design pins them; a held CPU must stay in the boot state.
CPU_BOOT_STATE = 0x01
CPU_POLL_STATE = 0x03

#: An MMIO address outside every declared window, for the recorded-error case.
UNMAPPED_OFFSET = 0x5000_0000


def _plan(profile: str):
    if profile == "cpu_execute":
        return example_plan()
    return build_composition(example_request(), base_dir=ROOT, drive_profile=profile)


def _window_base(plan, target_id: str) -> int:
    return next(int(window["base"]) for window in plan.plan["address_map"]["windows"]
                if str(window["target_id"]) == target_id)


def _selector(plan, target_id: str) -> int:
    """The BFM's own window index of one target, from the compiled parameters."""
    base = _window_base(plan, target_id)
    bases = [int(value) for value in plan.synthetic["parameters"]["WINDOW_BASE"]]
    return bases.index(base)


def _cycle_word(plan, **fields: int) -> int:
    """One raw cycle value: the synthetic fields at their recorded offsets.

    Every offset comes from the stimulus slots the plan records; the test only
    places values in them.
    """
    value = 0
    for name, raw in fields.items():
        slot = next(item for item in plan.synthetic["raw_ports"] if item["port"] == name)
        value |= (int(raw) & ((1 << int(slot["width"])) - 1)) << int(slot["raw_lo"])
    return value


def _offer_word(plan, *, selector: int, offset: int, write: int, wdata: int = 0,
                be: int = 0xF) -> int:
    return _cycle_word(plan, stim_offer=1, stim_target_selector=selector,
                       stim_offset=offset, stim_write=write, stim_wdata=wdata,
                       stim_be=be)


def _failed(result: dict) -> list[str]:
    return [str(item["check_id"]) for item in result["findings"] if item["status"] == FAIL]


def _audit(plan, text: str) -> dict:
    return audit_structure(plan, top_text=text,
                           source_files=[item["path"] for item in source_list(plan)],
                           base_dir=ROOT)


class BfmPlanAndRenderTests(unittest.TestCase):
    """The plan, the stimulus document, the RTL and the testbench, without a run."""

    def test_bfm_profiles_declare_the_synthetic_master_with_the_fabric_widths(self) -> None:
        for profile in ("bfm_isolated", "contention"):
            with self.subTest(profile=profile):
                plan = _plan(profile)
                synthetic = plan.synthetic
                self.assertTrue(synthetic, "no synthetic master was declared")
                self.assertEqual("fuzz_mmio", synthetic["kind"])
                self.assertEqual(["processor-memory-beat", "1"], synthetic["protocol"])
                self.assertEqual({"mmio_only", "mixed"}, set(synthetic["test_modes"]))
                self.assertIn(plan.stimulus["mode"], synthetic["test_modes"])
                master = next(item for item in plan.spec["masters"]
                              if item["source_id"] == synthetic["source_id"])
                parameters = plan.plan["fabric"]["rtl"]["parameters"]
                self.assertEqual(parameters["ADDRESS_WIDTH"], master["address_width"])
                self.assertEqual(parameters["DATA_WIDTH"], master["data_width"])
                self.assertEqual(parameters["ADDRESS_WIDTH"], plan.spec["masters"][0]["address_width"])
                self.assertEqual(parameters["DATA_WIDTH"], plan.spec["masters"][0]["data_width"])
                # The plan's own mode list is what compile_soc_stimulus checks.
                self.assertEqual({"cpu_only", "mmio_only", "mixed"},
                                 set(plan.plan["stimulus"]["available_modes"]))
                self.assertEqual({"cpu_only", "mmio_only", "mixed"},
                                 set(plan.spec["test_modes"]))

    def test_the_stimulus_document_is_compiled_and_stored_in_the_composition(self) -> None:
        from myfuzz.composition.soc_contracts import (
            soc_plan_hash,
            validate_soc_stimulus,
        )

        for profile, mode in (("bfm_isolated", "mmio_only"), ("contention", "mixed"),
                              ("cpu_execute", "cpu_only")):
            with self.subTest(profile=profile):
                plan = _plan(profile)
                document = composition_document(plan)
                self.assertEqual(plan.drive_profile, document["drive_profile"])
                self.assertEqual(plan.stimulus, document["stimulus"])
                self.assertEqual(mode, plan.stimulus["mode"])
                validate_soc_stimulus(dict(plan.stimulus))
                # The stimulus names the plan it was compiled from, recomputed here.
                self.assertEqual(soc_plan_hash(dict(plan.plan)), plan.stimulus["plan_hash"])
                self.assertTrue(str(plan.stimulus["layout_hash"]))
                if profile != "cpu_execute":
                    self.assertEqual(
                        plan.stimulus["rtl_projection"]["parameters"],
                        {key: value for key, value in plan.synthetic["parameters"].items()})

    def test_the_bfm_raw_ports_take_their_offsets_from_the_stimulus_segment(self) -> None:
        plan = _plan("bfm_isolated")
        segment = next(item for item in plan.stimulus["raw_layout"]["segments"]
                       if item["segment_id"] == "mmio")
        fields = {str(item["port"]): item for item in segment["fields"] if item.get("port")}
        base_bit = int(plan.raw_layout["raw_width"])
        self.assertEqual(base_bit, int(plan.synthetic["raw_base_bit"]))
        self.assertEqual(set(fields), {item["port"] for item in plan.synthetic["raw_ports"]})
        for item in plan.synthetic["raw_ports"]:
            field = fields[str(item["port"])]
            self.assertEqual(int(field["bit_offset"]), int(item["segment_bit_offset"]))
            self.assertEqual(base_bit + int(field["bit_offset"]), int(item["raw_lo"]))
            self.assertEqual(int(field["width"]), int(item["width"]))
            self.assertEqual(int(item["raw_lo"]) + int(item["width"]) - 1, int(item["raw_hi"]))
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        for item in plan.synthetic["raw_ports"]:
            width = int(item["width"])
            shape = "logic" if width == 1 else f"logic [{width - 1}:0]"
            self.assertIn(f"    input  {shape} {item['name']}", top)

    def test_the_rendered_top_holds_the_cpu_only_in_bfm_isolated(self) -> None:
        held = render_composition(_plan("bfm_isolated"))["myfuzz_soc_top.sv"]
        self.assertIn(f"  localparam bit {CPU_HELD_CONSTANT} = 1;", held)
        self.assertIn(f"  wire {CPU_RESET_NET} = rst_ni & ~{CPU_HELD_CONSTANT};", held)
        self.assertIn(f"    .rst_ni({CPU_RESET_NET}),", held)
        for profile in ("contention", "cpu_execute"):
            with self.subTest(profile=profile):
                top = render_composition(_plan(profile))["myfuzz_soc_top.sv"]
                self.assertNotIn(CPU_HELD_CONSTANT, top)
                self.assertNotIn(CPU_RESET_NET, top)
                self.assertIn("    .rst_ni(rst_ni),", top)

    def test_the_cpu_execute_composition_is_unchanged(self) -> None:
        plan = _plan("cpu_execute")
        self.assertEqual("cpu_execute", plan.drive_profile)
        self.assertEqual({}, dict(plan.synthetic))
        self.assertEqual(["cpu_only"], list(plan.plan["stimulus"]["available_modes"]))
        self.assertEqual(["cpu_only"], list(plan.spec["test_modes"]))
        self.assertEqual(1, len(plan.plan["fabric"]["sources"]))
        # A requested mode the structure cannot serve is still recorded as a gap.
        for mode in ("mmio_only", "mixed"):
            self.assertTrue(any(gap.startswith(f"{mode}:") for gap in plan.gaps), plan.gaps)
            self.assertTrue(any("no generated synthetic beat-master lane" in gap
                                for gap in plan.gaps if gap.startswith(f"{mode}:")))
        self.assertEqual("cpu_only", plan.stimulus["mode"])
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertNotIn("fuzz_mmio_master", top)
        self.assertNotIn("synthetic_master", {item["role"] for item in source_list(plan)})

    def test_the_testbench_drives_the_bfm_fields_without_a_driver_in_front(self) -> None:
        plan = _plan("bfm_isolated")
        testbench = render_profile_testbench(plan)
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        for item in plan.synthetic["raw_ports"]:
            self.assertIn(f"  assign {item['name']} = raw_bits[{item['raw_hi']}:"
                          f"{item['raw_lo']}];", testbench)
            # The raw port is the request: no special-input driver is rendered
            # between the top-level port and the master's own input.
            self.assertNotIn(f"u_drive_{item['name']}", top)
        special = [entry for instance in plan.instances for entry in instance.dispositions
                   if entry.disposition == "fuzz"]
        self.assertEqual(len(special), top.count("soc_special_input_driver #("))
        # The testbench exposes exactly the synthetic slots the runtime binary
        # consumes, and they are the same ports the top declares.
        for item in plan.synthetic["raw_ports"]:
            self.assertIn(f"  assign {item['name']} = raw_bits", testbench)

    def test_the_audit_passes_for_both_bfm_profiles(self) -> None:
        for profile in ("bfm_isolated", "contention"):
            with self.subTest(profile=profile):
                plan = _plan(profile)
                result = _audit(plan, render_composition(plan)["myfuzz_soc_top.sv"])
                self.assertEqual([], _failed(result), result["findings"])
                checks = {item["check_id"] for item in result["findings"]}
                for required in ("fabric_source_lanes", "response_ownership",
                                 "fuzz_master_reset", "fuzz_master_parameters",
                                 "cpu_reset_hold"):
                    self.assertIn(required, checks)


class BfmFaultInjectionTests(unittest.TestCase):
    """A wrong lane in the generated RTL must be found even though the plan is right."""

    def mutate(self, text: str, *pairs: tuple[str, str]) -> str:
        for old, new in pairs:
            self.assertIn(old, text, f"mutation anchor missing: {old}")
            self.assertNotEqual(old, new)
            text = text.replace(old, new)
        return text

    def test_swapped_response_lanes_are_detected(self) -> None:
        plan = _plan("contention")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        swapped = self.mutate(
            text,
            (".rsp_valid_i(src_rsp_valid[0])", ".rsp_valid_i(src_rsp_valid[1])"),
            (".rsp_valid(src_rsp_valid[1])", ".rsp_valid(src_rsp_valid[0])"))
        self.assertIn("response_ownership", _failed(_audit(plan, swapped)))

    def test_swapped_request_lanes_are_detected(self) -> None:
        plan = _plan("contention")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        swapped = self.mutate(text, (".req_valid(src_req_valid[1])",
                                     ".req_valid(src_req_valid[0])"))
        self.assertIn("fabric_source_lanes", _failed(_audit(plan, swapped)))

    def test_a_flipped_bfm_reset_is_detected(self) -> None:
        plan = _plan("contention")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        flipped = self.mutate(text, (".reset(~rst_ni),", ".reset(rst_ni),"))
        self.assertIn("fuzz_master_reset", _failed(_audit(plan, flipped)))

    def test_a_released_cpu_in_bfm_isolated_is_detected(self) -> None:
        plan = _plan("bfm_isolated")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        released = self.mutate(text, (f".rst_ni({CPU_RESET_NET}),", ".rst_ni(rst_ni),"))
        self.assertIn("cpu_reset_hold", _failed(_audit(plan, released)))

    def test_a_deasserted_hold_constant_in_bfm_isolated_is_detected(self) -> None:
        plan = _plan("bfm_isolated")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        deasserted = self.mutate(text, (f"localparam bit {CPU_HELD_CONSTANT} = 1;",
                                        f"localparam bit {CPU_HELD_CONSTANT} = 0;"))
        self.assertIn("cpu_reset_hold", _failed(_audit(plan, deasserted)))

    def test_a_wrong_projection_parameter_is_detected(self) -> None:
        plan = _plan("contention")
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        wrong = self.mutate(text, (".SELECTOR_INVALID(6)", ".SELECTOR_INVALID(7)"))
        self.assertIn("fuzz_master_parameters", _failed(_audit(plan, wrong)))


class _BfmRuntimeFixture(unittest.TestCase):
    """One rendered, audited, compiled SoC per profile, re-used by the class."""

    profile = ""
    build_timeout_s = int(os.environ.get("MYFUZZ_SOC_BFM_BUILD_TIMEOUT_S", "1800"))

    @classmethod
    def setUpClass(cls) -> None:
        if not OPT_IN:
            raise unittest.SkipTest("set MYFUZZ_SOC_REAL=1 for the real BFM runtime")
        import shutil

        cls.started = time.monotonic()
        cls.plan = _plan(cls.profile)
        cls.top_text = render_composition(cls.plan)["myfuzz_soc_top.sv"]
        cls.audit = _audit(cls.plan, cls.top_text)
        if _failed(cls.audit):
            raise AssertionError(f"{cls.profile}: generated top failed the audit: "
                                 f"{_failed(cls.audit)}")
        cls._temporary = TemporaryDirectory(prefix=".myfuzz-bfm-", dir=ROOT)
        output = Path(cls._temporary.name) / cls.profile
        cls.build = build_profile_runtime(
            cls.plan, output_dir=output, base_dir=ROOT, top_text=cls.top_text,
            sources=[item["path"] for item in source_list(cls.plan)
                     if item["role"] != "include_root"],
            timeout_seconds=cls.build_timeout_s)
        cls.build_seconds = time.monotonic() - cls.started
        print("\nMYFUZZ_SOC_BFM_TIMING profile=%s build_s=%.1f raw_width=%d"
              % (cls.profile, cls.build_seconds, cls.build.raw_width))

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "_temporary"):
            cls._temporary.cleanup()

    def offers(self, *, selector: int, offset: int, write: int, wdata: int, cycles: int,
               first: int, period: int, be: int = 0xF) -> tuple[int, ...]:
        raw = [0] * cycles
        count = 0
        for cycle in range(first, cycles, period):
            raw[cycle] = _offer_word(self.plan, selector=selector, offset=offset,
                                     write=write, wdata=wdata, be=be)
            count += 1
        self.offers_placed = count
        return tuple(raw)

    def run_raw(self, raw: tuple[int, ...], request_id: int):
        result = run_sample(self.build,
                            RuntimeSample(request_id=request_id, raw=raw))
        self.assertEqual("OK", result.status, result.reason)
        return result

    def observation(self, result, name: str) -> int:
        self.assertIn(name, result.observations, sorted(result.observations))
        return int(result.observations[name])


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real BFM runtime")
class BfmIsolatedRuntimeTests(_BfmRuntimeFixture):
    profile = "bfm_isolated"

    def test_the_bfm_completes_mmio_against_a_real_peripheral(self) -> None:
        raw = self.offers(selector=_selector(self.plan, GPIO_TARGET),
                          offset=_window_base(self.plan, GPIO_TARGET) + GPIO_DATA_OUT,
                          write=1, wdata=0x5A, cycles=64, first=0, period=8)
        result = self.run_raw(raw, request_id=1)
        completions = self.observation(result, "fuzz_mmio0__completion_count")
        drops = self.observation(result, "fuzz_mmio0__busy_drop_count")
        self.assertGreaterEqual(completions, 1, "the BFM completed nothing")
        self.assertEqual(0, self.observation(result, "fuzz_mmio0__error_count"))
        self.assertEqual(0, self.observation(result, "fuzz_mmio0__error_code"))
        # Every offer is either accepted exactly once or dropped while busy.
        self.assertEqual(self.offers_placed, completions + drops)
        # The real device register the BFM wrote is visible on the exported pin.
        self.assertEqual(0x5A, self.observation(result, "gpio0__gpio_out_o"))
        # The fabric attributes every completion to the synthetic master's lane.
        self.assertEqual(completions,
                         self.observation(result, "fabric_source_responses__fuzz_mmio0"))
        self.assertEqual(0, self.observation(result, "fabric_source_responses__cpu_master0"))
        self.assertEqual(0, self.observation(result, "fabric_protocol_error"))

    def test_the_cpu_is_held_in_reset_for_the_whole_test(self) -> None:
        selector = _selector(self.plan, GPIO_TARGET)
        base = _window_base(self.plan, GPIO_TARGET)
        active = self.run_raw(
            self.offers(selector=selector, offset=base, write=1, wdata=0x33,
                        cycles=64, first=0, period=4), request_id=2)
        idle = self.run_raw(tuple([0] * 64), request_id=3)
        # The RTL holds the CPU through a rendered constant, and the audit re-read it.
        self.assertIn(f"  localparam bit {CPU_HELD_CONSTANT} = 1;", self.top_text)
        self.assertEqual([], _failed(self.audit))
        # The CPU's observation ports do not advance, with or without bus traffic,
        # and stay in the state the reset value puts them in.
        self.assertEqual(CPU_BOOT_STATE, self.observation(active, "cpu0__status_o"))
        self.assertEqual(self.observation(idle, "cpu0__status_o"),
                         self.observation(active, "cpu0__status_o"))
        self.assertEqual(0, self.observation(active, "cpu0__trap_o"))
        self.assertEqual(0, self.observation(active, "fabric_source_responses__cpu_master0"))
        # The peripheral really did what the BFM asked in the active run.
        self.assertEqual(0x33, self.observation(active, "gpio0__gpio_out_o"))
        self.assertEqual(0x00, self.observation(idle, "gpio0__gpio_out_o"))

    def test_an_invalid_target_selector_is_an_internal_error_without_a_request(self) -> None:
        parameters = self.plan.synthetic["parameters"]
        invalid = int(parameters["SELECTOR_INVALID"])
        self.assertGreaterEqual(invalid, int(parameters["NUM_WINDOWS"]))
        raw = self.offers(selector=invalid, offset=0, write=1, wdata=0x11,
                          cycles=48, first=0, period=8)
        result = self.run_raw(raw, request_id=4)
        completions = self.observation(result, "fuzz_mmio0__completion_count")
        self.assertEqual(self.offers_placed, completions)
        self.assertEqual(self.offers_placed, self.observation(result, "fuzz_mmio0__error_count"))
        self.assertEqual(1, self.observation(result, "fuzz_mmio0__error_code"))
        # No fabric request was issued: the lane saw no response at all.
        self.assertEqual(0, self.observation(result, "fabric_source_responses__fuzz_mmio0"))
        # ... and the peripheral side effect never happened.
        self.assertEqual(0x00, self.observation(result, "gpio0__gpio_out_o"))

    def test_an_unmapped_address_is_recorded_not_retried(self) -> None:
        raw = self.offers(selector=_selector(self.plan, GPIO_TARGET),
                          offset=UNMAPPED_OFFSET, write=1, wdata=0x22,
                          cycles=48, first=0, period=8)
        result = self.run_raw(raw, request_id=5)
        completions = self.observation(result, "fuzz_mmio0__completion_count")
        self.assertGreaterEqual(completions, 1)
        # The fabric answered with an error; the driver recorded it and did not retry.
        self.assertEqual(completions, self.observation(result, "fuzz_mmio0__error_count"))
        self.assertEqual(2, self.observation(result, "fuzz_mmio0__error_code"))
        self.assertEqual(completions,
                         self.observation(result, "fabric_source_responses__fuzz_mmio0"))
        self.assertEqual(0x00, self.observation(result, "gpio0__gpio_out_o"))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real BFM runtime")
class ContentionRuntimeTests(_BfmRuntimeFixture):
    profile = "contention"

    def test_both_masters_complete_and_the_fabric_attributes_each_response(self) -> None:
        selector = _selector(self.plan, GPIO_TARGET)
        base = _window_base(self.plan, GPIO_TARGET)
        raw = self.offers(selector=selector, offset=base + GPIO_DATA_OUT, write=1,
                          wdata=0x3C, cycles=128, first=4, period=6)
        result = self.run_raw(raw, request_id=6)
        cpu_responses = self.observation(result, "fabric_source_responses__cpu_master0")
        fuzz_responses = self.observation(result, "fabric_source_responses__fuzz_mmio0")
        completions = self.observation(result, "fuzz_mmio0__completion_count")
        # Both masters are real: the CPU executes (it only leaves its boot state
        # after a real fetch handshake) and the synthetic master completes.
        self.assertGreaterEqual(cpu_responses, 2, "the CPU completed no transaction")
        self.assertGreaterEqual(fuzz_responses, 1, "the BFM completed no transaction")
        self.assertEqual(CPU_POLL_STATE, self.observation(result, "cpu0__status_o"))
        self.assertEqual(0, self.observation(result, "cpu0__trap_o"))
        # Each completion is attributed to its own source by the fabric itself:
        # the synthetic master's own counter equals its lane's response count.
        self.assertEqual(completions, fuzz_responses)
        self.assertEqual(0, self.observation(result, "fuzz_mmio0__error_count"))
        self.assertEqual(0, self.observation(result, "fabric_protocol_error"))
        # Alternating ownership, not concurrency: the fabric has one outstanding
        # transaction, so no run can have more completions than clock cycles.
        self.assertLessEqual(cpu_responses + fuzz_responses, result.cycles)
        self.assertEqual(0x3C, self.observation(result, "gpio0__gpio_out_o"))


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real BFM runtime")
class BfmToolingTests(unittest.TestCase):
    def test_verilator_is_required_when_opted_in(self) -> None:
        import shutil

        self.assertIsNotNone(shutil.which("verilator"),
                             "Verilator is required for the real BFM runtime")


if __name__ == "__main__":
    unittest.main()
