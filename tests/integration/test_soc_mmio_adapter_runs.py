"""Item 11: real runs of the MMIO infrastructure blocks a composed run cannot reach.

``soc_profile_renderer`` refuses ``mmio_width_adapter`` and ``beat_address_narrow``
by name (``width-adapter-rendering-unsupported`` /
``address-narrower-rendering-unsupported``), and the current composition path
refuses a 64-bit CPU master outright, so *no* plan built through
``build_composition`` can carry either block.  Rather than fake a run through the
composition, this module does both halves of the honest answer:

* it **refuses explicitly**: the planner's own named errors are asserted with
  their exact messages, including the plan-level proof that a narrowing is only
  admitted when the target's whole window fits the narrow address width
  (``address-narrowing-window:<target>``);
* it **runs the blocks for real**: ``tests/integration/rtl/mmio_beat_harness_tb.sv``
  drives ``beat_address_narrow``, ``mmio_width_adapter`` and
  ``beat_watchdog`` on a real Verilator build and reports every observation the
  checks below assert.  The harness prints the configuration it ran with, and
  this module compares it with the plan's own narrowing record, so the run is
  shown to be the plan's proven configuration and not a hand-picked one.

``MYFUZZ_SOC_REAL=1`` opts in, following
``tests/integration/test_soc_interrupt_lifecycle.py``.  Without it the real-run
tests skip cleanly; the planning/refusal tests always run.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_fabric import SocFabricError, build_soc_fabric
from myfuzz.composition.soc_profile_renderer import render_composition

from tests.composition.soc_generation_fixture import ROOT, example_plan

OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
RUN_ROOT = ROOT / "runs/soc-mmio-error-verification"
HARNESS_ROOT = RUN_ROOT / "harness"

IBEX_PROFILE = "configs/cpus/ibex/component_profile.json"
GPIO_PROFILE = "examples/soc_generation/profiles/novagpio.json"
CVA6_PROFILE = "configs/cpus/cva6/component_profile.json"
OPENTITAN_GPIO = "configs/peripherals/opentitan_gpio/component_profile.json"

#: The blocks the harness instantiates, in the order the artifact records them.
HARNESS_SOURCES = (
    "tests/integration/rtl/mmio_beat_harness_tb.sv",
    "src/myfuzz/protocols/rtl/beat_watchdog.sv",
    "src/myfuzz/protocols/rtl/beat_address_narrow.sv",
    "src/myfuzz/protocols/rtl/mmio_width_adapter.sv",
)

#: The declared wait bound the harness's bounded watchdog enforces.  It is the
#: bound the example peripheral profiles declare in ``capabilities``.
DECLARED_WAIT_BOUND = 16

#: The target window the harness narrows, and the width it narrows to.
HARNESS_WINDOW_BASE = 0x4000_0000
HARNESS_WINDOW_SIZE = 0x1000
HARNESS_NARROW_WIDTH = 32
HARNESS_ADDRESS_WIDTH = 64


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# the plan-side proof of the narrowing, and the planner's refusals
# ---------------------------------------------------------------------------


def fabric_spec(*, base: int = HARNESS_WINDOW_BASE, size: int = HARNESS_WINDOW_SIZE,
                narrow_width: int = HARNESS_NARROW_WIDTH) -> dict:
    """A fabric spec whose target is exactly the pair the harness runs.

    A 64-bit beat side against a 32-bit, narrow-address TL-UL target is what the
    planner turns into an ``mmio_width_adapter`` plus a ``beat_address_narrow``.
    """
    masters = [
        {"source_id": "cpu", "kind": "cpu_unified", "data_width": 64,
         "address_width": 64, "protocol": ["axi4", "1"]},
        {"source_id": "fuzz", "kind": "fuzz_mmio", "data_width": 64,
         "address_width": 64, "protocol": ["processor-memory-beat", "1"]},
    ]
    return {
        "masters": masters,
        "memory_regions": [
            {"region_id": "ram0", "component_id": "ram", "base": 0x8000_0000,
             "size": 0x1_0000,
             "permissions": {"read": True, "write": True, "execute": True},
             "physical_memory_id": "ram0", "initialization_policy": "on_demand"},
        ],
        "targets": [
            {"target_id": "tlul0_win", "component_id": "tlul0",
             "window": {"base": base, "size": size},
             "request_sources": ["cpu", "fuzz"], "data_width": 32,
             "fabric_address_width": narrow_width,
             "width_conversion": {"spanning_read": "reject",
                                  "spanning_write": "reject"},
             "permissions": {"read": True, "write": True, "execute": False}},
        ],
        "resources": {"limits": {"max_wait_cycles": DECLARED_WAIT_BOUND}},
    }


def fabric_execution() -> dict:
    return {
        "schema_version": "processor_execution.v1",
        "execution_hash": "sha256:" + "2" * 64,
        "routes": [{
            "route_id": 7, "function": "processor_memory_master",
            "target_protocol": ["processor-memory-beat", "1"],
            "parameters": {"READ_ONLY": 0},
            "widths": {"address": 64, "data": 64},
            "backend_contract": {"mode": "single_outstanding_request_response",
                                 "protocol": ["processor-memory-beat", "1"],
                                 "capabilities": {"max_outstanding": 1,
                                                  "max_wait_cycles": DECLARED_WAIT_BOUND}},
        }],
    }


class NarrowingPlanProofTests(unittest.TestCase):
    """The plan's own narrowing proof, and the refusal when it cannot hold."""

    def test_the_plan_records_the_narrowing_the_harness_runs(self) -> None:
        fabric = build_soc_fabric(fabric_spec(), fabric_execution())
        self.assertEqual(1, len(fabric["address_narrowers"]))
        narrower = fabric["address_narrowers"][0]
        self.assertEqual("beat_address_narrow", narrower["module"])
        parameters = narrower["parameters"]
        self.assertEqual(HARNESS_ADDRESS_WIDTH, int(parameters["ADDRESS_WIDTH"]))
        self.assertEqual(HARNESS_NARROW_WIDTH, int(parameters["NARROW_ADDRESS_WIDTH"]))
        self.assertEqual(HARNESS_WINDOW_BASE, int(parameters["WINDOW_BASE"]))
        self.assertEqual(HARNESS_WINDOW_SIZE, int(parameters["WINDOW_SIZE"]))
        # The proof itself: the whole window fits the narrow address width, so
        # the truncation the stage performs is lossless.
        self.assertLessEqual(int(parameters["WINDOW_BASE"])
                             + int(parameters["WINDOW_SIZE"]),
                             1 << int(parameters["NARROW_ADDRESS_WIDTH"]))
        self.assertEqual(1, len(fabric["width_adapters"]))
        adapter = fabric["width_adapters"][0]
        self.assertEqual("mmio_width_adapter", adapter["module"])
        self.assertEqual(64, int(adapter["parameters"]["DATA_WIDTH"]))
        self.assertEqual(32, int(adapter["parameters"]["PERIPHERAL_DATA_WIDTH"]))
        self.assertEqual(0, int(adapter["parameters"]["ALLOW_SPANNING_WRITE_SPLIT"]))
        self.assertEqual(0, int(adapter["parameters"]["ALLOW_SPANNING_READ_ASSEMBLE"]))

    def test_a_window_that_does_not_fit_the_narrow_width_is_refused(self) -> None:
        with self.assertRaises(SocFabricError) as error:
            build_soc_fabric(fabric_spec(base=0x1_0000_0000), fabric_execution())
        self.assertEqual("address-narrowing-window:tlul0_win", str(error.exception))

    def test_the_renderer_refuses_the_width_adapter_by_name(self) -> None:
        plan = example_plan()
        index = self._target_index(plan, "gpio0")
        annotated = dataclasses.replace(plan, plan={
            **plan.plan,
            "fabric": {**plan.plan["fabric"], "width_adapters": [{
                "target_index": index, "module": "mmio_width_adapter",
                "source": "src/myfuzz/protocols/rtl/mmio_width_adapter.sv",
                "parameters": {}}]},
        })
        with self.assertRaises(Exception) as error:
            render_composition(annotated)
        self.assertEqual("width-adapter-rendering-unsupported:gpio0",
                         str(error.exception))

    def test_the_renderer_refuses_the_address_narrower_by_name(self) -> None:
        plan = example_plan()
        index = self._target_index(plan, "gpio0")
        annotated = dataclasses.replace(plan, plan={
            **plan.plan,
            "fabric": {**plan.plan["fabric"], "address_narrowers": [{
                "target_index": index, "module": "beat_address_narrow",
                "source": "src/myfuzz/protocols/rtl/beat_address_narrow.sv",
                "parameters": {}}]},
        })
        with self.assertRaises(Exception) as error:
            render_composition(annotated)
        self.assertEqual("address-narrower-rendering-unsupported:gpio0",
                         str(error.exception))

    def test_a_64_bit_master_is_refused_by_the_composition_planner(self) -> None:
        """Why no composed plan can carry the two adapters in this checkout."""
        profiles = {}
        for relative in (CVA6_PROFILE, OPENTITAN_GPIO):
            path = ROOT / relative
            if not path.is_file():
                self.skipTest(f"missing {relative}")
            profile = load_component_profile(path)
            profiles[relative] = profile
            profiles.setdefault(profile.component_id, profile)
        document = {
            "schema_version": "composition_request.v1",
            "request_id": "cva6-opentitan-width-adapter",
            "cpu": {"instance_id": "cpu0", "profile": CVA6_PROFILE, "parameters": {}},
            "peripherals": [{"instance_id": "gpio0", "profile": OPENTITAN_GPIO,
                             "parameters": {}, "address": 0x4000_0000}],
            "memory": [
                {"region_id": "rom0", "base": 65536, "size": 32768,
                 "permissions": {"read": True, "write": False, "execute": True},
                 "physical_memory_id": "boot_rom", "initialization_policy": "rom"},
                {"region_id": "ram0", "base": 0x8000_0000, "size": 65536,
                 "permissions": {"read": True, "write": True, "execute": True},
                 "physical_memory_id": "main_ram",
                 "initialization_policy": "on_demand"},
            ],
            "address_policy": {"mmio_base": 0x4000_0000, "mmio_limit": 0x10_0000,
                               "alignment": 4096},
            "clock": {"domain": "core", "frequency_hz": 50_000_000},
            "reset": {"domain": "sys_rst", "polarity": "active_low",
                      "synchronous": False},
            "test_modes": ["cpu_only"],
        }
        request = load_composition_request(document, profiles=profiles)
        with self.assertRaises(Exception) as error:
            build_composition(request, base_dir=ROOT)
        self.assertEqual(
            "unsupported-master-data-width:cpu0:processor.memory.unified:"
            "axi4@1:64:only-32-bit-is-composed",
            str(error.exception),
            "the composition planner must refuse a 64-bit master by name: that is "
            "what keeps a plan needing the width adapter or the address narrower "
            "out of the composed path")

    @staticmethod
    def _target_index(plan, instance_id: str) -> int:
        target_id = next(str(record["target_id"]) for record in plan.target_records
                         if record.get("instance_id") == instance_id)
        return next(int(row["target_index"]) for row in plan.plan["fabric"]["decode"]["windows"]
                    if str(row["target_id"]) == target_id)


# ---------------------------------------------------------------------------
# the real harness run
# ---------------------------------------------------------------------------


def _read_observations(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        if not line.startswith("MYFUZZ_HARNESS "):
            continue
        name, _, value = line[len("MYFUZZ_HARNESS "):].partition("=")
        try:
            values[name.strip()] = int(value.strip())
        except ValueError:
            continue
    return values


def _run_status(text: str) -> tuple[str, str]:
    for line in text.splitlines():
        if line.startswith("MYFUZZ_HARNESS_RUN "):
            fields = dict(part.split("=", 1) for part in line.split()[1:] if "=" in part)
            return str(fields.get("status", "")), str(fields.get("reason", ""))
    return "", ""


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real harness run")
class MmioInfrastructureHarnessTests(unittest.TestCase):
    """Real Verilator runs of the watchdog, the narrower and the width adapter."""

    blocker: str | None = None
    bounded: str = ""
    unbounded: str = ""
    bounded_values: dict = {}
    unbounded_values: dict = {}
    build: dict = {}

    @classmethod
    def setUpClass(cls):
        try:
            cls._prepare()
        except Exception as error:                    # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        verilator = shutil.which("verilator")
        if verilator is None:
            raise AssertionError("Verilator is required for the harness run")
        digests = {relative: _sha256_file(ROOT / relative) for relative in HARNESS_SOURCES}
        key = hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest()[:16]
        output = HARNESS_ROOT / key
        executable = output / "obj_dir" / "mmio_beat_harness_sim"
        if not executable.is_file():
            if output.exists():
                shutil.rmtree(output)
            output.mkdir(parents=True, exist_ok=True)
            sources = [(ROOT / relative).as_posix() for relative in HARNESS_SOURCES]
            command = [verilator, "--binary", "--timing", "-Wno-fatal", "-Wno-lint",
                       "--top-module", "mmio_beat_harness_tb",
                       "-o", "mmio_beat_harness_sim",
                       "--Mdir", (output / "obj_dir").as_posix(), *sources]
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    cwd=ROOT.as_posix(), timeout=1800)
            if result.returncode != 0:
                raise AssertionError("harness build failed: "
                                     + (result.stdout + result.stderr)[-3000:])
        cls.build = {
            "tool": verilator,
            "output_dir": output.as_posix(),
            "executable": executable.as_posix(),
            "sources": {relative: digests[relative] for relative in HARNESS_SOURCES},
        }

        def run(*plusargs: str) -> str:
            # No host-side sleep: the harness's own cycle bound ends an
            # unbounded scenario, and the subprocess timeout is only a guard
            # against a hang in the harness itself.
            completed = subprocess.run([executable.as_posix(), *plusargs],
                                       capture_output=True, text=True, check=False,
                                       timeout=300)
            if completed.returncode != 0:
                raise AssertionError(f"harness run {plusargs} failed: "
                                     f"{completed.stdout[-2000:]}{completed.stderr[-2000:]}")
            return completed.stdout

        cls.bounded = run()
        cls.unbounded = run("+unbounded_stall")
        cls.bounded_values = _read_observations(cls.bounded)
        cls.unbounded_values = _read_observations(cls.unbounded)
        cls._write_artifact()

    @classmethod
    def _write_artifact(cls) -> None:
        RUN_ROOT.mkdir(parents=True, exist_ok=True)
        fabric = build_soc_fabric(fabric_spec(), fabric_execution())
        document = {
            "schema_version": "soc_mmio_infrastructure_run.v1",
            "provenance": ("tests/integration/test_soc_mmio_adapter_runs.py: real "
                           "Verilator run of beat_watchdog, beat_address_narrow and "
                           "mmio_width_adapter"),
            "build": cls.build,
            "bounded_run": {
                "plusargs": [],
                "status": _run_status(cls.bounded)[0],
                "reason": _run_status(cls.bounded)[1],
                "observations": dict(sorted(cls.bounded_values.items())),
            },
            "unbounded_run": {
                "plusargs": ["+unbounded_stall"],
                "status": _run_status(cls.unbounded)[0],
                "reason": _run_status(cls.unbounded)[1],
                "observations": dict(sorted(cls.unbounded_values.items())),
            },
            "plan_narrowing": fabric["address_narrowers"],
            "plan_width_adapter": fabric["width_adapters"],
            "declared_wait_bound": DECLARED_WAIT_BOUND,
        }
        (RUN_ROOT / "mmio_infrastructure_run.json").write_text(
            json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    def setUp(self) -> None:
        if self.blocker is not None:
            self.fail("the MMIO infrastructure harness could not be run: %s" % self.blocker)

    def test_the_bounded_run_passes_every_check_it_makes(self) -> None:
        status, reason = _run_status(self.bounded)
        self.assertEqual("OK", status, f"the harness self-check failed: {reason}")
        self.assertEqual("self-check-passed", reason)

    def test_the_narrowing_is_lossless_inside_the_window(self) -> None:
        values = self.bounded_values
        self.assertEqual(0, values["narrow.in_window.error"])
        self.assertEqual(0x2222_0001, values["narrow.in_window.rdata"])
        self.assertEqual(1, values["narrow.in_window.target_requests"])
        # The target saw the complete absolute address, so no in-window bit was
        # discarded by the narrowing.
        self.assertEqual(HARNESS_WINDOW_BASE + 4,
                         values["narrow.in_window.target_saw_absolute_address"])

    def test_an_aliasing_address_is_refused_without_reaching_the_target(self) -> None:
        values = self.bounded_values
        self.assertEqual(1, values["narrow.alias.error"])
        self.assertEqual(0, values["narrow.alias.rdata"])
        self.assertEqual(1, values["narrow.alias.target_requests_unchanged"],
                         "the out-of-window read must issue no downstream request")
        self.assertEqual(1, values["narrow.alias_write.error"])
        self.assertEqual(1, values["narrow.alias_write.target_requests_unchanged"],
                         "the out-of-window write must issue no downstream request")
        # The control: the same store inside the window really lands.
        self.assertEqual(0, values["narrow.in_window_write.error"])
        self.assertEqual(2, values["narrow.in_window_write.target_requests"])
        self.assertEqual(0xCAFE_0000, values["narrow.in_window_write.readback"])

    def test_the_width_adapter_converts_each_lane(self) -> None:
        values = self.bounded_values
        self.assertEqual(0, values["width.low_lane.error"])
        self.assertEqual(0x1111_0000, values["width.low_lane.rdata_low"])
        self.assertEqual(0, values["width.low_lane.rdata_high"])
        self.assertEqual(0x0000_0000, values["width.low_lane.peripheral_addr"])
        self.assertEqual(0, values["width.high_lane.error"])
        self.assertEqual(0x2222_0001, values["width.high_lane.rdata_high"])
        self.assertEqual(0, values["width.high_lane.rdata_low"])
        self.assertEqual(0x0000_0004, values["width.high_lane.peripheral_addr"])
        self.assertEqual(0, values["width.high_lane_write.error"])
        self.assertEqual(0x1234_5678, values["width.high_lane_write.peripheral_wdata"])
        self.assertEqual(0xF, values["width.high_lane_write.peripheral_be"])
        self.assertEqual(1, values["width.high_lane_write.peripheral_addr_bit2"])
        self.assertEqual(0x1234_5678, values["width.high_lane_write.readback"])
        self.assertEqual(1, values["width.partial_high_byte.peripheral_be"])
        self.assertEqual(0x0000_0055, values["width.partial_high_byte.peripheral_wdata"])
        self.assertEqual(0x1234_5655, values["width.partial_high_byte.readback"])

    def test_every_refused_beat_leaves_the_peripheral_alone(self) -> None:
        values = self.bounded_values
        for case in ("no_byte_enable", "lane_mismatch", "spanning_write"):
            self.assertEqual(1, values[f"width.{case}.error"], case)
            self.assertEqual(values["width.no_byte_enable.no_downstream_request"],
                             values[f"width.{case}.no_downstream_request"],
                             f"{case}: a refused access must issue no downstream request")
        self.assertEqual(1, values["width.peripheral_error.error"])
        self.assertEqual(0, values["width.peripheral_error.rdata"])
        self.assertEqual(values["width.no_byte_enable.no_downstream_request"] + 1,
                         values["width.peripheral_error.downstream_request"],
                         "the control access does reach the peripheral")

    def test_the_bounded_watchdog_turns_a_stalled_target_into_a_recorded_timeout(self) -> None:
        values = self.bounded_values
        self.assertEqual(1, values["watchdog.bounded.completed"],
                         "the transaction must complete exactly once")
        self.assertEqual(1, values["watchdog.bounded.error"])
        self.assertEqual(0, values["watchdog.bounded.rdata"])
        self.assertEqual(1, values["watchdog.bounded.timed_out"])
        self.assertEqual(DECLARED_WAIT_BOUND, values["watchdog.bounded.waited_cycles"],
                         "the bound the profile declares is the bound that expired")
        self.assertEqual(1, values["watchdog.bounded.timeout_count"])
        self.assertEqual(1, values["watchdog.bounded.target_requests"])
        self.assertEqual(1, values["watchdog.bounded.drain_pending"],
                         "the late target response is still owed and will be dropped")

    def test_the_unbounded_configuration_reports_a_timeout_instead_of_hanging(self) -> None:
        """The real evidence is a bound the RTL has, not a host-side sleep.

        With ``MAX_WAIT_CYCLES = 0`` nothing in the RTL can end the transaction, and
        the ``+unbounded_stall`` run is the control that shows it: the target
        accepted the request, no response ever arrives, and the harness's own
        cycle bound is what reports the timeout.  The process ends by itself --
        the subprocess timeout in the setup is a guard, never the mechanism.
        """
        status, reason = _run_status(self.unbounded)
        self.assertEqual("TIMEOUT", status)
        self.assertEqual("unbounded-target-never-completed-at-harness-cycle-bound",
                         reason)
        self.assertEqual(0, self.unbounded_values["unbounded_stall.rsp_valid"])
        self.assertEqual(0, self.unbounded_values["unbounded_stall.timed_out"],
                         "with the bound disabled nothing in the RTL reports a timeout")
        self.assertEqual(0, self.unbounded_values["unbounded_stall.timeout_count"])
        self.assertEqual(1, self.unbounded_values["unbounded_stall.target_requests"],
                         "the stalled target really accepted the request")
        # The same binary, without the plusarg, passes: the configuration is the
        # only difference between the two runs.
        self.assertEqual("OK", _run_status(self.bounded)[0])

    def test_the_harness_ran_the_plans_proven_configuration(self) -> None:
        values = self.bounded_values
        fabric = build_soc_fabric(fabric_spec(), fabric_execution())
        narrower = fabric["address_narrowers"][0]["parameters"]
        self.assertEqual(int(narrower["ADDRESS_WIDTH"]), values["narrow.address_width"])
        self.assertEqual(int(narrower["NARROW_ADDRESS_WIDTH"]),
                         values["narrow.narrow_address_width"])
        self.assertEqual(int(narrower["WINDOW_BASE"]), values["narrow.window_base"])
        self.assertEqual(int(narrower["WINDOW_SIZE"]), values["narrow.window_size"])
        adapter = fabric["width_adapters"][0]["parameters"]
        self.assertEqual(int(adapter["DATA_WIDTH"]), values["width.data_width"])
        self.assertEqual(int(adapter["PERIPHERAL_DATA_WIDTH"]),
                         values["width.peripheral_data_width"])

    def test_the_watchdog_bound_is_the_declared_capability(self) -> None:
        profile = load_component_profile(ROOT / GPIO_PROFILE)
        declared = int(profile.capabilities["max_wait_cycles"])
        self.assertEqual(declared, self.bounded_values["watchdog.max_wait_cycles"],
                         "the harness must enforce the wait bound the profile declares")
        self.assertEqual(declared, DECLARED_WAIT_BOUND)
        self.assertEqual(0, self.bounded_values["watchdog.stalled.max_wait_cycles"],
                         "and the unbounded control really has no bound")

    def test_the_run_artifact_records_both_runs(self) -> None:
        document = json.loads((RUN_ROOT / "mmio_infrastructure_run.json").read_text(
            encoding="utf-8"))
        self.assertEqual("OK", document["bounded_run"]["status"])
        self.assertEqual("TIMEOUT", document["unbounded_run"]["status"])
        self.assertEqual(set(HARNESS_SOURCES), set(document["build"]["sources"]))
        self.assertEqual(document["plan_narrowing"], build_soc_fabric(
            fabric_spec(), fabric_execution())["address_narrowers"])


if __name__ == "__main__":
    unittest.main()
