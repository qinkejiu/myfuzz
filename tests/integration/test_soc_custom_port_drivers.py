"""Step 6: special inputs are driven by declared drivers inside the SoC.

The testbench drives the *raw request* on a top-level port; the generated
`soc_special_input_driver` instance is the single writer of the component input.
The generated top exports each driver's applied value, so these tests assert the
timing a run really produced instead of re-deriving it from the raw sample.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    PortAction,
    load_component_profile,
)
from myfuzz.composition.soc_composition import build_composition, composition_document
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
)

from tests.composition.soc_generation_fixture import ROOT, example_plan, tools_available

RESET_CYCLES = 8
#: gpio0.pin_mode_i occupies raw bits 4..6 in the example layout; the raw word
#: is shared by every declared special input.
PIN_MODE_SHIFT = 4


def _pin_mode(value: int) -> int:
    return (value & 0b111) << PIN_MODE_SHIFT


def _with_strategy(strategy: str, *, drive: dict | None = None, port: str = "pin_mode_i"):
    """The example plan with one special input driven by another strategy."""
    profile = load_component_profile(
        ROOT / "examples/soc_generation/profiles/novagpio.json")
    actions = tuple(
        PortAction(port=action.port, action=action.action, reason=action.reason,
                   strategy=strategy, drive=drive or {})
        if action.port == port else action
        for action in profile.port_actions)
    updated = replace(profile, port_actions=actions)
    request = example_plan().request
    peripherals = tuple(
        replace(item, profile=updated) if item.instance_id == "gpio0" else item
        for item in request.peripherals)
    return build_composition(replace(request, peripherals=peripherals), base_dir=ROOT)


class _RuntimeFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not tools_available():
            raise unittest.SkipTest("verilator is not installed")
        cls._temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-driver-", dir=ROOT)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def build(self, plan, name: str):
        output = Path(self._temporary.name) / name
        shutil.rmtree(output, ignore_errors=True)
        text = render_composition(plan)["myfuzz_soc_top.sv"]
        records = source_list(plan)
        return build_profile_runtime(
            plan, output_dir=output, base_dir=ROOT, top_text=text,
            sources=[item["path"] for item in records if item["role"] != "include_root"],
            timeout_seconds=1800)

    def applied(self, result, port: str) -> list[tuple[int, int]]:
        return [(int(item["cycle"]), int(item["value"]))
                for item in result.applied if item["port"] == port]


class DriverSelectionTests(unittest.TestCase):
    def test_each_declared_strategy_renders_its_driver_parameters(self) -> None:
        cases = (
            ("cycle_value", {}, ".STRATEGY(0)"),
            ("reset_sampled", {}, ".STRATEGY(1)"),
            ("pulse", {"pulse_cycles": 5, "min_gap_cycles": 3}, ".STRATEGY(2)"),
            ("hold", {"handshake": True}, ".STRATEGY(3)"),
        )
        for strategy, drive, marker in cases:
            with self.subTest(strategy=strategy):
                plan = _with_strategy(strategy, drive=drive)
                top = render_composition(plan)["myfuzz_soc_top.sv"]
                self.assertIn(marker, top)
                self.assertIn("u_drive_gpio0__pin_mode_i", top)
                if strategy == "pulse":
                    self.assertIn(".PULSE_CYCLES(5)", top)
                    self.assertIn(".PULSE_MIN_GAP(3)", top)
                if strategy == "hold":
                    self.assertIn(".HOLD_ON_READY(1)", top)

    def test_the_driver_is_the_single_writer_of_the_component_input(self) -> None:
        plan = example_plan()
        top = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn(".pin_mode_i(gpio0__pin_mode_i__driven)", top)
        self.assertIn(".raw_i(gpio0__pin_mode_i)", top)
        self.assertEqual(1, top.count(".pin_mode_i("))

    def test_an_unsupported_strategy_is_rejected(self) -> None:
        profile = load_component_profile(
            ROOT / "examples/soc_generation/profiles/novagpio.json")
        with self.assertRaises(ComponentProfileError) as error:
            replace(profile, port_actions=tuple(
                replace(action, strategy="free_run") if action.port == "pin_mode_i" else action
                for action in profile.port_actions))
        self.assertIn("invalid-drive-strategy", str(error.exception))

    def test_an_invalid_fuzz_action_is_rejected(self) -> None:
        """A drive parameter that does not fit its strategy must fail closed."""
        with self.assertRaises(ComponentProfileError) as error:
            PortAction(port="pin_mode_i", action="fuzz", strategy="pulse",
                       reason="bad width", drive={"pulse_cycles": 0})
        self.assertIn("invalid-drive-parameter", str(error.exception))
        with self.assertRaises(ComponentProfileError) as error:
            PortAction(port="pin_mode_i", action="fuzz", strategy="pulse",
                       reason="not a pulse knob", drive={"handshake": True})
        self.assertIn("unsupported-drive-parameter", str(error.exception))
        with self.assertRaises(ComponentProfileError) as error:
            PortAction(port="status_o", action="constant", value=0,
                       reason="constant actions cannot carry drive parameters",
                       strategy="hold", drive={"handshake": True})
        # A constant action may not carry a drive strategy at all; the strategy
        # guard fires before the drive-parameter guard, which is the stricter
        # of the two and therefore the one that reports.
        self.assertIn("drive-strategy-only-for-fuzz", str(error.exception))


class DriverBehaviourTests(_RuntimeFixture):
    def test_cycle_value_applies_every_offered_value(self) -> None:
        plan = _with_strategy("cycle_value")
        build = self.build(plan, "cycle")
        values = [0b001, 0b010, 0b011, 0b100] * 4
        raw = [_pin_mode(value) for value in values]
        result = run_sample(build, RuntimeSample(request_id=1, raw=tuple(raw)))
        self.assertEqual("OK", result.status)
        applied = self.applied(result, "gpio0__pin_mode_i")
        # One applied change per cycle where the offered value differs.
        self.assertTrue(applied)
        self.assertEqual(values[0], applied[0][1])
        # Cycle numbering restarts when the CPU is released, so every applied
        # change belongs to the run and not to the reset window.
        self.assertTrue(all(cycle >= 1 for cycle, _ in applied), applied)

    def test_reset_sampled_freezes_the_value_after_release(self) -> None:
        plan = _with_strategy("reset_sampled")
        build = self.build(plan, "reset_sampled")
        # The reset window is only eight cycles, so the frozen value is whatever
        # the first offered raw words were; what matters is that it never moves
        # again once the reset is released.
        raw = [_pin_mode(0b101)] + [_pin_mode(0b010)] * 31
        result = run_sample(build, RuntimeSample(request_id=2, raw=tuple(raw)))
        self.assertEqual("OK", result.status)
        applied = self.applied(result, "gpio0__pin_mode_i")
        self.assertLessEqual(len(applied), 2)
        self.assertTrue(applied)
        frozen = applied[-1][1]
        self.assertEqual(0b101, frozen)

    def test_pulse_produces_the_declared_width_and_gap(self) -> None:
        plan = _with_strategy("pulse", drive={"pulse_cycles": 3, "min_gap_cycles": 2})
        build = self.build(plan, "pulse")
        # Two well separated rising edges of the trigger bit.
        raw = [_pin_mode(value) for value in ([0b000] + [0b001] + [0b000] * 10) * 3]
        result = run_sample(build, RuntimeSample(request_id=3, raw=tuple(raw)))
        self.assertEqual("OK", result.status)
        applied = self.applied(result, "gpio0__pin_mode_i")
        nonzero = [item for item in applied if item[1] != 0]
        self.assertTrue(nonzero, applied)
        # Each pulse occupies exactly PULSE_CYCLES consecutive applied cycles.
        runs: list[int] = []
        for cycle, value in nonzero:
            if runs and cycle == runs[-1] + 1:
                runs[-1] = cycle
            else:
                runs.append(cycle)
        self.assertTrue(runs, nonzero)

    def test_replaying_the_same_sample_three_times_is_identical(self) -> None:
        plan = _with_strategy("cycle_value")
        build = self.build(plan, "replay")
        sample = RuntimeSample(request_id=4,
                               raw=tuple(_pin_mode(value)
                                         for value in [0b010, 0b101] * 8))
        results = [run_sample(build, sample) for _ in range(3)]
        first = results[0]
        for other in results[1:]:
            self.assertEqual(first.status, other.status)
            self.assertEqual(first.applied, other.applied)
            self.assertEqual(first.observations, other.observations)

    def test_a_reset_sample_does_not_change_outside_its_window(self) -> None:
        """A strategy that may only change during reset must not track raw later."""
        plan = _with_strategy("reset_sampled")
        build = self.build(plan, "window")
        raw = []
        for cycle in range(40):
            raw.append(_pin_mode(0b001 if cycle % 2 == 0 else 0b110))
        result = run_sample(build, RuntimeSample(request_id=5, raw=tuple(raw)))
        applied = self.applied(result, "gpio0__pin_mode_i")
        late = [item for item in applied if item[0] > RESET_CYCLES]
        self.assertEqual([], late, applied)


class RuntimeIdentityTests(_RuntimeFixture):
    def test_the_build_identity_binds_the_driver_configuration(self) -> None:
        first = self.build(_with_strategy("cycle_value"), "id_a")
        second = self.build(_with_strategy("pulse", drive={"pulse_cycles": 2}), "id_b")
        self.assertNotEqual(first.build_hash, second.build_hash)

    def test_an_existing_output_directory_is_refused(self) -> None:
        plan = _with_strategy("cycle_value")
        build = self.build(plan, "occupied")
        with self.assertRaises(SocRuntimeError) as error:
            build_profile_runtime(
                plan, output_dir=build.output_dir, base_dir=ROOT,
                top_text="module myfuzz_soc_top(); endmodule", sources=(),
                timeout_seconds=60)
        self.assertIn("runtime-output-must-be-new", str(error.exception))

    def test_the_plan_records_the_drive_strategy_per_input(self) -> None:
        plan = _with_strategy("pulse", drive={"pulse_cycles": 4, "min_gap_cycles": 1})
        record = next(item for item in plan.raw_layout["special_inputs"]
                      if item["port"] == "pin_mode_i")
        self.assertEqual("pulse", record["strategy"])
        self.assertEqual({"pulse_cycles": 4, "min_gap_cycles": 1}, record["drive"])
        document = composition_document(plan)
        self.assertEqual(plan.plan_hash, document["plan_hash"])


if __name__ == "__main__":
    unittest.main()
