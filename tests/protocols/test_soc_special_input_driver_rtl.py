"""Behavioural RTL test for ``src/myfuzz/protocols/rtl/soc_special_input_driver.sv``.

The self-checking bench lives in
``tests/fixtures/rtl/soc_special_input_driver_tb.sv``; this module only compiles
it together with the DUT using ``iverilog``, runs it with ``vvp`` and asserts on
the single ``RESULT: ...`` line the bench prints.  Every parameterization is a
separate process, and the bench echoes its parameters and the scenario suite it
ran, so a lost or misspelled override cannot silently reduce coverage.

The seven frozen parameterizations cover all four drive strategies:

* ``(WIDTH=1, STRATEGY=0)`` and ``(WIDTH=4, STRATEGY=0)``: ``cycle_value``
  applies offered updates, holds without an offer, has no combinational path from
  ``raw_i`` to ``value_o`` and clears on reset (including a reset in the middle of
  an active offer);
* ``(WIDTH=3, STRATEGY=1)``: ``reset_sampled`` tracks every raw value while reset
  is asserted, latches the value picked in that window on the release edge,
  freezes it while ``raw_i`` walks over every other value for many cycles, applies
  only in the release cycle, and re-opens the window on a second reset;
* ``(WIDTH=1, STRATEGY=2, PULSE_CYCLES=1, PULSE_MIN_GAP=0)`` and
  ``(WIDTH=8, STRATEGY=2, PULSE_CYCLES=5, PULSE_MIN_GAP=3)``: ``pulse`` needs a
  rising edge of ``raw_i[0]`` that ``update_i`` offers, latches its payload for
  exactly ``PULSE_CYCLES`` cycles, ignores requests during the pulse and inside
  the minimum gap (no queueing, no extension, no restart), accepts a request
  exactly at the gap boundary, produces two independent pulses from two
  well-separated requests, and aborts a pulse on reset;
* ``(WIDTH=4, STRATEGY=3, HOLD_ON_READY=1)``: the handshake hold never moves
  while ``hold_ready_i`` is low and updates on the first cycle in which
  ``update_i`` and ``hold_ready_i`` coincide;
* ``(WIDTH=2, STRATEGY=3, HOLD_ON_READY=0)``: every offered update applies and
  ``hold_ready_i`` is ignored.

Two failure controls keep the harness honest: ``NEGATIVE_CONTROL=1`` corrupts
exactly one expectation inside the bench, and the invalid-parameter cases check
that a configuration outside the frozen limits is rejected instead of silently
accepted.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src" / "myfuzz" / "protocols" / "rtl" / "soc_special_input_driver.sv"
TESTBENCH = ROOT / "tests" / "fixtures" / "rtl" / "soc_special_input_driver_tb.sv"
TOP = "soc_special_input_driver_tb"

COMPILE_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 60

#: Bench defaults; a parameterization only has to override what it changes.
DEFAULTS = {
    "WIDTH": 1,
    "STRATEGY": 0,
    "PULSE_CYCLES": 1,
    "PULSE_MIN_GAP": 0,
    "HOLD_ON_READY": 0,
    "NEGATIVE_CONTROL": 0,
}

#: label, overrides, suite the bench must report
PARAMETERIZATIONS = (
    ("w1_cycle_value", {"WIDTH": 1, "STRATEGY": 0}, "cycle_value"),
    ("w4_cycle_value", {"WIDTH": 4, "STRATEGY": 0}, "cycle_value"),
    ("w3_reset_sampled", {"WIDTH": 3, "STRATEGY": 1}, "reset_sampled"),
    ("w1_pulse_c1_g0", {"WIDTH": 1, "STRATEGY": 2, "PULSE_CYCLES": 1, "PULSE_MIN_GAP": 0}, "pulse"),
    ("w8_pulse_c5_g3", {"WIDTH": 8, "STRATEGY": 2, "PULSE_CYCLES": 5, "PULSE_MIN_GAP": 3}, "pulse"),
    ("w4_hold_ready", {"WIDTH": 4, "STRATEGY": 3, "HOLD_ON_READY": 1}, "hold_ready"),
    ("w2_hold_free", {"WIDTH": 2, "STRATEGY": 3, "HOLD_ON_READY": 0}, "hold_free"),
)

#: label, overrides that must be rejected (compile or elaboration)
INVALID_PARAMETERIZATIONS = (
    ("width_zero", {"WIDTH": 0}),
    ("strategy_above_range", {"STRATEGY": 4}),
    ("strategy_below_range", {"STRATEGY": -1}),
    ("pulse_cycles_zero", {"STRATEGY": 2, "PULSE_CYCLES": 0}),
    ("pulse_min_gap_negative", {"STRATEGY": 2, "PULSE_MIN_GAP": -1}),
    ("hold_on_ready_above_range", {"STRATEGY": 3, "HOLD_ON_READY": 2}),
    ("hold_on_ready_below_range", {"STRATEGY": 3, "HOLD_ON_READY": -1}),
)


def result_lines(stdout: str) -> list[str]:
    """Every bench-produced result line, in order."""
    return [line.strip() for line in stdout.splitlines() if line.strip().startswith("RESULT:")]


def assert_simulation_passed(
    case: unittest.TestCase, result: subprocess.CompletedProcess[str], label: str
) -> None:
    """A run passes only with a zero exit status and exactly one PASS line."""
    case.assertEqual(0, result.returncode, f"{label}: vvp exit status\n{result.stdout}{result.stderr}")
    case.assertEqual(["RESULT: PASS"], result_lines(result.stdout), f"{label}: bench result line\n{result.stdout}")


def parameter_echo(parameters: dict[str, int]) -> str:
    """The NOTE line the bench prints for the effective parameterization."""
    effective = dict(DEFAULTS)
    effective.update(parameters)
    return " ".join(f"{key}={effective[key]}" for key in DEFAULTS)


def compile_and_run(
    directory: Path, label: str, parameters: dict[str, int]
) -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str] | None]:
    """Compile the DUT plus bench with iverilog and run it with vvp."""
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    if iverilog is None or vvp is None:  # pragma: no cover - guarded by skipUnless
        raise unittest.SkipTest("Icarus Verilog is not installed")
    executable = directory / f"{label}.vvp"
    overrides = [token for key, value in parameters.items() for token in ("-P", f"{TOP}.{key}={value}")]
    compiled = subprocess.run(
        [iverilog, "-g2012", "-s", TOP, *overrides, "-o", str(executable), str(RTL), str(TESTBENCH)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=COMPILE_TIMEOUT_SECONDS,
    )
    if compiled.returncode != 0:
        return compiled, None
    executed = subprocess.run(
        [vvp, str(executable)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    return compiled, executed


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class SocSpecialInputDriverRtlTests(unittest.TestCase):
    def test_driver_behaviour_passes_for_every_parameterization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, parameters, suite in PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executed = compile_and_run(root, label, parameters)
                    self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    assert_simulation_passed(self, executed, label)
                    self.assertIn(
                        f"NOTE: soc_special_input_driver_tb {parameter_echo(parameters)}", executed.stdout
                    )
                    self.assertIn(f"NOTE: suite={suite}", executed.stdout)

    def test_deliberately_broken_expectation_is_detected(self) -> None:
        """Negative control: a corrupted expectation must not report PASS."""
        with tempfile.TemporaryDirectory() as directory:
            compiled, executed = compile_and_run(
                Path(directory),
                "negative_control",
                {"WIDTH": 4, "STRATEGY": 0, "NEGATIVE_CONTROL": 1},
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            self.assertIsNotNone(executed)
            assert executed is not None
            self.assertNotEqual(0, executed.returncode, "a failing bench must exit non-zero")
            self.assertNotIn("RESULT: PASS", executed.stdout)
            self.assertIn("RESULT: FAIL:", executed.stdout)
            self.assertIn("S0 an idle release leaves value_o clear", executed.stdout)

    def test_invalid_parameters_are_rejected(self) -> None:
        """The DUT must fail closed below and above the frozen parameter limits."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, parameters in INVALID_PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executed = compile_and_run(root, f"invalid_{label}", parameters)
                    if compiled.returncode != 0:
                        continue  # Elaboration rejection is also a valid fail-closed outcome.
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    self.assertNotEqual(0, executed.returncode, "Invalid configuration was silently accepted")
                    self.assertNotIn("RESULT: PASS", executed.stdout)


class SocSpecialInputDriverHarnessNegativeControls(unittest.TestCase):
    """Cheap, tool-free checks that the result parsing really can fail."""

    def test_result_line_parsing_is_strict(self) -> None:
        self.assertEqual(["RESULT: PASS"], result_lines("NOTE: x\nRESULT: PASS\nvvp: $finish called at 1\n"))
        self.assertEqual(["RESULT: FAIL: nope"], result_lines("RESULT: FAIL: nope\nFATAL: x\n"))
        self.assertEqual([], result_lines("nothing to report\n"))

    def test_pass_assertion_rejects_missing_or_extra_results(self) -> None:
        passing = subprocess.CompletedProcess([], 0, "RESULT: PASS\n", "")
        assert_simulation_passed(self, passing, "synthetic")  # must not raise
        for stdout in ("no result line\n", "RESULT: FAIL: broken\n", "RESULT: PASS\nRESULT: FAIL: late\n", ""):
            with self.subTest(stdout=stdout):
                with self.assertRaises(AssertionError):
                    assert_simulation_passed(self, subprocess.CompletedProcess([], 0, stdout, ""), "synthetic")
        with self.assertRaises(AssertionError):
            assert_simulation_passed(self, subprocess.CompletedProcess([], 1, "RESULT: PASS\n", ""), "synthetic")

    def test_parameter_echo_covers_every_frozen_parameter(self) -> None:
        echo = parameter_echo({"WIDTH": 8, "STRATEGY": 2, "PULSE_CYCLES": 5, "PULSE_MIN_GAP": 3})
        self.assertEqual(
            "WIDTH=8 STRATEGY=2 PULSE_CYCLES=5 PULSE_MIN_GAP=3 HOLD_ON_READY=0 NEGATIVE_CONTROL=0", echo
        )


if __name__ == "__main__":
    unittest.main()
