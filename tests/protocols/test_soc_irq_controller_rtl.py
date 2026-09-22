"""Behavioural RTL test for ``src/myfuzz/protocols/rtl/soc_irq_controller.sv``.

The self-checking bench lives in ``tests/fixtures/rtl/soc_irq_controller_tb.sv``;
this module only compiles it together with the DUT using ``iverilog``, runs it
with ``vvp`` and asserts on the single ``RESULT: ...`` line the bench prints.
Two frozen parameterizations are cross-checked:

* ``NUM_SOURCES = 40, ADDRESS_WIDTH = 12``: ``B = 2`` bitmap words and a 6-bit
  source ID, so the complete register suite runs (priority claim, in-service
  exclusion, re-pending, wide IDs in the second bitmap word, ENABLE masking,
  backpressure and reset-in-transaction);
* ``NUM_SOURCES = 1, ADDRESS_WIDTH = 5``: the frozen minimum window.  A 5-bit
  byte address only decodes words 0..7 of the map, so ``ENABLE[0]`` at ``0x24``
  cannot be addressed at all in that configuration.  The bench says so on a NOTE
  line and runs its header-only checks, and the test asserts that it does, so the
  reduced coverage of that configuration is explicit rather than silent.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src" / "myfuzz" / "protocols" / "rtl" / "soc_irq_controller.sv"
TESTBENCH = ROOT / "tests" / "fixtures" / "rtl" / "soc_irq_controller_tb.sv"
TOP = "soc_irq_controller_tb"

COMPILE_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 60

PARAMETERIZATIONS = (
    ("minimum", {"NUM_SOURCES": 1, "ADDRESS_WIDTH": 5}),
    ("wide", {"NUM_SOURCES": 40, "ADDRESS_WIDTH": 12}),
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
class SocIrqControllerRtlTests(unittest.TestCase):
    def test_controller_behaviour_passes_for_both_parameterizations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, parameters in PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executed = compile_and_run(root, label, parameters)
                    self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    assert_simulation_passed(self, executed, label)
                    if label == "wide":
                        self.assertIn("B=2 ID_WIDTH=6 full_suite=1", executed.stdout)
                    else:
                        self.assertIn("full_suite=0", executed.stdout)
                        self.assertIn("window is not addressable", executed.stdout)

    def test_deliberately_broken_expectation_is_detected(self) -> None:
        """Negative control: a corrupted expectation must not report PASS."""
        with tempfile.TemporaryDirectory() as directory:
            compiled, executed = compile_and_run(
                Path(directory), "negative_control", {"NUM_SOURCES": 40, "ADDRESS_WIDTH": 12, "NEGATIVE_CONTROL": 1}
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            self.assertIsNotNone(executed)
            assert executed is not None
            self.assertNotEqual(0, executed.returncode, "a failing bench must exit non-zero")
            self.assertNotIn("RESULT: PASS", executed.stdout)
            self.assertIn("RESULT: FAIL:", executed.stdout)

    def test_invalid_parameters_are_rejected(self) -> None:
        """The bench must fail closed below the frozen parameter limits."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for key, value in (("NUM_SOURCES", 0), ("ADDRESS_WIDTH", 4)):
                with self.subTest(parameter=key, value=value):
                    parameters = {"NUM_SOURCES": 40, "ADDRESS_WIDTH": 12}
                    parameters[key] = value
                    compiled, executed = compile_and_run(root, f"invalid_{key}", parameters)
                    if compiled.returncode != 0:
                        continue  # Elaboration rejection is also a valid fail-closed outcome.
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    self.assertNotEqual(0, executed.returncode, "Invalid configuration was silently accepted")
                    self.assertNotIn("RESULT: PASS", executed.stdout)


class SocIrqControllerHarnessNegativeControls(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
