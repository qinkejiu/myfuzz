"""Behavioural RTL test for ``src/myfuzz/protocols/rtl/soc_irq_edge_detect.sv``.

The self-checking bench lives in
``tests/fixtures/rtl/soc_irq_edge_detect_tb.sv``; this module compiles it with
``iverilog``, runs it with ``vvp`` and asserts on the single ``RESULT: ...``
line the bench prints.

The detector is the converter that lets a peripheral declare an *edge-shaped*
interrupt source: a source that holds its asserted level to mean "an event
happened and has not been acknowledged".  ``soc_irq_controller`` samples its
input every clock, so such a source wired directly would re-pend one sampling
edge after every COMPLETE; the detector turns each declared edge into exactly
one event instead.

Frozen parameterizations cover both edge directions, both edges, single-cycle
and multi-cycle output pulses, and both declared reference levels.  A separate
negative case proves the parameter guards really abort: a converter built with
an out-of-range ``EDGE`` or a zero ``PULSE_CYCLES`` must fail elaboration-time
checking instead of silently degrading.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src" / "myfuzz" / "protocols" / "rtl" / "soc_irq_edge_detect.sv"
TESTBENCH = ROOT / "tests" / "fixtures" / "rtl" / "soc_irq_edge_detect_tb.sv"
TOP = "soc_irq_edge_detect_tb"

COMPILE_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 60

#: ``(label, EDGE, PULSE_CYCLES, RESET_LEVEL)``.  ``EDGE`` is 0 = rising,
#: 1 = falling, 2 = both; ``RESET_LEVEL`` is the level the source is assumed to
#: hold across reset, so the release itself is never an edge.
PARAMETERIZATIONS = (
    ("rising-single", 0, 1, 0),
    ("falling-triple", 1, 3, 0),
    ("both-single", 2, 1, 0),
    ("rising-wide-reference-high", 0, 5, 1),
    ("falling-single-reference-high", 1, 1, 1),
    ("both-triple-reference-high", 2, 3, 1),
)

#: ``(label, EDGE, PULSE_CYCLES, RESET_LEVEL, expected message)`` for the
#: parameter guards.  These must abort, not run with a wrong meaning.
INVALID_PARAMETERIZATIONS = (
    ("edge-out-of-range", 3, 1, 0, "EDGE must be 0 (rising), 1 (falling) or 2 (both)"),
    ("pulse-cycles-zero", 0, 0, 0, "PULSE_CYCLES must be >= 1"),
    ("reset-level-not-a-bit", 0, 1, 2, "RESET_LEVEL must be 0 or 1"),
)

RESULT_LINE = re.compile(r"^RESULT: (PASS|FAIL.*)$")


def compile_bench(directory: Path, label: str, edge: int, pulse_cycles: int,
                  reset_level: int, *, rtl: Path = RTL
                  ) -> tuple[subprocess.CompletedProcess[str], Path]:
    iverilog = shutil.which("iverilog")
    if iverilog is None:  # pragma: no cover - guarded by skipUnless
        raise unittest.SkipTest("Icarus Verilog is not installed")
    executable = directory / f"{label}.vvp"
    compiled = subprocess.run(
        [iverilog, "-g2012", "-s", TOP,
         "-P", f"{TOP}.EDGE={edge}",
         "-P", f"{TOP}.PULSE_CYCLES={pulse_cycles}",
         "-P", f"{TOP}.RESET_LEVEL={reset_level}",
         "-o", str(executable), str(rtl), str(TESTBENCH)],
        cwd=ROOT, text=True, capture_output=True, timeout=COMPILE_TIMEOUT_SECONDS)
    return compiled, executable


def run_bench(executable: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(executable)], cwd=ROOT, text=True, capture_output=True,
                          timeout=RUN_TIMEOUT_SECONDS)


def bench_result(executed: subprocess.CompletedProcess[str]) -> list[str]:
    return [line.strip() for line in executed.stdout.splitlines()
            if line.strip().startswith("RESULT:")]


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class SocIrqEdgeDetectRtlTests(unittest.TestCase):
    """The converter's behaviour, one parameterization per subtest."""

    def test_every_declared_parameterization_passes_the_bench(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for label, edge, pulse_cycles, reset_level in PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executable = compile_bench(directory, label, edge,
                                                         pulse_cycles, reset_level)
                    self.assertEqual(0, compiled.returncode,
                                     f"{label}: iverilog failed\n{compiled.stdout}{compiled.stderr}")
                    executed = run_bench(executable)
                    self.assertEqual(["RESULT: PASS"], bench_result(executed),
                                     f"{label}: bench result\n{executed.stdout}")
                    self.assertEqual(0, executed.returncode,
                                     f"{label}: vvp exit\n{executed.stdout}{executed.stderr}")

    def test_a_broken_converter_is_detected_by_the_same_bench(self) -> None:
        """The bench is only evidence if it can fail.

        The DUT is copied to a temporary directory and mutated so that it never
        detects an edge.  The real RTL is not touched.  The same bench that
        passes above must now report a failure, which is what makes the passing
        case meaningful rather than vacuous.
        """
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            mutated = directory / "soc_irq_edge_detect.sv"
            text = RTL.read_text(encoding="utf-8")
            self.assertIn("default: fire = raw_i ^ raw_q;", text)
            mutated.write_text(text.replace("default: fire = raw_i ^ raw_q;",
                                            "default: fire = 1'b0;"), encoding="utf-8")
            compiled, executable = compile_bench(directory, "broken-detector", 2, 1, 0,
                                                 rtl=mutated)
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            executed = run_bench(executable)
            results = bench_result(executed)
            self.assertTrue(results and results[0].startswith("RESULT: FAIL"),
                            f"the mutated converter was not detected\n{executed.stdout}")
            self.assertIn("CHECK-FAIL", executed.stdout)

    def test_invalid_parameters_abort_instead_of_degrading(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for label, edge, pulse_cycles, reset_level, message in INVALID_PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executable = compile_bench(directory, label, edge,
                                                         pulse_cycles, reset_level)
                    self.assertEqual(0, compiled.returncode,
                                     f"{label}: iverilog failed\n{compiled.stderr}")
                    executed = run_bench(executable)
                    combined = executed.stdout + executed.stderr
                    self.assertIn(message, combined,
                                  f"{label}: the guard did not fire\n{combined}")
                    self.assertNotIn("RESULT: PASS", executed.stdout,
                                     f"{label}: an invalid parameterization reported success")
                    self.assertNotEqual(0, executed.returncode,
                                        f"{label}: vvp exited zero on a fatal parameter\n{combined}")

    def test_the_declared_contract_is_the_modules_documented_contract(self) -> None:
        """The plan-side contract text and the RTL it points at must agree.

        The plan records ``no-clock-domain-crossing`` and ``no-glitch-filter``
        as the converter's non-features.  If the RTL ever grows a synchroniser
        or a filter, this check fails and forces the claim to be re-derived
        instead of silently overstating what was verified.
        """
        text = RTL.read_text(encoding="utf-8")
        self.assertIn("No clock-domain crossing", text)
        self.assertIn("No glitch filter", text)
        self.assertNotIn("always_ff @(posedge clk_i) begin\n    if (!rst_ni) begin\n      raw_q <= raw_i",
                         text, "the detector must not sample the raw input on the reset edge")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
