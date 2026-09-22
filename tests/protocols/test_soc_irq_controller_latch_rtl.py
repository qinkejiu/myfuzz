"""Behavioural RTL test for the ``LATCH_MASK`` behaviour of ``soc_irq_controller``.

``soc_irq_controller_tb.sv`` pins the controller's original level-for-every-
source behaviour and must keep passing unchanged.  This module pins the
*addition*: a source declared latched in ``LATCH_MASK`` has a set-dominant
pending bit that only CLAIM clears, which is what lets a bounded pulse (a
peripheral's one-cycle event output, or the output of ``soc_irq_edge_detect``)
survive until software services it.

The same bench is compiled with four masks, and the mask that leaves a source
unlatched is the negative control: the identical one-cycle pulse must then be
gone by the time the CPU could claim it.  Without that control the latch
scenarios would prove nothing.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src" / "myfuzz" / "protocols" / "rtl" / "soc_irq_controller.sv"
TESTBENCH = ROOT / "tests" / "fixtures" / "rtl" / "soc_irq_controller_latch_tb.sv"
TOP = "soc_irq_controller_latch_tb"

COMPILE_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 60

#: ``(label, LATCH_MASK, what the mask means)``.  ``mask`` 0 is the control.
PARAMETERIZATIONS = (
    ("latched-source-1", 0b01, "source 1 latched, source 2 level-following"),
    ("no-latch-control", 0b00, "both sources level-following: the pulse is dropped"),
    ("both-latched", 0b11, "both sources latched"),
    ("latched-source-2", 0b10, "source 2 latched, source 1 level-following"),
)

RESULT_LINE = re.compile(r"^RESULT: (PASS|FAIL.*)$")


def compile_and_run(directory: Path, label: str, mask: int
                    ) -> subprocess.CompletedProcess[str]:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    if iverilog is None or vvp is None:  # pragma: no cover - guarded by skipUnless
        raise unittest.SkipTest("Icarus Verilog is not installed")
    executable = directory / f"{label}.vvp"
    compiled = subprocess.run(
        [iverilog, "-g2012", "-s", TOP, "-P", f"{TOP}.LATCH_MASK=2'b{mask:02b}",
         "-o", str(executable), str(RTL), str(TESTBENCH)],
        cwd=ROOT, text=True, capture_output=True, timeout=COMPILE_TIMEOUT_SECONDS)
    if compiled.returncode != 0:
        raise AssertionError(f"{label}: iverilog failed\n{compiled.stdout}{compiled.stderr}")
    return subprocess.run([str(executable)], cwd=ROOT, text=True, capture_output=True,
                          timeout=RUN_TIMEOUT_SECONDS)


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class SocIrqControllerLatchTests(unittest.TestCase):
    def test_every_declared_mask_passes_the_latch_bench(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for label, mask, meaning in PARAMETERIZATIONS:
                with self.subTest(mask=label, meaning=meaning):
                    executed = compile_and_run(directory, label, mask)
                    results = [line.strip() for line in executed.stdout.splitlines()
                               if line.strip().startswith("RESULT:")]
                    self.assertEqual(["RESULT: PASS"], results,
                                     f"{label} ({meaning}):\n{executed.stdout}")
                    self.assertEqual(0, executed.returncode,
                                     f"{label}: vvp exit\n{executed.stdout}{executed.stderr}")

    def test_the_latch_scenarios_really_need_the_mask(self) -> None:
        """The control mask must fail the latch expectations, or S1 is vacuous.

        ``LATCH_MASK=0`` is compiled with the bench's latch expectations forced
        on by declaring every source latched through the testbench parameter
        while the DUT is built unlatched.  The bench's own S1 check must then
        report a failure.
        """
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            # Build the DUT with no latch but ask the bench for the latched
            # expectations by flipping only the bench-side copy of the mask: the
            # bench derives its expectations from its own parameter, and the DUT
            # gets `LATCH_MASK` through `-P` as well, so the honest way to force
            # the mismatch is to mutate the RTL copy to ignore the parameter.
            mutated = directory / "soc_irq_controller.sv"
            text = RTL.read_text(encoding="utf-8")
            self.assertIn("if (LATCH_MASK[sample_index])", text)
            mutated.write_text(text.replace("if (LATCH_MASK[sample_index])",
                                            "if (1'b0)", 1), encoding="utf-8")
            iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
            executable = directory / "ignores-mask.vvp"
            compiled = subprocess.run(
                [iverilog, "-g2012", "-s", TOP, "-P", f"{TOP}.LATCH_MASK=2'b01",
                 "-o", str(executable), str(mutated), str(TESTBENCH)],
                cwd=ROOT, text=True, capture_output=True, timeout=COMPILE_TIMEOUT_SECONDS)
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            executed = subprocess.run([str(executable)], cwd=ROOT, text=True,
                                      capture_output=True, timeout=RUN_TIMEOUT_SECONDS)
            results = [line.strip() for line in executed.stdout.splitlines()
                       if line.strip().startswith("RESULT:")]
            self.assertTrue(results and results[0].startswith("RESULT: FAIL"),
                            f"a controller that ignores LATCH_MASK was not detected\n"
                            f"{executed.stdout}")
            self.assertIn("CHECK-FAIL: S1", executed.stdout)

    def test_the_parameter_default_preserves_the_original_behaviour(self) -> None:
        """A caller that never mentions the mask gets the level-only controller."""
        text = RTL.read_text(encoding="utf-8")
        self.assertIn("parameter logic [NUM_SOURCES-1:0] LATCH_MASK = "
                      "{NUM_SOURCES{1'b0}}", text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
