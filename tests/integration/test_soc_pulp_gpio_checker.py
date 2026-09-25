"""Real-RTL calibration for the PULP GPIO checker and generated binding."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_ibex_pulp_dual_profile import load_dual_request


CHECKER = ROOT / "src/myfuzz/protocols/rtl/soc_pulp_gpio_checker.sv"
BENCH = ROOT / "tests/integration/rtl/soc_pulp_gpio_checker_tb.sv"
GPIO_RTL = ROOT / "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv"
GPIO_SOURCE = "src/myfuzz/protocols/rtl/soc_pulp_gpio_checker.sv"
MANIFEST = ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json"


def dual_plan(drive_profile="cpu_execute"):
    return build_composition(load_dual_request(), base_dir=ROOT,
                             drive_profile=drive_profile)


class PulpGpioCheckerTests(unittest.TestCase):
    def test_manifest_roles_and_generated_feedback_mapping(self):
        plan = dual_plan()
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        properties = document["properties"]
        enabled = {row["bit"] for row in properties
                   if row["property_id"].startswith("GPIO.")
                   and row["status"] == "active"}
        self.assertEqual(set(range(21, 32)), enabled)
        self.assertTrue(all(properties[bit]["status"] == "not_assessed"
                            and properties[bit]["binding"] is None
                            for bit in range(32, 36)))
        for bit in range(21, 32):
            self.assertEqual("u_checker_gpio0", properties[bit]["binding"])
            self.assertEqual("source_derived", properties[bit]["basis_kind"])
            self.assertIn("probe", properties[bit]["basis"].lower())

        rendered = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertFalse(plan.interrupt_plan.present)
        self.assertNotIn("soc_interrupt_controller", rendered)
        self.assertIn(".irq_external_i(1'b0)", rendered)
        self.assertIn("soc_pulp_gpio_checker u_checker_gpio0 (", rendered)
        self.assertIn(".paddr_i(gpio0__paddr[11:0])", rendered)
        self.assertIn(".gpio_in_i(gpio0__gpio_in)", rendered)
        self.assertIn(".gpio_out_i(gpio0__gpio_out)", rendered)
        self.assertIn(".gpio_dir_i(gpio0__gpio_dir)", rendered)
        self.assertIn(".gpio_padcfg_i(gpio0__gpio_padcfg)", rendered)
        self.assertIn(".gpio_in_sync_i(gpio0__gpio_in_sync)", rendered)
        self.assertIn(".interrupt_i(gpio0__interrupt)", rendered)
        for bit in range(21, 32):
            self.assertIn(f"checker_gpio0_eval[{bit - 21}]", rendered)
        self.assertIn("checker_eval_o[21] = checker_gpio0_eval[0]", rendered)
        self.assertIn("checker_fail_o[31] = checker_gpio0_fail[10]", rendered)
        for bit in range(32, 36):
            self.assertNotIn(f"checker_eval_o[{bit}] =", rendered)
            self.assertNotIn(f"checker_fail_o[{bit}] =", rendered)

        sources = source_list(plan)
        self.assertIn({"path": GPIO_SOURCE, "role": "checker_monitor",
                       "owner": "soc_top"}, sources)
        self.assertTrue(CHECKER.is_file())

    @unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                         "set MYFUZZ_SOC_REAL=1 for real RTL calibration")
    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_locked_gpio_rtl_and_checker_golden_plus_exact_mutants(self):
        for source in (CHECKER, BENCH, GPIO_RTL):
            self.assertTrue(source.is_file(), source)
        with tempfile.TemporaryDirectory() as tmp:
            command = [
                "verilator", "--binary", "--timing", "--top-module",
                "soc_pulp_gpio_checker_tb", "-Wno-fatal", "-Wno-lint",
                "--Mdir", tmp, str(CHECKER), str(GPIO_RTL), str(BENCH),
            ]
            built = subprocess.run(command, cwd=ROOT, text=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=False)
            self.assertEqual(0, built.returncode, built.stdout)
            result = subprocess.run(
                [str(Path(tmp) / "Vsoc_pulp_gpio_checker_tb")], cwd=ROOT,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("PULP_GPIO_CHECKER_PASS", result.stdout)

    @unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                         "set MYFUZZ_SOC_REAL=1 for generated SoC closure")
    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_generated_top_compilation_closure_and_source_digest(self):
        from myfuzz.composition.soc_runtime import build_profile_runtime

        # BFM-isolated declares the real synthetic MMIO input segment, so the
        # profile runtime has a non-empty raw ABI while holding the CPU reset.
        plan = dual_plan("bfm_isolated")
        generated = render_composition(plan)["myfuzz_soc_top.sv"]
        with tempfile.TemporaryDirectory() as tmp:
            source_paths = [item["path"] for item in source_list(plan)
                            if item["role"] != "include_root"]
            self.assertIn(GPIO_SOURCE, source_paths)
            build = build_profile_runtime(
                plan, output_dir=Path(tmp) / "runtime", base_dir=ROOT,
                top_text=generated, sources=source_paths,
                timeout_seconds=1800,
            )
            self.assertIn(GPIO_SOURCE, build.sources)
            self.assertEqual(
                "sha256:" + hashlib.sha256(CHECKER.read_bytes()).hexdigest(),
                build.source_hashes[GPIO_SOURCE],
            )
            self.assertTrue(build.executable.is_file())


if __name__ == "__main__":
    unittest.main()
