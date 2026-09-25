"""Calibrate protocol feedback against good and deliberately faulty traces."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_checker_profile import load_checker_profile
from myfuzz.composition.soc_profile_renderer import SocRenderError
from tests.integration.test_soc_ibex_pulp_dual_profile import load_dual_request
from tests.composition.soc_generation_fixture import ROOT


SOURCES = [ROOT / f"src/myfuzz/protocols/rtl/soc_{name}_checker.sv"
           for name in ("obi", "apb3", "fabric")]
BENCH = ROOT / "tests/integration/rtl/soc_protocol_checkers_tb.sv"


class ProtocolCheckerTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_good_trace_and_single_fault_mutants(self):
        for source in (*SOURCES, BENCH):
            self.assertTrue(source.is_file(), source)
        with tempfile.TemporaryDirectory() as tmp:
            command = ["verilator", "--binary", "--timing", "--top-module",
                       "soc_protocol_checkers_tb", "-Wno-fatal", "--Mdir", tmp,
                       *(str(source) for source in SOURCES), str(BENCH)]
            built = subprocess.run(command, cwd=ROOT, text=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(0, built.returncode, built.stdout)
            result = subprocess.run([str(Path(tmp) / "Vsoc_protocol_checkers_tb")],
                                    cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("PROTOCOL_CHECKERS_PASS", result.stdout)

    def test_active_bits_are_bound_and_sources_published(self):
        plan = build_composition(load_dual_request(), base_dir=ROOT,
                                 drive_profile="cpu_execute")
        manifest = json.loads((ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json")
                              .read_text(encoding="utf-8"))
        active = {row["bit"] for row in manifest["properties"]
                  if row["status"] == "active"}
        self.assertEqual({0, 1, 3, 4, 6, 8, 9, 10, 12, 13, 14, 15}
                         | set(range(21, 32)), active)
        self.assertEqual({"not_assessed"}, {manifest["properties"][bit]["status"]
                                            for bit in (2, 5, 7, 11)})
        rendered = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("soc_obi_checker u_checker_obi_instr", rendered)
        self.assertIn("soc_obi_checker u_checker_obi_data", rendered)
        self.assertIn("u_checker_gpio0_apb (", rendered)
        self.assertIn("u_checker_spi0_apb (", rendered)
        self.assertIn("u_checker_fabric (", rendered)
        self.assertIn("checker_fail_o[15]", rendered)
        self.assertEqual({source.as_posix().removeprefix(ROOT.as_posix() + "/")
                          for source in SOURCES} |
                         {"src/myfuzz/protocols/rtl/soc_pulp_gpio_checker.sv"},
                         {row["path"] for row in source_list(plan)
                          if row["role"] == "checker_monitor"})

    def test_active_manifest_binding_must_name_the_rendered_instance(self):
        plan = build_composition(load_dual_request(), base_dir=ROOT,
                                 drive_profile="cpu_execute")
        manifest = json.loads((ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json")
                              .read_text(encoding="utf-8"))
        manifest["properties"][14]["binding"] = "unconnected_fabric_checker"
        profile = load_checker_profile(manifest, plan)
        with self.assertRaisesRegex(SocRenderError, "checker-binding-mismatch"):
            render_composition(plan, checker_profile=profile)

    def test_not_assessed_protocol_bit_is_tied_low(self):
        plan = build_composition(load_dual_request(), base_dir=ROOT,
                                 drive_profile="cpu_execute")
        manifest = json.loads((ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json")
                              .read_text(encoding="utf-8"))
        manifest["properties"][0].update(status="not_assessed", binding=None,
                                          reason="calibration-withdrawn")
        profile = load_checker_profile(manifest, plan)
        top = render_composition(plan, checker_profile=profile)["myfuzz_soc_top.sv"]
        self.assertNotIn("checker_eval_o[0] =", top)
        self.assertIn("checker_eval_o[1] = checker_obi_instr_eval[1]", top)


if __name__ == "__main__":
    unittest.main()
