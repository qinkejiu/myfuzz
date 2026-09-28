"""PULP SPI checker profile, renderer binding and real-RTL calibration."""

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
from myfuzz.composition.soc_structure_audit import audit_structure
from tests.composition.soc_generation_fixture import ROOT
from tests.integration.test_soc_ibex_pulp_dual_profile import load_dual_request


MANIFEST = ROOT / "configs/soc/checkers/ibex_pulp_gpio_spi.json"
CHECKER_SOURCE = "src/myfuzz/protocols/rtl/soc_pulp_spi_checker.sv"
CHECKER = ROOT / CHECKER_SOURCE
BENCH = ROOT / "tests/integration/rtl/soc_pulp_spi_checker_tb.sv"
PULP_SOURCES = (
    "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    "third_party/soc-pulp-apb-spi/spi_master_apb_if.sv",
    "third_party/soc-pulp-axi-spi/spi_master_clkgen.sv",
    "third_party/soc-pulp-axi-spi/spi_master_controller.sv",
    "third_party/soc-pulp-axi-spi/spi_master_fifo.sv",
    "third_party/soc-pulp-axi-spi/spi_master_rx.sv",
    "third_party/soc-pulp-axi-spi/spi_master_tx.sv",
    "src/myfuzz/protocols/rtl/soc_pulp_spi_peer.sv",
)
ACTIVE_SPI_BITS = set(range(41, 47))


def dual_plan(drive_profile: str = "cpu_execute"):
    return build_composition(load_dual_request(), base_dir=ROOT,
                             drive_profile=drive_profile)


class PulpSpiCheckerRendererTests(unittest.TestCase):
    def test_only_calibrated_spi_properties_bind_to_the_real_boundary(self):
        plan = dual_plan()
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        properties = document["properties"]
        active = {row["bit"] for row in properties
                  if row["property_id"].startswith("SPI.")
                  and row["status"] == "active"}
        self.assertEqual(ACTIVE_SPI_BITS, active)
        for bit in sorted(ACTIVE_SPI_BITS):
            row = properties[bit]
            self.assertEqual("u_checker_spi0", row["binding"])
            self.assertIn(row["basis_kind"], {"standard", "independent_reference"})
            self.assertTrue(row["basis"])
            self.assertIsNone(row["reason"])
        for bit in set(range(36, 50)) - ACTIVE_SPI_BITS:
            row = properties[bit]
            self.assertEqual("not_assessed", row["status"])
            self.assertIsNone(row["binding"])
            self.assertTrue(row["reason"])

        rendered = render_composition(plan)["myfuzz_soc_top.sv"]
        self.assertIn("soc_pulp_spi_checker u_checker_spi0 (", rendered)
        self.assertIn(".paddr_i(spi0__paddr[11:0])", rendered)
        self.assertIn(".psel_i(spi0__psel)", rendered)
        self.assertIn(".prdata_i(spi0__prdata)", rendered)
        self.assertIn(".sck_i(spi0__spi_clk)", rendered)
        self.assertIn(".csn0_i(spi0__spi_csn0)", rendered)
        self.assertIn(".mode_i(spi0__spi_mode)", rendered)
        self.assertIn(".sdo0_i(spi0__spi_sdo0)", rendered)
        self.assertIn(".sdi1_i(spi0__spi_sdi1)", rendered)
        for bit in sorted(ACTIVE_SPI_BITS):
            self.assertIn(f"checker_eval_o[{bit}] = checker_spi0_eval[{bit - 36}]",
                          rendered)
            self.assertIn(f"checker_fail_o[{bit}] = checker_spi0_fail[{bit - 36}]",
                          rendered)
        for bit in set(range(36, 50)) - ACTIVE_SPI_BITS:
            self.assertNotIn(f"checker_eval_o[{bit}] =", rendered)
            self.assertNotIn(f"checker_fail_o[{bit}] =", rendered)

        records = source_list(plan)
        self.assertIn({"path": CHECKER_SOURCE, "role": "checker_monitor",
                       "owner": "soc_top"}, records)
        source_paths = [item["path"] for item in records
                        if item["role"] != "include_root"]
        include_roots = [item["path"] for item in records
                         if item["role"] == "include_root"]
        audit = audit_structure(plan, top_text=rendered, source_files=source_paths,
                                base_dir=ROOT, include_roots=include_roots)
        self.assertEqual("pass", next(
            item["status"] for item in audit["findings"]
            if item["check_id"] == "observation_outputs"), audit)

    @unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                         "set MYFUZZ_SOC_REAL=1 for generated SoC closure")
    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_generated_top_source_list_and_digest_include_spi_checker(self):
        from myfuzz.composition.soc_runtime import build_profile_runtime

        plan = dual_plan("bfm_isolated")
        generated = render_composition(plan)["myfuzz_soc_top.sv"]
        with tempfile.TemporaryDirectory() as tmp:
            paths = [item["path"] for item in source_list(plan)
                     if item["role"] != "include_root"]
            build = build_profile_runtime(
                plan, output_dir=Path(tmp) / "runtime", base_dir=ROOT,
                top_text=generated, sources=paths, timeout_seconds=1800,
            )
            self.assertIn(CHECKER_SOURCE, build.sources)
            self.assertEqual(
                "sha256:" + hashlib.sha256(CHECKER.read_bytes()).hexdigest(),
                build.source_hashes[CHECKER_SOURCE],
            )
            self.assertTrue(build.executable.is_file())

    @unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                         "set MYFUZZ_SOC_REAL=1 for real RTL calibration")
    @unittest.skipUnless(shutil.which("verilator"), "Verilator required")
    def test_locked_pulp_spi_checker_golden_and_boundary_mutants(self):
        for source in (CHECKER, BENCH, *(ROOT / item for item in PULP_SOURCES)):
            self.assertTrue(source.is_file(), source)
        with tempfile.TemporaryDirectory() as tmp:
            command = [
                "verilator", "--binary", "--timing", "--top-module",
                "soc_pulp_spi_checker_tb", "-Wno-fatal", "-Wno-lint",
                "--Mdir", tmp, *(str(ROOT / item) for item in PULP_SOURCES),
                str(CHECKER), str(BENCH),
            ]
            built = subprocess.run(command, cwd=ROOT, text=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=False)
            self.assertEqual(0, built.returncode, built.stdout)
            result = subprocess.run(
                [str(Path(tmp) / "Vsoc_pulp_spi_checker_tb")], cwd=ROOT,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                check=False)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn("PULP_SPI_CHECKER_ALL_PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
