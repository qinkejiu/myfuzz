"""P10 renderer/preflight tests.

The structural tests are always runnable.  The opt-in test deliberately only
checks the fail-closed dependency boundary; a source checkout being present is
not counted as real CPU/IP runtime acceptance.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.composition.soc_renderer import SocRenderError, render_soc
from myfuzz.composition.soc_stimulus import compile_soc_stimulus
from myfuzz.integration.rfuzz_simulator import probe_soc_dependencies

from tests.composition.test_soc_stimulus import plan_fixture, policy


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs/soc/ibex-pulp.json"


class SocRendererTests(unittest.TestCase):
    def test_ibex_pulp_profile_has_two_distinct_pulp_ips_and_explicit_contracts(self):
        document = json.loads(CONFIG.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], "soc_render_config.v1")
        self.assertEqual(document["cpu"]["top_module"], "ibex_top")
        self.assertEqual({item["id"] for item in document["peripherals"]},
                         {"pulp_gpio", "pulp_spi"})
        self.assertEqual(len(document["environment_links"]), 2)
        self.assertEqual(len(document["interrupt_routes"]), 2)
        self.assertTrue(document["acceptance"]["requires_real_cpu"])

    def test_render_is_deterministic_and_contains_source_backed_harness(self):
        plan = plan_fixture()
        stimulus = compile_soc_stimulus(plan, policy())
        first = render_soc(plan, stimulus)
        second = render_soc(plan, stimulus)
        self.assertEqual(first, second)
        self.assertIn("ibex_top", first["soc_top.sv"])
        self.assertIn("fuzz_spi_peer", first["soc_top.sv"])
        self.assertIn("soc_irq_router", first["soc_top.sv"])
        manifest = json.loads(first["soc_manifest.json"])
        self.assertEqual(manifest["schema_version"], "soc_render.v1")
        self.assertEqual(manifest["real_cpu"]["status"], "source_bound_pending_elaboration")
        self.assertTrue(manifest["render_hash"].startswith("sha256:"))

    @unittest.skipUnless(shutil.which("iverilog"), "Icarus is required for structural elaboration")
    def test_generated_environment_top_elaborates_without_python_side_effects(self):
        plan = plan_fixture()
        stimulus = compile_soc_stimulus(plan, policy())
        rendered = render_soc(plan, stimulus)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in rendered.items():
                (root / name).write_text(text, encoding="utf-8")
            result = subprocess.run(
                [shutil.which("iverilog"), "-g2012", "-s", "myfuzz_soc_top", "-o",
                 str(root / "soc.vvp"), str(root / "soc_top.sv"),
                 str(ROOT / "src/myfuzz/protocols/rtl/fuzz_uart_peer.sv"),
                 str(ROOT / "src/myfuzz/protocols/rtl/fuzz_spi_peer.sv"),
                 str(ROOT / "src/myfuzz/protocols/rtl/soc_irq_router.sv")],
                cwd=ROOT, text=True, capture_output=True, timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_renderer_rejects_stale_stimulus_identity(self):
        plan = plan_fixture()
        stimulus = compile_soc_stimulus(plan, policy())
        stimulus["plan_hash"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(SocRenderError, "plan-hash"):
            render_soc(plan, stimulus)


class SocDependencyBoundaryTests(unittest.TestCase):
    def test_probe_reports_missing_without_implicit_skip(self):
        report = probe_soc_dependencies(ROOT, source_paths=("does/not/exist.sv",),
                                        simulator="verilator", require_real=False)
        self.assertFalse(report["ready"])
        self.assertIn("does/not/exist.sv", report["missing"])
        self.assertFalse(report["opt_in"])

    def test_opt_in_missing_dependency_raises(self):
        with self.assertRaisesRegex(RuntimeError, "real SoC dependencies missing"):
            probe_soc_dependencies(ROOT, source_paths=("does/not/exist.sv",),
                                   simulator="verilator", require_real=True)


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for the real Ibex acceptance boundary")
class RealIbexOptInBoundaryTests(unittest.TestCase):
    def test_opt_in_never_silently_skips_missing_default_dependencies(self):
        report = probe_soc_dependencies(ROOT, require_real=True)
        self.assertTrue(report["ready"], report)
        self.assertEqual(report["status"], "ready")


if __name__ == "__main__":
    unittest.main()
