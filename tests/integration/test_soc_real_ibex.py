"""P10 renderer/preflight and real-source-boundary tests.

The structural tests are always runnable.  The opt-in test deliberately only
checks the fail-closed dependency boundary and generated-top elaboration; a
source checkout being present is not counted as real CPU/IP runtime acceptance.
The separate Verilator smoke fixture records the direct runtime evidence in
``docs/reports/soc-acceptance-20260914.md``.
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

    def test_manifest_exposes_the_real_runtime_closure_without_claiming_runtime(self):
        plan = plan_fixture()
        stimulus = compile_soc_stimulus(plan, policy())
        manifest = json.loads(render_soc(plan, stimulus)["soc_manifest.json"])
        elaboration = manifest["real_elaboration"]
        self.assertEqual("soc_ibex_pulp_core", elaboration["runtime_top"])
        self.assertEqual(["MYFUZZ_ENABLE_REAL_IBEX"], elaboration["defines"])
        self.assertIn(
            "third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv",
            elaboration["source_files"],
        )
        self.assertIn(
            "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
            elaboration["source_files"],
        )
        self.assertLess(
            elaboration["source_files"].index("third_party/rfuzz/upstream/ibex/rtl/ibex_pkg.sv"),
            elaboration["source_files"].index("third_party/rfuzz/upstream/ibex/rtl/ibex_id_stage.sv"),
        )
        self.assertEqual("runtime_unverified", elaboration["runtime_status"])

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

    def test_generated_real_top_elaborates_from_its_declared_closure(self):
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "Verilator is required for the real SoC boundary")
        plan = plan_fixture()
        rendered = render_soc(plan, compile_soc_stimulus(plan, policy()))
        manifest = json.loads(rendered["soc_manifest.json"])
        closure = manifest["real_elaboration"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "soc_top.sv").write_text(rendered["soc_top.sv"], encoding="utf-8")
            command = [
                str(verilator), "--lint-only", "-DMYFUZZ_ENABLE_REAL_IBEX",
                "--top-module", "myfuzz_soc_top", "-Wno-fatal", "-Wno-PINMISSING",
                "-Wno-WIDTHEXPAND", "-Wno-WIDTHTRUNC", "-Wno-MULTIDRIVEN",
                "-Wno-UNSIGNED", "-Wno-CASEINCOMPLETE", "-Wno-LATCH", "-Wno-UNOPTFLAT",
            ]
            command.extend("-I" + item for item in closure["include_dirs"])
            command.extend(
                str(ROOT / item) for item in closure["source_files"] if item.endswith(".sv")
            )
            command.append(str(root / "soc_top.sv"))
            result = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=120,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_source_bound_ibex_pulp_runtime_smoke(self):
        """Run the direct source-backed wrapper from the manifest closure."""
        verilator = shutil.which("verilator")
        self.assertIsNotNone(verilator, "Verilator is required for the real SoC smoke")
        plan = plan_fixture()
        rendered = render_soc(plan, compile_soc_stimulus(plan, policy()))
        manifest = json.loads(rendered["soc_manifest.json"])
        closure = manifest["real_elaboration"]
        source_files = [ROOT / item for item in closure["source_files"]
                        if item.endswith(".sv")]
        self.assertTrue(all(path.is_file() for path in source_files),
                        "manifest contains a missing source file")
        include_dirs = [ROOT / item for item in closure["include_dirs"]]
        include_dirs.extend([
            ROOT / "third_party/soc-pulp-apb-gpio/rtl",
            ROOT / "third_party/soc-pulp-apb-spi",
            ROOT / "third_party/soc-pulp-axi-spi",
            ROOT / "src/myfuzz/composition/rtl",
            ROOT / "src/myfuzz/protocols/rtl",
        ])
        warnings = [
            "-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTHEXPAND",
            "-Wno-WIDTHTRUNC", "-Wno-MULTIDRIVEN", "-Wno-UNSIGNED",
            "-Wno-CASEINCOMPLETE", "-Wno-LATCH", "-Wno-UNOPTFLAT",
        ]
        boot_image = ROOT / "tests/fixtures/soc_ibex_pulp_gpio.hex"
        testbench = ROOT / "tests/integration/rtl/soc_ibex_pulp_tb.sv"
        with tempfile.TemporaryDirectory() as directory:
            obj_dir = Path(directory) / "obj_dir"
            command = [
                str(verilator), "--binary", "--timing", "--top-module",
                "soc_ibex_pulp_tb", "-j", "2", "--Mdir", str(obj_dir),
                *warnings,
            ]
            command.extend("-I" + str(path) for path in include_dirs)
            command.extend(str(path) for path in source_files)
            command.append(str(testbench))
            compiled = subprocess.run(
                command, cwd=ROOT, text=True, capture_output=True, timeout=180,
            )
            self.assertEqual(0, compiled.returncode,
                             compiled.stdout + compiled.stderr)
            binary = obj_dir / "Vsoc_ibex_pulp_tb"
            self.assertTrue(binary.is_file(), "Verilator did not emit the smoke binary")
            result = subprocess.run(
                [str(binary), "+riscv_boot_image=" + str(boot_image)],
                cwd=ROOT, text=True, capture_output=True, timeout=30,
            )
            output = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, output)
            self.assertIn(
                "SOC_IBEX_PULP_REAL_OK cpu_tx=115 fuzz_tx=5 gpio=000000a5",
                output,
            )


if __name__ == "__main__":
    unittest.main()
