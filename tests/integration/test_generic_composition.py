from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition import GenericCompositionRequest, plan_generic_composition, write_generic_composition
from tests.composition.test_generic_auto import synthetic_description


class GenericCompositionIntegrationTests(unittest.TestCase):
    def test_writer_publishes_deterministic_ir_layout_top_and_source_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "opaque_cpu", ("x_clock", "x_reset", "x_input", "x_output"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            first_dir, second_dir = root / "one", root / "two"

            first = write_generic_composition(plan, first_dir, base_dir=root)
            second = write_generic_composition(plan, second_dir, base_dir=root)

            self.assertTrue(first["complete"])
            self.assertEqual(first["composition_ir_hash"], second["composition_ir_hash"])
            self.assertEqual(first["layout_hash"], second["layout_hash"])
            self.assertEqual(first["interface_annotation_hash"], second["interface_annotation_hash"])
            self.assertEqual(Path(first["top_path"]), first_dir / "generic_composition_top.sv")
            self.assertEqual(Path(first["source_list_path"]), first_dir / "sources.f")
            self.assertTrue((first_dir / "composition_ir.json").is_file())
            self.assertTrue((first_dir / "input_layout.json").is_file())
            self.assertEqual(
                (first_dir / "composition_ir.json").read_bytes(),
                (second_dir / "composition_ir.json").read_bytes(),
            )
            top = (first_dir / "generic_composition_top.sv").read_text(encoding="utf-8")
            self.assertIn("module generic_composition_top", top)
            self.assertIn("opaque_cpu", top)
            self.assertNotIn("ibex", top.lower())
            self.assertIn((root / "source" / "rtl" / "opaque_cpu.sv").as_posix(), (first_dir / "sources.f").read_text(encoding="utf-8"))
            self.assertEqual(json.loads((first_dir / "composition_ir.json").read_text())["composition_kind"], "generic_composition")

    def test_writer_does_not_replace_existing_artifacts_after_source_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "sealed_cpu", ("clk", "rst", "fuzz", "seen"))
            plan = plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root)
            output = root / "out"
            write_generic_composition(plan, output, base_dir=root)
            before = {
                path.name: path.read_bytes()
                for path in output.iterdir()
                if path.is_file()
            }
            (root / "source" / "rtl" / "sealed_cpu.sv").unlink()

            with self.assertRaisesRegex(ValueError, "source is missing"):
                write_generic_composition(plan, output, base_dir=root)

            self.assertEqual(
                before,
                {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()},
            )

    def test_cli_interface_description_mode_uses_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            description = synthetic_description(root, "cli_cpu", ("clk", "rst", "fuzz", "seen"))
            document = {
                "schema_version": "interface_description.v1",
                "source": {"root": description.source.source_root, "revision": description.source.revision,
                           "top_module": description.source.top_module, "files": list(description.source.files)},
                "endpoints": [{"endpoint_id": endpoint.endpoint_id, "function": endpoint.function,
                               "module": endpoint.module,
                               "fields": [{"role": field.role, "aliases": list(field.aliases)} for field in endpoint.fields]}
                              for endpoint in description.endpoints],
            }
            (root / "interface.json").write_text(json.dumps(document), encoding="utf-8")
            script = Path(__file__).resolve().parents[2] / "scripts" / "generate_composition.py"
            result = subprocess.run(
                ["python3", script, "--interface-description", "interface.json", "--base-dir", root, "--out-dir", "out"],
                check=False, capture_output=True, text=True,
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[2] / "src")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertTrue(summary["complete"])
            self.assertTrue((root / "out" / "generic_composition_top.sv").is_file())


if __name__ == "__main__":
    unittest.main()
