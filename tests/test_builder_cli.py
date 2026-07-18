import json
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.cli import main


class BuilderCliTest(unittest.TestCase):
    def test_materials_system_runs_end_to_end_with_rfuzz(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with redirect_stdout(io.StringIO()):
                result = main([
                    "--spec", str(ROOT / "examples/materials_simple_system.json"),
                    "--project-root", str(ROOT),
                    "--output-dir", str(output),
                    "--wrapper",
                    "--rfuzz",
                    "--rfuzz-format", "legacy-v1",
                    "--rfuzz-cycles", "8",
                    "--rfuzz-seed", "7",
                ])
            self.assertEqual(result, 0)
            report = json.loads((output / "generation_report.json").read_text())
            self.assertEqual(report["status"], "generated")
            self.assertEqual(report["summary"]["modules"], 5)
            self.assertFalse(report["wrapper"]["generated"])
            self.assertIn("protocol backend", report["wrapper"]["reason"])
            self.assertEqual(report["rfuzz"]["fuzz_input_count"], 2)
            self.assertEqual((output / "rfuzz_testcases/rfuzz_seed.bin").stat().st_size, 8)
            self.assertIn("rfuzz_testcases/rfuzz_seed.bin", report["generated_files"])
            address_map = json.loads((output / "address_map.json").read_text())
            self.assertEqual(len(address_map["windows"]), 4)
            self.assertEqual(address_map["windows"][0]["module"], "simple_ram")
            self.assertEqual(address_map["windows"][0]["base"], 0)
            graph = json.loads((output / "connection_graph.json").read_text())
            self.assertIn("__fabric_simple_bus", graph["virtual_modules"])

    def test_rfuzz_requires_explicit_legacy_format(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = main([
                    "--spec", str(ROOT / "examples/materials_simple_system.json"),
                    "--project-root", str(ROOT), "--output-dir", str(output), "--rfuzz",
                ])
            self.assertEqual(result, 2)
            report = json.loads((output / "generation_report.json").read_text())
            self.assertIn("explicit --rfuzz-format legacy-v1", report["validation_issues"][0])

    def test_invalid_spec_writes_failure_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad_spec = root / "bad.json"
            bad_spec.write_text('{"schema_version": 1}\n')
            output = root / "out"
            with redirect_stderr(io.StringIO()):
                result = main([
                    "--spec", str(bad_spec), "--project-root", str(ROOT),
                    "--output-dir", str(output),
                ])
            self.assertEqual(result, 2)
            report = json.loads((output / "generation_report.json").read_text())
            self.assertEqual(report["status"], "failed")
            self.assertTrue(report["validation_issues"])


if __name__ == "__main__":
    unittest.main()
