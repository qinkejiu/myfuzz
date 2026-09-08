import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "examples/real_ibex_rfuzz/run_example.py"
INPUT_PATH = ROOT / "examples/real_ibex_rfuzz/input/ibex-scratch.json"


def load_module():
    spec = importlib.util.spec_from_file_location("real_ibex_rfuzz_example", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealIbexRfuzzExampleTests(unittest.TestCase):
    def test_example_entrypoint_exists(self):
        self.assertTrue(MODULE_PATH.is_file(), "real Ibex example entrypoint is missing")

    def test_real_ibex_input_exists(self):
        self.assertTrue(INPUT_PATH.is_file(), "real Ibex example input is missing")

    def test_load_example_translates_single_personality(self):
        module = load_module()
        config, personality = module.load_example(INPUT_PATH, ROOT)
        self.assertNotIn("schema_version", config)
        self.assertNotIn("personality", config)
        self.assertEqual(config["protocol"], ["obi", "1"])
        self.assertEqual(config["interface"], "configs/cpus/ibex/official_core_interface_description.json")
        self.assertEqual(personality["name"], "scratch-registers")
        self.assertEqual(personality["mode"], 0)

    def test_load_example_rejects_unknown_keys(self):
        module = load_module()
        document = json.loads(INPUT_PATH.read_text())
        document["surprise"] = True
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "unknown keys"):
                module.load_example(path, ROOT)

    def test_load_example_rejects_wrong_schema(self):
        module = load_module()
        document = json.loads(INPUT_PATH.read_text())
        document["schema_version"] = "real_ibex_rfuzz_example.v2"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input.json"
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, "schema_version"):
                module.load_example(path, ROOT)

    def test_test_example_rejects_nonpositive_duration_before_build(self):
        module = load_module()
        with self.assertRaisesRegex(ValueError, "seconds must be a positive integer"):
            module.test_example(ROOT, INPUT_PATH, Path("kfuzz"), Path("out"), 0)

    def test_test_example_rejects_missing_client_before_build(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "kfuzz"
            with self.assertRaisesRegex(ValueError, "RFuzz client does not exist"):
                module.test_example(ROOT, INPUT_PATH, missing, Path(tmp) / "out", 5)

    def test_compose_publishes_inspectable_summary(self):
        module = load_module()
        artifact = object()
        proof = {
            "execution": {"first_fetch_matched": 1, "errors": 0},
            "composition_hash": "sha256:composition",
            "layout_hash": "sha256:layout",
            "coverage": [12, 11],
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "compose"
            with mock.patch.object(module, "build_candidate", return_value=(artifact, proof), create=True) as build:
                summary = module.compose_example(ROOT, INPUT_PATH, output)
            self.assertEqual(summary["mode"], "compose")
            self.assertEqual(summary, module.inspect_example(output))
            build.assert_called_once()

    def test_inspect_rejects_malformed_summary(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output / "summary.json").write_text("[]\n")
            with self.assertRaisesRegex(ValueError, "summary must be a JSON object"):
                module.inspect_example(output)


if __name__ == "__main__":
    unittest.main()
