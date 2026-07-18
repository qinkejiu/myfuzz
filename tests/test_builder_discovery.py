import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import InputValidationError, SystemSpec, discover_system


class DiscoveryTest(unittest.TestCase):
    def test_discovers_parameters_widths_instances_ownership_and_top(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "leaf.sv").write_text("""
                module leaf #(parameter int WIDTH = 8) (
                  input logic clk_i,
                  input logic [WIDTH-1:0] data_i,
                  output logic [WIDTH-1:0] data_o
                ); endmodule
            """)
            (root / "top.sv").write_text("""
                module top(input logic clk_i);
                  leaf #(.WIDTH(8)) u_leaf(.clk_i(clk_i), .data_i('0), .data_o());
                endmodule
            """)
            (root / "sources.f").write_text("leaf.sv\ntop.sv\n")
            spec = self._spec(["sources.f"])

            result = discover_system(spec, root)
            modules = {module.name: module for module in result.modules}
            self.assertEqual(modules["leaf"].parameters["WIDTH"], 8)
            self.assertEqual({port.name: port.width for port in modules["leaf"].ports}["data_i"], 8)
            self.assertEqual(modules["top"].instances[0].module_type, "leaf")
            self.assertFalse(modules["leaf"].top_candidate)
            self.assertTrue(modules["top"].top_candidate)
            self.assertEqual(modules["leaf"].source_set, "rtl")

    def test_user_top_candidate_overrides_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "units.sv").write_text("module a(); endmodule\nmodule b(); endmodule\n")
            data = self._spec_dict([], ["units.sv"])
            data["modules"][0]["top_candidate"] = True
            result = discover_system(SystemSpec.from_dict(data), root)
            tops = [module.name for module in result.modules if module.top_candidate]
            self.assertEqual(tops, ["a"])

    def test_missing_rtl_file_fails_clearly(self):
        with tempfile.TemporaryDirectory() as directory:
            spec = SystemSpec.from_dict(self._spec_dict([], ["missing.sv"]))
            with self.assertRaisesRegex(InputValidationError, "RTL source does not exist"):
                discover_system(spec, directory)

    def test_duplicate_module_definitions_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.sv").write_text("module duplicate(); endmodule\n")
            (root / "b.sv").write_text("module duplicate(); endmodule\n")
            spec = SystemSpec.from_dict(self._spec_dict([], ["a.sv", "b.sv"]))
            with self.assertRaisesRegex(InputValidationError, "duplicate RTL module"):
                discover_system(spec, root)

    @classmethod
    def _spec(cls, filelists):
        return SystemSpec.from_dict(cls._spec_dict(filelists, []))

    @staticmethod
    def _spec_dict(filelists, rtl_files):
        return {
            "schema_version": 1,
            "name": "discovery",
            "sources": [{"name": "rtl", "filelists": filelists, "rtl_files": rtl_files}],
            "modules": [{"name": "a", "kind": "generic", "source_set": "rtl", "ports": {}}],
        }


if __name__ == "__main__":
    unittest.main()
