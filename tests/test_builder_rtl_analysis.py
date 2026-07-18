import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contracts import build_elaboration_manifest
from myfuzz.builder.input_model import InputValidationError
from myfuzz.builder.rtl_analysis import (
    FRONTEND_SUPPORT_MATRIX,
    EvidenceState,
    analyze_elaboration,
    normalize_frontend_manifest,
)


class RTLAnalysisTest(unittest.TestCase):
    def test_frontend_support_matrix_is_explicit_and_fail_closed(self):
        self.assertIs(FRONTEND_SUPPORT_MATRIX["generate"], EvidenceState.KNOWN)
        self.assertIs(FRONTEND_SUPPORT_MATRIX["fixed_unpacked_memory"], EvidenceState.KNOWN)
        self.assertIs(FRONTEND_SUPPORT_MATRIX["dpi"], EvidenceState.NON_PROVABLE)
        self.assertIs(FRONTEND_SUPPORT_MATRIX["behavioral_memory"], EvidenceState.NON_PROVABLE)

    def test_verilator_frontend_elaborates_parameters_generate_package_and_shapes(self):
        library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("myfuzz Verilator frontend library has not been built")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.sv"
            source.write_text(
                """package widths_pkg; parameter int W = `DATA_WIDTH; endpackage
module child #(parameter int W = 4) (
  input logic [W-1:0] data_i,
  output logic [W-1:0] data_o
);
  assign data_o = data_i;
endmodule
module unused_module(input logic unused_i, output logic unused_o);
  assign unused_o = unused_i;
endmodule
module top import widths_pkg::*; #(
  parameter int COUNT = 2
) (
  input logic [W-1:0] packed_i [COUNT],
  output logic [W-1:0] packed_o [COUNT],
  inout wire pad,
  output logic sampled_o
);
  logic mem [0:3];
  for (genvar i = 0; i < COUNT; i++) begin : g
    child #(.W(W)) u_child (.data_i(packed_i[i]), .data_o(packed_o[i]));
  end
  always_comb begin
    mem[0] = pad;
    sampled_o = mem[0];
  end
endmodule
""",
                encoding="utf-8",
            )
            filelist = root / "sources.f"
            filelist.write_text("+define+DATA_WIDTH=8 fixture.sv\n", encoding="utf-8")
            manifest = build_elaboration_manifest(
                top_module="top", filelists=(filelist,), allow_roots=(root,), tools={"verilator": "5.020"},
            )
            analysis = analyze_elaboration(manifest, project_root=root, frontend_library=library)
            self.assertEqual(analysis.manifest_digest, manifest.digest)
            self.assertEqual(analysis.top_module, "top")
            top = next(module for module in analysis.modules if module.original_name == "top")
            self.assertEqual(len(top.instances), 2)
            self.assertTrue(all(len(instance.pins) == 2 for instance in top.instances))
            first_pins = {pin.port: pin for pin in top.instances[0].pins}
            self.assertEqual(first_pins["data_i"].direction.value, "input")
            self.assertEqual(first_pins["data_i"].width, 8)
            self.assertEqual(len(first_pins["data_i"].signals), 1)
            self.assertEqual(first_pins["data_i"].expression_kind, "ARRAYSEL")
            by_name = {port.name: port for port in top.ports}
            self.assertEqual(by_name["packed_i"].packed_width, 8)
            self.assertEqual(by_name["packed_i"].unpacked_ranges, ((0, 1),))
            self.assertEqual(by_name["packed_i"].width, 16)
            self.assertIn(("COUNT", "2"), top.parameters)
            self.assertIs(by_name["packed_i"].signed, False)
            self.assertIs(by_name["packed_i"].evidence.state, EvidenceState.KNOWN)
            self.assertIs(by_name["pad"].evidence.state, EvidenceState.NON_PROVABLE)
            self.assertIs(by_name["sampled_o"].evidence.state, EvidenceState.NON_PROVABLE)
            self.assertEqual(len(top.memories), 1)
            self.assertEqual(top.memories[0].name, "mem")
            self.assertEqual(top.memories[0].word_width, 1)
            self.assertEqual(top.memories[0].depth, 4)
            constructs = {item.construct for item in analysis.limitations}
            self.assertIn("tri_state", constructs)
            self.assertNotIn("behavioral_memory", constructs)
            child = next(module for module in analysis.modules if module.original_name == "child")
            self.assertTrue(any(item.target == "data_o" and "data_i" in item.sources for item in child.dependencies))
            self.assertNotIn("unused_module", {module.original_name for module in analysis.modules})

    def test_rejects_non_ast_and_missing_top_manifests(self):
        raw = {"schema": "myfuzz.frontend.v1", "source": "regex", "topModule": "top", "modules": []}
        with self.assertRaisesRegex(InputValidationError, "not backed"):
            normalize_frontend_manifest(raw, "0" * 64)
        raw["source"] = "verilator-frontend-ast"
        with self.assertRaisesRegex(InputValidationError, "missing"):
            normalize_frontend_manifest(raw, "0" * 64)

    def test_frontend_analysis_is_repeatable_in_one_python_process(self):
        library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("myfuzz Verilator frontend library has not been built")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "top.sv"
            source.write_text("module top(input logic a, output logic y); assign y = a; endmodule\n")
            filelist = root / "sources.f"
            filelist.write_text("top.sv\n")
            manifest = build_elaboration_manifest(
                top_module="top", filelists=(filelist,), allow_roots=(root,), tools={"verilator": "5.020"},
            )
            first = analyze_elaboration(manifest, project_root=root, frontend_library=library)
            second = analyze_elaboration(manifest, project_root=root, frontend_library=library)
            self.assertEqual(first, second)

    def test_non_provable_limitations_block_proof_consumers(self):
        raw = {
            "schema": "myfuzz.frontend.v1", "source": "verilator-frontend-ast", "topModule": "top",
            "modules": [{"name": "top", "origName": "top", "top": True, "level": 1,
                         "file": "top.sv", "ports": [], "instances": []}],
            "limitations": [{"module": "top", "signals": [], "construct": "dpi",
                             "source": "verilator_ast", "reason": "DPI call reaches output"}],
        }
        analysis = normalize_frontend_manifest(raw, "0" * 64)
        self.assertEqual(analysis.limitations[0].evidence.state, EvidenceState.NON_PROVABLE)
        with self.assertRaisesRegex(InputValidationError, "address proof.*DPI"):
            analysis.require_provable("address proof")

    def test_non_provable_signal_taint_propagates_through_dependencies(self):
        raw = {
            "schema": "myfuzz.frontend.v1", "source": "verilator-frontend-ast", "topModule": "top",
            "modules": [{
                "name": "top", "origName": "top", "top": True, "level": 1, "file": "top.sv",
                "parameters": [], "instances": [],
                "ports": [
                    {"name": "bad_i", "direction": "input", "width": 1, "packedWidth": 1,
                     "unpackedRanges": [], "signed": False},
                    {"name": "mid", "direction": "output", "width": 1, "packedWidth": 1,
                     "unpackedRanges": [], "signed": False},
                    {"name": "good_o", "direction": "output", "width": 1, "packedWidth": 1,
                     "unpackedRanges": [], "signed": False},
                ],
                "dependencies": [
                    {"target": "mid", "sources": ["bad_i"], "kind": "ASSIGNW"},
                    {"target": "good_o", "sources": ["mid"], "kind": "ASSIGNW"},
                ],
            }],
            "limitations": [{"module": "top", "signals": ["bad_i"], "construct": "tri_state",
                             "reason": "tri-state resolution is not modeled"}],
        }
        analysis = normalize_frontend_manifest(raw, "0" * 64)
        top = analysis.modules[0]
        self.assertTrue(all(port.evidence.state is EvidenceState.NON_PROVABLE for port in top.ports))
        self.assertTrue(all(item.evidence.state is EvidenceState.NON_PROVABLE for item in top.dependencies))
        with self.assertRaisesRegex(InputValidationError, "driver proof.*tri-state"):
            analysis.require_provable("driver proof", module="top", signals=("good_o",))

    def test_checked_in_axi_lite_development_material_passes_analysis_gate(self):
        library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("myfuzz Verilator frontend library has not been built")
        material = (
            ROOT / "materials" / "protocol" / "axi_lite" / "train" / "gpio"
            / "pulp_axi_lite_regs_model__26561a52"
        )
        rtl = material / "rtl" / "templates" / "autotop" / "famous_ip_models"
        sources = tuple(sorted(rtl.glob("*.sv")))
        self.assertTrue(sources)
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            filelist = temporary / "sources.f"
            filelist.write_text("\n".join(path.as_posix() for path in sources) + "\n")
            manifest = build_elaboration_manifest(
                top_module="pulp_axi_lite_regs_model",
                filelists=(filelist,),
                allow_roots=(material, temporary),
                tools={"verilator": "5.020"},
            )
            analysis = analyze_elaboration(manifest, project_root=material, frontend_library=library)
        top = next(module for module in analysis.modules if module.original_name == "pulp_axi_lite_regs_model")
        self.assertFalse(analysis.limitations)
        self.assertEqual({port.name for port in top.ports}, {
            "addr_i", "clk_i", "rdata_o", "req_i", "rst_ni", "wdata_i", "we_i",
        })
        self.assertEqual(len(top.memories), 1)


if __name__ == "__main__":
    unittest.main()
