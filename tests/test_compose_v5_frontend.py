import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contracts import build_elaboration_manifest  # noqa: E402
from myfuzz.builder.frontend_v5 import extract_frontend_v5_behavior  # noqa: E402
from myfuzz.builder.rtl_analysis import analyze_elaboration_with_frontend  # noqa: E402


def expression_kinds(expression):
    if expression is None:
        return set()
    result = {expression.kind}
    for child in expression.children:
        result.update(expression_kinds(child))
    return result


class ComposeV5FrontendTest(unittest.TestCase):
    def test_behavior_fixture_exports_sensitivity_guards_slices_and_transitions(self):
        library = ROOT / "src/myfuzz/frontend/build/libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("myfuzz Verilator frontend library has not been built")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "top.sv"
            source.write_text(
                """module top(
  input logic clk_i, input logic rst_ni, input logic req_i,
  input logic [3:0] data_i, output logic [1:0] state_o
);
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) state_o <= 2'b00;
    else if (req_i && data_i[3:2] == 2'b10) begin
      case (data_i[1:0])
        2'b00: state_o <= 2'b01;
        2'b01: state_o <= 2'b10;
        default: state_o <= state_o;
      endcase
    end
  end
endmodule
""",
                encoding="ascii",
            )
            manifest = build_elaboration_manifest(
                top_module="top", rtl_files=(source,), allow_roots=(root,),
                tools={"verilator": "5.020"},
            )
            _analysis, raw = analyze_elaboration_with_frontend(
                manifest, project_root=root, frontend_library=library,
            )
        behavior = extract_frontend_v5_behavior(raw)
        top = next(item for item in behavior.modules if item.original_name == "top")
        self.assertEqual(len(top.processes), 1)
        process = top.processes[0]
        edges = {(item.edge, tuple(item.signals)) for item in process.sensitivities}
        self.assertIn(("posedge", ("clk_i",)), edges)
        self.assertIn(("negedge", ("rst_ni",)), edges)
        self.assertGreaterEqual(len(process.transitions), 4)
        self.assertTrue(all(item.targets == ("state_o",) for item in process.transitions))
        guard_kinds = set()
        for transition in process.transitions:
            for guard in transition.guards:
                guard_kinds.update(expression_kinds(guard.expression))
        self.assertIn("LOGNOT", guard_kinds)
        self.assertIn("EQ", guard_kinds)
        self.assertIn("SEL", guard_kinds)
        self.assertIn("CASE_MATCH", guard_kinds)

    def test_behavior_schema_is_required(self):
        with self.assertRaisesRegex(ValueError, "behavior schema"):
            extract_frontend_v5_behavior({
                "schema": "myfuzz.frontend.v1", "source": "verilator-frontend-ast",
                "topModule": "top", "modules": [],
            })


if __name__ == "__main__":
    unittest.main()
