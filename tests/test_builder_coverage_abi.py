import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import InputValidationError, run_soc_instrumentation  # noqa: E402
from myfuzz.builder.contracts import build_elaboration_manifest, validate_contract  # noqa: E402
from myfuzz.instrumentation.source_branch_instrumenter import instrument_project  # noqa: E402


TOP = """\
module top(input logic clk, input logic sel, output logic result);
 logic a, b;
 leaf u_b(.clk(clk), .sel(sel), .hit(b));
 leaf u_a(.clk(clk), .sel(sel), .hit(a));
 always_comb begin if (sel) result=a; else result=b; end
endmodule
"""

LEAF = """\
module leaf(input logic clk, input logic sel, output logic hit);
 always_ff @(posedge clk) begin if (sel) hit<=1'b1; else hit<=1'b0; end
endmodule
"""


def instrument_fixture(parent):
    project = Path(parent) / "project"
    output = Path(parent) / "instrumented"
    project.mkdir()
    (project / "top.sv").write_text(TOP)
    (project / "leaf.sv").write_text(LEAF)
    return instrument_project(
        project, output, top_module="top", required_modules={"top", "leaf"},
    )


class CoverageABITest(unittest.TestCase):
    def test_unbraced_always_if_chain_is_runtime_branch_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            source = project / "top.v"
            source.write_text("""
module top(input wire clk, input wire resetn, input wire request,
           input wire ready, output reg valid);
 initial valid = 1'b0;
 always @(posedge clk)
 if (!resetn)
   valid <= 1'b0;
 else if (request)
   valid <= 1'b1;
 else if (ready)
   valid <= 1'b0;
endmodule
""")
            result = instrument_project(
                project, root / "instrumented", top_module="top",
                required_modules={"top"},
            )
            points = result["coverage_abi"]["points"]
            self.assertGreaterEqual(len(points), 3)
            self.assertTrue(all(point["process_kind"] == "edge_always" for point in points))
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "top", "-o", str(root / "a.out"),
                 str(root / "instrumented/top.v")],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)

    def test_soc_instrumentation_is_manifest_locked_and_emits_derived_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            top = project / "top.sv"
            leaf = project / "leaf.sv"
            top.write_text(TOP)
            leaf.write_text(LEAF)
            source_manifest = build_elaboration_manifest(
                top_module="top", rtl_files=(top, leaf), allow_roots=(project,),
            )
            result = run_soc_instrumentation(
                source_manifest, project, root / "instrumented",
                required_modules={"top", "leaf"},
            )
            self.assertEqual(result["source_manifest_digest"], source_manifest.digest)
            self.assertEqual(
                result["instrumented_manifest"]["parent_digest"], source_manifest.digest,
            )
            self.assertEqual(result["instrumented_manifest"]["stage"], "instrumented-soc")
            validate_contract(result["coverage_abi"], "coverage_abi_v1")
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "top", "-o", str(root / "a.out"),
                 *(item["path"] for item in result["instrumented_manifest"]["sources"])],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            top.write_text(TOP + "\n")
            with self.assertRaisesRegex(InputValidationError, "content changed"):
                run_soc_instrumentation(
                    source_manifest, project, root / "rejected",
                    required_modules={"top", "leaf"},
                )

    def test_soc_instrumentation_preserves_unrewritten_include_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            include = project / "include"
            include.mkdir(parents=True)
            (include / "config.svh").write_text("`define RESULT_VALUE 1'b1\n")
            top = project / "top.sv"
            top.write_text("""
`include "config.svh"
module top(input logic sel, output logic result);
 always_comb begin if(sel) result=`RESULT_VALUE; else result=1'b0; end
endmodule
""")
            filelist = project / "sources.f"
            filelist.write_text("+incdir+include\ntop.sv\n")
            source_manifest = build_elaboration_manifest(
                top_module="top", filelists=(filelist,), allow_roots=(project,),
            )
            result = run_soc_instrumentation(
                source_manifest, project, root / "instrumented", required_modules={"top"},
            )
            rewritten_include = Path(result["instrumented_manifest"]["include_dirs"][0])
            self.assertEqual(
                (rewritten_include / "config.svh").read_bytes(),
                (include / "config.svh").read_bytes(),
            )
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-I", str(rewritten_include), "-s", "top",
                 "-o", str(root / "include.out"),
                 *(item["path"] for item in result["instrumented_manifest"]["sources"])],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)

    def test_frontend_empty_instance_set_suppresses_inactive_source_generate_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            source = project / "design.sv"
            source.write_text("""
module child(input logic sel, output logic result);
 always_comb begin if(sel) result=1'b1; else result=1'b0; end
endmodule
module top #(parameter ENABLE_CHILD=0)(input logic sel, output logic result);
 generate if(ENABLE_CHILD) begin : g_child
  child u_child(.sel(sel), .result());
 end endgenerate
 always_comb begin if(sel) result=1'b1; else result=1'b0; end
endmodule
""")
            frontend = {"modules": [
                {"name": "child", "origName": "child", "file": str(source),
                 "instances": [], "branches": []},
                {"name": "top", "origName": "top", "file": str(source),
                 "instances": [], "branches": []},
            ]}
            result = instrument_project(
                project, root / "instrumented", top_module="top",
                frontend_manifest=frontend, required_modules={"top"},
            )
            self.assertEqual(result["top_modules"], ["top"])
            self.assertTrue(all(
                point["hierarchy"] == "top" for point in result["coverage_abi"]["points"]
            ))

    def test_fresh_builds_have_identical_instance_catalog_hash_and_offsets(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = instrument_fixture(first)
            right = instrument_fixture(second)
            self.assertEqual(left["coverage_abi"], right["coverage_abi"])
            abi = left["coverage_abi"]
            validate_contract(abi, "coverage_abi_v1")
            self.assertEqual(abi["width"], left["coverage_point_count"])
            self.assertEqual(
                sorted(point["offset"] for point in abi["points"] if point["included"]),
                list(range(abi["width"])),
            )
            leaf_points = [point for point in abi["points"] if point["module"] == "leaf"]
            self.assertEqual({point["hierarchy"] for point in leaf_points}, {"top.u_a", "top.u_b"})
            by_node = {}
            for point in leaf_points:
                by_node.setdefault(point["node_id"], set()).add(point["point_id"])
            self.assertTrue(all(len(ids) == 2 for ids in by_node.values()))
            self.assertEqual(left["coverage_inclusion_mask"], [True] * abi["width"])

    def test_optional_export_change_updates_abi_but_preserves_existing_point_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "top.sv").write_text("""
module top(input logic sel, output logic result);
 opt u_opt();
 always_comb begin if(sel) result=1; else result=0; end
endmodule
""")
            optional = project / "opt.sv"
            optional.write_text("module opt; initial begin if (1) $display(\"x\"); end endmodule\n")
            first = instrument_project(
                project, root / "first", top_module="top",
                required_modules={"top"}, optional_modules={"opt"},
            )
            self.assertGreater(first["coverage_skipped_point_count"], 0)
            first_top_ids = {
                point["point_id"] for point in first["coverage_abi"]["points"]
                if point["module"] == "top"
            }
            optional.write_text("module opt(); initial begin if (1) $display(\"x\"); end endmodule\n")
            second = instrument_project(
                project, root / "second", top_module="top",
                required_modules={"top"}, optional_modules={"opt"},
            )
            second_top_ids = {
                point["point_id"] for point in second["coverage_abi"]["points"]
                if point["module"] == "top"
            }
            self.assertEqual(first_top_ids, second_top_ids)
            self.assertNotEqual(first["coverage_abi_hash"], second["coverage_abi_hash"])
            self.assertEqual(second["coverage_skipped_point_count"], 0)

    def test_required_skip_fails_and_coverage_port_collision_is_renamed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            (project / "top.sv").write_text("""
module top(input logic sel, output logic __vi_coverage);
 opt u_opt();
 always_comb begin if(sel) __vi_coverage=1; else __vi_coverage=0; end
endmodule
""")
            (project / "opt.sv").write_text(
                "module opt; initial begin if (1) $display(\"x\"); end endmodule\n"
            )
            with self.assertRaisesRegex(SystemExit, "required module opt cannot export"):
                instrument_project(
                    project, root / "rejected", top_module="top",
                    required_modules={"top", "opt"},
                )
            manifest = instrument_project(
                project, root / "accepted", top_module="top",
                required_modules={"top"}, optional_modules={"opt"},
            )
            self.assertNotEqual(manifest["coverage_port"], "__vi_coverage")
            self.assertEqual(manifest["coverage_abi"]["port_name"], manifest["coverage_port"])
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "top", "-o", str(root / "a.out"),
                 str(root / "accepted/top.sv"), str(root / "accepted/opt.sv")],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            json.dumps(manifest["coverage_abi"], sort_keys=True)


if __name__ == "__main__":
    unittest.main()
