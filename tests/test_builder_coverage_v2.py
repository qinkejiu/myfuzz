import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (
    HarnessPort, PortDirection, build_common_coverage_abi_v2, build_constraint_ir,
    build_rawbits_layout, emit_dual_mode_harness, infer_hierarchy_component_ids,
    infer_hierarchy_component_paths, run_soc_instrumentation,
)
from myfuzz.builder.contracts import CoverageABI, build_elaboration_manifest, validate_contract
from myfuzz.instrumentation.source_branch_instrumenter import instrument_project


class CommonCoverageV2Test(unittest.TestCase):
    def test_component_identity_is_inferred_from_preregistered_hierarchy_roots(self):
        points = (
            {"hierarchy": "flat.cpu0.i_cpu.core"},
            {"hierarchy": "flat.ram0.i_ram"},
            {"hierarchy": "generated.i_soc.i_cpu.i_cpu.core"},
            {"hierarchy": "generated.i_soc.i_ram0.i_ram"},
            {"hierarchy": "generated.i_soc.i_fabric"},
        )
        mapping = infer_hierarchy_component_ids(points, {
            "cpu.main": ("flat.cpu0", "generated.i_soc.i_cpu"),
            "ip.ram0": ("flat.ram0", "generated.i_soc.i_ram0"),
        })
        self.assertEqual(mapping["flat.cpu0.i_cpu.core"], "cpu.main")
        self.assertEqual(mapping["generated.i_soc.i_cpu.i_cpu.core"], "cpu.main")
        self.assertEqual(mapping["generated.i_soc.i_ram0.i_ram"], "ip.ram0")
        self.assertNotIn("generated.i_soc.i_fabric", mapping)
        paths = infer_hierarchy_component_paths(points, {
            "cpu.main": ("flat.cpu0", "generated.i_soc.i_cpu"),
            "ip.ram0": ("flat.ram0", "generated.i_soc.i_ram0"),
        })
        self.assertEqual(paths["flat.cpu0.i_cpu.core"], "i_cpu.core")
        self.assertEqual(paths["generated.i_soc.i_cpu.i_cpu.core"], "i_cpu.core")

    def test_only_sequential_control_flow_is_primary_and_hierarchy_is_not_identity(self):
        points = (
            {"point_id": "old-a", "node_id": "n1", "source_id": "s", "hierarchy": "top.u_cpu",
             "module": "cpu", "kind": "if", "subtype": "true", "process_kind": "always_ff",
             "source_line": 10, "included": True, "offset": 0},
            {"point_id": "old-b", "node_id": "n2", "source_id": "s", "hierarchy": "top.u_cpu",
             "module": "cpu", "kind": "if", "subtype": "true", "process_kind": "always_comb",
             "source_line": 20, "included": True, "offset": 1},
            {"point_id": "old-c", "node_id": "n3", "source_id": "s", "hierarchy": "top.u_harness",
             "module": "harness", "kind": "case", "subtype": "item", "process_kind": "edge_always",
             "source_line": 30, "included": True, "offset": 2},)
        source = CoverageABI("a" * 64, "__vi_coverage", 3, points)
        left = build_common_coverage_abi_v2(source, {"top.u_cpu": "cpu.main"})
        renamed = tuple(dict(point, hierarchy=point["hierarchy"].replace("top", "other")) for point in points)
        right = build_common_coverage_abi_v2(CoverageABI("b" * 64, "__vi_coverage", 3, renamed),
                                             {"other.u_cpu": "cpu.main"})
        self.assertEqual(left, right)
        self.assertEqual(left.width, 1)
        self.assertEqual(left.transport_width, 3)
        self.assertEqual(next(p for p in left.points if p["node_id"] == "n2")["exclusion_reason"], "always_comb")
        self.assertEqual(next(p for p in left.points if p["node_id"] == "n3")["exclusion_reason"], "non_primary_component")
        validate_contract(left.to_dict(), "coverage_abi_v2")

    def test_catalog_digest_ignores_variant_specific_transport_offsets(self):
        point = {
            "point_id": "old-a", "node_id": "n1", "source_id": "s",
            "hierarchy": "flat.cpu0", "module": "cpu", "kind": "if",
            "subtype": "true", "process_kind": "always_ff", "source_line": 10,
            "included": True, "offset": 2,
        }
        left = build_common_coverage_abi_v2(
            CoverageABI("a" * 64, "__vi_coverage", 3, (point,)),
            {"flat.cpu0": "cpu.main"},
        )
        moved = dict(point, hierarchy="generated.i_soc.i_cpu", offset=7)
        right = build_common_coverage_abi_v2(
            CoverageABI("b" * 64, "__vi_coverage", 9, (moved,)),
            {"generated.i_soc.i_cpu": "cpu.main"},
        )
        self.assertEqual(left.catalog_digest, right.catalog_digest)
        self.assertNotEqual(left.transport_width, right.transport_width)
        self.assertNotEqual(left.points[0]["source_offset"], right.points[0]["source_offset"])

    def test_epoch_tagged_instrumentation_is_single_process_written_and_isolates_testcases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); project = root / "project"; project.mkdir()
            (project / "top.sv").write_text(
                "module top(input logic clk,input logic sel,output logic hit);\n"
                "always_ff @(posedge clk) begin if(sel) hit<=1; else hit<=0; end\nendmodule\n")
            result = instrument_project(project, root / "out", top_module="top",
                                        required_modules={"top"}, coverage_epoch_width=4)
            instrumented = root / "out/top.sv"
            text = instrumented.read_text()
            self.assertIn("__epoch = coverage_epoch_i", text)
            self.assertNotIn("always_comb", text)
            tb = root / "tb.sv"
            width = result["coverage_abi"]["width"]
            tb.write_text(f"""
module tb;
 logic clk=0,sel=0,hit; logic [3:0] epoch=1; wire [{width-1}:0] cov;
 top dut(.clk(clk),.sel(sel),.hit(hit),.coverage_epoch_i(epoch),.__vi_coverage(cov));
 always #5 clk=~clk;
 initial begin
  sel=1; @(posedge clk); #1; if (!(|cov)) $fatal(1,"epoch 1 did not hit");
  @(negedge clk); epoch=2; sel=0; #1; if (|cov) $fatal(1,"old epoch leaked");
  sel=1; @(posedge clk); #1; if (!(|cov)) $fatal(1,"epoch 2 did not hit");
  $finish;
 end
endmodule
""")
            output = root / "sim.out"
            compile_result = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(output),
                                             str(instrumented), str(tb)], capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run = subprocess.run(["vvp", str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)

    def test_soc_bridge_emits_primary_v2_and_full_transport_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); project = root / "project"; project.mkdir()
            source = project / "top.sv"
            source.write_text(
                "module top(input logic clk,input logic sel,output logic hit);\n"
                "always_ff @(posedge clk) begin if(sel) hit<=1; else hit<=0; end\n"
                "always_comb begin if(sel) hit=hit; end\nendmodule\n")
            manifest = build_elaboration_manifest(top_module="top", rtl_files=(source,), allow_roots=(project,))
            result = run_soc_instrumentation(
                manifest, project, root / "instrumented", required_modules={"top"},
                coverage_abi_version=2, hierarchy_component_ids={"top": "cpu.main"})
            self.assertEqual(result["coverage_abi"]["schema"], "myfuzz.coverage-abi/v2")
            self.assertGreater(result["coverage_transport_abi"]["width"], result["coverage_abi"]["width"])
            self.assertEqual(result["coverage_abi"]["transport_width"], result["coverage_transport_abi"]["width"])
            validate_contract(result["coverage_abi"], "coverage_abi_v2")

    def test_epoch_is_not_connected_to_zero_width_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); project = root / "project"; project.mkdir()
            (project / "top.sv").write_text(
                "module leaf(input logic value,output logic seen); assign seen=value; endmodule\n"
                "module top(input logic clk,input logic value,output logic seen,output logic hit);\n"
                "leaf u_leaf(.value(value),.seen(seen));\n"
                "always_ff @(posedge clk) begin if(value) hit<=1; else hit<=0; end\nendmodule\n")
            result = instrument_project(
                project, root / "out", top_module="top", required_modules={"top"},
                optional_modules={"leaf"}, coverage_epoch_width=4,
            )
            text = (root / "out/top.sv").read_text()
            self.assertNotIn(".seen(seen), .coverage_epoch_i", text)
            tb = root / "tb.sv"
            width = result["coverage_abi"]["width"]
            tb.write_text(
                f"module tb; logic clk,value,seen,hit; logic [3:0] epoch; wire [{width-1}:0] cov; "
                "top dut(.clk(clk),.value(value),.seen(seen),.hit(hit),"
                ".coverage_epoch_i(epoch),.__vi_coverage(cov)); endmodule\n")
            compile_result = subprocess.run([
                "iverilog", "-g2012", "-s", "tb", "-o", str(root / "sim.out"),
                str(root / "out/top.sv"), str(tb),
            ], capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)

    def test_soc_bridge_can_infer_component_ids_from_elaborated_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); project = root / "project"; project.mkdir()
            source = project / "top.sv"
            source.write_text(
                "module leaf(input logic clk,input logic sel,output logic hit);\n"
                "always_ff @(posedge clk) begin if(sel) hit<=1; else hit<=0; end\nendmodule\n"
                "module top(input logic clk,input logic sel,output logic primary,output logic auxiliary);\n"
                "leaf cpu0(.clk(clk),.sel(sel),.hit(primary));\n"
                "leaf helper0(.clk(clk),.sel(sel),.hit(auxiliary));\nendmodule\n")
            manifest = build_elaboration_manifest(
                top_module="top", rtl_files=(source,), allow_roots=(project,),
            )
            result = run_soc_instrumentation(
                manifest, project, root / "instrumented", required_modules={"top", "leaf"},
                coverage_abi_version=2,
                hierarchy_component_roots={"cpu.main": ("top.cpu0",)},
            )
            included = [point for point in result["coverage_abi"]["points"] if point["included"]]
            excluded = [point for point in result["coverage_abi"]["points"] if not point["included"]]
            self.assertTrue(included)
            self.assertEqual({point["component_id"] for point in included}, {"cpu.main"})
            self.assertTrue(any(point["exclusion_reason"] == "non_primary_component"
                                for point in excluded))

    def test_harness_projects_v2_transport_bits_and_connects_epoch(self):
        source = CoverageABI("a" * 64, "__vi_coverage", 3, (
            {"point_id": "p0", "node_id": "n0", "source_id": "s", "hierarchy": "top.u_cpu",
             "module": "cpu", "kind": "if", "subtype": "true", "process_kind": "always_ff",
             "source_line": 1, "included": True, "offset": 2},
            {"point_id": "p1", "node_id": "n1", "source_id": "s", "hierarchy": "top.u_cpu",
             "module": "cpu", "kind": "if", "subtype": "true", "process_kind": "always_comb",
             "source_line": 2, "included": True, "offset": 1},
            {"point_id": "p2", "node_id": "n2", "source_id": "s", "hierarchy": "top.u_cpu",
             "module": "cpu", "kind": "case", "subtype": "item", "process_kind": "edge_always",
             "source_line": 3, "included": True, "offset": 0},))
        abi = build_common_coverage_abi_v2(source, {"top.u_cpu": "cpu.main"}, epoch_width=4)
        layout = build_rawbits_layout(({"target": "pin", "width": 1, "purpose": "input", "provenance": "test"},))
        constraints = build_constraint_ir(layout, ({"target": "pin", "primitive": "DIRECT", "provenance": "test"},))
        harness = emit_dual_mode_harness("soc", layout, constraints, (
            HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
            HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
            HarnessPort("pin", PortDirection.INPUT, 1), HarnessPort("seen", PortDirection.OUTPUT, 1),
        ), coverage_abi=abi)
        self.assertIn("assign coverage_o[0]=coverage_transport[2]", harness.rtl)
        self.assertIn("assign coverage_o[1]=coverage_transport[0]", harness.rtl)
        self.assertIn(".coverage_epoch_i(coverage_epoch_i)", harness.rtl)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "all.sv"
            path.write_text("module soc(input logic clk,input logic resetn,input logic pin,output logic seen,"
                            "input logic [3:0] coverage_epoch_i,output logic [2:0] __vi_coverage);"
                            "assign seen=pin; assign __vi_coverage={pin,1'b0,pin}; endmodule\n" + harness.rtl)
            result = subprocess.run(["iverilog", "-g2012", "-s", harness.module_name,
                                     "-o", str(Path(directory) / "a.out"), str(path)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__": unittest.main()
