import subprocess
import sys
import tempfile
import unittest
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AxiLiteFabricConfig, InputValidationError, analyze_elaboration,
    emit_axi_lite_fabric, emit_generated_soc_top, emit_soc_filelist,
    run_soc_instrumentation, verify_realized_system_ir,
)
from myfuzz.builder.contracts import (  # noqa: E402
    ResolvedFile, SystemIR, build_elaboration_manifest, derive_elaboration_manifest,
)
from myfuzz.instrumentation.source_branch_instrumenter import instrument_project  # noqa: E402


def fixture_ir():
    return SystemIR("soc", (
        {"name": "source", "module_type": "source_mod", "instance": "u_source", "ports": (
            {"name": "clk", "direction": "input", "width": 1, "external": True},
            {"name": "data_o", "direction": "output", "width": 8},
        )},
        {"name": "sink", "module_type": "sink_mod", "instance": "u_sink", "ports": (
            {"name": "data_i", "direction": "input", "width": 8},
            {"name": "seen_o", "direction": "output", "width": 8, "external": True},
        )},
    ), ({"source": "source.data_o", "target": "sink.data_i", "width": 8},), ())


def port(name, direction, width=1, external=False):
    return {"name": name, "direction": direction, "width": width, "external": external}


MASTER_PORTS = (
    port("aclk", "input"), port("aresetn", "input"),
    port("awaddr", "output", 8), port("awvalid", "output"), port("awready", "input"),
    port("wdata", "output", 32), port("wstrb", "output", 4), port("wvalid", "output"),
    port("wready", "input"), port("bresp", "input", 2), port("bvalid", "input"),
    port("bready", "output"), port("araddr", "output", 8), port("arvalid", "output"),
    port("arready", "input"), port("rdata", "input", 32), port("rresp", "input", 2),
    port("rvalid", "input"), port("rready", "output"),
    port("done", "output", external=True), port("failed", "output", external=True),
)

FABRIC_PORTS = (
    port("aclk", "input"), port("aresetn", "input"),
    port("m_awaddr", "input", 8), port("m_awvalid", "input"), port("m_awready", "output"),
    port("m_wdata", "input", 32), port("m_wstrb", "input", 4), port("m_wvalid", "input"),
    port("m_wready", "output"), port("m_bresp", "output", 2), port("m_bvalid", "output"),
    port("m_bready", "input"), port("m_araddr", "input", 8), port("m_arvalid", "input"),
    port("m_arready", "output"), port("m_rdata", "output", 32), port("m_rresp", "output", 2),
    port("m_rvalid", "output"), port("m_rready", "input"),
    port("s_awvalid", "output"), port("s_awaddr", "output", 8), port("s_awready", "input"),
    port("s_wvalid", "output"), port("s_wdata", "output", 32), port("s_wstrb", "output", 4),
    port("s_wready", "input"), port("s_bvalid", "input"), port("s_bresp", "input", 2),
    port("s_bready", "output"), port("s_arvalid", "output"), port("s_araddr", "output", 8),
    port("s_arready", "input"), port("s_rvalid", "input"), port("s_rdata", "input", 32),
    port("s_rresp", "input", 2), port("s_rready", "output"),
)

SLAVE_PORTS = (
    port("aclk", "input"), port("aresetn", "input"),
    port("awvalid", "input"), port("awaddr", "input", 8), port("awready", "output"),
    port("wvalid", "input"), port("wdata", "input", 32), port("wstrb", "input", 4),
    port("wready", "output"), port("bvalid", "output"), port("bresp", "output", 2),
    port("bready", "input"), port("arvalid", "input"), port("araddr", "input", 8),
    port("arready", "output"), port("rvalid", "output"), port("rdata", "output", 32),
    port("rresp", "output", 2), port("rready", "input"),
)


def axi_soc_ir():
    modules = (
        {"name": "clock", "module_type": "clock_reset_source", "instance": "u_clock", "ports": (
            port("clk_i", "input", external=True), port("resetn_i", "input", external=True),
            port("clk_o", "output"), port("resetn_o", "output"),
        )},
        {"name": "master", "module_type": "mock_axi_master", "instance": "u_master", "ports": MASTER_PORTS},
        {"name": "fabric", "module_type": "myfuzz_axi_lite_fabric", "instance": "u_fabric",
         "parameters": {"SLAVES": 1, "DATA_WIDTH": 32, "ADDR_WIDTH": 8}, "ports": FABRIC_PORTS},
        {"name": "slave", "module_type": "mock_axi_slave", "instance": "u_slave", "ports": SLAVE_PORTS},
    )
    connections = []
    for target in ("master", "fabric", "slave"):
        connections.append({"source": "clock.clk_o", "target": f"{target}.aclk", "width": 1})
        connections.append({"source": "clock.resetn_o", "target": f"{target}.aresetn", "width": 1})
    for master_port in MASTER_PORTS[2:19]:
        name = master_port["name"]
        fabric_name = f"m_{name}"
        if master_port["direction"] == "output":
            source, target = f"master.{name}", f"fabric.{fabric_name}"
        else:
            source, target = f"fabric.{fabric_name}", f"master.{name}"
        connections.append({"source": source, "target": target, "width": master_port["width"]})
    for slave_port in SLAVE_PORTS[2:]:
        name = slave_port["name"]
        fabric_name = f"s_{name}"
        if slave_port["direction"] == "input":
            source, target = f"fabric.{fabric_name}", f"slave.{name}"
        else:
            source, target = f"slave.{name}", f"fabric.{fabric_name}"
        connections.append({"source": source, "target": target, "width": slave_port["width"]})
    return SystemIR("axi_soc", modules, tuple(connections), (
        {"module": "slave", "base": 0x10, "size": 0x10},
    ))


AXI_FIXTURE_RTL = r"""
module clock_reset_source(input logic clk_i, input logic resetn_i,
 output logic clk_o, output logic resetn_o);
 assign clk_o=clk_i; assign resetn_o=resetn_i;
endmodule

module mock_axi_master(
 input logic aclk, input logic aresetn,
 output logic [7:0] awaddr, output logic awvalid, input logic awready,
 output logic [31:0] wdata, output logic [3:0] wstrb, output logic wvalid, input logic wready,
 input logic [1:0] bresp, input logic bvalid, output logic bready,
 output logic [7:0] araddr, output logic arvalid, input logic arready,
 input logic [31:0] rdata, input logic [1:0] rresp, input logic rvalid, output logic rready,
 output logic done, output logic failed);
 logic [2:0] state;
 always_ff @(posedge aclk or negedge aresetn) begin
  if (!aresetn) begin
   state<=0; awaddr<=8'h14; awvalid<=0; wdata<=32'hcafe_babe; wstrb<=4'hf; wvalid<=0;
   bready<=0; araddr<=8'h14; arvalid<=0; rready<=0; done<=0; failed<=0;
  end else begin
   case (state)
    0: begin awvalid<=1; wvalid<=1; state<=1; end
    1: begin
     if (awvalid && awready) awvalid<=0;
     if (wvalid && wready) wvalid<=0;
     if ((!awvalid || awready) && (!wvalid || wready)) begin bready<=1; state<=2; end
    end
    2: if (bvalid) begin
     if (bresp != 0) failed<=1;
     bready<=0; arvalid<=1; state<=3;
    end
    3: if (arvalid && arready) begin arvalid<=0; rready<=1; state<=4; end
    4: if (rvalid) begin
     if (rresp != 0 || rdata != 32'hcafe_babe) failed<=1;
     rready<=0; done<=1; state<=5;
    end
   endcase
  end
 end
endmodule

module mock_axi_slave(
 input logic aclk, input logic aresetn,
 input logic awvalid, input logic [7:0] awaddr, output logic awready,
 input logic wvalid, input logic [31:0] wdata, input logic [3:0] wstrb, output logic wready,
 output logic bvalid, output logic [1:0] bresp, input logic bready,
 input logic arvalid, input logic [7:0] araddr, output logic arready,
 output logic rvalid, output logic [31:0] rdata, output logic [1:0] rresp, input logic rready);
 logic aw_hold, w_hold; logic [31:0] pending_data, register;
 assign awready=!aw_hold && !bvalid;
 assign wready=!w_hold && !bvalid;
 assign arready=!rvalid;
 always_ff @(posedge aclk or negedge aresetn) begin
  if (!aresetn) begin
   aw_hold<=0; w_hold<=0; pending_data<=0; register<=0;
   bvalid<=0; bresp<=0; rvalid<=0; rdata<=0; rresp<=0;
  end else begin
   if (awvalid && awready) aw_hold<=1;
   if (wvalid && wready) begin w_hold<=1; pending_data<=wdata; end
   if (!bvalid && (aw_hold || (awvalid && awready)) && (w_hold || (wvalid && wready))) begin
    register <= w_hold ? pending_data : wdata; aw_hold<=0; w_hold<=0; bvalid<=1; bresp<=0;
   end
   if (bvalid && bready) bvalid<=0;
   if (arvalid && arready) begin rvalid<=1; rdata<=register; rresp<=0; end
   if (rvalid && rready) rvalid<=0;
  end
 end
endmodule
"""


class SocEmitterTest(unittest.TestCase):
    def test_emits_deterministic_synthesizable_top(self):
        first = emit_generated_soc_top(fixture_ir())
        self.assertEqual(first, emit_generated_soc_top(fixture_ir()))
        self.assertEqual(first.external_ports, ("sink__seen_o", "source__clk"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "soc.sv"
            source.write_text(
                "module source_mod(input logic clk, output logic [7:0] data_o); assign data_o={8{clk}}; endmodule\n"
                "module sink_mod(input logic [7:0] data_i, output logic [7:0] seen_o); assign seen_o=data_i; endmodule\n"
                + first.rtl
            )
            result = subprocess.run(
                ["iverilog", "-g2012", "-s", "generated_soc_top", "-o", str(root / "a.out"), str(source)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unconnected_input_and_unobserved_output_fail(self):
        ir = fixture_ir()
        broken = dict(ir.modules[1])
        broken["ports"] = ({"name": "data_i", "direction": "input", "width": 8},)
        with self.assertRaisesRegex(InputValidationError, "unconnected required input"):
            emit_generated_soc_top(SystemIR("bad", (broken,), (), ()))

    def test_duplicate_logical_or_instance_names_fail(self):
        first, second = fixture_ir().modules
        duplicate_name = dict(second, name=first["name"])
        with self.assertRaisesRegex(InputValidationError, "unique logical"):
            emit_generated_soc_top(SystemIR("duplicate", (first, duplicate_name), (), ()))
        duplicate_instance = dict(second, instance=first["instance"])
        with self.assertRaisesRegex(InputValidationError, "unique instance"):
            emit_generated_soc_top(SystemIR("duplicate", (first, duplicate_instance), (), ()))

    def test_soc_filelist_serializes_derived_manifest_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base_source = root / "base.sv"
            generated_source = root / "generated_soc_top.sv"
            base_source.write_text("module base; endmodule\n")
            generated_source.write_text("module generated_soc_top; endmodule\n")
            base = build_elaboration_manifest(
                top_module="base", rtl_files=(base_source,), allow_roots=(root,),
                parameters={"WIDTH": 8}, tools={"verilator": "5.020"},
            )
            generated = ResolvedFile(
                str(generated_source), hashlib.sha256(generated_source.read_bytes()).hexdigest(),
                generated_source.stat().st_size,
            )
            derived = derive_elaboration_manifest(
                base, stage="soc", top_module="generated_soc_top", added_sources=(generated,),
            )
            filelist = emit_soc_filelist(derived)
            self.assertEqual(filelist, emit_soc_filelist(derived))
            self.assertIn(f"-GWIDTH=8\n", filelist)
            self.assertLess(filelist.index(str(base_source)), filelist.index(str(generated_source)))

    def test_one_output_fans_out_on_one_shared_net(self):
        modules = (
            {"name": "source", "module_type": "source_mod", "instance": "u_source", "ports": (
                {"name": "clk", "direction": "input", "width": 1, "external": True},
                {"name": "data_o", "direction": "output", "width": 8},
            )},
            {"name": "a", "module_type": "sink_mod", "instance": "u_a", "ports": (
                {"name": "data_i", "direction": "input", "width": 8},
                {"name": "seen_o", "direction": "output", "width": 8, "external": True},
            )},
            {"name": "b", "module_type": "sink_mod", "instance": "u_b", "ports": (
                {"name": "data_i", "direction": "input", "width": 8},
                {"name": "seen_o", "direction": "output", "width": 8, "external": True},
            )},
        )
        connections = (
            {"source": "source.data_o", "target": "a.data_i", "width": 8},
            {"source": "source.data_o", "target": "b.data_i", "width": 8},
        )
        rtl = emit_generated_soc_top(SystemIR("fanout", modules, connections, ())).rtl
        self.assertEqual(rtl.count("logic [7:0] __edge_0000;"), 1)
        self.assertNotIn("__edge_0001", rtl)

    def test_parameter_overrides_are_sorted_and_invalid_values_fail(self):
        module = dict(fixture_ir().modules[0])
        module["ports"] = tuple(
            dict(item, external=True) if item["direction"] == "output" else item
            for item in module["ports"]
        )
        module["parameters"] = {"WIDTH": 8, "ENABLED": True}
        rtl = emit_generated_soc_top(SystemIR("parameters", (module,), (), ())).rtl
        self.assertLess(rtl.index(".ENABLED(1'b1)"), rtl.index(".WIDTH(8)"))
        module["parameters"] = {"MODE": "unsafe_expression"}
        with self.assertRaisesRegex(InputValidationError, "integer or boolean"):
            emit_generated_soc_top(SystemIR("bad_parameters", (module,), (), ()))

    def test_real_axi_soc_compiles_and_completes_write_read(self):
        emitted = emit_generated_soc_top(axi_soc_ir())
        self.assertEqual(emitted.external_ports, (
            "clock__clk_i", "clock__resetn_i", "master__done", "master__failed",
        ))
        testbench = r"""
module tb;
 logic clk=0, resetn=0; logic done, failed;
 generated_soc_top dut(.clock__clk_i(clk), .clock__resetn_i(resetn),
  .master__done(done), .master__failed(failed));
 always #5 clk=~clk;
 initial begin
  repeat (3) @(posedge clk); resetn=1;
  repeat (80) begin @(posedge clk); if (done) begin
   if (failed) $fatal(1, "AXI transaction failed");
   $display("AXI_SOC_PASS"); $finish;
  end end
  $fatal(1, "AXI transaction timed out");
 end
endmodule
"""
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as testbench_directory,
            tempfile.TemporaryDirectory() as instrumentation_directory,
        ):
            root = Path(directory)
            source = root / "axi_soc.sv"
            source.write_text(
                AXI_FIXTURE_RTL
                + emit_axi_lite_fabric(AxiLiteFabricConfig(8, 32, 1, (0x10,), (0x10,)))
                + emitted.rtl
            )
            testbench_source = Path(testbench_directory) / "tb.sv"
            testbench_source.write_text(testbench)
            compile_result = subprocess.run(
                ["iverilog", "-g2012", "-s", "tb", "-o", str(root / "a.out"),
                 str(source), str(testbench_source)],
                capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            simulation = subprocess.run(["vvp", str(root / "a.out")], capture_output=True, text=True)
            self.assertEqual(simulation.returncode, 0, simulation.stderr + simulation.stdout)
            self.assertIn("AXI_SOC_PASS", simulation.stdout)

            base = build_elaboration_manifest(
                top_module="mock_axi_master", rtl_files=(source,), allow_roots=(root,),
                tools={"verilator": "5.020"},
            )
            manifest = derive_elaboration_manifest(
                base, stage="soc", top_module="generated_soc_top",
            )

            library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
            if library.is_file():
                analysis = analyze_elaboration(
                    manifest, project_root=root, frontend_library=library,
                )
                self.assertEqual(analysis.top_module, "generated_soc_top")
                self.assertTrue(any(item.original_name == "myfuzz_axi_lite_fabric" for item in analysis.modules))
                self.assertTrue(verify_realized_system_ir(axi_soc_ir(), analysis).equivalent)
                broken_connections = [dict(item) for item in axi_soc_ir().connections]
                awvalid = next(item for item in broken_connections if item["target"] == "fabric.m_awvalid")
                bready = next(item for item in broken_connections if item["target"] == "fabric.m_bready")
                awvalid["target"], bready["target"] = bready["target"], awvalid["target"]
                broken_ir = SystemIR(
                    "broken_axi_soc", axi_soc_ir().modules, tuple(broken_connections),
                    axi_soc_ir().address_windows,
                )
                with self.assertRaisesRegex(InputValidationError, "graph mismatch"):
                    verify_realized_system_ir(broken_ir, analysis)

            destination = Path(instrumentation_directory) / "instrumented"
            coverage = run_soc_instrumentation(
                manifest, root, destination,
                required_modules={
                    "generated_soc_top", "mock_axi_master",
                    "myfuzz_axi_lite_fabric", "mock_axi_slave",
                },
                optional_modules={"clock_reset_source"},
            )
            self.assertGreater(coverage["coverage_point_count"], 0)
            catalog = coverage["coverage_abi"]["points"]
            self.assertFalse(any(
                not point["included"] and point["requirement"] == "required"
                for point in catalog
            ))
            instrumented_compile = subprocess.run(
                ["iverilog", "-g2012", "-s", "generated_soc_top", "-o",
                 str(destination / "a.out"),
                 *(item["path"] for item in coverage["instrumented_manifest"]["sources"])],
                capture_output=True, text=True,
            )
            self.assertEqual(instrumented_compile.returncode, 0, instrumented_compile.stderr)

    def test_generated_top_passes_second_verilator_analysis(self):
        library = ROOT / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"
        if not library.is_file():
            self.skipTest("myfuzz Verilator frontend library has not been built")
        emitted = emit_generated_soc_top(fixture_ir())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "generated_soc_top.sv"
            source.write_text(
                "module source_mod(input logic clk, output logic [7:0] data_o); assign data_o={8{clk}}; endmodule\n"
                "module sink_mod(input logic [7:0] data_i, output logic [7:0] seen_o); assign seen_o=data_i; endmodule\n"
                + emitted.rtl
            )
            base = build_elaboration_manifest(
                top_module="source_mod", rtl_files=(source,), allow_roots=(root,),
                tools={"verilator": "5.020"},
            )
            manifest = derive_elaboration_manifest(base, stage="soc", top_module="generated_soc_top")
            analysis = analyze_elaboration(manifest, project_root=root, frontend_library=library)
        self.assertEqual(analysis.top_module, "generated_soc_top")
        self.assertTrue(any(module.original_name == "generated_soc_top" for module in analysis.modules))

    def test_generated_top_is_instrumented_hierarchically_and_recompiles(self):
        emitted = emit_generated_soc_top(fixture_ir())
        with tempfile.TemporaryDirectory() as project, tempfile.TemporaryDirectory() as output:
            root = Path(project)
            destination = Path(output)
            (root / "soc.sv").write_text(
                "module source_mod(input logic clk, output logic [7:0] data_o); "
                "always_comb begin if(clk) data_o=8'hff; else data_o=0; end endmodule\n"
                "module sink_mod(input logic [7:0] data_i, output logic [7:0] seen_o); "
                "assign seen_o=data_i; endmodule\n" + emitted.rtl
            )
            manifest = instrument_project(
                root, destination, top_module="generated_soc_top", force=True,
            )
            self.assertGreater(manifest["coverage_point_count"], 0)
            result = subprocess.run(
                ["iverilog", "-g2012", "-s", "generated_soc_top", "-o",
                 str(destination / "a.out"), str(destination / "soc.sv")],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
