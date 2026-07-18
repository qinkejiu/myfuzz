import tempfile
import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    SystemSpec, analyze_declared_components_v2, build_protocol_system_v2,
    run_generated_bcd_campaign,
)


def _interface(role, prefix):
    target_directions = {
        "awvalid": "input", "awready": "output", "awaddr": "input",
        "wvalid": "input", "wready": "output", "wdata": "input", "wstrb": "input",
        "bvalid": "output", "bready": "input", "bresp": "output",
        "arvalid": "input", "arready": "output", "araddr": "input",
        "rvalid": "output", "rready": "input", "rdata": "output", "rresp": "output",
    }
    if role == "initiator":
        target_directions = {
            name: "output" if direction == "input" else "input"
            for name, direction in target_directions.items()
        }
    return {
        "name": "bus", "protocol": "axi_lite", "role": role,
        "ports": {name: f"{prefix}_{name}" for name in target_directions},
    }


class AnalyzedDiscoveryV2Test(unittest.TestCase):
    def test_multiple_logical_instances_can_share_one_rtl_module(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "shared.sv").write_text(
                "module shared(input logic clk, output logic value); assign value=clk; endmodule\n",
                encoding="ascii",
            )
            spec = SystemSpec.from_dict({
                "schema_version": 1,
                "name": "shared_instances",
                "sources": [{"name": "rtl", "rtl_files": ["shared.sv"]}],
                "modules": [
                    {"name": name, "rtl_module": "shared", "kind": "generic",
                     "source_set": "rtl", "component_id": f"ip.{name}",
                     "ports": {"clk": {"direction": "input", "type": "clock", "width": 1}}}
                    for name in ("left", "right")
                ],
            })

            result = analyze_declared_components_v2(spec, root)

            self.assertEqual({module.name for module in result.discovery.modules}, {"left", "right"})
            self.assertEqual(set(result.component_analysis_digests), {"left", "right"})

    def test_internal_dependencies_are_elaborated_but_not_logical_components(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "components.sv"
            source.write_text("""
module hidden_helper(input logic clk,input logic resetn,input logic value_i,output logic value_o);
  always_ff @(posedge clk or negedge resetn) begin
    if (!resetn) value_o <= 1'b0;
    else if (value_i) value_o <= 1'b1;
    else value_o <= 1'b0;
  end
endmodule
module novel_cpu # (parameter WIDTH=32) (
  input logic clk,input logic resetn,
  output logic m_awvalid,input logic m_awready,output logic [WIDTH-1:0] m_awaddr,
  output logic m_wvalid,input logic m_wready,output logic [31:0] m_wdata,
  output logic [3:0] m_wstrb,input logic m_bvalid,output logic m_bready,
  input logic [1:0] m_bresp,output logic m_arvalid,input logic m_arready,
  output logic [WIDTH-1:0] m_araddr,input logic m_rvalid,output logic m_rready,
  input logic [31:0] m_rdata,input logic [1:0] m_rresp);
  always_ff @(posedge clk or negedge resetn) begin
    if (!resetn) m_bready <= 1'b0;
    else if (m_bvalid) m_bready <= 1'b1;
    else m_bready <= 1'b0;
  end
  assign m_awvalid=0; assign m_awaddr='0; assign m_wvalid=0; assign m_wdata='0;
  assign m_wstrb='0; assign m_arvalid=0; assign m_araddr='0;
  assign m_rready=1;
endmodule
module novel_device (
  input logic clk,input logic resetn,
  input logic s_awvalid,output logic s_awready,input logic [31:0] s_awaddr,
  input logic s_wvalid,output logic s_wready,input logic [31:0] s_wdata,
  input logic [3:0] s_wstrb,output logic s_bvalid,input logic s_bready,
  output logic [1:0] s_bresp,input logic s_arvalid,output logic s_arready,
  input logic [31:0] s_araddr,output logic s_rvalid,input logic s_rready,
  output logic [31:0] s_rdata,output logic [1:0] s_rresp);
  logic helper_value;
  hidden_helper helper(.clk(clk),.resetn(resetn),.value_i(s_awvalid),.value_o(helper_value));
  assign s_awready=helper_value; assign s_wready=1; assign s_bvalid=0;
  assign s_bresp=0; assign s_arready=1; assign s_rvalid=0; assign s_rdata=0;
  assign s_rresp=0;
endmodule
""", encoding="ascii")
            spec = SystemSpec.from_dict({
                "schema_version": 1,
                "name": "unseen_components",
                "sources": [{"name": "rtl", "rtl_files": ["components.sv"]}],
                "modules": [
                    {"name": "novel_cpu", "kind": "cpu", "source_set": "rtl",
                     "parameters": {"WIDTH": 32}, "ports": {
                         "clk": {"direction": "input", "type": "clock", "width": 1},
                         "resetn": {"direction": "input", "type": "reset_active_low", "width": 1},
                     },
                     "interfaces": [_interface("initiator", "m")]},
                    {"name": "novel_device", "kind": "peripheral", "source_set": "rtl",
                     "ports": {
                         "clk": {"direction": "input", "type": "clock", "width": 1},
                         "resetn": {"direction": "input", "type": "reset_active_low", "width": 1},
                     }, "interfaces": [_interface("target", "s")],
                     "address": {"mode": "fixed", "base": 0x20000000,
                                 "size": 0x1000, "alignment": 0x1000}},
                ],
            })
            result = analyze_declared_components_v2(spec, root)
            self.assertEqual({module.name for module in result.discovery.modules},
                             {"novel_cpu", "novel_device"})
            device = next(module for module in result.discovery.modules
                          if module.name == "novel_device")
            self.assertEqual(device.instances[0].module_type, "hidden_helper")
            self.assertEqual(set(result.component_analysis_digests),
                             {"novel_cpu", "novel_device"})
            self.assertEqual(len(set(result.source_digests.values())), 1)

            built = build_protocol_system_v2(
                spec, root, root / "build", cpu_profile_id="picorv32",
                operation_timeout_limit=16, coverage_epoch_width=4,
                reset_cycles=1, drain_cycles=2,
            )
            self.assertGreater(built.pipeline.coverage_abi.width, 0)
            self.assertEqual(built.rom.cpu_id, "picorv32")
            run = run_generated_bcd_campaign(
                built.pipeline.target.path, root / "runs", seeds=tuple(range(10)), cycles=2,
            )
            self.assertTrue(run.report["shared_ordered_input_bytes_per_seed"])
            self.assertEqual(run.report["variants"]["D_SCENARIO_CONSTRAINED"]["seed_count"], 10)


if __name__ == "__main__":
    unittest.main()
