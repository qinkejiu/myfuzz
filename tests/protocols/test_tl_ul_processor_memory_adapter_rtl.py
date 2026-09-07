from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/tl_ul_processor_memory_adapter.sv"


class TlUlProcessorMemoryAdapterRtlTests(unittest.TestCase):
    def test_requests_responses_identity_errors_and_backpressure(self) -> None:
        iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
        if not iverilog or not vvp:
            self.skipTest("Icarus Verilog is not installed")
        with tempfile.TemporaryDirectory() as directory:
            out, tb = Path(directory)/"tb.vvp", Path(directory)/"tb.sv"
            tb.write_text(textwrap.dedent("""
              module tb;
                logic clk_i=0,rst_ni=0,a_valid_i,a_ready_o; logic [2:0] a_opcode_i,a_param_i,a_size_i;
                logic a_source_i; logic [31:0] a_address_i,a_data_i; logic [3:0] a_mask_i; logic a_corrupt_i;
                logic d_valid_o,d_ready_i; logic [2:0] d_opcode_o,d_param_o,d_size_o; logic d_source_o,d_sink_o;
                logic d_denied_o; logic [31:0] d_data_o; logic d_corrupt_o;
                logic req_valid_o,req_ready_i,req_write_o; logic [31:0] req_addr_o,req_wdata_o;
                logic [3:0] req_be_o; logic rsp_valid_i,rsp_ready_o; logic [31:0] rsp_rdata_i; logic rsp_error_i;
                tl_ul_processor_memory_adapter dut(.*); always #5 clk_i=~clk_i;
                task tick; @(posedge clk_i); #1; endtask
                task check(input bit ok,input [8*80-1:0] msg); if(!ok) begin $display("FAIL: %0s",msg);$fatal(1);end endtask
                initial begin
                  a_valid_i=1;a_opcode_i=4;a_param_i=0;a_size_i=2;a_source_i=1;a_address_i=32'h40;
                  a_mask_i=4'hf;a_data_i=0;a_corrupt_i=0;d_ready_i=0;req_ready_i=0;
                  rsp_valid_i=0;rsp_rdata_i=0;rsp_error_i=0;#1;
                  check(!a_ready_o,"reset blocks source acceptance despite valid request");
                  tick();rst_ni=1;@(negedge clk_i);a_valid_i=0;
                  @(negedge clk_i);a_valid_i=1;tick();check(req_valid_o&&!a_ready_o&&!req_write_o&&req_addr_o==32'h40,
                    "Get becomes held backend request");
                  @(negedge clk_i);a_valid_i=0;repeat(2)begin tick();check(req_valid_o&&req_addr_o==32'h40,"request held");end
                  @(negedge clk_i);req_ready_i=1;tick();check(!req_valid_o&&rsp_ready_o,"backend accepted");
                  @(negedge clk_i);req_ready_i=0;rsp_valid_i=1;rsp_rdata_i=32'hfeedbeef;rsp_error_i=1;tick();
                  check(d_valid_o&&d_opcode_o==1&&d_source_o==1&&d_size_o==2&&d_denied_o&&d_corrupt_o,
                    "read error preserves TL identity and shape");
                  @(negedge clk_i);rsp_valid_i=0;repeat(2)begin tick();check(d_valid_o&&d_data_o==0,"D held");end
                  @(negedge clk_i);d_ready_i=1;tick();check(!d_valid_o&&a_ready_o,"D handshake releases");
                  @(negedge clk_i);d_ready_i=0;a_valid_i=1;a_opcode_i=1;a_source_i=0;a_address_i=32'h44;
                  a_mask_i=4'b0011;a_data_i=32'h12345678;tick();
                  check(req_valid_o&&req_write_o&&req_be_o==4'b0011&&req_wdata_o==32'h12345678,"PutPartial maps bytes");
                  @(negedge clk_i);a_valid_i=0;req_ready_i=1;tick();
                  @(negedge clk_i);req_ready_i=0;rsp_valid_i=1;rsp_error_i=0;tick();
                  check(d_valid_o&&d_opcode_o==0&&!d_denied_o&&!d_corrupt_o,"write AccessAck");
                  @(negedge clk_i);rsp_valid_i=0;d_ready_i=1;tick();
                  @(negedge clk_i);d_ready_i=0;a_valid_i=1;a_opcode_i=1;a_mask_i=0;tick();
                  check(d_valid_o&&d_opcode_o==0&&!d_denied_o&&!req_valid_o,
                    "empty PutPartial is a successful local no-op");
                  @(negedge clk_i);a_valid_i=0;d_ready_i=1;tick();
                  @(negedge clk_i);d_ready_i=0;a_valid_i=1;a_opcode_i=2;tick();
                  check(d_valid_o&&d_opcode_o==1&&d_denied_o&&d_corrupt_o&&!req_valid_o,
                    "unsupported ArithmeticData gets AccessAckData error");
                  @(negedge clk_i);a_valid_i=0;d_ready_i=1;tick();
                  @(negedge clk_i);d_ready_i=0;a_valid_i=1;a_opcode_i=4;a_size_i=3;a_address_i=32'h40;a_mask_i=4'hf;tick();
                  check(d_valid_o&&d_opcode_o==1&&d_denied_o&&d_corrupt_o,"large Get first error beat");
                  @(negedge clk_i);a_valid_i=0;d_ready_i=1;tick();check(d_valid_o,"large Get second error beat");
                  tick();check(!d_valid_o,"large Get returns declared D beat count");
                  @(negedge clk_i);d_ready_i=0;a_valid_i=1;a_opcode_i=0;tick();
                  check(a_ready_o&&!d_valid_o&&!req_valid_o,"large Put drains remaining A beat");
                  tick();check(d_valid_o&&d_opcode_o==0&&d_denied_o,"large Put responds after A drain");
                  @(negedge clk_i);rst_ni=0;tick();check(!a_ready_o&&!d_valid_o&&!req_valid_o&&!rsp_ready_o,"reset clears");
                  $display("PASS");$finish;
                end
              endmodule
            """),encoding="utf-8")
            compiled=subprocess.run([iverilog,"-g2012","-s","tb","-o",str(out),str(RTL),str(tb)],cwd=ROOT,text=True,capture_output=True,timeout=20)
            self.assertEqual(0,compiled.returncode,compiled.stderr)
            result=subprocess.run([vvp,str(out)],cwd=ROOT,text=True,capture_output=True,timeout=20)
            self.assertEqual(0,result.returncode,result.stdout+result.stderr)
            self.assertIn("PASS",result.stdout)

if __name__ == "__main__": unittest.main()
