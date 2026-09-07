from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"


class ObiProcessorMemoryAdapterRtlTests(unittest.TestCase):
    def test_read_only_profile_forces_read_and_full_byte_enable(self) -> None:
        iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
        if not iverilog or not vvp:
            self.skipTest("Icarus Verilog is not installed")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ro.vvp"
            tb = Path(directory) / "ro.sv"
            tb.write_text(textwrap.dedent("""
                module tb;
                  logic clk_i=0, rst_ni=0, req_i=0, gnt_o, we_i=1;
                  logic [31:0] addr_i=32'h44, wdata_i=32'hdeadbeef;
                  logic [3:0] be_i=4'b0001; logic rvalid_o; logic [31:0] rdata_o; logic error_o;
                  logic req_valid_o, req_ready_i=1, req_write_o; logic [31:0] req_addr_o;
                  logic [31:0] req_wdata_o; logic [3:0] req_be_o;
                  logic rsp_valid_i=0, rsp_ready_o; logic [31:0] rsp_rdata_i=0; logic rsp_error_i=0;
                  obi_processor_memory_adapter #(.READ_ONLY(1), .HAS_BE(0), .HAS_ERROR(1)) dut (.*);
                  always #5 clk_i=~clk_i;
                  initial begin
                    @(posedge clk_i); #1; rst_ni=1; @(negedge clk_i); req_i=1; #1;
                    if (!req_valid_o || !gnt_o || req_write_o || req_be_o!=4'b1111 ||
                        req_wdata_o!=0 || req_addr_o!=32'h44) $fatal(1, "read-only projection");
                    @(posedge clk_i); #1; req_i=0; req_ready_i=0;
                    @(negedge clk_i); rsp_valid_i=1; rsp_rdata_i=32'hc001c0de;
                    @(posedge clk_i); #1;
                    if (!rvalid_o || rdata_o!=32'hc001c0de || error_o) $fatal(1, "read response");
                    $display("PASS"); $finish;
                  end
                endmodule
            """), encoding="utf-8")
            compiled = subprocess.run(
                [iverilog, "-g2012", "-s", "tb", "-o", str(output), str(RTL), str(tb)],
                cwd=ROOT, text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            result = subprocess.run([vvp, str(output)], cwd=ROOT, text=True,
                                    capture_output=True, timeout=20)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)

    def test_grant_backend_stalls_response_errors_and_reset(self) -> None:
        iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
        if not iverilog or not vvp:
            self.skipTest("Icarus Verilog is not installed")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "tb.vvp"
            tb = Path(directory) / "tb.sv"
            tb.write_text(textwrap.dedent("""
                module tb;
                  logic clk_i=0, rst_ni=0;
                  logic req_i, gnt_o, we_i; logic [31:0] addr_i, wdata_i;
                  logic [3:0] be_i; logic rvalid_o; logic [31:0] rdata_o; logic error_o;
                  logic req_valid_o, req_ready_i, req_write_o; logic [31:0] req_addr_o;
                  logic [31:0] req_wdata_o; logic [3:0] req_be_o;
                  logic rsp_valid_i, rsp_ready_o; logic [31:0] rsp_rdata_i; logic rsp_error_i;
                  obi_processor_memory_adapter #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32),
                    .READ_ONLY(0), .HAS_BE(1), .HAS_ERROR(1)) dut (.*);
                  always #5 clk_i=~clk_i;
                  task tick; @(posedge clk_i); #1; endtask
                  task check(input bit ok, input [8*80-1:0] msg);
                    if (!ok) begin $display("FAIL: %0s",msg); $fatal(1); end
                  endtask
                  initial begin
                    req_i=0; we_i=0; addr_i=0; wdata_i=0; be_i=0;
                    req_ready_i=0; rsp_valid_i=0; rsp_rdata_i=0; rsp_error_i=0;
                    tick(); rst_ni=1;
                    @(negedge clk_i); req_i=1; we_i=1; addr_i=32'h80;
                    wdata_i=32'h12345678; be_i=4'b0101;
                    repeat(2) begin tick(); check(req_valid_o && !gnt_o && req_write_o &&
                      req_addr_o==32'h80 && req_wdata_o==32'h12345678 && req_be_o==4'b0101,
                      "OBI payload held while backend stalls"); end
                    @(negedge clk_i); req_ready_i=1; #1;
                    check(gnt_o && req_valid_o, "grant exactly qualifies backend acceptance");
                    tick(); check(!gnt_o && rsp_ready_o, "accepted request waits for response");
                    @(negedge clk_i); req_i=0; req_ready_i=0; tick();
                    check(rsp_ready_o && !rvalid_o, "response wait survives request removal");
                    @(negedge clk_i); rsp_valid_i=1; rsp_rdata_i=32'hfeedbeef; rsp_error_i=1; tick();
                    check(rvalid_o && rdata_o==32'hfeedbeef && error_o,
                          "backend response becomes one OBI response pulse");
                    @(negedge clk_i); rsp_valid_i=0; tick();
                    check(!rvalid_o && req_valid_o==0, "OBI response pulse clears");
                    @(negedge clk_i); req_i=1; tick();
                    @(negedge clk_i); rst_ni=0; tick();
                    check(!gnt_o && !req_valid_o && !rvalid_o && !rsp_ready_o,
                          "reset discards outstanding request");
                    $display("PASS"); $finish;
                  end
                endmodule
            """), encoding="utf-8")
            compiled = subprocess.run(
                [iverilog, "-g2012", "-s", "tb", "-o", str(output), str(RTL), str(tb)],
                cwd=ROOT, text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            result = subprocess.run(
                [vvp, str(output)], cwd=ROOT, text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
