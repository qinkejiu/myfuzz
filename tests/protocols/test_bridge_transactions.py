"""Clocked protocol bridge transactions; no waveform generation."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

RTL = Path(__file__).resolve().parents[2] / "src/myfuzz/protocols/rtl"
COMMON = """module tb;
logic clk=0, rst=0, valid=0, write=0, ready, response, error;
logic [31:0] address=32'h40, data=32'h12345678, result;
logic [3:0] be=4'hf;
always #5 clk=~clk;
initial begin #10000; $fatal(1,"test timed out"); end
task tick; @(posedge clk); #1; endtask
task check(input bit condition); if (!condition) $fatal(1,"transaction failed"); endtask
"""
CANONICAL = """
.clk_i(clk), .rst_ni(rst), .req_valid_i(valid), .req_write_i(write),
.req_addr_i(address), .req_wdata_i(data), .req_be_i(be), .req_ready_o(ready),
.rsp_valid_o(response), .rsp_ready_i(1'b0), .rsp_rdata_o(result), .rsp_error_o(error)
"""


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class BridgeTransactionTests(unittest.TestCase):
    def run_rtl(self, module, body):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bench, executable = root / "tb.sv", root / "sim.vvp"
            bench.write_text(COMMON + body + "\nendmodule\n")
            compiled = subprocess.run(
                [shutil.which("iverilog"), "-g2012", "-s", "tb", "-o", str(executable),
                 str(RTL / (module + ".sv")), str(bench)],
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(0, compiled.returncode, compiled.stderr)
            result = subprocess.run([shutil.which("vvp"), str(executable)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_apb_setup_access_wait_and_error(self):
        self.run_rtl("apb3_mmio_bridge", """
logic select, enable, pwrite, pready=0, pslverr=0;
logic [31:0] paddr, pwdata;
apb3_mmio_bridge dut (""" + CANONICAL + """,
.psel_o(select), .penable_o(enable), .pwrite_o(pwrite), .pready_i(pready),
.pslverr_i(pslverr), .paddr_o(paddr), .pwdata_o(pwdata), .prdata_i(32'hfeed));
initial begin
 tick; rst=1; @(negedge clk); valid=1;
 tick; check(select && !enable && paddr==32'h40);
 @(negedge clk); valid=0; address=32'h80;
 tick; check(select && enable && paddr==32'h40);
 repeat(3) begin tick; check(select && enable && !response && paddr==32'h40); end
 @(negedge clk); pready=1; pslverr=1;
 tick; check(response && error && !select);
 repeat(2) begin tick; check(response && error && !ready); end
 $finish;
end
""")

    def test_obi_grant_and_response_are_separate(self):
        self.run_rtl("obi_mmio_bridge", """
logic request, grant=0, response_valid=0, we;
logic [31:0] addr, wdata;
obi_mmio_bridge dut (""" + CANONICAL + """,
.req_o(request), .gnt_i(grant), .rvalid_i(response_valid), .rdata_i(32'hface),
.addr_o(addr), .we_o(we), .wdata_o(wdata));
initial begin
 tick; rst=1; @(negedge clk); valid=1;
 tick; check(request && addr==32'h40);
 @(negedge clk); valid=0; address=32'h80;
 repeat(2) begin tick; check(request && addr==32'h40 && !response); end
 @(negedge clk); grant=1;
 tick; check(!request && !response);
 @(negedge clk); grant=0;
 repeat(2) begin tick; check(!response); end
 @(negedge clk); response_valid=1;
 tick; check(response && !error && result==32'hface);
 repeat(2) begin tick; check(response && result==32'hface && !ready); end
 $finish;
end
""")

    def test_axi_write_data_can_be_accepted_before_address(self):
        self.run_rtl("axi4_mmio_bridge", """
logic awvalid, wvalid, bready, awready=0, wready=0, bvalid=0;
logic [31:0] awaddr, wdata;
axi4_mmio_bridge dut (""" + CANONICAL + """,
.awvalid_o(awvalid), .awready_i(awready), .awaddr_o(awaddr),
.wvalid_o(wvalid), .wready_i(wready), .wdata_o(wdata),
.bready_o(bready), .bvalid_i(bvalid), .bresp_i(2'b00), .bid_i(1'b0),
.arready_i(1'b0), .rid_i(1'b0), .rdata_i(32'b0), .rresp_i(2'b0), .rlast_i(1'b0), .rvalid_i(1'b0));
initial begin
 tick; rst=1; @(negedge clk); valid=1; write=1;
 tick; check(awvalid && wvalid && awaddr==32'h40 && wdata==32'h12345678);
 @(negedge clk); valid=0; wready=1;
 tick; check(awvalid && !wvalid && !bready);
 @(negedge clk); wready=0;
 repeat(2) begin tick; check(awvalid && !wvalid && !response); end
 @(negedge clk); awready=1;
 tick; check(!awvalid && bready);
 @(negedge clk); awready=0; bvalid=1;
 tick; check(response && !error);
 repeat(2) begin tick; check(response && !ready); end
 $finish;
end
""")
