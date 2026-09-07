from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class ProcessorMemoryArbiterRtlTests(unittest.TestCase):
    def test_two_named_initiators_share_backend_with_exactly_once_completions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, bench = root / "arbiter.vvp", root / "arbiter_tb.sv"
            bench.write_text(textwrap.dedent(r"""
                module tb;
                  logic clk_i=0, rst_ni=0;
                  logic i0_req_valid_i=0, i0_req_ready_o, i0_req_write_i=0, i0_req_mapped_i=1;
                  logic [31:0] i0_req_addr_i=0, i0_req_wdata_i=0; logic [3:0] i0_req_be_i=0;
                  logic i0_rsp_valid_o, i0_rsp_ready_i=1; logic [31:0] i0_rsp_rdata_o; logic i0_rsp_error_o;
                  logic i1_req_valid_i=0, i1_req_ready_o, i1_req_write_i=0, i1_req_mapped_i=1;
                  logic [31:0] i1_req_addr_i=0, i1_req_wdata_i=0; logic [3:0] i1_req_be_i=0;
                  logic i1_rsp_valid_o, i1_rsp_ready_i=1; logic [31:0] i1_rsp_rdata_o; logic i1_rsp_error_o;
                  logic req_valid_o, req_ready_i=0, req_write_o; logic [31:0] req_addr_o, req_wdata_o;
                  logic [3:0] req_be_o; logic rsp_valid_i=0, rsp_ready_o;
                  logic [31:0] rsp_rdata_i=0; logic rsp_error_i=0;
                  integer c0=0, c1=0, backend_accepts=0;

                  processor_memory_arbiter #(
                    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(3),
                    .INITIATOR0_READ_ONLY(0), .INITIATOR1_READ_ONLY(1)
                  ) dut (.*);
                  always #5 clk_i=~clk_i;
                  always @(posedge clk_i) begin
                    if (rst_ni && req_valid_o && req_ready_i) backend_accepts <= backend_accepts+1;
                    if (rst_ni && i0_rsp_valid_o && i0_rsp_ready_i) c0 <= c0+1;
                    if (rst_ni && i1_rsp_valid_o && i1_rsp_ready_i) c1 <= c1+1;
                  end
                  task tick; @(posedge clk_i); #1; endtask
                  task check(input bit ok, input [8*96-1:0] msg);
                    if (!ok) begin $display("FAIL: %0s",msg); $fatal(1); end
                  endtask
                  task respond(input [31:0] data, input bit error);
                    begin
                      @(negedge clk_i); rsp_valid_i=1; rsp_rdata_i=data; rsp_error_i=error;
                      tick(); @(negedge clk_i); rsp_valid_i=0; rsp_error_i=0;
                    end
                  endtask

                  initial begin
                    tick(); rst_ni=1;

                    // Simultaneous named requesters: source 0 wins first, payload is held.
                    @(negedge clk_i);
                    i0_req_valid_i=1; i0_req_addr_i=32'h100; i0_req_write_i=1;
                    i0_req_wdata_i=32'h11223344; i0_req_be_i=4'b0101;
                    i1_req_valid_i=1; i1_req_addr_i=32'h200;
                    #1; check(i0_req_ready_o && !i1_req_ready_o, "initial round-robin owner");
                    tick();
                    i0_req_addr_i=32'hdeadbeef; i0_req_wdata_i=0; i0_req_be_i=0;
                    repeat(2) begin
                      tick(); check(req_valid_o && !req_ready_i && req_addr_o==32'h100 &&
                        req_write_o && req_wdata_o==32'h11223344 && req_be_o==4'b0101,
                        "request payload stable under backend backpressure");
                    end
                    @(negedge clk_i); req_ready_i=1; tick();
                    @(negedge clk_i); req_ready_i=0; i0_req_valid_i=0;
                    respond(32'ha0a0a0a0, 0); tick();
                    check(c0==1 && c1==0, "response belongs only to source 0");

                    // Source 1 was continuously valid, so fairness grants it next.
                    #1; check(i1_req_ready_o, "waiting source receives next grant");
                    tick(); @(negedge clk_i); i1_req_valid_i=0;
                    req_ready_i=1; tick(); @(negedge clk_i); req_ready_i=0;
                    respond(32'hb1b1b1b1, 0); tick();
                    check(c0==1 && c1==1, "fair source 1 completion");

                    // Response payload and ownership hold while owner applies backpressure.
                    @(negedge clk_i); i0_req_valid_i=1; i0_req_write_i=0; i0_req_addr_i=32'h300;
                    tick(); @(negedge clk_i); i0_req_valid_i=0; req_ready_i=1; tick();
                    @(negedge clk_i); req_ready_i=0; i0_rsp_ready_i=0;
                    respond(32'hcafef00d, 0);
                    repeat(2) begin tick(); check(i0_rsp_valid_o && !i1_rsp_valid_o &&
                      i0_rsp_rdata_o==32'hcafef00d && !i0_rsp_error_o,
                      "response stable under owner backpressure"); end
                    @(negedge clk_i); i0_rsp_ready_i=1; tick();

                    // Unmapped accesses and read-only writes error without backend effects.
                    @(negedge clk_i); i0_req_valid_i=1; i0_req_mapped_i=0; i0_req_addr_i=32'hf000;
                    tick(); @(negedge clk_i); i0_req_valid_i=0; tick();
                    check(i0_rsp_valid_o && i0_rsp_error_o && backend_accepts==3,
                      "unmapped access errors without backend request");
                    tick();
                    @(negedge clk_i); i1_req_valid_i=1; i1_req_write_i=1; i1_req_mapped_i=1;
                    i1_req_addr_i=32'h400; i1_req_wdata_i=32'hffffffff; i1_req_be_i=4'b1111;
                    tick(); @(negedge clk_i); i1_req_valid_i=0; tick();
                    check(i1_rsp_valid_o && i1_rsp_error_o && backend_accepts==3,
                      "read-only instruction write rejected without side effect");
                    tick(); i1_req_write_i=0;

                    // Accepted request times out once; late response is quarantined.
                    @(negedge clk_i); i0_req_valid_i=1; i0_req_mapped_i=1; i0_req_addr_i=32'h500;
                    tick(); @(negedge clk_i); i0_req_valid_i=0; req_ready_i=1; tick();
                    @(negedge clk_i); req_ready_i=0;
                    repeat(3) tick();
                    check(i0_rsp_valid_o && i0_rsp_error_o, "timeout completes once with error");
                    tick(); check(c0==4, "timeout counted exactly once");
                    @(negedge clk_i); i1_req_valid_i=1; i1_req_addr_i=32'h600; #1;
                    check(!i1_req_ready_o && rsp_ready_o, "late response quarantine blocks reuse");
                    respond(32'h5555aaaa, 0); #1;
                    check(c0==4 && c1==2 && i1_req_ready_o,
                      "late response discarded then requests resume");
                    tick(); @(negedge clk_i); i1_req_valid_i=0; req_ready_i=1; tick();
                    @(negedge clk_i); req_ready_i=0; respond(32'h600d600d, 0); tick();
                    check(c1==3, "post-timeout request completes normally");

                    // Reset aborts an outstanding request and the arbiter recovers.
                    @(negedge clk_i); i0_req_valid_i=1; i0_req_addr_i=32'h700;
                    tick(); @(negedge clk_i); i0_req_valid_i=0;
                    tick(); rst_ni=0; #1;
                    check(!req_valid_o && !rsp_ready_o && !i0_rsp_valid_o && !i1_rsp_valid_o,
                      "reset aborts without completion");
                    tick(); rst_ni=1;
                    @(negedge clk_i); i0_req_valid_i=1; i0_req_addr_i=32'h704;
                    tick(); @(negedge clk_i); i0_req_valid_i=0; req_ready_i=1; tick();
                    @(negedge clk_i); req_ready_i=0; respond(32'h70707070, 0); tick();
                    check(c0==5 && c1==3, "reset recovery completion ownership");
                    $display("PASS accepts=%0d c0=%0d c1=%0d", backend_accepts, c0, c1);
                    $finish;
                  end
                endmodule
            """), encoding="utf-8")
            compiled = subprocess.run(
                [shutil.which("iverilog"), "-g2012", "-s", "tb", "-o", str(executable),
                 str(RTL), str(bench)], cwd=ROOT, text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            result = subprocess.run(
                [shutil.which("vvp"), str(executable)], cwd=ROOT, text=True,
                capture_output=True, timeout=20,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
