from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv"


class Axi4ProcessorMemoryAdapterRtlTests(unittest.TestCase):
    def test_independent_channels_backpressure_ids_errors_and_rejection(self) -> None:
        iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
        if not iverilog or not vvp:
            self.skipTest("Icarus Verilog is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tb = root / "tb.sv"
            output = root / "tb.vvp"
            tb.write_text(textwrap.dedent("""
                module tb;
                  logic clk_i=0, rst_ni=0;
                  logic [3:0] awid_i; logic [31:0] awaddr_i; logic [7:0] awlen_i;
                  logic [2:0] awsize_i; logic [1:0] awburst_i; logic awlock_i;
                  logic [3:0] awcache_i; logic [2:0] awprot_i; logic [3:0] awqos_i, awregion_i;
                  logic [5:0] awatop_i; logic [1:0] awuser_i; logic awvalid_i, awready_o;
                  logic [31:0] wdata_i; logic [3:0] wstrb_i; logic wlast_i;
                  logic [1:0] wuser_i; logic wvalid_i, wready_o;
                  logic [3:0] bid_o; logic [1:0] bresp_o; logic [1:0] buser_o;
                  logic bvalid_o, bready_i;
                  logic [3:0] arid_i; logic [31:0] araddr_i; logic [7:0] arlen_i;
                  logic [2:0] arsize_i; logic [1:0] arburst_i; logic arlock_i;
                  logic [3:0] arcache_i; logic [2:0] arprot_i; logic [3:0] arqos_i, arregion_i;
                  logic [1:0] aruser_i; logic arvalid_i, arready_o;
                  logic [3:0] rid_o; logic [31:0] rdata_o; logic [1:0] rresp_o;
                  logic rlast_o; logic [1:0] ruser_o; logic rvalid_o, rready_i;
                  logic req_valid_o, req_ready_i, req_write_o;
                  logic [31:0] req_addr_o, req_wdata_o; logic [3:0] req_be_o;
                  logic rsp_valid_i, rsp_ready_o; logic [31:0] rsp_rdata_i; logic rsp_error_i;

                  axi4_processor_memory_adapter #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32),
                    .ID_WIDTH(4), .USER_WIDTH(2)) dut (.*);
                  always #5 clk_i=~clk_i;
                  task tick; @(posedge clk_i); #1; endtask
                  task check(input bit ok, input [8*96-1:0] msg);
                    if (!ok) begin $display("FAIL: %0s",msg); $fatal(1); end
                  endtask
                  task defaults;
                    begin
                      awid_i=0; awaddr_i=0; awlen_i=0; awsize_i=2; awburst_i=1;
                      awlock_i=0; awcache_i=0; awprot_i=0; awqos_i=0; awregion_i=0;
                      awatop_i=0; awuser_i=0; awvalid_i=0;
                      wdata_i=0; wstrb_i=0; wlast_i=1; wuser_i=0; wvalid_i=0; bready_i=0;
                      arid_i=0; araddr_i=0; arlen_i=0; arsize_i=2; arburst_i=1;
                      arlock_i=0; arcache_i=0; arprot_i=0; arqos_i=0; arregion_i=0;
                      aruser_i=0; arvalid_i=0; rready_i=0;
                      req_ready_i=0; rsp_valid_i=0; rsp_rdata_i=0; rsp_error_i=0;
                    end
                  endtask
                  initial begin
                    defaults(); tick(); rst_ni=1;

                    // W may arrive before AW.  The completed write request holds under backend stall.
                    @(negedge clk_i); wvalid_i=1; wdata_i=32'h11223344; wstrb_i=4'b0101;
                    tick(); check(!wready_o && !req_valid_o, "captured early W without issuing");
                    @(negedge clk_i); wvalid_i=0; awvalid_i=1; awid_i=4'h5; awaddr_i=32'h80000024;
                    tick(); check(req_valid_o && req_write_o, "AW completes one backend write");
                    check(req_addr_o==32'h80000024 && req_wdata_o==32'h11223344 && req_be_o==4'b0101,
                          "write payload preserved");
                    @(negedge clk_i); awvalid_i=0; tick();
                    check(req_valid_o && req_addr_o==32'h80000024, "backend request held under stall");
                    @(negedge clk_i); req_ready_i=1; tick();
                    check(!req_valid_o && rsp_ready_o, "accepted request waits for backend response");
                    @(negedge clk_i); req_ready_i=0; rsp_valid_i=1; rsp_error_i=0; tick();
                    check(bvalid_o && bid_o==4'h5 && bresp_o==2'b00 && buser_o==0,
                          "write response preserves ID and zeros user");
                    @(negedge clk_i); rsp_valid_i=0; repeat(2) begin tick();
                      check(bvalid_o && bid_o==4'h5, "B response held under backpressure"); end
                    @(negedge clk_i); bready_i=1; tick();
                    check(!bvalid_o && awready_o && wready_o, "B handshake releases adapter");

                    // Legal read propagates data and backend error as SLVERR while holding R.
                    @(negedge clk_i); bready_i=0; arvalid_i=1; arid_i=4'h9; araddr_i=32'h80000040;
                    tick(); check(req_valid_o && !req_write_o && req_addr_o==32'h80000040,
                                  "AR maps to backend read");
                    @(negedge clk_i); arvalid_i=0; req_ready_i=1; tick();
                    check(rsp_ready_o, "read waits for backend response");
                    @(negedge clk_i); req_ready_i=0; rsp_valid_i=1;
                    rsp_rdata_i=32'hfeedbeef; rsp_error_i=1; tick();
                    check(rvalid_o && rid_o==4'h9 && rdata_o==32'hfeedbeef && rresp_o==2'b10 && rlast_o,
                          "read error is qualified by held R response");
                    check(ruser_o==0, "read user response is deterministic zero");
                    @(negedge clk_i); rsp_valid_i=0; rsp_error_i=0; repeat(2) begin tick();
                      check(rvalid_o && rdata_o==32'hfeedbeef, "R held under backpressure"); end
                    @(negedge clk_i); rready_i=1; tick(); check(!rvalid_o, "R handshake releases adapter");

                    // Unsupported write burst is drained before its DECERR response.
                    @(negedge clk_i); rready_i=0; awvalid_i=1; wvalid_i=1; awid_i=4'ha;
                    awlen_i=1; awatop_i=0; awlock_i=0; wlast_i=0;
                    tick(); check(!bvalid_o && wready_o && !req_valid_o,
                                  "unsupported write burst drains remaining W");
                    @(negedge clk_i); awvalid_i=0; wvalid_i=1; wlast_i=1; tick();
                    check(bvalid_o && bid_o==4'ha && bresp_o==2'b11 && !req_valid_o,
                          "drained write burst receives DECERR");
                    @(negedge clk_i); wvalid_i=0; bready_i=1; tick();

                    // AWLEN, rather than an early malformed WLAST, determines drain length.
                    @(negedge clk_i); bready_i=0; awvalid_i=1; wvalid_i=1; awid_i=4'hd;
                    awlen_i=2; awatop_i=0; wlast_i=1;
                    tick(); check(!bvalid_o && wready_o, "early WLAST does not shorten AWLEN drain");
                    @(negedge clk_i); awvalid_i=0; wlast_i=0; tick();
                    check(!bvalid_o && wready_o, "declared middle W beat is drained");
                    @(negedge clk_i); wlast_i=1; tick();
                    check(bvalid_o && bid_o==4'hd && bresp_o==2'b11,
                          "response follows every declared W transfer");
                    @(negedge clk_i); wvalid_i=0; bready_i=1; tick();

                    // ATOP with a read-result obligation receives both R and B errors.
                    @(negedge clk_i); bready_i=1; awvalid_i=1; wvalid_i=1; awid_i=4'hb;
                    awlen_i=0; awatop_i=6'h20; wlast_i=1;
                    tick(); check(rvalid_o && rid_o==4'hb && rresp_o==2'b11 && rlast_o &&
                                  bvalid_o && bid_o==4'hb && bresp_o==2'b11,
                                  "ATOP exposes independent R and B DECERR responses");
                    @(negedge clk_i); awvalid_i=0; wvalid_i=0; tick();
                    check(rvalid_o && !bvalid_o,
                          "ATOP R remains valid after independently accepted B");
                    @(negedge clk_i); bready_i=0; rready_i=1; tick();
                    check(!rvalid_o && !bvalid_o, "ATOP releases after both response handshakes");

                    // A two-transfer AtomicLoad returns two R errors even when unsupported.
                    @(negedge clk_i); rready_i=0; bready_i=0; awvalid_i=1; wvalid_i=1;
                    awid_i=4'he; awlen_i=1; awatop_i=6'b100000; wlast_i=0;
                    tick(); check(!rvalid_o && !bvalid_o && wready_o,
                                  "multi-transfer AtomicLoad drains W before responses");
                    @(negedge clk_i); awvalid_i=0; wlast_i=1; tick();
                    check(rvalid_o && !rlast_o && bvalid_o && rid_o==4'he && bid_o==4'he,
                          "AtomicLoad first R beat and B become independently valid");
                    @(negedge clk_i); wvalid_i=0; rready_i=1; tick();
                    check(rvalid_o && rlast_o && bvalid_o,
                          "AtomicLoad final R beat alone carries RLAST");
                    tick(); check(!rvalid_o && bvalid_o, "AtomicLoad holds unaccepted B");
                    @(negedge clk_i); rready_i=0; bready_i=1; tick();
                    check(!rvalid_o && !bvalid_o, "AtomicLoad completes all response obligations");

                    // AtomicCompare has half as many R transfers as W transfers.
                    @(negedge clk_i); bready_i=0; awvalid_i=1; wvalid_i=1; awid_i=4'hf;
                    awlen_i=3; awatop_i=6'b110001; wlast_i=0;
                    tick(); check(wready_o && !rvalid_o, "AtomicCompare begins four-beat drain");
                    @(negedge clk_i); awvalid_i=0; tick();
                    check(wready_o && !rvalid_o, "AtomicCompare drains second W beat");
                    tick(); check(wready_o && !rvalid_o, "AtomicCompare drains third W beat");
                    @(negedge clk_i); wlast_i=1; tick();
                    check(rvalid_o && !rlast_o && bvalid_o,
                          "AtomicCompare returns first of two R beats");
                    @(negedge clk_i); wvalid_i=0; bready_i=1; repeat(2) begin tick();
                      check(rvalid_o && !rlast_o, "AtomicCompare R holds under backpressure"); end
                    @(negedge clk_i); bready_i=0; rready_i=1; tick();
                    check(rvalid_o && rlast_o && !bvalid_o,
                          "AtomicCompare second R beat is final after B completes");
                    tick(); check(!rvalid_o && !bvalid_o, "AtomicCompare completes exactly two R beats");

                    // Unsupported read burst returns every declared beat and only final RLAST.
                    @(negedge clk_i); bready_i=0; arvalid_i=1; arid_i=4'hc; arlen_i=1; arlock_i=1;
                    tick(); check(rvalid_o && rid_o==4'hc && rresp_o==2'b11 && !rlast_o && !req_valid_o,
                                  "first rejected read burst beat has no RLAST");
                    @(negedge clk_i); arvalid_i=0; rready_i=1; tick();
                    check(rvalid_o && rresp_o==2'b11 && rlast_o,
                          "final rejected read burst beat has RLAST");
                    tick(); check(!rvalid_o, "all rejected read beats complete");

                    // Reset discards a partially captured independent write channel.
                    @(negedge clk_i); rready_i=0; wvalid_i=1; wdata_i=32'hdeadbeef; tick();
                    @(negedge clk_i); wvalid_i=0; rst_ni=0; tick();
                    check(!req_valid_o && !bvalid_o && !rvalid_o, "reset clears partial transaction");
                    rst_ni=1; tick(); check(awready_o && wready_o && arready_o, "reset returns idle");
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
