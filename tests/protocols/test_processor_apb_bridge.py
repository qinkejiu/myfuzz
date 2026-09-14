"""RTL proof for the source-backed CPU beat to APB3 bridge."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/processor_apb_bridge.sv"


class ProcessorApbBridgeRtlTests(unittest.TestCase):
    def test_apb3_rejects_partial_writes_without_a_side_effect(self) -> None:
        iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
        self.assertIsNotNone(iverilog, "iverilog is required for APB bridge RTL tests")
        self.assertIsNotNone(vvp, "vvp is required for APB bridge RTL tests")
        bench = textwrap.dedent(
            r"""
            module tb;
              logic clk = 1'b0, reset = 1'b1;
              always #5 clk = ~clk;
              task tick; @(posedge clk); #1; endtask
              task check(input bit ok, input [8*160-1:0] msg);
                if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
              endtask

              logic req_valid = 1'b0, req_ready, req_write = 1'b0;
              logic [31:0] req_addr = 32'd0, req_wdata = 32'hCAFE_BABE;
              logic [3:0] req_be = 4'h0;
              logic rsp_valid, rsp_ready = 1'b1, rsp_error;
              logic [31:0] rsp_rdata;
              logic [11:0] paddr;
              logic [31:0] pwdata, prdata = 32'h1234_5678;
              logic pwrite, psel, penable, pready = 1'b1, pslverr = 1'b0;
              integer apb_transfers = 0;

              processor_apb_bridge #(.ALLOW_PARTIAL_WRITE(0)) dut (
                .clk_i(clk), .rst_ni(!reset), .req_valid_i(req_valid), .req_ready_o(req_ready),
                .req_write_i(req_write), .req_addr_i(req_addr), .req_wdata_i(req_wdata),
                .req_be_i(req_be), .rsp_valid_o(rsp_valid), .rsp_ready_i(rsp_ready),
                .rsp_rdata_o(rsp_rdata), .rsp_error_o(rsp_error), .paddr_o(paddr),
                .pwdata_o(pwdata), .pwrite_o(pwrite), .psel_o(psel), .penable_o(penable),
                .prdata_i(prdata), .pready_i(pready), .pslverr_i(pslverr));

              always @(posedge clk)
                if (psel && penable && pready) apb_transfers = apb_transfers + 1;

              initial begin
                tick(); reset = 1'b0;
                req_write = 1'b1; req_be = 4'b0011; req_valid = 1'b1; tick(); req_valid = 1'b0;
                check(rsp_valid && rsp_error && rsp_rdata == 0,
                      "partial write is rejected at beat boundary");
                check(!psel && !penable && apb_transfers == 0,
                      "rejected partial write issues no APB transfer");
                tick();

                req_be = 4'hf; req_valid = 1'b1; tick(); req_valid = 1'b0;
                check(psel && !penable, "full write starts with APB setup");
                tick();
                check(psel && penable && pwrite && pwdata == 32'hCAFE_BABE,
                      "full write holds APB access fields");
                tick();
                check(rsp_valid && !rsp_error && rsp_rdata == 32'h1234_5678,
                      "full write returns target response");
                check(apb_transfers == 1, "full write has one APB transfer");
                $display("PASS"); $finish;
              end
            endmodule
            """
        )
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "bridge.vvp"
            tb = Path(directory) / "tb.sv"
            tb.write_text(bench, encoding="utf-8")
            compiled = subprocess.run(
                [str(iverilog), "-g2012", "-s", "tb", "-o", str(image), str(RTL), str(tb)],
                cwd=ROOT, text=True, capture_output=True, timeout=60,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            result = subprocess.run(
                [str(vvp), str(image)], cwd=ROOT, text=True, capture_output=True, timeout=60,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
