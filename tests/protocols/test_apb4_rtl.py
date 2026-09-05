from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL_DIR = ROOT / "src" / "myfuzz" / "protocols" / "rtl"


class Apb4RtlTest(unittest.TestCase):
    def test_bridge_and_target_preserve_apb4_transaction_rules(self) -> None:
        """Exercise setup/access, bounded target wait, adapter mapping, and response hold."""
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if iverilog is None or vvp is None:
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            testbench = temporary_path / "apb4_mmio_tb.sv"
            executable = temporary_path / "apb4_mmio_tb.vvp"
            testbench.write_text(
                textwrap.dedent(
                    """
                    module tb;
                        logic clk_i = 1'b0;
                        logic rst_ni = 1'b0;
                        logic req_valid_i;
                        logic req_write_i;
                        logic [31:0] req_addr_i;
                        logic [31:0] req_wdata_i;
                        logic [3:0] req_be_i;
                        logic req_ready_o;
                        logic rsp_valid_o;
                        logic rsp_ready_i;
                        logic [31:0] rsp_rdata_o;
                        logic rsp_error_o;
                        logic [31:0] paddr;
                        logic [2:0] pprot;
                        logic psel;
                        logic penable;
                        logic pwrite;
                        logic [31:0] pwdata;
                        logic [3:0] pstrb;
                        logic pready;
                        logic [31:0] prdata;
                        logic pslverr;
                        logic target_valid;
                        logic target_write;
                        logic [31:0] target_addr;
                        logic [31:0] target_wdata;
                        logic [3:0] target_be;
                        logic target_ready;
                        logic [31:0] target_rdata;
                        logic target_error;

                        apb4_mmio_bridge dut (
                            .clk_i,
                            .rst_ni,
                            .req_valid_i,
                            .req_write_i,
                            .req_addr_i,
                            .req_wdata_i,
                            .req_be_i,
                            .req_ready_o,
                            .rsp_valid_o,
                            .rsp_ready_i,
                            .rsp_rdata_o,
                            .rsp_error_o,
                            .paddr_o(paddr),
                            .pprot_o(pprot),
                            .psel_o(psel),
                            .penable_o(penable),
                            .pwrite_o(pwrite),
                            .pwdata_o(pwdata),
                            .pstrb_o(pstrb),
                            .pready_i(pready),
                            .prdata_i(prdata),
                            .pslverr_i(pslverr)
                        );

                        apb4_mmio_target target (
                            .clk_i,
                            .rst_ni,
                            .paddr_i(paddr),
                            .pprot_i(pprot),
                            .psel_i(psel),
                            .penable_i(penable),
                            .pwrite_i(pwrite),
                            .pwdata_i(pwdata),
                            .pstrb_i(pstrb),
                            .pready_o(pready),
                            .prdata_o(prdata),
                            .pslverr_o(pslverr),
                            .valid_o(target_valid),
                            .write_o(target_write),
                            .addr_o(target_addr),
                            .wdata_o(target_wdata),
                            .be_o(target_be),
                            .rdata_i(target_rdata),
                            .ready_i(target_ready),
                            .error_i(target_error)
                        );

                        always #5 clk_i = ~clk_i;

                        task automatic check(input bit condition, input [8*96-1:0] message);
                            if (!condition) begin
                                $display("FAIL: %0s", message);
                                $fatal(1);
                            end
                        endtask

                        task automatic tick;
                            @(posedge clk_i);
                            #1;
                        endtask

                        task automatic check_read_access;
                            check(psel && penable, "read must be in APB access phase");
                            check(target_valid && !target_write, "adapter must expose read access");
                            check(paddr == 32'h0000_0020, "read address must remain stable");
                            check(pprot == 3'b000, "protection must be deterministic");
                            check(!pwrite && pwdata == 32'h0 && pstrb == 4'h0,
                                   "read APB fields must be stable and deterministic");
                            check(!pready, "adapter must deassert PREADY while target waits");
                        endtask

                        initial begin
                            req_valid_i = 1'b0;
                            req_write_i = 1'b0;
                            req_addr_i = '0;
                            req_wdata_i = '0;
                            req_be_i = '0;
                            rsp_ready_i = 1'b0;
                            target_ready = 1'b0;
                            target_rdata = 32'h0;
                            target_error = 1'b0;

                            tick;
                            rst_ni = 1'b1;
                            @(negedge clk_i);
                            req_valid_i = 1'b1;
                            req_write_i = 1'b0;
                            req_addr_i = 32'h0000_0020;
                            req_wdata_i = 32'h0;
                            req_be_i = 4'hf;
                            tick;
                            check(psel && !penable, "read must start with APB setup phase");
                            check(!target_valid, "adapter must not assert valid during setup");
                            check(paddr == 32'h0000_0020 && pstrb == 4'h0,
                                   "setup must latch deterministic read fields");
                            @(negedge clk_i);
                            req_valid_i = 1'b0;
                            tick;
                            check_read_access();
                            tick;
                            check_read_access();
                            @(negedge clk_i);
                            target_ready = 1'b1;
                            target_rdata = 32'hcafe_babe;
                            tick;
                            check(rsp_valid_o && !rsp_error_o && rsp_rdata_o == 32'hcafe_babe,
                                   "read completion must return target data");
                            check(!psel && !penable && !target_valid,
                                   "bridge must leave APB access after completion");

                            repeat (20) begin
                                tick;
                                check(rsp_valid_o && !rsp_error_o && rsp_rdata_o == 32'hcafe_babe,
                                       "response must remain stable during backpressure");
                            end
                            @(negedge clk_i);
                            rsp_ready_i = 1'b1;
                            tick;
                            check(!rsp_valid_o && req_ready_o,
                                   "response handshake must release the bridge");
                            rsp_ready_i = 1'b0;
                            target_ready = 1'b0;
                            target_error = 1'b0;

                            @(negedge clk_i);
                            req_valid_i = 1'b1;
                            req_write_i = 1'b1;
                            req_addr_i = 32'h0000_0044;
                            req_wdata_i = 32'h1122_3344;
                            req_be_i = 4'b0101;
                            tick;
                            check(psel && !penable && pwrite && paddr == 32'h0000_0044,
                                   "write must start with APB setup phase");
                            check(pwdata == 32'h1122_3344 && pstrb == 4'b0101,
                                   "write setup must preserve data and byte enables");
                            @(negedge clk_i);
                            req_valid_i = 1'b0;
                            tick;
                            check(psel && penable && target_valid && target_write,
                                   "write must expose component access phase");
                            check(target_addr == 32'h0000_0044 && target_wdata == 32'h1122_3344
                                   && target_be == 4'b0101,
                                   "adapter must preserve write request fields");
                            tick;
                            check(psel && penable && paddr == 32'h0000_0044
                                   && pwdata == 32'h1122_3344 && pstrb == 4'b0101,
                                   "write fields must remain stable while PREADY is low");
                            @(negedge clk_i);
                            target_ready = 1'b1;
                            target_error = 1'b1;
                            tick;
                            check(rsp_valid_o && rsp_error_o && rsp_rdata_o == 32'h0,
                                   "PSLVERR must become deterministic write error response");

                            @(negedge clk_i);
                            rsp_ready_i = 1'b1;
                            target_error = 1'b0;
                            tick;
                            rsp_ready_i = 1'b0;
                            target_ready = 1'b0;
                            @(negedge clk_i);
                            req_valid_i = 1'b1;
                            req_write_i = 1'b0;
                            req_addr_i = 32'h0000_0060;
                            req_wdata_i = 32'h0;
                            req_be_i = 4'hf;
                            tick;
                            @(negedge clk_i);
                            req_valid_i = 1'b0;
                            tick;
                            repeat (15) begin
                                tick;
                                check(psel && penable && !rsp_valid_o,
                                       "bridge must remain in access before timeout bound");
                            end
                            tick;
                            check(rsp_valid_o && rsp_error_o && rsp_rdata_o == 32'h0,
                                   "unready APB target must complete with bounded error response");
                            $display("PASS");
                            $finish;
                        end
                    endmodule
                    """
                ),
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                [
                    iverilog,
                    "-g2012",
                    "-s",
                    "tb",
                    "-o",
                    str(executable),
                    str(RTL_DIR / "apb4_mmio_bridge.sv"),
                    str(RTL_DIR / "apb4_mmio_target.sv"),
                    str(testbench),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                msg=compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [vvp, str(executable)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                msg=run_result.stdout + run_result.stderr,
            )
            self.assertIn("PASS", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
