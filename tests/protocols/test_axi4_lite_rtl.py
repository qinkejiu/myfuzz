from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL_DIR = ROOT / "src" / "myfuzz" / "protocols" / "rtl"


class Axi4LiteRtlTest(unittest.TestCase):
    def test_bridge_and_target_preserve_lite_handshake_rules(self) -> None:
        """Exercise independent write channels, unified MMIO, bounded wait, and response holds."""
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if iverilog is None or vvp is None:
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            testbench = temporary_path / "axi4_lite_mmio_tb.sv"
            executable = temporary_path / "axi4_lite_mmio_tb.vvp"
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
                        logic [31:0] awaddr;
                        logic [2:0] awprot;
                        logic awvalid;
                        logic awready;
                        logic [31:0] wdata;
                        logic [3:0] wstrb;
                        logic wvalid;
                        logic wready;
                        logic [1:0] bresp;
                        logic bvalid;
                        logic bready;
                        logic [31:0] araddr;
                        logic [2:0] arprot;
                        logic arvalid;
                        logic arready;
                        logic [31:0] rdata;
                        logic [1:0] rresp;
                        logic rvalid;
                        logic rready;

                        logic [31:0] s_awaddr;
                        logic [2:0] s_awprot;
                        logic s_awvalid;
                        logic s_awready;
                        logic [31:0] s_wdata;
                        logic [3:0] s_wstrb;
                        logic s_wvalid;
                        logic s_wready;
                        logic [1:0] s_bresp;
                        logic s_bvalid;
                        logic s_bready;
                        logic [31:0] s_araddr;
                        logic [2:0] s_arprot;
                        logic s_arvalid;
                        logic s_arready;
                        logic [31:0] s_rdata;
                        logic [1:0] s_rresp;
                        logic s_rvalid;
                        logic s_rready;
                        logic target_valid;
                        logic target_write;
                        logic [31:0] target_addr;
                        logic [31:0] target_wdata;
                        logic [3:0] target_be;
                        logic target_ready;
                        logic [31:0] target_rdata;
                        logic target_error;

                        axi4_lite_mmio_bridge bridge (
                            .clk_i, .rst_ni,
                            .req_valid_i, .req_write_i, .req_addr_i, .req_wdata_i, .req_be_i,
                            .req_ready_o, .rsp_valid_o, .rsp_ready_i, .rsp_rdata_o, .rsp_error_o,
                            .awaddr_o(awaddr), .awprot_o(awprot), .awvalid_o(awvalid), .awready_i(awready),
                            .wdata_o(wdata), .wstrb_o(wstrb), .wvalid_o(wvalid), .wready_i(wready),
                            .bresp_i(bresp), .bvalid_i(bvalid), .bready_o(bready),
                            .araddr_o(araddr), .arprot_o(arprot), .arvalid_o(arvalid), .arready_i(arready),
                            .rdata_i(rdata), .rresp_i(rresp), .rvalid_i(rvalid), .rready_o(rready)
                        );

                        axi4_lite_mmio_target target (
                            .clk_i, .rst_ni,
                            .awaddr_i(s_awaddr), .awprot_i(s_awprot), .awvalid_i(s_awvalid), .awready_o(s_awready),
                            .wdata_i(s_wdata), .wstrb_i(s_wstrb), .wvalid_i(s_wvalid), .wready_o(s_wready),
                            .bresp_o(s_bresp), .bvalid_o(s_bvalid), .bready_i(s_bready),
                            .araddr_i(s_araddr), .arprot_i(s_arprot), .arvalid_i(s_arvalid), .arready_o(s_arready),
                            .rdata_o(s_rdata), .rresp_o(s_rresp), .rvalid_o(s_rvalid), .rready_i(s_rready),
                            .valid_o(target_valid), .write_o(target_write), .addr_o(target_addr),
                            .wdata_o(target_wdata), .be_o(target_be), .rdata_i(target_rdata),
                            .ready_i(target_ready), .error_i(target_error)
                        );

                        always #5 clk_i = ~clk_i;

                        task automatic check(input bit condition, input [8*112-1:0] message);
                            if (!condition) begin
                                $display("FAIL: %0s", message);
                                $fatal(1);
                            end
                        endtask

                        task automatic tick;
                            @(posedge clk_i);
                            #1;
                        endtask

                        initial begin
                            req_valid_i = 1'b0;
                            req_write_i = 1'b0;
                            req_addr_i = '0;
                            req_wdata_i = '0;
                            req_be_i = '0;
                            rsp_ready_i = 1'b0;
                            awready = 1'b0;
                            wready = 1'b0;
                            bresp = 2'b00;
                            bvalid = 1'b0;
                            arready = 1'b0;
                            rdata = '0;
                            rresp = 2'b00;
                            rvalid = 1'b0;
                            s_awaddr = '0;
                            s_awprot = '0;
                            s_awvalid = 1'b0;
                            s_wdata = '0;
                            s_wstrb = '0;
                            s_wvalid = 1'b0;
                            s_bready = 1'b0;
                            s_araddr = '0;
                            s_arprot = '0;
                            s_arvalid = 1'b0;
                            s_rready = 1'b0;
                            target_ready = 1'b0;
                            target_rdata = '0;
                            target_error = 1'b0;

                            tick;
                            rst_ni = 1'b1;

                            @(negedge clk_i);
                            req_valid_i = 1'b1;
                            req_write_i = 1'b1;
                            req_addr_i = 32'h8003_0040;
                            req_wdata_i = 32'h1122_3344;
                            req_be_i = 4'b0101;
                            tick;
                            check(awvalid && wvalid, "bridge must offer AW and W independently");
                            check(awaddr == 32'h8003_0040 && awprot == 3'b000,
                                  "AW payload must be deterministic and stable");
                            check(wdata == 32'h1122_3344 && wstrb == 4'b0101,
                                  "W payload must preserve data and byte enables");
                            @(negedge clk_i);
                            req_valid_i = 1'b0;
                            wready = 1'b1;
                            tick;
                            check(awvalid && !wvalid, "AW must remain valid after W independently handshakes");
                            check(awaddr == 32'h8003_0040 && wdata == 32'h1122_3344 && wstrb == 4'b0101,
                                  "unhandshaken AW and captured W payload must stay stable");
                            @(negedge clk_i);
                            wready = 1'b0;
                            awready = 1'b1;
                            tick;
                            check(!awvalid && !wvalid, "both write channels must retire after independent handshakes");
                            @(negedge clk_i);
                            awready = 1'b0;
                            bvalid = 1'b1;
                            bresp = 2'b10;
                            tick;
                            check(!bready && rsp_valid_o && rsp_error_o && rsp_rdata_o == 32'h0,
                                  "BRESP slave error must become deterministic native error");
                            repeat (20) begin
                                tick;
                                check(!bready && rsp_valid_o && rsp_error_o,
                                      "bridge must hold the native B response during backpressure");
                            end
                            @(negedge clk_i);
                            rsp_ready_i = 1'b1;
                            tick;
                            check(!bready && !rsp_valid_o && req_ready_o,
                                  "native B response handshake must release the bridge");
                            @(negedge clk_i);
                            rsp_ready_i = 1'b0;
                            bvalid = 1'b0;
                            req_valid_i = 1'b1;
                            req_write_i = 1'b0;
                            req_addr_i = 32'h8003_0060;
                            req_wdata_i = '0;
                            req_be_i = 4'hf;
                            tick;
                            check(arvalid && araddr == 32'h8003_0060 && arprot == 3'b000,
                                  "read address must be valid with a stable deterministic payload");
                            @(negedge clk_i);
                            req_valid_i = 1'b0;
                            arready = 1'b1;
                            tick;
                            check(!arvalid && rready, "AR handshake must enable the R channel");
                            @(negedge clk_i);
                            arready = 1'b0;
                            rvalid = 1'b1;
                            rdata = 32'hfeed_beef;
                            rresp = 2'b10;
                            tick;
                            check(!rready && rsp_valid_o && rsp_error_o && rsp_rdata_o == 32'hfeed_beef,
                                  "RRESP slave error must preserve read data and report native error");
                            repeat (20) begin
                                tick;
                                check(!rready && rsp_valid_o && rsp_error_o && rsp_rdata_o == 32'hfeed_beef,
                                      "bridge must hold the native R response during backpressure");
                            end
                            @(negedge clk_i);
                            rsp_ready_i = 1'b1;
                            tick;
                            check(!rready && !rsp_valid_o && req_ready_o,
                                  "native R response handshake must release the bridge");

                            @(negedge clk_i);
                            rsp_ready_i = 1'b0;
                            rvalid = 1'b0;
                            s_awvalid = 1'b1;
                            s_awaddr = 32'h8004_0010;
                            s_awprot = 3'b000;
                            tick;
                            check(!s_awready && s_wready && !target_valid,
                                  "target must independently accept AW before W");
                            @(negedge clk_i);
                            s_awvalid = 1'b0;
                            s_wvalid = 1'b1;
                            s_wdata = 32'haabb_ccdd;
                            s_wstrb = 4'b1010;
                            tick;
                            check(!s_wready && target_valid && target_write,
                                  "target must submit one unified write after both channels arrive");
                            check(target_addr == 32'h8004_0010 && target_wdata == 32'haabb_ccdd
                                  && target_be == 4'b1010,
                                  "target must map AW/W payloads to one MMIO write");
                            @(negedge clk_i);
                            s_wvalid = 1'b0;
                            repeat (15) begin
                                tick;
                                check(target_valid && target_write && !s_bvalid,
                                      "target must hold unified request before bounded timeout");
                            end
                            tick;
                            check(s_bvalid && s_bresp == 2'b10,
                                  "unready write target must produce bounded slave error");
                            repeat (20) begin
                                tick;
                                check(s_bvalid && s_bresp == 2'b10,
                                      "BVALID and BRESP must remain stable while BREADY is low");
                            end
                            @(negedge clk_i);
                            s_bready = 1'b1;
                            tick;
                            check(!s_bvalid && s_awready && s_wready,
                                  "B response handshake must release target write state");
                            @(negedge clk_i);
                            s_bready = 1'b0;
                            s_arvalid = 1'b1;
                            s_araddr = 32'h8004_0020;
                            s_arprot = 3'b000;
                            target_ready = 1'b1;
                            target_rdata = 32'hcafe_babe;
                            target_error = 1'b1;
                            tick;
                            check(!s_arready && target_valid && !target_write,
                                  "target must submit AR as a unified read");
                            check(target_addr == 32'h8004_0020 && target_be == 4'h0,
                                  "target must map read byte enable deterministically to zero");
                            @(negedge clk_i);
                            s_arvalid = 1'b0;
                            tick;
                            check(s_rvalid && s_rresp == 2'b10 && s_rdata == 32'hcafe_babe,
                                  "target read error must return deterministic R channel response");
                            @(negedge clk_i);
                            target_ready = 1'b0;
                            repeat (20) begin
                                tick;
                                check(s_rvalid && s_rresp == 2'b10 && s_rdata == 32'hcafe_babe,
                                      "RVALID, RRESP, and RDATA must remain stable while RREADY is low");
                            end
                            @(negedge clk_i);
                            s_rready = 1'b1;
                            tick;
                            check(!s_rvalid && s_arready,
                                  "R response handshake must release target read state");
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
                    str(RTL_DIR / "axi4_lite_mmio_bridge.sv"),
                    str(RTL_DIR / "axi4_lite_mmio_target.sv"),
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
