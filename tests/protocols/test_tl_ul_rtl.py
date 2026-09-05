from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL_DIR = ROOT / "src" / "myfuzz" / "protocols" / "rtl"


class TileLinkUlRtlTest(unittest.TestCase):
    def test_target_compiles_cleanly_with_wide_address(self) -> None:
        verilator = shutil.which("verilator")
        if verilator is None:
            self.skipTest("Verilator is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            wrapper = temporary_path / "tl_ul_target_wrapper.sv"
            wrapper.write_text(
                textwrap.dedent(
                    """
                    module tl_ul_target_wrapper;
                        logic clk_i, rst_ni, a_valid_i, a_ready_o;
                        logic [2:0] a_opcode_i, a_param_i, a_size_i;
                        logic [0:0] a_source_i;
                        logic [63:0] a_address_i, a_data_i;
                        logic [7:0] a_mask_i;
                        logic a_corrupt_i, d_valid_o, d_ready_i;
                        logic [2:0] d_opcode_o, d_size_o;
                        logic [1:0] d_param_o;
                        logic [0:0] d_source_o, d_sink_o;
                        logic d_denied_o;
                        logic [63:0] d_data_o;
                        logic d_corrupt_o, valid_o, write_o;
                        logic [63:0] addr_o, wdata_o, rdata_i;
                        logic [7:0] be_o;
                        logic ready_i, error_i;

                        tl_ul_mmio_target #(.ADDRESS_WIDTH(64), .DATA_WIDTH(64)) dut (.*);
                    endmodule
                    """
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [verilator, "--lint-only", "-Wall", "-Wno-fatal", "--language", "1800-2012", "--top-module",
                 "tl_ul_target_wrapper", str(RTL_DIR / "tl_ul_mmio_target.sv"), str(wrapper)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotRegex(result.stderr, r"WIDTHEXPAND|WIDTHTRUNC")

    def test_bridge_and_target_preserve_single_beat_tlul_rules(self) -> None:
        """Exercise Get/Put A/D holds, mask mapping, bounded waits, and errors."""
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if iverilog is None or vvp is None:
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            testbench = temporary_path / "tl_ul_mmio_tb.sv"
            executable = temporary_path / "tl_ul_mmio_tb.vvp"
            testbench.write_text(
                textwrap.dedent(
                    """
                    module tb;
                        logic clk_i = 1'b0;
                        logic rst_ni = 1'b0;

                        logic req_valid_i, req_write_i, req_ready_o;
                        logic [31:0] req_addr_i, req_wdata_i;
                        logic [3:0] req_be_i;
                        logic rsp_valid_o, rsp_ready_i, rsp_error_o;
                        logic [31:0] rsp_rdata_o;
                        logic a_valid, a_ready, a_corrupt;
                        logic [2:0] a_opcode, a_param, a_size;
                        logic [0:0] a_source;
                        logic [31:0] a_address, a_data;
                        logic [3:0] a_mask;
                        logic d_valid, d_ready, d_denied, d_corrupt;
                        logic [2:0] d_opcode, d_size;
                        logic [1:0] d_param;
                        logic [0:0] d_source, d_sink;
                        logic [31:0] d_data;

                        logic ta_valid, ta_ready, ta_corrupt;
                        logic [2:0] ta_opcode, ta_param, ta_size;
                        logic [0:0] ta_source;
                        logic [31:0] ta_address, ta_data;
                        logic [3:0] ta_mask;
                        logic td_valid, td_ready, td_denied, td_corrupt;
                        logic [2:0] td_opcode, td_size;
                        logic [1:0] td_param;
                        logic [0:0] td_source, td_sink;
                        logic [31:0] td_data;
                        logic target_valid, target_write, target_ready, target_error;
                        logic [31:0] target_addr, target_wdata, target_rdata;
                        logic [3:0] target_be;

                        tl_ul_mmio_bridge bridge (
                            .clk_i, .rst_ni,
                            .req_valid_i, .req_write_i, .req_addr_i, .req_wdata_i, .req_be_i,
                            .req_ready_o, .rsp_valid_o, .rsp_ready_i, .rsp_rdata_o, .rsp_error_o,
                            .a_valid_o(a_valid), .a_ready_i(a_ready), .a_opcode_o(a_opcode),
                            .a_param_o(a_param), .a_size_o(a_size), .a_source_o(a_source),
                            .a_address_o(a_address), .a_mask_o(a_mask), .a_data_o(a_data),
                            .a_corrupt_o(a_corrupt), .d_valid_i(d_valid), .d_ready_o(d_ready),
                            .d_opcode_i(d_opcode), .d_param_i(d_param), .d_size_i(d_size),
                            .d_source_i(d_source), .d_sink_i(d_sink), .d_denied_i(d_denied),
                            .d_data_i(d_data), .d_corrupt_i(d_corrupt)
                        );

                        tl_ul_mmio_target target (
                            .clk_i, .rst_ni,
                            .a_valid_i(ta_valid), .a_ready_o(ta_ready), .a_opcode_i(ta_opcode),
                            .a_param_i(ta_param), .a_size_i(ta_size), .a_source_i(ta_source),
                            .a_address_i(ta_address), .a_mask_i(ta_mask), .a_data_i(ta_data),
                            .a_corrupt_i(ta_corrupt), .d_valid_o(td_valid), .d_ready_i(td_ready),
                            .d_opcode_o(td_opcode), .d_param_o(td_param), .d_size_o(td_size),
                            .d_source_o(td_source), .d_sink_o(td_sink), .d_denied_o(td_denied),
                            .d_data_o(td_data), .d_corrupt_o(td_corrupt), .valid_o(target_valid),
                            .write_o(target_write), .addr_o(target_addr), .wdata_o(target_wdata),
                            .be_o(target_be), .rdata_i(target_rdata), .ready_i(target_ready),
                            .error_i(target_error)
                        );

                        always #5 clk_i = ~clk_i;

                        task automatic check(input bit condition, input [8*128-1:0] message);
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
                            req_valid_i = 0; req_write_i = 0; req_addr_i = '0; req_wdata_i = '0;
                            req_be_i = '0; rsp_ready_i = 0; a_ready = 0;
                            d_valid = 0; d_opcode = '0; d_param = '0; d_size = '0; d_source = '0;
                            d_sink = '0; d_denied = 0; d_data = '0; d_corrupt = 0;
                            ta_valid = 0; ta_opcode = '0; ta_param = '0; ta_size = '0; ta_source = '0;
                            ta_address = '0; ta_mask = '0; ta_data = '0; ta_corrupt = 0; td_ready = 0;
                            target_ready = 0; target_rdata = '0; target_error = 0;
                            tick;
                            rst_ni = 1;

                            // PutFullData: hold A payload stable until AREADY and map native write.
                            @(negedge clk_i);
                            req_valid_i = 1; req_write_i = 1; req_addr_i = 32'h0000_0040;
                            req_wdata_i = 32'h1122_3344; req_be_i = 4'hf;
                            tick;
                            check(a_valid && a_opcode == 3'd0 && a_param == 3'd0 && a_size == 3'd2,
                                  "PutFullData A fields must be complete and deterministic");
                            check(a_source == 0 && a_address == 32'h0000_0040 && a_mask == 4'hf
                                  && a_data == 32'h1122_3344 && !a_corrupt,
                                  "PutFullData must preserve its A payload while stalled");
                            @(negedge clk_i);
                            req_valid_i = 0;
                            tick;
                            check(a_valid && a_address == 32'h0000_0040 && a_data == 32'h1122_3344,
                                  "A payload must remain stable before handshake");
                            @(negedge clk_i);
                            a_ready = 1;
                            tick;
                            check(!a_valid && d_ready, "DREADY must follow exactly one A handshake");
                            @(negedge clk_i);
                            a_ready = 0; d_valid = 1; d_opcode = 3'd0; d_param = 0; d_size = 3'd2;
                            d_source = 0; d_sink = 0; d_denied = 0; d_corrupt = 0; d_data = 32'hffff_ffff;
                            tick;
                            check(rsp_valid_o && !rsp_error_o && rsp_rdata_o == 0,
                                  "write D response must become deterministic native success");
                            repeat (20) begin
                                tick;
                                check(rsp_valid_o && !rsp_error_o && rsp_rdata_o == 0,
                                      "native response must remain stable while backpressured");
                            end
                            @(negedge clk_i);
                            rsp_ready_i = 1;
                            tick;
                            check(!rsp_valid_o && req_ready_o, "native response handshake must release bridge");

                            // Get always emits a full-byte A mask and preserves returned data.
                            @(negedge clk_i);
                            rsp_ready_i = 0; d_valid = 0; req_valid_i = 1; req_write_i = 0;
                            req_addr_i = 32'h0000_0050; req_be_i = 4'b0001;
                            tick;
                            check(a_valid && a_opcode == 3'd4 && a_mask == 4'hf && a_size == 3'd2,
                                  "Get must use opcode 4 and a full-byte mask");
                            @(negedge clk_i);
                            req_valid_i = 0; a_ready = 1;
                            tick;
                            @(negedge clk_i);
                            a_ready = 0; d_valid = 1; d_opcode = 3'd1; d_size = 3'd2; d_source = 0;
                            d_denied = 0; d_corrupt = 0; d_data = 32'hfeed_beef;
                            tick;
                            check(rsp_valid_o && !rsp_error_o && rsp_rdata_o == 32'hfeed_beef,
                                  "AccessAckData must preserve valid read data");
                            @(negedge clk_i);
                            rsp_ready_i = 1;
                            tick;

                            // PutPartialData target mapping and target error -> denied response.
                            @(negedge clk_i);
                            rsp_ready_i = 0; d_valid = 0; td_ready = 0; ta_valid = 1; ta_opcode = 3'd1;
                            ta_param = 0; ta_size = 3'd2; ta_source = 0; ta_address = 32'h8000_0010;
                            ta_mask = 4'b0101; ta_data = 32'haabb_ccdd; ta_corrupt = 0;
                            tick;
                            check(!ta_ready && target_valid && target_write && target_addr == 32'h8000_0010,
                                  "PutPartialData must become one unified target write");
                            check(target_wdata == 32'haabb_ccdd && target_be == 4'b0101,
                                  "PutPartialData must preserve the byte-enable mask");
                            @(negedge clk_i);
                            ta_valid = 0; target_ready = 1; target_error = 1;
                            tick;
                            check(td_valid && td_opcode == 3'd0 && td_denied && !td_corrupt && td_data == 0,
                                  "target error must return a deterministic denied write response");
                            repeat (20) begin
                                tick;
                                check(td_valid && td_denied && !td_corrupt && td_data == 0,
                                      "D response must remain stable while DREADY is low");
                            end
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;
                            check(!td_valid && ta_ready, "D handshake must release the target");

                            // Sub-word PutFullData must use the size/address-derived lane mask.
                            @(negedge clk_i);
                            td_ready = 0; target_ready = 0; target_error = 0; ta_valid = 1;
                            ta_opcode = 3'd0; ta_param = 0; ta_size = 3'd1; ta_source = 0;
                            ta_address = 32'h8000_0012; ta_mask = 4'b1100;
                            ta_data = 32'haabb_ccdd; ta_corrupt = 0;
                            tick;
                            check(target_valid && target_write && target_be == 4'b1100,
                                  "sub-word PutFullData must map its derived byte lanes");
                            @(negedge clk_i);
                            ta_valid = 0; target_ready = 1;
                            tick;
                            check(td_valid && td_opcode == 3'd0 && !td_denied && !td_corrupt,
                                  "sub-word PutFullData must return AccessAck");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;
                            check(!td_valid && ta_ready, "sub-word D handshake must release the target");

                            // Get validates and maps the size/address-derived read mask.
                            @(negedge clk_i);
                            td_ready = 0; target_error = 0; ta_valid = 1; ta_opcode = 3'd4; ta_param = 0;
                            ta_size = 3'd1; ta_source = 0; ta_address = 32'h8000_0022; ta_mask = 4'b1100;
                            ta_data = 0; ta_corrupt = 0;
                            tick;
                            check(target_valid && !target_write && target_be == 4'b1100,
                                  "Get target mapping must use its derived byte lanes");
                            @(negedge clk_i);
                            ta_valid = 0; target_ready = 1; target_rdata = 32'hcafe_babe;
                            tick;
                            check(td_valid && td_opcode == 3'd1 && !td_denied && !td_corrupt
                                  && td_data == 32'hcafe_babe,
                                  "Get must return AccessAckData with target data");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;

                            // A Get target error must mark both denial and corrupt data.
                            @(negedge clk_i);
                            td_ready = 0; target_error = 0; ta_valid = 1; ta_opcode = 3'd4; ta_param = 0;
                            ta_size = 3'd2; ta_source = 0; ta_address = 32'h8000_0030; ta_mask = 4'hf;
                            ta_data = 0; ta_corrupt = 0;
                            tick;
                            check(target_valid && !target_write, "Get error request must reach the target");
                            @(negedge clk_i);
                            ta_valid = 0; target_ready = 1; target_error = 1; target_rdata = 32'hdead_beef;
                            tick;
                            check(td_valid && td_opcode == 3'd1 && td_denied && td_corrupt && td_data == 0,
                                  "Get target error must return denied corrupt AccessAckData");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;
                            check(!td_valid && ta_ready, "Get error D handshake must release the target");

                            // Reject an unaligned sub-word request without touching MMIO.
                            @(negedge clk_i);
                            td_ready = 0; target_error = 0; target_ready = 0; ta_valid = 1;
                            ta_opcode = 3'd4; ta_param = 0; ta_size = 3'd1; ta_source = 0;
                            ta_address = 32'h8000_0021; ta_mask = 4'b0110; ta_data = 0; ta_corrupt = 0;
                            tick;
                            check(td_valid && !td_denied && td_corrupt && !target_valid,
                                  "unaligned Get must be rejected as corrupt without MMIO");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;

                            // Reject a PutPartial mask that reaches outside the derived transfer lanes.
                            @(negedge clk_i);
                            td_ready = 0; ta_valid = 1; ta_opcode = 3'd1; ta_param = 0; ta_size = 3'd1;
                            ta_source = 0; ta_address = 32'h8000_0022; ta_mask = 4'b0110;
                            ta_data = 32'haabb_ccdd; ta_corrupt = 0;
                            tick;
                            check(td_valid && !td_denied && td_corrupt && !target_valid,
                                  "out-of-range PutPartial mask must be rejected as corrupt");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;

                            // Unsupported A opcode produces corrupt, deterministic data, no target request.
                            @(negedge clk_i);
                            td_ready = 0; target_ready = 0; ta_valid = 1; ta_opcode = 3'd7;
                            ta_param = 0; ta_size = 3'd2; ta_source = 0; ta_address = 32'h8000_0030;
                            ta_mask = 4'hf; ta_data = 32'hdead_beef; ta_corrupt = 0;
                            tick;
                            check(!ta_ready && td_valid && !td_denied && td_corrupt && td_data == 0
                                  && !target_valid, "unsupported opcode must yield corrupt deterministic D response");

                            // Target wait is bounded, while the generated D response is held separately.
                            @(negedge clk_i);
                            td_ready = 1; ta_valid = 0;
                            tick;
                            @(negedge clk_i);
                            td_ready = 0; ta_valid = 1; ta_opcode = 3'd4; ta_param = 0;
                            ta_size = 3'd2; ta_source = 0; ta_address = 32'h8000_0040; ta_mask = 4'hf;
                            ta_data = 0; ta_corrupt = 0;
                            tick;
                            @(negedge clk_i);
                            ta_valid = 0; target_ready = 0;
                            repeat (15) begin
                                tick;
                                check(target_valid && !td_valid,
                                      "target must remain active before its bounded wait expires");
                            end
                            tick;
                            check(td_valid && td_opcode == 3'd1 && td_denied && td_corrupt && td_data == 0,
                                  "unready Get target must produce a bounded denied corrupt D response");
                            @(negedge clk_i);
                            td_ready = 1;
                            tick;

                            // A-channel wait is bounded separately from native response backpressure.
                            @(negedge clk_i);
                            td_ready = 0; req_valid_i = 1; req_write_i = 0; req_addr_i = 32'h0000_0060;
                            req_wdata_i = 0; req_be_i = 4'hf; a_ready = 0;
                            tick;
                            @(negedge clk_i);
                            req_valid_i = 0;
                            repeat (15) begin
                                tick;
                                check(a_valid && !rsp_valid_o,
                                      "A channel must remain valid before its bounded wait expires");
                            end
                            tick;
                            check(!a_valid && rsp_valid_o && rsp_error_o && rsp_rdata_o == 0,
                                  "unready A channel must produce a bounded native error response");
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
                    str(RTL_DIR / "tl_ul_mmio_bridge.sv"),
                    str(RTL_DIR / "tl_ul_mmio_target.sv"),
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
