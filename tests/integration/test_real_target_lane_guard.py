from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANE_RTL = ROOT / "configs/designs/ibex_multicomponent_ip/rtl/real_targets/real_64_to_32_lane.sv"


class RealTargetLaneGuardTests(unittest.TestCase):
    def test_reads_writes_and_rejections_are_lane_exact(self) -> None:
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if iverilog is None or vvp is None:
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            testbench = temporary_path / "lane_guard_tb.sv"
            executable = temporary_path / "lane_guard_tb.vvp"
            testbench.write_text(
                textwrap.dedent(
                    """
                    module tb;
                        logic mmio_valid, mmio_write;
                        logic [63:0] mmio_addr, mmio_wdata;
                        logic [7:0] mmio_be;
                        logic [63:0] mmio_rdata;
                        logic mmio_error, native_valid, native_write;
                        logic [31:0] native_addr, native_wdata, native_rdata;
                        logic [3:0] native_be;

                        real_64_to_32_lane dut (.*);

                        task automatic check(input bit condition, input [8*160-1:0] message);
                            if (!condition) begin
                                $display("FAIL: %0s", message);
                                $fatal(1);
                            end
                        endtask

                        task automatic drive(
                            input logic write,
                            input logic [63:0] address,
                            input logic [63:0] data,
                            input logic [7:0] byte_enable
                        );
                            mmio_valid = 1'b1;
                            mmio_write = write;
                            mmio_addr = address;
                            mmio_wdata = data;
                            mmio_be = byte_enable;
                            #1;
                        endtask

                        initial begin
                            native_rdata = 32'hcafe_babe;
                            mmio_valid = 0; mmio_write = 0; mmio_addr = 0;
                            mmio_wdata = 0; mmio_be = 0;
                            #1;

                            // Reads have no strobe; address bit 2 selects the lane.
                            drive(0, 64'h0, 64'h0, 8'h00);
                            check(!mmio_error && native_valid && native_addr == 32'h0
                                  && native_be == 4'hf && mmio_rdata == 64'h0000_0000_cafe_babe,
                                  "low-lane read must select native address zero");
                            drive(0, 64'h4, 64'h0, 8'h00);
                            check(!mmio_error && native_valid && native_addr == 32'h4
                                  && native_be == 4'hf && mmio_rdata == 64'hcafe_babe_0000_0000,
                                  "high-lane read must select native address plus four");

                            // Full-lane writes preserve the corresponding data word.
                            drive(1, 64'h0, 64'h1122_3344_5566_7788, 8'h0f);
                            check(!mmio_error && native_valid && native_addr == 32'h0
                                  && native_wdata == 32'h5566_7788 && native_be == 4'hf,
                                  "low-lane write must preserve the low data word");
                            drive(1, 64'h4, 64'haabb_ccdd_eeff_0011, 8'hf0);
                            check(!mmio_error && native_valid && native_addr == 32'h4
                                  && native_wdata == 32'haabb_ccdd && native_be == 4'hf,
                                  "high-lane write at plus four must not become plus eight");

                            // Unsupported shapes fail closed before native_valid.
                            drive(1, 64'h0, 64'h0, 8'hff);
                            check(mmio_error && !native_valid,
                                  "a two-lane write must be rejected");
                            drive(1, 64'h4, 64'h0, 8'h30);
                            check(mmio_error && !native_valid,
                                  "a partial high-lane write must be rejected");
                            drive(0, 64'h2, 64'h0, 8'h00);
                            check(mmio_error && !native_valid,
                                  "an unaligned read must be rejected");

                            mmio_valid = 1'b0;
                            #1;
                            check(!mmio_error && !native_valid,
                                  "an inactive request must not reach the native IP");
                            $display("PASS");
                            $finish;
                        end
                    endmodule
                    """
                ),
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                [iverilog, "-g2012", "-s", "tb", "-o", str(executable), str(LANE_RTL), str(testbench)],
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
                timeout=20,
            )
            self.assertEqual(
                run_result.returncode,
                0,
                msg=run_result.stdout + run_result.stderr,
            )
            self.assertIn("PASS", run_result.stdout)


if __name__ == "__main__":
    unittest.main()
