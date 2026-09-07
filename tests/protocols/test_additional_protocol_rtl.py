from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL_DIR = ROOT / "src" / "myfuzz" / "protocols" / "rtl"


class AdditionalProtocolRtlTest(unittest.TestCase):
    def test_bridges_expose_bounded_canonical_mmio_contracts(self) -> None:
        expected_ports = {
            "apb3_mmio_bridge.sv": ("apb3_mmio_bridge", ("paddr_o", "psel_o", "penable_o", "pwrite_o", "pwdata_o", "pready_i", "prdata_i", "pslverr_i")),
            "obi_mmio_bridge.sv": ("obi_mmio_bridge", ("req_o", "gnt_i", "addr_o", "we_o", "wdata_o", "rvalid_i", "rdata_i")),
            "wishbone_mmio_bridge.sv": ("wishbone_mmio_bridge", ("cyc_o", "stb_o", "we_o", "adr_o", "dat_w_o", "sel_o", "ack_i", "err_i", "stall_i", "dat_r_i")),
            "axi4_mmio_bridge.sv": ("axi4_mmio_bridge", ("awid_o", "awaddr_o", "awlen_o", "awsize_o", "awburst_o", "wlast_o", "bid_i", "arid_o", "araddr_o", "arlen_o", "arsize_o", "arburst_o", "rid_i", "rlast_i")),
        }
        canonical_ports = ("req_valid_i", "req_write_i", "req_addr_i", "req_wdata_i", "req_be_i", "req_ready_o", "rsp_valid_o", "rsp_ready_i", "rsp_rdata_o", "rsp_error_o")

        for filename, (module_name, protocol_ports) in expected_ports.items():
            with self.subTest(bridge=filename):
                source = (RTL_DIR / filename).read_text(encoding="utf-8")
                self.assertIn(f"module {module_name} #(\n", source)
                for parameter in ("ADDRESS_WIDTH", "DATA_WIDTH", "MAX_WAIT_CYCLES"):
                    self.assertIn(f"parameter integer {parameter}", source)
                for port in (*canonical_ports, *protocol_ports):
                    self.assertIn(port, source)
                self.assertIn("EFFECTIVE_MAX_WAIT_CYCLES", source)
                self.assertIn("WAIT_TIMEOUT_VALUE", source)
                self.assertIn("rsp_error_q <= 1'b1", source)

    def test_apb3_has_no_apb4_only_outputs_and_axi4_forces_single_beat(self) -> None:
        apb3 = (RTL_DIR / "apb3_mmio_bridge.sv").read_text(encoding="utf-8")
        obi = (RTL_DIR / "obi_mmio_bridge.sv").read_text(encoding="utf-8")
        axi4 = (RTL_DIR / "axi4_mmio_bridge.sv").read_text(encoding="utf-8")

        self.assertNotIn("pprot_o", apb3)
        self.assertNotIn("pstrb_o", apb3)
        self.assertIn("req_be_i != FULL_BE", apb3)
        self.assertIn("req_be_i != FULL_BE", obi)
        self.assertIn("assign awlen_o = 8'd0", axi4)
        self.assertIn("assign arlen_o = 8'd0", axi4)
        self.assertIn("assign wlast_o = 1'b1", axi4)
        self.assertIn("bid_i != '0", axi4)
        self.assertIn("rid_i != '0", axi4)
        self.assertIn("!rlast_i", axi4)

    def test_wishbone_holds_cycle_and_strobe_until_ack_or_error(self) -> None:
        source = (RTL_DIR / "wishbone_mmio_bridge.sv").read_text(encoding="utf-8")

        self.assertIn("assign cyc_o = (state_q == REQUEST)", source)
        self.assertIn("assign stb_o = (state_q == REQUEST)", source)
        self.assertIn("if (ack_i || err_i)", source)
        self.assertIn("stall_i", source)

    def test_bridge_wrapper_fixtures_lint_when_verilator_is_available(self) -> None:
        verilator = shutil.which("verilator")
        if verilator is None:
            self.skipTest("Verilator is not installed")

        modules = {
            "apb3_mmio_bridge.sv": "apb3_mmio_bridge",
            "obi_mmio_bridge.sv": "obi_mmio_bridge",
            "wishbone_mmio_bridge.sv": "wishbone_mmio_bridge",
            "axi4_mmio_bridge.sv": "axi4_mmio_bridge",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            for filename, module_name in modules.items():
                with self.subTest(bridge=filename):
                    wrapper = temporary_path / f"{module_name}_wrapper.sv"
                    wrapper.write_text(
                        textwrap.dedent(
                            f"""
                            module {module_name}_wrapper;
                                {module_name} dut ();
                            endmodule
                            """
                        ),
                        encoding="utf-8",
                    )
                    result = subprocess.run(
                        [
                            verilator,
                            "--lint-only",
                            "-Wall",
                            "-Wno-fatal",
                            "--language",
                            "1800-2012",
                            "--top-module",
                            f"{module_name}_wrapper",
                            str(RTL_DIR / filename),
                            str(wrapper),
                        ],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_bridges_compile_with_icarus_when_available(self) -> None:
        iverilog = shutil.which("iverilog")
        if iverilog is None:
            self.skipTest("Icarus Verilog is not installed")

        modules = {
            "apb3_mmio_bridge.sv": "apb3_mmio_bridge",
            "obi_mmio_bridge.sv": "obi_mmio_bridge",
            "wishbone_mmio_bridge.sv": "wishbone_mmio_bridge",
            "axi4_mmio_bridge.sv": "axi4_mmio_bridge",
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            for filename, module_name in modules.items():
                with self.subTest(bridge=filename):
                    result = subprocess.run(
                        [
                            iverilog,
                            "-g2012",
                            "-s",
                            module_name,
                            "-o",
                            str(temporary_path / f"{module_name}.vvp"),
                            str(RTL_DIR / filename),
                        ],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_wishbone_directed_handshake_holds_through_stall(self) -> None:
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        if iverilog is None or vvp is None:
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            testbench = temporary_path / "wishbone_tb.sv"
            executable = temporary_path / "wishbone_tb.vvp"
            testbench.write_text(
                textwrap.dedent(
                    """
                    module tb;
                        logic clk_i = 1'b0, rst_ni = 1'b0;
                        logic req_valid_i, req_write_i, req_ready_o, rsp_valid_o, rsp_ready_i, rsp_error_o;
                        logic [31:0] req_addr_i, req_wdata_i, rsp_rdata_o;
                        logic [3:0] req_be_i, sel_o;
                        logic cyc_o, stb_o, we_o, ack_i, err_i, stall_i;
                        logic [31:0] adr_o, dat_w_o, dat_r_i;

                        wishbone_mmio_bridge dut (.*);
                        always #5 clk_i = ~clk_i;
                        task automatic tick;
                            @(posedge clk_i); #1;
                        endtask
                        task automatic check(input bit condition, input [8*80-1:0] message);
                            if (!condition) begin $display("FAIL: %0s", message); $fatal(1); end
                        endtask
                        initial begin
                            req_valid_i = 0; req_write_i = 0; req_addr_i = '0; req_wdata_i = '0; req_be_i = '0;
                            rsp_ready_i = 0; ack_i = 0; err_i = 0; stall_i = 0; dat_r_i = '0;
                            tick; rst_ni = 1;
                            @(negedge clk_i);
                            req_valid_i = 1; req_addr_i = 32'h40; req_be_i = 4'hf;
                            tick;
                            check(cyc_o && stb_o && !we_o && adr_o == 32'h40 && sel_o == 4'hf,
                                  "Wishbone request must start with CYC/STB");
                            @(negedge clk_i); req_valid_i = 0; stall_i = 1;
                            tick;
                            check(cyc_o && stb_o && !rsp_valid_o, "STALL must hold CYC/STB without a response");
                            @(negedge clk_i); stall_i = 0; ack_i = 1; dat_r_i = 32'hcafe_babe;
                            tick;
                            check(!cyc_o && !stb_o && rsp_valid_o && !rsp_error_o && rsp_rdata_o == 32'hcafe_babe,
                                  "ACK must complete the held read with data");
                            $finish;
                        end
                    endmodule
                    """
                ),
                encoding="utf-8",
            )
            compile_result = subprocess.run(
                [iverilog, "-g2012", "-s", "tb", "-o", str(executable), str(RTL_DIR / "wishbone_mmio_bridge.sv"), str(testbench)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([vvp, str(executable)], cwd=ROOT, text=True, capture_output=True, check=False)
            self.assertEqual(run_result.returncode, 0, run_result.stdout + run_result.stderr)


if __name__ == "__main__":
    unittest.main()
