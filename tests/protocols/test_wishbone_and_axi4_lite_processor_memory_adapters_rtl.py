"""Behavioural RTL tests for the two CPU-side protocol adapters added for P17.

`wishbone_processor_memory_adapter` and `axi4_lite_processor_memory_adapter` are
INITIATOR-side adapters: they sample what a real CPU master drives and produce
the generic processor-memory-beat request/response pair.  They are the mirror of
`beat_to_wishbone` and `axi4_lite_mmio_bridge`, which drive targets, and must not
be confused with them.

Every test here compiles the adapter with Icarus Verilog and runs a self-checking
scoreboard bench: the bench drives the CPU-side protocol, models the backend
handshake (including backpressure and error), and asserts on the request shape,
the response and the termination.  No assertion inspects RTL source text.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl"
WISHBONE = RTL / "wishbone_processor_memory_adapter.sv"
AXI4_LITE = RTL / "axi4_lite_processor_memory_adapter.sv"


def _run(test: unittest.TestCase, body: str, sources: list[Path],
         *, expect_success: bool = True) -> subprocess.CompletedProcess[str]:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    if not iverilog or not vvp:
        test.skipTest("Icarus Verilog is not installed")
    for source in sources:
        test.assertTrue(Path(source).is_file(), f"missing RTL source: {source}")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "tb.vvp"
        bench = Path(directory) / "tb.sv"
        bench.write_text(textwrap.dedent(body), encoding="utf-8")
        compiled = subprocess.run(
            [iverilog, "-g2012", "-s", "tb", "-o", str(output)]
            + [str(source) for source in sources] + [str(bench)],
            cwd=ROOT, text=True, capture_output=True, timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stderr)
        result = subprocess.run([vvp, str(output)], cwd=ROOT, text=True,
                                capture_output=True, timeout=60)
    if expect_success:
        test.assertEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertIn("PASS", result.stdout, result.stdout + result.stderr)
    else:
        test.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
    return result


_WISHBONE_HEADER = """\
`timescale 1ns/1ps
module tb;
  logic clk_i = 1'b0, rst_ni = 1'b0;
  logic cyc_i = 1'b0, stb_i = 1'b0, we_i = 1'b0;
  logic [31:0] adr_i = '0, dat_w_i = '0;
  logic [3:0] sel_i = '0;
  logic stall_o, ack_o, err_o;
  logic [31:0] dat_r_o;
  logic req_valid_o, req_ready_i = 1'b1, req_write_o;
  logic [31:0] req_addr_o, req_wdata_o;
  logic [3:0] req_be_o;
  logic rsp_valid_i = 1'b0, rsp_ready_o;
  logic [31:0] rsp_rdata_i = '0;
  logic rsp_error_i = 1'b0;
  integer i, held;

  @DUT@

  always #5 clk_i = ~clk_i;
  task tick; @(posedge clk_i); #1; endtask
  task settle; @(negedge clk_i); #1; endtask
  task check(input bit ok, input [8*110-1:0] msg);
    if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
  endtask
  task reset_dut;
    begin
      rst_ni = 1'b0; cyc_i = 1'b0; stb_i = 1'b0; we_i = 1'b0;
      rsp_valid_i = 1'b0; rsp_error_i = 1'b0; rsp_rdata_i = '0;
      tick(); tick(); rst_ni = 1'b1; settle();
    end
  endtask
  task wait_response_window;
    begin
      i = 0;
      while (!rsp_ready_o && (i < 20)) begin tick(); i = i + 1; end
      check(rsp_ready_o, "the adapter offered the backend response for acceptance");
    end
  endtask
"""


class WishboneProcessorMemoryAdapterRtlTests(unittest.TestCase):
    def _tb(self, program: str, *, read_only: int = 0, has_sel: int = 1) -> str:
        dut = (
            "wishbone_processor_memory_adapter #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32),\n"
            "      .READ_ONLY(%d), .HAS_SEL(%d)) dut (.*);" % (read_only, has_sel)
        )
        return (_WISHBONE_HEADER.replace("@DUT@", dut)
                + "  initial begin\n"
                + textwrap.indent(textwrap.dedent(program), "    ")
                + "    $display(\"PASS\"); $finish;\n"
                + "  end\nendmodule\n")

    def test_read_and_write_transfers_hold_ack_until_the_master_ends_the_cycle(self) -> None:
        program = """\
      reset_dut();
      // A read passes the CPU's fields through unchanged.
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h100; sel_i = 4'hF;
      #1;
      check(req_valid_o && !req_write_o && req_addr_o == 32'h100 &&
            req_be_o == 4'hF && !stall_o, "read request shape");
      tick();
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'hc0ffee00;
      tick();
      check(ack_o && !err_o && dat_r_o == 32'hc0ffee00, "read ack carries the data");
      // The termination is held while the master keeps the cycle open.
      tick();
      check(ack_o && dat_r_o == 32'hc0ffee00, "ack is held until the master ends the cycle");
      @(negedge clk_i); stb_i = 1'b0; cyc_i = 1'b0; tick();
      check(!ack_o && !err_o, "the termination clears once the cycle ends");

      // A write carries write data and byte enables, and never read data.
      settle();
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b1; adr_i = 32'h204;
      dat_w_i = 32'hdeadbeef; sel_i = 4'b0011;
      #1;
      check(req_valid_o && req_write_o && req_addr_o == 32'h204 &&
            req_wdata_o == 32'hdeadbeef && req_be_o == 4'b0011, "write request shape");
      tick();
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'hffffffff;
      tick();
      check(ack_o && dat_r_o == 32'h0, "a write ack never exposes read data");
      @(negedge clk_i); rsp_valid_i = 1'b0; stb_i = 1'b0; cyc_i = 1'b0; tick();
      check(!ack_o, "the write cycle terminated");
    """
        _run(self, self._tb(program), [WISHBONE])

    def test_backend_error_terminates_with_err_and_zero_data(self) -> None:
        program = """\
      reset_dut();
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h300; sel_i = 4'hF;
      tick();
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'hdead; rsp_error_i = 1'b1;
      tick();
      check(err_o && !ack_o && dat_r_o == 32'h0,
            "a backend error is ERR with no data, never ACK");
      @(negedge clk_i); rsp_valid_i = 1'b0; rsp_error_i = 1'b0; stb_i = 1'b0; cyc_i = 1'b0;
      tick();
      check(!err_o, "the error termination cleared");
    """
        _run(self, self._tb(program), [WISHBONE])

    def test_stall_holds_the_cycle_until_the_backend_accepts(self) -> None:
        program = """\
      reset_dut();
      req_ready_i = 1'b0;
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h400; sel_i = 4'hF;
      #1;
      check(stall_o && req_valid_o && req_addr_o == 32'h400,
            "the master is stalled while the backend refuses the request");
      tick();
      #1;
      check(stall_o && req_addr_o == 32'h400 && req_be_o == 4'hF,
            "the stalled cycle keeps its fields stable");
      req_ready_i = 1'b1;
      tick();
      check(!stall_o, "the stall releases once the request is accepted");
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'h1234;
      tick();
      check(ack_o && dat_r_o == 32'h1234, "the stalled transfer completed correctly");
      @(negedge clk_i); rsp_valid_i = 1'b0; stb_i = 1'b0; cyc_i = 1'b0; tick();
    """
        _run(self, self._tb(program), [WISHBONE])

    def test_a_transfer_with_no_byte_selected_is_refused_without_a_request(self) -> None:
        program = """\
      reset_dut();
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b1; adr_i = 32'h500; sel_i = 4'h0;
      #1;
      check(!req_valid_o, "an empty-select write issues no backend request");
      check(!stall_o, "a refused transfer is not stalled");
      tick();
      check(err_o && !ack_o, "an empty-select write terminates with ERR");
      @(negedge clk_i); stb_i = 1'b0; cyc_i = 1'b0; tick();
      check(!err_o, "the refusal cleared");

      // A read with no byte selected has no defined size either.
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h504; sel_i = 4'h0;
      #1;
      check(!req_valid_o, "an empty-select read issues no backend request");
      tick();
      check(err_o, "an empty-select read terminates with ERR");
      @(negedge clk_i); stb_i = 1'b0; cyc_i = 1'b0; tick();
    """
        _run(self, self._tb(program), [WISHBONE])

    def test_read_only_projection_refuses_writes_and_forces_full_select(self) -> None:
        program = """\
      reset_dut();
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b1; adr_i = 32'h600; sel_i = 4'hF;
      #1;
      check(!req_valid_o, "a read-only boundary issues no write request");
      tick();
      check(err_o, "a refused write is reported as ERR, not silently dropped");
      @(negedge clk_i); stb_i = 1'b0; cyc_i = 1'b0; tick();

      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h604; sel_i = 4'h0;
      #1;
      check(req_valid_o && !req_write_o && req_be_o == 4'hF && !stall_o,
            "a read-only read is forced to a full byte enable");
      tick();
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'h55;
      tick();
      check(ack_o && dat_r_o == 32'h55, "the forced read completed");
      @(negedge clk_i); rsp_valid_i = 1'b0; stb_i = 1'b0; cyc_i = 1'b0; tick();
    """
        _run(self, self._tb(program, read_only=1, has_sel=0), [WISHBONE])

    def test_a_master_without_select_is_projected_to_a_full_byte_enable(self) -> None:
        program = """\
      reset_dut();
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b1; adr_i = 32'h700;
      dat_w_i = 32'h01020304; sel_i = 4'b0001;
      #1;
      check(req_valid_o && req_write_o && req_be_o == 4'hF,
            "HAS_SEL=0 drives a full byte enable regardless of the tied select");
      tick();
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1;
      tick();
      check(ack_o, "the projected write completed");
      @(negedge clk_i); rsp_valid_i = 1'b0; stb_i = 1'b0; cyc_i = 1'b0; tick();
    """
        _run(self, self._tb(program, has_sel=0), [WISHBONE])

    def test_an_idle_bus_cycle_issues_nothing(self) -> None:
        program = """\
      reset_dut();
      cyc_i = 1'b1; stb_i = 1'b0; we_i = 1'b0; adr_i = 32'h800; sel_i = 4'hF;
      #1;
      check(!req_valid_o && !stall_o && !ack_o && !err_o,
            "CYC without STB is an idle bus cycle, not a transfer");
      tick(); tick();
      check(!req_valid_o && !ack_o && !err_o, "the idle bus cycle stayed idle");
      @(negedge clk_i); cyc_i = 1'b0; tick();
      // Reset in the middle of a transfer must leave no stale termination.  The
      // master still holds the cycle here, so a fresh request afterwards is
      // correct; what must not survive is the previous ACK or ERR.
      cyc_i = 1'b1; stb_i = 1'b1; we_i = 1'b0; adr_i = 32'h804; sel_i = 4'hF;
      tick();
      rst_ni = 1'b0; tick(); rst_ni = 1'b1; settle();
      check(!ack_o && !err_o, "reset left no stale termination behind");
      @(negedge clk_i); stb_i = 1'b0; cyc_i = 1'b0; tick();
      check(!req_valid_o && !ack_o && !err_o, "the adapter is idle after the cycle ends");
    """
        _run(self, self._tb(program), [WISHBONE])


_AXI4_LITE_HEADER = """\
`timescale 1ns/1ps
module tb;
  logic clk_i = 1'b0, rst_ni = 1'b0;
  logic [31:0] awaddr_i = '0, wdata_i = '0, araddr_i = '0;
  logic [2:0] awprot_i = '0, arprot_i = '0;
  logic [3:0] wstrb_i = '0;
  logic awvalid_i = 1'b0, awready_o, wvalid_i = 1'b0, wready_o;
  logic [1:0] bresp_o, rresp_o;
  logic bvalid_o, bready_i = 1'b1, rvalid_o, rready_i = 1'b1;
  logic [31:0] rdata_o;
  logic arvalid_i = 1'b0, arready_o;
  logic req_valid_o, req_ready_i = 1'b1, req_write_o;
  logic [31:0] req_addr_o, req_wdata_o;
  logic [3:0] req_be_o;
  logic rsp_valid_i = 1'b0, rsp_ready_o;
  logic [31:0] rsp_rdata_i = '0;
  logic rsp_error_i = 1'b0;
  integer i;

  axi4_lite_processor_memory_adapter #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) dut (.*);

  always #5 clk_i = ~clk_i;
  task tick; @(posedge clk_i); #1; endtask
  task settle; @(negedge clk_i); #1; endtask
  task check(input bit ok, input [8*110-1:0] msg);
    if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
  endtask
  task reset_dut;
    begin
      rst_ni = 1'b0;
      awvalid_i = 1'b0; wvalid_i = 1'b0; arvalid_i = 1'b0; rsp_valid_i = 1'b0;
      rsp_error_i = 1'b0; rsp_rdata_i = '0;
      tick(); tick(); rst_ni = 1'b1; settle();
    end
  endtask
  task wait_request;
    begin
      i = 0;
      while (!req_valid_o && (i < 20)) begin tick(); i = i + 1; end
      check(req_valid_o, "the adapter issued its backend request");
    end
  endtask
  task wait_response_window;
    begin
      i = 0;
      while (!rsp_ready_o && (i < 20)) begin tick(); i = i + 1; end
      check(rsp_ready_o, "the adapter offered the backend response for acceptance");
    end
  endtask
  task wait_b;
    begin
      i = 0;
      while (!bvalid_o && (i < 20)) begin tick(); i = i + 1; end
      check(bvalid_o, "the write response arrived");
    end
  endtask
  task wait_r;
    begin
      i = 0;
      while (!rvalid_o && (i < 20)) begin tick(); i = i + 1; end
      check(rvalid_o, "the read response arrived");
    end
  endtask
"""


class Axi4LiteProcessorMemoryAdapterRtlTests(unittest.TestCase):
    def _tb(self, program: str) -> str:
        return (_AXI4_LITE_HEADER
                + "  initial begin\n"
                + textwrap.indent(textwrap.dedent(program), "    ")
                + "    $display(\"PASS\"); $finish;\n"
                + "  end\nendmodule\n")

    def test_write_channels_may_arrive_in_either_order(self) -> None:
        program = """\
      reset_dut();
      // AW first, W second.
      settle(); awvalid_i = 1'b1; awaddr_i = 32'h400;
      wstrb_i = 4'b0011; wdata_i = 32'h11223344;
      #1;
      check(awready_o, "AW is accepted first");
      tick();
      settle(); awvalid_i = 1'b0; wvalid_i = 1'b1;
      #1;
      check(wready_o, "W is accepted afterwards");
      tick();
      wait_request();
      check(req_write_o && req_addr_o == 32'h400 && req_wdata_o == 32'h11223344 &&
            req_be_o == 4'b0011, "the write request carries the captured AW and W payload");
      settle(); wvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1;
      tick(); wait_b();
      check(bresp_o == 2'b00 && !rvalid_o, "B is OKAY and the read channel is quiet");
      settle(); rsp_valid_i = 1'b0; tick();
      check(!bvalid_o, "B terminated");

      // W first, AW second.
      settle(); wvalid_i = 1'b1; wdata_i = 32'haabbccdd; wstrb_i = 4'hF;
      #1;
      check(wready_o, "W is accepted first");
      tick();
      settle(); wvalid_i = 1'b0; awvalid_i = 1'b1; awaddr_i = 32'h700;
      #1;
      check(awready_o, "AW is accepted afterwards");
      tick();
      wait_request();
      check(req_write_o && req_addr_o == 32'h700 && req_wdata_o == 32'haabbccdd,
            "the write request uses the W payload captured before AW arrived");
      settle(); awvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1;
      tick(); wait_b(); check(bresp_o == 2'b00, "the second write is OKAY");
      settle(); rsp_valid_i = 1'b0; tick();
    """
        _run(self, self._tb(program), [AXI4_LITE])

    def test_read_returns_data_and_an_errored_read_is_slverr_with_zero_data(self) -> None:
        program = """\
      reset_dut();
      settle(); arvalid_i = 1'b1; araddr_i = 32'h500;
      #1;
      check(arready_o, "AR is accepted when no write is in flight");
      tick();
      wait_request();
      check(!req_write_o && req_addr_o == 32'h500, "the read request carries the AR address");
      settle(); arvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'hfeedf00d;
      tick(); wait_r();
      check(rdata_o == 32'hfeedf00d && rresp_o == 2'b00 && !bvalid_o,
            "R carries the data with OKAY");
      settle(); rsp_valid_i = 1'b0; tick();
      check(!rvalid_o, "R terminated");

      settle(); arvalid_i = 1'b1; araddr_i = 32'h600;
      tick(); wait_request();
      settle(); arvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_error_i = 1'b1; rsp_rdata_i = 32'hdead;
      tick(); wait_r();
      check(rresp_o == 2'b10 && rdata_o == 32'h0,
            "an errored read is SLVERR with zeroed data");
      settle(); rsp_valid_i = 1'b0; rsp_error_i = 1'b0; tick();
    """
        _run(self, self._tb(program), [AXI4_LITE])

    def test_an_errored_write_is_slverr(self) -> None:
        program = """\
      reset_dut();
      settle(); awvalid_i = 1'b1; awaddr_i = 32'h800; wvalid_i = 1'b1;
      wdata_i = 32'h1; wstrb_i = 4'hF;
      tick(); wait_request();
      settle(); awvalid_i = 1'b0; wvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_error_i = 1'b1;
      tick(); wait_b();
      check(bresp_o == 2'b10, "an errored write is SLVERR, not a silent OKAY");
      settle(); rsp_valid_i = 1'b0; rsp_error_i = 1'b0; tick();
      check(!bvalid_o, "B terminated");
    """
        _run(self, self._tb(program), [AXI4_LITE])

    def test_a_write_in_flight_owns_the_adapter_over_a_simultaneous_read(self) -> None:
        program = """\
      reset_dut();
      settle(); awvalid_i = 1'b1; awaddr_i = 32'h900; wvalid_i = 1'b1;
      wdata_i = 32'h2; wstrb_i = 4'hF; arvalid_i = 1'b1; araddr_i = 32'ha00;
      #1;
      check(!arready_o, "AR is refused while a write is presented, so the outcome is deterministic");
      check(awready_o && wready_o, "the write channels are still accepted");
      tick();
      settle(); awvalid_i = 1'b0; wvalid_i = 1'b0;
      wait_request();
      check(req_write_o && req_addr_o == 32'h900, "the accepted transfer is the write");
      settle(); arvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1;
      tick(); wait_b();
      settle(); rsp_valid_i = 1'b0; tick();
      check(arready_o, "AR is accepted once the write has finished");
    """
        _run(self, self._tb(program), [AXI4_LITE])

    def test_b_and_r_are_held_under_backpressure(self) -> None:
        program = """\
      reset_dut();
      bready_i = 1'b0; rready_i = 1'b0;
      settle(); arvalid_i = 1'b1; araddr_i = 32'hb00;
      tick(); wait_request();
      settle(); arvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1; rsp_rdata_i = 32'h7;
      tick(); wait_r();
      check(rdata_o == 32'h7, "R holds its data while rready is low");
      tick(); check(rvalid_o && rdata_o == 32'h7, "R is still held a cycle later");
      settle(); rready_i = 1'b1; rsp_valid_i = 1'b0; tick();
      check(!rvalid_o, "R released once rready arrived");

      // The same for B.
      settle(); awvalid_i = 1'b1; awaddr_i = 32'hc00; wvalid_i = 1'b1;
      wdata_i = 32'h3; wstrb_i = 4'hF;
      tick(); wait_request();
      settle(); awvalid_i = 1'b0; wvalid_i = 1'b0;
      wait_response_window();
      @(negedge clk_i); rsp_valid_i = 1'b1;
      tick(); wait_b();
      tick(); check(bvalid_o, "B is held while bready is low");
      settle(); bready_i = 1'b1; rsp_valid_i = 1'b0; tick();
      check(!bvalid_o, "B released once bready arrived");
    """
        _run(self, self._tb(program), [AXI4_LITE])

    def test_reset_clears_a_partially_collected_write(self) -> None:
        program = """\
      reset_dut();
      settle(); awvalid_i = 1'b1; awaddr_i = 32'hd00; wstrb_i = 4'hF;
      #1;
      check(awready_o, "AW accepted before reset");
      tick();
      settle(); awvalid_i = 1'b0;
      rst_ni = 1'b0; tick(); tick(); rst_ni = 1'b1; settle();
      check(!req_valid_o && !bvalid_o && !rvalid_o,
            "reset left no pending request or response behind");
      // The adapter must accept a fresh write afterwards.
      settle(); awvalid_i = 1'b1; awaddr_i = 32'he00; wvalid_i = 1'b1;
      wdata_i = 32'h4; wstrb_i = 4'hF;
      tick(); wait_request();
      check(req_write_o && req_addr_o == 32'he00, "a fresh write is collected after reset");
    """
        _run(self, self._tb(program), [AXI4_LITE])


if __name__ == "__main__":
    unittest.main()
