"""Behavioural RTL tests for the independent MMIO driver (P7).

Every test compiles fuzz_mmio_master.sv with Icarus Verilog and runs a
self-checking scoreboard test bench.  The bench drives the raw stimulus segment
and the beat initiator port, models the fabric handshake, and asserts on the
observable behaviour; no assertion in this module inspects RTL source text.

The four behaviours required by P7 are proven by simulation:

* latch during stall: new raw bits never change an accepted transaction;
* exactly one completion per accepted transaction (beat response or recorded
  invalid-selector error);
* busy_drop_count increments exactly when an offer is present while busy;
* reset terminates an in-flight transaction and clears the driver state.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RTL = ROOT / "src/myfuzz/protocols/rtl/fuzz_mmio_master.sv"

_HEADER = """\
module tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  always #5 clk = ~clk;
  task tick; @(posedge clk); #1; endtask
  task check(input bit ok, input [8*160-1:0] msg);
    if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
  endtask
"""


def _require_tools(test: unittest.TestCase) -> tuple[str, str]:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    test.assertIsNotNone(iverilog, "iverilog is required for the MMIO driver RTL tests")
    test.assertIsNotNone(vvp, "vvp is required for the MMIO driver RTL tests")
    return str(iverilog), str(vvp)


def _compile_and_run(test: unittest.TestCase, body: str) -> subprocess.CompletedProcess[str]:
    iverilog, vvp = _require_tools(test)
    test.assertTrue(RTL.is_file(), f"missing RTL source: {RTL}")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "mmio_master.vvp"
        bench = Path(directory) / "mmio_master_tb.sv"
        bench.write_text(textwrap.dedent(body), encoding="utf-8")
        compiled = subprocess.run(
            [iverilog, "-g2012", "-s", "tb", "-o", str(output), str(RTL), str(bench)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
        result = subprocess.run(
            [vvp, str(output)], cwd=ROOT, text=True, capture_output=True, timeout=60
        )
    test.assertEqual(0, result.returncode, result.stdout + result.stderr)
    test.assertIn("PASS", result.stdout, result.stdout + result.stderr)
    return result


# ---------------------------------------------------------------------------
# biased addressing: window table in the driver parameters
# ---------------------------------------------------------------------------

_BIASED_TB = _HEADER + textwrap.dedent("""
  localparam integer AW = 32;
  localparam integer DW = 32;
  localparam integer SW = 3;
  localparam integer NW = 4;
  localparam logic [SW-1:0] SEL_INVALID = 3'd4;
  localparam logic [NW*AW-1:0] WINDOW_BASE =
      {32'h8000_0000, 32'h5000_0000, 32'h4000_0000, 32'h0001_0000};
  localparam logic [NW*AW-1:0] WINDOW_SIZE =
      {32'h0001_0000, 32'h0000_1000, 32'h0000_1000, 32'h0000_8000};

  logic stim_offer = 1'b0;
  logic [SW-1:0] stim_target_selector = '0;
  logic [AW-1:0] stim_offset = '0;
  logic stim_write = 1'b0;
  logic [DW-1:0] stim_wdata = '0;
  logic [DW/8-1:0] stim_be = '0;

  logic req_valid, req_ready = 1'b0, write;
  logic [AW-1:0] addr;
  logic [DW-1:0] wdata;
  logic [DW/8-1:0] be;
  logic rsp_valid = 1'b0, rsp_ready, error = 1'b0;
  logic [DW-1:0] rdata = '0;
  logic [31:0] busy_drop_count, error_count, completion_count;
  logic [3:0] error_code;

  integer beat_accepts = 0;
  integer beat_completions = 0;
  always_ff @(posedge clk) begin
    if (req_valid && req_ready) beat_accepts <= beat_accepts + 1;
    if (rsp_valid && rsp_ready) beat_completions <= beat_completions + 1;
  end

  fuzz_mmio_master #(
    .ADDRESS_WIDTH(AW), .DATA_WIDTH(DW), .SELECTOR_WIDTH(SW),
    .SELECTOR_INVALID(SEL_INVALID), .NUM_WINDOWS(NW), .ADDRESS_STRATEGY(1),
    .WINDOW_BASE(WINDOW_BASE), .WINDOW_SIZE(WINDOW_SIZE)
  ) dut (.*);

  initial begin
    stim_offer = 1'b0;
    tick();
    check(!req_valid && !rsp_ready, "reset: no beat activity");
    check(busy_drop_count == 0 && error_count == 0 && completion_count == 0,
          "reset: counters cleared");
    check(error_code == 4'd0, "reset: error code cleared");

    stim_offer = 1'b1; stim_target_selector = 3'd1; stim_offset = 32'h0000_1234;
    stim_write = 1'b1; stim_wdata = 32'hCAFE_BABE; stim_be = 4'hF;
    tick();
    check(!req_valid && busy_drop_count == 0 && completion_count == 0,
          "reset: an offer while reset is asserted is ignored");

    // idle accepts A and latches every payload field
    reset = 1'b0;
    tick();
    check(req_valid, "idle accepts the offer");
    check(addr == 32'h4000_0234, "biased address is window base plus masked offset");
    check(write && wdata == 32'hCAFE_BABE && be == 4'hF, "latched write payload");
    check(!rsp_ready && completion_count == 0, "no completion before the response");

    // new raw bits B while stalled must not change the in-flight transaction
    stim_target_selector = 3'd2; stim_offset = 32'hDEAD_BEEF;
    stim_write = 1'b0; stim_wdata = 32'h0BAD_F00D; stim_be = 4'h3;
    stim_offer = 1'b0;
    tick();
    check(busy_drop_count == 0, "no busy drop without an offer");
    stim_offer = 1'b1;
    repeat (3) begin
      tick();
      check(addr == 32'h4000_0234 && write && wdata == 32'hCAFE_BABE && be == 4'hF,
            "latched fields survive new raw bits while stalled");
    end
    check(busy_drop_count == 3, "busy_drop_count counts every offer while stalled");
    check(req_valid, "the accepted request is still pending");

    // the fabric accepts the request
    @(negedge clk); req_ready = 1'b1;
    tick();
    @(negedge clk); req_ready = 1'b0;
    check(!req_valid && rsp_ready, "response state waits for the beat response");
    check(addr == '0 && wdata == '0 && be == '0 && !write,
          "no request payload outside the request state");
    check(busy_drop_count == 4, "the pending offer is dropped while the request is accepted");

    // exactly one completion per accepted transaction
    @(negedge clk); rsp_valid = 1'b1; error = 1'b0; rdata = 32'h1357_9BDF;
    tick();
    check(completion_count == 1, "exactly one completion for the accepted transaction");
    check(error_count == 0 && error_code == 4'd0, "a successful response records no error");
    // The two negedge waits above include one response-wait posedge as well
    // as the completion posedge.  stim_offer remains asserted on both.
    check(busy_drop_count == 6, "response wait and completion offers are both dropped and counted");
    check(!req_valid && !rsp_ready, "the driver returns to idle after completion");
    @(negedge clk); rsp_valid = 1'b0;
    tick();
    check(completion_count == 1, "an extra response cannot complete the transaction twice");
    check(req_valid && addr == 32'h5000_0EEF && !write &&
          wdata == 32'h0BAD_F00D && be == 4'h3,
          "the next accepted offer uses the new raw bits");

    // a response outside the response state is not accepted
    @(negedge clk); rsp_valid = 1'b1; error = 1'b1;
    tick();
    check(completion_count == 1 && error_count == 0, "early response is rejected");
    @(negedge clk); rsp_valid = 1'b0; error = 1'b0;

    // reset terminates the in-flight transaction and clears the driver state
    @(negedge clk); req_ready = 1'b1;
    tick();
    @(negedge clk); req_ready = 1'b0;
    check(!req_valid && rsp_ready, "the second request reached the response state");
    reset = 1'b1;
    tick();
    check(!req_valid && !rsp_ready, "reset terminates the in-flight transaction");
    check(busy_drop_count == 0 && error_count == 0 && completion_count == 0 &&
          error_code == 4'd0, "reset clears counters and driver state");
    @(negedge clk); rsp_valid = 1'b1; error = 1'b1;
    tick();
    check(completion_count == 0 && error_count == 0,
          "a stale response during reset is rejected");
    @(negedge clk); rsp_valid = 1'b0; error = 1'b0;

    // an invalid selector completes once with a recorded error and no request
    reset = 1'b0; stim_target_selector = SEL_INVALID; stim_offset = 32'h0000_0000;
    stim_write = 1'b0; stim_wdata = 32'hFFFF_FFFF; stim_be = 4'hF;
    tick();
    check(!req_valid, "an invalid selector issues no beat request");
    check(error_count == 1 && completion_count == 1,
          "the invalid selector completes exactly once");
    check(error_code == 4'd1, "the invalid selector error is recorded");
    check(busy_drop_count == 0, "an offer accepted in idle is not a busy drop");

    // recovery: a valid offer is accepted and completes normally
    stim_target_selector = 3'd3; stim_offset = 32'h0000_0010;
    tick();
    check(req_valid && addr == 32'h8000_0010, "post-error recovery request");
    @(negedge clk); req_ready = 1'b1;
    tick();
    @(negedge clk); req_ready = 1'b0;
    @(negedge clk); rsp_valid = 1'b1; error = 1'b0;
    tick();
    @(negedge clk); rsp_valid = 1'b0;
    check(completion_count == 2 && error_count == 1, "post-error completion accounting");
    // The second accepted beat was deliberately interrupted by full reset;
    // the first and third beats completed.  Reset is not a completion.
    check(beat_accepts == 3 && beat_completions == 2,
          "two completed beats and one reset-interrupted beat are accounted for");
    $display("PASS busy_drop_count=%0d error_count=%0d completion_count=%0d",
             busy_drop_count, error_count, completion_count);
    $finish;
  end
endmodule
""")


# ---------------------------------------------------------------------------
# bias_off: the raw offset field is the address, never rewritten by the driver
# ---------------------------------------------------------------------------

_BIAS_OFF_TB = _HEADER + textwrap.dedent("""
  localparam integer AW = 32;
  localparam integer DW = 32;
  localparam integer SW = 3;
  localparam integer NW = 4;
  localparam logic [SW-1:0] SEL_INVALID = 3'd4;
  localparam logic [NW*AW-1:0] WINDOW_BASE =
      {32'h8000_0000, 32'h5000_0000, 32'h4000_0000, 32'h0001_0000};
  localparam logic [NW*AW-1:0] WINDOW_SIZE =
      {32'h0001_0000, 32'h0000_1000, 32'h0000_1000, 32'h0000_8000};

  logic stim_offer = 1'b0;
  logic [SW-1:0] stim_target_selector = '0;
  logic [AW-1:0] stim_offset = '0;
  logic stim_write = 1'b0;
  logic [DW-1:0] stim_wdata = '0;
  logic [DW/8-1:0] stim_be = '0;

  logic req_valid, req_ready = 1'b0, write;
  logic [AW-1:0] addr;
  logic [DW-1:0] wdata;
  logic [DW/8-1:0] be;
  logic rsp_valid = 1'b0, rsp_ready, error = 1'b0;
  logic [DW-1:0] rdata = '0;
  logic [31:0] busy_drop_count, error_count, completion_count;
  logic [3:0] error_code;

  fuzz_mmio_master #(
    .ADDRESS_WIDTH(AW), .DATA_WIDTH(DW), .SELECTOR_WIDTH(SW),
    .SELECTOR_INVALID(SEL_INVALID), .NUM_WINDOWS(NW), .ADDRESS_STRATEGY(0),
    .WINDOW_BASE(WINDOW_BASE), .WINDOW_SIZE(WINDOW_SIZE)
  ) dut (.*);

  initial begin
    tick();
    reset = 1'b0;
    stim_offer = 1'b1; stim_target_selector = 3'd2; stim_offset = 32'h5000_0040;
    stim_write = 1'b1; stim_wdata = 32'hA5A5_5A5A; stim_be = 4'hF;
    tick();
    check(req_valid && addr == 32'h5000_0040, "bias_off forwards the raw address bits");
    check(write && wdata == 32'hA5A5_5A5A && be == 4'hF, "bias_off latched payload");

    // a new raw offer while stalled is dropped and never re-latched
    stim_offset = 32'h0000_2000;
    tick();
    check(busy_drop_count == 1, "bias_off busy drop counted");
    check(addr == 32'h5000_0040, "bias_off latched address survives new raw bits");

    @(negedge clk); req_ready = 1'b1;
    tick();
    @(negedge clk); req_ready = 1'b0;
    @(negedge clk); rsp_valid = 1'b1;
    tick();
    @(negedge clk); rsp_valid = 1'b0;
    check(completion_count == 1 && error_count == 0, "bias_off completion");

    // an unmapped raw address is passed through unchanged: rewriting it into a
    // declared window is the fabric's decision, not the driver's
    stim_target_selector = 3'd0; stim_offset = 32'h0000_2000; stim_write = 1'b0;
    tick();
    check(req_valid && addr == 32'h0000_2000,
          "an unmapped raw address is forwarded without region bias");

    reset = 1'b1;
    tick();
    check(busy_drop_count == 0 && error_count == 0 && completion_count == 0,
          "bias_off reset clears the driver state");
    $display("PASS bias_off addr=%08x", addr);
    $finish;
  end
endmodule
""")


class FuzzMmioMasterRtlTests(unittest.TestCase):
    def test_latch_stall_single_completion_drop_count_and_reset(self) -> None:
        _compile_and_run(self, _BIASED_TB)

    def test_bias_off_forwards_the_raw_address_and_reset_clears_state(self) -> None:
        _compile_and_run(self, _BIAS_OFF_TB)


if __name__ == "__main__":
    unittest.main()
