"""Behavioural RTL tests for the SoC fabric: arbiter, router and width adapter.

Every test in this module compiles the fabric modules with Icarus Verilog and
runs a self-checking scoreboard bench: the bench drives the processor-memory
beat contract, models real targets/peripherals (including delayed and late
responses) and asserts on transaction counts, routing and side effects.  No
assertion in this module inspects RTL source text.
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

ARBITER = RTL / "soc_arbiter.sv"
ROUTER = RTL / "soc_router.sv"
WIDTH_ADAPTER = RTL / "mmio_width_adapter.sv"


# ---------------------------------------------------------------------------
# simulation helpers
# ---------------------------------------------------------------------------

_HEADER = """\
`timescale 1ns/1ps
module tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  logic target_reset = 1'b0;
  integer i, j, k, gap, last;
  always #5 clk = ~clk;
  task tick; @(posedge clk); #1; endtask
  task check(input bit ok, input [8*200-1:0] msg);
    if (!ok) begin $display("FAIL: %0s", msg); $fatal(1); end
  endtask
"""


def _require_tools(test: unittest.TestCase) -> tuple[str, str]:
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    test.assertIsNotNone(iverilog, "iverilog is required for the SoC fabric RTL tests")
    test.assertIsNotNone(vvp, "vvp is required for the SoC fabric RTL tests")
    return str(iverilog), str(vvp)


def _compile_and_run(
    test: unittest.TestCase,
    body: str,
    sources: list[Path | str],
    *,
    expect_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    iverilog, vvp = _require_tools(test)
    for source in sources:
        test.assertTrue(Path(source).is_file(), f"missing RTL source: {source}")
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "tb.vvp"
        bench = Path(directory) / "tb.sv"
        bench.write_text(textwrap.dedent(body), encoding="utf-8")
        compiled = subprocess.run(
            [iverilog, "-g2012", "-s", "tb", "-o", str(output)]
            + [str(source) for source in sources]
            + [str(bench)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=60,
        )
        test.assertEqual(0, compiled.returncode, compiled.stderr)
        result = subprocess.run(
            [vvp, str(output)], cwd=ROOT, text=True, capture_output=True, timeout=60
        )
    if expect_success:
        test.assertEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertIn("PASS", result.stdout, result.stdout + result.stderr)
    else:
        test.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        test.assertNotIn("PASS", result.stdout)
    return result


# ---------------------------------------------------------------------------
# packed parameter encodings (Icarus Verilog has no array parameters)
# ---------------------------------------------------------------------------


def _hex_vector(values: list[int], width: int, max_windows: int) -> str:
    padded = list(values) + [0] * (max_windows - len(values))
    return "{" + ", ".join(f"{width}'h{padded[i]:x}" for i in reversed(range(max_windows))) + "}"


def _bit_vector(values: list[int], max_windows: int) -> str:
    padded = [1 if value else 0 for value in values] + [0] * (max_windows - len(values))
    return f"{max_windows}'b" + "".join(str(padded[i]) for i in reversed(range(max_windows)))


WINDOWS_THREE_TARGETS = [
    (0x1000_0000, 0x1000, 0),
    (0x2000_0000, 0x1000, 1),
    (0x3000_0000, 0x1000, 2),
]

# window 0 is executable and tiny (for out-of-range/cross-region checks)
WINDOWS_TIGHT = [
    (0x1000_0000, 0x100, 0),
    (0x2000_0000, 0x1000, 1),
    (0x3000_0000, 0x1000, 2),
]

WINDOWS_INSTR = [
    (0x1000_0000, 0x1000, 0),   # executable
    (0x2000_0000, 0x1000, 1),   # MMIO, not executable
    (0x3000_0000, 0x1000, 2),   # MMIO, not executable
]


# ---------------------------------------------------------------------------
# fabric test bench
# ---------------------------------------------------------------------------

_FABRIC_TEMPLATE = """\
  localparam integer NUM_SOURCES = 3;
  localparam integer NUM_TARGETS = 3;

  logic [NUM_SOURCES-1:0] s_req_valid, s_req_ready, s_write, s_instr;
  logic [NUM_SOURCES-1:0] s_rsp_valid, s_rsp_ready, s_error;
  logic [NUM_SOURCES-1:0][31:0] s_addr, s_wdata, s_rdata;
  logic [NUM_SOURCES-1:0][3:0] s_be;

  logic req_valid, req_ready, write, instr, rsp_valid, rsp_ready, error, protocol_error;
  logic [31:0] addr, wdata, rdata;
  logic [3:0] be;
  logic [1:0] source_id, rsp_source_id, selected_target;
  logic [7:0] transaction_id, rsp_transaction_id;
  logic stale_pending;

  logic [NUM_TARGETS-1:0] t_req_valid, t_req_ready, t_write;
  logic [NUM_TARGETS-1:0] t_rsp_valid, t_rsp_ready, t_error;
  logic [NUM_TARGETS-1:0][31:0] t_addr, t_wdata, t_rdata;
  logic [NUM_TARGETS-1:0][3:0] t_be;

  logic [NUM_TARGETS-1:0] tgt_busy;
  logic [NUM_TARGETS-1:0][31:0] tgt_addr, tgt_wdata;
  logic [NUM_TARGETS-1:0][3:0] tgt_be;
  logic [NUM_TARGETS-1:0] tgt_write;
  logic [NUM_TARGETS-1:0][7:0] tgt_delay;
  integer tgt_selects [0:NUM_TARGETS-1];
  integer tgt_writes [0:NUM_TARGETS-1];

  integer rec_count, sel_strobes;
  logic [1:0] rec_source [0:63];
  logic [1:0] rec_target [0:63];
  logic [31:0] rec_addr [0:63];
  logic [31:0] rec_wdata [0:63];
  logic rec_write [0:63];
  integer rsp_count [0:NUM_SOURCES-1];
  logic [31:0] rsp_data [0:NUM_SOURCES-1];
  logic rsp_error [0:NUM_SOURCES-1];
  logic quiet_violation;
  integer rsp_delay;
  logic hold_ready;

  soc_arbiter #(
      .NUM_SOURCES(NUM_SOURCES), .ADDRESS_WIDTH(32), .DATA_WIDTH(32),
      .SOURCE_ID_WIDTH(2), .TRANSACTION_ID_WIDTH(8)
  ) u_arb (
      .clk(clk), .reset(reset),
      .s_req_valid(s_req_valid), .s_req_ready(s_req_ready), .s_write(s_write),
      .s_addr(s_addr), .s_wdata(s_wdata), .s_be(s_be), .s_instr(s_instr),
      .s_rsp_valid(s_rsp_valid), .s_rsp_ready(s_rsp_ready),
      .s_rdata(s_rdata), .s_error(s_error),
      .req_valid(req_valid), .req_ready(req_ready), .write(write), .addr(addr),
      .wdata(wdata), .be(be), .instr(instr),
      .source_id(source_id), .transaction_id(transaction_id),
      .rsp_valid(rsp_valid), .rsp_ready(rsp_ready), .rdata(rdata), .error(error),
      .rsp_source_id(rsp_source_id), .rsp_transaction_id(rsp_transaction_id),
      .protocol_error(protocol_error)
  );

  soc_router #(
      .NUM_TARGETS(NUM_TARGETS), .ADDRESS_WIDTH(32), .DATA_WIDTH(32),
      .SOURCE_ID_WIDTH(2), .TRANSACTION_ID_WIDTH(8), .TARGET_ID_WIDTH(2),
      .MAX_WINDOWS(@MAX_WINDOWS@), .NUM_WINDOWS(@NUM_WINDOWS@),
      .WINDOW_BASE(@WINDOW_BASE@), .WINDOW_SIZE(@WINDOW_SIZE@),
      .WINDOW_TARGET(@WINDOW_TARGET@), .WINDOW_EXECUTABLE(@WINDOW_EXECUTABLE@),
      .WINDOW_READABLE(@WINDOW_READABLE@), .WINDOW_WRITABLE(@WINDOW_WRITABLE@)
  ) u_router (
      .clk(clk), .reset(reset),
      .req_valid(req_valid), .req_ready(req_ready), .write(write), .addr(addr),
      .wdata(wdata), .be(be), .instr(instr), .source_id(source_id),
      .transaction_id(transaction_id),
      .rsp_valid(rsp_valid), .rsp_ready(rsp_ready), .rdata(rdata), .error(error),
      .rsp_source_id(rsp_source_id), .rsp_transaction_id(rsp_transaction_id),
      .t_req_valid(t_req_valid), .t_req_ready(t_req_ready), .t_write(t_write),
      .t_addr(t_addr), .t_wdata(t_wdata), .t_be(t_be),
      .t_rsp_valid(t_rsp_valid), .t_rsp_ready(t_rsp_ready), .t_rdata(t_rdata),
      .t_error(t_error),
      .selected_target(selected_target), .stale_pending(stale_pending)
  );

  always_comb begin
    t_rdata = '0;
    t_error = '0;
    for (int unsigned t = 0; t < NUM_TARGETS; t++) begin
      t_req_ready[t] = !tgt_busy[t] && !hold_ready && !target_reset;
      t_rdata[t] = (tgt_addr[t] ^ 32'hA5A5_0000) + t;
    end
  end

  always @(posedge clk) begin
    for (int unsigned t = 0; t < NUM_TARGETS; t++) begin
      if (target_reset) begin
        tgt_busy[t] <= 1'b0;
        t_rsp_valid[t] <= 1'b0;
        tgt_delay[t] <= 8'h0;
      end else begin
        if (t_req_valid[t] && t_req_ready[t]) begin
          tgt_busy[t] <= 1'b1;
          tgt_addr[t] <= t_addr[t];
          tgt_wdata[t] <= t_wdata[t];
          tgt_be[t] <= t_be[t];
          tgt_write[t] <= t_write[t];
          tgt_delay[t] <= rsp_delay[7:0];
          tgt_selects[t] = tgt_selects[t] + 1;
          if (t_write[t]) tgt_writes[t] = tgt_writes[t] + 1;
        end
        if (tgt_busy[t] && !t_rsp_valid[t]) begin
          if (tgt_delay[t] == 8'h0) t_rsp_valid[t] <= 1'b1;
          else tgt_delay[t] <= tgt_delay[t] - 8'h1;
        end
        if (t_rsp_valid[t] && t_rsp_ready[t]) begin
          t_rsp_valid[t] <= 1'b0;
          tgt_busy[t] <= 1'b0;
        end
      end
    end
  end

  always @(posedge clk) begin
    for (int unsigned t = 0; t < NUM_TARGETS; t++) begin
      if (t_req_valid[t]) sel_strobes = sel_strobes + 1;
      if (t_req_valid[t] && t_req_ready[t]) begin
        rec_source[rec_count] = source_id;
        rec_target[rec_count] = t;
        rec_addr[rec_count] = t_addr[t];
        rec_wdata[rec_count] = t_wdata[t];
        rec_write[rec_count] = t_write[t];
        rec_count = rec_count + 1;
      end
      if (!t_req_valid[t] &&
          (t_write[t] || (t_addr[t] != 32'h0) || (t_wdata[t] != 32'h0) || (t_be[t] != 4'h0)))
        quiet_violation = 1'b1;
    end
    for (int unsigned s = 0; s < NUM_SOURCES; s++) begin
      if (s_rsp_valid[s] && s_rsp_ready[s]) begin
        rsp_count[s] = rsp_count[s] + 1;
        rsp_data[s] = s_rdata[s];
        rsp_error[s] = s_error[s];
      end
    end
  end

  task clear_counters;
    begin
      rec_count = 0;
      sel_strobes = 0;
      quiet_violation = 1'b0;
      gap = 0;
      last = 0;
      for (int unsigned t = 0; t < NUM_TARGETS; t++) begin
        tgt_selects[t] = 0;
        tgt_writes[t] = 0;
      end
      for (int unsigned s = 0; s < NUM_SOURCES; s++) begin
        rsp_count[s] = 0;
        rsp_data[s] = 32'h0;
        rsp_error[s] = 1'b0;
      end
    end
  endtask

  initial begin
    s_req_valid = '0; s_write = '0; s_instr = '0;
    s_addr = '0; s_wdata = '0; s_be = '0;
    s_rsp_ready = '0;
    rsp_delay = 0;
    hold_ready = 1'b0;
    reset = 1'b1;
    target_reset = 1'b1;
    tgt_busy = '0; tgt_addr = '0; tgt_wdata = '0; tgt_be = '0;
    tgt_write = '0; tgt_delay = '0; t_rsp_valid = '0;
    clear_counters();
    tick(); tick();
    target_reset = 1'b0;
    reset = 1'b0;
    tick();
    clear_counters();
    @PROGRAM@
    $display("FAIL: test program finished without PASS");
    $fatal(1);
  end
endmodule
"""


def _fabric_tb(
    program: str,
    *,
    windows: list[tuple[int, int, int]],
    executable: list[int] | None = None,
    readable: list[int] | None = None,
    writable: list[int] | None = None,
    max_windows: int = 4,
) -> str:
    count = len(windows)
    assert count <= max_windows
    executable = executable if executable is not None else [0] * count
    readable = readable if readable is not None else [1] * count
    writable = writable if writable is not None else [1] * count
    body = _FABRIC_TEMPLATE
    replacements = {
        "@MAX_WINDOWS@": str(max_windows),
        "@NUM_WINDOWS@": str(count),
        "@WINDOW_BASE@": _hex_vector([w[0] for w in windows], 32, max_windows),
        "@WINDOW_SIZE@": _hex_vector([w[1] for w in windows], 32, max_windows),
        "@WINDOW_TARGET@": _hex_vector([w[2] for w in windows], 2, max_windows),
        "@WINDOW_EXECUTABLE@": _bit_vector(executable, max_windows),
        "@WINDOW_READABLE@": _bit_vector(readable, max_windows),
        "@WINDOW_WRITABLE@": _bit_vector(writable, max_windows),
        "@PROGRAM@": textwrap.indent(textwrap.dedent(program), "    "),
    }
    for marker, value in replacements.items():
        body = body.replace(marker, value)
    return _HEADER + body


# ---------------------------------------------------------------------------
# width adapter test bench
# ---------------------------------------------------------------------------

_WIDTH_TEMPLATE = """\
  logic req_valid, req_ready, write, rsp_valid, rsp_ready, error;
  logic [31:0] addr;
  logic [63:0] wdata, rdata;
  logic [7:0] be;
  logic p_req_valid, p_req_ready, p_write, p_rsp_valid, p_rsp_ready, p_error;
  logic [31:0] p_addr, p_wdata, p_rdata;
  logic [3:0] p_be;
  logic stale_pending;

  logic [31:0] preg [0:7];
  integer p_accesses, p_writes, p_reads;
  logic [31:0] seen_addr [0:31], seen_wdata [0:31];
  logic [3:0] seen_be [0:31];
  logic [31:0] last_addr, last_wdata;
  logic [63:0] last_rdata;
  logic [3:0] last_be;
  logic last_error;
  logic p_busy;
  logic [7:0] p_delay, p_delay_max;

  mmio_width_adapter #(
      .ADDRESS_WIDTH(32), .DATA_WIDTH(64), .PERIPHERAL_DATA_WIDTH(32),
      .ALLOW_SPANNING_WRITE_SPLIT(@SPLIT@), .ALLOW_SPANNING_READ_ASSEMBLE(@ASSEMBLE@)
  ) dut (
      .clk(clk), .reset(reset),
      .req_valid(req_valid), .req_ready(req_ready), .write(write), .addr(addr),
      .wdata(wdata), .be(be),
      .rsp_valid(rsp_valid), .rsp_ready(rsp_ready), .rdata(rdata), .error(error),
      .p_req_valid(p_req_valid), .p_req_ready(p_req_ready), .p_write(p_write),
      .p_addr(p_addr), .p_wdata(p_wdata), .p_be(p_be),
      .p_rsp_valid(p_rsp_valid), .p_rsp_ready(p_rsp_ready), .p_rdata(p_rdata),
      .p_error(p_error), .stale_pending(stale_pending)
  );

  always_comb begin
    p_req_ready = !p_busy;
    p_rdata = preg[p_addr[4:2]];
    p_error = 1'b0;
  end

  always @(posedge clk) begin
    if (target_reset) begin
      p_busy <= 1'b0;
      p_rsp_valid <= 1'b0;
      p_delay <= 8'h0;
    end else begin
      if (p_req_valid && p_req_ready) begin
        p_busy <= 1'b1;
        p_delay <= p_delay_max;
        seen_addr[p_accesses] = p_addr;
        seen_wdata[p_accesses] = p_wdata;
        seen_be[p_accesses] = p_be;
        p_accesses = p_accesses + 1;
        last_addr = p_addr;
        last_wdata = p_wdata;
        last_be = p_be;
        if (p_write) begin
          p_writes = p_writes + 1;
          preg[p_addr[4:2]] = p_wdata;
        end else begin
          p_reads = p_reads + 1;
        end
      end
      if (p_busy && !p_rsp_valid) begin
        if (p_delay == 8'h0) p_rsp_valid <= 1'b1;
        else p_delay <= p_delay - 8'h1;
      end
      if (p_rsp_valid && p_rsp_ready) begin
        p_rsp_valid <= 1'b0;
        p_busy <= 1'b0;
      end
    end
  end

  task beat_access(input bit wr, input [31:0] a, input [63:0] d, input [7:0] b);
    begin
      addr = a; wdata = d; be = b; write = wr; req_valid = 1'b1;
      #1;
      check(req_ready, "width adapter accepted the beat request");
      tick();
      req_valid = 1'b0;
      i = 0;
      while (!rsp_valid && (i < 100)) begin tick(); i = i + 1; end
      check(rsp_valid, "width adapter returned a response");
      last_rdata = rdata;
      last_error = error;
      tick();
      check(req_ready, "width adapter returned to idle");
    end
  endtask

  initial begin
    req_valid = 1'b0; write = 1'b0; addr = 32'h0; wdata = 64'h0; be = 8'h0;
    rsp_ready = 1'b1;
    p_delay_max = 8'h1;
    p_accesses = 0; p_writes = 0; p_reads = 0;
    last_addr = 32'h0; last_wdata = 32'h0; last_be = 4'h0;
    last_rdata = 64'h0; last_error = 1'b0;
    for (int unsigned r = 0; r < 8; r++) preg[r] = 32'h0;
    reset = 1'b1;
    target_reset = 1'b1;
    tick(); tick();
    reset = 1'b0;
    target_reset = 1'b0;
    preg[0] = 32'h1111_1111;
    preg[1] = 32'h2222_2222;
    @PROGRAM@
    $display("FAIL: test program finished without PASS");
    $fatal(1);
  end
endmodule
"""


def _width_tb(program: str, *, allow_split: bool, allow_read: bool) -> str:
    body = _WIDTH_TEMPLATE
    body = body.replace("@SPLIT@", "1'b1" if allow_split else "1'b0")
    body = body.replace("@ASSEMBLE@", "1'b1" if allow_read else "1'b0")
    body = body.replace("@PROGRAM@", textwrap.indent(textwrap.dedent(program), "    "))
    return _HEADER + body


# ---------------------------------------------------------------------------
# test benches
# ---------------------------------------------------------------------------

_THREE_SOURCES_PROGRAM = """\
    s_rsp_ready = 3'b111;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF; s_be[1] = 4'hF; s_be[2] = 4'hF;
    s_addr[0] = 32'h2000_0040;
    s_addr[1] = 32'h3000_0080;
    s_addr[2] = 32'h1000_000C;
    s_req_valid = 3'b111;

    hold_ready = 1'b1;
    i = 0;
    while ((t_req_valid == 3'b000) && (i < 20)) begin tick(); i = i + 1; end
    check(t_req_valid != 3'b000, "backpressure: a request reached a target");
    check(t_req_ready == 3'b000, "backpressure: the selected target held the request");
    check(rec_count == 0, "backpressure: no transaction was accepted");
    check((tgt_selects[0] + tgt_selects[1] + tgt_selects[2]) == 0,
          "backpressure: no target accepted a request");
    hold_ready = 1'b0;

    i = 0;
    while (((rsp_count[0] + rsp_count[1] + rsp_count[2]) < 3) && (i < 400)) begin
      tick(); i = i + 1;
    end
    s_req_valid = 3'b000;
    tick();

    check(rec_count == 3, "exactly three transactions were accepted");
    check(rec_source[0] == 0 && rec_source[1] == 1 && rec_source[2] == 2,
          "grant order follows the round-robin priority");
    check(rec_target[0] == 1 && rec_target[1] == 2 && rec_target[2] == 0,
          "each source reached the target that owns its window");
    check(rec_addr[0] == 32'h2000_0040 && rec_addr[1] == 32'h3000_0080 &&
          rec_addr[2] == 32'h1000_000C, "the selected target sees the latched address");
    check(rsp_count[0] == 1 && rsp_count[1] == 1 && rsp_count[2] == 1,
          "exactly one completion per source");
    check(rsp_data[0] == ((32'h2000_0040 ^ 32'hA5A5_0000) + 1),
          "source 0 completion data was produced by target 1");
    check(rsp_data[1] == ((32'h3000_0080 ^ 32'hA5A5_0000) + 2),
          "source 1 completion data was produced by target 2");
    check(rsp_data[2] == ((32'h1000_000C ^ 32'hA5A5_0000) + 0),
          "source 2 completion data was produced by target 0");
    check(rsp_error[0] == 0 && rsp_error[1] == 0 && rsp_error[2] == 0,
          "mapped accesses complete without error");
    check(!protocol_error, "no arbiter protocol error was reported");
    check(!quiet_violation, "non-selected targets never saw a strobe");
    $display("PASS");
    $finish;
"""

_FAIRNESS_PROGRAM = """\
    s_rsp_ready = 3'b111;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF; s_be[1] = 4'hF; s_be[2] = 4'hF;
    s_addr[0] = 32'h1000_0010;
    s_addr[1] = 32'h2000_0010;
    s_addr[2] = 32'h3000_0010;
    s_req_valid = 3'b111;

    i = 0;
    while (((rsp_count[0] + rsp_count[1] + rsp_count[2]) < 12) && (i < 800)) begin
      tick(); i = i + 1;
    end
    s_req_valid = 3'b000;
    tick();

    check(rsp_count[0] == 4 && rsp_count[1] == 4 && rsp_count[2] == 4,
          "round-robin gave every always-requesting source four grants in twelve");
    check(rec_count == 12, "twelve transactions were accepted");
    for (k = 0; k < 12; k = k + 1)
      check(rec_source[k] == (k % 3), "grant sequence rotates through every source");

    for (j = 0; j < 3; j = j + 1) begin
      last = -1;
      gap = 0;
      for (k = 0; k < 12; k = k + 1) begin
        if (rec_source[k] == j) begin
          if ((last >= 0) && ((k - last) > gap)) gap = k - last;
          last = k;
        end
      end
      check(gap <= 3, "no source waits more than NUM_SOURCES grants");
    end

    check(rsp_error[0] == 0 && rsp_error[1] == 0 && rsp_error[2] == 0,
          "fairness run completed without error");
    $display("PASS");
    $finish;
"""

_PENDING_PROGRAM = """\
    s_rsp_ready = 3'b000;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF;
    s_addr[0] = 32'h1000_0020;
    s_req_valid = 3'b001;
    rsp_delay = 2;

    i = 0;
    while ((tgt_selects[0] == 0) && (i < 100)) begin tick(); i = i + 1; end
    check(tgt_selects[0] == 1, "the target accepted the first transaction");
    i = 0;
    while (!s_rsp_valid[0] && (i < 50)) begin tick(); i = i + 1; end
    tick();

    check(s_rsp_valid[0], "the source is offered its pending completion");
    check(!s_req_ready[0], "a source holding req_valid during its own response is not granted again");
    check(rec_count == 1, "no second transaction was accepted while the response was pending");
    check(tgt_selects[0] == 1, "the target saw exactly one request while the response was pending");
    check(sel_strobes <= 2, "no second select strobe was issued while the response was pending");

    s_rsp_ready[0] = 1'b1;
    i = 0;
    while ((rsp_count[0] < 2) && (i < 200)) begin tick(); i = i + 1; end
    s_req_valid = 3'b000;
    tick();

    check(rsp_count[0] == 2, "the held request completed only after the first response");
    check(rec_count == 2, "exactly two transactions in total");
    check(rec_addr[1] == 32'h1000_0020, "the second transaction used the new latched address");
    check(rsp_error[0] == 0, "both completions were successful");
    $display("PASS");
    $finish;
"""

_ERRORS_PROGRAM = """\
    s_rsp_ready = 3'b111;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF;
    s_req_valid = 3'b001;

    s_addr[0] = 32'h9000_0000;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && s_error[0], "unmapped address returns an error response");
    check(rec_count == 0, "unmapped address selected no target");
    check(sel_strobes == 0, "unmapped address asserted no target select strobe");
    tick();

    s_addr[0] = 32'h1000_00FD;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && s_error[0], "cross-region access returns an error response");
    check(rec_count == 0, "cross-region access selected no target");
    check(sel_strobes == 0, "cross-region access asserted no target select strobe");
    tick();

    s_addr[0] = 32'h1000_00FC;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && !s_error[0], "the last in-window word still completes normally");
    check(rec_count == 1 && rec_target[0] == 0 && rec_addr[0] == 32'h1000_00FC,
          "in-window access reached target 0 with the right address");
    tick();
    s_req_valid = 3'b000;
    tick();
    check(sel_strobes == 1, "only the in-window access produced a select strobe");
    $display("PASS");
    $finish;
"""

_INSTRUCTION_PROGRAM = """\
    s_rsp_ready = 3'b111;
    s_write = 3'b000;
    s_be[0] = 4'hF;
    s_req_valid = 3'b001;
    s_instr[0] = 1'b1;

    s_addr[0] = 32'h2000_0004;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && s_error[0], "instruction fetch to a non-executable window errors");
    check(rec_count == 0, "instruction fetch to a non-executable window selected no target");
    check(sel_strobes == 0, "instruction fetch to a non-executable window asserted no select");
    tick();

    s_addr[0] = 32'h1000_0004;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && !s_error[0], "instruction fetch to an executable window completes");
    check(rec_count == 1 && rec_target[0] == 0, "executable fetch reached target 0");
    tick();

    s_instr[0] = 1'b0;
    s_addr[0] = 32'h2000_0004;
    i = 0;
    while (!s_rsp_valid[0] && (i < 100)) begin tick(); i = i + 1; end
    check(s_rsp_valid[0] && !s_error[0], "a data access to the same window completes");
    check(rec_count == 2 && rec_target[1] == 1, "data access reached target 1");
    tick();
    s_req_valid = 3'b000;
    tick();
    check(sel_strobes == 2, "only the two permitted accesses selected a target");
    $display("PASS");
    $finish;
"""

_QUIET_PROGRAM = """\
    s_rsp_ready = 3'b111;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF;
    s_addr[0] = 32'h2000_0020;
    s_req_valid = 3'b001;
    rsp_delay = 4;

    i = 0;
    while ((rsp_count[0] == 0) && (i < 200)) begin tick(); i = i + 1; end
    s_req_valid = 3'b000;
    tick();

    check(rsp_count[0] == 1, "the transaction to target 1 completed");
    check(tgt_selects[0] == 0 && tgt_selects[1] == 1 && tgt_selects[2] == 0,
          "only target 1 was selected");
    check(tgt_writes[0] == 0 && tgt_writes[1] == 0 && tgt_writes[2] == 0,
          "no side effect appeared on any target");
    check(!quiet_violation, "a non-selected target never saw a select or strobe");
    $display("PASS");
    $finish;
"""

_RESET_PROGRAM = """\
    s_rsp_ready = 3'b000;
    s_write = 3'b001;
    s_instr = 3'b000;
    s_be[0] = 4'hF;
    s_addr[0] = 32'h1000_0010;
    s_wdata[0] = 32'h1122_3344;
    s_req_valid = 3'b001;
    rsp_delay = 6;

    i = 0;
    while ((tgt_selects[0] == 0) && (i < 100)) begin tick(); i = i + 1; end
    check(tgt_selects[0] == 1, "the target accepted the write before the reset");
    check(tgt_writes[0] == 1, "the target performed exactly one write side effect");

    reset = 1'b1;
    s_req_valid = 3'b000;
    tick(); tick(); tick();
    check(!s_rsp_valid[0] && !s_rsp_valid[1] && !s_rsp_valid[2],
          "no response is asserted while reset is high");
    reset = 1'b0;
    tick();

    check(stale_pending, "the router remembers that a response may still arrive");
    check(!s_rsp_valid[0] && !s_rsp_valid[1] && !s_rsp_valid[2],
          "reset left no stranded response");
    i = 0;
    while (stale_pending && (i < 100)) begin tick(); i = i + 1; end
    check(!stale_pending, "the late response was drained");
    check(tgt_selects[0] == 1 && tgt_writes[0] == 1,
          "reset produced no duplicate transaction or side effect");
    check(rsp_count[0] == 0 && rsp_count[1] == 0 && rsp_count[2] == 0,
          "the aborted transaction produced no completion");

    s_rsp_ready = 3'b001;
    s_addr[0] = 32'h1000_0020;
    s_wdata[0] = 32'h5566_7788;
    s_req_valid = 3'b001;
    i = 0;
    while ((rsp_count[0] == 0) && (i < 200)) begin tick(); i = i + 1; end
    s_req_valid = 3'b000;
    tick();
    check(rsp_count[0] == 1, "the post-reset transaction completed exactly once");
    check(rsp_error[0] == 0, "the post-reset transaction completed without error");
    check(tgt_selects[0] == 2 && tgt_writes[0] == 2,
          "the post-reset transaction performed exactly one more side effect");
    check(rec_count == 2 && rec_addr[1] == 32'h1000_0020 && rec_wdata[1] == 32'h5566_7788,
          "the post-reset transaction carried the new address and data");
    $display("PASS");
    $finish;
"""

_LATE_RESPONSE_PROGRAM = """\
    s_rsp_ready = 3'b000;
    s_write = 3'b000;
    s_instr = 3'b000;
    s_be[0] = 4'hF;
    s_addr[0] = 32'h1000_0030;
    s_req_valid = 3'b001;
    rsp_delay = 6;

    i = 0;
    while ((tgt_selects[0] == 0) && (i < 100)) begin tick(); i = i + 1; end
    check(tgt_selects[0] == 1, "the target accepted the read before the reset");

    reset = 1'b1;
    s_req_valid = 3'b000;
    tick(); tick();
    reset = 1'b0;
    tick();

    check(stale_pending && !rsp_valid, "the abandoned read is still tracked, not answered");
    check(!s_rsp_valid[0], "no stale completion was delivered to the source");
    i = 0;
    while (stale_pending && (i < 100)) begin tick(); i = i + 1; end
    check(!stale_pending, "the late response was discarded");
    check(rsp_count[0] == 0, "the late response was never attributed to the source");

    s_rsp_ready = 3'b001;
    s_addr[0] = 32'h1000_0044;
    s_req_valid = 3'b001;
    i = 0;
    while ((rsp_count[0] == 0) && (i < 200)) begin tick(); i = i + 1; end
    s_req_valid = 3'b000;
    tick();
    check(rsp_count[0] == 1, "the post-reset read completed exactly once");
    check(rsp_data[0] == ((32'h1000_0044 ^ 32'hA5A5_0000) + 0),
          "the post-reset read received its own data, not the late response");
    check(rsp_error[0] == 0, "the post-reset read completed without error");
    $display("PASS");
    $finish;
"""

_WIDTH_STRICT_PROGRAM = """\
    beat_access(1'b0, 32'h100, 64'h0, 8'h0F);
    check(!last_error, "32-bit low lane read completes without error");
    check(last_rdata === 64'h0000_0000_1111_1111,
          "32-bit low lane read is zero-extended into bits 31:0");
    check(p_reads == 1 && last_addr == 32'h100, "one peripheral read at 0x100");

    beat_access(1'b0, 32'h104, 64'h0, 8'hF0);
    check(!last_error, "32-bit high lane read completes without error");
    check(last_rdata === 64'h2222_2222_0000_0000,
          "32-bit high lane read is placed in bits 63:32 and zero-extended below");
    check(p_reads == 2 && last_addr == 32'h104, "address bit 2 selected the second peripheral word");

    beat_access(1'b1, 32'h100, 64'hDEAD_BEEF_1234_5678, 8'h0F);
    check(!last_error, "32-bit low lane write completes without error");
    check(p_writes == 1 && last_addr == 32'h100 && last_be == 4'hF,
          "low lane write used the low half with translated byte enables");
    check(last_wdata == 32'h1234_5678, "low lane write drove wdata[31:0] to the peripheral");

    beat_access(1'b1, 32'h104, 64'hDEAD_BEEF_1234_5678, 8'hF0);
    check(p_writes == 2 && last_addr == 32'h104 && last_be == 4'hF,
          "high lane write used the high half at the address selected by bit 2");
    check(last_wdata == 32'hDEAD_BEEF, "high lane write drove wdata[63:32] to the peripheral");

    beat_access(1'b1, 32'h100, 64'h0011_2233_4455_6677, 8'b0000_0010);
    check(last_be == 4'b0010 && last_wdata == 32'h4455_6677,
          "single byte enable in the low lane is translated to the peripheral byte mask");

    beat_access(1'b1, 32'h104, 64'h0011_2233_4455_6677, 8'b0001_0000);
    check(last_be == 4'b0001 && last_wdata == 32'h0011_2233,
          "single byte enable in the high lane is translated to peripheral lane 0");

    k = p_accesses;
    beat_access(1'b1, 32'h100, 64'hAABB_CCDD_EEFF_0011, 8'hFF);
    check(last_error, "spanning 64-bit MMIO write is refused without explicit permission");
    check(p_accesses == k, "refused spanning write issued no peripheral access at all");
    check(p_writes == 4, "refused spanning write issued no peripheral write");

    k = p_accesses;
    beat_access(1'b0, 32'h100, 64'h0, 8'hFF);
    check(last_error, "spanning 64-bit MMIO read is refused without explicit permission");
    check(p_accesses == k && p_reads == 2, "refused spanning read issued no peripheral read");

    k = p_accesses;
    beat_access(1'b1, 32'h104, 64'h0, 8'h0F);
    check(last_error, "lane and address bit 2 mismatch is refused");
    check(p_accesses == k, "mismatched lane issued no peripheral access");

    k = p_accesses;
    beat_access(1'b1, 32'h100, 64'h0, 8'h00);
    check(last_error, "an access with no byte enables is refused");
    check(p_accesses == k, "empty access issued no peripheral access");

    p_delay_max = 8'h8;
    req_valid = 1'b1; write = 1'b0; addr = 32'h108; be = 8'h0F; wdata = 64'h0;
    #1;
    check(req_ready, "adapter accepted the slow read");
    tick();
    req_valid = 1'b0;
    i = 0;
    while (!p_busy && (i < 20)) begin tick(); i = i + 1; end
    check(p_busy, "the peripheral is busy with the slow read");
    reset = 1'b1;
    tick(); tick();
    reset = 1'b0;
    tick();
    check(stale_pending, "reset while a peripheral access was in flight is tracked");
    check(!rsp_valid, "no response is forwarded after reset");
    i = 0;
    while (stale_pending && (i < 100)) begin tick(); i = i + 1; end
    check(!stale_pending, "the late peripheral response was drained");
    check(!rsp_valid, "the late peripheral response was not forwarded");
    check(p_writes == 4 && p_reads == 3, "reset did not add or duplicate peripheral accesses");
    $display("PASS");
    $finish;
"""

_WIDTH_PERMISSIVE_PROGRAM = """\
    k = p_accesses;
    beat_access(1'b0, 32'h100, 64'h0, 8'hFF);
    check(!last_error, "64-bit spanning read is assembled when the window permits it");
    check(last_rdata === 64'h2222_2222_1111_1111,
          "full 64-bit read returns the low half in bits 31:0 and the high half in 63:32");
    check(p_reads == 2, "spanning read performed exactly two peripheral reads");
    check(seen_addr[k] == 32'h100 && seen_addr[k+1] == 32'h104,
          "spanning read touched the low word first and the high word second");

    k = p_accesses;
    beat_access(1'b1, 32'h100, 64'hAABB_CCDD_EEFF_0011, 8'hFF);
    check(!last_error, "64-bit spanning write is split when the window declares it safe");
    check(p_writes == 2, "spanning write performed exactly two peripheral writes");
    check(seen_addr[k] == 32'h100 && seen_wdata[k] == 32'hEEFF_0011 && seen_be[k] == 4'hF,
          "low half was written first with full byte enables");
    check(seen_addr[k+1] == 32'h104 && seen_wdata[k+1] == 32'hAABB_CCDD && seen_be[k+1] == 4'hF,
          "high half was written second with full byte enables");

    k = p_accesses;
    beat_access(1'b1, 32'h100, 64'hAABB_CCDD_EEFF_0011, 8'b0101_1111);
    check(p_writes == 4, "partially enabled spanning write still issues two writes");
    check(seen_be[k] == 4'hF && seen_be[k+1] == 4'b0101,
          "byte enables are translated per half for a spanning write");
    check(seen_wdata[k] == 32'hEEFF_0011 && seen_wdata[k+1] == 32'hAABB_CCDD,
          "spanning write data is taken from the matching half");

    k = p_accesses;
    beat_access(1'b1, 32'h104, 64'hAABB_CCDD_EEFF_0011, 8'hFF);
    check(last_error, "a misaligned 64-bit write is refused even with split permission");
    check(p_accesses == k && p_writes == 4, "misaligned wide write issued no peripheral access");

    k = p_accesses;
    beat_access(1'b0, 32'h104, 64'h0, 8'hFF);
    check(last_error, "a misaligned 64-bit read is refused even with assemble permission");
    check(p_accesses == k && p_reads == 2, "misaligned wide read issued no peripheral access");
    $display("PASS");
    $finish;
"""


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


class SocFabricRtlTests(unittest.TestCase):
    def test_default_parameters_elaborate(self) -> None:
        body = (
            "module tb;\n"
            "  logic clk = 1'b0;\n"
            "  logic reset = 1'b1;\n"
            "  always #5 clk = ~clk;\n"
            "  soc_arbiter u_arb (.clk(clk), .reset(reset));\n"
            "  soc_router u_router (.clk(clk), .reset(reset));\n"
            "  mmio_width_adapter u_adapter (.clk(clk), .reset(reset));\n"
            "  initial begin #10; $display(\"PASS\"); $finish; end\n"
            "endmodule\n"
        )
        _compile_and_run(self, body, [ARBITER, ROUTER, WIDTH_ADAPTER])

    def test_three_sources_reach_three_targets_after_backpressure(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_THREE_SOURCES_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_round_robin_fairness_is_bounded(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_FAIRNESS_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_source_holding_request_during_pending_response(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_PENDING_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_unmapped_and_cross_region_accesses_error_without_select(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_ERRORS_PROGRAM, windows=WINDOWS_TIGHT),
            [ARBITER, ROUTER],
        )

    def test_instruction_fetch_to_non_executable_window_errors(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(
                _INSTRUCTION_PROGRAM,
                windows=WINDOWS_INSTR,
                executable=[1, 0, 0],
            ),
            [ARBITER, ROUTER],
        )

    def test_non_selected_targets_never_see_a_strobe(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_QUIET_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_reset_mid_transaction_terminates_cleanly(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_RESET_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_late_response_after_reset_is_discarded(self) -> None:
        _compile_and_run(
            self,
            _fabric_tb(_LATE_RESPONSE_PROGRAM, windows=WINDOWS_THREE_TARGETS),
            [ARBITER, ROUTER],
        )

    def test_width_adapter_strict_cva6_lane_behaviour(self) -> None:
        _compile_and_run(
            self,
            _width_tb(_WIDTH_STRICT_PROGRAM, allow_split=False, allow_read=False),
            [WIDTH_ADAPTER],
        )

    def test_width_adapter_permitted_spanning_accesses(self) -> None:
        _compile_and_run(
            self,
            _width_tb(_WIDTH_PERMISSIVE_PROGRAM, allow_split=True, allow_read=True),
            [WIDTH_ADAPTER],
        )

    def test_full_test_reset_discards_router_pending_target(self) -> None:
        program = """
            s_req_valid = 3'b001; s_be[0] = 4'hf;
            s_addr[0] = 32'h1000_0010; rsp_delay = 50;
            i = 0;
            while (tgt_selects[0] == 0 && i < 20) begin tick(); i++; end
            check(tgt_selects[0] == 1, "a real target request preceded full reset");
            reset = 1; target_reset = 1; s_req_valid = 0;
            tick(); tick();
            reset = 0; target_reset = 0;
            tick();
            check(req_ready && !stale_pending, "full reset clears pending target state");
            rsp_delay = 0; s_rsp_ready = '1; s_req_valid = 3'b001;
            i = 0;
            while (rsp_count[0] == 0 && i < 30) begin tick(); i++; end
            check(rsp_count[0] == 1 && !rsp_error[0], "next test receives its own response");
            $display("PASS"); $finish;
        """
        bench = _fabric_tb(program, windows=WINDOWS_THREE_TARGETS).replace(
            "soc_router #(", "soc_router #(.RESET_CLEARS_TARGETS(1'b1),")
        _compile_and_run(self, bench, [ARBITER, ROUTER])

    def test_full_test_reset_discards_width_adapter_pending_target(self) -> None:
        program = """
            p_delay_max = 50;
            req_valid = 1; addr = 32'h100; be = 8'h0f;
            tick(); req_valid = 0;
            i = 0;
            while (!p_busy && i < 20) begin tick(); i++; end
            check(p_busy, "a real peripheral request preceded full reset");
            reset = 1; target_reset = 1;
            tick(); tick();
            reset = 0; target_reset = 0;
            tick();
            check(req_ready && !stale_pending, "full reset clears pending peripheral state");
            p_delay_max = 0;
            beat_access(0, 32'h100, 0, 8'h0f);
            check(!last_error && p_accesses == 2, "next test completes a fresh peripheral request");
            $display("PASS"); $finish;
        """
        bench = _width_tb(program, allow_split=False, allow_read=False).replace(
            "mmio_width_adapter #(", "mmio_width_adapter #(.RESET_CLEARS_TARGETS(1'b1),")
        _compile_and_run(self, bench, [WIDTH_ADAPTER])


if __name__ == "__main__":
    unittest.main()
