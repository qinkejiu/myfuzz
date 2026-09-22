// Test-only harness for the myfuzz-owned MMIO infrastructure blocks that a
// composed profile run cannot reach.
//
// WHY THIS FILE EXISTS
//   `soc_profile_renderer` refuses `mmio_width_adapter` and `beat_address_narrow`
//   outright (`width-adapter-rendering-unsupported` /
//   `address-narrower-rendering-unsupported`), and no peripheral profile in this
//   checkout declares a target that stalls, so a composed run cannot exercise
//   the width adapter, the address narrower or the wait bound.  Rather than fake
//   a run through the composition, this harness drives the three RTL blocks
//   directly on the real Verilator and prints what they really did.
//
//   Everything in this file is test scaffolding: `harness_target` below is a
//   stimulus model, not a component under test.  The blocks under test are
//     * src/myfuzz/protocols/rtl/beat_watchdog.sv
//     * src/myfuzz/protocols/rtl/beat_address_narrow.sv
//     * src/myfuzz/protocols/rtl/mmio_width_adapter.sv
//
// Output protocol: one `MYFUZZ_HARNESS <key>=<value>` line per observation and
// exactly one final `MYFUZZ_HARNESS_RUN status=OK|FAIL|TIMEOUT reason=<text>`.
// Every key the Python test asserts on is printed here, and a scenario that
// cannot run prints FAIL with its reason instead of passing silently.
//
// Two bounds are enforced inside this file, both of them testbench bounds that
// the test asserts on rather than host-side sleeps: every scenario gives up
// after a bounded number of cycles, and the whole harness stops at
// HARNESS_MAX_CYCLES.

`timescale 1ns/1ps

// ---------------------------------------------------------------------------
// Stimulus target model: four 32-bit registers, one-cycle response latency, a
// stall input that suppresses the response forever, and the latched view of the
// request the target really accepted.
// ---------------------------------------------------------------------------
module harness_target #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32
) (
    input  logic                       clk,
    input  logic                       reset,
    input  logic                       stall,
    input  logic                       req_valid,
    output logic                       req_ready,
    input  logic                       write,
    input  logic [ADDRESS_WIDTH-1:0]   addr,
    input  logic [DATA_WIDTH-1:0]      wdata,
    input  logic [(DATA_WIDTH/8)-1:0]  be,
    output logic                       rsp_valid,
    input  logic                       rsp_ready,
    output logic [DATA_WIDTH-1:0]      rdata,
    output logic                       error,
    // Observations.
    output logic [ADDRESS_WIDTH-1:0]   last_addr,
    output logic [DATA_WIDTH-1:0]      last_wdata,
    output logic [(DATA_WIDTH/8)-1:0]  last_be,
    output logic                       last_write,
    output logic [31:0]                request_count
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;
    localparam logic [1:0] ERROR_REGISTER = 2'd3;
    logic [DATA_WIDTH-1:0] memory [0:3];
    logic [1:0] phase_q;
    logic busy_q;
    logic [31:0] count_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BE_WIDTH-1:0] be_q;
    logic write_q;

    integer index;
    initial begin
        for (index = 0; index < 4; index = index + 1) memory[index] = '0;
        memory[0] = 32'h1111_0000;
        memory[1] = 32'h2222_0001;
        memory[2] = 32'h3333_0002;
        memory[3] = 32'h4444_0003;
        phase_q = 2'd0;
        busy_q = 1'b0;
        count_q = 32'd0;
        addr_q = '0;
        wdata_q = '0;
        be_q = '0;
        write_q = 1'b0;
    end

    assign req_ready = !reset && !busy_q;
    assign rsp_valid = !reset && (phase_q == 2'd2);
    assign rdata = memory[addr_q[3:2]];
    assign error = (addr_q[3:2] == ERROR_REGISTER);
    assign last_addr = addr_q;
    assign last_wdata = wdata_q;
    assign last_be = be_q;
    assign last_write = write_q;
    assign request_count = count_q;

    always_ff @(posedge clk) begin
        logic [BE_WIDTH-1:0] lane;
        if (reset) begin
            phase_q <= 2'd0;
            busy_q <= 1'b0;
            count_q <= 32'd0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            write_q <= 1'b0;
        end else begin
            if (req_valid && req_ready) begin
                count_q <= count_q + 32'd1;
                busy_q <= 1'b1;
                phase_q <= 2'd1;
                addr_q <= addr;
                wdata_q <= wdata;
                be_q <= be;
                write_q <= write;
                if (write && (addr[3:2] != ERROR_REGISTER)) begin
                    for (lane = 0; lane < BE_WIDTH; lane = lane + 1) begin
                        if (be[lane])
                            memory[addr[3:2]][lane*8 +: 8] <= wdata[lane*8 +: 8];
                    end
                end
            end else if (phase_q == 2'd1) begin
                // The stall holds the target here forever: the response never
                // becomes valid, which is exactly the unresponsive target the
                // plan's declared wait bound has to turn into a timeout.
                if (!stall) phase_q <= 2'd2;
            end else if (phase_q == 2'd2) begin
                if (rsp_ready) begin
                    phase_q <= 2'd0;
                    busy_q <= 1'b0;
                end
            end
        end
    end
endmodule

// ---------------------------------------------------------------------------
// The harness itself.
// ---------------------------------------------------------------------------
module mmio_beat_harness_tb;
    localparam integer HALF = 5;
    localparam integer SCENARIO_CYCLES = 64;
    localparam integer HARNESS_MAX_CYCLES = 4000;

    logic clk = 1'b0;
    logic reset = 1'b1;
    integer cycles = 0;
    always #(HALF) clk = ~clk;

    integer failures = 0;
    integer waited = 0;
    integer width_requests_before = 0;

    task automatic check(input string key, input logic [63:0] expected,
                         input logic [63:0] observed);
        begin
            $display("MYFUZZ_HARNESS %s=%0d", key, observed);
            if (expected !== observed) begin
                failures = failures + 1;
                $display("MYFUZZ_HARNESS FAIL key=%s expected=%0d observed=%0d",
                         key, expected, observed);
            end
        end
    endtask

    // -- address narrower ---------------------------------------------------
    logic        n_req_valid, n_req_ready, n_write, n_rsp_valid, n_rsp_ready;
    logic        n_error, n_stale;
    logic [63:0] n_addr, n_wdata, n_rdata;
    logic [7:0]  n_be;
    logic        n_p_req_valid, n_p_req_ready, n_p_write;
    logic [31:0] n_p_addr, n_p_wdata, n_p_rdata;
    logic [3:0]  n_p_be;
    logic        n_p_rsp_valid, n_p_rsp_ready, n_p_error;
    logic [31:0] n_last_addr, n_last_wdata, n_count;
    logic [3:0]  n_last_be;

    localparam logic [63:0] NARROW_WINDOW_BASE = 64'h0000_0000_4000_0000;
    localparam integer      NARROW_WINDOW_SIZE = 4096;

    beat_address_narrow #(
        .ADDRESS_WIDTH(64),
        .NARROW_ADDRESS_WIDTH(32),
        .DATA_WIDTH(32),
        .WINDOW_BASE(NARROW_WINDOW_BASE),
        .WINDOW_SIZE(NARROW_WINDOW_SIZE)
    ) u_narrow (
        .clk(clk), .reset(reset),
        .req_valid(n_req_valid), .req_ready(n_req_ready), .write(n_write),
        .addr(n_addr), .wdata(n_wdata), .be(n_be),
        .rsp_valid(n_rsp_valid), .rsp_ready(n_rsp_ready),
        .rdata(n_rdata), .error(n_error),
        .p_req_valid(n_p_req_valid), .p_req_ready(n_p_req_ready), .p_write(n_p_write),
        .p_addr(n_p_addr), .p_wdata(n_p_wdata), .p_be(n_p_be),
        .p_rsp_valid(n_p_rsp_valid), .p_rsp_ready(n_p_rsp_ready),
        .p_rdata(n_p_rdata), .p_error(n_p_error),
        .stale_pending(n_stale)
    );

    harness_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_narrow_target (
        .clk(clk), .reset(reset), .stall(1'b0),
        .req_valid(n_p_req_valid), .req_ready(n_p_req_ready), .write(n_p_write),
        .addr(n_p_addr), .wdata(n_p_wdata), .be(n_p_be),
        .rsp_valid(n_p_rsp_valid), .rsp_ready(n_p_rsp_ready),
        .rdata(n_p_rdata), .error(n_p_error),
        .last_addr(n_last_addr), .last_wdata(n_last_wdata), .last_be(n_last_be),
        .last_write(), .request_count(n_count)
    );

    // -- width adapter ------------------------------------------------------
    logic        w_req_valid, w_req_ready, w_write, w_rsp_valid, w_rsp_ready;
    logic        w_error, w_stale;
    logic [63:0] w_addr, w_wdata, w_rdata;
    logic [7:0]  w_be;
    logic        w_p_req_valid, w_p_req_ready, w_p_write;
    logic [31:0] w_p_addr, w_p_wdata, w_p_rdata;
    logic [3:0]  w_p_be;
    logic        w_p_rsp_valid, w_p_rsp_ready, w_p_error;
    logic [31:0] w_last_addr, w_last_wdata, w_count;
    logic [3:0]  w_last_be;

    mmio_width_adapter #(
        .ADDRESS_WIDTH(32),
        .DATA_WIDTH(64),
        .PERIPHERAL_DATA_WIDTH(32),
        .ALLOW_SPANNING_WRITE_SPLIT(1'b0),
        .ALLOW_SPANNING_READ_ASSEMBLE(1'b0)
    ) u_width (
        .clk(clk), .reset(reset),
        .req_valid(w_req_valid), .req_ready(w_req_ready), .write(w_write),
        .addr(w_addr[31:0]), .wdata(w_wdata), .be(w_be),
        .rsp_valid(w_rsp_valid), .rsp_ready(w_rsp_ready),
        .rdata(w_rdata), .error(w_error),
        .p_req_valid(w_p_req_valid), .p_req_ready(w_p_req_ready),
        .p_write(w_p_write), .p_addr(w_p_addr), .p_wdata(w_p_wdata), .p_be(w_p_be),
        .p_rsp_valid(w_p_rsp_valid), .p_rsp_ready(w_p_rsp_ready),
        .p_rdata(w_p_rdata), .p_error(w_p_error),
        .stale_pending(w_stale)
    );

    harness_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_width_target (
        .clk(clk), .reset(reset), .stall(1'b0),
        .req_valid(w_p_req_valid), .req_ready(w_p_req_ready), .write(w_p_write),
        .addr(w_p_addr), .wdata(w_p_wdata), .be(w_p_be),
        .rsp_valid(w_p_rsp_valid), .rsp_ready(w_p_rsp_ready),
        .rdata(w_p_rdata), .error(w_p_error),
        .last_addr(w_last_addr), .last_wdata(w_last_wdata), .last_be(w_last_be),
        .last_write(), .request_count(w_count)
    );

    // -- bounded watchdog in front of a target that never answers -----------
    logic        b_req_valid, b_req_ready, b_write, b_rsp_valid, b_rsp_ready;
    logic        b_error, b_timed_out, b_drain;
    logic [31:0] b_addr, b_wdata, b_rdata, b_waited, b_timeouts;
    logic [3:0]  b_be;
    logic        b_p_req_valid, b_p_req_ready, b_p_write;
    logic [31:0] b_p_addr, b_p_wdata, b_p_rdata;
    logic [3:0]  b_p_be;
    logic        b_p_rsp_valid, b_p_rsp_ready, b_p_error;
    logic [31:0] b_count;

    beat_watchdog #(
        .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(16)
    ) u_watchdog_bounded (
        .clk(clk), .reset(reset),
        .req_valid(b_req_valid), .req_ready(b_req_ready), .write(b_write),
        .addr(b_addr), .wdata(b_wdata), .be(b_be),
        .rsp_valid(b_rsp_valid), .rsp_ready(b_rsp_ready),
        .rdata(b_rdata), .error(b_error),
        .p_req_valid(b_p_req_valid), .p_req_ready(b_p_req_ready), .p_write(b_p_write),
        .p_addr(b_p_addr), .p_wdata(b_p_wdata), .p_be(b_p_be),
        .p_rsp_valid(b_p_rsp_valid), .p_rsp_ready(b_p_rsp_ready),
        .p_rdata(b_p_rdata), .p_error(b_p_error),
        .timed_out(b_timed_out), .waited_cycles(b_waited),
        .timeout_count(b_timeouts), .drain_pending(b_drain)
    );

    harness_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_stalled_target (
        .clk(clk), .reset(reset), .stall(1'b1),
        .req_valid(b_p_req_valid), .req_ready(b_p_req_ready), .write(b_p_write),
        .addr(b_p_addr), .wdata(b_p_wdata), .be(b_p_be),
        .rsp_valid(b_p_rsp_valid), .rsp_ready(b_p_rsp_ready),
        .rdata(b_p_rdata), .error(b_p_error),
        .last_addr(), .last_wdata(), .last_be(), .last_write(),
        .request_count(b_count)
    );

    // -- unbounded watchdog (bound disabled) in front of a responsive target -
    logic        u_req_valid, u_req_ready, u_write, u_rsp_valid, u_rsp_ready;
    logic        u_error, u_timed_out, u_drain;
    logic [31:0] u_addr, u_wdata, u_rdata, u_waited, u_timeouts;
    logic [3:0]  u_be;
    logic        u_p_req_valid, u_p_req_ready, u_p_write;
    logic [31:0] u_p_addr, u_p_wdata, u_p_rdata;
    logic [3:0]  u_p_be;
    logic        u_p_rsp_valid, u_p_rsp_ready, u_p_error;
    logic [31:0] u_count;

    beat_watchdog #(
        .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(0)
    ) u_watchdog_unbounded (
        .clk(clk), .reset(reset),
        .req_valid(u_req_valid), .req_ready(u_req_ready), .write(u_write),
        .addr(u_addr), .wdata(u_wdata), .be(u_be),
        .rsp_valid(u_rsp_valid), .rsp_ready(u_rsp_ready),
        .rdata(u_rdata), .error(u_error),
        .p_req_valid(u_p_req_valid), .p_req_ready(u_p_req_ready), .p_write(u_p_write),
        .p_addr(u_p_addr), .p_wdata(u_p_wdata), .p_be(u_p_be),
        .p_rsp_valid(u_p_rsp_valid), .p_rsp_ready(u_p_rsp_ready),
        .p_rdata(u_p_rdata), .p_error(u_p_error),
        .timed_out(u_timed_out), .waited_cycles(u_waited),
        .timeout_count(u_timeouts), .drain_pending(u_drain)
    );

    harness_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_responsive_target (
        .clk(clk), .reset(reset), .stall(1'b0),
        .req_valid(u_p_req_valid), .req_ready(u_p_req_ready), .write(u_p_write),
        .addr(u_p_addr), .wdata(u_p_wdata), .be(u_p_be),
        .rsp_valid(u_p_rsp_valid), .rsp_ready(u_p_rsp_ready),
        .rdata(u_p_rdata), .error(u_p_error),
        .last_addr(), .last_wdata(), .last_be(), .last_write(),
        .request_count(u_count)
    );

    // -- unbounded watchdog in front of a target that never answers ---------
    // This is the pair the ``+unbounded_stall`` run uses: with the bound
    // disabled nothing can complete the transaction, so only the harness's own
    // cycle bound ends the simulation.
    logic        s_req_valid, s_req_ready, s_write, s_rsp_valid, s_rsp_ready;
    logic        s_error, s_timed_out, s_drain;
    logic [31:0] s_addr, s_wdata, s_rdata, s_waited, s_timeouts;
    logic [3:0]  s_be;
    logic        s_p_req_valid, s_p_req_ready, s_p_write;
    logic [31:0] s_p_addr, s_p_wdata, s_p_rdata;
    logic [3:0]  s_p_be;
    logic        s_p_rsp_valid, s_p_rsp_ready, s_p_error;
    logic [31:0] s_count;

    beat_watchdog #(
        .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .MAX_WAIT_CYCLES(0)
    ) u_watchdog_unbounded_stall (
        .clk(clk), .reset(reset),
        .req_valid(s_req_valid), .req_ready(s_req_ready), .write(s_write),
        .addr(s_addr), .wdata(s_wdata), .be(s_be),
        .rsp_valid(s_rsp_valid), .rsp_ready(s_rsp_ready),
        .rdata(s_rdata), .error(s_error),
        .p_req_valid(s_p_req_valid), .p_req_ready(s_p_req_ready), .p_write(s_p_write),
        .p_addr(s_p_addr), .p_wdata(s_p_wdata), .p_be(s_p_be),
        .p_rsp_valid(s_p_rsp_valid), .p_rsp_ready(s_p_rsp_ready),
        .p_rdata(s_p_rdata), .p_error(s_p_error),
        .timed_out(s_timed_out), .waited_cycles(s_waited),
        .timeout_count(s_timeouts), .drain_pending(s_drain)
    );

    harness_target #(.ADDRESS_WIDTH(32), .DATA_WIDTH(32)) u_stalled_forever (
        .clk(clk), .reset(reset), .stall(1'b1),
        .req_valid(s_p_req_valid), .req_ready(s_p_req_ready), .write(s_p_write),
        .addr(s_p_addr), .wdata(s_p_wdata), .be(s_p_be),
        .rsp_valid(s_p_rsp_valid), .rsp_ready(s_p_rsp_ready),
        .rdata(s_p_rdata), .error(s_p_error),
        .last_addr(), .last_wdata(), .last_be(), .last_write(),
        .request_count(s_count)
    );

    // -- transaction helpers ------------------------------------------------
    logic [63:0] got_rdata;
    logic        got_error;

    // NOTE 1: these tasks deliberately avoid ``disable <task>;``.  Verilator
    // 5.051 mis-parses an ANSI task header once the body contains a disable
    // statement (it then reports "too many arguments" at every call site), so
    // the early exit is written as an if/else instead.
    //
    // NOTE 2: every driven signal changes on a NEGEDGE and is sampled on a
    // POSEDGE.  Driving at a posedge races the DUT's own edge-triggered logic
    // in Verilator, which silently dropped the first request of every scenario.
    task automatic do_narrow(input logic [63:0] address, input logic wr,
                             input logic [63:0] wd, input logic [7:0] byte_enable);
        logic accepted, responded;
        begin
            @(negedge clk);
            n_addr = address;
            n_write = wr;
            n_wdata = wd;
            n_be = byte_enable[3:0];
            n_rsp_ready = 1'b1;
            n_req_valid = 1'b1;
            accepted = 1'b0;
            waited = 0;
            while (!accepted && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (n_req_ready) accepted = 1'b1;
                else waited = waited + 1;
            end
            @(negedge clk);
            n_req_valid = 1'b0;
            responded = 1'b0;
            waited = 0;
            while (!responded && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (n_rsp_valid) responded = 1'b1;
                else waited = waited + 1;
            end
            if (!accepted || !responded) begin
                failures = failures + 1;
                $display("MYFUZZ_HARNESS FAIL key=narrow-timeout accepted=%0d responded=%0d",
                         accepted, responded);
                n_rsp_ready = 1'b0;
                got_rdata = '0;
                got_error = 1'b1;
            end else begin
                got_rdata = n_rdata;
                got_error = n_error;
                @(negedge clk);
                n_rsp_ready = 1'b0;
                repeat (2) @(posedge clk);
            end
        end
    endtask

    task automatic do_width(input logic [31:0] address, input logic wr,
                            input logic [63:0] wd, input logic [7:0] byte_enable);
        logic accepted, responded;
        begin
            @(negedge clk);
            w_addr = {32'b0, address};
            w_write = wr;
            w_wdata = wd;
            w_be = byte_enable;
            w_rsp_ready = 1'b1;
            w_req_valid = 1'b1;
            accepted = 1'b0;
            waited = 0;
            while (!accepted && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (w_req_ready) accepted = 1'b1;
                else waited = waited + 1;
            end
            @(negedge clk);
            w_req_valid = 1'b0;
            responded = 1'b0;
            waited = 0;
            while (!responded && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (w_rsp_valid) responded = 1'b1;
                else waited = waited + 1;
            end
            if (!accepted || !responded) begin
                failures = failures + 1;
                $display("MYFUZZ_HARNESS FAIL key=width-timeout accepted=%0d responded=%0d",
                         accepted, responded);
                w_rsp_ready = 1'b0;
                got_rdata = '0;
                got_error = 1'b1;
            end else begin
                got_rdata = w_rdata;
                got_error = w_error;
                @(negedge clk);
                w_rsp_ready = 1'b0;
                repeat (2) @(posedge clk);
            end
        end
    endtask

    task automatic do_watchdog_bounded();
        logic accepted, responded;
        begin
            @(negedge clk);
            b_addr = 32'h0000_0000;
            b_write = 1'b0;
            b_wdata = '0;
            b_be = 4'hF;
            b_rsp_ready = 1'b1;
            b_req_valid = 1'b1;
            accepted = 1'b0;
            waited = 0;
            while (!accepted && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (b_req_ready) accepted = 1'b1;
                else waited = waited + 1;
            end
            @(negedge clk);
            b_req_valid = 1'b0;
            responded = 1'b0;
            waited = 0;
            while (!responded && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (b_rsp_valid) responded = 1'b1;
                else waited = waited + 1;
            end
            if (!accepted || !responded) begin
                failures = failures + 1;
                $display("MYFUZZ_HARNESS FAIL key=watchdog-bounded-never-completed accepted=%0d responded=%0d", accepted, responded);
            end else begin
                check("watchdog.bounded.completed", 1, 1);
                check("watchdog.bounded.error", 1, b_error);
                check("watchdog.bounded.rdata", 0, b_rdata);
                check("watchdog.bounded.timed_out", 1, b_timed_out);
                check("watchdog.bounded.waited_cycles", 16, b_waited);
                check("watchdog.bounded.timeout_count", 1, b_timeouts);
                check("watchdog.bounded.target_requests", 1, b_count);
                @(negedge clk);
                b_rsp_ready = 1'b0;
                check("watchdog.bounded.drain_pending", 1, b_drain);
            end
        end
    endtask

    task automatic do_watchdog_passthrough();
        logic accepted, responded;
        begin
            @(negedge clk);
            u_addr = 32'h0000_0004;
            u_write = 1'b0;
            u_wdata = '0;
            u_be = 4'hF;
            u_rsp_ready = 1'b1;
            u_req_valid = 1'b1;
            accepted = 1'b0;
            waited = 0;
            while (!accepted && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (u_req_ready) accepted = 1'b1;
                else waited = waited + 1;
            end
            @(negedge clk);
            u_req_valid = 1'b0;
            responded = 1'b0;
            waited = 0;
            while (!responded && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                if (u_rsp_valid) responded = 1'b1;
                else waited = waited + 1;
            end
            if (!accepted || !responded) begin
                failures = failures + 1;
                $display("MYFUZZ_HARNESS FAIL key=watchdog-passthrough-never-completed accepted=%0d responded=%0d", accepted, responded);
            end else begin
                check("watchdog.unbounded.completed", 1, 1);
                check("watchdog.unbounded.error", 0, u_error);
                check("watchdog.unbounded.rdata", 32'h2222_0001, u_rdata);
                check("watchdog.unbounded.timed_out", 0, u_timed_out);
                check("watchdog.unbounded.timeout_count", 0, u_timeouts);
                check("watchdog.unbounded.target_requests", 1, u_count);
                check("watchdog.unbounded.waited_cycles_nonzero", 1, (u_waited != 0));
                @(negedge clk);
                u_rsp_ready = 1'b0;
            end
        end
    endtask

    // -- scenarios ----------------------------------------------------------
    initial begin
        n_req_valid = 1'b0; n_rsp_ready = 1'b0; n_write = 1'b0;
        n_addr = '0; n_wdata = '0; n_be = '0;
        w_req_valid = 1'b0; w_rsp_ready = 1'b0; w_write = 1'b0;
        w_addr = '0; w_wdata = '0; w_be = '0;
        b_req_valid = 1'b0; b_rsp_ready = 1'b0; b_write = 1'b0;
        b_addr = '0; b_wdata = '0; b_be = '0;
        u_req_valid = 1'b0; u_rsp_ready = 1'b0; u_write = 1'b0;
        u_addr = '0; u_wdata = '0; u_be = '0;
        s_req_valid = 1'b0; s_rsp_ready = 1'b0; s_write = 1'b0;
        s_addr = '0; s_wdata = '0; s_be = '0;

        reset = 1'b1;
        repeat (4) @(posedge clk);
        reset = 1'b0;
        repeat (2) @(posedge clk);

        // The configuration this run really used, so a test can compare it with
        // the plan's own narrowing record instead of trusting the source text.
        $display("MYFUZZ_HARNESS narrow.address_width=%0d", 64);
        $display("MYFUZZ_HARNESS narrow.narrow_address_width=%0d", 32);
        $display("MYFUZZ_HARNESS narrow.window_base=%0d", NARROW_WINDOW_BASE);
        $display("MYFUZZ_HARNESS narrow.window_size=%0d", NARROW_WINDOW_SIZE);
        $display("MYFUZZ_HARNESS width.data_width=%0d", 64);
        $display("MYFUZZ_HARNESS width.peripheral_data_width=%0d", 32);
        $display("MYFUZZ_HARNESS watchdog.max_wait_cycles=%0d", 16);
        $display("MYFUZZ_HARNESS watchdog.stalled.max_wait_cycles=%0d", 0);

        // -- address narrowing: the plan's proven, lossless window ---------
        do_narrow(NARROW_WINDOW_BASE + 64'h4, 1'b0, '0, 4'hF);
        check("narrow.in_window.error", 0, got_error);
        check("narrow.in_window.rdata", 64'h2222_0001, got_rdata);
        check("narrow.in_window.target_requests", 1, n_count);
        check("narrow.in_window.target_saw_absolute_address", 64'h4000_0004, n_last_addr);
        // An out-of-window address whose low 32 bits alias into the window is
        // refused locally: error, zero data, and no downstream request at all.
        do_narrow(64'h1_0000_0004, 1'b0, '0, 4'hF);
        check("narrow.alias.error", 1, got_error);
        check("narrow.alias.rdata", 0, got_rdata);
        check("narrow.alias.target_requests_unchanged", 1, n_count);
        do_narrow(64'h1_0000_0004, 1'b1, 64'hDEAD_BEEF, 4'hF);
        check("narrow.alias_write.error", 1, got_error);
        check("narrow.alias_write.target_requests_unchanged", 1, n_count);
        // Control: the same store inside the window does reach the target.
        do_narrow(NARROW_WINDOW_BASE + 64'h0, 1'b1, 64'h0000_0000_CAFE_0000, 4'hF);
        check("narrow.in_window_write.error", 0, got_error);
        check("narrow.in_window_write.target_requests", 2, n_count);
        check("narrow.in_window_write.target_be", 4'hF, n_last_be);
        do_narrow(NARROW_WINDOW_BASE + 64'h0, 1'b0, '0, 4'hF);
        check("narrow.in_window_write.readback", 32'hCAFE_0000, got_rdata[31:0]);

        // -- width conversion: 64-bit beat against a 32-bit peripheral -----
        do_width(32'h0000_0000, 1'b0, '0, 8'h0F);
        check("width.low_lane.error", 0, got_error);
        check("width.low_lane.rdata_low", 32'h1111_0000, got_rdata[31:0]);
        check("width.low_lane.rdata_high", 0, got_rdata[63:32]);
        check("width.low_lane.peripheral_addr", 32'h0000_0000, w_last_addr);
        do_width(32'h0000_0004, 1'b0, '0, 8'hF0);
        check("width.high_lane.error", 0, got_error);
        check("width.high_lane.rdata_high", 32'h2222_0001, got_rdata[63:32]);
        check("width.high_lane.rdata_low", 0, got_rdata[31:0]);
        check("width.high_lane.peripheral_addr", 32'h0000_0004, w_last_addr);
        // A high-lane write drives the peripheral word with the beat's high
        // half and its own low byte enables, at the unchanged peripheral
        // address (whose bit 2 selects the register).
        do_width(32'h0000_0004, 1'b1, 64'h1234_5678_9ABC_DEF0, 8'hF0);
        check("width.high_lane_write.error", 0, got_error);
        check("width.high_lane_write.peripheral_wdata", 32'h1234_5678, w_last_wdata);
        check("width.high_lane_write.peripheral_be", 4'hF, w_last_be);
        check("width.high_lane_write.peripheral_addr_bit2", 1, w_last_addr[2]);
        // The peripheral word comes back in the lane it was addressed in.
        do_width(32'h0000_0004, 1'b0, '0, 8'hF0);
        check("width.high_lane_write.readback", 32'h1234_5678, got_rdata[63:32]);
        check("width.high_lane_write.readback_low", 0, got_rdata[31:0]);
        // One enabled byte in the high half is a partial write of the
        // peripheral word, not a whole-word overwrite.
        do_width(32'h0000_0004, 1'b1, 64'h0000_0055_0000_0000, 8'h10);
        check("width.partial_high_byte.peripheral_be", 4'h1, w_last_be);
        check("width.partial_high_byte.peripheral_wdata", 32'h0000_0055, w_last_wdata);
        do_width(32'h0000_0004, 1'b0, '0, 8'hF0);
        check("width.partial_high_byte.readback", 32'h1234_5655, got_rdata[63:32]);
        // Negative cases: every refused access must leave the peripheral alone,
        // which is checked against the target's own request counter.
        width_requests_before = w_count;
        do_width(32'h0000_0000, 1'b0, '0, 8'h00);
        check("width.no_byte_enable.error", 1, got_error);
        check("width.no_byte_enable.rdata", 0, got_rdata);
        check("width.no_byte_enable.no_downstream_request", width_requests_before, w_count);
        do_width(32'h0000_0000, 1'b1, 64'hFFFF_FFFF_FFFF_FFFF, 8'hF0);
        check("width.lane_mismatch.error", 1, got_error);
        check("width.lane_mismatch.no_downstream_request", width_requests_before, w_count);
        do_width(32'h0000_0000, 1'b1, 64'hFFFF_FFFF_FFFF_FFFF, 8'hFF);
        check("width.spanning_write.error", 1, got_error);
        check("width.spanning_write.no_downstream_request", width_requests_before, w_count);
        // The control: the same lane and enable set against the peripheral's
        // error register does reach it, and its error response is reported.
        do_width(32'h0000_000C, 1'b0, '0, 8'hF0);
        check("width.peripheral_error.error", 1, got_error);
        check("width.peripheral_error.rdata", 0, got_rdata);
        check("width.peripheral_error.downstream_request", width_requests_before + 1,
              w_count);

        // -- the wait bound -------------------------------------------------
        // Bounded watchdog in front of a target that never answers: the declared
        // bound must expire, the transaction must still complete exactly once
        // with error = 1, and the evidence outputs must say so.
        do_watchdog_bounded();
        // The unbounded configuration in front of a responsive target is a
        // pass-through: no timeout, the target's own data, its real wait.
        do_watchdog_passthrough();
        // Deliberately unbounded against a stalled target, driven by the
        // ``+unbounded_stall`` plusarg: nothing here waits for a response, so
        // only the harness's own cycle bound can report the timeout.
        if ($test$plusargs("unbounded_stall")) begin
            @(negedge clk);
            s_addr = 32'h0000_0000;
            s_write = 1'b0;
            s_wdata = '0;
            s_be = 4'hF;
            s_rsp_ready = 1'b1;
            s_req_valid = 1'b1;
            waited = 0;
            while (!s_req_ready && waited <= SCENARIO_CYCLES) begin
                @(posedge clk);
                waited = waited + 1;
            end
            @(negedge clk);
            s_req_valid = 1'b0;
            forever @(posedge clk);
        end

        if (failures != 0)
            $display("MYFUZZ_HARNESS_RUN status=FAIL reason=%0d-checks-failed", failures);
        else
            $display("MYFUZZ_HARNESS_RUN status=OK reason=self-check-passed");
        $finish;
    end

    // The outer bound.  The ``+unbounded_stall`` run is the unbounded case: the
    // bound is disabled and the target never answers, so only the harness's own
    // cycle bound can stop the simulation.  The Python test runs the binary
    // twice -- with and without the plusarg -- so the two configurations cannot
    // be confused.
    logic stalled_unbounded = 1'b0;
    integer unbounded_cycles = 0;
    initial begin
        if ($test$plusargs("unbounded_stall")) stalled_unbounded = 1'b1;
    end

    // The outer bound.  This is the testbench-enforced limit that makes an
    // unresponsive target a reported timeout instead of a hang; it is not a
    // host-side sleep.
    initial begin
        for (cycles = 0; cycles < HARNESS_MAX_CYCLES; cycles = cycles + 1) begin
            @(posedge clk);
            if (stalled_unbounded) begin
                // Count from the cycle the stalled target really accepted the
                // request, so the report names a request that was issued and
                // never answered rather than one that never started.
                if (s_count != 32'd0) unbounded_cycles = unbounded_cycles + 1;
                if (unbounded_cycles > 40) begin
                    $display("MYFUZZ_HARNESS unbounded_stall.rsp_valid=%0d", s_rsp_valid);
                    $display("MYFUZZ_HARNESS unbounded_stall.timed_out=%0d", s_timed_out);
                    $display("MYFUZZ_HARNESS unbounded_stall.timeout_count=%0d", s_timeouts);
                    $display("MYFUZZ_HARNESS unbounded_stall.target_requests=%0d", s_count);
                    $display("MYFUZZ_HARNESS_RUN status=TIMEOUT reason=unbounded-target-never-completed-at-harness-cycle-bound");
                    $finish;
                end
            end
        end
        if (!stalled_unbounded)
            $display("MYFUZZ_HARNESS_RUN status=TIMEOUT reason=harness-cycle-bound-exceeded");
        $finish;
    end
endmodule
