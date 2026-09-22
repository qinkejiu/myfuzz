// beat_watchdog: the RTL bound behind the plan's declared ``max_wait_cycles``.
//
// WHY THIS BLOCK EXISTS
//   The composition plan publishes a watchdog record for every fabric it
//   builds: ``{"enforcement": "external_runtime_watchdog", "max_wait_cycles":
//   N, "on_expiry": "terminate_test_without_transaction_id_reuse",
//   "rtl_enforced": false}``.  The bound is a declared fact (the targets'
//   ``capabilities.max_wait_cycles``), but nothing in the fabric enforced it:
//   a target that never asserts its response left the transaction open, and
//   only a Python-level subprocess timeout (or the generated testbench's fixed
//   cycle count) ended the run.  A Python sleep is not evidence about the DUT.
//
//   This block is that bound in RTL.  It sits on a beat-contract link, counts
//   the cycles a target takes to answer a request it accepted, and on expiry
//   answers the *initiator* with ``error = 1``, ``rdata = 0`` and a recorded
//   timeout instead of waiting forever.  It never invents a response for a
//   transaction the target already completed and it never reuses a transaction
//   id: a late response from the target is drained and discarded.
//
// Beat contract (identical to the P5 target adapters): clk, reset, req_valid,
// req_ready, write, addr, wdata, be, rsp_valid, rsp_ready, rdata, error.  The
// upstream side uses the bare names, the downstream side the same names with a
// ``p_`` prefix.  "reset" is synchronous and active high.
//
// Parameters
//   MAX_WAIT_CYCLES = 0 : no bound at all.  The block is then a pass-through
//                         that only counts the wait, which is what makes the
//                         difference between "bounded" and "unbounded"
//                         measurable in one harness.
//   FAIL_CLOSED     = 1 : on expiry the initiator is answered locally with
//                         error = 1 and zero read data (the transaction still
//                         completes exactly once, so a caller waiting on
//                         rsp_valid cannot hang).
//
// Evidence outputs (observations only, they never drive the bus):
//   timed_out       : high from the expiry until the local response is accepted
//   waited_cycles   : the cycles the last completed transaction really waited
//   timeout_count   : how many transactions expired
//   drain_pending   : a late target response is still owed and will be dropped

module beat_watchdog #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    // Zero disables the bound; any positive value is the enforced wait bound.
    parameter integer MAX_WAIT_CYCLES = 0,
    parameter bit     FAIL_CLOSED = 1'b1
) (
    input  logic                       clk,
    input  logic                       reset,

    // Upstream (initiator) side: bare beat contract.
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

    // Downstream (target) side: the same contract with a p_ prefix.
    output logic                       p_req_valid,
    input  logic                       p_req_ready,
    output logic                       p_write,
    output logic [ADDRESS_WIDTH-1:0]   p_addr,
    output logic [DATA_WIDTH-1:0]      p_wdata,
    output logic [(DATA_WIDTH/8)-1:0]  p_be,
    input  logic                       p_rsp_valid,
    output logic                       p_rsp_ready,
    input  logic [DATA_WIDTH-1:0]      p_rdata,
    input  logic                       p_error,

    // Evidence.
    output logic                       timed_out,
    output logic [31:0]                waited_cycles,
    output logic [31:0]                timeout_count,
    output logic                       drain_pending
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;

    initial begin
        if (DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "beat_watchdog: DATA_WIDTH must be a whole number of bytes");
        if (MAX_WAIT_CYCLES < 0)
            $fatal(1, "beat_watchdog: MAX_WAIT_CYCLES cannot be negative (0 disables the bound)");
    end

    typedef enum logic [1:0] {IDLE, WAIT_RSP, RESPOND} state_t;
    // Explicit initial values: neither the drain flag nor the state may start
    // as X, otherwise the first reset edge would leave req_ready undefined.
    state_t state_q = IDLE;
    logic drain_q = 1'b0;

    logic write_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BE_WIDTH-1:0] be_q;
    logic [DATA_WIDTH-1:0] rdata_q;
    logic error_q, expired_q;
    logic [31:0] waited_q, last_waited_q, timeout_count_q;

    assign req_ready = !reset && !drain_q && (state_q == IDLE);
    assign rsp_valid = !reset && (state_q == RESPOND);
    assign rdata = rdata_q;
    assign error = error_q;
    assign timed_out = expired_q;
    assign waited_cycles = last_waited_q;
    assign timeout_count = timeout_count_q;
    assign drain_pending = drain_q;

    always_comb begin
        // The request is forwarded combinationally and latched by the target on
        // the same edge the initiator sees req_ready, so no accepted request can
        // be lost.  Once accepted, only the response path is live.
        p_req_valid = 1'b0;
        p_write = 1'b0;
        p_addr = '0;
        p_wdata = '0;
        p_be = '0;
        p_rsp_ready = 1'b0;
        if (!reset) begin
            if (state_q == IDLE && !drain_q) begin
                p_req_valid = req_valid;
                p_write = write;
                p_addr = addr;
                p_wdata = wdata;
                p_be = be;
            end else if (state_q == WAIT_RSP) begin
                p_rsp_ready = 1'b1;
            end else if (drain_q) begin
                // A late response is owed: accept and discard it before any new
                // transaction is accepted, so it cannot be attributed to one.
                p_rsp_ready = 1'b1;
            end
        end
    end

    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE;
            write_q <= 1'b0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            rdata_q <= '0;
            error_q <= 1'b0;
            expired_q <= 1'b0;
            waited_q <= 32'd0;
            last_waited_q <= 32'd0;
            timeout_count_q <= 32'd0;
            if (state_q == WAIT_RSP) drain_q <= 1'b1;
            else drain_q <= 1'b0;
        end else begin
            if (drain_q && p_rsp_valid) drain_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    if (req_valid && req_ready && p_req_ready) begin
                        write_q <= write;
                        addr_q <= addr;
                        wdata_q <= wdata;
                        be_q <= be;
                        rdata_q <= '0;
                        error_q <= 1'b0;
                        expired_q <= 1'b0;
                        waited_q <= 32'd0;
                        state_q <= WAIT_RSP;
                    end
                end
                WAIT_RSP: begin
                    if (p_rsp_valid) begin
                        rdata_q <= p_rdata;
                        error_q <= p_error;
                        last_waited_q <= waited_q;
                        expired_q <= 1'b0;
                        state_q <= RESPOND;
                    end else begin
                        waited_q <= waited_q + 32'd1;
                        if ((MAX_WAIT_CYCLES != 0) && (waited_q + 32'd1 >= MAX_WAIT_CYCLES)) begin
                            // The declared bound expired: complete the
                            // transaction locally instead of waiting forever,
                            // keep the id unavailable until the target's own
                            // response (if it ever comes) has been drained.
                            rdata_q <= '0;
                            error_q <= FAIL_CLOSED;
                            expired_q <= 1'b1;
                            last_waited_q <= waited_q + 32'd1;
                            timeout_count_q <= timeout_count_q + 32'd1;
                            drain_q <= 1'b1;
                            state_q <= RESPOND;
                        end
                    end
                end
                RESPOND: begin
                    if (rsp_ready) begin
                        expired_q <= 1'b0;
                        state_q <= IDLE;
                    end
                end
                default: state_q <= IDLE;
            endcase
        end
    end
endmodule
