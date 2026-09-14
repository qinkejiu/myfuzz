// soc_router: decode one outstanding beat transaction onto exactly one target.
//
// Beat contract on both sides (identical to the P5 target adapters):
//   clk, reset, req_valid, req_ready, write, addr, wdata, be,
//   rsp_valid, rsp_ready, rdata, error
// "reset" is synchronous and active high.
//
// The request side is the target port of soc_arbiter; it additionally carries
// the accepted "source_id", a "transaction_id" and an "instr" sideband.  The
// response side echoes source_id/transaction_id so the arbiter can attribute
// the completion.
//
// The address is decoded against a parameterisable window table
// (base, size, target index, executable/readable/writable policy per window).
// Icarus Verilog has no array parameters, so the table is passed as packed
// vectors whose element 0 (the least significant slice) is window 0; a window
// is active only when its index is below NUM_WINDOWS.
//
// Every one of the following produces an error response WITHOUT asserting any
// target select/strobe:
//   * an address that matches no window (unmapped is an explicit error),
//   * an access that starts inside a window but whose enabled bytes extend
//     past the end of that window (out of range / cross region),
//   * a write/read/instruction fetch that the matched window policy forbids
//     (for example an instruction fetch to a non-executable MMIO window),
//   * an access with no byte enables.
//
// Reset discipline: when reset terminates a transaction that was already
// accepted by a target, the router enters a drain state.  It does not accept
// any new transaction (req_ready stays low) and does not forward any response
// until the late response of the abandoned transaction has been consumed and
// discarded, so the same target-side transaction identity is never reused
// while a late response may still arrive.  stale_pending exposes that state to
// the harness; if the target never answers, the fabric prefers stopping over
// reusing the identity (a timeout cannot safely cancel a real side effect).

module soc_router #(
    // Set only when reset also resets every downstream target and adapter.
    // A local reset must retain quarantine for any possible late response.
    parameter bit RESET_CLEARS_TARGETS = 1'b0,
    parameter integer NUM_TARGETS = 2,
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SOURCE_ID_WIDTH = 1,
    parameter integer NUM_SOURCES = (1 << SOURCE_ID_WIDTH),
    parameter integer TRANSACTION_ID_WIDTH = 8,
    parameter integer TARGET_ID_WIDTH = (NUM_TARGETS <= 1) ? 1 : $clog2(NUM_TARGETS),
    parameter integer MAX_WINDOWS = 8,
    parameter integer NUM_WINDOWS = 1,
    parameter logic [MAX_WINDOWS*ADDRESS_WIDTH-1:0] WINDOW_BASE = {(MAX_WINDOWS*ADDRESS_WIDTH){1'b0}},
    parameter logic [MAX_WINDOWS*ADDRESS_WIDTH-1:0] WINDOW_TARGET_BASE = WINDOW_BASE,
    parameter logic [MAX_WINDOWS*ADDRESS_WIDTH-1:0] WINDOW_SIZE = {(MAX_WINDOWS*ADDRESS_WIDTH){1'b0}},
    parameter logic [MAX_WINDOWS*TARGET_ID_WIDTH-1:0] WINDOW_TARGET = {(MAX_WINDOWS*TARGET_ID_WIDTH){1'b0}},
    parameter logic [MAX_WINDOWS-1:0] WINDOW_EXECUTABLE = {(MAX_WINDOWS){1'b0}},
    parameter logic [MAX_WINDOWS-1:0] WINDOW_READABLE = {(MAX_WINDOWS){1'b1}},
    parameter logic [MAX_WINDOWS-1:0] WINDOW_WRITABLE = {(MAX_WINDOWS){1'b1}},
    parameter logic [MAX_WINDOWS*NUM_SOURCES-1:0] WINDOW_SOURCE_MASK =
        {(MAX_WINDOWS*NUM_SOURCES){1'b1}}
) (
    input  logic clk,
    input  logic reset,

    input  logic                                req_valid,
    output logic                                req_ready,
    input  logic                                write,
    input  logic [ADDRESS_WIDTH-1:0]            addr,
    input  logic [DATA_WIDTH-1:0]               wdata,
    input  logic [(DATA_WIDTH/8)-1:0]           be,
    input  logic                                instr,
    input  logic [SOURCE_ID_WIDTH-1:0]          source_id,
    input  logic [TRANSACTION_ID_WIDTH-1:0]     transaction_id,

    output logic                                rsp_valid,
    input  logic                                rsp_ready,
    output logic [DATA_WIDTH-1:0]               rdata,
    output logic                                error,
    output logic [SOURCE_ID_WIDTH-1:0]          rsp_source_id,
    output logic [TRANSACTION_ID_WIDTH-1:0]     rsp_transaction_id,

    output logic [NUM_TARGETS-1:0]                       t_req_valid,
    input  logic [NUM_TARGETS-1:0]                       t_req_ready,
    output logic [NUM_TARGETS-1:0]                       t_write,
    output logic [NUM_TARGETS-1:0][ADDRESS_WIDTH-1:0]    t_addr,
    output logic [NUM_TARGETS-1:0][DATA_WIDTH-1:0]       t_wdata,
    output logic [NUM_TARGETS-1:0][(DATA_WIDTH/8)-1:0]   t_be,
    input  logic [NUM_TARGETS-1:0]                       t_rsp_valid,
    output logic [NUM_TARGETS-1:0]                       t_rsp_ready,
    input  logic [NUM_TARGETS-1:0][DATA_WIDTH-1:0]       t_rdata,
    input  logic [NUM_TARGETS-1:0]                       t_error,

    output logic [TARGET_ID_WIDTH-1:0]          selected_target,
    output logic                                stale_pending
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;
    //: Byte lanes of one beat container: the low bits of the address that the
    //: beat's byte enables are relative to.
    localparam logic [ADDRESS_WIDTH-1:0] BEAT_LANE_MASK = ADDRESS_WIDTH'(BE_WIDTH - 1);

    initial begin
        if (NUM_TARGETS < 1 || ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "invalid soc_router width parameters");
        if (MAX_WINDOWS < 1 || NUM_WINDOWS < 0 || NUM_WINDOWS > MAX_WINDOWS)
            $fatal(1, "invalid soc_router window count");
        if (TARGET_ID_WIDTH < 1 || NUM_TARGETS > (1 << TARGET_ID_WIDTH))
            $fatal(1, "TARGET_ID_WIDTH cannot index NUM_TARGETS");
        if (NUM_SOURCES < 1 || NUM_SOURCES > (1 << SOURCE_ID_WIDTH))
            $fatal(1, "SOURCE_ID_WIDTH cannot index NUM_SOURCES");
    end

    typedef enum logic [2:0] {IDLE, SELECT, WAIT_RSP, CAPTURE_RSP, RESPOND} state_t;
    // Explicit initial values: the drain flag must never start as X, otherwise
    // the first reset edge (when state_q is still X) would leave req_ready
    // undefined.
    state_t state_q = IDLE;
    logic stale_q = 1'b0;

    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q, rdata_q;
    logic [BE_WIDTH-1:0] be_q;
    logic write_q, instr_q, error_q;
    logic [SOURCE_ID_WIDTH-1:0] source_q;
    logic [TRANSACTION_ID_WIDTH-1:0] txid_q;
    logic [TARGET_ID_WIDTH-1:0] target_q, decode_target;
    logic [ADDRESS_WIDTH-1:0] decode_target_addr;
    logic decode_hit, decode_error;
    logic [ADDRESS_WIDTH:0] access_last;
    logic [TARGET_ID_WIDTH-1:0] stale_target_q = '0;

    assign req_ready = !reset && !stale_q && (state_q == IDLE);
    assign selected_target = target_q;
    assign stale_pending = stale_q;

    // Window decode of the request presented in the accept cycle.  The request
    // fields are held stable by the arbiter until the transaction completes,
    // and the decision (target_q/error_q) is latched with the transaction, so
    // the target never changes while the response is pending.  The lowest
    // matching window wins; the SoC contract forbids overlapping windows.
    always_comb begin
        decode_hit = 1'b0;
        decode_target = '0;
        decode_target_addr = addr;
        decode_error = 1'b1;
        access_last = '0;
        if (be != '0) begin
            logic [ADDRESS_WIDTH-1:0] last_offset;
            logic [ADDRESS_WIDTH-1:0] beat_base;
            last_offset = '0;
            for (int unsigned b = 0; b < BE_WIDTH; b++)
                if (be[b]) last_offset = b[ADDRESS_WIDTH-1:0];
            // be is a lane index inside the DATA_WIDTH/8-byte aligned beat
            // container, exactly like AXI WSTRB, while addr is the unaligned
            // byte address.  Adding the lane index to addr directly would count
            // the intra-beat offset twice and reject a legal access whose top
            // lane sits inside the window (for example a 4-byte write at
            // window_base+0xc on a 64-bit beat).
            beat_base = addr & ~BEAT_LANE_MASK;
            access_last = {1'b0, beat_base} + {1'b0, last_offset};
            for (int unsigned w = 0; w < NUM_WINDOWS; w++) begin
                logic [ADDRESS_WIDTH-1:0] window_base, window_size;
                logic [ADDRESS_WIDTH-1:0] window_target_base;
                window_base = WINDOW_BASE[w*ADDRESS_WIDTH +: ADDRESS_WIDTH];
                window_size = WINDOW_SIZE[w*ADDRESS_WIDTH +: ADDRESS_WIDTH];
                window_target_base = WINDOW_TARGET_BASE[w*ADDRESS_WIDTH +: ADDRESS_WIDTH];
                if (!decode_hit && (addr >= window_base) &&
                    (addr < (window_base + window_size))) begin
                    decode_hit = 1'b1;
                    decode_target = WINDOW_TARGET[w*TARGET_ID_WIDTH +: TARGET_ID_WIDTH];
                    decode_target_addr = addr - window_base + window_target_base;
                    decode_error = 1'b0;
                    if (access_last > ({1'b0, window_base} + {1'b0, window_size} - 1'b1))
                        decode_error = 1'b1;
                    if (write && !WINDOW_WRITABLE[w]) decode_error = 1'b1;
                    if (!write && !WINDOW_READABLE[w]) decode_error = 1'b1;
                    if (instr && !WINDOW_EXECUTABLE[w]) decode_error = 1'b1;
                    // Check the numeric bound before using source_id as a
                    // packed-vector index.  Encodings above NUM_SOURCES are
                    // denied even when SOURCE_ID_WIDTH has spare values.
                    if (source_id >= NUM_SOURCES) decode_error = 1'b1;
                    else if (!WINDOW_SOURCE_MASK[w*NUM_SOURCES + source_id])
                        decode_error = 1'b1;
                end
            end
        end
    end

    // Only the selected target sees a select or any request strobe; every
    // other target lane is driven to zero.
    always_comb begin
        t_req_valid = '0;
        t_write = '0;
        t_addr = '0;
        t_wdata = '0;
        t_be = '0;
        t_rsp_ready = '0;
        if (!reset) begin
            if (state_q == SELECT) begin
                t_req_valid[target_q] = 1'b1;
                t_write[target_q] = write_q;
                t_addr[target_q] = addr_q;
                t_wdata[target_q] = wdata_q;
                t_be[target_q] = be_q;
                t_rsp_ready[target_q] = 1'b1;
            end else if (state_q == CAPTURE_RSP) begin
                t_rsp_ready[target_q] = 1'b1;
            end else if (stale_q) begin
                t_rsp_ready[stale_target_q] = 1'b1;
            end
        end
    end

    assign rsp_valid = !reset && (state_q == RESPOND);
    assign rdata = rdata_q;
    assign error = error_q;
    assign rsp_source_id = source_q;
    assign rsp_transaction_id = txid_q;

    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE;
            write_q <= 1'b0;
            instr_q <= 1'b0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            rdata_q <= '0;
            error_q <= 1'b0;
            source_q <= '0;
            txid_q <= '0;
            target_q <= '0;
            // A target already accepted the request, so a late response may
            // still arrive.  Remember the target and refuse new transactions
            // until that response has been drained.  stale_q is deliberately
            // not cleared here so it survives a multi-cycle reset.
            if (RESET_CLEARS_TARGETS) begin
                stale_q <= 1'b0;
                stale_target_q <= '0;
            end else if (state_q == WAIT_RSP) begin
                stale_q <= 1'b1;
                stale_target_q <= target_q;
            end
        end else begin
            if (stale_q && t_rsp_valid[stale_target_q]) stale_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    if (req_valid && req_ready) begin
                        addr_q <= decode_target_addr;
                        write_q <= write;
                        wdata_q <= wdata;
                        be_q <= be;
                        instr_q <= instr;
                        source_q <= source_id;
                        txid_q <= transaction_id;
                        target_q <= decode_target;
                        rdata_q <= '0;
                        error_q <= decode_error;
                        if (decode_error) state_q <= RESPOND;
                        else state_q <= SELECT;
                    end
                end
                SELECT: begin
                    if (t_req_valid[target_q] && t_req_ready[target_q]) begin
                        if (t_rsp_valid[target_q]) begin
                            rdata_q <= t_rdata[target_q];
                            error_q <= t_error[target_q];
                            state_q <= RESPOND;
                        end else begin
                            state_q <= WAIT_RSP;
                        end
                    end
                end
                WAIT_RSP: begin
                    if (t_rsp_valid[target_q]) begin
                        // Do not sample a target's data on the same edge on
                        // which a clocked target raises RSP_VALID.  Holding
                        // READY low for one capture cycle keeps the response
                        // payload stable and prevents an NBA race from
                        // attributing stale data to the completion.
                        state_q <= CAPTURE_RSP;
                    end
                end
                CAPTURE_RSP: begin
                    if (t_rsp_valid[target_q]) begin
                        rdata_q <= t_rdata[target_q];
                        error_q <= t_error[target_q];
                        state_q <= RESPOND;
                    end
                end
                RESPOND: begin
                    if (rsp_ready) state_q <= IDLE;
                end
                default: state_q <= IDLE;
            endcase
        end
    end
endmodule
