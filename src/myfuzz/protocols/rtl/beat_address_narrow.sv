// beat_address_narrow: structural address-narrowing stage in front of a target
// whose own adapter can only accept a bounded address width.
//
// WHY THIS STAGE EXISTS
//   The fabric beat address width is fixed by the CPU backend: an RV64 CVA6
//   produces 64-bit addresses.  A TL-UL target that requires generated command
//   integrity can only cover 32 address bits, because the inv-64/57 SEC-DED
//   code is computed over {instr_type, opcode, mask, address}.  A wider address
//   therefore cannot be encoded, and beat_to_tlul fails closed at elaboration
//   instead of emitting integrity over bits the code never covered.
//
//   The fix is structural and belongs here, in front of the target: narrow the
//   address exactly once, next to the target that needs the narrow view, and
//   prove the narrowing lossless from the target's own decode window.  Relaxing
//   the adapter guard would instead emit integrity over a truncated address.
//
// PROOF OBLIGATION (elaboration time, not run time)
//   WINDOW_SIZE > 0 and the whole window [WINDOW_BASE, WINDOW_BASE+WINDOW_SIZE)
//   lies inside [0, 2**NARROW_ADDRESS_WIDTH).  Every address the target can
//   legitimately be asked for is then representable in NARROW_ADDRESS_WIDTH
//   bits, so the bits forwarded downstream are the complete absolute address
//   and no in-window information is discarded.  A window that does not fit is
//   an elaboration error, never a silent truncation.
//
// FAIL-CLOSED ALIASING RULE
//   The window test is evaluated on the WIDE address, before truncation.  An
//   out-of-window request is answered locally with a beat error response and
//   issues no downstream request, so a wide address whose low bits would alias
//   into the window can never reach the target.
//
// Beat contract on both sides (identical to the P5 target adapters and to
// mmio_width_adapter): clk, reset, req_valid, req_ready, write, addr, wdata, be,
// rsp_valid, rsp_ready, rdata, error.  The wide side uses the bare contract
// names; the narrow side uses the same names with a p_ prefix.  "reset" is
// synchronous and active high.
//
// Reset discipline matches mmio_width_adapter: if reset terminates a request
// the target already accepted, the adapter drains and discards the late
// response before accepting anything new (stale_pending exposes that state), so
// a late response can never be attributed to a later transaction.

module beat_address_narrow #(
    // Valid only for a full-test reset shared with all downstream state.
    parameter bit RESET_CLEARS_TARGETS = 1'b0,
    parameter integer ADDRESS_WIDTH = 64,
    parameter integer NARROW_ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter logic [ADDRESS_WIDTH-1:0] WINDOW_BASE = '0,
    parameter integer WINDOW_SIZE = 0
) (
    input  logic clk,
    input  logic reset,

    input  logic                                    req_valid,
    output logic                                    req_ready,
    input  logic                                    write,
    input  logic [ADDRESS_WIDTH-1:0]                addr,
    input  logic [DATA_WIDTH-1:0]                   wdata,
    input  logic [(DATA_WIDTH/8)-1:0]               be,
    output logic                                    rsp_valid,
    input  logic                                    rsp_ready,
    output logic [DATA_WIDTH-1:0]                   rdata,
    output logic                                    error,

    output logic                                    p_req_valid,
    input  logic                                    p_req_ready,
    output logic                                    p_write,
    output logic [NARROW_ADDRESS_WIDTH-1:0]         p_addr,
    output logic [DATA_WIDTH-1:0]                   p_wdata,
    output logic [(DATA_WIDTH/8)-1:0]               p_be,
    input  logic                                    p_rsp_valid,
    output logic                                    p_rsp_ready,
    input  logic [DATA_WIDTH-1:0]                   p_rdata,
    input  logic                                    p_error,

    output logic                                    stale_pending
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;
    localparam logic [ADDRESS_WIDTH-1:0] WINDOW_LIMIT = WINDOW_SIZE;
    // Bits at or above NARROW_ADDRESS_WIDTH: zero for every address the target
    // can be asked for.  The shift amount is clamped so that an invalid
    // NARROW_ADDRESS_WIDTH is reported by the explicit check below instead of
    // making this constant expression itself out of range.
    localparam integer NARROW_SHIFT =
        (NARROW_ADDRESS_WIDTH < ADDRESS_WIDTH) ? NARROW_ADDRESS_WIDTH : (ADDRESS_WIDTH - 1);
    localparam logic [ADDRESS_WIDTH-1:0] NARROW_HIGH_MASK =
        ~((ADDRESS_WIDTH'(1) << NARROW_SHIFT) - 1);
    // Last byte of the window, widened by one bit so a wrapped sum is visible
    // instead of silently comparing small.
    localparam logic [ADDRESS_WIDTH-1:0] WINDOW_LAST = WINDOW_BASE + (WINDOW_SIZE - 1);

    initial begin
        if (NARROW_ADDRESS_WIDTH < 1 || NARROW_ADDRESS_WIDTH >= ADDRESS_WIDTH)
            $fatal(1, "beat_address_narrow: the narrow address must be at least one bit and strictly narrower than the source address");
        if (DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "beat_address_narrow: DATA_WIDTH must be a whole number of bytes");
        if (WINDOW_SIZE <= 0)
            $fatal(1, "beat_address_narrow: a bounded positive target window is required to prove the narrowing lossless");
        if (WINDOW_SIZE % BE_WIDTH != 0)
            $fatal(1, "beat_address_narrow: WINDOW_SIZE must be a multiple of the data width");
        if (WINDOW_BASE % BE_WIDTH != 0)
            $fatal(1, "beat_address_narrow: WINDOW_BASE must be aligned to the data width");
        if (WINDOW_LAST < WINDOW_BASE)
            $fatal(1, "beat_address_narrow: the target window wraps the source address width");
        if (((WINDOW_BASE | WINDOW_LAST) & NARROW_HIGH_MASK) != 0)
            $fatal(1, "beat_address_narrow: the target window does not fit the narrow address width");
    end

    typedef enum logic [1:0] {IDLE, ACCESS, WAIT_RSP, RESPOND} state_t;
    // Explicit initial values: the drain flag must never start as X, otherwise
    // the first reset edge (when state_q is still X) would leave req_ready
    // undefined.
    state_t state_q = IDLE;
    logic stale_q = 1'b0;

    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q, rdata_q;
    logic [BE_WIDTH-1:0] be_q;
    logic write_q, error_q;

    // Evaluated on the wide address, so an out-of-window address can never be
    // truncated into the window.
    logic in_window;
    assign in_window = ((addr - WINDOW_BASE) < WINDOW_LIMIT);

    assign req_ready = !reset && !stale_q && (state_q == IDLE);
    assign rsp_valid = !reset && (state_q == RESPOND);
    assign rdata = rdata_q;
    assign error = error_q;
    assign stale_pending = stale_q;

    always_comb begin
        p_req_valid = 1'b0;
        p_write = 1'b0;
        p_addr = '0;
        p_wdata = '0;
        p_be = '0;
        p_rsp_ready = 1'b0;
        if (!reset) begin
            // Fields are held until the response is consumed, so a
            // combinational target keeps seeing the addressed request.
            if ((state_q == ACCESS) || (state_q == WAIT_RSP)) begin
                p_write = write_q;
                // In-window addresses are known to fit NARROW_ADDRESS_WIDTH
                // bits, so these low bits are the complete absolute address.
                p_addr = addr_q[NARROW_ADDRESS_WIDTH-1:0];
                p_wdata = wdata_q;
                p_be = be_q;
            end
            if (state_q == ACCESS) begin
                p_req_valid = 1'b1;
            end else if (state_q == WAIT_RSP) begin
                p_rsp_ready = 1'b1;
            end else if (stale_q) begin
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
            // The target already accepted a request, so a late response may
            // still arrive; drain it before accepting anything new.
            if (RESET_CLEARS_TARGETS) stale_q <= 1'b0;
            else if (state_q == WAIT_RSP) stale_q <= 1'b1;
        end else begin
            if (stale_q && p_rsp_valid) stale_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    if (req_valid && req_ready) begin
                        addr_q <= addr;
                        wdata_q <= wdata;
                        be_q <= be;
                        write_q <= write;
                        rdata_q <= '0;
                        if (!in_window) begin
                            // Local rejection: no downstream request at all.
                            error_q <= 1'b1;
                            state_q <= RESPOND;
                        end else begin
                            error_q <= 1'b0;
                            state_q <= ACCESS;
                        end
                    end
                end
                ACCESS: begin
                    if (p_req_valid && p_req_ready) state_q <= WAIT_RSP;
                end
                WAIT_RSP: begin
                    if (p_rsp_valid) begin
                        rdata_q <= p_rdata;
                        error_q <= p_error;
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
