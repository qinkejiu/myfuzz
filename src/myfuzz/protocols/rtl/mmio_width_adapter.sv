// mmio_width_adapter: 64-bit beat side <-> 32-bit peripheral side.
//
// Beat contract on both sides (identical to the P5 target adapters):
//   clk, reset, req_valid, req_ready, write, addr, wdata, be,
//   rsp_valid, rsp_ready, rdata, error
// The beat side (64-bit) uses the bare contract names; the peripheral side
// (32-bit) uses the same names with a p_ prefix.  "reset" is synchronous and
// active high.
//
// Lane rules (address bit 2 selects the peripheral word; the byte enables are
// byte lanes of the beat, exactly like AXI WSTRB):
//   * byte enables inside the low half (be[3:0]) require addr[2] == 0 and are
//     driven to the peripheral as p_be = be[3:0], p_wdata = wdata[31:0];
//   * byte enables inside the high half (be[7:4]) require addr[2] == 1 and are
//     driven as p_be = be[7:4], p_wdata = wdata[63:32], with the peripheral
//     address unchanged so its own bit 2 selects the second register;
//   * a 32-bit read returns the peripheral word zero-extended into the lane it
//     was read from (low -> rdata[31:0], high -> rdata[63:32]);
//   * byte enables in both halves of an 8-byte-aligned beat are a wide
//     (spanning) access and are refused unless the caller explicitly declares
//     the window safe;
//   * a wide access that is not 8-byte aligned, a lane/address-bit-2 mismatch
//     or an access with no byte enables is always refused.
//
// A 64-bit MMIO WRITE that would span TWO registers with side effects is NOT
// split into two 32-bit writes by default: ALLOW_SPANNING_WRITE_SPLIT is
// 1'b0, so the adapter answers with error = 1 and issues NO peripheral write.
// Set ALLOW_SPANNING_WRITE_SPLIT = 1'b1 only for a window whose two 32-bit
// registers are declared side-effect free to split (for example two halves of
// one plain data register).  A 64-bit read that spans two registers is
// assembled only when the window declares that reading both halves is
// side-effect free: ALLOW_SPANNING_READ_ASSEMBLE = 1'b0 by default (reading a
// FIFO or any read-to-clear register twice is not safe).  A refused access
// never touches the peripheral.
//
// Reset discipline: if reset terminates a peripheral access that was already
// accepted, the adapter drains and discards the late peripheral response
// before accepting anything new (stale_pending exposes that state), so a late
// response can never be attributed to a later transaction.

module mmio_width_adapter #(
    // Valid only for a full-test reset shared with all downstream state.
    parameter bit RESET_CLEARS_TARGETS = 1'b0,
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 64,
    parameter integer PERIPHERAL_DATA_WIDTH = 32,
    parameter bit ALLOW_SPANNING_WRITE_SPLIT = 1'b0,
    parameter bit ALLOW_SPANNING_READ_ASSEMBLE = 1'b0
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
    output logic [ADDRESS_WIDTH-1:0]                p_addr,
    output logic [PERIPHERAL_DATA_WIDTH-1:0]        p_wdata,
    output logic [(PERIPHERAL_DATA_WIDTH/8)-1:0]    p_be,
    input  logic                                    p_rsp_valid,
    output logic                                    p_rsp_ready,
    input  logic [PERIPHERAL_DATA_WIDTH-1:0]        p_rdata,
    input  logic                                    p_error,

    output logic                                    stale_pending
);
    localparam integer BE_WIDTH = DATA_WIDTH / 8;
    localparam integer PERIPHERAL_BE_WIDTH = PERIPHERAL_DATA_WIDTH / 8;
    localparam integer PERIPHERAL_BYTES = PERIPHERAL_DATA_WIDTH / 8;

    initial begin
        if ((DATA_WIDTH != (2 * PERIPHERAL_DATA_WIDTH)) ||
            (DATA_WIDTH % 8 != 0) || (PERIPHERAL_DATA_WIDTH % 8 != 0))
            $fatal(1, "mmio_width_adapter requires a 64-bit beat side and a 32-bit peripheral side");
        if (ADDRESS_WIDTH < 3)
            $fatal(1, "mmio_width_adapter needs address bit 2 for lane selection");
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
    logic write_q, error_q, spanning_q, phase_q;

    logic decode_error, decode_spanning, decode_phase;

    // Lane decode of the request presented at the accept cycle.
    always_comb begin
        logic [PERIPHERAL_BE_WIDTH-1:0] low_mask, high_mask;
        low_mask = be[0 +: PERIPHERAL_BE_WIDTH];
        high_mask = be[PERIPHERAL_BE_WIDTH +: PERIPHERAL_BE_WIDTH];
        decode_error = 1'b0;
        decode_spanning = 1'b0;
        decode_phase = addr[2];
        if (be == '0) begin
            decode_error = 1'b1;
        end else if ((low_mask != '0) && (high_mask != '0)) begin
            decode_spanning = 1'b1;
            if (addr[2:0] != 3'b000) decode_error = 1'b1;
            else if (write) decode_error = !ALLOW_SPANNING_WRITE_SPLIT;
            else decode_error = !ALLOW_SPANNING_READ_ASSEMBLE;
        end else if (addr[2] != (high_mask != '0)) begin
            decode_error = 1'b1;
        end
    end

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
            // The request fields are held until the peripheral response has
            // been consumed, so a combinational target keeps presenting the
            // addressed data while the access is in flight.
            if ((state_q == ACCESS) || (state_q == WAIT_RSP)) begin
                p_write = write_q;
                p_addr = (spanning_q && phase_q)
                         ? (addr_q + PERIPHERAL_BYTES[ADDRESS_WIDTH-1:0]) : addr_q;
                p_wdata = phase_q ? wdata_q[DATA_WIDTH-1:PERIPHERAL_DATA_WIDTH]
                                  : wdata_q[PERIPHERAL_DATA_WIDTH-1:0];
                p_be = phase_q ? be_q[BE_WIDTH-1:PERIPHERAL_BE_WIDTH]
                               : be_q[PERIPHERAL_BE_WIDTH-1:0];
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
            spanning_q <= 1'b0;
            phase_q <= 1'b0;
            // The peripheral already accepted a request, so a late response
            // may still arrive; drain it before accepting anything new.
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
                        error_q <= decode_error;
                        spanning_q <= decode_spanning;
                        phase_q <= decode_phase;
                        if (decode_error) state_q <= RESPOND;
                        else state_q <= ACCESS;
                    end
                end
                ACCESS: begin
                    if (p_req_valid && p_req_ready) state_q <= WAIT_RSP;
                end
                WAIT_RSP: begin
                    if (p_rsp_valid) begin
                        if (p_error) begin
                            rdata_q <= '0;
                            error_q <= 1'b1;
                            state_q <= RESPOND;
                        end else begin
                            if (phase_q) rdata_q[DATA_WIDTH-1:PERIPHERAL_DATA_WIDTH] <= p_rdata;
                            else rdata_q[PERIPHERAL_DATA_WIDTH-1:0] <= p_rdata;
                            if (!spanning_q || phase_q) begin
                                state_q <= RESPOND;
                            end else begin
                                phase_q <= 1'b1;
                                state_q <= ACCESS;
                            end
                        end
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
