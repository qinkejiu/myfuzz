// wishbone_processor_memory_adapter: CPU-side Wishbone (classic) initiator to
// the generic processor-memory-beat backend.
//
// DIRECTION
//   Wishbone MASTER (a real CPU such as the ZipCPU) -> this adapter -> the
//   generic fabric's beat request/response backend.  This is the mirror image of
//   beat_to_wishbone, which drives a Wishbone TARGET from a beat initiator; that
//   module is peripheral side and is not reused backwards here.
//
//   The CPU is the Wishbone master, so the ports this adapter samples are the
//   master's outputs (cyc/stb/we/adr/dat_w/sel) and the ports it drives are the
//   master's inputs (stall/ack/err/dat_r).  Port names are adapter centric, like
//   the other *_processor_memory_adapter modules: _i is an adapter input.
//
// CYCLE RULES (Wishbone classic, one outstanding transfer)
//   * A transfer exists while CYC and STB are both asserted.  CYC without STB is
//     an idle bus cycle and issues nothing.
//   * The adapter issues exactly one beat request per transfer.  Until the
//     backend accepts it, STALL_O is asserted so a conforming master holds the
//     cycle's address, data and select lines.  Request fields therefore pass
//     through combinationally and stay stable for the whole transfer.
//   * ACK_O or ERR_O is asserted when the backend answers, together with DAT_R_O
//     for a read, and is held until the master drops STB.  That is the tolerant
//     reading of the classic handshake: a master that drops STB in the cycle
//     after it samples ACK sees a one-cycle pulse, and a slower master cannot
//     miss the termination.  A master must not start the next transfer before
//     the previous one has terminated.
//   * ERR_O is asserted for a backend error and for a locally refused transfer;
//     a locally refused transfer issues no beat request at all.  ERR is part of
//     the classic master interface, so this adapter always publishes it: a CPU
//     without an ERR input could not be told that an access failed, and
//     reporting success instead would be silently wrong.
//
// FAIL-CLOSED CASES (beat error response, zero backend requests)
//   * a transfer with no byte selected (SEL == 0 and HAS_SEL == 1) has no
//     defined transfer size in Wishbone, so it is refused instead of being
//     guessed or pushed downstream as a zero-mask access;
//   * any write when READ_ONLY = 1 is refused rather than silently dropped,
//     because this boundary exists to carry the CPU's writes to the fabric.
//
// RESET
//   rst_ni is synchronous and active low, matching the other CPU-side adapters.

module wishbone_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer READ_ONLY = 0,
    parameter integer HAS_SEL = 1
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,

    input  logic                         cyc_i,
    input  logic                         stb_i,
    input  logic                         we_i,
    input  logic [ADDRESS_WIDTH-1:0]     adr_i,
    input  logic [DATA_WIDTH-1:0]        dat_w_i,
    input  logic [(DATA_WIDTH/8)-1:0]    sel_i,
    output logic                         stall_o,
    output logic                         ack_o,
    output logic                         err_o,
    output logic [DATA_WIDTH-1:0]        dat_r_o,

    output logic                         req_valid_o,
    input  logic                         req_ready_i,
    output logic                         req_write_o,
    output logic [ADDRESS_WIDTH-1:0]     req_addr_o,
    output logic [DATA_WIDTH-1:0]        req_wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]    req_be_o,
    input  logic                         rsp_valid_i,
    output logic                         rsp_ready_o,
    input  logic [DATA_WIDTH-1:0]        rsp_rdata_i,
    input  logic                         rsp_error_i
);
    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0)
            $fatal(1, "invalid Wishbone/backend address or data width");
        if ((READ_ONLY != 0 && READ_ONLY != 1) ||
            (HAS_SEL != 0 && HAS_SEL != 1))
            $fatal(1, "wishbone_processor_memory_adapter feature parameters must be boolean");
    end

    localparam logic [(DATA_WIDTH/8)-1:0] FULL_SEL = {(DATA_WIDTH/8){1'b1}};

    typedef enum logic [1:0] {IDLE, WAIT_RESPONSE, TERMINATE} state_t;
    state_t state_q;

    logic transfer;
    logic write_transfer;
    logic [(DATA_WIDTH/8)-1:0] transfer_sel;
    logic refused_read_only;
    logic refused_empty_select;

    logic ack_q, err_q;
    logic [DATA_WIDTH-1:0] dat_r_q;

    assign transfer = cyc_i && stb_i;
    assign write_transfer = transfer && (READ_ONLY == 0) && we_i;
    assign transfer_sel = (HAS_SEL != 0) ? sel_i : FULL_SEL;
    // Nothing selected means no defined transfer, and this boundary must not
    // silently drop an access the CPU believes it performed.
    assign refused_empty_select = transfer && (HAS_SEL != 0) && (transfer_sel == '0);
    assign refused_read_only = transfer && (READ_ONLY != 0) && we_i;
    // The adapter's request handshake for this transfer.
    assign req_valid_o = rst_ni && (state_q == IDLE) && transfer &&
                         !refused_empty_select && !refused_read_only;
    assign req_write_o = write_transfer;
    assign req_addr_o = req_valid_o ? adr_i : '0;
    assign req_wdata_o = req_valid_o ? dat_w_i : '0;
    assign req_be_o = req_valid_o ? transfer_sel : '0;
    // Hold the master until the backend has taken the request.  A refused
    // transfer is never stalled: it terminates with ERR in the same cycle.
    assign stall_o = rst_ni && (state_q == IDLE) && req_valid_o && !req_ready_i;
    assign rsp_ready_o = rst_ni && (state_q == WAIT_RESPONSE);
    assign ack_o = ack_q;
    assign err_o = err_q;
    assign dat_r_o = dat_r_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            ack_q <= 1'b0;
            err_q <= 1'b0;
            dat_r_q <= '0;
        end else begin
            case (state_q)
                IDLE: begin
                    ack_q <= 1'b0;
                    err_q <= 1'b0;
                    if (refused_empty_select || refused_read_only) begin
                        // Local refusal: no beat request, terminate at once.
                        dat_r_q <= '0;
                        err_q <= 1'b1;
                        state_q <= TERMINATE;
                    end else if (req_valid_o && req_ready_i) begin
                        state_q <= WAIT_RESPONSE;
                    end
                end
                WAIT_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        dat_r_q <= (write_transfer || rsp_error_i) ? '0 : rsp_rdata_i;
                        ack_q <= !rsp_error_i;
                        err_q <= rsp_error_i;
                        state_q <= TERMINATE;
                    end
                end
                TERMINATE: begin
                    // Hold the termination until the master ends the cycle, so a
                    // slow master cannot miss it.
                    if (!stb_i) begin
                        ack_q <= 1'b0;
                        err_q <= 1'b0;
                        state_q <= IDLE;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    ack_q <= 1'b0;
                    err_q <= 1'b1;
                    dat_r_q <= '0;
                end
            endcase
        end
    end
endmodule
