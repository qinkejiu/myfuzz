// beat_to_tlul: target-side adapter from a processor-memory-beat initiator to a
// TL-UL (TileLink Uncached Lightweight) peripheral target.
//
// DIRECTION (fixed by task P5):
//   processor-memory-beat INITIATOR (arbiter/router output) -> this adapter ->
//   TL-UL TARGET (OpenTitan uart / gpio style peripheral).
// This is not tl_ul_mmio_bridge/tl_ul_processor_memory_adapter reused
// backwards.  Those modules are CPU side: they consume a TL-UL initiator and
// produce beat requests.  This module consumes beat requests and drives a TL-UL
// target.
//
// Beat initiator port contract (exactly these names, first release = one
// outstanding transaction):
//   clk, reset, req_valid, req_ready, write, addr[AW-1:0], wdata[DW-1:0],
//   be[DW/8-1:0], rsp_valid, rsp_ready, rdata[DW-1:0], error
// reset is synchronous and active high.  The surrounding *_mmio_bridge.sv
// modules use an active-low rst_ni; the P5 beat contract fixes this port as an
// active-high "reset", so a parent that owns an rst_ni domain must invert it.
//
// A channel: a_valid/a_opcode/a_param/a_size/a_source/a_address/a_mask/a_data/
// a_user, terminated by a_ready.  Get for reads, PutFullData for full writes,
// PutPartialData when be is a real subset; a_mask comes from be (full mask for
// reads); a_source is constant SOURCE_ID for the single outstanding
// transaction; a_size is the full beat transfer size.
//
// D channel: d_valid/d_opcode/d_param/d_size/d_source/d_sink/d_data/d_user/
// d_error, terminated by d_ready.  d_error, a D-channel shape violation or a
// timeout becomes the beat error response.  OpenTitan forces d_data to all ones
// on writes and on errored reads, so rdata is forced to zero whenever error is
// asserted and on every write: errored data is never treated as meaningful.
//
// Integrity (GEN_INTEGRITY, default 1 = the recorded OpenTitan requirement):
// a_user = {rsvd, instr_type=MuBi4False, cmd_intg, data_intg} where cmd_intg is
// the inv-64/57 SEC-DED code over {addr, opcode, mask, instr_type} and
// data_intg is the inv-39/32 SEC-DED code over a_data (the same codes
// tlul_cmd_intg_chk/tlul_data_integ_enc check).  With GEN_INTEGRITY=0 the
// adapter drives the TL_A_USER_DEFAULT fields (all ones) and the fabric owns
// integrity.  TL-UL carries only a 7-bit data integrity field, so generation is
// only defined for DATA_WIDTH=32; any other width aborts at elaboration time
// instead of emitting silently wrong check bits.
//
// A target that is not addressed (address outside WINDOW_BASE..+WINDOW_SIZE) is
// rejected locally: beat error response, no A-channel request at all.

module beat_to_tlul #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SIZE_WIDTH = 2,
    parameter integer SOURCE_WIDTH = 8,
    parameter integer SINK_WIDTH = 1,
    parameter integer USER_WIDTH = 23,
    parameter integer DUSER_WIDTH = 14,
    parameter integer GEN_INTEGRITY = 1,
    parameter integer SOURCE_ID = 0,
    parameter integer MAX_WAIT_CYCLES = 16,
    parameter logic [ADDRESS_WIDTH-1:0] WINDOW_BASE = '0,
    parameter integer WINDOW_SIZE = 0
) (
    input  logic                          clk,
    input  logic                          reset,

    input  logic                          req_valid,
    output logic                          req_ready,
    input  logic                          write,
    input  logic [ADDRESS_WIDTH-1:0]      addr,
    input  logic [DATA_WIDTH-1:0]         wdata,
    input  logic [(DATA_WIDTH/8)-1:0]     be,

    output logic                          rsp_valid,
    input  logic                          rsp_ready,
    output logic [DATA_WIDTH-1:0]         rdata,
    output logic                          error,

    output logic                          a_valid,
    input  logic                          a_ready,
    output logic [2:0]                    a_opcode,
    output logic [2:0]                    a_param,
    output logic [SIZE_WIDTH-1:0]         a_size,
    output logic [SOURCE_WIDTH-1:0]       a_source,
    output logic [ADDRESS_WIDTH-1:0]      a_address,
    output logic [(DATA_WIDTH/8)-1:0]     a_mask,
    output logic [DATA_WIDTH-1:0]         a_data,
    output logic [USER_WIDTH-1:0]         a_user,

    input  logic                          d_valid,
    output logic                          d_ready,
    input  logic [2:0]                    d_opcode,
    input  logic [2:0]                    d_param,
    input  logic [SIZE_WIDTH-1:0]         d_size,
    input  logic [SOURCE_WIDTH-1:0]       d_source,
    input  logic [SINK_WIDTH-1:0]         d_sink,
    input  logic [DATA_WIDTH-1:0]         d_data,
    input  logic [DUSER_WIDTH-1:0]        d_user,
    input  logic                          d_error
);

    localparam integer BYTE_ENABLE_WIDTH = DATA_WIDTH / 8;
    localparam integer LOG2_BYTE_ENABLE = (BYTE_ENABLE_WIDTH <= 1) ? 0 : $clog2(BYTE_ENABLE_WIDTH);
    localparam logic [(DATA_WIDTH/8)-1:0] FULL_MASK = {(DATA_WIDTH/8){1'b1}};
    localparam logic [SIZE_WIDTH-1:0] SIZE_VALUE = SIZE_WIDTH'($clog2(BYTE_ENABLE_WIDTH));
    localparam logic [SOURCE_WIDTH-1:0] SOURCE_VALUE = SOURCE_WIDTH'(SOURCE_ID);
    localparam logic [USER_WIDTH-1:0] A_USER_DEFAULT =
        USER_WIDTH'({4'h9, 7'h7f, 7'h7f});
    localparam logic [ADDRESS_WIDTH-1:0] WINDOW_LIMIT = WINDOW_SIZE;
    localparam integer CMD_PAYLOAD_BITS = 4 + ADDRESS_WIDTH + 3 + BYTE_ENABLE_WIDTH;
    // A non-zero replication count keeps the concatenation legal for every
    // configured address width; the assignment to [56:0] drops any excess pad.
    localparam integer CMD_PAD_BITS = (57 > CMD_PAYLOAD_BITS) ? (57 - CMD_PAYLOAD_BITS) : 1;
    localparam integer WAIT_COUNTER_WIDTH =
        (MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(MAX_WAIT_CYCLES - 1);
    localparam integer SIZE_BITS_NEEDED =
        (BYTE_ENABLE_WIDTH <= 1) ? 1 : $clog2($clog2(BYTE_ENABLE_WIDTH) + 1);

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "beat_to_tlul: invalid address or data width");
        if (GEN_INTEGRITY != 0 && GEN_INTEGRITY != 1)
            $fatal(1, "beat_to_tlul: GEN_INTEGRITY must be boolean");
        if (GEN_INTEGRITY != 0 && DATA_WIDTH != 32)
            $fatal(1, "beat_to_tlul: TL-UL data integrity is the inv-39/32 code over a 32-bit a_data; cannot produce integrity for this DATA_WIDTH");
        if (GEN_INTEGRITY != 0 && ADDRESS_WIDTH > 32)
            $fatal(1, "beat_to_tlul: command integrity covers at most 32 address bits");
        if (GEN_INTEGRITY != 0 && USER_WIDTH < 18)
            $fatal(1, "beat_to_tlul: USER_WIDTH must hold instr_type and both integrity fields");
        if (SOURCE_WIDTH < 1 || SINK_WIDTH < 1 || USER_WIDTH < 1 || DUSER_WIDTH < 1)
            $fatal(1, "beat_to_tlul: channel field widths must be positive");
        if (SIZE_WIDTH < SIZE_BITS_NEEDED)
            $fatal(1, "beat_to_tlul: SIZE_WIDTH cannot encode the beat transfer size");
        if (SOURCE_ID < 0 || SOURCE_ID >= (1 << SOURCE_WIDTH))
            $fatal(1, "beat_to_tlul: SOURCE_ID does not fit SOURCE_WIDTH");
        if (MAX_WAIT_CYCLES < 1)
            $fatal(1, "beat_to_tlul: MAX_WAIT_CYCLES must be positive");
        if (WINDOW_SIZE < 0 || WINDOW_SIZE % BYTE_ENABLE_WIDTH != 0)
            $fatal(1, "beat_to_tlul: WINDOW_SIZE must be a multiple of the data width");
        if (WINDOW_SIZE != 0 &&
            (WINDOW_LIMIT == 0 || WINDOW_BASE % BYTE_ENABLE_WIDTH != 0))
            $fatal(1, "beat_to_tlul: window does not fit the address width or is misaligned");
    end

    // OpenTitan SEC-DED encoders (prim_secded_pkg / prim_secded_inv_*_enc).
    function automatic logic [6:0] inv_39_32_intg(input logic [31:0] payload);
        logic [38:0] code;
        begin
            code = {7'b0, payload};
            code[32] = ^(code & 39'h002606BD25);
            code[33] = ^(code & 39'h00DEBA8050);
            code[34] = ^(code & 39'h00413D89AA);
            code[35] = ^(code & 39'h0031234ED1);
            code[36] = ^(code & 39'h00C2C1323B);
            code[37] = ^(code & 39'h002DCC624C);
            code[38] = ^(code & 39'h0098505586);
            code ^= 39'h2A00000000;
            inv_39_32_intg = code[38:32];
        end
    endfunction

    function automatic logic [6:0] inv_64_57_intg(input logic [56:0] payload);
        logic [63:0] code;
        begin
            code = {7'b0, payload};
            code[57] = ^(code & 64'h0103FFF800007FFF);
            code[58] = ^(code & 64'h017C1FF801FF801F);
            code[59] = ^(code & 64'h01BDE1F87E0781E1);
            code[60] = ^(code & 64'h01DEEE3B8E388E22);
            code[61] = ^(code & 64'h01EF76CDB2C93244);
            code[62] = ^(code & 64'h01F7BB56D5525488);
            code[63] = ^(code & 64'h01FBDDA769A46910);
            code ^= 64'h5400000000000000;
            inv_64_57_intg = code[63:57];
        end
    endfunction

    typedef enum logic [1:0] {
        IDLE,
        A_CHANNEL,
        D_CHANNEL
    } state_t;

    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic write_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BYTE_ENABLE_WIDTH-1:0] mask_q;
    logic [SIZE_WIDTH-1:0] size_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic rsp_valid_q;
    logic [DATA_WIDTH-1:0] rsp_rdata_q;
    logic rsp_error_q;

    logic in_window;
    logic [56:0] cmd_payload;
    logic [6:0] cmd_intg;
    logic [6:0] data_intg;
    logic d_shape_error;
    logic d_failure;

    assign in_window = (WINDOW_SIZE <= 0) ||
                       ((addr - WINDOW_BASE) < WINDOW_LIMIT);

    assign cmd_payload = {{CMD_PAD_BITS{1'b0}}, 4'h9, addr_q,
                          (write_q ? (mask_q == FULL_MASK ? 3'd0 : 3'd1) : 3'd4),
                          mask_q};
    assign cmd_intg = (GEN_INTEGRITY != 0) ? inv_64_57_intg(cmd_payload) : 7'h7f;
    assign data_intg = (GEN_INTEGRITY != 0) ? inv_39_32_intg(a_data) : 7'h7f;

    assign d_shape_error = (d_opcode != (write_q ? 3'd0 : 3'd1)) ||
                           (d_param != 3'd0) ||
                           (d_size != size_q) ||
                           (d_source != SOURCE_VALUE) ||
                           (d_sink != '0);
    assign d_failure = d_shape_error || d_error;

    assign req_ready = !reset && (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid = rsp_valid_q;
    assign rdata = rsp_rdata_q;
    assign error = rsp_error_q;

    assign a_valid = (state_q == A_CHANNEL);
    assign a_opcode = !a_valid ? 3'd0 :
                      (!write_q ? 3'd4 : ((mask_q == FULL_MASK) ? 3'd0 : 3'd1));
    assign a_param = 3'd0;
    assign a_size = size_q;
    assign a_source = SOURCE_VALUE;
    assign a_address = a_valid ? addr_q : '0;
    assign a_mask = a_valid ? mask_q : '0;
    assign a_data = (a_valid && write_q) ? wdata_q : '0;
    assign a_user = a_valid ? USER_WIDTH'({4'h9, cmd_intg, data_intg}) : A_USER_DEFAULT;

    assign d_ready = (state_q == D_CHANNEL) && !rsp_valid_q;

    always_ff @(posedge clk) begin
        if (reset) begin
            state_q <= IDLE;
            addr_q <= '0;
            write_q <= 1'b0;
            wdata_q <= '0;
            mask_q <= '0;
            size_q <= SIZE_VALUE;
            wait_count_q <= '0;
            rsp_valid_q <= 1'b0;
            rsp_rdata_q <= '0;
            rsp_error_q <= 1'b0;
        end else begin
            if (rsp_valid_q && rsp_ready) rsp_valid_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    wait_count_q <= '0;
                    if (req_valid && !rsp_valid_q) begin
                        if (!in_window) begin
                            // Local rejection: no A-channel request at all.
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            addr_q <= addr;
                            write_q <= write;
                            wdata_q <= wdata;
                            mask_q <= write ? be : FULL_MASK;
                            size_q <= SIZE_VALUE;
                            state_q <= A_CHANNEL;
                        end
                    end
                end
                A_CHANNEL: begin
                    if (a_valid && a_ready) begin
                        state_q <= D_CHANNEL;
                        wait_count_q <= '0;
                    end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= 1'b1;
                    end else begin
                        wait_count_q <= wait_count_q + 1'b1;
                    end
                end
                D_CHANNEL: begin
                    if (d_valid) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= (write_q || d_failure) ? '0 : d_data;
                        rsp_error_q <= d_failure;
                    end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= 1'b1;
                    end else begin
                        wait_count_q <= wait_count_q + 1'b1;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    wait_count_q <= '0;
                    rsp_valid_q <= 1'b1;
                    rsp_rdata_q <= '0;
                    rsp_error_q <= 1'b1;
                end
            endcase
        end
    end

endmodule
