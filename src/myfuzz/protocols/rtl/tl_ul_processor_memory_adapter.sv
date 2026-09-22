module tl_ul_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SOURCE_WIDTH = 1
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic                         a_valid_i,
    output logic                         a_ready_o,
    input  logic [2:0]                   a_opcode_i,
    input  logic [2:0]                   a_param_i,
    input  logic [2:0]                   a_size_i,
    input  logic [SOURCE_WIDTH-1:0]      a_source_i,
    input  logic [ADDRESS_WIDTH-1:0]     a_address_i,
    input  logic [(DATA_WIDTH/8)-1:0]    a_mask_i,
    input  logic [DATA_WIDTH-1:0]        a_data_i,
    input  logic                         a_corrupt_i,
    output logic                         d_valid_o,
    input  logic                         d_ready_i,
    output logic [2:0]                   d_opcode_o,
    output logic [2:0]                   d_param_o,
    output logic [2:0]                   d_size_o,
    output logic [SOURCE_WIDTH-1:0]      d_source_o,
    output logic                         d_sink_o,
    output logic                         d_denied_o,
    output logic [DATA_WIDTH-1:0]        d_data_o,
    output logic                         d_corrupt_o,
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
            $fatal(1, "invalid TL-UL/backend address or data width");
    end

    localparam integer BYTE_LANES = DATA_WIDTH / 8;
    localparam logic [2:0] MAX_SIZE = 3'($clog2(BYTE_LANES));
    localparam logic [ADDRESS_WIDTH-1:0] BYTE_LANES_VALUE = ADDRESS_WIDTH'(BYTE_LANES);
    typedef enum logic [2:0] {IDLE, REQUEST, RESPONSE, DRAIN_A, TL_RESPONSE} state_t;
    state_t state_q;
    logic write_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] data_q;
    logic [BYTE_LANES-1:0] be_q;
    logic [2:0] size_q;
    logic [SOURCE_WIDTH-1:0] source_q;
    logic d_valid_q, d_denied_q, d_corrupt_q;
    logic [2:0] d_opcode_q;
    logic [DATA_WIDTH-1:0] d_data_q;
    logic [7:0] a_beats_left_q, d_beats_left_q;

    function automatic [BYTE_LANES-1:0] transfer_mask(
        input logic [2:0] size,
        input logic [ADDRESS_WIDTH-1:0] address
    );
        integer bytes, offset, lane;
        begin
            bytes = 1 << size;
            offset = integer'(address % BYTE_LANES_VALUE);
            transfer_mask = '0;
            for (lane = 0; lane < BYTE_LANES; lane = lane + 1)
                if (lane >= offset && lane < offset + bytes)
                    transfer_mask[lane] = 1'b1;
        end
    endfunction

    function automatic [7:0] multibeat_left(input logic [2:0] size);
        begin
            if (size <= MAX_SIZE)
                multibeat_left = 8'd0;
            else
                multibeat_left = (8'd1 << (size - MAX_SIZE)) - 1'b1;
        end
    endfunction

    wire is_get = a_opcode_i == 3'd4;
    wire is_put = (a_opcode_i == 3'd0) || (a_opcode_i == 3'd1);
    wire size_ok = a_size_i <= MAX_SIZE;
    wire aligned = size_ok && ((a_address_i % (ADDRESS_WIDTH'(1) << a_size_i)) == 0);
    wire [BYTE_LANES-1:0] expected_mask = transfer_mask(a_size_i, a_address_i);
    wire mask_ok = (is_get && (a_mask_i == expected_mask)) ||
                   ((a_opcode_i == 3'd0) && (a_mask_i == expected_mask)) ||
                   ((a_opcode_i == 3'd1) &&
                    ((a_mask_i & ~expected_mask) == '0));
    wire malformed = !(is_get || is_put) || (a_param_i != 3'd0) ||
                     a_corrupt_i || !aligned || !mask_ok;
    wire response_has_data = (a_opcode_i == 3'd2) ||
                             (a_opcode_i == 3'd3) || is_get;
    wire request_has_multibeat_data = (a_opcode_i <= 3'd3);
    wire [2:0] error_response_opcode = response_has_data ? 3'd1 :
                                             (a_opcode_i == 3'd5) ? 3'd2 : 3'd0;
    wire empty_partial_write = (a_opcode_i == 3'd1) && (a_mask_i == '0);

    assign a_ready_o = rst_ni && (((state_q == IDLE) && !d_valid_q) ||
                                  (state_q == DRAIN_A));
    assign d_valid_o = d_valid_q;
    assign d_opcode_o = d_opcode_q;
    assign d_param_o = 3'd0;
    assign d_size_o = size_q;
    assign d_source_o = source_q;
    assign d_sink_o = 1'b0;
    assign d_denied_o = d_denied_q;
    assign d_data_o = d_data_q;
    assign d_corrupt_o = d_corrupt_q;
    assign req_valid_o = state_q == REQUEST;
    assign req_write_o = write_q;
    assign req_addr_o = req_valid_o ? addr_q : '0;
    assign req_wdata_o = (req_valid_o && write_q) ? data_q : '0;
    assign req_be_o = req_valid_o ? be_q : '0;
    assign rsp_ready_o = state_q == RESPONSE;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE; write_q <= 1'b0; addr_q <= '0; data_q <= '0;
            be_q <= '0; size_q <= '0; source_q <= 1'b0; d_valid_q <= 1'b0;
            d_opcode_q <= '0; d_denied_q <= 1'b0; d_data_q <= '0; d_corrupt_q <= 1'b0;
            a_beats_left_q <= '0; d_beats_left_q <= '0;
        end else begin
            case (state_q)
                IDLE: if (a_valid_i && a_ready_o) begin
                    size_q <= a_size_i;
                    source_q <= a_source_i;
                    if (malformed) begin
                        d_valid_q <= 1'b1;
                        d_opcode_q <= error_response_opcode;
                        d_denied_q <= 1'b1;
                        d_data_q <= '0;
                        d_corrupt_q <= response_has_data;
                        d_beats_left_q <= response_has_data ?
                                              multibeat_left(a_size_i) : 8'd0;
                        if (request_has_multibeat_data &&
                            (multibeat_left(a_size_i) != 8'd0)) begin
                            a_beats_left_q <= multibeat_left(a_size_i);
                            d_valid_q <= 1'b0;
                            state_q <= DRAIN_A;
                        end else begin
                            state_q <= TL_RESPONSE;
                        end
                    end else if (empty_partial_write) begin
                        d_valid_q <= 1'b1;
                        d_opcode_q <= 3'd0;
                        d_denied_q <= 1'b0;
                        d_data_q <= '0;
                        d_corrupt_q <= 1'b0;
                        d_beats_left_q <= 8'd0;
                        state_q <= TL_RESPONSE;
                    end else begin
                        write_q <= is_put;
                        addr_q <= a_address_i;
                        data_q <= a_data_i;
                        be_q <= a_mask_i;
                        state_q <= REQUEST;
                    end
                end
                REQUEST: if (req_valid_o && req_ready_i) state_q <= RESPONSE;
                RESPONSE: if (rsp_valid_i && rsp_ready_o) begin
                    d_valid_q <= 1'b1;
                    d_opcode_q <= write_q ? 3'd0 : 3'd1;
                    d_denied_q <= rsp_error_i;
                    d_data_q <= (write_q || rsp_error_i) ? '0 : rsp_rdata_i;
                    d_corrupt_q <= !write_q && rsp_error_i;
                    state_q <= TL_RESPONSE;
                end
                DRAIN_A: if (a_valid_i && a_ready_o) begin
                    if (a_beats_left_q == 8'd1) begin
                        a_beats_left_q <= 8'd0;
                        d_valid_q <= 1'b1;
                        state_q <= TL_RESPONSE;
                    end else begin
                        a_beats_left_q <= a_beats_left_q - 1'b1;
                    end
                end
                TL_RESPONSE: if (d_valid_q && d_ready_i) begin
                    if (d_beats_left_q != 8'd0) begin
                        d_beats_left_q <= d_beats_left_q - 1'b1;
                    end else begin
                        d_valid_q <= 1'b0; d_opcode_q <= '0; d_denied_q <= 1'b0;
                        d_data_q <= '0; d_corrupt_q <= 1'b0; state_q <= IDLE;
                    end
                end
                default: begin
                    state_q <= IDLE; d_valid_q <= 1'b0; d_denied_q <= 1'b0;
                    d_corrupt_q <= 1'b0;
                end
            endcase
        end
    end
endmodule

// Variant used when a TL-UL endpoint explicitly declares optional user and
// integrity sidebands.  The historical module above intentionally keeps its
// original port list so legacy benches using ``.*`` continue to elaborate.
// This wrapper exposes the optional fields without duplicating the transaction
// state machine; the generic beat backend has no user payload, so d_user_o is
// deterministic zero and d_error_o mirrors the response error indication.
module tl_ul_processor_memory_adapter_sideband #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer SOURCE_WIDTH = 1,
    parameter integer USER_WIDTH = 23,
    parameter integer DUSER_WIDTH = 14
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic                         a_valid_i,
    output logic                         a_ready_o,
    input  logic [2:0]                   a_opcode_i,
    input  logic [2:0]                   a_param_i,
    input  logic [2:0]                   a_size_i,
    input  logic [SOURCE_WIDTH-1:0]      a_source_i,
    input  logic [ADDRESS_WIDTH-1:0]     a_address_i,
    input  logic [(DATA_WIDTH/8)-1:0]    a_mask_i,
    input  logic [DATA_WIDTH-1:0]        a_data_i,
    input  logic                         a_corrupt_i,
    input  logic [USER_WIDTH-1:0]        a_user_i,
    output logic                         d_valid_o,
    input  logic                         d_ready_i,
    output logic [2:0]                   d_opcode_o,
    output logic [2:0]                   d_param_o,
    output logic [2:0]                   d_size_o,
    output logic [SOURCE_WIDTH-1:0]      d_source_o,
    output logic                         d_sink_o,
    output logic                         d_denied_o,
    output logic [DATA_WIDTH-1:0]        d_data_o,
    output logic                         d_corrupt_o,
    output logic [DUSER_WIDTH-1:0]       d_user_o,
    output logic                         d_error_o,
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
    // The sideband is a declared protocol field, but this adapter's backend
    // contract has no integrity payload to consume.  Keeping the input in the
    // explicit interface makes that loss auditable instead of silently
    // dropping a port during rendering.
    logic unused_a_user;
    assign unused_a_user = ^a_user_i;

    tl_ul_processor_memory_adapter #(
        .ADDRESS_WIDTH(ADDRESS_WIDTH),
        .DATA_WIDTH(DATA_WIDTH),
        .SOURCE_WIDTH(SOURCE_WIDTH)
    ) u_base (
        .clk_i(clk_i), .rst_ni(rst_ni),
        .a_valid_i(a_valid_i), .a_ready_o(a_ready_o),
        .a_opcode_i(a_opcode_i), .a_param_i(a_param_i), .a_size_i(a_size_i),
        .a_source_i(a_source_i), .a_address_i(a_address_i),
        .a_mask_i(a_mask_i), .a_data_i(a_data_i), .a_corrupt_i(a_corrupt_i),
        .d_valid_o(d_valid_o), .d_ready_i(d_ready_i),
        .d_opcode_o(d_opcode_o), .d_param_o(d_param_o), .d_size_o(d_size_o),
        .d_source_o(d_source_o), .d_sink_o(d_sink_o), .d_denied_o(d_denied_o),
        .d_data_o(d_data_o), .d_corrupt_o(d_corrupt_o),
        .req_valid_o(req_valid_o), .req_ready_i(req_ready_i),
        .req_write_o(req_write_o), .req_addr_o(req_addr_o),
        .req_wdata_o(req_wdata_o), .req_be_o(req_be_o),
        .rsp_valid_i(rsp_valid_i), .rsp_ready_o(rsp_ready_o),
        .rsp_rdata_i(rsp_rdata_i), .rsp_error_i(rsp_error_i)
    );

    assign d_user_o = '0;
    assign d_error_o = d_denied_o || d_corrupt_o;
endmodule
