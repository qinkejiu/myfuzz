module tl_ul_mmio_target #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,

    input  logic                          a_valid_i,
    output logic                          a_ready_o,
    input  logic [2:0]                    a_opcode_i,
    input  logic [2:0]                    a_param_i,
    input  logic [2:0]                    a_size_i,
    input  logic [0:0]                    a_source_i,
    input  logic [ADDRESS_WIDTH-1:0]      a_address_i,
    input  logic [(DATA_WIDTH/8)-1:0]     a_mask_i,
    input  logic [DATA_WIDTH-1:0]         a_data_i,
    input  logic                          a_corrupt_i,

    output logic                          d_valid_o,
    input  logic                          d_ready_i,
    output logic [2:0]                    d_opcode_o,
    output logic [1:0]                    d_param_o,
    output logic [2:0]                    d_size_o,
    output logic [0:0]                    d_source_o,
    output logic [0:0]                    d_sink_o,
    output logic                          d_denied_o,
    output logic [DATA_WIDTH-1:0]         d_data_o,
    output logic                          d_corrupt_o,

    output logic                          valid_o,
    output logic                          write_o,
    output logic [ADDRESS_WIDTH-1:0]      addr_o,
    output logic [DATA_WIDTH-1:0]         wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     be_o,
    input  logic [DATA_WIDTH-1:0]         rdata_i,
    input  logic                          ready_i,
    input  logic                          error_i
);

    localparam integer BYTE_LANES = DATA_WIDTH / 8;
    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 :
        ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(EFFECTIVE_MAX_WAIT_CYCLES - 1);
    localparam logic [2:0] MAX_TRANSFER_SIZE = 3'($clog2(BYTE_LANES));
    localparam logic [ADDRESS_WIDTH-1:0] BYTE_LANES_COUNT = ADDRESS_WIDTH'(BYTE_LANES);

    function automatic [BYTE_LANES-1:0] transfer_mask(
        input logic [2:0] size,
        input logic [ADDRESS_WIDTH-1:0] address
    );
        integer transfer_bytes;
        integer address_offset;
        integer lane;
        begin
            transfer_bytes = 1 << size;
            address_offset = integer'(address % BYTE_LANES_COUNT);
            transfer_mask = '0;
            for (lane = 0; lane < BYTE_LANES; lane = lane + 1) begin
                if ((lane >= address_offset) &&
                    (lane < address_offset + transfer_bytes)) begin
                    transfer_mask[lane] = 1'b1;
                end
            end
        end
    endfunction

    function automatic logic address_is_aligned(
        input logic [2:0] size,
        input logic [ADDRESS_WIDTH-1:0] address
    );
        logic [ADDRESS_WIDTH-1:0] transfer_bytes;
        logic [ADDRESS_WIDTH-1:0] remainder;
        begin
            transfer_bytes = ADDRESS_WIDTH'(1) << size;
            remainder = address % transfer_bytes;
            address_is_aligned = remainder == '0;
        end
    endfunction

    logic active_q;
    logic write_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;
    logic [2:0] opcode_q;
    logic [2:0] size_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic d_valid_q;
    logic [2:0] d_opcode_q;
    logic [2:0] d_size_q;
    logic d_denied_q;
    logic [DATA_WIDTH-1:0] d_data_q;
    logic d_corrupt_q;

    wire a_take = a_valid_i && a_ready_o;
    wire supported_opcode = (a_opcode_i == 3'd0) || (a_opcode_i == 3'd1) ||
                            (a_opcode_i == 3'd4);
    wire write_opcode = (a_opcode_i == 3'd0) || (a_opcode_i == 3'd1);
    wire size_valid = a_size_i <= MAX_TRANSFER_SIZE;
    wire address_aligned = size_valid && address_is_aligned(a_size_i, a_address_i);
    wire [BYTE_LANES-1:0] expected_mask = transfer_mask(a_size_i, a_address_i);
    wire get_mask_valid = (a_opcode_i != 3'd4) || (a_mask_i == expected_mask);
    wire put_full_mask_valid = (a_opcode_i != 3'd0) || (a_mask_i == expected_mask);
    wire put_partial_mask_valid = (a_opcode_i != 3'd1) ||
                                  ((a_mask_i != '0) &&
                                   ((a_mask_i & ~expected_mask) == '0));
    wire request_malformed = !supported_opcode || a_corrupt_i || (a_param_i != 3'd0) ||
                             !size_valid || !address_aligned || (a_source_i != 1'b0) ||
                             !get_mask_valid || !put_full_mask_valid ||
                             !put_partial_mask_valid;

    assign a_ready_o = !active_q && !d_valid_q;
    assign d_valid_o = d_valid_q;
    assign d_opcode_o = d_opcode_q;
    assign d_param_o = 2'b00;
    assign d_size_o = d_size_q;
    assign d_source_o = 1'b0;
    assign d_sink_o = 1'b0;
    assign d_denied_o = d_denied_q;
    assign d_data_o = d_data_q;
    assign d_corrupt_o = d_corrupt_q;
    assign valid_o = active_q;
    assign write_o = active_q && write_q;
    assign addr_o = active_q ? addr_q : '0;
    assign wdata_o = (active_q && write_q) ? wdata_q : '0;
    assign be_o = active_q ? be_q : '0;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            active_q <= 1'b0;
            write_q <= 1'b0;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            opcode_q <= '0;
            size_q <= '0;
            wait_count_q <= '0;
            d_valid_q <= 1'b0;
            d_opcode_q <= '0;
            d_size_q <= '0;
            d_denied_q <= 1'b0;
            d_data_q <= '0;
            d_corrupt_q <= 1'b0;
        end else begin
            if (d_valid_q && d_ready_i) begin
                d_valid_q <= 1'b0;
                d_opcode_q <= '0;
                d_size_q <= '0;
                d_denied_q <= 1'b0;
                d_data_q <= '0;
                d_corrupt_q <= 1'b0;
            end

            if (active_q) begin
                if (ready_i) begin
                    active_q <= 1'b0;
                    wait_count_q <= '0;
                    d_valid_q <= 1'b1;
                    d_opcode_q <= (opcode_q == 3'd4) ? 3'd1 : 3'd0;
                    d_size_q <= size_q;
                    d_denied_q <= error_i;
                    d_data_q <= error_i ? '0 : ((opcode_q == 3'd4) ? rdata_i : '0);
                    d_corrupt_q <= error_i && (opcode_q == 3'd4);
                end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                    active_q <= 1'b0;
                    wait_count_q <= '0;
                    d_valid_q <= 1'b1;
                    d_opcode_q <= (opcode_q == 3'd4) ? 3'd1 : 3'd0;
                    d_size_q <= size_q;
                    d_denied_q <= 1'b1;
                    d_data_q <= '0;
                    d_corrupt_q <= opcode_q == 3'd4;
                end else begin
                    wait_count_q <= wait_count_q + 1'b1;
                end
            end else if (!d_valid_q && a_take) begin
                wait_count_q <= '0;
                if (request_malformed) begin
                    d_valid_q <= 1'b1;
                    d_opcode_q <= (a_opcode_i == 3'd4) ? 3'd1 : 3'd0;
                    d_size_q <= a_size_i;
                    d_denied_q <= 1'b0;
                    d_data_q <= '0;
                    d_corrupt_q <= 1'b1;
                end else begin
                    active_q <= 1'b1;
                    write_q <= write_opcode;
                    addr_q <= a_address_i;
                    wdata_q <= a_data_i;
                    be_q <= (a_opcode_i == 3'd4) ? expected_mask : a_mask_i;
                    opcode_q <= a_opcode_i;
                    size_q <= a_size_i;
                end
            end
        end
    end

endmodule
