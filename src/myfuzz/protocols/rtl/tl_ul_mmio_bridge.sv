module tl_ul_mmio_bridge #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                          clk_i,
    input  logic                          rst_ni,

    input  logic                          req_valid_i,
    input  logic                          req_write_i,
    input  logic [ADDRESS_WIDTH-1:0]      req_addr_i,
    input  logic [DATA_WIDTH-1:0]         req_wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]     req_be_i,
    output logic                          req_ready_o,

    output logic                          rsp_valid_o,
    input  logic                          rsp_ready_i,
    output logic [DATA_WIDTH-1:0]         rsp_rdata_o,
    output logic                          rsp_error_o,

    output logic                          a_valid_o,
    input  logic                          a_ready_i,
    output logic [2:0]                    a_opcode_o,
    output logic [2:0]                    a_param_o,
    output logic [2:0]                    a_size_o,
    output logic [0:0]                    a_source_o,
    output logic [ADDRESS_WIDTH-1:0]      a_address_o,
    output logic [(DATA_WIDTH/8)-1:0]     a_mask_o,
    output logic [DATA_WIDTH-1:0]         a_data_o,
    output logic                          a_corrupt_o,

    input  logic                          d_valid_i,
    output logic                          d_ready_o,
    input  logic [2:0]                    d_opcode_i,
    input  logic [1:0]                    d_param_i,
    input  logic [2:0]                    d_size_i,
    input  logic [0:0]                    d_source_i,
    input  logic [0:0]                    d_sink_i,
    input  logic                          d_denied_i,
    input  logic [DATA_WIDTH-1:0]         d_data_i,
    input  logic                          d_corrupt_i
);

    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 :
        ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(EFFECTIVE_MAX_WAIT_CYCLES - 1);
    localparam logic [2:0] TRANSFER_SIZE = 3'($clog2(DATA_WIDTH / 8));
    localparam logic [(DATA_WIDTH/8)-1:0] FULL_MASK = {(DATA_WIDTH/8){1'b1}};

    typedef enum logic [1:0] {
        IDLE,
        A_CHANNEL,
        D_CHANNEL
    } state_t;

    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic                     write_q;
    logic [DATA_WIDTH-1:0]    wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic rsp_valid_q;
    logic [DATA_WIDTH-1:0] rsp_rdata_q;
    logic rsp_error_q;

    wire a_take = a_valid_o && a_ready_i;
    wire d_take = d_valid_i && d_ready_o;
    wire d_shape_error = (d_opcode_i != (write_q ? 3'd0 : 3'd1)) ||
                         (d_param_i != 2'b00) ||
                         (d_size_i != TRANSFER_SIZE) ||
                         (d_source_i != 1'b0) || (d_sink_i != 1'b0);
    wire d_error = d_shape_error || d_denied_i || d_corrupt_i;

    assign req_ready_o = (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid_o = rsp_valid_q;
    assign rsp_rdata_o = rsp_rdata_q;
    assign rsp_error_o = rsp_error_q;

    assign a_valid_o = (state_q == A_CHANNEL);
    assign a_opcode_o = !a_valid_o ? 3'd0 :
                        !write_q ? 3'd4 : (be_q == FULL_MASK ? 3'd0 : 3'd1);
    assign a_param_o = 3'd0;
    assign a_size_o = TRANSFER_SIZE;
    assign a_source_o = 1'b0;
    assign a_address_o = a_valid_o ? addr_q : '0;
    assign a_mask_o = !a_valid_o ? '0 : (!write_q ? FULL_MASK : be_q);
    assign a_data_o = a_valid_o ? wdata_q : '0;
    assign a_corrupt_o = 1'b0;
    assign d_ready_o = (state_q == D_CHANNEL) && !rsp_valid_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            addr_q <= '0;
            write_q <= 1'b0;
            wdata_q <= '0;
            be_q <= '0;
            wait_count_q <= '0;
            rsp_valid_q <= 1'b0;
            rsp_rdata_q <= '0;
            rsp_error_q <= 1'b0;
        end else begin
            if (rsp_valid_q && rsp_ready_i) begin
                rsp_valid_q <= 1'b0;
            end

            case (state_q)
                IDLE: begin
                    wait_count_q <= '0;
                    if (req_valid_i && !rsp_valid_q) begin
                        addr_q <= req_addr_i;
                        write_q <= req_write_i;
                        wdata_q <= req_wdata_i;
                        be_q <= req_be_i;
                        state_q <= A_CHANNEL;
                    end
                end

                A_CHANNEL: begin
                    if (a_take) begin
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
                    if (d_take) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= d_error ? '0 : (write_q ? '0 : d_data_i);
                        rsp_error_q <= d_error;
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
