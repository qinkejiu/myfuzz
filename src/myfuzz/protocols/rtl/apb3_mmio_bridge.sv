module apb3_mmio_bridge #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input logic clk_i, rst_ni,
    input logic req_valid_i, req_write_i,
    input logic [ADDRESS_WIDTH-1:0] req_addr_i,
    input logic [DATA_WIDTH-1:0] req_wdata_i,
    input logic [(DATA_WIDTH/8)-1:0] req_be_i,
    output logic req_ready_o,
    output logic rsp_valid_o,
    input logic rsp_ready_i,
    output logic [DATA_WIDTH-1:0] rsp_rdata_o,
    output logic rsp_error_o,
    output logic [ADDRESS_WIDTH-1:0] paddr_o,
    output logic psel_o, penable_o, pwrite_o,
    output logic [DATA_WIDTH-1:0] pwdata_o,
    input logic pready_i,
    input logic [DATA_WIDTH-1:0] prdata_i,
    input logic pslverr_i
);
    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH % 8 != 0)
            $fatal(1, "invalid MMIO address/data width");
        if (MAX_WAIT_CYCLES < 1 || MAX_WAIT_CYCLES > 16)
            $fatal(1, "MAX_WAIT_CYCLES must be in [1,16]");
    end
    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 : ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(EFFECTIVE_MAX_WAIT_CYCLES - 1);
    localparam logic [(DATA_WIDTH/8)-1:0] FULL_BE = {(DATA_WIDTH/8){1'b1}};
    typedef enum logic [1:0] { IDLE, SETUP, ACCESS } state_t;
    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic write_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic rsp_valid_q, rsp_error_q;
    logic [DATA_WIDTH-1:0] rsp_rdata_q;

    assign req_ready_o = (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid_o = rsp_valid_q;
    assign rsp_rdata_o = rsp_rdata_q;
    assign rsp_error_o = rsp_error_q;
    assign paddr_o = (state_q == IDLE) ? '0 : addr_q;
    assign psel_o = (state_q == SETUP) || (state_q == ACCESS);
    assign penable_o = (state_q == ACCESS);
    assign pwrite_o = psel_o && write_q;
    assign pwdata_o = (state_q == IDLE) ? '0 : wdata_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE; addr_q <= '0; write_q <= 1'b0; wdata_q <= '0;
            wait_count_q <= '0; rsp_valid_q <= 1'b0; rsp_rdata_q <= '0; rsp_error_q <= 1'b0;
        end else begin
            if (rsp_valid_q && rsp_ready_i) rsp_valid_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    wait_count_q <= '0;
                    if (req_valid_i && !rsp_valid_q) begin
                        if (req_write_i && (req_be_i != FULL_BE)) begin
                            rsp_valid_q <= 1'b1; rsp_rdata_q <= '0; rsp_error_q <= 1'b1;
                        end else begin
                            addr_q <= req_addr_i; write_q <= req_write_i; wdata_q <= req_wdata_i;
                            state_q <= SETUP;
                        end
                    end
                end
                SETUP: state_q <= ACCESS;
                ACCESS: begin
                    if (pready_i) begin
                        state_q <= IDLE; wait_count_q <= '0; rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= pslverr_i ? '0 : (write_q ? '0 : prdata_i);
                        rsp_error_q <= pslverr_i;
                    end else if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                        state_q <= IDLE; wait_count_q <= '0; rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0; rsp_error_q <= 1'b1;
                    end else wait_count_q <= wait_count_q + 1'b1;
                end
                default: begin
                    state_q <= IDLE; wait_count_q <= '0; rsp_valid_q <= 1'b1;
                    rsp_rdata_q <= '0; rsp_error_q <= 1'b1;
                end
            endcase
        end
    end
endmodule
