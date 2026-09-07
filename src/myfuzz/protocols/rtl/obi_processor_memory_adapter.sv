module obi_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer READ_ONLY = 0,
    parameter integer HAS_BE = 0,
    parameter integer HAS_ERROR = 1
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic                         req_i,
    output logic                         gnt_o,
    input  logic [ADDRESS_WIDTH-1:0]     addr_i,
    input  logic                         we_i,
    input  logic [DATA_WIDTH-1:0]        wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]    be_i,
    output logic                         rvalid_o,
    output logic [DATA_WIDTH-1:0]        rdata_o,
    output logic                         error_o,
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
            $fatal(1, "invalid OBI/backend address or data width");
        if ((READ_ONLY != 0 && READ_ONLY != 1) ||
            (HAS_BE != 0 && HAS_BE != 1) ||
            (HAS_ERROR != 0 && HAS_ERROR != 1))
            $fatal(1, "OBI feature parameters must be boolean");
    end

    localparam logic [(DATA_WIDTH/8)-1:0] FULL_BE = {(DATA_WIDTH/8){1'b1}};
    typedef enum logic {IDLE, WAIT_RESPONSE} state_t;
    state_t state_q;
    logic rvalid_q, error_q;
    logic [DATA_WIDTH-1:0] rdata_q;

    assign req_valid_o = rst_ni && (state_q == IDLE) && req_i;
    assign gnt_o = req_valid_o && req_ready_i;
    assign req_write_o = (READ_ONLY == 0) && we_i;
    assign req_addr_o = req_valid_o ? addr_i : '0;
    assign req_wdata_o = (req_valid_o && (READ_ONLY == 0)) ? wdata_i : '0;
    assign req_be_o = (READ_ONLY != 0) ? FULL_BE :
                      ((HAS_BE != 0) ? be_i : FULL_BE);
    assign rsp_ready_o = rst_ni && (state_q == WAIT_RESPONSE);
    assign rvalid_o = rvalid_q;
    assign rdata_o = rdata_q;
    assign error_o = (HAS_ERROR != 0) && error_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            rvalid_q <= 1'b0;
            rdata_q <= '0;
            error_q <= 1'b0;
        end else begin
            rvalid_q <= 1'b0;
            error_q <= 1'b0;
            case (state_q)
                IDLE: begin
                    if (req_valid_o && req_ready_i)
                        state_q <= WAIT_RESPONSE;
                end
                WAIT_RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        state_q <= IDLE;
                        rvalid_q <= 1'b1;
                        rdata_q <= rsp_rdata_i;
                        error_q <= rsp_error_i;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    rvalid_q <= 1'b1;
                    rdata_q <= '0;
                    error_q <= 1'b1;
                end
            endcase
        end
    end
endmodule
