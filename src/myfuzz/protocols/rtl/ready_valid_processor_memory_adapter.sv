module ready_valid_processor_memory_adapter #(
    parameter integer ADDRESS_WIDTH = 32,
    parameter integer DATA_WIDTH = 32,
    parameter integer MAX_WAIT_CYCLES = 16
) (
    input  logic                         clk_i,
    input  logic                         rst_ni,
    input  logic                         valid_i,
    output logic                         ready_o,
    input  logic [ADDRESS_WIDTH-1:0]     addr_i,
    input  logic [DATA_WIDTH-1:0]        wdata_i,
    input  logic [(DATA_WIDTH/8)-1:0]    wstrb_i,
    output logic [DATA_WIDTH-1:0]        rdata_o,
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
    localparam integer BYTE_COUNT = DATA_WIDTH / 8;
    localparam integer WAIT_WIDTH = (MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(MAX_WAIT_CYCLES + 1);
    typedef enum logic [1:0] {IDLE, REQUEST, RESPONSE, RESPOND} state_t;
    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0] wdata_q;
    logic [BYTE_COUNT-1:0] wstrb_q;
    logic [DATA_WIDTH-1:0] rdata_q;
    logic [WAIT_WIDTH-1:0] wait_q;

    initial begin
        if (ADDRESS_WIDTH < 1 || DATA_WIDTH < 8 || DATA_WIDTH > 1024 ||
            DATA_WIDTH % 8 != 0 || (DATA_WIDTH & (DATA_WIDTH - 1)) != 0 ||
            MAX_WAIT_CYCLES < 1)
            $fatal(1, "invalid ready-valid/backend parameters");
    end

    assign ready_o = rst_ni && ((state_q == IDLE) || (state_q == RESPOND));
    assign rdata_o = (state_q == RESPOND) ? rdata_q : '0;
    assign req_valid_o = rst_ni && (state_q == REQUEST);
    assign req_write_o = |wstrb_q;
    assign req_addr_o = (state_q == REQUEST) ? addr_q : '0;
    assign req_wdata_o = (state_q == REQUEST && |wstrb_q) ? wdata_q : '0;
    assign req_be_o = (state_q == REQUEST) ? wstrb_q : '0;
    assign rsp_ready_o = rst_ni && (state_q == RESPONSE);

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            addr_q <= '0;
            wdata_q <= '0;
            wstrb_q <= '0;
            rdata_q <= '0;
            wait_q <= '0;
        end else begin
            case (state_q)
                IDLE: begin
                    if (valid_i && ready_o) begin
                        addr_q <= addr_i;
                        wdata_q <= wdata_i;
                        wstrb_q <= wstrb_i;
                        wait_q <= '0;
                        state_q <= REQUEST;
                    end
                end
                REQUEST: begin
                    if (req_valid_o && req_ready_i) begin
                        wait_q <= '0;
                        state_q <= RESPONSE;
                    end
                end
                RESPONSE: begin
                    if (rsp_valid_i && rsp_ready_o) begin
                        rdata_q <= rsp_error_i ? '0 : rsp_rdata_i;
                        state_q <= RESPOND;
                        wait_q <= '0;
                    end else if (wait_q + 1 >= MAX_WAIT_CYCLES) begin
                        rdata_q <= '0;
                        state_q <= RESPOND;
                        wait_q <= '0;
                    end else begin
                        wait_q <= wait_q + 1'b1;
                    end
                end
                RESPOND: begin
                    if (valid_i && ready_o) begin
                        addr_q <= addr_i;
                        wdata_q <= wdata_i;
                        wstrb_q <= wstrb_i;
                        wait_q <= '0;
                        state_q <= REQUEST;
                    end else begin
                        state_q <= IDLE;
                    end
                end
                default: begin
                    state_q <= IDLE;
                    rdata_q <= '0;
                    wait_q <= '0;
                end
            endcase
        end
    end
endmodule

