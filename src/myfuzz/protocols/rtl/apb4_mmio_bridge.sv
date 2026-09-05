module apb4_mmio_bridge #(
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

    output logic [ADDRESS_WIDTH-1:0]      paddr_o,
    output logic [2:0]                    pprot_o,
    output logic                          psel_o,
    output logic                          penable_o,
    output logic                          pwrite_o,
    output logic [DATA_WIDTH-1:0]         pwdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     pstrb_o,
    input  logic                          pready_i,
    input  logic [DATA_WIDTH-1:0]         prdata_i,
    input  logic                          pslverr_i
);

    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 :
        ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);

    typedef enum logic [1:0] {
        IDLE,
        SETUP,
        ACCESS
    } state_t;

    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic                     write_q;
    logic [DATA_WIDTH-1:0]    wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic                     rsp_valid_q;
    logic [DATA_WIDTH-1:0]    rsp_rdata_q;
    logic                     rsp_error_q;

    assign req_ready_o = (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid_o = rsp_valid_q;
    assign rsp_rdata_o = rsp_rdata_q;
    assign rsp_error_o = rsp_error_q;

    assign paddr_o = (state_q == IDLE) ? '0 : addr_q;
    assign pprot_o = 3'b000;
    assign psel_o = (state_q == SETUP) || (state_q == ACCESS);
    assign penable_o = (state_q == ACCESS);
    assign pwrite_o = (state_q == IDLE) ? 1'b0 : write_q;
    assign pwdata_o = (state_q == IDLE) ? '0 : wdata_q;
    assign pstrb_o = (state_q == IDLE || !write_q) ? '0 : be_q;

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
                        state_q <= SETUP;
                    end
                end

                SETUP: begin
                    wait_count_q <= '0;
                    state_q <= ACCESS;
                end

                ACCESS: begin
                    if (pready_i) begin
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= write_q ? '0 : prdata_i;
                        rsp_error_q <= pslverr_i;
                        wait_count_q <= '0;
                        state_q <= IDLE;
                    end else if (wait_count_q == EFFECTIVE_MAX_WAIT_CYCLES - 1) begin
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= 1'b1;
                        wait_count_q <= '0;
                        state_q <= IDLE;
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
