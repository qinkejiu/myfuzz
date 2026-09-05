module axi4_lite_mmio_bridge #(
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

    output logic [ADDRESS_WIDTH-1:0]      awaddr_o,
    output logic [2:0]                    awprot_o,
    output logic                          awvalid_o,
    input  logic                          awready_i,
    output logic [DATA_WIDTH-1:0]         wdata_o,
    output logic [(DATA_WIDTH/8)-1:0]     wstrb_o,
    output logic                          wvalid_o,
    input  logic                          wready_i,
    input  logic [1:0]                    bresp_i,
    input  logic                          bvalid_i,
    output logic                          bready_o,
    output logic [ADDRESS_WIDTH-1:0]      araddr_o,
    output logic [2:0]                    arprot_o,
    output logic                          arvalid_o,
    input  logic                          arready_i,
    input  logic [DATA_WIDTH-1:0]         rdata_i,
    input  logic [1:0]                    rresp_i,
    input  logic                          rvalid_i,
    output logic                          rready_o
);

    localparam integer EFFECTIVE_MAX_WAIT_CYCLES =
        (MAX_WAIT_CYCLES < 1) ? 1 :
        ((MAX_WAIT_CYCLES > 16) ? 16 : MAX_WAIT_CYCLES);
    localparam integer WAIT_COUNTER_WIDTH =
        (EFFECTIVE_MAX_WAIT_CYCLES <= 1) ? 1 : $clog2(EFFECTIVE_MAX_WAIT_CYCLES);
    localparam logic [WAIT_COUNTER_WIDTH-1:0] WAIT_TIMEOUT_VALUE =
        WAIT_COUNTER_WIDTH'(EFFECTIVE_MAX_WAIT_CYCLES - 1);

    typedef enum logic [2:0] {
        IDLE,
        WRITE_CHANNELS,
        WRITE_RESPONSE,
        READ_ADDRESS,
        READ_RESPONSE
    } state_t;

    state_t state_q;
    logic [ADDRESS_WIDTH-1:0] addr_q;
    logic [DATA_WIDTH-1:0]    wdata_q;
    logic [(DATA_WIDTH/8)-1:0] be_q;
    logic aw_done_q;
    logic w_done_q;
    logic [WAIT_COUNTER_WIDTH-1:0] wait_count_q;
    logic rsp_valid_q;
    logic [DATA_WIDTH-1:0] rsp_rdata_q;
    logic rsp_error_q;

    wire aw_take = awvalid_o && awready_i;
    wire w_take = wvalid_o && wready_i;

    assign req_ready_o = (state_q == IDLE) && !rsp_valid_q;
    assign rsp_valid_o = rsp_valid_q;
    assign rsp_rdata_o = rsp_rdata_q;
    assign rsp_error_o = rsp_error_q;

    assign awaddr_o = (state_q == WRITE_CHANNELS) ? addr_q : '0;
    assign awprot_o = 3'b000;
    assign awvalid_o = (state_q == WRITE_CHANNELS) && !aw_done_q;
    assign wdata_o = (state_q == WRITE_CHANNELS) ? wdata_q : '0;
    assign wstrb_o = (state_q == WRITE_CHANNELS) ? be_q : '0;
    assign wvalid_o = (state_q == WRITE_CHANNELS) && !w_done_q;
    assign bready_o = (state_q == WRITE_RESPONSE) && !rsp_valid_q;
    assign araddr_o = (state_q == READ_ADDRESS) ? addr_q : '0;
    assign arprot_o = 3'b000;
    assign arvalid_o = (state_q == READ_ADDRESS);
    assign rready_o = (state_q == READ_RESPONSE) && !rsp_valid_q;

    always_ff @(posedge clk_i) begin
        if (!rst_ni) begin
            state_q <= IDLE;
            addr_q <= '0;
            wdata_q <= '0;
            be_q <= '0;
            aw_done_q <= 1'b0;
            w_done_q <= 1'b0;
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
                    aw_done_q <= 1'b0;
                    w_done_q <= 1'b0;
                    if (req_valid_i && !rsp_valid_q) begin
                        addr_q <= req_addr_i;
                        wdata_q <= req_wdata_i;
                        be_q <= req_be_i;
                        if (req_write_i) begin
                            state_q <= WRITE_CHANNELS;
                        end else begin
                            state_q <= READ_ADDRESS;
                        end
                    end
                end

                WRITE_CHANNELS: begin
                    if (aw_take) begin
                        aw_done_q <= 1'b1;
                    end
                    if (w_take) begin
                        w_done_q <= 1'b1;
                    end
                    if ((aw_done_q || aw_take) && (w_done_q || w_take)) begin
                        state_q <= WRITE_RESPONSE;
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

                WRITE_RESPONSE: begin
                    if (bvalid_i && !rsp_valid_q) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= '0;
                        rsp_error_q <= (bresp_i != 2'b00);
                    end else if (!rsp_valid_q) begin
                        if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                            state_q <= IDLE;
                            wait_count_q <= '0;
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            wait_count_q <= wait_count_q + 1'b1;
                        end
                    end
                end

                READ_ADDRESS: begin
                    if (arready_i) begin
                        state_q <= READ_RESPONSE;
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

                READ_RESPONSE: begin
                    if (rvalid_i && !rsp_valid_q) begin
                        state_q <= IDLE;
                        wait_count_q <= '0;
                        rsp_valid_q <= 1'b1;
                        rsp_rdata_q <= rdata_i;
                        rsp_error_q <= (rresp_i != 2'b00);
                    end else if (!rsp_valid_q) begin
                        if (wait_count_q == WAIT_TIMEOUT_VALUE) begin
                            state_q <= IDLE;
                            wait_count_q <= '0;
                            rsp_valid_q <= 1'b1;
                            rsp_rdata_q <= '0;
                            rsp_error_q <= 1'b1;
                        end else begin
                            wait_count_q <= wait_count_q + 1'b1;
                        end
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
