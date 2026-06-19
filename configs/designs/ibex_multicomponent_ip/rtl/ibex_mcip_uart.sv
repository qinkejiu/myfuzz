module ibex_mcip_uart (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic        rx_valid_i,
    input  logic [7:0]  rx_data_i,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [7:0] rx_q;
    logic [7:0] tx_q;
    logic       rx_pending_q;
    logic       irq_enable_q;

    assign irq_o = rx_pending_q && irq_enable_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            rx_q <= 8'h0;
            tx_q <= 8'h0;
            rx_pending_q <= 1'b0;
            irq_enable_q <= 1'b1;
        end else begin
            if (rx_valid_i) begin
                rx_q <= rx_data_i;
                rx_pending_q <= 1'b1;
            end
            if (valid_i && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: begin
                        tx_q <= wdata_i[7:0];
                    end
                    2'd1: begin
                        irq_enable_q <= wdata_i[0];
                    end
                    2'd2: begin
                        if (wdata_i[0]) rx_pending_q <= 1'b0;
                    end
                    default: begin
                        tx_q <= tx_q ^ wdata_i[7:0];
                    end
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = {24'h0, rx_q};
            2'd1: rdata_o = {30'h0, irq_enable_q, rx_pending_q};
            2'd2: rdata_o = {24'h0, tx_q};
            default: rdata_o = {16'h0, tx_q, rx_q};
        endcase
    end

    assign state_o = {irq_o, irq_enable_q, rx_pending_q, rx_q[4:0]};

endmodule
