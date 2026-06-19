module toy_uart (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [3:0]  be_i,
    input  logic        ext_ready_i,
    input  logic        rx_valid_i,
    input  logic [7:0]  rx_data_i,
    output logic        ready_o,
    output logic        rvalid_o,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [7:0] rx_data_q;
    logic [7:0] tx_data_q;
    logic rx_pending_q;
    logic tx_busy_q;
    logic irq_enable_q;

    assign ready_o = ext_ready_i || valid_i;
    assign rvalid_o = valid_i && ready_o;
    assign irq_o = rx_pending_q && irq_enable_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            rx_data_q <= 8'h00;
            tx_data_q <= 8'h00;
            rx_pending_q <= 1'b0;
            tx_busy_q <= 1'b0;
            irq_enable_q <= 1'b0;
        end else begin
            if (rx_valid_i) begin
                rx_data_q <= rx_data_i;
                rx_pending_q <= 1'b1;
            end
            if (tx_busy_q) begin
                tx_busy_q <= 1'b0;
            end
            if (valid_i && ready_o && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: begin
                        tx_data_q <= wdata_i[7:0];
                        tx_busy_q <= 1'b1;
                    end
                    2'd1: irq_enable_q <= wdata_i[0];
                    2'd2: begin
                        if (wdata_i[0]) rx_pending_q <= 1'b0;
                    end
                    default: rx_data_q <= wdata_i[7:0];
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = {24'h0, rx_data_q};
            2'd1: rdata_o = {29'h0, irq_o, tx_busy_q, rx_pending_q};
            2'd2: rdata_o = {31'h0, irq_enable_q};
            default: rdata_o = {24'h0, tx_data_q};
        endcase
    end

    assign state_o = {irq_o, irq_enable_q, rx_pending_q, tx_busy_q, rx_data_q[3:0]};

endmodule
