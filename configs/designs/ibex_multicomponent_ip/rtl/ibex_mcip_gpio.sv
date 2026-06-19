module ibex_mcip_gpio (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [15:0] pins_i,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [15:0] pins_q;
    logic [15:0] output_q;
    logic [15:0] irq_mask_q;
    logic        pending_q;

    assign irq_o = pending_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            pins_q <= 16'h0;
            output_q <= 16'h0;
            irq_mask_q <= 16'h0001;
            pending_q <= 1'b0;
        end else begin
            pins_q <= pins_i;
            if ((|(pins_i ^ pins_q)) && (|irq_mask_q)) begin
                pending_q <= 1'b1;
            end
            if (valid_i && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: output_q <= wdata_i[15:0];
                    2'd1: irq_mask_q <= wdata_i[15:0];
                    2'd2: begin
                        if (wdata_i[0]) pending_q <= 1'b0;
                    end
                    default: output_q <= output_q ^ wdata_i[15:0];
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = {16'h0, pins_q};
            2'd1: rdata_o = {16'h0, irq_mask_q};
            2'd2: rdata_o = {31'h0, pending_q};
            default: rdata_o = {16'h0, output_q};
        endcase
    end

    assign state_o = {pending_q, pins_q[2:0], output_q[3:0]};

endmodule
