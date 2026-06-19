module ibex_mcip_timer (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic        tick_i,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [31:0] counter_q;
    logic [31:0] compare_q;
    logic        enable_q;
    logic        irq_enable_q;
    logic        pending_q;

    assign irq_o = pending_q && irq_enable_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            counter_q <= 32'h0;
            compare_q <= 32'h20;
            enable_q <= 1'b1;
            irq_enable_q <= 1'b1;
            pending_q <= 1'b0;
        end else begin
            if (enable_q && tick_i) begin
                counter_q <= counter_q + 32'h1;
                if ((counter_q + 32'h1) >= compare_q) begin
                    pending_q <= 1'b1;
                end
            end
            if (valid_i && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: counter_q <= wdata_i;
                    2'd1: compare_q <= wdata_i;
                    2'd2: begin
                        enable_q <= wdata_i[0];
                        irq_enable_q <= wdata_i[1];
                    end
                    default: begin
                        if (wdata_i[0]) pending_q <= 1'b0;
                    end
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = counter_q;
            2'd1: rdata_o = compare_q;
            2'd2: rdata_o = {30'h0, irq_enable_q, enable_q};
            default: rdata_o = {31'h0, pending_q};
        endcase
    end

    assign state_o = {irq_o, pending_q, irq_enable_q, enable_q, counter_q[3:0]};

endmodule
