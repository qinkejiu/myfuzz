module toy_timer (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [3:0]  be_i,
    input  logic        ext_ready_i,
    input  logic        tick_i,
    output logic        ready_o,
    output logic        rvalid_o,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [15:0] counter_q;
    logic [15:0] compare_q;
    logic enable_q;
    logic irq_enable_q;
    logic pending_q;

    assign ready_o = ext_ready_i || valid_i;
    assign rvalid_o = valid_i && ready_o;
    assign irq_o = pending_q && irq_enable_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            counter_q <= 16'h0;
            compare_q <= 16'h0010;
            enable_q <= 1'b1;
            irq_enable_q <= 1'b0;
            pending_q <= 1'b0;
        end else begin
            if (enable_q && tick_i) begin
                counter_q <= counter_q + 16'h1;
                if (counter_q >= compare_q) begin
                    pending_q <= 1'b1;
                end
            end
            if (valid_i && ready_o && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: begin
                        if (be_i[0]) enable_q <= wdata_i[0];
                        if (be_i[1]) irq_enable_q <= wdata_i[8];
                    end
                    2'd1: compare_q <= wdata_i[15:0];
                    2'd2: begin
                        if (wdata_i[0]) pending_q <= 1'b0;
                    end
                    default: counter_q <= wdata_i[15:0];
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = {14'h0, pending_q, irq_enable_q, 15'h0, enable_q};
            2'd1: rdata_o = {16'h0, compare_q};
            2'd2: rdata_o = {31'h0, pending_q};
            default: rdata_o = {16'h0, counter_q};
        endcase
    end

    assign state_o = {enable_q, irq_enable_q, pending_q, irq_o, counter_q[3:0]};

endmodule
