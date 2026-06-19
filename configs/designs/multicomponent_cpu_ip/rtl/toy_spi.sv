module toy_spi (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [3:0]  be_i,
    input  logic        ext_ready_i,
    input  logic        miso_valid_i,
    input  logic [7:0]  miso_data_i,
    output logic        ready_o,
    output logic        rvalid_o,
    output logic [31:0] rdata_o,
    output logic        irq_o,
    output logic [7:0]  state_o
);

    logic [7:0] shift_q;
    logic [3:0] bit_count_q;
    logic enable_q;
    logic done_q;
    logic irq_enable_q;

    assign ready_o = ext_ready_i || valid_i;
    assign rvalid_o = valid_i && ready_o;
    assign irq_o = done_q && irq_enable_q;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            shift_q <= 8'h00;
            bit_count_q <= 4'h0;
            enable_q <= 1'b0;
            done_q <= 1'b0;
            irq_enable_q <= 1'b0;
        end else begin
            if (enable_q && miso_valid_i) begin
                shift_q <= {shift_q[6:0], miso_data_i[0]};
                bit_count_q <= bit_count_q + 4'h1;
                if (bit_count_q == 4'h7) begin
                    done_q <= 1'b1;
                end
            end
            if (valid_i && ready_o && write_i) begin
                unique case (addr_i[3:2])
                    2'd0: begin
                        shift_q <= wdata_i[7:0];
                        bit_count_q <= 4'h0;
                        done_q <= 1'b0;
                    end
                    2'd1: begin
                        enable_q <= wdata_i[0];
                        irq_enable_q <= wdata_i[1];
                    end
                    2'd2: begin
                        if (wdata_i[0]) done_q <= 1'b0;
                    end
                    default: shift_q <= shift_q ^ miso_data_i;
                endcase
            end
        end
    end

    always_comb begin
        unique case (addr_i[3:2])
            2'd0: rdata_o = {24'h0, shift_q};
            2'd1: rdata_o = {27'h0, irq_o, done_q, irq_enable_q, enable_q};
            2'd2: rdata_o = {28'h0, bit_count_q};
            default: rdata_o = {24'h0, miso_data_i};
        endcase
    end

    assign state_o = {irq_o, done_q, enable_q, bit_count_q, shift_q[0]};

endmodule
