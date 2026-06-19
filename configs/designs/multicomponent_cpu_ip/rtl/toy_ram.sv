module toy_ram (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [3:0]  be_i,
    input  logic        ext_ready_i,
    output logic        ready_o,
    output logic        rvalid_o,
    output logic [31:0] rdata_o,
    output logic [7:0]  state_o
);

    logic [31:0] mem_word_q [0:3];
    logic [31:0] last_addr_q;
    logic [1:0] index;

    assign index = addr_i[3:2];
    assign ready_o = ext_ready_i || valid_i;
    assign rvalid_o = valid_i && ready_o;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            mem_word_q[0] <= 32'h0000_0013;
            mem_word_q[1] <= 32'h0000_1013;
            mem_word_q[2] <= 32'h0000_2013;
            mem_word_q[3] <= 32'h0000_3013;
            last_addr_q <= 32'h0;
        end else begin
            if (valid_i && ready_o) begin
                last_addr_q <= addr_i;
                if (write_i) begin
                    if (be_i[0]) mem_word_q[index][7:0] <= wdata_i[7:0];
                    if (be_i[1]) mem_word_q[index][15:8] <= wdata_i[15:8];
                    if (be_i[2]) mem_word_q[index][23:16] <= wdata_i[23:16];
                    if (be_i[3]) mem_word_q[index][31:24] <= wdata_i[31:24];
                end
            end
        end
    end

    always_comb begin
        if (addr_i[1:0] != 2'b00) begin
            rdata_o = 32'h1bad_0001;
        end else if (write_i) begin
            rdata_o = wdata_i;
        end else begin
            rdata_o = mem_word_q[index] ^ {last_addr_q[15:0], addr_i[15:0]};
        end
    end

    assign state_o = {valid_i, write_i, ready_o, rvalid_o, index, addr_i[1:0]};

endmodule
