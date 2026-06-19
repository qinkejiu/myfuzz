module ibex_mcip_ram #(
    parameter int WORDS = 64
) (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        valid_i,
    input  logic        write_i,
    input  logic [31:0] addr_i,
    input  logic [31:0] wdata_i,
    input  logic [3:0]  be_i,
    input  logic [31:0] seed_i,
    output logic [31:0] rdata_o,
    output logic [7:0]  state_o
);

    logic [31:0] mem_q [0:WORDS-1];
    logic [31:0] read_word;
    wire [$clog2(WORDS)-1:0] word_index = addr_i[$clog2(WORDS)+1:2];

    integer i;
    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            for (i = 0; i < WORDS; i = i + 1) begin
                mem_q[i] <= 32'h0000_0013 ^ seed_i ^ i[31:0];
            end
        end else if (valid_i && write_i) begin
            if (be_i[0]) mem_q[word_index][7:0]   <= wdata_i[7:0];
            if (be_i[1]) mem_q[word_index][15:8]  <= wdata_i[15:8];
            if (be_i[2]) mem_q[word_index][23:16] <= wdata_i[23:16];
            if (be_i[3]) mem_q[word_index][31:24] <= wdata_i[31:24];
        end
    end

    always_comb begin
        read_word = mem_q[word_index] ^ {addr_i[15:0], seed_i[15:0]};
        if (addr_i[1:0] != 2'b00) begin
            read_word = 32'hbad0_0001 ^ addr_i;
        end
    end

    assign rdata_o = read_word;
    assign state_o = {valid_i, write_i, be_i, word_index[1:0]};

endmodule
