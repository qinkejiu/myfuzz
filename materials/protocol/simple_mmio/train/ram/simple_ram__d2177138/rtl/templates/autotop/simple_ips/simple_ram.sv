// Simple RAM module for auto_soc_top testing
// 简单的单端口RAM，用于第一阶段测试

module simple_ram #(
  parameter int ADDR_WIDTH = 12,  // 4KB default
  parameter int DATA_WIDTH = 32
) (
  input  logic                  clk_i,
  input  logic                  rst_ni,

  // Simple bus interface
  input  logic                  req_i,
  input  logic                  we_i,
  input  logic [31:0]           addr_i,
  input  logic [DATA_WIDTH-1:0] wdata_i,
  output logic [DATA_WIDTH-1:0] rdata_o
);

  localparam int DEPTH = 2**ADDR_WIDTH;

  // RAM storage
  logic [DATA_WIDTH-1:0] mem [DEPTH];

  // Word-aligned address
  logic [ADDR_WIDTH-1:0] word_addr;
  assign word_addr = addr_i[ADDR_WIDTH+1:2];

  // Read/Write logic
  always_ff @(posedge clk_i) begin
    if (req_i) begin
      if (we_i) begin
        mem[word_addr] <= wdata_i;
      end
      rdata_o <= mem[word_addr];
    end
  end

endmodule
