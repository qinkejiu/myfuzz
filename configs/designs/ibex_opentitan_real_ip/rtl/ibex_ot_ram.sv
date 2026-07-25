module ibex_ot_ram #(
  parameter int unsigned Words = 4096,
  parameter string Image =
      "configs/designs/ibex_opentitan_real_ip/programs/mmio_exerciser.hex"
) (
  input  logic        clk_i,
  input  logic        rst_ni,

  input  logic        instr_req_i,
  input  logic [31:0] instr_addr_i,
  output logic        instr_gnt_o,
  output logic        instr_rvalid_o,
  output logic [31:0] instr_rdata_o,

  input  logic        data_req_i,
  input  logic        data_we_i,
  input  logic [3:0]  data_be_i,
  input  logic [31:0] data_addr_i,
  input  logic [31:0] data_wdata_i,
  output logic        data_gnt_o,
  output logic        data_rvalid_o,
  output logic [31:0] data_rdata_o
);
  localparam int unsigned AddrWidth = $clog2(Words);

  logic [31:0] mem [0:Words-1];
  wire [AddrWidth-1:0] instr_index = instr_addr_i[AddrWidth+1:2];
  wire [AddrWidth-1:0] data_index = data_addr_i[AddrWidth+1:2];

  initial begin
    for (int unsigned i = 0; i < Words; i++) begin
      mem[i] = 32'h0000_0013;
    end
    $readmemh(Image, mem);
  end

  assign instr_gnt_o = instr_req_i;
  assign data_gnt_o = data_req_i;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      instr_rvalid_o <= 1'b0;
      instr_rdata_o <= '0;
      data_rvalid_o <= 1'b0;
      data_rdata_o <= '0;
    end else begin
      instr_rvalid_o <= instr_req_i;
      data_rvalid_o <= data_req_i;
      if (instr_req_i) begin
        instr_rdata_o <= mem[instr_index];
      end
      if (data_req_i) begin
        data_rdata_o <= mem[data_index];
        if (data_we_i) begin
          if (data_be_i[0]) mem[data_index][7:0] <= data_wdata_i[7:0];
          if (data_be_i[1]) mem[data_index][15:8] <= data_wdata_i[15:8];
          if (data_be_i[2]) mem[data_index][23:16] <= data_wdata_i[23:16];
          if (data_be_i[3]) mem[data_index][31:24] <= data_wdata_i[31:24];
        end
      end
    end
  end
endmodule
