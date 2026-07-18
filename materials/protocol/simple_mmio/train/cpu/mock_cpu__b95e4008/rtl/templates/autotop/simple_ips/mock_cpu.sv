// Mock CPU for testing auto_soc_top framework
// 这是一个最小的"CPU"，只有简单的总线接口

module mock_cpu (
  input  logic        clk_i,
  input  logic        rst_ni,

  // Data bus master interface
  output logic [31:0] data_addr_o,
  output logic [31:0] data_wdata_o,
  input  logic [31:0] data_rdata_i,
  output logic        data_we_o,
  output logic        data_req_o,
  input  logic        data_gnt_i
);

  // Simple counter that generates addresses
  logic [31:0] counter;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      counter <= 32'h0;
    end else begin
      counter <= counter + 1'b1;
    end
  end

  // Simple bus driver
  assign data_addr_o  = {counter[15:0], 16'h0000};
  assign data_wdata_o = counter;
  assign data_we_o    = counter[0];
  assign data_req_o   = 1'b1;

endmodule
