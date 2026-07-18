// SPDX-License-Identifier: Apache-2.0
module zipcpu_axilempty_wrapper (
  input wire clk, input wire resetn,
  input wire s_awvalid, output wire s_awready, input wire [3:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output wire s_bvalid, input wire s_bready,
  output wire [1:0] s_bresp, input wire s_arvalid, output wire s_arready,
  input wire [3:0] s_araddr, output wire s_rvalid, input wire s_rready,
  output wire [31:0] s_rdata, output wire [1:0] s_rresp
);
  wire unused_request = ^{s_awaddr, s_wdata, s_wstrb, s_araddr};
  axilempty #(.C_AXI_ADDR_WIDTH(4), .OPT_SKIDBUFFER(1'b1)) i_empty (
    .S_AXI_ACLK(clk), .S_AXI_ARESETN(resetn),
    .S_AXI_AWVALID(s_awvalid), .S_AXI_AWREADY(s_awready),
    .S_AXI_WVALID(s_wvalid), .S_AXI_WREADY(s_wready),
    .S_AXI_BVALID(s_bvalid), .S_AXI_BREADY(s_bready), .S_AXI_BRESP(s_bresp),
    .S_AXI_ARVALID(s_arvalid), .S_AXI_ARREADY(s_arready),
    .S_AXI_RVALID(s_rvalid), .S_AXI_RREADY(s_rready),
    .S_AXI_RDATA(s_rdata), .S_AXI_RRESP(s_rresp)
  );
endmodule
