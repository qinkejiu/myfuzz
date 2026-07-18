// SPDX-License-Identifier: MIT
// Expose the complete supported AXI-Lite subset and bind protection attributes.
module verilog_axi_ram_wrapper (
  input  wire        clk,
  input  wire        reset,
  input  wire        s_awvalid,
  output wire        s_awready,
  input  wire [15:0] s_awaddr,
  input  wire        s_wvalid,
  output wire        s_wready,
  input  wire [31:0] s_wdata,
  input  wire [3:0]  s_wstrb,
  output wire        s_bvalid,
  input  wire        s_bready,
  output wire [1:0]  s_bresp,
  input  wire        s_arvalid,
  output wire        s_arready,
  input  wire [15:0] s_araddr,
  output wire        s_rvalid,
  input  wire        s_rready,
  output wire [31:0] s_rdata,
  output wire [1:0]  s_rresp
);
  axil_ram #(
    .DATA_WIDTH(32),
    .ADDR_WIDTH(16)
  ) i_ram (
    .clk(clk),
    .rst(reset),
    .s_axil_awaddr(s_awaddr),
    .s_axil_awprot(3'b000),
    .s_axil_awvalid(s_awvalid),
    .s_axil_awready(s_awready),
    .s_axil_wdata(s_wdata),
    .s_axil_wstrb(s_wstrb),
    .s_axil_wvalid(s_wvalid),
    .s_axil_wready(s_wready),
    .s_axil_bresp(s_bresp),
    .s_axil_bvalid(s_bvalid),
    .s_axil_bready(s_bready),
    .s_axil_araddr(s_araddr),
    .s_axil_arprot(3'b000),
    .s_axil_arvalid(s_arvalid),
    .s_axil_arready(s_arready),
    .s_axil_rdata(s_rdata),
    .s_axil_rresp(s_rresp),
    .s_axil_rvalid(s_rvalid),
    .s_axil_rready(s_rready)
  );
endmodule
