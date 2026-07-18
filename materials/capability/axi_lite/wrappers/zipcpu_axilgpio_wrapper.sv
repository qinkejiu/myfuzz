// SPDX-License-Identifier: Apache-2.0
// Capability wrapper around upstream axilgpio. External GPIO inputs are tied low.
module zipcpu_axilgpio_wrapper (
  input  wire        clk,
  input  wire        resetn,
  input  wire        s_awvalid,
  output wire        s_awready,
  input  wire [4:0]  s_awaddr,
  input  wire        s_wvalid,
  output wire        s_wready,
  input  wire [31:0] s_wdata,
  input  wire [3:0]  s_wstrb,
  output wire        s_bvalid,
  input  wire        s_bready,
  output wire [1:0]  s_bresp,
  input  wire        s_arvalid,
  output wire        s_arready,
  input  wire [4:0]  s_araddr,
  output wire        s_rvalid,
  input  wire        s_rready,
  output wire [31:0] s_rdata,
  output wire [1:0]  s_rresp
);
  wire [31:0] gpio_out;
  wire gpio_irq;
  wire unused_observation = ^{gpio_out, gpio_irq};

  axilgpio #(
    .C_AXI_ADDR_WIDTH(5),
    .OPT_SKIDBUFFER(1'b1),
    .NOUT(32),
    .NIN(32)
  ) i_gpio (
    .S_AXI_ACLK(clk),
    .S_AXI_ARESETN(resetn),
    .S_AXI_AWVALID(s_awvalid),
    .S_AXI_AWREADY(s_awready),
    .S_AXI_AWADDR(s_awaddr),
    .S_AXI_AWPROT(3'b000),
    .S_AXI_WVALID(s_wvalid),
    .S_AXI_WREADY(s_wready),
    .S_AXI_WDATA(s_wdata),
    .S_AXI_WSTRB(s_wstrb),
    .S_AXI_BVALID(s_bvalid),
    .S_AXI_BREADY(s_bready),
    .S_AXI_BRESP(s_bresp),
    .S_AXI_ARVALID(s_arvalid),
    .S_AXI_ARREADY(s_arready),
    .S_AXI_ARADDR(s_araddr),
    .S_AXI_ARPROT(3'b000),
    .S_AXI_RVALID(s_rvalid),
    .S_AXI_RREADY(s_rready),
    .S_AXI_RDATA(s_rdata),
    .S_AXI_RRESP(s_rresp),
    .o_gpio(gpio_out),
    .i_gpio(32'b0),
    .o_int(gpio_irq)
  );
endmodule
