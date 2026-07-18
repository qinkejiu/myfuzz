// SPDX-License-Identifier: Apache-2.0
module zipcpu_axil2apb_wrapper (
  input wire clk, input wire resetn,
  input wire s_awvalid, output wire s_awready, input wire [11:0] s_awaddr,
  input wire s_wvalid, output wire s_wready, input wire [31:0] s_wdata,
  input wire [3:0] s_wstrb, output wire s_bvalid, input wire s_bready,
  output wire [1:0] s_bresp, input wire s_arvalid, output wire s_arready,
  input wire [11:0] s_araddr, output wire s_rvalid, input wire s_rready,
  output wire [31:0] s_rdata, output wire [1:0] s_rresp
);
  wire psel, penable, pwrite;
  wire [11:0] paddr;
  wire [31:0] pwdata;
  wire [3:0] pwstrb;
  wire [2:0] pprot;
  logic [31:0] registers [0:3];
  integer index;

  always_ff @(posedge clk) begin
    if (!resetn) begin
      for (index = 0; index < 4; index = index + 1) registers[index] <= 32'b0;
    end else if (psel && penable && pwrite) begin
      if (pwstrb[0]) registers[paddr[3:2]][7:0] <= pwdata[7:0];
      if (pwstrb[1]) registers[paddr[3:2]][15:8] <= pwdata[15:8];
      if (pwstrb[2]) registers[paddr[3:2]][23:16] <= pwdata[23:16];
      if (pwstrb[3]) registers[paddr[3:2]][31:24] <= pwdata[31:24];
    end
  end

  axil2apb #(.C_AXI_ADDR_WIDTH(12), .C_AXI_DATA_WIDTH(32)) i_bridge (
    .S_AXI_ACLK(clk), .S_AXI_ARESETN(resetn),
    .S_AXI_AWVALID(s_awvalid), .S_AXI_AWREADY(s_awready),
    .S_AXI_AWADDR(s_awaddr), .S_AXI_AWPROT(3'b000),
    .S_AXI_WVALID(s_wvalid), .S_AXI_WREADY(s_wready),
    .S_AXI_WDATA(s_wdata), .S_AXI_WSTRB(s_wstrb),
    .S_AXI_BVALID(s_bvalid), .S_AXI_BREADY(s_bready), .S_AXI_BRESP(s_bresp),
    .S_AXI_ARVALID(s_arvalid), .S_AXI_ARREADY(s_arready),
    .S_AXI_ARADDR(s_araddr), .S_AXI_ARPROT(3'b000),
    .S_AXI_RVALID(s_rvalid), .S_AXI_RREADY(s_rready),
    .S_AXI_RDATA(s_rdata), .S_AXI_RRESP(s_rresp),
    .M_APB_PSEL(psel), .M_APB_PENABLE(penable), .M_APB_PREADY(1'b1),
    .M_APB_PADDR(paddr), .M_APB_PWRITE(pwrite), .M_APB_PWDATA(pwdata),
    .M_APB_PWSTRB(pwstrb), .M_APB_PPROT(pprot),
    .M_APB_PRDATA(registers[paddr[3:2]]), .M_APB_PSLVERR(1'b0)
  );
endmodule
