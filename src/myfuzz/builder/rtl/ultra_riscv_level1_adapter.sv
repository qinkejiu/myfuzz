// SPDX-License-Identifier: BSD-3-Clause
// Experiment-only adapter exposing the upstream TCM loader target.
module ultra_riscv_level1_adapter #(
  parameter [31:0] RESET_VECTOR = 32'h0000_2000
) (
  input  wire        clk,
  input  wire        reset,
  input  wire        cpu_reset,
  input  wire [31:0] fuzz_irq,
  output wire        m_awvalid, input wire m_awready, output wire [31:0] m_awaddr,
  output wire        m_wvalid, input wire m_wready, output wire [31:0] m_wdata,
  output wire [3:0]  m_wstrb, input wire m_bvalid, output wire m_bready,
  input  wire [1:0]  m_bresp, output wire m_arvalid, input wire m_arready,
  output wire [31:0] m_araddr, input wire m_rvalid, output wire m_rready,
  input  wire [31:0] m_rdata, input wire [1:0] m_rresp,

  input  wire        loader_awvalid, output wire loader_awready,
  input  wire [31:0] loader_awaddr, input wire [3:0] loader_awid,
  input  wire [7:0]  loader_awlen, input wire [1:0] loader_awburst,
  input  wire        loader_wvalid, output wire loader_wready,
  input  wire [31:0] loader_wdata, input wire [3:0] loader_wstrb,
  input  wire        loader_wlast, output wire loader_bvalid,
  input  wire        loader_bready, output wire [1:0] loader_bresp,
  output wire [3:0]  loader_bid, input wire loader_arvalid,
  output wire        loader_arready, input wire [31:0] loader_araddr,
  input  wire [3:0]  loader_arid, input wire [7:0] loader_arlen,
  input  wire [1:0]  loader_arburst, output wire loader_rvalid,
  input  wire        loader_rready, output wire [31:0] loader_rdata,
  output wire [1:0]  loader_rresp, output wire [3:0] loader_rid,
  output wire        loader_rlast
);
  riscv_tcm_top #(.BOOT_VECTOR(RESET_VECTOR), .TCM_MEM_BASE(32'h0000_0000)) i_cpu (
    .clk_i(clk), .rst_i(reset), .rst_cpu_i(cpu_reset),
    .axi_i_awready_i(m_awready), .axi_i_wready_i(m_wready),
    .axi_i_bvalid_i(m_bvalid), .axi_i_bresp_i(m_bresp),
    .axi_i_arready_i(m_arready), .axi_i_rvalid_i(m_rvalid),
    .axi_i_rdata_i(m_rdata), .axi_i_rresp_i(m_rresp),
    .axi_i_awvalid_o(m_awvalid), .axi_i_awaddr_o(m_awaddr),
    .axi_i_wvalid_o(m_wvalid), .axi_i_wdata_o(m_wdata), .axi_i_wstrb_o(m_wstrb),
    .axi_i_bready_o(m_bready), .axi_i_arvalid_o(m_arvalid),
    .axi_i_araddr_o(m_araddr), .axi_i_rready_o(m_rready),
    .axi_t_awvalid_i(loader_awvalid), .axi_t_awaddr_i(loader_awaddr),
    .axi_t_awid_i(loader_awid), .axi_t_awlen_i(loader_awlen),
    .axi_t_awburst_i(loader_awburst), .axi_t_wvalid_i(loader_wvalid),
    .axi_t_wdata_i(loader_wdata), .axi_t_wstrb_i(loader_wstrb),
    .axi_t_wlast_i(loader_wlast), .axi_t_bready_i(loader_bready),
    .axi_t_arvalid_i(loader_arvalid), .axi_t_araddr_i(loader_araddr),
    .axi_t_arid_i(loader_arid), .axi_t_arlen_i(loader_arlen),
    .axi_t_arburst_i(loader_arburst), .axi_t_rready_i(loader_rready),
    .axi_t_awready_o(loader_awready), .axi_t_wready_o(loader_wready),
    .axi_t_bvalid_o(loader_bvalid), .axi_t_bresp_o(loader_bresp),
    .axi_t_bid_o(loader_bid), .axi_t_arready_o(loader_arready),
    .axi_t_rvalid_o(loader_rvalid), .axi_t_rdata_o(loader_rdata),
    .axi_t_rresp_o(loader_rresp), .axi_t_rid_o(loader_rid),
    .axi_t_rlast_o(loader_rlast), .intr_i(fuzz_irq)
  );
endmodule
