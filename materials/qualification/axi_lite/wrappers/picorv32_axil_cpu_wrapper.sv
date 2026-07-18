// SPDX-License-Identifier: ISC
// Port-only qualification wrapper around upstream picorv32_axi.
module picorv32_axil_cpu_wrapper (
  input  wire        clk,
  input  wire        resetn,
  input  wire [31:0] fuzz_irq,
  output wire        m_awvalid,
  input  wire        m_awready,
  output wire [31:0] m_awaddr,
  output wire        m_wvalid,
  input  wire        m_wready,
  output wire [31:0] m_wdata,
  output wire [3:0]  m_wstrb,
  input  wire        m_bvalid,
  output wire        m_bready,
  input  wire [1:0]  m_bresp,
  output wire        m_arvalid,
  input  wire        m_arready,
  output wire [31:0] m_araddr,
  input  wire        m_rvalid,
  output wire        m_rready,
  input  wire [31:0] m_rdata,
  input  wire [1:0]  m_rresp
);
  wire trap;
  wire [31:0] pcpi_insn, pcpi_rs1, pcpi_rs2, eoi;
  wire pcpi_valid, trace_valid;
  wire [35:0] trace_data;
  wire unused_response = ^{m_bresp, m_rresp};

  picorv32_axi #(
    .ENABLE_PCPI(1'b0),
    .ENABLE_IRQ(1'b1),
    .ENABLE_TRACE(1'b0)
  ) i_cpu (
    .clk(clk),
    .resetn(resetn),
    .trap(trap),
    .mem_axi_awvalid(m_awvalid),
    .mem_axi_awready(m_awready),
    .mem_axi_awaddr(m_awaddr),
    .mem_axi_awprot(),
    .mem_axi_wvalid(m_wvalid),
    .mem_axi_wready(m_wready),
    .mem_axi_wdata(m_wdata),
    .mem_axi_wstrb(m_wstrb),
    .mem_axi_bvalid(m_bvalid),
    .mem_axi_bready(m_bready),
    .mem_axi_arvalid(m_arvalid),
    .mem_axi_arready(m_arready),
    .mem_axi_araddr(m_araddr),
    .mem_axi_arprot(),
    .mem_axi_rvalid(m_rvalid),
    .mem_axi_rready(m_rready),
    .mem_axi_rdata(m_rdata),
    .pcpi_valid(pcpi_valid),
    .pcpi_insn(pcpi_insn),
    .pcpi_rs1(pcpi_rs1),
    .pcpi_rs2(pcpi_rs2),
    .pcpi_wr(1'b0),
    .pcpi_rd(32'b0),
    .pcpi_wait(1'b0),
    .pcpi_ready(1'b0),
    .irq(fuzz_irq),
    .eoi(eoi),
    .trace_valid(trace_valid),
    .trace_data(trace_data)
  );
endmodule
