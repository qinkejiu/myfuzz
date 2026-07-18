// PicoRV32 wrapper exposing an AXI4 single-beat master subset.
module picorv32_axi4_master #(
  parameter [31:0] PROGADDR_RESET = 32'h0000_0000,
  parameter [31:0] PROGADDR_IRQ   = 32'h0000_0100,
  parameter [31:0] STACKADDR      = 32'h0000_0200
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic        trap_o,

  output logic        axi_awvalid_o,
  input  logic        axi_awready_i,
  output logic [31:0] axi_awaddr_o,
  output logic [7:0]  axi_awlen_o,
  output logic [2:0]  axi_awsize_o,
  output logic [1:0]  axi_awburst_o,
  output logic        axi_wvalid_o,
  input  logic        axi_wready_i,
  output logic [31:0] axi_wdata_o,
  output logic [3:0]  axi_wstrb_o,
  output logic        axi_wlast_o,
  input  logic        axi_bvalid_i,
  output logic        axi_bready_o,
  input  logic [1:0]  axi_bresp_i,
  output logic        axi_arvalid_o,
  input  logic        axi_arready_i,
  output logic [31:0] axi_araddr_o,
  output logic [7:0]  axi_arlen_o,
  output logic [2:0]  axi_arsize_o,
  output logic [1:0]  axi_arburst_o,
  input  logic        axi_rvalid_i,
  output logic        axi_rready_o,
  input  logic [31:0] axi_rdata_i,
  input  logic [1:0]  axi_rresp_i,
  input  logic        axi_rlast_i
);
  logic        mem_valid;
  logic        mem_ready;
  logic [31:0] mem_addr;
  logic [31:0] mem_wdata;
  logic [3:0]  mem_wstrb;
  logic [31:0] mem_rdata;
  logic        is_write;

  assign is_write      = |mem_wstrb;
  assign axi_awvalid_o = mem_valid && is_write;
  assign axi_awaddr_o  = mem_addr;
  assign axi_awlen_o   = 8'h0;
  assign axi_awsize_o  = 3'd2;
  assign axi_awburst_o = 2'b01;
  assign axi_wvalid_o  = mem_valid && is_write;
  assign axi_wdata_o   = mem_wdata;
  assign axi_wstrb_o   = mem_wstrb;
  assign axi_wlast_o   = 1'b1;
  assign axi_bready_o  = 1'b1;
  assign axi_arvalid_o = mem_valid && !is_write;
  assign axi_araddr_o  = mem_addr;
  assign axi_arlen_o   = 8'h0;
  assign axi_arsize_o  = 3'd2;
  assign axi_arburst_o = 2'b01;
  assign axi_rready_o  = 1'b1;
  assign mem_ready     = is_write
                       ? (axi_awready_i && axi_wready_i && axi_bvalid_i && axi_bresp_i == 2'b00)
                       : (axi_arready_i && axi_rvalid_i && axi_rlast_i && axi_rresp_i == 2'b00);
  assign mem_rdata     = axi_rdata_i;

  picorv32 #(
    .ENABLE_COUNTERS      (1'b1),
    .ENABLE_COUNTERS64    (1'b0),
    .ENABLE_REGS_16_31    (1'b1),
    .ENABLE_REGS_DUALPORT (1'b1),
    .BARREL_SHIFTER       (1'b1),
    .COMPRESSED_ISA       (1'b1),
    .ENABLE_MUL           (1'b1),
    .ENABLE_DIV           (1'b1),
    .ENABLE_IRQ           (1'b0),
    .PROGADDR_RESET       (PROGADDR_RESET),
    .PROGADDR_IRQ         (PROGADDR_IRQ),
    .STACKADDR            (STACKADDR)
  ) u_core (
    .clk          (clk_i),
    .resetn       (rst_ni),
    .trap         (trap_o),
    .mem_valid    (mem_valid),
    .mem_instr    (),
    .mem_ready    (mem_ready),
    .mem_addr     (mem_addr),
    .mem_wdata    (mem_wdata),
    .mem_wstrb    (mem_wstrb),
    .mem_rdata    (mem_rdata),
    .mem_la_read  (),
    .mem_la_write (),
    .mem_la_addr  (),
    .mem_la_wdata (),
    .mem_la_wstrb (),
    .pcpi_valid   (),
    .pcpi_insn    (),
    .pcpi_rs1     (),
    .pcpi_rs2     (),
    .pcpi_wr      (1'b0),
    .pcpi_rd      (32'h0),
    .pcpi_wait    (1'b0),
    .pcpi_ready   (1'b0),
    .irq          (32'h0),
    .eoi          (),
    .trace_valid  (),
    .trace_data   ()
  );
endmodule
