// PicoRV32 wrapper exposing a compact TL-UL-like master interface.
module picorv32_tlul_master #(
  parameter [31:0] PROGADDR_RESET = 32'h0000_0000,
  parameter [31:0] PROGADDR_IRQ   = 32'h0000_0100,
  parameter [31:0] STACKADDR      = 32'h0000_0200
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic        trap_o,

  output logic        tl_valid_o,
  output logic        tl_write_o,
  output logic [31:0] tl_addr_o,
  output logic [31:0] tl_wdata_o,
  output logic [3:0]  tl_wmask_o,
  input  logic        tl_ready_i,
  input  logic        tl_rvalid_i,
  input  logic [31:0] tl_rdata_i,
  input  logic        tl_error_i
);
  logic        mem_valid;
  logic        mem_ready;
  logic [31:0] mem_addr;
  logic [31:0] mem_wdata;
  logic [3:0]  mem_wstrb;
  logic [31:0] mem_rdata;

  assign tl_valid_o = mem_valid;
  assign tl_write_o = |mem_wstrb;
  assign tl_addr_o  = mem_addr;
  assign tl_wdata_o = mem_wdata;
  assign tl_wmask_o = mem_wstrb;
  assign mem_ready  = mem_valid && tl_ready_i && tl_rvalid_i && !tl_error_i;
  assign mem_rdata  = tl_rdata_i;

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
