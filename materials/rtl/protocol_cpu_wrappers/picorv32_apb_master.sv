// PicoRV32 wrapper exposing a simple APB master interface.
module picorv32_apb_master #(
  parameter [31:0] PROGADDR_RESET = 32'h0000_0000,
  parameter [31:0] PROGADDR_IRQ   = 32'h0000_0100,
  parameter [31:0] STACKADDR      = 32'h0000_0200
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  output logic        trap_o,

  output logic        psel_o,
  output logic        penable_o,
  output logic        pwrite_o,
  output logic [31:0] paddr_o,
  output logic [31:0] pwdata_o,
  output logic [3:0]  pstrb_o,
  input  logic [31:0] prdata_i,
  input  logic        pready_i,
  input  logic        pslverr_i
);
  logic        mem_valid;
  logic        mem_ready;
  logic [31:0] mem_addr;
  logic [31:0] mem_wdata;
  logic [3:0]  mem_wstrb;
  logic [31:0] mem_rdata;

  typedef enum logic [1:0] {APB_IDLE, APB_SETUP, APB_ACCESS} apb_state_t;
  apb_state_t state_q, state_d;

  logic [31:0] paddr_q;
  logic [31:0] pwdata_q;
  logic [3:0]  pstrb_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q <= APB_IDLE;
      paddr_q <= 32'h0;
      pwdata_q <= 32'h0;
      pstrb_q <= 4'h0;
    end else begin
      state_q <= state_d;
      if (state_q == APB_IDLE && mem_valid) begin
        paddr_q <= mem_addr;
        pwdata_q <= mem_wdata;
        pstrb_q <= mem_wstrb;
      end
    end
  end

  always_comb begin
    state_d = state_q;
    unique case (state_q)
      APB_IDLE: begin
        if (mem_valid) state_d = APB_SETUP;
      end
      APB_SETUP: begin
        state_d = APB_ACCESS;
      end
      APB_ACCESS: begin
        if (pready_i && !pslverr_i) state_d = APB_IDLE;
      end
      default: state_d = APB_IDLE;
    endcase
  end

  assign psel_o    = (state_q == APB_SETUP) || (state_q == APB_ACCESS);
  assign penable_o = (state_q == APB_ACCESS);
  assign pwrite_o  = |pstrb_q;
  assign paddr_o   = paddr_q;
  assign pwdata_o  = pwdata_q;
  assign pstrb_o   = pstrb_q;
  assign mem_ready = (state_q == APB_ACCESS) && pready_i && !pslverr_i;
  assign mem_rdata = prdata_i;

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
