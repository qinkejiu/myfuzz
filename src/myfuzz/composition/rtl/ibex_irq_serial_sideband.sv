// Passive RVFI sideband for the pinned Ibex controller and RVFI pipeline.
module ibex_irq_serial_sideband #(
  parameter bit WritebackStage = 1'b0
) (
  input  logic clk_i,
  input  logic rst_ni,
  input  logic external_decision_i,
  input  logic any_irq_pc_decision_i,
  input  logic instr_first_cycle_id_i,
  input  logic rvfi_id_done_i,
  input  logic rvfi_wb_done_i,
  input  logic rvfi_valid_i,
  input  logic rvfi_intr_i,
  output logic [63:0] decision_serial_o,
  output logic [63:0] retirement_serial_o
);
  logic [63:0] sequence_q;
  logic [63:0] pending_q;
  logic [63:0] intr_q;
  logic [63:0] stage_id_q;
  logic [63:0] stage_wb_q;
  logic [63:0] intr_d;

  // Zero means that no external source has a provable lineage. Saturation
  // prevents a later decision from reusing a serial within one reset epoch.
  assign decision_serial_o = external_decision_i && sequence_q != '1
                           ? sequence_q + 64'd1 : 64'd0;
  assign intr_d = instr_first_cycle_id_i ? pending_q : intr_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sequence_q <= '0;
      pending_q <= '0;
      intr_q <= '0;
      stage_id_q <= '0;
      stage_wb_q <= '0;
    end else begin
      if (external_decision_i) sequence_q <= sequence_q == '1 ? sequence_q : sequence_q + 64'd1;
      // Mirrors Ibex rvfi_set_trap_pc_d priority. Any later IRQ PC
      // decision replaces the source, including NMI/fast/timer/software.
      if (any_irq_pc_decision_i) pending_q <= decision_serial_o;
      else if (rvfi_id_done_i) pending_q <= '0;
      intr_q <= intr_d;
      if (rvfi_id_done_i) stage_id_q <= intr_d;
      if (WritebackStage && rvfi_wb_done_i) stage_wb_q <= stage_id_q;
    end
  end

  assign retirement_serial_o = rvfi_valid_i && rvfi_intr_i
                             ? (WritebackStage ? stage_wb_q : stage_id_q) : 64'd0;
endmodule
