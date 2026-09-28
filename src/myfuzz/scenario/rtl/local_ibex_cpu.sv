`default_nettype none

// Ibex alone: the host supplies independent OBI-compatible memory responses.
module local_ibex_cpu (
  input logic clk, reset,
  input logic [1:0] irq,
  output logic instr_req_valid,
  input logic instr_req_ready,
  output logic instr_write,
  output logic [31:0] instr_addr, instr_wdata,
  output logic [3:0] instr_be,
  input logic instr_rsp_valid,
  output logic instr_rsp_ready,
  input logic [31:0] instr_rdata,
  input logic instr_error,
  output logic data_req_valid,
  input logic data_req_ready,
  output logic data_write,
  output logic [31:0] data_addr, data_wdata,
  output logic [3:0] data_be,
  input logic data_rsp_valid,
  output logic data_rsp_ready,
  input logic [31:0] data_rdata,
  input logic data_error,
  output logic [1:0] startup_priv,
  output logic irq_masked_pre,
  output logic irq_taken_pre
);
  soc_ibex_beat_core u_cpu (
    .clk_i(clk), .reset_i(reset), .irq_i(irq),
    .instr_req_valid_o(instr_req_valid), .instr_req_ready_i(instr_req_ready),
    .instr_write_o(instr_write), .instr_addr_o(instr_addr),
    .instr_wdata_o(instr_wdata), .instr_be_o(instr_be),
    .instr_rsp_valid_i(instr_rsp_valid), .instr_rsp_ready_o(instr_rsp_ready),
    .instr_rdata_i(instr_rdata), .instr_error_i(instr_error),
    .data_req_valid_o(data_req_valid), .data_req_ready_i(data_req_ready),
    .data_write_o(data_write), .data_addr_o(data_addr),
    .data_wdata_o(data_wdata), .data_be_o(data_be),
    .data_rsp_valid_i(data_rsp_valid), .data_rsp_ready_o(data_rsp_ready),
    .data_rdata_i(data_rdata), .data_error_i(data_error), .flush_o()
  );
  assign startup_priv = u_cpu.u_ibex.u_ibex_core.cs_registers_i.priv_lvl_q;
  // Sampled by the C++ harness before the clock edge that receives irq.
  // The external source is disabled when MEIE is clear, or MIE is clear in M-mode.
  assign irq_masked_pre =
      ~u_cpu.u_ibex.u_ibex_core.cs_registers_i.mie_q.irq_external |
      ((startup_priv == 2'b11) & ~u_cpu.u_ibex.u_ibex_core.csr_mstatus_mie);
  // This is the controller's actual external IRQ trap redirect decision.
  assign irq_taken_pre =
      u_cpu.u_ibex.u_ibex_core.id_stage_i.controller_i.pc_set_o &
      u_cpu.u_ibex.u_ibex_core.id_stage_i.controller_i.csr_save_cause_o &
      (u_cpu.u_ibex.u_ibex_core.id_stage_i.controller_i.exc_pc_mux_o ==
       ibex_pkg::EXC_PC_IRQ) &
      (u_cpu.u_ibex.u_ibex_core.id_stage_i.controller_i.exc_cause_o ==
       ibex_pkg::ExcCauseIrqExternalM);
endmodule

`default_nettype wire
