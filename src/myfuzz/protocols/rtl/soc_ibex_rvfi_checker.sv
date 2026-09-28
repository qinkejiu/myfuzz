`default_nettype none
// Minimal Ibex RVFI monitor for real instruction execution campaigns.
//
// This checker validates the RVFI record sequence and emits ISA opcode-class
// coverage pulses. It is not an independent architectural oracle: register
// results, memory values, trap policy and Spike comparison remain unassessed.
module soc_ibex_rvfi_checker (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        rvfi_valid_i,
    input  logic [63:0] rvfi_order_i,
    input  logic [31:0] rvfi_insn_i,
    input  logic        rvfi_trap_i,
    output logic        eval_o,
    output logic        fail_o,
    output logic [11:0] opcode_coverage_o
);
  logic [63:0] expected_order_q;
  logic fail_q;

  // Count every valid RVFI record for the order property, including a trap
  // record. Opcode bins count only non-trapping retired instructions.
  assign eval_o = rvfi_valid_i;
  assign fail_o = fail_q;

  always_comb begin
    opcode_coverage_o = 12'b0;
    if (rvfi_valid_i && !rvfi_trap_i) begin
      unique case (rvfi_insn_i[6:0])
        7'h37: opcode_coverage_o[0] = 1'b1; // LUI
        7'h17: opcode_coverage_o[1] = 1'b1; // AUIPC
        7'h6f: opcode_coverage_o[2] = 1'b1; // JAL
        7'h67: opcode_coverage_o[3] = 1'b1; // JALR
        7'h63: opcode_coverage_o[4] = 1'b1; // conditional branches
        7'h03: opcode_coverage_o[5] = 1'b1; // loads
        7'h23: opcode_coverage_o[6] = 1'b1; // stores
        7'h13: opcode_coverage_o[7] = 1'b1; // OP-IMM
        7'h33: begin
          if (rvfi_insn_i[31:25] == 7'b0000001)
            opcode_coverage_o[9] = 1'b1; // RV32M
          else
            opcode_coverage_o[8] = 1'b1; // register-register integer ops
        end
        7'h0f: opcode_coverage_o[10] = 1'b1; // FENCE
        7'h73: opcode_coverage_o[11] = 1'b1; // SYSTEM / CSR
        default: ;
      endcase
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      // The pinned Ibex implementation resets its internal order counter to
      // zero and increments it when the first instruction completes, so the
      // first valid RVFI record after reset is order 1.
      expected_order_q <= 64'd1;
      fail_q <= 1'b0;
    end else if (rvfi_valid_i) begin
      if (rvfi_order_i != expected_order_q)
        fail_q <= 1'b1;
      expected_order_q <= expected_order_q + 64'd1;
    end
  end
endmodule
`default_nettype wire
