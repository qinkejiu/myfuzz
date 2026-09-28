module soc_ibex_rvfi_checker_tb;
  logic clk = 1'b0;
  logic rst_n = 1'b0;
  logic rvfi_valid = 1'b0;
  logic [63:0] rvfi_order = '0;
  logic [31:0] rvfi_insn = '0;
  logic rvfi_trap = 1'b0;
  wire eval_o, fail_o;
  wire [11:0] opcode_coverage_o;

  always #5 clk = ~clk;

  soc_ibex_rvfi_checker dut (
      .clk_i(clk), .rst_ni(rst_n), .rvfi_valid_i(rvfi_valid),
      .rvfi_order_i(rvfi_order), .rvfi_insn_i(rvfi_insn),
      .rvfi_trap_i(rvfi_trap), .eval_o(eval_o), .fail_o(fail_o),
      .opcode_coverage_o(opcode_coverage_o)
  );

  task automatic tick;
    @(posedge clk);
    #1;
  endtask

  initial begin
    tick();
    rst_n = 1'b1;

    rvfi_valid = 1'b1;
    rvfi_order = 64'd1;
    rvfi_insn = 32'h0010_0093; // ADDI x1, x0, 1
    #1;
    if (!eval_o || opcode_coverage_o != (12'b1 << 7))
      $fatal(1, "ADDI retirement was not counted: eval=%b bins=%h", eval_o,
             opcode_coverage_o);
    tick();
    if (fail_o) $fatal(1, "Ibex initial RVFI order one was rejected");

    rvfi_order = 64'd2;
    rvfi_insn = 32'h0220_81b3; // MUL x3, x1, x2
    #1;
    if (opcode_coverage_o != (12'b1 << 9))
      $fatal(1, "M-extension opcode bin missing: %h", opcode_coverage_o);
    tick();
    if (fail_o) $fatal(1, "sequential RVFI order two was rejected");

    rvfi_order = 64'd4;
    rvfi_insn = 32'h0000_0073; // ECALL trap record is not retired coverage
    rvfi_trap = 1'b1;
    #1;
    if (opcode_coverage_o != 12'b0)
      $fatal(1, "trap record entered opcode coverage: %h", opcode_coverage_o);
    tick();
    if (!fail_o) $fatal(1, "skipped RVFI order did not set sticky failure");

    rst_n = 1'b0;
    tick();
    if (fail_o) $fatal(1, "reset did not clear testcase-local failure");
    $display("IBEX_RVFI_CHECKER_ALL_PASS");
    $finish;
  end
endmodule
