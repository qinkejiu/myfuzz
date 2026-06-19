module top(input logic clock, input logic reset, input logic a, input logic [1:0] n, output logic y);
  always_comb begin
    y = a ^ n[0];
  end

  always_ff @(posedge clock) begin
    if (!reset && !a && n == 2'b00) begin
      $fatal(1, "myfuzz crash_smoke trigger: a=0 n=0");
    end
  end
endmodule
