module child(input logic a, input logic [1:0] n, output logic y);
  int i;

  task automatic touch();
    y = y;
  endtask

  always_comb begin
    if (a) begin
      y = 1'b1;
    end else if (n == 2'd1) begin
      y = 1'b1;
    end else begin
      y = 1'b0;
    end
    if (n[0]) begin
      y = y ^ 1'b1;
    end
    case (n)
      2'd0: begin
        y = a;
      end
      default: begin
        y = ~a;
      end
    endcase
    for (i = 0; i < n; i = i + 1) begin
      y = y ^ a;
    end
    while (i < 4) i = i + 1;
    touch();
    assert (n != 2'd3);
  end
endmodule

module gen_child(input logic a, output logic y);
  generate
    if (1) begin : g_static
      assign y = a ? 1'b1 : 1'b0;
    end
  endgenerate
endmodule

module top(input logic a, input logic [1:0] n, output logic y);
  child u_child(.a(a), .n(n), .y(y));
endmodule
