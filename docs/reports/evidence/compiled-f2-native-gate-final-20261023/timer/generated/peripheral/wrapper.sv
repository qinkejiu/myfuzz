module local_peripheral (
  input logic clk,
  input logic reset,
  input logic [11:0] lh_p_2_11_0,
  input logic [0:0] lh_p_3_0_0,
  output logic [31:0] lh_p_4_31_0,
  output logic [0:0] lh_p_5_0_0,
  input logic [0:0] lh_p_6_0_0,
  output logic [0:0] lh_p_7_0_0,
  input logic [31:0] lh_p_8_31_0,
  input logic [0:0] lh_p_9_0_0,
  output logic [3:0] lh_p_10_3_0
);
  logic [0:0] dut_p_0;
  assign dut_p_0[0:0] = clk;
  logic [0:0] dut_p_1;
  assign dut_p_1[0:0] = ~reset;
  logic [11:0] dut_p_2;
  assign dut_p_2[11:0] = lh_p_2_11_0;
  logic [0:0] dut_p_3;
  assign dut_p_3[0:0] = lh_p_3_0_0;
  logic [31:0] dut_p_4;
  assign lh_p_4_31_0 = dut_p_4[31:0];
  logic [0:0] dut_p_5;
  assign lh_p_5_0_0 = dut_p_5[0:0];
  logic [0:0] dut_p_6;
  assign dut_p_6[0:0] = lh_p_6_0_0;
  logic [0:0] dut_p_7;
  assign lh_p_7_0_0 = dut_p_7[0:0];
  logic [31:0] dut_p_8;
  assign dut_p_8[31:0] = lh_p_8_31_0;
  logic [0:0] dut_p_9;
  assign dut_p_9[0:0] = lh_p_9_0_0;
  logic [3:0] dut_p_10;
  assign lh_p_10_3_0 = dut_p_10[3:0];
  apb_timer #(
    .APB_ADDR_WIDTH(12),
    .TIMER_CNT(2)
  ) u_dut (
    .HCLK(dut_p_0),
    .HRESETn(dut_p_1),
    .PADDR(dut_p_2),
    .PENABLE(dut_p_3),
    .PRDATA(dut_p_4),
    .PREADY(dut_p_5),
    .PSEL(dut_p_6),
    .PSLVERR(dut_p_7),
    .PWDATA(dut_p_8),
    .PWRITE(dut_p_9),
    .irq_o(dut_p_10)
  );
endmodule
