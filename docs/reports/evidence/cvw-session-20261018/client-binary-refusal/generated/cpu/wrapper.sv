module local_cpu (
  input logic clk,
  input logic reset,
  output logic [33:0] lh_p_0_33_0,
  output logic [2:0] lh_p_1_2_0,
  output logic [0:0] lh_p_2_0_0,
  output logic [0:0] lh_p_3_0_0,
  output logic [3:0] lh_p_4_3_0,
  input logic [31:0] lh_p_5_31_0,
  output logic [0:0] lh_p_6_0_0,
  input logic [0:0] lh_p_7_0_0,
  output logic [0:0] lh_p_8_0_0,
  input logic [0:0] lh_p_9_0_0,
  output logic [0:0] lh_p_10_0_0,
  output logic [2:0] lh_p_11_2_0,
  output logic [1:0] lh_p_12_1_0,
  output logic [31:0] lh_p_13_31_0,
  output logic [0:0] lh_p_14_0_0,
  output logic [3:0] lh_p_15_3_0
);
  logic [33:0] dut_p_0;
  assign lh_p_0_33_0 = dut_p_0[33:0];
  logic [2:0] dut_p_1;
  assign lh_p_1_2_0 = dut_p_1[2:0];
  logic [0:0] dut_p_2;
  assign lh_p_2_0_0 = dut_p_2[0:0];
  logic [0:0] dut_p_3;
  assign lh_p_3_0_0 = dut_p_3[0:0];
  logic [3:0] dut_p_4;
  assign lh_p_4_3_0 = dut_p_4[3:0];
  logic [31:0] dut_p_5;
  assign dut_p_5[31:0] = lh_p_5_31_0;
  logic [0:0] dut_p_6;
  assign lh_p_6_0_0 = dut_p_6[0:0];
  logic [0:0] dut_p_7;
  assign dut_p_7[0:0] = lh_p_7_0_0;
  logic [0:0] dut_p_8;
  assign lh_p_8_0_0 = dut_p_8[0:0];
  logic [0:0] dut_p_9;
  assign dut_p_9[0:0] = lh_p_9_0_0;
  logic [0:0] dut_p_10;
  assign lh_p_10_0_0 = dut_p_10[0:0];
  logic [2:0] dut_p_11;
  assign lh_p_11_2_0 = dut_p_11[2:0];
  logic [1:0] dut_p_12;
  assign lh_p_12_1_0 = dut_p_12[1:0];
  logic [31:0] dut_p_13;
  assign lh_p_13_31_0 = dut_p_13[31:0];
  logic [0:0] dut_p_14;
  assign lh_p_14_0_0 = dut_p_14[0:0];
  logic [3:0] dut_p_15;
  assign lh_p_15_3_0 = dut_p_15[3:0];
  logic [0:0] dut_p_16;
  assign dut_p_16[0:0] = clk;
  logic [0:0] dut_p_17;
  assign dut_p_17[0:0] = reset;
  cvw_ahb_cpu_top u_dut (
    .HADDR(dut_p_0),
    .HBURST(dut_p_1),
    .HCLK(dut_p_2),
    .HMASTLOCK(dut_p_3),
    .HPROT(dut_p_4),
    .HRDATAEXT(dut_p_5),
    .HREADY(dut_p_6),
    .HREADYEXT(dut_p_7),
    .HRESETn(dut_p_8),
    .HRESPEXT(dut_p_9),
    .HSELEXT(dut_p_10),
    .HSIZE(dut_p_11),
    .HTRANS(dut_p_12),
    .HWDATA(dut_p_13),
    .HWRITE(dut_p_14),
    .HWSTRB(dut_p_15),
    .clk(dut_p_16),
    .reset_ext(dut_p_17)
  );
endmodule
