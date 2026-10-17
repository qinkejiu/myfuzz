module local_gpio (
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
  output logic [31:0] lh_p_11_31_0,
  input logic [31:0] lh_p_12_31_0,
  output logic [31:0] lh_p_13_31_0,
  output logic [31:0] lh_p_14_31_0,
  output logic [127:0] lh_p_15_127_0,
  output logic [0:0] lh_p_16_0_0
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
  logic [0:0] dut_p_10;
  assign dut_p_10[0:0] = 1'd0;
  logic [31:0] dut_p_11;
  assign lh_p_11_31_0 = dut_p_11[31:0];
  logic [31:0] dut_p_12;
  assign dut_p_12[31:0] = lh_p_12_31_0;
  logic [31:0] dut_p_13;
  assign lh_p_13_31_0 = dut_p_13[31:0];
  logic [31:0] dut_p_14;
  assign lh_p_14_31_0 = dut_p_14[31:0];
  logic [127:0] dut_p_15;
  assign lh_p_15_127_0 = dut_p_15[127:0];
  logic [0:0] dut_p_16;
  assign lh_p_16_0_0 = dut_p_16[0:0];
  apb_gpio #(
    .APB_ADDR_WIDTH(12),
    .NBIT_PADCFG(4),
    .PAD_NUM(32)
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
    .dft_cg_enable_i(dut_p_10),
    .gpio_dir(dut_p_11),
    .gpio_in(dut_p_12),
    .gpio_in_sync(dut_p_13),
    .gpio_out(dut_p_14),
    .gpio_padcfg(dut_p_15),
    .interrupt(dut_p_16)
  );
endmodule
