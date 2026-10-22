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
  output logic [1:0] lh_p_10_1_0,
  output logic [0:0] lh_p_11_0_0,
  output logic [0:0] lh_p_12_0_0,
  output logic [0:0] lh_p_13_0_0,
  output logic [0:0] lh_p_14_0_0,
  output logic [0:0] lh_p_15_0_0,
  output logic [1:0] lh_p_16_1_0,
  input logic [0:0] lh_p_17_0_0,
  input logic [0:0] lh_p_18_0_0,
  input logic [0:0] lh_p_19_0_0,
  input logic [0:0] lh_p_20_0_0,
  output logic [0:0] lh_p_21_0_0,
  output logic [0:0] lh_p_22_0_0,
  output logic [0:0] lh_p_23_0_0,
  output logic [0:0] lh_p_24_0_0
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
  logic [1:0] dut_p_10;
  assign lh_p_10_1_0 = dut_p_10[1:0];
  logic [0:0] dut_p_11;
  assign lh_p_11_0_0 = dut_p_11[0:0];
  logic [0:0] dut_p_12;
  assign lh_p_12_0_0 = dut_p_12[0:0];
  logic [0:0] dut_p_13;
  assign lh_p_13_0_0 = dut_p_13[0:0];
  logic [0:0] dut_p_14;
  assign lh_p_14_0_0 = dut_p_14[0:0];
  logic [0:0] dut_p_15;
  assign lh_p_15_0_0 = dut_p_15[0:0];
  logic [1:0] dut_p_16;
  assign lh_p_16_1_0 = dut_p_16[1:0];
  logic [0:0] dut_p_17;
  assign dut_p_17[0:0] = lh_p_17_0_0;
  logic [0:0] dut_p_18;
  assign dut_p_18[0:0] = lh_p_18_0_0;
  logic [0:0] dut_p_19;
  assign dut_p_19[0:0] = lh_p_19_0_0;
  logic [0:0] dut_p_20;
  assign dut_p_20[0:0] = lh_p_20_0_0;
  logic [0:0] dut_p_21;
  assign lh_p_21_0_0 = dut_p_21[0:0];
  logic [0:0] dut_p_22;
  assign lh_p_22_0_0 = dut_p_22[0:0];
  logic [0:0] dut_p_23;
  assign lh_p_23_0_0 = dut_p_23[0:0];
  logic [0:0] dut_p_24;
  assign lh_p_24_0_0 = dut_p_24[0:0];
  apb_spi_master #(
    .APB_ADDR_WIDTH(12),
    .BUFFER_DEPTH(10)
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
    .events_o(dut_p_10),
    .spi_clk(dut_p_11),
    .spi_csn0(dut_p_12),
    .spi_csn1(dut_p_13),
    .spi_csn2(dut_p_14),
    .spi_csn3(dut_p_15),
    .spi_mode(dut_p_16),
    .spi_sdi0(dut_p_17),
    .spi_sdi1(dut_p_18),
    .spi_sdi2(dut_p_19),
    .spi_sdi3(dut_p_20),
    .spi_sdo0(dut_p_21),
    .spi_sdo1(dut_p_22),
    .spi_sdo2(dut_p_23),
    .spi_sdo3(dut_p_24)
  );
endmodule
