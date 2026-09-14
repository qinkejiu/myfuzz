`default_nettype none
// Source-backed ZipCPU wbuart Wishbone target wrapper.
//
// Thin uniform shell around the pinned real IP
// (third_party/soc-zipcpu-wbuart/rtl/wbuart.v).  P1 recorded a registered-ack
// response with a single-cycle STB requirement; the pulse generation lives in
// the P5 beat_to_wishbone adapter, not here.
//
// MYFUZZ_IRQ_OUTPUTS: o_uart_rx_int o_uart_tx_int o_uart_rxfifo_int o_uart_txfifo_int
module soc_zipcpu_uart_target #(
  parameter integer INITIAL_SETUP = 25,
  parameter integer LGFLEN = 4,
  parameter integer HARDWARE_FLOW_CONTROL_PRESENT = 1
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        cyc_i,
  input  logic        stb_i,
  input  logic        we_i,
  input  logic [1:0]  adr_i,
  input  logic [31:0] dat_w_i,
  input  logic [3:0]  sel_i,
  output logic        ack_o,
  output logic        err_o,
  output logic        stall_o,
  output logic [31:0] dat_r_o,
  input  logic [31:0] env_gpio_in_i,
  input  logic        env_uart_rx_i,
  input  logic        env_spi_sck_i,
  input  logic        env_spi_cs_i,
  input  logic        env_spi_sdi_i,
  output logic [31:0] obs_gpio_out_o,
  output logic [31:0] obs_gpio_dir_o,
  output logic        obs_spi_clk_o,
  output logic        obs_spi_cs0_o,
  output logic        obs_spi_sdo0_o,
  output logic        obs_uart_tx_o,
  output logic        irq_o,
  output logic        gpio_irq_o
);
  logic o_uart_rx_int;
  logic o_uart_tx_int;
  logic o_uart_rxfifo_int;
  logic o_uart_txfifo_int;
  logic unused_env;

  assign unused_env = (|env_gpio_in_i) | env_spi_sck_i | env_spi_cs_i | env_spi_sdi_i;
  assign err_o = 1'b0;

  wbuart #(
    .INITIAL_SETUP(INITIAL_SETUP[30:0]),
    .LGFLEN(LGFLEN[3:0]),
    .HARDWARE_FLOW_CONTROL_PRESENT(HARDWARE_FLOW_CONTROL_PRESENT[0])
  ) u_wbuart (
    .i_clk(clk_i),
    .i_reset(~rst_ni),
    .i_wb_cyc(cyc_i),
    .i_wb_stb(stb_i),
    .i_wb_we(we_i),
    .i_wb_addr(adr_i),
    .i_wb_data(dat_w_i),
    .i_wb_sel(sel_i),
    .o_wb_stall(stall_o),
    .o_wb_ack(ack_o),
    .o_wb_data(dat_r_o),
    .i_uart_rx(env_uart_rx_i),
    .o_uart_tx(obs_uart_tx_o),
    .i_cts_n(1'b1),
    .o_rts_n(),
    .o_uart_rx_int(o_uart_rx_int),
    .o_uart_tx_int(o_uart_tx_int),
    .o_uart_rxfifo_int(o_uart_rxfifo_int),
    .o_uart_txfifo_int(o_uart_txfifo_int)
  );

  assign obs_gpio_out_o = '0;
  assign obs_gpio_dir_o = '0;
  assign obs_spi_clk_o = 1'b0;
  assign obs_spi_cs0_o = 1'b0;
  assign obs_spi_sdo0_o = 1'b0;
  assign irq_o = o_uart_rx_int | o_uart_tx_int | o_uart_rxfifo_int | o_uart_txfifo_int;
  assign gpio_irq_o = 1'b0;
endmodule
`default_nettype wire
