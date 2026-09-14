`default_nettype none
// Source-backed ZipCPU ziptimer Wishbone target wrapper.
//
// Thin uniform shell around the pinned real IP
// (third_party/soc-zipcpu/rtl/peripherals/ziptimer.v).  The IP has no address
// port, no implemented i_wb_sel and no error output; the single-register
// window and all error responses belong to the P5 adapter and the P6 router.
//
// MYFUZZ_IRQ_OUTPUTS: o_int
module soc_zipcpu_timer_target #(
  parameter integer BW = 32,
  parameter integer VW = 31,
  parameter [0:0]   RELOADABLE = 1'b1
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        cyc_i,
  input  logic        stb_i,
  input  logic        we_i,
  input  logic [0:0]  adr_i,
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
  logic unused_env;

  assign unused_env = (|env_gpio_in_i) | env_uart_rx_i | env_spi_sck_i
                    | env_spi_cs_i | env_spi_sdi_i | (|adr_i) | (|sel_i);
  assign err_o = 1'b0;

  ziptimer #(.BW(BW), .VW(VW), .RELOADABLE(RELOADABLE)) u_ziptimer (
    .i_clk(clk_i),
    .i_reset(~rst_ni),
    .i_ce(1'b1),
    .i_wb_cyc(cyc_i),
    .i_wb_stb(stb_i),
    .i_wb_we(we_i),
    .i_wb_data(dat_w_i),
    .i_wb_sel(sel_i),
    .o_wb_stall(stall_o),
    .o_wb_ack(ack_o),
    .o_wb_data(dat_r_o),
    .o_int(irq_o)
  );

  assign obs_gpio_out_o = '0;
  assign obs_gpio_dir_o = '0;
  assign obs_spi_clk_o = 1'b0;
  assign obs_spi_cs0_o = 1'b0;
  assign obs_spi_sdo0_o = 1'b0;
  assign obs_uart_tx_o = 1'b0;
  assign gpio_irq_o = 1'b0;
endmodule
`default_nettype wire
