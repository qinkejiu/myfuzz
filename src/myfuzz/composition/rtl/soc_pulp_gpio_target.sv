`default_nettype none
// Source-backed PULP APB GPIO target wrapper.
//
// This is a thin, uniform shell around the pinned real IP
// (third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv).  It contains no behavioural
// substitute: the real apb_gpio instance is the only responder on the APB
// port.  The renderer derives the module name from the peripheral's source
// lock (soc_<source_lock>_target), connects the P5 target adapter to the
// canonical protocol-side ports below, and connects the environment and
// observability ports by convention:
//
//   <adapter role>_i / <adapter role>_o   protocol side (from target_side_ports)
//   env_*                                 environment pins
//   obs_*                                 harness observability (0 when unused)
//   irq_o / gpio_irq_o                    declared interrupt aggregation
//
// MYFUZZ_IRQ_OUTPUTS: interrupt
module soc_pulp_gpio_target #(
  parameter integer APB_ADDR_WIDTH = 12,
  parameter integer PAD_NUM = 32,
  parameter integer NBIT_PADCFG = 4
) (
  input  logic                       clk_i,
  input  logic                       rst_ni,
  // APB3 target port (the real IP has no PSTRB)
  input  logic                       psel_i,
  input  logic                       penable_i,
  input  logic                       pwrite_i,
  input  logic [APB_ADDR_WIDTH-1:0]  paddr_i,
  input  logic [31:0]                pwdata_i,
  input  logic [3:0]                 pstrb_i,
  output logic [31:0]                prdata_o,
  output logic                       pready_o,
  output logic                       pslverr_o,
  // environment and observability
  input  logic [31:0]                env_gpio_in_i,
  input  logic                       env_uart_rx_i,
  input  logic                       env_spi_sck_i,
  input  logic                       env_spi_cs_i,
  input  logic                       env_spi_sdi_i,
  output logic [31:0]                obs_gpio_out_o,
  output logic [31:0]                obs_gpio_dir_o,
  output logic                       obs_spi_clk_o,
  output logic                       obs_spi_cs0_o,
  output logic                       obs_spi_sdo0_o,
  output logic                       obs_uart_tx_o,
  output logic                       irq_o,
  output logic                       gpio_irq_o
);
  logic [PAD_NUM-1:0] gpio_in_sync;
  logic [PAD_NUM-1:0] gpio_out;
  logic [PAD_NUM-1:0] gpio_dir;
  logic [PAD_NUM-1:0][NBIT_PADCFG-1:0] gpio_padcfg;
  logic unused_env;
  logic unused_pstrb;

  assign unused_env = env_uart_rx_i | env_spi_sck_i | env_spi_cs_i | env_spi_sdi_i;
  assign unused_pstrb = |pstrb_i;

  apb_gpio #(
    .APB_ADDR_WIDTH(APB_ADDR_WIDTH),
    .PAD_NUM(PAD_NUM),
    .NBIT_PADCFG(NBIT_PADCFG)
  ) u_apb_gpio (
    .HCLK(clk_i),
    .HRESETn(rst_ni),
    .dft_cg_enable_i(1'b1),
    .PADDR(paddr_i),
    .PWDATA(pwdata_i),
    .PWRITE(pwrite_i),
    .PSEL(psel_i),
    .PENABLE(penable_i),
    .PRDATA(prdata_o),
    .PREADY(pready_o),
    .PSLVERR(pslverr_o),
    .gpio_in(env_gpio_in_i[PAD_NUM-1:0]),
    .gpio_in_sync(gpio_in_sync),
    .gpio_out(gpio_out),
    .gpio_dir(gpio_dir),
    .gpio_padcfg(gpio_padcfg),
    .interrupt(irq_o)
  );

  assign obs_gpio_out_o = {{(32-PAD_NUM){1'b0}}, gpio_out};
  assign obs_gpio_dir_o = {{(32-PAD_NUM){1'b0}}, gpio_dir};
  assign obs_spi_clk_o = 1'b0;
  assign obs_spi_cs0_o = 1'b0;
  assign obs_spi_sdo0_o = 1'b0;
  assign obs_uart_tx_o = 1'b0;
  assign gpio_irq_o = irq_o;
endmodule
`default_nettype wire
