`default_nettype none
// Source-backed PULP APB SPI master target wrapper.
//
// Thin uniform shell around the pinned real IP
// (third_party/soc-pulp-apb-spi/apb_spi_master.sv plus the pinned AXI-SPI
// helper closure).  No behavioural substitute and no invented pin.
//
// MYFUZZ_IRQ_OUTPUTS: events_o
module soc_pulp_spi_target #(
  parameter integer APB_ADDR_WIDTH = 12,
  parameter integer BUFFER_DEPTH = 10
) (
  input  logic                       clk_i,
  input  logic                       rst_ni,
  input  logic                       psel_i,
  input  logic                       penable_i,
  input  logic                       pwrite_i,
  input  logic [APB_ADDR_WIDTH-1:0]  paddr_i,
  input  logic [31:0]                pwdata_i,
  input  logic [3:0]                 pstrb_i,
  output logic [31:0]                prdata_o,
  output logic                       pready_o,
  output logic                       pslverr_o,
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
  logic [1:0] events;
  logic spi_clk;
  logic spi_csn0, spi_csn1, spi_csn2, spi_csn3;
  logic spi_mode;
  logic spi_sdo0, spi_sdo1, spi_sdo2, spi_sdo3;
  logic unused_env;

  assign unused_env = (|env_gpio_in_i) | env_uart_rx_i | |pstrb_i;

  apb_spi_master #(
    .BUFFER_DEPTH(BUFFER_DEPTH),
    .APB_ADDR_WIDTH(APB_ADDR_WIDTH)
  ) u_apb_spi_master (
    .HCLK(clk_i),
    .HRESETn(rst_ni),
    .PADDR(paddr_i),
    .PWDATA(pwdata_i),
    .PWRITE(pwrite_i),
    .PSEL(psel_i),
    .PENABLE(penable_i),
    .PRDATA(prdata_o),
    .PREADY(pready_o),
    .PSLVERR(pslverr_o),
    .events_o(events),
    .spi_clk(spi_clk),
    .spi_csn0(spi_csn0),
    .spi_csn1(spi_csn1),
    .spi_csn2(spi_csn2),
    .spi_csn3(spi_csn3),
    .spi_mode(spi_mode),
    .spi_sdo0(spi_sdo0),
    .spi_sdo1(spi_sdo1),
    .spi_sdo2(spi_sdo2),
    .spi_sdo3(spi_sdo3),
    .spi_sdi0(env_spi_sdi_i),
    .spi_sdi1(1'b0),
    .spi_sdi2(1'b0),
    .spi_sdi3(1'b0)
  );

  assign obs_gpio_out_o = '0;
  assign obs_gpio_dir_o = '0;
  assign obs_spi_clk_o = spi_clk;
  assign obs_spi_cs0_o = spi_csn0;
  assign obs_spi_sdo0_o = spi_sdo0;
  assign obs_uart_tx_o = 1'b0;
  assign irq_o = |events;
  assign gpio_irq_o = 1'b0;
endmodule
`default_nettype wire
