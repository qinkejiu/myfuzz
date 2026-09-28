// Independent elaboration boundary for the pinned OpenTitan SPI Host closure.
module opentitan_spi_host_closure_wrapper (
  input  logic clk_i,
  input  logic rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  input  logic [3:0] sd_i,
  output logic sck_o,
  output logic csb_o,
  output logic [3:0] sd_o,
  output logic [3:0] sd_en_o,
  output logic irq_event_o,
  output logic irq_error_o
);
  prim_alert_pkg::alert_rx_t [spi_host_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [spi_host_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_error_log_t racl_error;
  spi_device_pkg::passthrough_rsp_t passthrough_rsp;
  logic sck_en, csb_en, lsio_trigger;

  assign alert_rx = '{default:prim_alert_pkg::ALERT_RX_DEFAULT};
  spi_host #(.NumCS(1)) u_spi_host (
    .clk_i,
    .rst_ni,
    .tl_i,
    .tl_o,
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .racl_policies_i('0),
    .racl_error_o(racl_error),
    .cio_sck_o(sck_o),
    .cio_sck_en_o(sck_en),
    .cio_csb_o(csb_o),
    .cio_csb_en_o(csb_en),
    .cio_sd_o(sd_o),
    .cio_sd_en_o(sd_en_o),
    .cio_sd_i(sd_i),
    .passthrough_i(spi_device_pkg::PASSTHROUGH_REQ_DEFAULT),
    .passthrough_o(passthrough_rsp),
    .lsio_trigger_o(lsio_trigger),
    .intr_error_o(irq_error_o),
    .intr_spi_event_o(irq_event_o)
  );
endmodule
