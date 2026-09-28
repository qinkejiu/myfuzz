// Independent digital boundary for the pinned OpenTitan SPI Device.
module opentitan_spi_device_closure_wrapper (
  input  logic clk_i,
  input  logic rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  input  logic sck_i,
  input  logic csb_i,
  input  logic tpm_csb_i,
  input  logic [3:0] sd_i,
  output logic [3:0] sd_o,
  output logic [3:0] sd_en_o,
  output logic [7:0] irq_o
);
  prim_alert_pkg::alert_rx_t [spi_device_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [spi_device_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_error_log_t racl_error;
  spi_device_pkg::passthrough_req_t passthrough_req;
  prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t ram_cfg_sys2spi;
  prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t ram_cfg_spi2sys;
  logic sck_monitor;

  assign alert_rx = '{default:prim_alert_pkg::ALERT_RX_DEFAULT};
  spi_device u_spi_device (
    .clk_i,
    .rst_ni,
    .tl_i,
    .tl_o,
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .racl_policies_i('0),
    .racl_error_o(racl_error),
    .cio_sck_i(sck_i),
    .cio_csb_i(csb_i),
    .cio_sd_o(sd_o),
    .cio_sd_en_o(sd_en_o),
    .cio_sd_i(sd_i),
    .cio_tpm_csb_i(tpm_csb_i),
    .passthrough_o(passthrough_req),
    .passthrough_i(spi_device_pkg::PASSTHROUGH_RSP_DEFAULT),
    .intr_upload_cmdfifo_not_empty_o(irq_o[0]),
    .intr_upload_payload_not_empty_o(irq_o[1]),
    .intr_upload_payload_overflow_o(irq_o[2]),
    .intr_readbuf_watermark_o(irq_o[3]),
    .intr_readbuf_flip_o(irq_o[4]),
    .intr_tpm_header_not_empty_o(irq_o[5]),
    .intr_tpm_rdfifo_cmd_end_o(irq_o[6]),
    .intr_tpm_rdfifo_drop_o(irq_o[7]),
    .ram_cfg_sys2spi_i(prim_ram_1r1w_pkg::RAM_1R1W_CFG_REQ_DEFAULT),
    .ram_cfg_sys2spi_o(ram_cfg_sys2spi),
    .ram_cfg_spi2sys_i(prim_ram_1r1w_pkg::RAM_1R1W_CFG_REQ_DEFAULT),
    .ram_cfg_spi2sys_o(ram_cfg_spi2sys),
    .sck_monitor_o(sck_monitor),
    .mbist_en_i(1'b0),
    .scan_clk_i(1'b0),
    .scan_rst_ni(rst_ni),
    .scanmode_i(prim_mubi_pkg::MuBi4False)
  );
endmodule
