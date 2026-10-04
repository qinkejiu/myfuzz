`default_nettype none
// Scalar local TL-UL boundary; SPI SCK remains an independently driven pad.
module soc_opentitan_spi_device_local_target (
  input logic clk_i,
  input logic rst_ni,
  input logic a_valid_i,
  output logic a_ready_o,
  input logic [2:0] a_opcode_i,
  input logic [2:0] a_param_i,
  input logic [1:0] a_size_i,
  input logic [7:0] a_source_i,
  input logic [31:0] a_address_i,
  input logic [3:0] a_mask_i,
  input logic [31:0] a_data_i,
  input logic [22:0] a_user_i,
  output logic d_valid_o,
  input logic d_ready_i,
  output logic [2:0] d_opcode_o,
  output logic [2:0] d_param_o,
  output logic [1:0] d_size_o,
  output logic [7:0] d_source_o,
  output logic d_sink_o,
  output logic [31:0] d_data_o,
  output logic [13:0] d_user_o,
  output logic d_error_o,
  input logic sck_i,
  input logic csb_i,
  input logic tpm_csb_i,
  input logic [3:0] sd_i,
  output logic [3:0] sd_o,
  output logic [3:0] sd_en_o,
  output logic [7:0] irq_o,
  output logic [1:0] alert_tx_o,
  output logic [36:0] racl_error_o,
  output logic [$bits(spi_device_pkg::passthrough_req_t)-1:0] passthrough_o,
  output logic [$bits(prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t)-1:0] ram_cfg_sys2spi_o,
  output logic [$bits(prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t)-1:0] ram_cfg_spi2sys_o,
  output logic sck_monitor_o
);
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [spi_device_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [spi_device_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_error_log_t racl_error;
  spi_device_pkg::passthrough_req_t passthrough_req;
  prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t ram_cfg_sys2spi;
  prim_ram_1r1w_pkg::ram_1r1w_cfg_rsp_t ram_cfg_spi2sys;

  assign alert_rx = '{default:prim_alert_pkg::ALERT_RX_DEFAULT};
  assign alert_tx_o = alert_tx[0];
  assign racl_error_o = racl_error;
  assign passthrough_o = passthrough_req;
  assign ram_cfg_sys2spi_o = ram_cfg_sys2spi;
  assign ram_cfg_spi2sys_o = ram_cfg_spi2sys;
  assign tl_h2d.a_valid = a_valid_i;
  assign tl_h2d.a_opcode = tlul_pkg::tl_a_op_e'(a_opcode_i);
  assign tl_h2d.a_param = a_param_i;
  assign tl_h2d.a_size = a_size_i;
  assign tl_h2d.a_source = a_source_i;
  assign tl_h2d.a_address = a_address_i;
  assign tl_h2d.a_mask = a_mask_i;
  assign tl_h2d.a_data = a_data_i;
  assign tl_h2d.a_user = a_user_i;
  assign tl_h2d.d_ready = d_ready_i;
  assign a_ready_o = tl_d2h.a_ready;
  assign d_valid_o = tl_d2h.d_valid;
  assign d_opcode_o = tl_d2h.d_opcode;
  assign d_param_o = tl_d2h.d_param;
  assign d_size_o = tl_d2h.d_size;
  assign d_source_o = tl_d2h.d_source;
  assign d_sink_o = tl_d2h.d_sink;
  assign d_data_o = tl_d2h.d_data;
  assign d_user_o = tl_d2h.d_user;
  assign d_error_o = tl_d2h.d_error;

  spi_device u_spi_device (
    .clk_i, .rst_ni, .tl_i(tl_h2d), .tl_o(tl_d2h),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i('0), .racl_error_o(racl_error),
    .cio_sck_i(sck_i), .cio_csb_i(csb_i), .cio_tpm_csb_i(tpm_csb_i),
    .cio_sd_i(sd_i), .cio_sd_o(sd_o), .cio_sd_en_o(sd_en_o),
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
    .sck_monitor_o,
    .mbist_en_i(1'b0), .scan_clk_i(1'b0), .scan_rst_ni(rst_ni),
    .scanmode_i(prim_mubi_pkg::MuBi4False)
  );
endmodule
`default_nettype wire
