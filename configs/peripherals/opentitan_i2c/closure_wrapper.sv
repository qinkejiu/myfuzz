// Independent native TL-UL I2C elaboration boundary.
module opentitan_i2c_closure_wrapper (
  input logic clk_i,
  input logic rst_ni,
  input tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  input logic scl_i,
  output logic scl_o,
  output logic scl_en_o,
  input logic sda_i,
  output logic sda_o,
  output logic sda_en_o,
  output logic [14:0] irq_o
);
  prim_alert_pkg::alert_rx_t [i2c_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [i2c_reg_pkg::NumAlerts-1:0] alert_tx;
  prim_ram_1p_pkg::ram_1p_cfg_rsp_t ram_cfg_rsp;
  top_racl_pkg::racl_error_log_t racl_error;
  logic lsio_trigger;
  assign alert_rx = '{default:prim_alert_pkg::ALERT_RX_DEFAULT};
  i2c u_i2c (
    .clk_i, .rst_ni, .tl_i, .tl_o,
    .ram_cfg_i(prim_ram_1p_pkg::RAM_1P_CFG_REQ_DEFAULT), .ram_cfg_o(ram_cfg_rsp),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i('0), .racl_error_o(racl_error),
    .cio_scl_i(scl_i), .cio_scl_o(scl_o), .cio_scl_en_o(scl_en_o),
    .cio_sda_i(sda_i), .cio_sda_o(sda_o), .cio_sda_en_o(sda_en_o),
    .lsio_trigger_o(lsio_trigger),
    .intr_fmt_threshold_o(irq_o[0]), .intr_rx_threshold_o(irq_o[1]),
    .intr_acq_threshold_o(irq_o[2]), .intr_rx_overflow_o(irq_o[3]),
    .intr_controller_halt_o(irq_o[4]), .intr_scl_interference_o(irq_o[5]),
    .intr_sda_interference_o(irq_o[6]), .intr_stretch_timeout_o(irq_o[7]),
    .intr_sda_unstable_o(irq_o[8]), .intr_cmd_complete_o(irq_o[9]),
    .intr_tx_stretch_o(irq_o[10]), .intr_tx_threshold_o(irq_o[11]),
    .intr_acq_stretch_o(irq_o[12]), .intr_unexp_stop_o(irq_o[13]),
    .intr_host_timeout_o(irq_o[14])
  );
endmodule
