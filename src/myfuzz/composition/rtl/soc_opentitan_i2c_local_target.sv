`default_nettype none
// Scalar, complete local boundary around the pinned OpenTitan I2C controller.
module soc_opentitan_i2c_local_target (
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
  input logic scl_i,
  output logic scl_o,
  output logic scl_en_o,
  input logic sda_i,
  output logic sda_o,
  output logic sda_en_o,
  output logic [14:0] irq_o,
  output logic lsio_trigger_o,
  output logic [1:0] alert_tx_o,
  output logic [36:0] racl_error_o,
  output logic ram_cfg_rsp_o
);
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [i2c_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [i2c_reg_pkg::NumAlerts-1:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;
  prim_ram_1p_pkg::ram_1p_cfg_rsp_t ram_cfg_rsp;

  assign alert_rx = '{default:prim_alert_pkg::ALERT_RX_DEFAULT};
  assign racl_policies = '0;
  assign alert_tx_o = alert_tx[0];
  assign racl_error_o = racl_error;
  assign ram_cfg_rsp_o = ram_cfg_rsp;
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

  i2c #(.EnableRacl(1'b0), .RaclErrorRsp(1'b0), .InputDelayCycles(0)) u_i2c (
    .clk_i, .rst_ni, .tl_i(tl_h2d), .tl_o(tl_d2h),
    .ram_cfg_i(prim_ram_1p_pkg::RAM_1P_CFG_REQ_DEFAULT), .ram_cfg_o(ram_cfg_rsp),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies), .racl_error_o(racl_error),
    .cio_scl_i(scl_i), .cio_scl_o(scl_o), .cio_scl_en_o(scl_en_o),
    .cio_sda_i(sda_i), .cio_sda_o(sda_o), .cio_sda_en_o(sda_en_o),
    .lsio_trigger_o,
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
`default_nettype wire
