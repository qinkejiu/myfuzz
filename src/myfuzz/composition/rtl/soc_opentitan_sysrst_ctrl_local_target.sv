`default_nettype none
// Complete scalar local boundary for the pinned OpenTitan sysrst_ctrl.
// The native AON/core clocks and resets remain independent. rst_req_o is an
// observed DUT result and is deliberately not connected to either reset.
module soc_opentitan_sysrst_ctrl_local_target (
  input  logic clk_i,
  input  logic clk_aon_i,
  input  logic rst_ni,
  input  logic rst_aon_ni,
  input  logic a_valid_i,
  output logic a_ready_o,
  input  logic [2:0] a_opcode_i,
  input  logic [2:0] a_param_i,
  input  logic [1:0] a_size_i,
  input  logic [7:0] a_source_i,
  input  logic [31:0] a_address_i,
  input  logic [3:0] a_mask_i,
  input  logic [31:0] a_data_i,
  input  logic [22:0] a_user_i,
  output logic d_valid_o,
  input  logic d_ready_i,
  output logic [2:0] d_opcode_o,
  output logic [2:0] d_param_o,
  output logic [1:0] d_size_o,
  output logic [7:0] d_source_o,
  output logic d_sink_o,
  output logic [31:0] d_data_o,
  output logic [13:0] d_user_o,
  output logic d_error_o,
  input  logic cio_ac_present_i,
  input  logic cio_ec_rst_l_i,
  input  logic cio_key0_in_i,
  input  logic cio_key1_in_i,
  input  logic cio_key2_in_i,
  input  logic cio_pwrb_in_i,
  input  logic cio_lid_open_i,
  input  logic cio_flash_wp_l_i,
  output logic [1:0] alert_tx_o,
  output logic wkup_req_o,
  output logic rst_req_o,
  output logic intr_event_detected_o,
  output logic cio_bat_disable_o,
  output logic cio_flash_wp_l_o,
  output logic cio_ec_rst_l_o,
  output logic cio_key0_out_o,
  output logic cio_key1_out_o,
  output logic cio_key2_out_o,
  output logic cio_pwrb_out_o,
  output logic cio_z3_wakeup_o,
  output logic cio_bat_disable_en_o,
  output logic cio_flash_wp_l_en_o,
  output logic cio_ec_rst_l_en_o,
  output logic cio_key0_out_en_o,
  output logic cio_key1_out_en_o,
  output logic cio_key2_out_en_o,
  output logic cio_pwrb_out_en_o,
  output logic cio_z3_wakeup_en_o
);
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [0:0] alert_rx;
  prim_alert_pkg::alert_tx_t [0:0] alert_tx;

  assign alert_rx[0] = prim_alert_pkg::ALERT_RX_DEFAULT;
  assign alert_tx_o = alert_tx[0];

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

  sysrst_ctrl u_sysrst_ctrl (
    .clk_i,
    .clk_aon_i,
    .rst_ni,
    .rst_aon_ni,
    .tl_i(tl_h2d),
    .tl_o(tl_d2h),
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .wkup_req_o,
    .rst_req_o,
    .intr_event_detected_o,
    .cio_ac_present_i,
    .cio_ec_rst_l_i,
    .cio_key0_in_i,
    .cio_key1_in_i,
    .cio_key2_in_i,
    .cio_pwrb_in_i,
    .cio_lid_open_i,
    .cio_flash_wp_l_i,
    .cio_bat_disable_o,
    .cio_flash_wp_l_o,
    .cio_ec_rst_l_o,
    .cio_key0_out_o,
    .cio_key1_out_o,
    .cio_key2_out_o,
    .cio_pwrb_out_o,
    .cio_z3_wakeup_o,
    .cio_bat_disable_en_o,
    .cio_flash_wp_l_en_o,
    .cio_ec_rst_l_en_o,
    .cio_key0_out_en_o,
    .cio_key1_out_en_o,
    .cio_key2_out_en_o,
    .cio_pwrb_out_en_o,
    .cio_z3_wakeup_en_o
  );
endmodule
`default_nettype wire
