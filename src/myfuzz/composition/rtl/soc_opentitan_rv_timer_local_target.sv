`default_nettype none
// Complete scalar boundary for the pinned OpenTitan Earlgrey GPIO.
// The typed alert receiver and RACL policy constants are the source package
// defaults; alert and RACL outputs remain observable at this boundary.
module soc_opentitan_rv_timer_local_target (
  input  logic clk_i,
  input  logic rst_ni,
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
  output logic intr_timer_expired_hart0_timer0_o,
  output logic [1:0] alert_tx_o,
  output logic [36:0] racl_error_o
);
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [0:0] alert_rx;
  prim_alert_pkg::alert_tx_t [0:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;

  assign alert_rx[0] = prim_alert_pkg::ALERT_RX_DEFAULT;
  assign racl_policies = top_racl_pkg::RACL_POLICY_VEC_DEFAULT;
  assign alert_tx_o = alert_tx[0];
  assign racl_error_o = racl_error;

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

  rv_timer #(.EnableRacl(1'b0), .RaclErrorRsp(1'b0)) u_timer (
    .clk_i(clk_i), .rst_ni(rst_ni), .tl_i(tl_h2d), .tl_o(tl_d2h),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies), .racl_error_o(racl_error),
    .intr_timer_expired_hart0_timer0_o(intr_timer_expired_hart0_timer0_o)
  );
endmodule
`default_nettype wire
