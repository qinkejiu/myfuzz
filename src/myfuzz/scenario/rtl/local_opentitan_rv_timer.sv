`default_nettype none
module local_opentitan_rv_timer (
  input logic clk, reset,
  input logic req_valid, req_write,
  output logic req_ready,
  input logic [31:0] req_addr, req_wdata,
  input logic [3:0] req_be,
  output logic rsp_valid, rsp_error,
  input logic rsp_ready,
  output logic [31:0] rsp_rdata,
  output logic irq
);
  logic a_valid, a_ready;
  logic [2:0] a_opcode, a_param;
  logic [1:0] a_size;
  logic [7:0] a_source;
  logic [31:0] a_address, a_data;
  logic [3:0] a_mask;
  logic [22:0] a_user;
  logic d_valid, d_ready, d_error;
  logic [2:0] d_opcode, d_param;
  logic [1:0] d_size;
  logic [7:0] d_source;
  logic [0:0] d_sink;
  logic [31:0] d_data;
  logic [13:0] d_user;
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [0:0] alert_rx;
  prim_alert_pkg::alert_tx_t [0:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;

  beat_to_tlul #(
    .ADDRESS_WIDTH(32), .DATA_WIDTH(32), .WINDOW_BASE(32'h4000_0000),
    .WINDOW_SIZE(4096), .GEN_INTEGRITY(1)
  ) u_protocol (
    .clk(clk), .reset(reset),
    .req_valid(req_valid), .req_ready(req_ready), .write(req_write),
    .addr(req_addr), .wdata(req_wdata), .be(req_be),
    .rsp_valid(rsp_valid), .rsp_ready(rsp_ready),
    .rdata(rsp_rdata), .error(rsp_error),
    .a_valid(a_valid), .a_ready(a_ready), .a_opcode(a_opcode),
    .a_param(a_param), .a_size(a_size), .a_source(a_source),
    .a_address(a_address), .a_mask(a_mask), .a_data(a_data), .a_user(a_user),
    .d_valid(d_valid), .d_ready(d_ready), .d_opcode(d_opcode),
    .d_param(d_param), .d_size(d_size), .d_source(d_source),
    .d_sink(d_sink), .d_data(d_data), .d_user(d_user), .d_error(d_error)
  );
  assign alert_rx[0] = prim_alert_pkg::ALERT_RX_DEFAULT;
  assign racl_policies = '0;
  assign tl_h2d.a_valid = a_valid;
  assign tl_h2d.a_opcode = tlul_pkg::tl_a_op_e'(a_opcode);
  assign tl_h2d.a_param = a_param;
  assign tl_h2d.a_size = a_size;
  assign tl_h2d.a_source = a_source;
  assign tl_h2d.a_address = a_address;
  assign tl_h2d.a_mask = a_mask;
  assign tl_h2d.a_data = a_data;
  assign tl_h2d.a_user = a_user;
  assign tl_h2d.d_ready = d_ready;
  assign a_ready = tl_d2h.a_ready;
  assign d_valid = tl_d2h.d_valid;
  assign d_opcode = tl_d2h.d_opcode;
  assign d_param = tl_d2h.d_param;
  assign d_size = tl_d2h.d_size;
  assign d_source = tl_d2h.d_source;
  assign d_sink = tl_d2h.d_sink;
  assign d_data = tl_d2h.d_data;
  assign d_user = tl_d2h.d_user;
  assign d_error = tl_d2h.d_error;

  rv_timer #(.EnableRacl(1'b0), .RaclErrorRsp(1'b0)) u_timer (
    .clk_i(clk), .rst_ni(~reset), .tl_i(tl_h2d), .tl_o(tl_d2h),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies), .racl_error_o(racl_error),
    .intr_timer_expired_hart0_timer0_o(irq)
  );
endmodule
`default_nettype wire
