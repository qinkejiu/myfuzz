`default_nettype none
// Source-backed OpenTitan TL-UL UART target wrapper.
//
// Thin uniform shell around the pinned real IP
// (third_party/soc-opentitan/hw/ip/uart/rtl/uart.sv).  The TL-UL struct ports
// of the real IP are packed from the flattened P5 adapter fields; the alert
// receiver peer is not part of the pinned closure, so alert_rx_i is driven
// with prim_alert_pkg::ALERT_RX_DEFAULT (the documented idle value) and no
// alert response is invented.
//
// MYFUZZ_IRQ_OUTPUTS: intr_tx_watermark_o intr_tx_empty_o intr_rx_watermark_o intr_tx_done_o intr_rx_overflow_o intr_rx_frame_err_o intr_rx_break_err_o intr_rx_timeout_o intr_rx_parity_err_o
module soc_opentitan_uart_target #(
  parameter integer AlertAsyncOn = 1,
  parameter integer AlertSkewCycles = 1,
  parameter integer EnableRacl = 0,
  parameter integer RaclErrorRsp = 0
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic        a_valid_i,
  output logic        a_ready_o,
  input  logic [2:0]  a_opcode_i,
  input  logic [2:0]  a_param_i,
  input  logic [1:0]  a_size_i,
  input  logic [7:0]  a_source_i,
  input  logic [31:0] a_address_i,
  input  logic [3:0]  a_mask_i,
  input  logic [31:0] a_data_i,
  input  logic [22:0] a_user_i,
  output logic        d_valid_o,
  input  logic        d_ready_i,
  output logic [2:0]  d_opcode_o,
  output logic [2:0]  d_param_o,
  output logic [1:0]  d_size_o,
  output logic [7:0]  d_source_o,
  output logic [0:0]  d_sink_o,
  output logic [31:0] d_data_o,
  output logic [13:0] d_user_o,
  output logic        d_error_o,
  input  logic [31:0] env_gpio_in_i,
  input  logic        env_uart_rx_i,
  input  logic        env_spi_sck_i,
  input  logic        env_spi_cs_i,
  input  logic        env_spi_sdi_i,
  output logic [31:0] obs_gpio_out_o,
  output logic [31:0] obs_gpio_dir_o,
  output logic        obs_spi_clk_o,
  output logic        obs_spi_cs0_o,
  output logic        obs_spi_sdo0_o,
  output logic        obs_uart_tx_o,
  output logic        irq_o,
  output logic        gpio_irq_o
);
  tlul_pkg::tl_h2d_t tl_h2d;
  tlul_pkg::tl_d2h_t tl_d2h;
  prim_alert_pkg::alert_rx_t [0:0] alert_rx;
  prim_alert_pkg::alert_tx_t [0:0] alert_tx;
  top_racl_pkg::racl_policy_vec_t racl_policies;
  top_racl_pkg::racl_error_log_t racl_error;
  logic lsio_trigger;
  logic cio_tx_en;
  logic intr_tx_watermark;
  logic intr_tx_empty;
  logic intr_rx_watermark;
  logic intr_tx_done;
  logic intr_rx_overflow;
  logic intr_rx_frame_err;
  logic intr_rx_break_err;
  logic intr_rx_timeout;
  logic intr_rx_parity_err;
  logic unused_env;

  assign unused_env = (|env_gpio_in_i) | env_spi_sck_i | env_spi_cs_i | env_spi_sdi_i;
  assign alert_rx[0] = prim_alert_pkg::ALERT_RX_DEFAULT;
  assign racl_policies = '0;

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

  uart #(
    .AlertAsyncOn(AlertAsyncOn[0]),
    .AlertSkewCycles(AlertSkewCycles),
    .EnableRacl(EnableRacl[0]),
    .RaclErrorRsp(RaclErrorRsp[0])
  ) u_uart (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .tl_i(tl_h2d),
    .tl_o(tl_d2h),
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .racl_policies_i(racl_policies),
    .racl_error_o(racl_error),
    .lsio_trigger_o(lsio_trigger),
    .cio_rx_i(env_uart_rx_i),
    .cio_tx_o(obs_uart_tx_o),
    .cio_tx_en_o(cio_tx_en),
    .intr_tx_watermark_o(intr_tx_watermark),
    .intr_tx_empty_o(intr_tx_empty),
    .intr_rx_watermark_o(intr_rx_watermark),
    .intr_tx_done_o(intr_tx_done),
    .intr_rx_overflow_o(intr_rx_overflow),
    .intr_rx_frame_err_o(intr_rx_frame_err),
    .intr_rx_break_err_o(intr_rx_break_err),
    .intr_rx_timeout_o(intr_rx_timeout),
    .intr_rx_parity_err_o(intr_rx_parity_err)
  );

  assign irq_o = intr_tx_watermark | intr_tx_empty | intr_rx_watermark
               | intr_tx_done | intr_rx_overflow | intr_rx_frame_err
               | intr_rx_break_err | intr_rx_timeout | intr_rx_parity_err;

  assign obs_gpio_out_o = '0;
  assign obs_gpio_dir_o = '0;
  assign obs_spi_clk_o = 1'b0;
  assign obs_spi_cs0_o = 1'b0;
  assign obs_spi_sdo0_o = 1'b0;
  assign gpio_irq_o = 1'b0;
endmodule
`default_nettype wire
