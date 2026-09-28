`default_nettype none

// One real OpenTitan UART with a local TL-UL adapter. No CPU or SoC fabric.
module local_opentitan_uart (
  input logic clk, reset,
  input logic req_valid, req_write,
  output logic req_ready,
  input logic [31:0] req_addr, req_wdata,
  input logic [3:0] req_be,
  output logic rsp_valid, rsp_error,
  input logic rsp_ready,
  output logic [31:0] rsp_rdata,
  input logic uart_rx,
  output logic uart_tx, irq, tx_done, tx_watermark, tx_idle
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

  soc_opentitan_uart_target u_uart (
    .clk_i(clk), .rst_ni(~reset),
    .a_valid_i(a_valid), .a_ready_o(a_ready), .a_opcode_i(a_opcode),
    .a_param_i(a_param), .a_size_i(a_size), .a_source_i(a_source),
    .a_address_i(a_address), .a_mask_i(a_mask), .a_data_i(a_data),
    .a_user_i(a_user), .d_valid_o(d_valid), .d_ready_i(d_ready),
    .d_opcode_o(d_opcode), .d_param_o(d_param), .d_size_o(d_size),
    .d_source_o(d_source), .d_sink_o(d_sink), .d_data_o(d_data),
    .d_user_o(d_user), .d_error_o(d_error),
    .env_gpio_in_i('0), .env_uart_rx_i(uart_rx),
    .env_spi_sck_i(1'b0), .env_spi_cs_i(1'b1), .env_spi_sdi_i(1'b0),
    .obs_gpio_out_o(), .obs_gpio_dir_o(),
    .obs_spi_clk_o(), .obs_spi_cs0_o(), .obs_spi_sdo0_o(),
    .obs_uart_tx_o(uart_tx),
    .obs_uart_tx_done_o(tx_done),
    .obs_uart_tx_watermark_o(tx_watermark),
    .irq_o(irq), .gpio_irq_o()
  );

  // Read the real UART STATUS.txidle source without issuing a TL-UL read or
  // advancing its clock. The pinned RTL computes this in uart_core.
  assign tx_idle = u_uart.u_uart.hw2reg.status.txidle.d;
endmodule

`default_nettype wire
