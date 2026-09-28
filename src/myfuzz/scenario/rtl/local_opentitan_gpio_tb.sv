`default_nettype none

// One OpenTitan GPIO RTL instance with its native TL-UL protocol adapter.
// This local acceptance harness has no CPU, crossbar, bridge or other IP.
module local_opentitan_gpio_tb;
  logic clk = 1'b0;
  always #5 clk = ~clk;
  logic reset = 1'b1;

  logic req_valid, req_ready, req_write;
  logic [31:0] req_addr, req_wdata;
  logic [3:0] req_be;
  logic rsp_valid, rsp_ready, rsp_error;
  logic [31:0] rsp_rdata;

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

  logic [31:0] gpio_in, gpio_out, gpio_dir;
  logic irq, gpio_irq;

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

  soc_opentitan_gpio_target u_gpio (
    .clk_i(clk), .rst_ni(~reset),
    .a_valid_i(a_valid), .a_ready_o(a_ready), .a_opcode_i(a_opcode),
    .a_param_i(a_param), .a_size_i(a_size), .a_source_i(a_source),
    .a_address_i(a_address), .a_mask_i(a_mask), .a_data_i(a_data),
    .a_user_i(a_user), .d_valid_o(d_valid), .d_ready_i(d_ready),
    .d_opcode_o(d_opcode), .d_param_o(d_param), .d_size_o(d_size),
    .d_source_o(d_source), .d_sink_o(d_sink), .d_data_o(d_data),
    .d_user_o(d_user), .d_error_o(d_error),
    .env_gpio_in_i(gpio_in), .env_uart_rx_i(1'b1),
    .env_spi_sck_i(1'b0), .env_spi_cs_i(1'b1), .env_spi_sdi_i(1'b0),
    .obs_gpio_out_o(gpio_out), .obs_gpio_dir_o(gpio_dir),
    .obs_spi_clk_o(), .obs_spi_cs0_o(), .obs_spi_sdo0_o(),
    .obs_uart_tx_o(), .irq_o(irq), .gpio_irq_o(gpio_irq)
  );

  task automatic request(input logic write, input logic [31:0] addr,
                         input logic [31:0] data, output logic [31:0] readback);
    integer cycles;
    @(negedge clk);
    req_valid = 1'b1;
    req_write = write;
    req_addr = addr;
    req_wdata = data;
    req_be = 4'hf;
    #1;
    cycles = 0;
    while (!req_ready && cycles < 100) begin
      @(negedge clk);
      #1;
      cycles++;
    end
    if (!req_ready) $fatal(1, "GPIO request acceptance timed out");
    @(posedge clk);
    @(negedge clk);
    req_valid = 1'b0;
    cycles = 0;
    while (!rsp_valid && cycles < 100) begin
      @(negedge clk);
      cycles++;
    end
    if (!rsp_valid) $fatal(1, "GPIO response timed out");
    if (rsp_error) $fatal(1, "GPIO returned TL-UL error at %08x", addr);
    readback = rsp_rdata;
    @(posedge clk);
  endtask

  logic [31:0] readback;
  initial begin
    req_valid = 1'b0;
    req_write = 1'b0;
    req_addr = 32'd0;
    req_wdata = 32'd0;
    req_be = 4'd0;
    rsp_ready = 1'b1;
    gpio_in = 32'd0;
    repeat (5) @(negedge clk);
    reset = 1'b0;
    repeat (5) @(negedge clk);

    request(1'b1, 32'h4000_0014, 32'h0000_00a5, readback);
    repeat (16) @(negedge clk);
    request(1'b0, 32'h4000_0014, 32'd0, readback);
    if (readback != 32'h0000_00a5 || gpio_out != 32'h0000_00a5)
      $fatal(1, "real GPIO output/readback mismatch: %08x %08x", gpio_out, readback);

    request(1'b1, 32'h4000_0004, 32'h0000_0001, readback);
    request(1'b1, 32'h4000_002c, 32'h0000_0001, readback);
    repeat (8) @(negedge clk);
    gpio_in = 32'h0000_0001;
    repeat (24) @(negedge clk);
    if (!gpio_irq || !irq)
      $fatal(1, "real GPIO rising-edge interrupt was not observed");
    if (gpio_out != 32'h0000_00a5)
      $fatal(1, "GPIO output did not persist until later interrupt");
    $display("OT_GPIO_LOCAL_OK out=%08x irq=%0d", gpio_out, irq);
    $finish;
  end
endmodule

`default_nettype wire
