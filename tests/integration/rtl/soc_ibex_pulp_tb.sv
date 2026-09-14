// Small real-RTL smoke: a fuzz beat traverses the same fabric as Ibex and
// updates the pinned PULP GPIO register.  The Python acceptance test supplies
// a boot image so Ibex also elaborates and fetches from the real ROM target.
module soc_ibex_pulp_tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  logic stim_offer = 1'b0;
  logic [2:0] stim_target_selector = 3'd0;
  logic [31:0] stim_offset = 32'd0;
  logic stim_write = 1'b0;
  logic [31:0] stim_wdata = 32'd0;
  logic [3:0] stim_be = 4'hf;
  logic [7:0] gpio_in = 8'd0;
  logic spi_sck = 1'b0;
  logic spi_cs = 1'b1;
  logic irq_claim = 1'b0;
  logic irq_complete = 1'b0;
  wire [31:0] gpio_out;
  wire [31:0] gpio_dir;
  wire gpio_irq, spi_clk, spi_cs0, spi_sdo0, cpu_irq;
  wire cpu_tx, fuzz_tx, fabric_error;
  wire [31:0] cpu_count, fuzz_count, cpu_done, fuzz_done;
  logic prev_spi_clk = 1'b0;
  logic spi_seen_selected = 1'b0;
  logic spi_seen_toggle = 1'b0;

  always #1 clk = ~clk;

  // Observe the real APB SPI outputs, rather than treating successful APB
  // register writes as proof that the controller entered its transfer state.
  always @(posedge clk) begin
    if (reset) begin
      prev_spi_clk <= 1'b0;
      spi_seen_selected <= 1'b0;
      spi_seen_toggle <= 1'b0;
    end else begin
      if (!spi_cs0) spi_seen_selected <= 1'b1;
      if (spi_clk != prev_spi_clk) spi_seen_toggle <= 1'b1;
      prev_spi_clk <= spi_clk;
    end
  end

  soc_ibex_pulp_core dut (
      .clk_i(clk), .reset_i(reset), .stim_offer_i(stim_offer),
      .stim_target_selector_i(stim_target_selector), .stim_offset_i(stim_offset),
      .stim_write_i(stim_write), .stim_wdata_i(stim_wdata), .stim_be_i(stim_be),
      .gpio_in_i(gpio_in), .spi_sck_i(spi_sck), .spi_cs_i(spi_cs),
      .irq_claim_i(irq_claim), .irq_complete_i(irq_complete),
      .gpio_out_o(gpio_out), .gpio_dir_o(gpio_dir), .gpio_irq_o(gpio_irq),
      .spi_clk_o(spi_clk), .spi_cs0_o(spi_cs0), .spi_sdo0_o(spi_sdo0),
      .cpu_irq_o(cpu_irq), .cpu_mmio_transaction_o(cpu_tx),
      .fuzz_mmio_transaction_o(fuzz_tx), .cpu_transaction_count_o(cpu_count),
      .fuzz_transaction_count_o(fuzz_count), .cpu_completion_count_o(cpu_done),
      .fuzz_completion_count_o(fuzz_done), .fabric_protocol_error_o(fabric_error)
  );

  // Drive each offer around a falling edge and hold it across a complete
  // rising edge.  This keeps the source handshake independent of simulator
  // active/NBA scheduling in the testbench itself.
  task automatic drive_fuzz_write(
      input logic [2:0] selector,
      input logic [31:0] offset,
      input logic [31:0] data,
      input integer expected_completion,
      input string label
  );
    begin
      @(negedge clk);
      stim_target_selector = selector;
      stim_offset = offset;
      stim_write = 1'b1;
      stim_wdata = data;
      stim_be = 4'hf;
      stim_offer = 1'b1;
      @(negedge clk);
      stim_offer = 1'b0;
      repeat (200) @(posedge clk);
      if (fuzz_done != expected_completion)
        $fatal(1, "%s beat did not complete: count=%0d", label, fuzz_done);
      $display("%s_DONE fuzz_done=%0d", label, fuzz_done);
    end
  endtask

  initial begin
    repeat (8) @(posedge clk);
    reset <= 1'b0;
    // Let the real Ibex fetch and retire the directed GPIO store before the
    // independent fuzz source is offered.
    repeat (80) @(posedge clk);
    if (gpio_out[7:0] !== 8'h5a) $fatal(1, "real Ibex GPIO store did not reach PULP IP: %h", gpio_out);
    drive_fuzz_write(3'd2, 32'h0c, 32'h0000_00a5, 1, "GPIO");
    #2;
    if (gpio_out[7:0] !== 8'ha5) $fatal(1, "PULP GPIO write did not reach real IP: %h", gpio_out);

    // Configure and start a real PULP APB SPI write through the same fuzz
    // beat/fabric/APB path.  The controller should assert CS0 and toggle its
    // generated clock while consuming the TX FIFO byte.
    drive_fuzz_write(3'd3, 32'h04, 32'h0000_0000, 2, "SPI_CLKDIV");
    drive_fuzz_write(3'd3, 32'h10, 32'h0008_0000, 3, "SPI_LEN");
    drive_fuzz_write(3'd3, 32'h18, 32'h0000_003c, 4, "SPI_TX");
    drive_fuzz_write(3'd3, 32'h00, 32'h0000_0102, 5, "SPI_STATUS");
    repeat (200) @(posedge clk);
    if (!spi_seen_selected) $fatal(1, "real PULP SPI controller never selected CS0");
    if (!spi_seen_toggle) $fatal(1, "real PULP SPI controller never toggled its generated clock");
    if (fuzz_count != 32'd5) $fatal(1, "fuzz source accepted count mismatch: %0d", fuzz_count);
    if (cpu_count < 32'd2) $fatal(1, "real Ibex did not reach a data transaction: %0d", cpu_count);
    if (fabric_error) $fatal(1, "fabric protocol error");
    $display("SOC_IBEX_PULP_REAL_OK cpu_tx=%0d fuzz_tx=%0d gpio=%h", cpu_count, fuzz_count, gpio_out);
    $finish;
  end
endmodule
