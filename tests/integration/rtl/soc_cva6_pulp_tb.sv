`timescale 1ns/1ps
module soc_cva6_pulp_tb;
  logic clk = 1'b0;
  logic reset = 1'b1;
  integer unsigned cycles = 0;
  logic seen_gpio = 1'b0;
  logic gpio_write_completed = 1'b0;
  logic [31:0] completions_before_gpio = 32'd0;

  always #1 clk = ~clk;

  soc_cva6_pulp_core dut (
      .clk_i(clk), .reset_i(reset),
      .gpio_out_o(), .gpio_dir_o(), .gpio_irq_o(),
      .spi_clk_o(), .spi_cs0_o(), .spi_sdo0_o(),
      .cpu_mmio_transaction_o(), .cpu_transaction_count_o(),
      .cpu_completion_count_o(), .fabric_protocol_error_o()
  );

  always @(posedge clk) begin
    cycles = cycles + 1;
    if (!reset && dut.gpio_out_o[7:0] == 8'hA5 && !seen_gpio) begin
      seen_gpio = 1'b1;
      completions_before_gpio = dut.cpu_completion_count_o;
    end
    if (seen_gpio && dut.cpu_completion_count_o > completions_before_gpio)
      gpio_write_completed = 1'b1;
    if (gpio_write_completed) begin
      if (dut.cpu_transaction_count_o == 0 || dut.cpu_completion_count_o == 0)
        $fatal(1, "GPIO changed without a completed CVA6 transaction");
      if (dut.fabric_protocol_error_o)
        $fatal(1, "SoC fabric protocol error");
      $display("SOC_CVA6_PULP_REAL_OK cpu_tx=%0d cpu_done=%0d gpio=%h",
               dut.cpu_transaction_count_o, dut.cpu_completion_count_o,
               dut.gpio_out_o);
      $finish;
    end
    if (cycles >= 20000)
      $fatal(1, "CVA6 PULP runtime timeout tx=%0d done=%0d gpio=%h",
             dut.cpu_transaction_count_o, dut.cpu_completion_count_o,
             dut.gpio_out_o);
  end

  initial begin
    repeat (10) @(negedge clk);
    reset = 1'b0;
  end
endmodule
