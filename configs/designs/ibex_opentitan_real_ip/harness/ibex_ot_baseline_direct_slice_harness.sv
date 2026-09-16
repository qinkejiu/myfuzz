`ifndef IBEX_OT_COVERAGE_MSB
`define IBEX_OT_COVERAGE_MSB 4095
`endif

module ibex_ot_baseline_direct_slice_harness (
  input  logic         clock,
  input  logic         reset,
  input  logic         io_meta_reset,
  input  logic [511:0] rfuzz_input_bits,
  output logic [`IBEX_OT_COVERAGE_MSB:0] __vi_coverage
);
  wire rst_ni = ~(reset | io_meta_reset);

  ibex_opentitan_real_ip_top dut (
    .clk_i            (clock),
    .rst_ni           (rst_ni),
    .uart_rx_i        (rfuzz_input_bits[0]),
    .gpio_i           (rfuzz_input_bits[32:1]),
    .strap_en_i       (rfuzz_input_bits[33]),
    .debug_req_i      (rfuzz_input_bits[34]),
    .irq_software_i   (rfuzz_input_bits[35]),
    .irq_external_i   (rfuzz_input_bits[36]),
    .uart_tx_o        (),
    .uart_tx_en_o     (),
    .gpio_o           (),
    .gpio_oe_o        (),
    .timer_irq_o      (),
    .core_instr_addr_o(),
    .__vi_coverage    (__vi_coverage)
  );
endmodule
