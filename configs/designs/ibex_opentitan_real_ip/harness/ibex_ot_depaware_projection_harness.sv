`ifndef IBEX_OT_COVERAGE_MSB
`define IBEX_OT_COVERAGE_MSB 4095
`endif

module ibex_ot_depaware_projection_harness (
  input  logic         clock,
  input  logic         reset,
  input  logic         io_meta_reset,
  input  logic [511:0] rfuzz_input_bits,
  output logic [`IBEX_OT_COVERAGE_MSB:0] __vi_coverage
);
  wire rst_ni = ~(reset | io_meta_reset);
  logic [15:0] cycle_q;

  always_ff @(posedge clock or negedge rst_ni) begin
    if (!rst_ni) begin
      cycle_q <= '0;
    end else begin
      cycle_q <= cycle_q + 16'd1;
    end
  end

  wire [4:0] gpio_shift = cycle_q[8:4] ^ rfuzz_input_bits[44:40];
  wire [31:0] gpio_seed = rfuzz_input_bits[95:64] ^ rfuzz_input_bits[159:128];
  wire [31:0] gpio_event =
      (gpio_seed << gpio_shift) | (gpio_seed >> (5'd0 - gpio_shift));
  wire uart_rx_event =
      rfuzz_input_bits[192 + cycle_q[2:0]] ^ cycle_q[4] ^ cycle_q[7];

  wire strap_event = rfuzz_input_bits[200] && (cycle_q == 16'd8);
  wire irq_window = cycle_q[7:0] == rfuzz_input_bits[239:232];
  wire debug_window = cycle_q[7:0] == {2'b00, rfuzz_input_bits[247:242]};
  wire irq_software_event = irq_window && rfuzz_input_bits[240];
  wire irq_external_event = irq_window && rfuzz_input_bits[241];
  wire debug_event = debug_window && rfuzz_input_bits[250] &&
                     !irq_software_event && !irq_external_event;

  ibex_opentitan_real_ip_top dut (
    .clk_i            (clock),
    .rst_ni           (rst_ni),
    .uart_rx_i        (uart_rx_event),
    .gpio_i           (gpio_event),
    .strap_en_i       (strap_event),
    .debug_req_i      (debug_event),
    .irq_software_i   (irq_software_event),
    .irq_external_i   (irq_external_event),
    .uart_tx_o        (),
    .uart_tx_en_o     (),
    .gpio_o           (),
    .gpio_oe_o        (),
    .timer_irq_o      (),
    .core_instr_addr_o(),
    .__vi_coverage    (__vi_coverage)
  );
endmodule
