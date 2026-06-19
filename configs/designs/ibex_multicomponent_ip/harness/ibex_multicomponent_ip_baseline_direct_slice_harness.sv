// Baseline harness for the Ibex + common-IP multi-component target.
//
// The RFuzz input vector is fixed-sliced directly into the wrapper ports.
// No address/protocol/IP/IRQ dependency projection is applied here.

`ifndef IBEX_MCIP_COVERAGE_MSB
`define IBEX_MCIP_COVERAGE_MSB 4095
`endif

module ibex_multicomponent_ip_baseline_direct_slice_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [511:0] rfuzz_input_bits,
    output logic [`IBEX_MCIP_COVERAGE_MSB:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    ibex_multicomponent_ip_top dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .boot_addr_i(rfuzz_input_bits[31:0]),
        .hart_id_i(rfuzz_input_bits[63:32]),
        .instr_seed_i(rfuzz_input_bits[95:64]),
        .data_seed_i(rfuzz_input_bits[127:96]),
        .instr_latency_i(rfuzz_input_bits[130:128]),
        .data_latency_i(rfuzz_input_bits[133:131]),
        .gpio_pins_i(rfuzz_input_bits[149:134]),
        .uart_rx_valid_i(rfuzz_input_bits[150]),
        .uart_rx_data_i(rfuzz_input_bits[158:151]),
        .spi_miso_valid_i(rfuzz_input_bits[159]),
        .spi_miso_data_i(rfuzz_input_bits[167:160]),
        .timer_tick_i(rfuzz_input_bits[168]),
        .irq_fast_i(rfuzz_input_bits[183:169]),
        .irq_software_i(rfuzz_input_bits[184]),
        .irq_nm_i(rfuzz_input_bits[185]),
        .debug_req_i(rfuzz_input_bits[186]),
        .instr_err_i(rfuzz_input_bits[187]),
        .data_err_i(rfuzz_input_bits[188]),
        .fetch_enable_i(rfuzz_input_bits[192:189]),
        .system_observe_o(),
        .ip_observe_o(),
        .__vi_coverage(__vi_coverage)
    );

endmodule
