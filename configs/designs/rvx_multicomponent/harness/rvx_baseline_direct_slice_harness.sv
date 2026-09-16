`ifndef RVX_COVERAGE_MSB
`define RVX_COVERAGE_MSB 4095
`endif

module rvx_baseline_direct_slice_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [511:0] rfuzz_input_bits,
    output logic [`RVX_COVERAGE_MSB:0] __vi_coverage
);
    wire dut_reset = reset | io_meta_reset;

    rvx #(
        .MEMORY_INIT_FILE("configs/designs/rvx_multicomponent/programs/mmio_exerciser.hex")
    ) dut (
        .clock(clock),
        .reset(dut_reset),
        .halt(rfuzz_input_bits[0]),
        .uart_rx(rfuzz_input_bits[1]),
        .uart_tx(),
        .gpio_input(rfuzz_input_bits[2]),
        .gpio_oe(),
        .gpio_output(),
        .sclk(),
        .pico(),
        .poci(rfuzz_input_bits[3]),
        .cs(),
        .__vi_coverage(__vi_coverage)
    );
endmodule
