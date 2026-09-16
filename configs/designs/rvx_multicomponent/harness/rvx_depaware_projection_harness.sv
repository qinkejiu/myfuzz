`ifndef RVX_COVERAGE_MSB
`define RVX_COVERAGE_MSB 4095
`endif

module rvx_depaware_projection_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [511:0] rfuzz_input_bits,
    output logic [`RVX_COVERAGE_MSB:0] __vi_coverage
);
    wire dut_reset = reset | io_meta_reset;
    logic [15:0] cycle_q;

    always_ff @(posedge clock) begin
        if (dut_reset)
            cycle_q <= 16'h0;
        else
            cycle_q <= cycle_q + 16'h1;
    end

    // Keep the core progressing while retaining a short, raw-controlled halt event.
    wire halt_event = rfuzz_input_bits[0] && (cycle_q[7:4] == 4'hf);
    // UART and SPI serial inputs transition over time instead of remaining stuck per test.
    wire uart_rx_event = rfuzz_input_bits[8 + cycle_q[2:0]] ^ cycle_q[3];
    wire spi_poci_event = rfuzz_input_bits[32 + cycle_q[3:0]] ^ cycle_q[1];
    // GPIO changes at the slower peripheral timescale and is independent of serial phase.
    wire gpio_event = rfuzz_input_bits[64 + cycle_q[5:3]] ^ cycle_q[5];

    rvx #(
        .MEMORY_INIT_FILE("configs/designs/rvx_multicomponent/programs/mmio_exerciser.hex")
    ) dut (
        .clock(clock),
        .reset(dut_reset),
        .halt(halt_event),
        .uart_rx(uart_rx_event),
        .uart_tx(),
        .gpio_input(gpio_event),
        .gpio_oe(),
        .gpio_output(),
        .sclk(),
        .pico(),
        .poci(spi_poci_event),
        .cs(),
        .__vi_coverage(__vi_coverage)
    );
endmodule
