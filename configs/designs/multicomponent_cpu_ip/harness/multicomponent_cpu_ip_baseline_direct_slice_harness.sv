// Baseline harness for the CPU + multi-IP smoke target.
//
// This is the clean comparison baseline: the RFuzz input vector is split into
// fixed fields and wired directly to the target.  It intentionally does not
// repair address/protocol/IRQ/debug dependencies between fields.

module multicomponent_cpu_ip_baseline_direct_slice_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [255:0] rfuzz_input_bits,
    output logic [101:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    wire        fetch_enable = rfuzz_input_bits[0];
    wire        cpu_req_valid = rfuzz_input_bits[1];
    wire        cpu_req_write = rfuzz_input_bits[2];
    wire [31:0] cpu_req_addr = rfuzz_input_bits[34:3];
    wire [31:0] cpu_req_wdata = rfuzz_input_bits[66:35];
    wire [3:0]  cpu_req_be = rfuzz_input_bits[70:67];
    wire [4:0]  ip_ready = rfuzz_input_bits[75:71];
    wire        timer_tick = rfuzz_input_bits[76];
    wire [15:0] gpio_pins = rfuzz_input_bits[92:77];
    wire        uart_rx_valid = rfuzz_input_bits[93];
    wire [7:0]  uart_rx_data = rfuzz_input_bits[101:94];
    wire        spi_miso_valid = rfuzz_input_bits[102];
    wire [7:0]  spi_miso_data = rfuzz_input_bits[110:103];
    wire        debug_req = rfuzz_input_bits[111];
    wire        error = rfuzz_input_bits[112];

    multicomponent_cpu_ip_top dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .fetch_enable_i(fetch_enable),
        .cpu_req_valid_i(cpu_req_valid),
        .cpu_req_write_i(cpu_req_write),
        .cpu_req_addr_i(cpu_req_addr),
        .cpu_req_wdata_i(cpu_req_wdata),
        .cpu_req_be_i(cpu_req_be),
        .ip_ready_i(ip_ready),
        .timer_tick_i(timer_tick),
        .gpio_pins_i(gpio_pins),
        .uart_rx_valid_i(uart_rx_valid),
        .uart_rx_data_i(uart_rx_data),
        .spi_miso_valid_i(spi_miso_valid),
        .spi_miso_data_i(spi_miso_data),
        .debug_req_i(debug_req),
        .error_i(error),
        .cpu_observe_o(),
        .bus_observe_o(),
        .ip_observe_o(),
        .__vi_coverage(__vi_coverage)
    );

endmodule
