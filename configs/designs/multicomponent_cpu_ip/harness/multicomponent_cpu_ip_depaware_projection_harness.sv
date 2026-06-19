// Dependency-aware harness for the CPU + multi-IP smoke target.
//
// The same 256 RFuzz bits are first decoded as scenario/data fields and then
// projected through explicit CPU/bus/IP dependency rules.  This remains a fuzz
// harness: raw bits still choose regions, data, latency, and low-frequency
// events; the harness only repairs relationships that the manifest declares.

module multicomponent_cpu_ip_depaware_projection_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [255:0] rfuzz_input_bits,
    output logic [101:0] __vi_coverage
);

    logic rst_ni;
    assign rst_ni = ~(reset | io_meta_reset);

    wire [31:0] seed0 = rfuzz_input_bits[31:0];
    wire [31:0] seed1 = rfuzz_input_bits[63:32];
    wire [31:0] seed2 = rfuzz_input_bits[95:64];
    wire [31:0] seed3 = rfuzz_input_bits[127:96];
    wire [31:0] seed4 = rfuzz_input_bits[159:128];
    wire [31:0] seed5 = rfuzz_input_bits[191:160];
    wire [31:0] seed6 = rfuzz_input_bits[223:192];
    wire [31:0] seed7 = rfuzz_input_bits[255:224];

    wire [2:0]  region_sel = seed0[2:0] ^ seed4[2:0];
    wire [1:0]  op_sel = seed0[4:3] ^ seed5[1:0];
    wire [3:0]  byte_lane_sel = seed0[8:5] ^ seed6[3:0];
    wire [2:0]  latency_sel = seed0[11:9] ^ seed7[2:0];
    wire [2:0]  event_sel = seed0[14:12] ^ seed7[5:3];
    wire [31:0] data_salt = seed1 ^ {seed2[15:0], seed2[31:16]} ^ seed6;
    wire [15:0] gpio_salt = seed3[15:0] ^ seed4[31:16];
    wire [7:0]  uart_salt = seed3[23:16] ^ seed5[15:8];
    wire [7:0]  spi_salt = seed3[31:24] ^ seed5[23:16];

    logic [31:0] cycle_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 32'h0;
        end else begin
            cycle_q <= cycle_q + 32'h1;
        end
    end

    function automatic logic [31:0] region_base(input logic [2:0] region);
        begin
            unique case (region)
                3'd1: region_base = 32'h8000_0000; // UART
                3'd2: region_base = 32'h8001_0000; // timer
                3'd3: region_base = 32'h8002_0000; // GPIO
                3'd4: region_base = 32'h8003_0000; // SPI
                default: region_base = 32'h0000_0000; // RAM
            endcase
        end
    endfunction

    wire [31:0] aligned_offset = {24'h0, seed2[9:2], 2'b00};
    wire [31:0] cpu_req_addr = region_base(region_sel) ^ aligned_offset;
    wire        cpu_req_write = op_sel[0];
    wire        cpu_req_valid = seed0[15] | seed0[16] | (region_sel != 3'd0);
    wire [31:0] cpu_req_wdata = data_salt ^ {16'h0, gpio_salt};
    wire [3:0]  cpu_req_be = (byte_lane_sel == 4'h0) ? 4'hf : byte_lane_sel;

    wire        region_is_ram = (region_sel == 3'd0) || (region_sel > 3'd4);
    wire        region_is_uart = (region_sel == 3'd1);
    wire        region_is_timer = (region_sel == 3'd2);
    wire        region_is_gpio = (region_sel == 3'd3);
    wire        region_is_spi = (region_sel == 3'd4);

    wire        response_now = cpu_req_valid && (latency_sel[0] || cycle_q[0] || op_sel[1]);
    wire [4:0]  selected_ready = {
        region_is_spi,
        region_is_uart,
        region_is_gpio,
        region_is_timer,
        region_is_ram
    };
    wire [4:0]  raw_ready_bias = {
        seed7[12],
        seed7[11],
        seed7[10],
        seed7[9],
        seed7[8]
    };
    wire [4:0]  ip_ready = response_now ? (selected_ready | raw_ready_bias) : raw_ready_bias;

    wire        fetch_enable = seed0[17] | seed0[18] | cpu_req_valid;
    wire        timer_tick = seed4[0] | region_is_timer | cycle_q[1];
    wire [15:0] gpio_pins = gpio_salt ^ {12'h0, region_sel, cycle_q[0]};
    wire        uart_rx_valid = region_is_uart && (seed4[1] | cycle_q[2]);
    wire [7:0]  uart_rx_data = uart_salt ^ cpu_req_addr[7:0];
    wire        spi_miso_valid = region_is_spi && (seed4[2] | cycle_q[3]);
    wire [7:0]  spi_miso_data = spi_salt ^ cpu_req_wdata[15:8];

    wire        irq_window = (event_sel == 3'd3) || (event_sel == 3'd5);
    wire        fault_window = (event_sel == 3'd6) && cycle_q[2];
    wire        debug_window = (event_sel == 3'd7) && !fault_window && cycle_q[1];
    wire        debug_req = debug_window;
    wire        error = fault_window && !debug_window;

    multicomponent_cpu_ip_top dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .fetch_enable_i(fetch_enable),
        .cpu_req_valid_i(cpu_req_valid),
        .cpu_req_write_i(cpu_req_write),
        .cpu_req_addr_i(cpu_req_addr),
        .cpu_req_wdata_i(cpu_req_wdata),
        .cpu_req_be_i(cpu_req_be),
        .ip_ready_i(ip_ready | {3'h0, irq_window, 1'b0}),
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
