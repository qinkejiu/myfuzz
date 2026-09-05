// Fixed RFuzz transport harness for the Ibex protocol composition.
//
// The fuzzer ABI remains 56 bytes -> 395 effective bits.  Bits [186:0]
// directly seed the generated wrapper inputs.  Bits [394:187] are folded into
// a deterministic 32-bit salt and mixed into those same inputs; no additional
// random field or feedback channel is introduced.
`ifndef IBEX_PROTOCOL_COVERAGE_MSB
`define IBEX_PROTOCOL_COVERAGE_MSB 4095
`endif

module ibex_protocol_composition_fixed_395_harness (
    input  logic                                  clock,
    input  logic                                  reset,
    input  logic                                  io_meta_reset,
    input  logic [394:0]                          rfuzz_input_bits,
    output logic [`IBEX_PROTOCOL_COVERAGE_MSB:0]  __vi_coverage
);
    wire rst_ni = ~(reset | io_meta_reset);

    function automatic [31:0] fold_extra(input logic [207:0] value);
        integer index;
        begin
            fold_extra = 32'h0;
            for (index = 0; index < 208; index = index + 1) begin
                fold_extra[index % 32] = fold_extra[index % 32] ^ value[index];
            end
        end
    endfunction

    wire [31:0] extra_mix = fold_extra(rfuzz_input_bits[394:187]);
    wire [31:0] boot_addr_i = rfuzz_input_bits[31:0] ^ extra_mix;
    wire [31:0] hart_id_i = rfuzz_input_bits[63:32] ^ {extra_mix[15:0], extra_mix[31:16]};
    wire [31:0] instr_seed_i = rfuzz_input_bits[95:64] ^ {extra_mix[7:0], extra_mix[31:8]};
    wire [31:0] data_seed_i = rfuzz_input_bits[127:96] ^ {extra_mix[23:0], extra_mix[31:24]};
    wire [15:0] gpio_pins_i = rfuzz_input_bits[143:128] ^ extra_mix[15:0];
    wire uart_rx_valid_i = rfuzz_input_bits[144] ^ extra_mix[0];
    wire [7:0] uart_rx_data_i = rfuzz_input_bits[152:145] ^ extra_mix[7:0];
    wire spi_miso_valid_i = rfuzz_input_bits[153] ^ extra_mix[1];
    wire [7:0] spi_miso_data_i = rfuzz_input_bits[161:154] ^ extra_mix[15:8];
    wire timer_tick_i = rfuzz_input_bits[162] ^ extra_mix[2];
    wire [14:0] irq_fast_i = rfuzz_input_bits[177:163] ^ extra_mix[14:0];
    wire irq_software_i = rfuzz_input_bits[178] ^ extra_mix[3];
    wire irq_nm_i = rfuzz_input_bits[179] ^ extra_mix[4];
    wire debug_req_i = rfuzz_input_bits[180] ^ extra_mix[5];
    wire instr_err_i = rfuzz_input_bits[181] ^ extra_mix[6];
    wire data_err_i = rfuzz_input_bits[182] ^ extra_mix[7];
    wire [3:0] fetch_enable_i = rfuzz_input_bits[186:183] ^ extra_mix[3:0];

    wire [31:0] system_observe_o;
    wire [31:0] ip_observe_o;

    ibex_protocol_composition_top dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .boot_addr_i(boot_addr_i),
        .hart_id_i(hart_id_i),
        .instr_seed_i(instr_seed_i),
        .data_seed_i(data_seed_i),
        .gpio_pins_i(gpio_pins_i),
        .uart_rx_valid_i(uart_rx_valid_i),
        .uart_rx_data_i(uart_rx_data_i),
        .spi_miso_valid_i(spi_miso_valid_i),
        .spi_miso_data_i(spi_miso_data_i),
        .timer_tick_i(timer_tick_i),
        .irq_fast_i(irq_fast_i),
        .irq_software_i(irq_software_i),
        .irq_nm_i(irq_nm_i),
        .debug_req_i(debug_req_i),
        .instr_err_i(instr_err_i),
        .data_err_i(data_err_i),
        .fetch_enable_i(fetch_enable_i),
        .system_observe_o(system_observe_o),
        .ip_observe_o(ip_observe_o),
        .__vi_coverage(__vi_coverage)
    );
endmodule
