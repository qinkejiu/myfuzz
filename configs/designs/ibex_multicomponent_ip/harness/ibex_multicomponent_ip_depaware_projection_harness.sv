// Dependency-aware harness for the Ibex + common-IP multi-component target.
//
// The same 512 RFuzz bits are decoded into scenario fields and projected
// through the dependency manifest: boot/fetch sanity, request-response latency,
// MMIO-region event correlation, IP-status-driven IRQ, and low-frequency
// debug/error/NMI priority.  It does not use DUT outputs to construct inputs.

`ifndef IBEX_MCIP_COVERAGE_MSB
`define IBEX_MCIP_COVERAGE_MSB 4095
`endif

module ibex_multicomponent_ip_depaware_projection_harness (
    input  logic         clock,
    input  logic         reset,
    input  logic         io_meta_reset,
    input  logic [511:0] rfuzz_input_bits,
    output logic [`IBEX_MCIP_COVERAGE_MSB:0] __vi_coverage
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
    wire [31:0] seed8 = rfuzz_input_bits[287:256];
    wire [31:0] seed9 = rfuzz_input_bits[319:288];
    wire [31:0] seed10 = rfuzz_input_bits[351:320];
    wire [31:0] seed11 = rfuzz_input_bits[383:352];
    wire [31:0] seed12 = rfuzz_input_bits[415:384];
    wire [31:0] seed13 = rfuzz_input_bits[447:416];
    wire [31:0] seed14 = rfuzz_input_bits[479:448];
    wire [31:0] seed15 = rfuzz_input_bits[511:480];

    wire [2:0] scenario = seed0[2:0] ^ seed8[2:0];
    wire [2:0] ip_focus = seed0[5:3] ^ seed9[2:0];
    wire [2:0] event_sel = seed0[8:6] ^ seed10[2:0];
    wire [2:0] latency_sel = seed0[11:9] ^ seed11[2:0];
    wire [31:0] instr_seed = seed1 ^ {seed5[15:0], seed5[31:16]};
    wire [31:0] data_seed = seed2 ^ seed6 ^ {16'h0, seed12[15:0]};

    logic [31:0] cycle_q;
    always_ff @(posedge clock or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 32'h0;
        end else begin
            cycle_q <= cycle_q + 32'h1;
        end
    end

    function automatic logic [31:0] boot_for_scenario(
        input logic [2:0] scenario_i,
        input logic [31:0] raw_i
    );
        begin
            unique case (scenario_i)
                3'd0: boot_for_scenario = 32'h0000_0000;
                3'd1: boot_for_scenario = 32'h0000_0040;
                3'd2: boot_for_scenario = 32'h0000_0100;
                3'd3: boot_for_scenario = 32'h8001_0000;
                3'd4: boot_for_scenario = 32'h8002_0000;
                default: boot_for_scenario = {raw_i[31:2], 2'b00};
            endcase
        end
    endfunction

    wire [31:0] boot_addr = boot_for_scenario(scenario, seed3);
    wire [31:0] hart_id = {24'h0, seed4[7:0]};
    wire [2:0] instr_latency = (latency_sel == 3'h0) ? 3'b011 : latency_sel;
    wire [2:0] data_latency = (latency_sel ^ scenario) | 3'b001;
    wire [15:0] gpio_pins = seed7[15:0] ^ {12'h0, ip_focus, cycle_q[0]};
    wire uart_focus = (ip_focus == 3'd3) || (scenario == 3'd3);
    wire spi_focus = (ip_focus == 3'd4) || (scenario == 3'd4);
    wire timer_focus = (ip_focus == 3'd1) || (scenario == 3'd1);
    wire gpio_focus = (ip_focus == 3'd2) || (scenario == 3'd2);
    wire uart_rx_valid = uart_focus && (seed13[0] || cycle_q[1]);
    wire [7:0] uart_rx_data = seed13[15:8] ^ seed9[7:0];
    wire spi_miso_valid = spi_focus && (seed13[1] || cycle_q[2]);
    wire [7:0] spi_miso_data = seed13[23:16] ^ seed10[7:0];
    wire timer_tick = timer_focus || seed13[2] || cycle_q[0];

    wire lowfreq_a = &seed14[3:0];
    wire lowfreq_b = &seed14[7:4];
    wire lowfreq_c = &seed14[11:8];
    wire irq_window = (event_sel == 3'd2) || (event_sel == 3'd4) || lowfreq_a;
    wire nmi_window = (event_sel == 3'd6) && lowfreq_b;
    wire debug_window = (event_sel == 3'd7) && lowfreq_c && !nmi_window;
    wire error_window = (event_sel == 3'd5) && lowfreq_b && !debug_window;
    wire [14:0] irq_fast_onehot =
        seed15[0]  ? 15'h0001 :
        seed15[1]  ? 15'h0002 :
        seed15[2]  ? 15'h0004 :
        seed15[3]  ? 15'h0008 :
        seed15[4]  ? 15'h0010 :
        seed15[5]  ? 15'h0020 :
        seed15[6]  ? 15'h0040 :
        seed15[7]  ? 15'h0080 :
        seed15[8]  ? 15'h0100 :
        seed15[9]  ? 15'h0200 :
        seed15[10] ? 15'h0400 :
        seed15[11] ? 15'h0800 :
        seed15[12] ? 15'h1000 :
        seed15[13] ? 15'h2000 :
        seed15[14] ? 15'h4000 : 15'h0;

    wire [14:0] irq_fast = irq_window && !nmi_window ? irq_fast_onehot : 15'h0;
    wire irq_software = irq_window && seed15[15] && !nmi_window;
    wire irq_nm = nmi_window;
    wire debug_req = debug_window;
    wire instr_err = error_window && seed15[16];
    wire data_err = error_window && seed15[17];
    wire [3:0] fetch_enable = {seed15[20:18], 1'b1};

    ibex_multicomponent_ip_top dut (
        .clk_i(clock),
        .rst_ni(rst_ni),
        .boot_addr_i(boot_addr),
        .hart_id_i(hart_id),
        .instr_seed_i(instr_seed),
        .data_seed_i(data_seed),
        .instr_latency_i(instr_latency),
        .data_latency_i(data_latency),
        .gpio_pins_i(gpio_pins),
        .uart_rx_valid_i(uart_rx_valid),
        .uart_rx_data_i(uart_rx_data),
        .spi_miso_valid_i(spi_miso_valid),
        .spi_miso_data_i(spi_miso_data),
        .timer_tick_i(timer_tick),
        .irq_fast_i(irq_fast),
        .irq_software_i(irq_software),
        .irq_nm_i(irq_nm),
        .debug_req_i(debug_req),
        .instr_err_i(instr_err),
        .data_err_i(data_err),
        .fetch_enable_i(fetch_enable),
        .system_observe_o(),
        .ip_observe_o(),
        .__vi_coverage(__vi_coverage)
    );

endmodule
