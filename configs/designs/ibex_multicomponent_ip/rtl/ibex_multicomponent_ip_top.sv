module ibex_multicomponent_ip_top (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic [31:0] boot_addr_i,
    input  logic [31:0] hart_id_i,
    input  logic [31:0] instr_seed_i,
    input  logic [31:0] data_seed_i,
    input  logic [2:0]  instr_latency_i,
    input  logic [2:0]  data_latency_i,
    input  logic [15:0] gpio_pins_i,
    input  logic        uart_rx_valid_i,
    input  logic [7:0]  uart_rx_data_i,
    input  logic        spi_miso_valid_i,
    input  logic [7:0]  spi_miso_data_i,
    input  logic        timer_tick_i,
    input  logic [14:0] irq_fast_i,
    input  logic        irq_software_i,
    input  logic        irq_nm_i,
    input  logic        debug_req_i,
    input  logic        instr_err_i,
    input  logic        data_err_i,
    input  logic [3:0]  fetch_enable_i,
    output logic [31:0] system_observe_o,
    output logic [31:0] ip_observe_o
);

    localparam logic [2:0] REGION_RAM   = 3'd0;
    localparam logic [2:0] REGION_TIMER = 3'd1;
    localparam logic [2:0] REGION_GPIO  = 3'd2;
    localparam logic [2:0] REGION_UART  = 3'd3;
    localparam logic [2:0] REGION_SPI   = 3'd4;

    logic [31:0] cycle_q;

    logic instr_req;
    logic instr_gnt;
    logic instr_rvalid;
    logic [31:0] instr_addr;
    logic [31:0] instr_rdata;

    logic data_req;
    logic data_gnt;
    logic data_rvalid;
    logic data_we;
    logic [3:0] data_be;
    logic [31:0] data_addr;
    logic [31:0] data_wdata;
    logic [31:0] data_rdata;

    logic [31:0] instr_ram_rdata;
    logic [31:0] data_ram_rdata;
    logic [31:0] timer_rdata;
    logic [31:0] gpio_rdata;
    logic [31:0] uart_rdata;
    logic [31:0] spi_rdata;

    logic timer_valid;
    logic gpio_valid;
    logic uart_valid;
    logic spi_valid;
    logic ram_data_valid;
    logic timer_irq;
    logic gpio_irq;
    logic uart_irq;
    logic spi_irq;
    logic irq_external;
    logic [7:0] instr_ram_state;
    logic [7:0] data_ram_state;
    logic [7:0] timer_state;
    logic [7:0] gpio_state;
    logic [7:0] uart_state;
    logic [7:0] spi_state;
    logic [2:0] data_region;
    logic [21:0] ic_tag_rdata [0:1];
    logic [63:0] ic_data_rdata [0:1];

    assign irq_external = gpio_irq || uart_irq || spi_irq;
    assign ic_tag_rdata[0] = 22'h0;
    assign ic_tag_rdata[1] = 22'h0;
    assign ic_data_rdata[0] = 64'h0;
    assign ic_data_rdata[1] = 64'h0;

    always_ff @(posedge clk_i or negedge rst_ni) begin
        if (!rst_ni) begin
            cycle_q <= 32'h0;
        end else begin
            cycle_q <= cycle_q + 32'h1;
        end
    end

    always_comb begin
        unique case (data_addr[31:16])
            16'h8001: data_region = REGION_TIMER;
            16'h8002: data_region = REGION_GPIO;
            16'h8003: data_region = REGION_UART;
            16'h8004: data_region = REGION_SPI;
            default:  data_region = REGION_RAM;
        endcase
    end

    assign timer_valid = data_req && (data_region == REGION_TIMER);
    assign gpio_valid = data_req && (data_region == REGION_GPIO);
    assign uart_valid = data_req && (data_region == REGION_UART);
    assign spi_valid = data_req && (data_region == REGION_SPI);
    assign ram_data_valid = data_req && (data_region == REGION_RAM);

    assign instr_gnt = instr_req && (instr_latency_i[0] || cycle_q[0]);
    assign instr_rvalid = instr_gnt && (instr_latency_i[1] || cycle_q[1] || instr_latency_i[2]);
    assign data_gnt = data_req && (data_latency_i[0] || cycle_q[0]);
    assign data_rvalid = data_gnt && (data_latency_i[1] || cycle_q[1] || data_latency_i[2]);

    ibex_mcip_ram u_instr_ram (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(instr_req),
        .write_i(1'b0),
        .addr_i(instr_addr),
        .wdata_i(32'h0),
        .be_i(4'h0),
        .seed_i(instr_seed_i),
        .rdata_o(instr_ram_rdata),
        .state_o(instr_ram_state)
    );

    assign instr_rdata = instr_ram_rdata ^ instr_seed_i;

    ibex_mcip_ram u_data_ram (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(ram_data_valid),
        .write_i(ram_data_valid && data_we),
        .addr_i(data_addr),
        .wdata_i(data_wdata),
        .be_i(data_be),
        .seed_i(data_seed_i),
        .rdata_o(data_ram_rdata),
        .state_o(data_ram_state)
    );

    ibex_mcip_timer u_timer (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(timer_valid),
        .write_i(data_we),
        .addr_i(data_addr),
        .wdata_i(data_wdata ^ data_seed_i),
        .tick_i(timer_tick_i),
        .rdata_o(timer_rdata),
        .irq_o(timer_irq),
        .state_o(timer_state)
    );

    ibex_mcip_gpio u_gpio (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(gpio_valid),
        .write_i(data_we),
        .addr_i(data_addr),
        .wdata_i(data_wdata),
        .pins_i(gpio_pins_i),
        .rdata_o(gpio_rdata),
        .irq_o(gpio_irq),
        .state_o(gpio_state)
    );

    ibex_mcip_uart u_uart (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(uart_valid),
        .write_i(data_we),
        .addr_i(data_addr),
        .wdata_i(data_wdata),
        .rx_valid_i(uart_rx_valid_i),
        .rx_data_i(uart_rx_data_i),
        .rdata_o(uart_rdata),
        .irq_o(uart_irq),
        .state_o(uart_state)
    );

    ibex_mcip_spi u_spi (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(spi_valid),
        .write_i(data_we),
        .addr_i(data_addr),
        .wdata_i(data_wdata),
        .miso_valid_i(spi_miso_valid_i),
        .miso_data_i(spi_miso_data_i),
        .rdata_o(spi_rdata),
        .irq_o(spi_irq),
        .state_o(spi_state)
    );

    always_comb begin
        unique case (data_region)
            REGION_TIMER: data_rdata = timer_rdata;
            REGION_GPIO: data_rdata = gpio_rdata;
            REGION_UART: data_rdata = uart_rdata;
            REGION_SPI: data_rdata = spi_rdata;
            default: data_rdata = data_ram_rdata ^ data_seed_i;
        endcase
    end

    ibex_core #(
        .PMPEnable(1'b0),
        .SecureIbex(1'b0),
        .RV32M(ibex_pkg::RV32MFast),
        .RV32B(ibex_pkg::RV32BNone),
        .WritebackStage(1'b0),
        .ICache(1'b0),
        .RegFileECC(1'b0),
        .MemECC(1'b0)
    ) u_ibex (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .hart_id_i(hart_id_i),
        .boot_addr_i(boot_addr_i),
        .instr_req_o(instr_req),
        .instr_gnt_i(instr_gnt),
        .instr_rvalid_i(instr_rvalid),
        .instr_addr_o(instr_addr),
        .instr_rdata_i(instr_rdata),
        .instr_err_i(instr_err_i && instr_rvalid),
        .data_req_o(data_req),
        .data_gnt_i(data_gnt),
        .data_rvalid_i(data_rvalid),
        .data_we_o(data_we),
        .data_be_o(data_be),
        .data_addr_o(data_addr),
        .data_wdata_o(data_wdata),
        .data_rdata_i(data_rdata),
        .data_err_i(data_err_i && data_rvalid),
        .dummy_instr_id_o(),
        .dummy_instr_wb_o(),
        .rf_raddr_a_o(),
        .rf_raddr_b_o(),
        .rf_waddr_wb_o(),
        .rf_we_wb_o(),
        .rf_wdata_wb_ecc_o(),
        .rf_rdata_a_ecc_i(data_seed_i),
        .rf_rdata_b_ecc_i(instr_seed_i),
        .ic_tag_req_o(),
        .ic_tag_write_o(),
        .ic_tag_addr_o(),
        .ic_tag_wdata_o(),
        .ic_tag_rdata_i(ic_tag_rdata),
        .ic_data_req_o(),
        .ic_data_write_o(),
        .ic_data_addr_o(),
        .ic_data_wdata_o(),
        .ic_data_rdata_i(ic_data_rdata),
        .ic_scr_key_valid_i(1'b0),
        .ic_scr_key_req_o(),
        .irq_software_i(irq_software_i),
        .irq_timer_i(timer_irq),
        .irq_external_i(irq_external),
        .irq_fast_i(irq_fast_i),
        .irq_nm_i(irq_nm_i),
        .irq_pending_o(),
        .debug_req_i(debug_req_i),
        .crash_dump_o(),
        .double_fault_seen_o(),
        .alert_minor_o(),
        .alert_major_internal_o(),
        .alert_major_bus_o(),
        .core_busy_o(),
        .fetch_enable_i(fetch_enable_i)
    );

    assign system_observe_o = {
        instr_req, instr_gnt, instr_rvalid,
        data_req, data_gnt, data_rvalid, data_we,
        data_region,
        irq_external, irq_software_i, irq_nm_i, debug_req_i,
        instr_addr[7:0],
        data_addr[7:0],
        cycle_q[1:0]
    };
    assign ip_observe_o = {
        instr_ram_state ^ data_ram_state,
        timer_state,
        gpio_state ^ uart_state,
        spi_state
    };

endmodule
