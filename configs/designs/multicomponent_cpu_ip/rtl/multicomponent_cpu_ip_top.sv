module multicomponent_cpu_ip_top (
    input  logic        clk_i,
    input  logic        rst_ni,
    input  logic        fetch_enable_i,
    input  logic        cpu_req_valid_i,
    input  logic        cpu_req_write_i,
    input  logic [31:0] cpu_req_addr_i,
    input  logic [31:0] cpu_req_wdata_i,
    input  logic [3:0]  cpu_req_be_i,
    input  logic [4:0]  ip_ready_i,
    input  logic        timer_tick_i,
    input  logic [15:0] gpio_pins_i,
    input  logic        uart_rx_valid_i,
    input  logic [7:0]  uart_rx_data_i,
    input  logic        spi_miso_valid_i,
    input  logic [7:0]  spi_miso_data_i,
    input  logic        debug_req_i,
    input  logic        error_i,
    output logic [31:0] cpu_observe_o,
    output logic [31:0] bus_observe_o,
    output logic [31:0] ip_observe_o
);

    logic cpu_bus_valid;
    logic cpu_bus_write;
    logic [31:0] cpu_bus_addr;
    logic [31:0] cpu_bus_wdata;
    logic [3:0] cpu_bus_be;
    logic cpu_bus_ready;
    logic cpu_bus_rvalid;
    logic [31:0] cpu_bus_rdata;
    logic timer_irq;
    logic gpio_irq;
    logic uart_irq;
    logic spi_irq;
    logic external_irq;
    logic [7:0] cpu_state;
    logic [2:0] selected_region;

    logic ram_valid;
    logic ram_write;
    logic [31:0] ram_addr;
    logic [31:0] ram_wdata;
    logic [3:0] ram_be;
    logic ram_ready;
    logic ram_rvalid;
    logic [31:0] ram_rdata;
    logic [7:0] ram_state;

    logic timer_valid;
    logic timer_write;
    logic [31:0] timer_addr;
    logic [31:0] timer_wdata;
    logic [3:0] timer_be;
    logic timer_ready;
    logic timer_rvalid;
    logic [31:0] timer_rdata;
    logic [7:0] timer_state;

    logic gpio_valid;
    logic gpio_write;
    logic [31:0] gpio_addr;
    logic [31:0] gpio_wdata;
    logic [3:0] gpio_be;
    logic gpio_ready;
    logic gpio_rvalid;
    logic [31:0] gpio_rdata;
    logic [7:0] gpio_state;

    logic uart_valid;
    logic uart_write;
    logic [31:0] uart_addr;
    logic [31:0] uart_wdata;
    logic [3:0] uart_be;
    logic uart_ready;
    logic uart_rvalid;
    logic [31:0] uart_rdata;
    logic [7:0] uart_state;

    logic spi_valid;
    logic spi_write;
    logic [31:0] spi_addr;
    logic [31:0] spi_wdata;
    logic [3:0] spi_be;
    logic spi_ready;
    logic spi_rvalid;
    logic [31:0] spi_rdata;
    logic [7:0] spi_state;

    assign external_irq = gpio_irq || uart_irq || spi_irq;

    toy_cpu u_core (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .fetch_enable_i(fetch_enable_i),
        .req_valid_i(cpu_req_valid_i),
        .req_write_i(cpu_req_write_i),
        .req_addr_i(cpu_req_addr_i),
        .req_wdata_i(cpu_req_wdata_i),
        .req_be_i(cpu_req_be_i),
        .debug_req_i(debug_req_i),
        .error_i(error_i),
        .timer_irq_i(timer_irq),
        .external_irq_i(external_irq),
        .bus_ready_i(cpu_bus_ready),
        .bus_rvalid_i(cpu_bus_rvalid),
        .bus_rdata_i(cpu_bus_rdata),
        .bus_valid_o(cpu_bus_valid),
        .bus_write_o(cpu_bus_write),
        .bus_addr_o(cpu_bus_addr),
        .bus_wdata_o(cpu_bus_wdata),
        .bus_be_o(cpu_bus_be),
        .state_o(cpu_state)
    );

    toy_bus u_bus (
        .cpu_valid_i(cpu_bus_valid),
        .cpu_write_i(cpu_bus_write),
        .cpu_addr_i(cpu_bus_addr),
        .cpu_wdata_i(cpu_bus_wdata),
        .cpu_be_i(cpu_bus_be),
        .cpu_ready_o(cpu_bus_ready),
        .cpu_rvalid_o(cpu_bus_rvalid),
        .cpu_rdata_o(cpu_bus_rdata),
        .ram_valid_o(ram_valid),
        .ram_write_o(ram_write),
        .ram_addr_o(ram_addr),
        .ram_wdata_o(ram_wdata),
        .ram_be_o(ram_be),
        .ram_ready_i(ram_ready),
        .ram_rvalid_i(ram_rvalid),
        .ram_rdata_i(ram_rdata),
        .timer_valid_o(timer_valid),
        .timer_write_o(timer_write),
        .timer_addr_o(timer_addr),
        .timer_wdata_o(timer_wdata),
        .timer_be_o(timer_be),
        .timer_ready_i(timer_ready),
        .timer_rvalid_i(timer_rvalid),
        .timer_rdata_i(timer_rdata),
        .gpio_valid_o(gpio_valid),
        .gpio_write_o(gpio_write),
        .gpio_addr_o(gpio_addr),
        .gpio_wdata_o(gpio_wdata),
        .gpio_be_o(gpio_be),
        .gpio_ready_i(gpio_ready),
        .gpio_rvalid_i(gpio_rvalid),
        .gpio_rdata_i(gpio_rdata),
        .uart_valid_o(uart_valid),
        .uart_write_o(uart_write),
        .uart_addr_o(uart_addr),
        .uart_wdata_o(uart_wdata),
        .uart_be_o(uart_be),
        .uart_ready_i(uart_ready),
        .uart_rvalid_i(uart_rvalid),
        .uart_rdata_i(uart_rdata),
        .spi_valid_o(spi_valid),
        .spi_write_o(spi_write),
        .spi_addr_o(spi_addr),
        .spi_wdata_o(spi_wdata),
        .spi_be_o(spi_be),
        .spi_ready_i(spi_ready),
        .spi_rvalid_i(spi_rvalid),
        .spi_rdata_i(spi_rdata),
        .selected_region_o(selected_region)
    );

    toy_ram u_ram (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(ram_valid),
        .write_i(ram_write),
        .addr_i(ram_addr),
        .wdata_i(ram_wdata),
        .be_i(ram_be),
        .ext_ready_i(ip_ready_i[0]),
        .ready_o(ram_ready),
        .rvalid_o(ram_rvalid),
        .rdata_o(ram_rdata),
        .state_o(ram_state)
    );

    toy_timer u_mtimer (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(timer_valid),
        .write_i(timer_write),
        .addr_i(timer_addr),
        .wdata_i(timer_wdata),
        .be_i(timer_be),
        .ext_ready_i(ip_ready_i[1]),
        .tick_i(timer_tick_i),
        .ready_o(timer_ready),
        .rvalid_o(timer_rvalid),
        .rdata_o(timer_rdata),
        .irq_o(timer_irq),
        .state_o(timer_state)
    );

    toy_gpio u_gpio (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(gpio_valid),
        .write_i(gpio_write),
        .addr_i(gpio_addr),
        .wdata_i(gpio_wdata),
        .be_i(gpio_be),
        .ext_ready_i(ip_ready_i[2]),
        .pins_i(gpio_pins_i),
        .ready_o(gpio_ready),
        .rvalid_o(gpio_rvalid),
        .rdata_o(gpio_rdata),
        .irq_o(gpio_irq),
        .state_o(gpio_state)
    );

    toy_uart u_uart (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(uart_valid),
        .write_i(uart_write),
        .addr_i(uart_addr),
        .wdata_i(uart_wdata),
        .be_i(uart_be),
        .ext_ready_i(ip_ready_i[3]),
        .rx_valid_i(uart_rx_valid_i),
        .rx_data_i(uart_rx_data_i),
        .ready_o(uart_ready),
        .rvalid_o(uart_rvalid),
        .rdata_o(uart_rdata),
        .irq_o(uart_irq),
        .state_o(uart_state)
    );

    toy_spi u_spi (
        .clk_i(clk_i),
        .rst_ni(rst_ni),
        .valid_i(spi_valid),
        .write_i(spi_write),
        .addr_i(spi_addr),
        .wdata_i(spi_wdata),
        .be_i(spi_be),
        .ext_ready_i(ip_ready_i[4]),
        .miso_valid_i(spi_miso_valid_i),
        .miso_data_i(spi_miso_data_i),
        .ready_o(spi_ready),
        .rvalid_o(spi_rvalid),
        .rdata_o(spi_rdata),
        .irq_o(spi_irq),
        .state_o(spi_state)
    );

    assign cpu_observe_o = {cpu_state, 5'h0, selected_region, timer_irq, external_irq, cpu_bus_rdata[13:0]};
    assign bus_observe_o = {cpu_bus_valid, cpu_bus_write, cpu_bus_ready, cpu_bus_rvalid,
                            ram_valid, timer_valid, gpio_valid, uart_valid, spi_valid,
                            cpu_bus_addr[22:0]};
    assign ip_observe_o = {ram_state, timer_state, gpio_state, uart_state} ^ {24'h0, spi_state};

endmodule
