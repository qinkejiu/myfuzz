module toy_bus (
    input  logic        cpu_valid_i,
    input  logic        cpu_write_i,
    input  logic [31:0] cpu_addr_i,
    input  logic [31:0] cpu_wdata_i,
    input  logic [3:0]  cpu_be_i,
    output logic        cpu_ready_o,
    output logic        cpu_rvalid_o,
    output logic [31:0] cpu_rdata_o,
    output logic        ram_valid_o,
    output logic        ram_write_o,
    output logic [31:0] ram_addr_o,
    output logic [31:0] ram_wdata_o,
    output logic [3:0]  ram_be_o,
    input  logic        ram_ready_i,
    input  logic        ram_rvalid_i,
    input  logic [31:0] ram_rdata_i,
    output logic        timer_valid_o,
    output logic        timer_write_o,
    output logic [31:0] timer_addr_o,
    output logic [31:0] timer_wdata_o,
    output logic [3:0]  timer_be_o,
    input  logic        timer_ready_i,
    input  logic        timer_rvalid_i,
    input  logic [31:0] timer_rdata_i,
    output logic        gpio_valid_o,
    output logic        gpio_write_o,
    output logic [31:0] gpio_addr_o,
    output logic [31:0] gpio_wdata_o,
    output logic [3:0]  gpio_be_o,
    input  logic        gpio_ready_i,
    input  logic        gpio_rvalid_i,
    input  logic [31:0] gpio_rdata_i,
    output logic        uart_valid_o,
    output logic        uart_write_o,
    output logic [31:0] uart_addr_o,
    output logic [31:0] uart_wdata_o,
    output logic [3:0]  uart_be_o,
    input  logic        uart_ready_i,
    input  logic        uart_rvalid_i,
    input  logic [31:0] uart_rdata_i,
    output logic        spi_valid_o,
    output logic        spi_write_o,
    output logic [31:0] spi_addr_o,
    output logic [31:0] spi_wdata_o,
    output logic [3:0]  spi_be_o,
    input  logic        spi_ready_i,
    input  logic        spi_rvalid_i,
    input  logic [31:0] spi_rdata_i,
    output logic [2:0]  selected_region_o
);

    localparam logic [2:0] REGION_RAM = 3'd0;
    localparam logic [2:0] REGION_UART = 3'd1;
    localparam logic [2:0] REGION_TIMER = 3'd2;
    localparam logic [2:0] REGION_GPIO = 3'd3;
    localparam logic [2:0] REGION_SPI = 3'd4;

    logic [2:0] selected_region;

    always_comb begin
        unique casez (cpu_addr_i[31:16])
            16'h8000: selected_region = REGION_UART;
            16'h8001: selected_region = REGION_TIMER;
            16'h8002: selected_region = REGION_GPIO;
            16'h8003: selected_region = REGION_SPI;
            default:  selected_region = REGION_RAM;
        endcase
    end

    assign ram_valid_o = cpu_valid_i && (selected_region == REGION_RAM);
    assign timer_valid_o = cpu_valid_i && (selected_region == REGION_TIMER);
    assign gpio_valid_o = cpu_valid_i && (selected_region == REGION_GPIO);
    assign uart_valid_o = cpu_valid_i && (selected_region == REGION_UART);
    assign spi_valid_o = cpu_valid_i && (selected_region == REGION_SPI);

    assign ram_write_o = cpu_write_i;
    assign timer_write_o = cpu_write_i;
    assign gpio_write_o = cpu_write_i;
    assign uart_write_o = cpu_write_i;
    assign spi_write_o = cpu_write_i;

    assign ram_addr_o = cpu_addr_i;
    assign timer_addr_o = cpu_addr_i;
    assign gpio_addr_o = cpu_addr_i;
    assign uart_addr_o = cpu_addr_i;
    assign spi_addr_o = cpu_addr_i;

    assign ram_wdata_o = cpu_wdata_i;
    assign timer_wdata_o = cpu_wdata_i;
    assign gpio_wdata_o = cpu_wdata_i;
    assign uart_wdata_o = cpu_wdata_i;
    assign spi_wdata_o = cpu_wdata_i;

    assign ram_be_o = cpu_be_i;
    assign timer_be_o = cpu_be_i;
    assign gpio_be_o = cpu_be_i;
    assign uart_be_o = cpu_be_i;
    assign spi_be_o = cpu_be_i;

    always_comb begin
        cpu_ready_o = 1'b0;
        cpu_rvalid_o = 1'b0;
        cpu_rdata_o = 32'h0;
        unique case (selected_region)
            REGION_RAM: begin
                cpu_ready_o = ram_ready_i;
                cpu_rvalid_o = ram_rvalid_i;
                cpu_rdata_o = ram_rdata_i;
            end
            REGION_UART: begin
                cpu_ready_o = uart_ready_i;
                cpu_rvalid_o = uart_rvalid_i;
                cpu_rdata_o = uart_rdata_i;
            end
            REGION_TIMER: begin
                cpu_ready_o = timer_ready_i;
                cpu_rvalid_o = timer_rvalid_i;
                cpu_rdata_o = timer_rdata_i;
            end
            REGION_GPIO: begin
                cpu_ready_o = gpio_ready_i;
                cpu_rvalid_o = gpio_rvalid_i;
                cpu_rdata_o = gpio_rdata_i;
            end
            REGION_SPI: begin
                cpu_ready_o = spi_ready_i;
                cpu_rvalid_o = spi_rvalid_i;
                cpu_rdata_o = spi_rdata_i;
            end
            default: begin
                cpu_ready_o = 1'b1;
                cpu_rvalid_o = cpu_valid_i;
                cpu_rdata_o = 32'hbad0_bad0;
            end
        endcase
    end

    assign selected_region_o = selected_region;

endmodule
