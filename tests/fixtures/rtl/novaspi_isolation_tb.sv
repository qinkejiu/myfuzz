// Independent APB driver: isolates the SPI component from CPU, fabric and IRQ.
module novaspi_isolation_tb;
  logic clk_i = 0;
  logic rst_ni = 1;
  logic [11:0] paddr_i = 0;
  logic psel_i = 0;
  logic penable_i = 0;
  logic pwrite_i = 0;
  logic [31:0] pwdata_i = 0;
  logic [3:0] pstrb_i = 0;
  wire pready_o;
  wire [31:0] prdata_o;
  wire pslverr_o;
  wire spi_sck_o, spi_cs_o, spi_mosi_o, irq_o;
  logic [7:0] observed_mosi = 0;
  integer observed_bits = 0;

  always #5 clk_i = ~clk_i;

  novaspi #(.BITS(8), .CPOL(0), .CPHA(0), .SCK_HALF_DIV(4),
            .CS_SETUP(2), .CS_HOLD(2)) dut (
      .clk_i(clk_i), .rst_ni(rst_ni), .paddr_i(paddr_i),
      .psel_i(psel_i), .penable_i(penable_i), .pwrite_i(pwrite_i),
      .pwdata_i(pwdata_i), .pstrb_i(pstrb_i), .pready_o(pready_o),
      .prdata_o(prdata_o), .pslverr_o(pslverr_o),
      .spi_sck_o(spi_sck_o), .spi_cs_o(spi_cs_o),
      .spi_mosi_o(spi_mosi_o), .spi_miso_i(1'b0), .irq_o(irq_o));

  always @(posedge spi_sck_o) begin
    if (!spi_cs_o) begin
      observed_mosi = {observed_mosi[6:0], spi_mosi_o};
      observed_bits = observed_bits + 1;
    end
  end

  task automatic write_reg(input logic [11:0] address,
                           input logic [31:0] value);
    @(negedge clk_i);
    paddr_i = address;
    pwdata_i = value;
    pstrb_i = 4'hf;
    psel_i = 1;
    penable_i = 1;
    pwrite_i = 1;
    @(negedge clk_i);
    psel_i = 0;
    penable_i = 0;
    pwrite_i = 0;
  endtask

  initial begin
    @(negedge clk_i);
    rst_ni = 0;
    repeat (4) @(negedge clk_i);
    rst_ni = 1;
    write_reg(12'h008, 32'h0000_005a);
    write_reg(12'h000, 32'h0000_0003);
    repeat (250) @(negedge clk_i);
    $display("MYFUZZ_ISOLATED_SPI bits=%0d mosi=%0h", observed_bits, observed_mosi);
    $finish;
  end
endmodule
