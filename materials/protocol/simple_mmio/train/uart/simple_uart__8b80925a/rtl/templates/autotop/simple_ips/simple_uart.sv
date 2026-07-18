// Simple UART module for auto_soc_top testing
// 最小的UART实现，只支持基本的收发

module simple_uart (
  input  logic        clk_i,
  input  logic        rst_ni,

  // Simple bus interface
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o,

  // UART pins
  output logic        tx_o,
  input  logic        rx_i
);

  // Register addresses
  localparam ADDR_DATA   = 8'h00;
  localparam ADDR_STATUS = 8'h04;

  // Registers
  logic [7:0] tx_data;
  logic [7:0] rx_data;
  logic       tx_busy;
  logic       rx_valid;

  // Simple TX (just hold the data)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      tx_data <= 8'h0;
      tx_busy <= 1'b0;
    end else if (req_i && we_i && (addr_i == ADDR_DATA)) begin
      tx_data <= wdata_i[7:0];
      tx_busy <= 1'b1;
    end else begin
      tx_busy <= 1'b0;
    end
  end

  // Simple RX (just sample rx_i)
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      rx_data <= 8'h0;
      rx_valid <= 1'b0;
    end else begin
      rx_data <= {7'h0, rx_i};
      rx_valid <= 1'b1;
    end
  end

  // Read mux
  always_comb begin
    rdata_o = 32'h0;
    case (addr_i)
      ADDR_DATA:   rdata_o = {24'h0, rx_data};
      ADDR_STATUS: rdata_o = {30'h0, rx_valid, tx_busy};
      default:     rdata_o = 32'h0;
    endcase
  end

  // TX output (just drive constant for now)
  assign tx_o = 1'b1;

endmodule
