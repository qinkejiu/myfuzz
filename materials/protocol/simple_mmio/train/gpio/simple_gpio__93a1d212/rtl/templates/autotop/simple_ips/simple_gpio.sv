// Simple GPIO module for auto_soc_top testing

module simple_gpio #(
  parameter int WIDTH = 8
) (
  input  logic              clk_i,
  input  logic              rst_ni,

  // Simple bus interface
  input  logic              req_i,
  input  logic              we_i,
  input  logic [7:0]        addr_i,
  input  logic [31:0]       wdata_i,
  output logic [31:0]       rdata_o,

  // GPIO pins
  output logic [WIDTH-1:0]  gpio_o,
  input  logic [WIDTH-1:0]  gpio_i
);

  // Register addresses
  localparam ADDR_OUTPUT = 8'h00;
  localparam ADDR_INPUT  = 8'h04;
  localparam ADDR_DIR    = 8'h08;  // Direction: 0=input, 1=output

  // Registers
  logic [WIDTH-1:0] output_reg;
  logic [WIDTH-1:0] input_reg;
  logic [WIDTH-1:0] dir_reg;

  // GPIO logic
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      output_reg <= '0;
      dir_reg    <= '0;
    end else if (req_i && we_i) begin
      case (addr_i)
        ADDR_OUTPUT: output_reg <= wdata_i[WIDTH-1:0];
        ADDR_DIR:    dir_reg    <= wdata_i[WIDTH-1:0];
        default: begin end  // Ignore other addresses
      endcase
    end
  end

  // Input sampling
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      input_reg <= '0;
    end else begin
      input_reg <= gpio_i;
    end
  end

  // Read mux
  always_comb begin
    rdata_o = 32'h0;
    case (addr_i)
      ADDR_OUTPUT: rdata_o = {{(32-WIDTH){1'b0}}, output_reg};
      ADDR_INPUT:  rdata_o = {{(32-WIDTH){1'b0}}, input_reg};
      ADDR_DIR:    rdata_o = {{(32-WIDTH){1'b0}}, dir_reg};
      default:     rdata_o = 32'h0;
    endcase
  end

  // Output drive
  assign gpio_o = output_reg;

endmodule
