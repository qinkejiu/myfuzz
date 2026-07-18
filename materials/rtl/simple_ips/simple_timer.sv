// Simple Timer module for auto_soc_top testing

module simple_timer (
  input  logic        clk_i,
  input  logic        rst_ni,

  // Simple bus interface
  input  logic        req_i,
  input  logic        we_i,
  input  logic [7:0]  addr_i,
  input  logic [31:0] wdata_i,
  output logic [31:0] rdata_o
);

  // Register addresses
  localparam ADDR_COUNTER = 8'h00;
  localparam ADDR_COMPARE = 8'h04;
  localparam ADDR_CONTROL = 8'h08;

  // Registers
  logic [31:0] counter;
  logic [31:0] compare;
  logic        enable;

  // Counter logic
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      counter <= 32'h0;
      compare <= 32'hFFFFFFFF;
      enable  <= 1'b0;
    end else begin
      // Write logic
      if (req_i && we_i) begin
        case (addr_i)
          ADDR_COUNTER: counter <= wdata_i;
          ADDR_COMPARE: compare <= wdata_i;
          ADDR_CONTROL: enable  <= wdata_i[0];
          default: begin end  // Ignore other addresses
        endcase
      end

      // Counter increment
      if (enable) begin
        if (counter >= compare) begin
          counter <= 32'h0;
        end else begin
          counter <= counter + 1'b1;
        end
      end
    end
  end

  // Read mux
  always_comb begin
    rdata_o = 32'h0;
    case (addr_i)
      ADDR_COUNTER: rdata_o = counter;
      ADDR_COMPARE: rdata_o = compare;
      ADDR_CONTROL: rdata_o = {31'h0, enable};
      default:      rdata_o = 32'h0;
    endcase
  end

endmodule
