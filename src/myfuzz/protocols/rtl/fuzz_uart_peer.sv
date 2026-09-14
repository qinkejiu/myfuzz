// Explicit UART RX environment peer.
// The byte/baud contract is parameterized; no signal-name inference is used.
module fuzz_uart_peer #(
    parameter integer DATA_WIDTH = 8,
    parameter integer BAUD_DIV = 1,
    parameter integer FRAME_BITS = 10
) (
    input  logic                 clk_i,
    input  logic                 reset_i,
    input  logic                 offer_i,
    input  logic [DATA_WIDTH-1:0] data_i,
    output logic                 rx_o,
    output logic                 ready_o,
    output logic                 busy_o,
    output logic [31:0]          drop_count_o,
    output logic [31:0]          sent_count_o,
    output logic                 event_valid_o,
    output logic [DATA_WIDTH-1:0] event_data_o
);
  localparam integer INDEX_WIDTH = (FRAME_BITS <= 2) ? 1 : $clog2(FRAME_BITS);
  logic [DATA_WIDTH-1:0] data_q;
  logic [INDEX_WIDTH-1:0] bit_q;
  integer baud_q;
  logic busy_q;

  assign busy_o = busy_q;
  assign ready_o = !busy_q;

  always @* begin
    rx_o = 1'b1;
    if (busy_q) begin
      if (bit_q == 0)
        rx_o = 1'b0; // start
      else if (bit_q <= DATA_WIDTH)
        rx_o = data_q[bit_q-1]; // least-significant bit first
      else
        rx_o = 1'b1; // stop
    end
  end

  always @(posedge clk_i) begin
    if (reset_i) begin
      data_q <= '0;
      bit_q <= '0;
      baud_q <= 0;
      busy_q <= 1'b0;
      drop_count_o <= '0;
      sent_count_o <= '0;
      event_valid_o <= 1'b0;
      event_data_o <= '0;
    end else begin
      event_valid_o <= 1'b0;
      if (!busy_q) begin
        if (offer_i) begin
          data_q <= data_i;
          bit_q <= '0;
          baud_q <= (BAUD_DIV > 0) ? BAUD_DIV - 1 : 0;
          busy_q <= 1'b1;
        end
      end else if (offer_i) begin
        drop_count_o <= drop_count_o + 1'b1;
      end

      if (busy_q) begin
        if (baud_q != 0) begin
          baud_q <= baud_q - 1;
        end else begin
          baud_q <= (BAUD_DIV > 0) ? BAUD_DIV - 1 : 0;
          if (bit_q == FRAME_BITS-1) begin
            busy_q <= 1'b0;
            sent_count_o <= sent_count_o + 1'b1;
            event_valid_o <= 1'b1;
            event_data_o <= data_q;
          end else begin
            bit_q <= bit_q + 1'b1;
          end
        end
      end
    end
  end
endmodule
