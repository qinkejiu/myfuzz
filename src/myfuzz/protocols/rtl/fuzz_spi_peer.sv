// Explicit SPI MISO environment peer.
// The selected CPOL/CPHA contract is supplied by parameters.
module fuzz_spi_peer #(
    parameter integer BITS = 8,
    parameter integer CPOL = 0,
    parameter integer CPHA = 0
) (
    input  logic             clk_i,
    input  logic             reset_i,
    input  logic             offer_i,
    input  logic [BITS-1:0]  data_i,
    input  logic             sck_i,
    input  logic             cs_i,
    output logic             miso_o,
    output logic             ready_o,
    output logic             busy_o,
    output logic [31:0]      drop_count_o,
    output logic [31:0]      sent_count_o,
    output logic             event_valid_o,
    output logic [BITS-1:0]  event_data_o
);
  localparam integer COUNT_WIDTH = (BITS <= 2) ? 1 : $clog2(BITS);
  logic [BITS-1:0] shift_q;
  logic [BITS-1:0] payload_q;
  logic [COUNT_WIDTH-1:0] count_q;
  logic busy_q;
  logic sck_q;

  assign busy_o = busy_q;
  assign ready_o = !busy_q;
  assign miso_o = (!cs_i && busy_q) ? shift_q[BITS-1] : 1'b0;

  always_ff @(posedge clk_i) begin
      if (reset_i) begin
        shift_q <= '0;
        payload_q <= '0;
      count_q <= '0;
      busy_q <= 1'b0;
      sck_q <= CPOL[0];
      drop_count_o <= '0;
      sent_count_o <= '0;
      event_valid_o <= 1'b0;
      event_data_o <= '0;
    end else begin
      sck_q <= sck_i;
      event_valid_o <= 1'b0;
      if (cs_i && busy_q) begin
        busy_q <= 1'b0;
      end else if (!busy_q && offer_i) begin
        shift_q <= data_i;
        payload_q <= data_i;
        count_q <= '0;
        busy_q <= 1'b1;
      end else if (busy_q && offer_i) begin
        drop_count_o <= drop_count_o + 1'b1;
      end

      if (busy_q && !cs_i) begin
        // CPHA=0 presents a bit before the active edge and advances on the
        // trailing edge; CPHA=1 advances on the active edge.
        if ((CPHA == 0 && sck_q != sck_i && sck_i == CPOL[0]) ||
            (CPHA != 0 && sck_q != sck_i && sck_i != CPOL[0])) begin
          if (count_q == BITS-1) begin
            busy_q <= 1'b0;
            sent_count_o <= sent_count_o + 1'b1;
            event_valid_o <= 1'b1;
            event_data_o <= payload_q;
          end else begin
            shift_q <= {shift_q[BITS-2:0], 1'b0};
            count_q <= count_q + 1'b1;
          end
        end
      end
    end
  end
endmodule
