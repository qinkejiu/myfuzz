// Generic external UART peer for a profile-driven SoC harness.
//
// The peer owns both directions of one asynchronous serial link.  Nothing in
// this file selects behaviour by component or model name: the frame timing, the
// idle level, the stop-bit count and the idle timeout are parameters, an
// out-of-range parameterization is rejected at time 0 with $fatal, and every
// output is a register cleared by the active-low synchronous reset rst_ni (the
// serial line and the ready handshake read their reset value for as long as
// rst_ni is asserted, so they are defined before the first clock edge).
//
// Port convention
//   serial_tx_o          the line this peer drives towards the component under
//                        test; a component uart_rx_i input binds to it.
//   serial_rx_i          the line this peer samples; a component uart_tx_o
//                        output binds to it.
//   tx_request_valid_i /
//   tx_request_data_i    the explicit transmit event plan: one offered byte per
//                        cycle, never a random value.
//   tx_ready_o           high when the peer can take an offer.  It reads low
//                        while rst_ni is asserted.
//   tx_busy_o            high from the edge that accepts an offer until the
//                        last stop bit period has been driven.
//   tx_sent_count_o      frames fully driven onto serial_tx_o.
//   tx_drop_count_o      offers that arrived while tx_busy_o was already high;
//                        a dropped byte is never queued and never transmitted
//                        later.
//   rx_data_o /          the byte that was sampled from serial_rx_i and a
//   rx_valid_o           one-cycle pulse on the edge that reports it.
//   rx_count_o           bytes reported so far.
//   framing_error_count_o stop bit periods sampled at the start level.
//   timeout_count_o      idle windows that expired without a start bit.
//   rx_busy_o            high while a frame is being sampled.
//
// Frame format (every cycle count is a clk_i cycle count)
//   The transmitter drives one start bit at the start level, then DATA_WIDTH
//   data bits least-significant bit first, then STOP_BITS stop bits at the idle
//   level, and holds every one of those bits for exactly BAUD_DIV cycles.  The
//   idle level is IDLE_LEVEL (0 or 1) and the start level is its complement.
//
// Receiver
//   A start bit is the start-level sample the receiver takes on the edge where
//   an idle receiver first sees that level.  The receiver then samples each
//   data bit and each stop bit inside its bit period, at its middle when the
//   divisor allows: the first data bit BAUD_DIV + BAUD_DIV/2 - 1 edges after
//   the start sample, and every later bit BAUD_DIV edges after the previous
//   one.  The sample is therefore strictly inside the bit period and not on a
//   bit boundary: a frame whose data bits are inverted on their first and last
//   cycles is still received correctly.  A reported byte is always a byte that
//   was sampled from the line: rx_valid_o is asserted only on the edge that
//   samples the last stop bit period, and no byte is reported while the line
//   stays idle.
//
//   A stop bit period sampled at the start level increments
//   framing_error_count_o and the data bits that were sampled are still
//   reported, because they did come from the line.  A line held at the start
//   level is not idle: it is received as back-to-back frames, each one with a
//   framing error.  TIMEOUT_BITS consecutive idle bit periods without a
//   detected start bit increment timeout_count_o once and restart the window,
//   so an idle line never reports a byte and times out repeatedly.
//
// Deliberately not modelled, so that no claim is implied
//   parity and every other frame format beyond start/data/stop; fractional or
//   mismatched baud rates (the peer samples at exactly BAUD_DIV cycles per bit
//   and does not resynchronise inside a frame); glitch filtering and start-bit
//   re-verification, so a start pulse one clk_i cycle long is accepted as a
//   frame start and a glitch is received as a byte of idle-level bits; FIFOs,
//   flow control and every electrical property of the line.
module soc_uart_peer #(
    parameter integer DATA_WIDTH = 8,    // data bits per frame, >= 1
    parameter integer BAUD_DIV = 1,      // clk_i cycles per bit period, >= 1
    parameter integer STOP_BITS = 1,     // stop bit periods per frame, >= 1
    parameter integer IDLE_LEVEL = 1,    // line level between frames, 0 or 1
    parameter integer TIMEOUT_BITS = 16  // idle bit periods per timeout event, >= 1
) (
    input  logic                  clk_i,
    input  logic                  rst_ni,
    input  logic                  tx_request_valid_i,
    input  logic [DATA_WIDTH-1:0] tx_request_data_i,
    output logic                  tx_ready_o,
    output logic                  tx_busy_o,
    output logic [31:0]           tx_sent_count_o,
    output logic [31:0]           tx_drop_count_o,
    output logic                  serial_tx_o,
    input  logic                  serial_rx_i,
    output logic [DATA_WIDTH-1:0] rx_data_o,
    output logic                  rx_valid_o,
    output logic [31:0]           rx_count_o,
    output logic [31:0]           framing_error_count_o,
    output logic [31:0]           timeout_count_o,
    output logic                  rx_busy_o
);
  localparam logic IDLE = (IDLE_LEVEL == 0) ? 1'b0 : 1'b1;
  localparam logic START = ~IDLE;

  localparam integer FRAME_BITS = 1 + DATA_WIDTH + STOP_BITS;
  // Distance from the start-bit sample to the middle of the first data bit, and
  // from one bit sample to the next one, in clk_i edges.
  localparam integer CENTER_CYCLES = BAUD_DIV / 2;
  localparam integer FIRST_SAMPLE_WAIT = BAUD_DIV + CENTER_CYCLES - 1;
  localparam integer TIMEOUT_CYCLES = TIMEOUT_BITS * BAUD_DIV;

  localparam logic [1:0] RX_IDLE = 2'd0;
  localparam logic [1:0] RX_DATA = 2'd1;
  localparam logic [1:0] RX_STOP = 2'd2;

  logic [DATA_WIDTH-1:0] tx_data_q;
  integer                tx_bit_q;   // 0 = start, 1..DATA_WIDTH = data, rest = stop
  integer                tx_baud_q;  // cycles left in the bit period being driven
  logic                  tx_busy_q;
  logic                  serial_tx_q;

  logic [1:0]            rx_state_q;
  integer                rx_bit_q;    // index inside the data group or stop group
  integer                rx_phase_q;  // edges left before the next bit sample
  integer                rx_idle_q;   // idle cycles inside the current timeout window
  logic [DATA_WIDTH-1:0] rx_shift_q;
  logic [DATA_WIDTH-1:0] rx_byte_q;

  integer                assemble_index;

  initial begin
    if ((DATA_WIDTH < 1) || (BAUD_DIV < 1) || (STOP_BITS < 1) ||
        ((IDLE_LEVEL != 0) && (IDLE_LEVEL != 1)) || (TIMEOUT_BITS < 1))
      $fatal(1, "invalid soc_uart_peer parameters");
  end

  assign tx_ready_o = rst_ni && !tx_busy_q;
  assign tx_busy_o = tx_busy_q;
  // The line a component samples reads the idle level for as long as reset is
  // asserted, so it is defined from time 0 instead of one edge later.
  assign serial_tx_o = rst_ni ? serial_tx_q : IDLE;
  assign rx_busy_o = (rx_state_q != RX_IDLE);

  // The level the transmitter drives for a bit index of the frame it is sending.
  function automatic logic frame_level(input integer index);
    begin
      if (index == 0)
        frame_level = START;
      else if (index <= DATA_WIDTH)
        frame_level = tx_data_q[index-1];
      else
        frame_level = IDLE;
    end
  endfunction

  // The data bits sampled so far with the bit sampled in this cycle placed at
  // the position the frame assigns to it, so the byte is assembled
  // least-significant bit first without depending on DATA_WIDTH.
  function automatic [DATA_WIDTH-1:0] with_sample(input [DATA_WIDTH-1:0] accumulated,
                                                  input integer index,
                                                  input logic bit_value);
    begin
      with_sample = accumulated;
      for (assemble_index = 0; assemble_index < DATA_WIDTH; assemble_index = assemble_index + 1)
        if (assemble_index == index)
          with_sample[assemble_index] = bit_value;
    end
  endfunction

  // ---------------------------------------------------------------------------
  // Transmitter: one frame per accepted offer, dropped offers are counted.
  // ---------------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      tx_data_q <= {DATA_WIDTH{1'b0}};
      tx_bit_q <= 0;
      tx_baud_q <= 0;
      tx_busy_q <= 1'b0;
      serial_tx_q <= IDLE;
      tx_sent_count_o <= '0;
      tx_drop_count_o <= '0;
    end else if (!tx_busy_q) begin
      serial_tx_q <= IDLE;
      if (tx_request_valid_i) begin
        tx_data_q <= tx_request_data_i;
        tx_bit_q <= 0;
        tx_baud_q <= BAUD_DIV - 1;
        tx_busy_q <= 1'b1;
        serial_tx_q <= START;
      end
    end else begin
      if (tx_request_valid_i)
        tx_drop_count_o <= tx_drop_count_o + 32'd1;
      if (tx_baud_q == 0) begin
        tx_baud_q <= BAUD_DIV - 1;
        if (tx_bit_q == FRAME_BITS - 1) begin
          tx_busy_q <= 1'b0;
          serial_tx_q <= IDLE;
          tx_sent_count_o <= tx_sent_count_o + 32'd1;
        end else begin
          tx_bit_q <= tx_bit_q + 1;
          serial_tx_q <= frame_level(tx_bit_q + 1);
        end
      end else begin
        tx_baud_q <= tx_baud_q - 1;
      end
    end
  end

  // ---------------------------------------------------------------------------
  // Receiver: sample the line, report only what was sampled.
  // ---------------------------------------------------------------------------
  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      rx_state_q <= RX_IDLE;
      rx_bit_q <= 0;
      rx_phase_q <= 0;
      rx_idle_q <= 0;
      rx_shift_q <= {DATA_WIDTH{1'b0}};
      rx_byte_q <= {DATA_WIDTH{1'b0}};
      rx_data_o <= {DATA_WIDTH{1'b0}};
      rx_valid_o <= 1'b0;
      rx_count_o <= '0;
      framing_error_count_o <= '0;
      timeout_count_o <= '0;
    end else begin
      rx_valid_o <= 1'b0;
      case (rx_state_q)
        RX_IDLE: begin
          if (serial_rx_i == START) begin
            // The value sampled on this edge is the start bit; it is not
            // re-verified, so no glitch filter is modelled here.
            rx_state_q <= RX_DATA;
            rx_bit_q <= 0;
            rx_shift_q <= {DATA_WIDTH{1'b0}};
            rx_byte_q <= {DATA_WIDTH{1'b0}};
            rx_phase_q <= FIRST_SAMPLE_WAIT;
            rx_idle_q <= 0;
          end else if (rx_idle_q == TIMEOUT_CYCLES - 1) begin
            rx_idle_q <= 0;
            timeout_count_o <= timeout_count_o + 32'd1;
          end else begin
            rx_idle_q <= rx_idle_q + 1;
          end
        end
        RX_DATA: begin
          if (rx_phase_q == 0) begin
            rx_phase_q <= BAUD_DIV - 1;
            rx_shift_q[rx_bit_q] <= serial_rx_i;
            if (rx_bit_q == DATA_WIDTH - 1) begin
              rx_byte_q <= with_sample(rx_shift_q, rx_bit_q, serial_rx_i);
              rx_bit_q <= 0;
              rx_state_q <= RX_STOP;
            end else begin
              rx_bit_q <= rx_bit_q + 1;
            end
          end else begin
            rx_phase_q <= rx_phase_q - 1;
          end
        end
        default: begin
          // RX_STOP: every stop bit period must be at the idle level, and the
          // byte is reported only after the last one was sampled.
          if (rx_phase_q == 0) begin
            rx_phase_q <= BAUD_DIV - 1;
            if (serial_rx_i != IDLE)
              framing_error_count_o <= framing_error_count_o + 32'd1;
            if (rx_bit_q == STOP_BITS - 1) begin
              rx_state_q <= RX_IDLE;
              rx_idle_q <= 0;
              rx_data_o <= rx_byte_q;
              rx_valid_o <= 1'b1;
              rx_count_o <= rx_count_o + 32'd1;
            end else begin
              rx_bit_q <= rx_bit_q + 1;
            end
          end else begin
            rx_phase_q <= rx_phase_q - 1;
          end
        end
      endcase
    end
  end
endmodule
