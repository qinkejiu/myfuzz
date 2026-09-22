// Generic external SPI slave peer for a profile-driven SoC harness.
//
// The component under test is the SPI master: it drives sck_i, cs_i and mosi_i,
// and this peer is the selected slave that drives miso_o.  Nothing in this file
// selects behaviour by component or model name: the frame length and the SPI
// mode (CPOL/CPHA) are parameters, an unsupported mode or frame length is
// rejected at time 0 with $fatal, and the observation outputs are registers
// cleared by the active-low synchronous reset rst_ni (miso_o and the ready
// handshake read their reset value for as long as rst_ni is asserted, so they
// are defined before the first clock edge).
//
// Port convention
//   sck_i / cs_i / mosi_i  the master's clock, chip select and data output.
//                          cs_i is active low when CS_ACTIVE_LOW is 1 and
//                          active high when it is 0.
//   miso_o                 the slave data output.  It carries the armed byte
//                          most-significant bit first while the peer is
//                          selected, and reads 0 while it is not selected, so
//                          it only changes on the edge the mode assigns to the
//                          slave and never while deselected.
//   tx_request_valid_i /
//   tx_request_data_i      the explicit transmit event plan: the byte the peer
//                          will shift out on miso_o.  One byte is armed at a
//                          time (tx_ready_o is high while the arm register is
//                          free); an offer that arrives while the register is
//                          full is dropped and counted in tx_drop_count_o,
//                          never queued.  The armed byte is consumed by the
//                          selection that follows it, and a selection with
//                          nothing armed shifts out zeros.
//   tx_armed_o             high while a byte is armed.
//   rx_data_o / rx_valid_o the byte assembled from mosi_i and a one-cycle valid
//                          pulse on the edge that completes it.
//   rx_count_o             bytes completed so far.
//   bit_count_o            bits sampled since the last completed byte, 0..BITS-1.
//   clock_count_o          sck_i transitions observed while selected.
//   deselected_clock_count_o /
//   deselected_clock_error_o  sck_i transitions observed while deselected and a
//                          sticky flag for the first of them.
//   incomplete_count_o /
//   incomplete_error_o     selections that ended with a partial byte and a
//                          sticky flag for the first of them.
//   selected_o             the registered chip-select state.
//
// SPI mode
//   CPOL selects the level of an idle sck_i: 0 = low, 1 = high.  The leading
//   edge is the one that leaves that idle level, the trailing edge is the one
//   that returns to it.  CPHA selects which edge carries what: with CPHA=0 the
//   peer samples mosi_i on the leading edge and changes miso_o on the trailing
//   edge, so the first bit is already presented when cs_i is asserted; with
//   CPHA=1 the peer changes miso_o on the leading edge and samples mosi_i on
//   the trailing edge, so the first bit appears on the first leading edge.  In
//   both modes the byte travels most-significant bit first.
//
// Selection semantics
//   The transfer is defined by the selection, not by a counter that runs across
//   one: every group of BITS sampled bits is reported on rx_valid_o, a
//   selection that ends with a partial group sets incomplete_error_o and
//   reports no byte for that partial group, and a selection with no clock edge
//   at all is empty rather than incomplete.  A byte that was not assembled from
//   BITS samples of mosi_i is never reported.
//
// Timing assumptions (the peer oversamples sck_i and cs_i with clk_i)
//   every sck_i level must be held for at least two clk_i cycles, or the pulse
//   can be missed; cs_i must be stable for at least one clk_i cycle in each
//   state; and cs_i must be asserted at least one clk_i cycle before the first
//   leading edge, so that a CPHA=0 selection can present its first bit in time.
//   After the armed byte is exhausted the peer keeps driving zeros.
//
// Deliberately not modelled, so that no claim is implied
//   word sizes above one parameterized frame with a word select, daisy chains,
//   dual-edge or delayed modes, wait states, FIFOs, and every electrical
//   property of the pins.
module soc_spi_peer #(
    parameter integer BITS = 8,           // bits per transferred byte, >= 1
    parameter integer CPOL = 0,           // idle sck_i level, 0 or 1
    parameter integer CPHA = 0,           // sample/shift edge selection, 0 or 1
    parameter integer CS_ACTIVE_LOW = 1   // 1 = cs_i active low, 0 = active high
) (
    input  logic            clk_i,
    input  logic            rst_ni,
    input  logic            tx_request_valid_i,
    input  logic [BITS-1:0] tx_request_data_i,
    output logic            tx_ready_o,
    output logic            tx_armed_o,
    output logic [31:0]     tx_drop_count_o,
    input  logic            sck_i,
    input  logic            cs_i,
    input  logic            mosi_i,
    output logic            miso_o,
    output logic [BITS-1:0] rx_data_o,
    output logic            rx_valid_o,
    output logic [31:0]     rx_count_o,
    output logic [31:0]     bit_count_o,
    output logic [31:0]     clock_count_o,
    output logic [31:0]     deselected_clock_count_o,
    output logic            deselected_clock_error_o,
    output logic [31:0]     incomplete_count_o,
    output logic            incomplete_error_o,
    output logic            selected_o
);
  localparam logic SCK_IDLE = (CPOL == 0) ? 1'b0 : 1'b1;

  logic       selected_w;   // live chip-select state
  logic       selected_q;   // registered chip-select state
  logic       cs_assert_w;  // first edge of a selection
  logic       cs_release_w; // first edge after a selection
  logic       sck_q;
  logic       sck_rise_w;
  logic       sck_fall_w;
  logic       sck_change_w;
  logic       leading_w;
  logic       trailing_w;
  logic       sample_w;     // the edge that samples mosi_i
  logic       shift_w;      // the edge that changes miso_o

  logic [BITS-1:0] armed_data_q;
  logic            armed_q;
  logic [BITS-1:0] tx_data_q;
  integer          tx_index_q;
  logic            miso_q;
  logic [BITS-1:0] rx_shift_q;
  integer          bit_count_q;
  integer          assemble_index;

  initial begin
    if ((BITS < 1) || ((CPOL != 0) && (CPOL != 1)) ||
        ((CPHA != 0) && (CPHA != 1)) ||
        ((CS_ACTIVE_LOW != 0) && (CS_ACTIVE_LOW != 1)))
      $fatal(1, "invalid soc_spi_peer parameters");
  end

  assign selected_w = (CS_ACTIVE_LOW != 0) ? ~cs_i : cs_i;
  assign cs_assert_w = selected_w && !selected_q;
  assign cs_release_w = !selected_w && selected_q;

  assign sck_rise_w = sck_i && !sck_q;
  assign sck_fall_w = !sck_i && sck_q;
  assign sck_change_w = sck_rise_w || sck_fall_w;
  assign leading_w = (CPOL == 0) ? sck_rise_w : sck_fall_w;
  assign trailing_w = (CPOL == 0) ? sck_fall_w : sck_rise_w;
  assign sample_w = (CPHA == 0) ? leading_w : trailing_w;
  assign shift_w = (CPHA == 0) ? trailing_w : leading_w;

  assign tx_ready_o = rst_ni && !armed_q;
  assign tx_armed_o = armed_q;
  // MISO reads 0 for as long as reset is asserted, so the line a master samples
  // is defined from time 0 instead of one edge later.
  assign miso_o = rst_ni ? miso_q : 1'b0;
  assign bit_count_o = bit_count_q[31:0];
  assign selected_o = selected_q;

  // The bits sampled so far with the bit sampled in this cycle placed at the
  // position the frame assigns to it, so the byte is assembled
  // most-significant bit first without depending on BITS.
  function automatic [BITS-1:0] with_sample(input [BITS-1:0] accumulated,
                                            input integer index,
                                            input logic bit_value);
    begin
      with_sample = accumulated;
      for (assemble_index = 0; assemble_index < BITS; assemble_index = assemble_index + 1)
        if (assemble_index == index)
          with_sample[assemble_index] = bit_value;
    end
  endfunction

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      selected_q <= 1'b0;
      sck_q <= SCK_IDLE;
      armed_q <= 1'b0;
      armed_data_q <= {BITS{1'b0}};
      tx_data_q <= {BITS{1'b0}};
      tx_index_q <= 0;
      miso_q <= 1'b0;
      rx_shift_q <= {BITS{1'b0}};
      rx_data_o <= {BITS{1'b0}};
      rx_valid_o <= 1'b0;
      rx_count_o <= '0;
      bit_count_q <= 0;
      clock_count_o <= '0;
      deselected_clock_count_o <= '0;
      deselected_clock_error_o <= 1'b0;
      incomplete_count_o <= '0;
      incomplete_error_o <= 1'b0;
      tx_drop_count_o <= '0;
    end else begin
      selected_q <= selected_w;
      sck_q <= sck_i;
      rx_valid_o <= 1'b0;

      // Every clock edge counts somewhere: inside a selection it is a transfer
      // edge, outside one it is an error condition rather than a transfer.
      if (sck_change_w && !selected_w) begin
        deselected_clock_count_o <= deselected_clock_count_o + 32'd1;
        deselected_clock_error_o <= 1'b1;
      end

      if (sck_change_w && selected_w) begin
        clock_count_o <= clock_count_o + 32'd1;
        if (sample_w) begin
          rx_shift_q[BITS-1-bit_count_q] <= mosi_i;
          if (bit_count_q == BITS - 1) begin
            rx_data_o <= with_sample(rx_shift_q, BITS-1-bit_count_q, mosi_i);
            rx_valid_o <= 1'b1;
            rx_count_o <= rx_count_o + 32'd1;
            bit_count_q <= 0;
          end else begin
            bit_count_q <= bit_count_q + 1;
          end
        end
        if (shift_w) begin
          miso_q <= (tx_index_q < BITS) ? tx_data_q[BITS-1-tx_index_q] : 1'b0;
          if (tx_index_q < BITS)
            tx_index_q <= tx_index_q + 1;
        end
      end

      // The selection boundaries own the shift state.
      if (cs_assert_w) begin
        rx_shift_q <= {BITS{1'b0}};
        bit_count_q <= 0;
        tx_data_q <= armed_q ? armed_data_q : {BITS{1'b0}};
        tx_index_q <= (CPHA == 0) ? 1 : 0;
        miso_q <= ((CPHA == 0) && armed_q) ? armed_data_q[BITS-1] : 1'b0;
        armed_q <= 1'b0;
      end else if (cs_release_w) begin
        if (bit_count_q != 0) begin
          incomplete_count_o <= incomplete_count_o + 32'd1;
          incomplete_error_o <= 1'b1;
        end
        bit_count_q <= 0;
        miso_q <= 1'b0;
        tx_index_q <= 0;
      end

      // The transmit event plan: one armed byte, everything else is dropped.
      if (tx_request_valid_i) begin
        if (!armed_q || cs_assert_w) begin
          armed_q <= 1'b1;
          armed_data_q <= tx_request_data_i;
        end else begin
          tx_drop_count_o <= tx_drop_count_o + 32'd1;
        end
      end
    end
  end
endmodule
