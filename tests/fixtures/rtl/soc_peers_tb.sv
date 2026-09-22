// Self-checking behavioural testbenches for the generic external peers
// (Icarus): soc_uart_peer, soc_spi_peer and soc_gpio_peer.
//
//   iverilog -g2012 -s <bench_top> -o tb.vvp <peer_rtl>.sv \
//       tests/fixtures/rtl/soc_peers_tb.sv
//   vvp tb.vvp
//
// Three bench modules live in this one file and the Python harness selects one
// with -s, so every bench is a complete self-checking unit:
//
//   soc_uart_peer_tb  framing of the byte the peer transmits, reception of a
//                     byte the bench drives on the line, a missing stop bit, an
//                     idle line, two different baud divisors, a skewed frame
//                     that only proves the sample point is inside the bit
//                     period, and the documented absence of a glitch filter.
//   soc_spi_peer_tb   a byte shifting in on the declared edge for every
//                     supported CPOL/CPHA combination, MISO changing only while
//                     selected and only on the declared edge, an unarmed
//                     selection, a clock edge while deselected (including one
//                     too short to be observed), a partial byte, and two whole
//                     bytes inside one selection.
//   soc_gpio_peer_tb  input read, output drive, direction change, one side
//                     driving, agreement, contention, and the default level of
//                     an undriven pin.
//
// Each bench prints its effective parameterization, the suite it ran, and
// exactly one result line, "RESULT: PASS" or "RESULT: FAIL: <reason>".  A
// failure prints the FAIL line and then aborts through $fatal, so vvp exits
// non-zero, and no PASS line is printed after a failure.
//
// NEGATIVE_CONTROL is a compile-time self-test hook that corrupts exactly one
// expectation per bench, so the Python harness can prove that the bench really
// fails when an expectation is wrong.  It is 0 in every real run:
//   soc_uart_peer_tb  the level expected of every transmitted stop bit.
//   soc_spi_peer_tb   the MISO bit a CPHA=0 selection presents before the first
//                     clock edge, so the hook only bites for CPHA=0.
//   soc_gpio_peer_tb  the contention flags expected when both sides drive the
//                     same value.

// ---------------------------------------------------------------------------
// UART peer
// ---------------------------------------------------------------------------
module soc_uart_peer_tb #(
    parameter integer DATA_WIDTH = 8,
    parameter integer BAUD_DIV = 1,
    parameter integer STOP_BITS = 1,
    parameter integer IDLE_LEVEL = 1,
    parameter integer TIMEOUT_BITS = 4,
    parameter integer NEGATIVE_CONTROL = 0
) ();
  localparam logic IDLE = (IDLE_LEVEL != 0) ? 1'b1 : 1'b0;
  localparam logic START = ~IDLE;
  localparam logic CORRUPT = (NEGATIVE_CONTROL != 0);
  localparam integer FRAME_BITS = 1 + DATA_WIDTH + STOP_BITS;
  localparam integer FRAME_CYCLES = FRAME_BITS * BAUD_DIV;
  localparam integer TIMEOUT_CYCLES = TIMEOUT_BITS * BAUD_DIV;
  localparam integer CENTER_CYCLES = BAUD_DIV / 2;
  localparam [DATA_WIDTH-1:0] ZERO_BYTE = {DATA_WIDTH{1'b0}};
  localparam [DATA_WIDTH-1:0] IDLE_BYTE = {DATA_WIDTH{IDLE}};

  logic                  clk_i = 1'b0;
  logic                  rst_ni = 1'b0;
  logic                  tx_request_valid_i = 1'b0;
  logic [DATA_WIDTH-1:0] tx_request_data_i = {DATA_WIDTH{1'b0}};
  logic                  tx_ready_o;
  logic                  tx_busy_o;
  logic [31:0]           tx_sent_count_o;
  logic [31:0]           tx_drop_count_o;
  logic                  serial_tx_o;
  logic                  serial_rx_i = IDLE;
  logic [DATA_WIDTH-1:0] rx_data_o;
  logic                  rx_valid_o;
  logic [31:0]           rx_count_o;
  logic [31:0]           framing_error_count_o;
  logic [31:0]           timeout_count_o;
  logic                  rx_busy_o;

  soc_uart_peer #(
      .DATA_WIDTH(DATA_WIDTH),
      .BAUD_DIV(BAUD_DIV),
      .STOP_BITS(STOP_BITS),
      .IDLE_LEVEL(IDLE_LEVEL),
      .TIMEOUT_BITS(TIMEOUT_BITS)
  ) dut (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .tx_request_valid_i(tx_request_valid_i),
      .tx_request_data_i(tx_request_data_i),
      .tx_ready_o(tx_ready_o),
      .tx_busy_o(tx_busy_o),
      .tx_sent_count_o(tx_sent_count_o),
      .tx_drop_count_o(tx_drop_count_o),
      .serial_tx_o(serial_tx_o),
      .serial_rx_i(serial_rx_i),
      .rx_data_o(rx_data_o),
      .rx_valid_o(rx_valid_o),
      .rx_count_o(rx_count_o),
      .framing_error_count_o(framing_error_count_o),
      .timeout_count_o(timeout_count_o),
      .rx_busy_o(rx_busy_o)
  );

  always #5 clk_i = ~clk_i;

  // -------------------------------------------------------------------------
  // Monitors: a reported byte is only accepted through a real one-cycle
  // rx_valid_o pulse, and the drop count is mirrored from observable signals.
  // Reading tx_busy_o in a clocked block gives its value before the edge, which
  // is exactly the busy state the DUT decides on at that edge.
  // -------------------------------------------------------------------------
  integer                rx_pulse_count = 0;
  logic [DATA_WIDTH-1:0] rx_pulse_data = {DATA_WIDTH{1'b0}};
  logic                  rx_valid_q = 1'b0;
  integer                drop_mirror = 0;

  always @(posedge clk_i) begin
    rx_valid_q <= rx_valid_o;
    if (rst_ni) begin
      if (rx_valid_o) begin
        if (rx_valid_q)
          fail("S2 rx_valid_o is a one-cycle pulse, not a level");
        rx_pulse_count <= rx_pulse_count + 1;
        rx_pulse_data <= rx_data_o;
      end
      if (tx_busy_o && tx_request_valid_i)
        drop_mirror <= drop_mirror + 1;
    end
  end

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------
  task automatic tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  task automatic fail(input [8*240-1:0] message);
    begin
      $display("RESULT: FAIL: %0s", message);
      $fatal(1, "soc_uart_peer self-check failed");
    end
  endtask

  task automatic check(input bit condition, input [8*240-1:0] message);
    begin
      if (!condition)
        fail(message);
    end
  endtask

  task automatic check32(input [31:0] actual, input [31:0] expected, input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%0d expected=%0d", actual, expected);
        fail(message);
      end
    end
  endtask

  task automatic check_byte(input [DATA_WIDTH-1:0] actual, input [DATA_WIDTH-1:0] expected,
                            input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%b expected=%b", actual, expected);
        fail(message);
      end
    end
  endtask

  // The level of frame bit `index`: 0 is the start bit, 1..DATA_WIDTH are the
  // data bits least-significant bit first, the rest are stop bits.
  function automatic logic frame_bit(input [DATA_WIDTH-1:0] value, input integer index);
    begin
      if (index == 0)
        frame_bit = START;
      else if (index <= DATA_WIDTH)
        frame_bit = value[index-1];
      else
        frame_bit = IDLE;
    end
  endfunction

  // The level the bench drives for cycle `cycle_index` of a frame it sends.  A
  // frame without a stop bit holds the start level for the first half of its
  // first stop bit period and returns to idle afterwards, so the peer samples
  // exactly one bad stop bit and then finds an idle line again instead of
  // starting another frame by itself.
  function automatic logic frame_cycle_level(input [DATA_WIDTH-1:0] value,
                                             input integer cycle_index,
                                             input bit stop_ok);
    integer bit_index;
    integer offset;
    begin
      bit_index = cycle_index / BAUD_DIV;
      offset = cycle_index % BAUD_DIV;
      if ((bit_index <= DATA_WIDTH) || stop_ok)
        frame_cycle_level = frame_bit(value, bit_index);
      else if (bit_index == DATA_WIDTH + 1)
        frame_cycle_level = (offset <= CENTER_CYCLES) ? START : IDLE;
      else
        frame_cycle_level = IDLE;
    end
  endfunction

  // Two deterministic byte patterns that differ from each other.
  function automatic [DATA_WIDTH-1:0] pattern_a;
    integer k;
    begin
      pattern_a = ZERO_BYTE;
      for (k = 0; k < DATA_WIDTH; k = k + 1)
        pattern_a[k] = ((k % 3) == 0);
    end
  endfunction

  function automatic [DATA_WIDTH-1:0] pattern_b;
    integer k;
    begin
      pattern_b = ZERO_BYTE;
      for (k = 0; k < DATA_WIDTH; k = k + 1)
        pattern_b[k] = ((k % 3) == 1);
    end
  endfunction

  // -------------------------------------------------------------------------
  // S1 transmit: the offer is presented on a falling edge and the whole frame is
  // then checked cycle by cycle against the declared format.  `hold_offer`
  // keeps a second byte offered for the whole frame so that the drop accounting
  // can be checked as well.
  // -------------------------------------------------------------------------
  task automatic peer_transmit(input [DATA_WIDTH-1:0] value,
                               input bit hold_offer,
                               input [DATA_WIDTH-1:0] second);
    integer k;
    integer index;
    logic expected;
    integer sent_before;
    begin
      sent_before = tx_sent_count_o;
      @(negedge clk_i);
      tx_request_valid_i = 1'b1;
      tx_request_data_i = value;
      tick();
      if (hold_offer) begin
        tx_request_valid_i = 1'b1;   // held for the rest of the frame
        tx_request_data_i = second;
      end else begin
        tx_request_valid_i = 1'b0;
      end
      check(tx_busy_o, "S1 the peer is busy on the edge that accepts an offer");
      check(!tx_ready_o, "S1 the peer is not ready while it transmits");
      for (k = 0; k < FRAME_CYCLES; k = k + 1) begin
        index = k / BAUD_DIV;
        expected = frame_bit(value, index);
        if (index == 0)
          check(serial_tx_o === expected,
                "S1 the transmitted start bit is held for exactly BAUD_DIV cycles");
        else if (index <= DATA_WIDTH)
          check(serial_tx_o === expected,
                "S1 the transmitted data bits are framed least-significant bit first");
        else
          check(serial_tx_o === (expected ^ CORRUPT),
                "S1 the transmitted stop bits are held at the idle level");
        check(tx_busy_o, "S1 tx_busy_o stays high for the whole frame");
        tick();
      end
      tx_request_valid_i = 1'b0;
      check(!tx_busy_o, "S1 tx_busy_o drops after the last stop bit period");
      check(serial_tx_o === IDLE, "S1 the line returns to the idle level after the frame");
      check32(tx_sent_count_o, sent_before + 1, "S1 an accepted offer is transmitted exactly once");
    end
  endtask

  // -------------------------------------------------------------------------
  // S2/S3 receive: the bench drives one frame at the declared divisor, checks
  // that no byte is reported before the data bits were sampled, and that no
  // idle timeout is counted while the frame is being sampled.  The monitor
  // collects the report itself.
  // -------------------------------------------------------------------------
  task automatic dut_send_frame(input [DATA_WIDTH-1:0] value, input bit stop_ok);
    integer k;
    integer index;
    integer timeouts_at_start;
    begin
      timeouts_at_start = timeout_count_o;
      for (k = 0; k < FRAME_CYCLES; k = k + 1) begin
        index = k / BAUD_DIV;
        @(negedge clk_i);
        serial_rx_i = frame_cycle_level(value, k, stop_ok);
        if (index <= DATA_WIDTH)
          check(!rx_valid_o,
                "S2 the peer reports no byte before the data bits were sampled");
        if (rx_busy_o)
          check32(timeout_count_o, timeouts_at_start,
                  "S4 sampling a frame does not count as an idle timeout");
        tick();
      end
      @(negedge clk_i);
      serial_rx_i = IDLE;
    end
  endtask

  // The peer registers the report on the edge that sampled the last stop bit, so
  // the clocked monitor observes the pulse on the following edge: wait for it
  // with a bound instead of assuming an exact edge.
  task automatic await_reports(input integer expected, input [8*240-1:0] message);
    integer k;
    begin
      for (k = 0; (k < 4) && (rx_pulse_count < expected); k = k + 1)
        tick();
      if (rx_pulse_count != expected) begin
        $display("NOTE: reports=%0d expected=%0d", rx_pulse_count, expected);
        fail(message);
      end
    end
  endtask

  // S6 receive a frame whose data bits are only correct around the middle of
  // each bit period: the first and the last cycle of every data bit period carry
  // the opposite level.  A receiver that samples strictly inside the bit period
  // still receives the byte, so a received byte here proves the sample point is
  // not on a bit boundary.  The start and stop bits are driven cleanly, because
  // a late start level would itself look like a new frame.
  task automatic dut_send_skewed_frame(input [DATA_WIDTH-1:0] value);
    integer k;
    integer index;
    integer offset;
    logic level;
    begin
      for (k = 0; k < FRAME_CYCLES; k = k + 1) begin
        index = k / BAUD_DIV;
        offset = k % BAUD_DIV;
        level = frame_bit(value, index);
        if ((index >= 1) && (index <= DATA_WIDTH) && ((offset == 0) || (offset == BAUD_DIV - 1)))
          level = ~level;
        @(negedge clk_i);
        serial_rx_i = level;
        tick();
      end
      @(negedge clk_i);
      serial_rx_i = IDLE;
    end
  endtask

  // -------------------------------------------------------------------------
  // Run
  // -------------------------------------------------------------------------
  integer pulses_before;
  integer bytes_before;
  integer framing_before;
  integer timeouts_before;
  integer drops_before;
  integer idle_cycles;
  integer k;

  initial begin
    $display({"NOTE: soc_uart_peer_tb DATA_WIDTH=%0d BAUD_DIV=%0d STOP_BITS=%0d IDLE_LEVEL=%0d ",
              "TIMEOUT_BITS=%0d NEGATIVE_CONTROL=%0d"},
             DATA_WIDTH, BAUD_DIV, STOP_BITS, IDLE_LEVEL, TIMEOUT_BITS, NEGATIVE_CONTROL);
    $display("NOTE: suite=uart");
    rst_ni = 1'b0;
    tx_request_valid_i = 1'b0;
    tx_request_data_i = ZERO_BYTE;
    serial_rx_i = IDLE;
    #1;
    check(serial_tx_o === IDLE, "S0 reset drives the line to the idle level");
    check(!tx_ready_o, "S0 reset clears tx_ready_o");
    tick();   // the synchronous reset is applied on this edge
    check(serial_tx_o === IDLE, "S0 reset keeps the line at the idle level");
    check(!tx_busy_o, "S0 reset clears tx_busy_o");
    check32(tx_sent_count_o, 0, "S0 reset clears tx_sent_count_o");
    check32(tx_drop_count_o, 0, "S0 reset clears tx_drop_count_o");
    check(!rx_valid_o, "S0 reset clears rx_valid_o");
    check(!rx_busy_o, "S0 reset clears rx_busy_o");
    check_byte(rx_data_o, ZERO_BYTE, "S0 reset clears rx_data_o");
    check32(rx_count_o, 0, "S0 reset clears rx_count_o");
    check32(framing_error_count_o, 0, "S0 reset clears framing_error_count_o");
    check32(timeout_count_o, 0, "S0 reset clears timeout_count_o");
    tick();
    check(serial_tx_o === IDLE, "S0 reset keeps the line at the idle level");
    check32(tx_sent_count_o, 0, "S0 reset keeps the counters clear");
    @(negedge clk_i);
    rst_ni = 1'b1;
    tick();
    check(tx_ready_o, "S0 the peer is ready after reset");

    // S1 transmit: three frames with different bytes, then one frame with a
    // competing offer held for its whole length.
    peer_transmit(pattern_a(), 1'b0, ZERO_BYTE);
    peer_transmit(pattern_b(), 1'b0, ZERO_BYTE);
    peer_transmit(ZERO_BYTE, 1'b0, ZERO_BYTE);
    check32(tx_sent_count_o, 3, "S1 every accepted offer is transmitted");
    drops_before = tx_drop_count_o;
    peer_transmit(pattern_a(), 1'b1, pattern_b());
    check(tx_drop_count_o > drops_before, "S1 an offer during a frame is dropped and counted");
    check32(tx_drop_count_o, drop_mirror,
            "S1 a dropped offer is counted once for every busy cycle that offers it");
    check32(tx_sent_count_o, 4, "S1 a dropped offer never becomes a second frame");
    for (k = 0; k < FRAME_CYCLES; k = k + 1) begin
      check(serial_tx_o === IDLE, "S1 a dropped offer is never transmitted later");
      check(!tx_busy_o, "S1 a dropped offer never starts a frame");
      tick();
    end

    // S2 receive: three different bytes at the declared divisor.
    pulses_before = rx_pulse_count;
    bytes_before = rx_count_o;
    framing_before = framing_error_count_o;
    dut_send_frame(pattern_a(), 1'b1);
    await_reports(pulses_before + 1, "S2 one framed byte produces exactly one report");
    check_byte(rx_pulse_data, pattern_a(), "S2 the reported byte is the byte that was on the line");
    check32(rx_count_o, bytes_before + 1, "S2 rx_count_o counts the reported byte");
    check32(framing_error_count_o, framing_before,
            "S2 a well framed byte reports no framing error");
    pulses_before = rx_pulse_count;
    dut_send_frame(pattern_b(), 1'b1);
    await_reports(pulses_before + 1, "S2 the receiver is ready for the next byte");
    check_byte(rx_pulse_data, pattern_b(), "S2 the second reported byte is the second byte on the line");
    pulses_before = rx_pulse_count;
    dut_send_frame(IDLE_BYTE, 1'b1);
    await_reports(pulses_before + 1, "S2 a byte of idle-level bits is received as data");
    check_byte(rx_pulse_data, IDLE_BYTE, "S2 the reported value does not depend on the bit pattern");

    // S3 a missing stop bit: the sampled data bits are still reported, the stop
    // bit period is one framing error, and the receiver recovers afterwards.
    pulses_before = rx_pulse_count;
    framing_before = framing_error_count_o;
    bytes_before = rx_count_o;
    dut_send_frame(pattern_a(), 1'b0);
    await_reports(pulses_before + 1,
                  "S3 the data bits of a frame with a missing stop bit are still reported");
    check_byte(rx_pulse_data, pattern_a(), "S3 the reported byte is the byte that was sampled");
    check32(rx_count_o, bytes_before + 1, "S3 a framing error still reports the sampled byte");
    check32(framing_error_count_o, framing_before + 1,
            "S3 a missing stop bit is counted as exactly one framing error");
    pulses_before = rx_pulse_count;
    framing_before = framing_error_count_o;
    dut_send_frame(pattern_b(), 1'b1);
    await_reports(pulses_before + 1, "S3 the receiver recovers after a framing error");
    check_byte(rx_pulse_data, pattern_b(), "S3 the byte after the framing error is sampled correctly");
    check32(framing_error_count_o, framing_before, "S3 the good frame adds no framing error");

    // S4 an idle line: no byte, no framing error, one timeout per TIMEOUT_BITS
    // idle bit periods, and no timeout while a frame is being sampled.
    pulses_before = rx_pulse_count;
    bytes_before = rx_count_o;
    timeouts_before = timeout_count_o;
    framing_before = framing_error_count_o;
    // Two whole timeout windows plus a margin: the window phase is unknown, so
    // the count must be at least two and at most one more than the number of
    // whole windows the idle stretch can contain.
    idle_cycles = 2 * TIMEOUT_CYCLES + 2;
    for (k = 0; k < idle_cycles; k = k + 1)
      tick();
    check32(rx_count_o, bytes_before, "S4 an idle line reports no byte");
    check(rx_pulse_count == pulses_before, "S4 an idle line never pulses rx_valid_o");
    check32(framing_error_count_o, framing_before, "S4 an idle line is not a framing error");
    check(timeout_count_o >= timeouts_before + 2,
          "S4 an idle line times out once per TIMEOUT_BITS idle bit periods");
    check(timeout_count_o <= timeouts_before + (idle_cycles / TIMEOUT_CYCLES) + 1,
          "S4 the idle timeout never fires faster than TIMEOUT_BITS bit periods");
    pulses_before = rx_pulse_count;
    dut_send_frame(pattern_b(), 1'b1);
    await_reports(pulses_before + 1, "S4 a frame on an otherwise idle line is still received");

    // S5 the documented absence of a glitch filter: a start pulse one clk_i
    // cycle long is accepted as a frame start and the following idle line is
    // received as a byte of idle-level bits without a framing error.
    pulses_before = rx_pulse_count;
    framing_before = framing_error_count_o;
    @(negedge clk_i);
    serial_rx_i = START;
    tick();
    @(negedge clk_i);
    serial_rx_i = IDLE;
    for (k = 0; k <= FRAME_CYCLES + 2; k = k + 1)
      tick();
    await_reports(pulses_before + 1,
                  "S5 there is no glitch filter: a one-cycle start pulse is received as a frame");
    check_byte(rx_pulse_data, IDLE_BYTE, "S5 a glitch is received as a byte of idle-level bits");
    check32(framing_error_count_o, framing_before,
            "S5 a glitch frame has no framing error when the line returns to idle");

    // S6 the sample point sits strictly inside every bit period: a frame whose
    // data bits are inverted on their first and last cycles is still received.
    // With fewer than three cycles per bit there is no interior cycle to keep
    // clean, so the scenario only runs where it can mean something.
    if (BAUD_DIV >= 3) begin
      pulses_before = rx_pulse_count;
      framing_before = framing_error_count_o;
      dut_send_skewed_frame(pattern_a());
      await_reports(pulses_before + 1,
                    "S6 a skewed frame is received: the sample point is inside the bit period");
      check_byte(rx_pulse_data, pattern_a(), "S6 the skewed frame reports the sampled byte");
      check32(framing_error_count_o, framing_before,
              "S6 the clean stop bit of a skewed frame is not a framing error");
    end

    $display("NOTE: reported bytes=%0d framing errors=%0d timeouts=%0d transmitted=%0d dropped=%0d",
             rx_pulse_count, framing_error_count_o, timeout_count_o, tx_sent_count_o, tx_drop_count_o);

    // A last reset must leave the peer idle and clear.
    @(negedge clk_i);
    rst_ni = 1'b0;
    tx_request_valid_i = 1'b0;
    serial_rx_i = IDLE;
    #1;
    check(serial_tx_o === IDLE, "final: reset drives the line to the idle level");
    tick();   // the synchronous reset is applied on this edge
    check(serial_tx_o === IDLE, "final: the line stays idle under reset");
    check(!tx_busy_o, "final: reset clears tx_busy_o");
    check(!rx_busy_o, "final: reset clears rx_busy_o");
    check(!rx_valid_o, "final: reset clears rx_valid_o");
    check32(tx_sent_count_o, 0, "final: reset clears tx_sent_count_o");
    $display("RESULT: PASS");
    $finish;
  end
endmodule

// ---------------------------------------------------------------------------
// SPI peer
// ---------------------------------------------------------------------------
module soc_spi_peer_tb #(
    parameter integer BITS = 8,
    parameter integer CPOL = 0,
    parameter integer CPHA = 0,
    parameter integer CS_ACTIVE_LOW = 1,
    parameter integer NEGATIVE_CONTROL = 0
) ();
  localparam logic SCK_IDLE = (CPOL == 0) ? 1'b0 : 1'b1;
  localparam logic SCK_ACTIVE = ~SCK_IDLE;
  localparam logic CS_ACTIVE = (CS_ACTIVE_LOW != 0) ? 1'b0 : 1'b1;
  localparam logic CS_INACTIVE = ~CS_ACTIVE;
  localparam logic CORRUPT = (NEGATIVE_CONTROL != 0);
  localparam integer SCK_HALF_CYCLES = 2;   // every sck_i level is held two clk_i cycles
  localparam [BITS-1:0] ZERO_BYTE = {BITS{1'b0}};

  logic            clk_i = 1'b0;
  logic            rst_ni = 1'b0;
  logic            tx_request_valid_i = 1'b0;
  logic [BITS-1:0] tx_request_data_i = {BITS{1'b0}};
  logic            tx_ready_o;
  logic            tx_armed_o;
  logic [31:0]     tx_drop_count_o;
  logic            sck_i = SCK_IDLE;
  logic            cs_i = CS_INACTIVE;
  logic            mosi_i = 1'b0;
  logic            miso_o;
  logic [BITS-1:0] rx_data_o;
  logic            rx_valid_o;
  logic [31:0]     rx_count_o;
  logic [31:0]     bit_count_o;
  logic [31:0]     clock_count_o;
  logic [31:0]     deselected_clock_count_o;
  logic            deselected_clock_error_o;
  logic [31:0]     incomplete_count_o;
  logic            incomplete_error_o;
  logic            selected_o;

  soc_spi_peer #(
      .BITS(BITS),
      .CPOL(CPOL),
      .CPHA(CPHA),
      .CS_ACTIVE_LOW(CS_ACTIVE_LOW)
  ) dut (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .tx_request_valid_i(tx_request_valid_i),
      .tx_request_data_i(tx_request_data_i),
      .tx_ready_o(tx_ready_o),
      .tx_armed_o(tx_armed_o),
      .tx_drop_count_o(tx_drop_count_o),
      .sck_i(sck_i),
      .cs_i(cs_i),
      .mosi_i(mosi_i),
      .miso_o(miso_o),
      .rx_data_o(rx_data_o),
      .rx_valid_o(rx_valid_o),
      .rx_count_o(rx_count_o),
      .bit_count_o(bit_count_o),
      .clock_count_o(clock_count_o),
      .deselected_clock_count_o(deselected_clock_count_o),
      .deselected_clock_error_o(deselected_clock_error_o),
      .incomplete_count_o(incomplete_count_o),
      .incomplete_error_o(incomplete_error_o),
      .selected_o(selected_o)
  );

  always #5 clk_i = ~clk_i;

  integer          rx_pulse_count = 0;
  logic [BITS-1:0] rx_pulse_data = {BITS{1'b0}};
  logic            rx_valid_q = 1'b0;

  always @(posedge clk_i) begin
    rx_valid_q <= rx_valid_o;
    if (rst_ni && rx_valid_o) begin
      if (rx_valid_q)
        fail("S2 rx_valid_o is a one-cycle pulse, not a level");
      rx_pulse_count <= rx_pulse_count + 1;
      rx_pulse_data <= rx_data_o;
    end
  end

  task automatic tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  task automatic fail(input [8*240-1:0] message);
    begin
      $display("RESULT: FAIL: %0s", message);
      $fatal(1, "soc_spi_peer self-check failed");
    end
  endtask

  task automatic check(input bit condition, input [8*240-1:0] message);
    begin
      if (!condition)
        fail(message);
    end
  endtask

  task automatic check32(input [31:0] actual, input [31:0] expected, input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%0d expected=%0d", actual, expected);
        fail(message);
      end
    end
  endtask

  task automatic check_byte(input [BITS-1:0] actual, input [BITS-1:0] expected,
                            input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%b expected=%b", actual, expected);
        fail(message);
      end
    end
  endtask

  function automatic [BITS-1:0] pattern_a;
    integer k;
    begin
      pattern_a = ZERO_BYTE;
      for (k = 0; k < BITS; k = k + 1)
        pattern_a[k] = ((k % 2) == 0);
    end
  endfunction

  function automatic [BITS-1:0] pattern_b;
    integer k;
    begin
      pattern_b = ZERO_BYTE;
      for (k = 0; k < BITS; k = k + 1)
        pattern_b[k] = ((k % 2) == 1);
    end
  endfunction

  // Offer one byte to the transmit arm register.
  task automatic arm_byte(input [BITS-1:0] value);
    begin
      @(negedge clk_i);
      tx_request_valid_i = 1'b1;
      tx_request_data_i = value;
      tick();
      tx_request_valid_i = 1'b0;
      check(tx_armed_o, "S1 an offered byte is armed for the next selection");
      check(!tx_ready_o, "S1 the arm register is busy while a byte is armed");
    end
  endtask

  task automatic select_slave;
    begin
      @(negedge clk_i);
      cs_i = CS_ACTIVE;
      tick();
      check(selected_o, "S2 the peer reports the selection it was given");
    end
  endtask

  task automatic deselect_slave;
    begin
      @(negedge clk_i);
      cs_i = CS_INACTIVE;
      tick();
      check(!selected_o, "S2 the peer reports the end of the selection");
      check(miso_o === 1'b0, "S2 MISO reads 0 while the peer is not selected");
    end
  endtask

  task automatic drive_mosi(input logic value);
    begin
      @(negedge clk_i);
      mosi_i = value;
    end
  endtask

  // One sck_i edge, driven at a falling clk_i edge so that the peer sees the new
  // level on the following rising edge, followed by a check of miso_o on every
  // clk_i edge of the half period: MISO must be stable across the whole half
  // period and may only change on the edge the declared mode assigns to it.
  task automatic spi_edge(input logic sck_level, input logic miso_expected,
                          input [8*240-1:0] message);
    integer k;
    begin
      @(negedge clk_i);
      sck_i = sck_level;
      for (k = 0; k < SCK_HALF_CYCLES; k = k + 1) begin
        tick();
        check(miso_o === miso_expected, message);
      end
    end
  endtask

  // One byte inside an already asserted selection.  The bench is the master and
  // drives mosi_i most-significant bit first; `miso_byte` is the sequence the
  // peer has to present, and the assembled byte must equal `master_byte`.
  task automatic spi_bits(input [BITS-1:0] master_byte, input [BITS-1:0] miso_byte,
                          input [8*240-1:0] message);
    integer b;
    integer next_index;
    begin
      for (b = 0; b < BITS; b = b + 1) begin
        next_index = BITS - 2 - b;
        drive_mosi(master_byte[BITS-1-b]);
        if (CPHA == 0) begin
          spi_edge(SCK_ACTIVE, miso_byte[BITS-1-b],
                   "S3 MISO is stable for the leading half period of a CPHA=0 bit");
          spi_edge(SCK_IDLE, (next_index >= 0) ? miso_byte[next_index] : 1'b0,
                   "S2 MISO changes on the trailing edge of a CPHA=0 selection");
        end else begin
          spi_edge(SCK_ACTIVE, miso_byte[BITS-1-b],
                   "S2 MISO changes on the leading edge of a CPHA=1 selection");
          spi_edge(SCK_IDLE, miso_byte[BITS-1-b],
                   "S3 MISO is stable for the trailing half period of a CPHA=1 bit");
        end
      end
      check_byte(rx_pulse_data, master_byte, message);
    end
  endtask

  integer          pulses_before;
  integer          bytes_before;
  integer          clk_before;
  integer          errors_before;
  integer          drops_before;
  integer          k;
  integer          j;
  logic [BITS-1:0] armed;
  logic [BITS-1:0] master;

  initial begin
    $display({"NOTE: soc_spi_peer_tb BITS=%0d CPOL=%0d CPHA=%0d CS_ACTIVE_LOW=%0d ",
              "NEGATIVE_CONTROL=%0d"},
             BITS, CPOL, CPHA, CS_ACTIVE_LOW, NEGATIVE_CONTROL);
    $display("NOTE: suite=spi");
    rst_ni = 1'b0;
    tx_request_valid_i = 1'b0;
    tx_request_data_i = ZERO_BYTE;
    sck_i = SCK_IDLE;
    cs_i = CS_INACTIVE;
    mosi_i = 1'b0;
    #1;
    check(miso_o === 1'b0, "S0 reset drives MISO to 0");
    check(tx_ready_o === 1'b0, "S0 reset holds the arm handshake low");
    tick();   // the synchronous reset is applied on this edge
    check(miso_o === 1'b0, "S0 reset keeps MISO at 0");
    check(!selected_o, "S0 reset clears the selection");
    check(!tx_armed_o, "S0 reset clears the arm register");
    check(!rx_valid_o, "S0 reset clears rx_valid_o");
    check32(rx_count_o, 0, "S0 reset clears rx_count_o");
    check32(bit_count_o, 0, "S0 reset clears bit_count_o");
    check32(clock_count_o, 0, "S0 reset clears clock_count_o");
    check32(deselected_clock_count_o, 0, "S0 reset clears deselected_clock_count_o");
    check(!deselected_clock_error_o, "S0 reset clears deselected_clock_error_o");
    check32(incomplete_count_o, 0, "S0 reset clears incomplete_count_o");
    check(!incomplete_error_o, "S0 reset clears incomplete_error_o");
    check32(tx_drop_count_o, 0, "S0 reset clears tx_drop_count_o");
    tick();
    check(miso_o === 1'b0, "S0 reset keeps MISO at 0");
    @(negedge clk_i);
    rst_ni = 1'b1;
    tick();
    check(tx_ready_o, "S0 the peer can take an offer after reset");
    check(miso_o === 1'b0, "S0 MISO is 0 after reset");

    // S1 the explicit transmit event plan: one armed byte, extras are dropped.
    armed = pattern_a();
    arm_byte(armed);
    check32(tx_drop_count_o, 0, "S1 arming one byte is not a drop");
    @(negedge clk_i);
    tx_request_valid_i = 1'b1;
    tx_request_data_i = pattern_b();
    tick();
    tx_request_valid_i = 1'b0;
    check32(tx_drop_count_o, 1, "S1 an offer while the arm register is full is dropped and counted");
    check(tx_armed_o, "S1 a dropped offer does not replace the armed byte");

    // S2 one byte per selection in the declared mode.
    master = pattern_a();
    pulses_before = rx_pulse_count;
    bytes_before = rx_count_o;
    clk_before = clock_count_o;
    select_slave();
    if (CPHA == 0)
      check(miso_o === (armed[BITS-1] ^ CORRUPT),
            "S2 a CPHA=0 selection presents the armed byte first bit before the first clock edge");
    else
      check(miso_o === 1'b0, "S2 MISO is 0 before the first leading edge of a CPHA=1 selection");
    spi_bits(master, armed, "S2 the byte on mosi_i is assembled most-significant bit first");
    deselect_slave();
    check(rx_pulse_count == pulses_before + 1, "S2 one complete byte produces exactly one report");
    check32(rx_count_o, bytes_before + 1, "S2 rx_count_o counts the completed byte");
    check32(clock_count_o, clk_before + (2 * BITS), "S2 every clock edge inside the selection is counted");
    check32(bit_count_o, 0, "S2 bit_count_o returns to 0 after a complete byte");
    check32(incomplete_count_o, 0, "S2 a complete byte is not incomplete");
    check(!incomplete_error_o, "S2 a complete byte leaves the incomplete flag clear");

    // S2b a second selection with the other byte value.
    armed = pattern_b();
    master = pattern_b();
    arm_byte(armed);
    pulses_before = rx_pulse_count;
    select_slave();
    if (CPHA == 0)
      check(miso_o === (armed[BITS-1] ^ CORRUPT),
            "S2 a CPHA=0 selection presents the armed byte first bit before the first clock edge");
    spi_bits(master, armed, "S2 the second byte is assembled and shifted independently");
    deselect_slave();
    check(rx_pulse_count == pulses_before + 1, "S2 the second selection reports one byte");

    // S3 a selection with nothing armed shifts out zeros.
    master = pattern_a();
    pulses_before = rx_pulse_count;
    select_slave();
    if (CPHA == 0)
      check(miso_o === 1'b0, "S3 an unarmed CPHA=0 selection presents 0");
    spi_bits(master, ZERO_BYTE, "S3 an unarmed selection still collects the byte on mosi_i");
    deselect_slave();
    check(rx_pulse_count == pulses_before + 1, "S3 an unarmed selection still reports its received byte");

    // S4 MISO does not move while the peer is deselected, even when bytes are
    // offered and armed.  The first offer arms, every later one is dropped.
    drops_before = tx_drop_count_o;
    for (k = 0; k < 8; k = k + 1) begin
      @(negedge clk_i);
      tx_request_valid_i = 1'b1;
      tx_request_data_i = pattern_b();
      tick();
      tx_request_valid_i = 1'b0;
      check(miso_o === 1'b0, "S4 MISO stays 0 for every deselected cycle");
      check(!selected_o, "S4 the peer stays deselected");
    end
    check32(tx_drop_count_o, drops_before + 7,
            "S4 one of eight deselected offers arms and the other seven are dropped");
    // An empty selection consumes the armed byte, so the next scenario starts
    // from a known register state.
    select_slave();
    deselect_slave();
    check(tx_ready_o, "S4 the empty selection released the arm register");
    check(miso_o === 1'b0, "S4 MISO is still 0 after the empty selection");

    // S5 a clock edge while deselected is an error condition, counted once per
    // observed transition and never as a transfer clock.
    clk_before = clock_count_o;
    errors_before = deselected_clock_count_o;
    for (k = 0; k < 4; k = k + 1) begin
      @(negedge clk_i);
      sck_i = ~sck_i;
      for (j = 0; j < SCK_HALF_CYCLES; j = j + 1)
        tick();
      check32(deselected_clock_count_o, errors_before + k + 1,
              "S5 a clock edge while deselected is counted exactly once");
      check(deselected_clock_error_o,
            "S5 a clock edge while deselected sets the sticky error flag");
    end
    check(sck_i === SCK_IDLE, "S5 four toggles return the clock to its idle level");
    check32(deselected_clock_count_o, errors_before + 4, "S5 only real clock transitions are counted");
    check32(clock_count_o, clk_before, "S5 deselected clock edges are not transfer clocks");

    // A pulse shorter than one clk_i cycle can be missed, which is why the
    // environment has to hold every sck_i level: the peer samples the clock on
    // clk_i, it does not watch it.
    errors_before = deselected_clock_count_o;
    @(negedge clk_i);
    sck_i = ~sck_i;
    #2;
    sck_i = ~sck_i;   // back to the idle level before the sampling edge
    tick();
    check32(deselected_clock_count_o, errors_before,
            "S5 a clock pulse shorter than one clk_i cycle is not observed");
    check32(clock_count_o, clk_before, "S5 a missed clock pulse is not a transfer clock");

    // S6 a byte that does not complete reports no byte and sets the flag, while
    // a selection with no clock edge is empty rather than incomplete.
    pulses_before = rx_pulse_count;
    bytes_before = rx_count_o;
    errors_before = incomplete_count_o;
    if (BITS >= 2) begin
      armed = pattern_a();
      master = pattern_a();
      arm_byte(armed);
      select_slave();
      for (k = 0; k < BITS - 1; k = k + 1) begin
        drive_mosi(master[BITS-1-k]);
        if (CPHA == 0) begin
          spi_edge(SCK_ACTIVE, armed[BITS-1-k],
                   "S6 MISO still follows the declared edge while a partial byte is clocked");
          spi_edge(SCK_IDLE, (BITS - 2 - k) >= 0 ? armed[BITS-2-k] : 1'b0,
                   "S6 MISO still follows the declared edge while a partial byte is clocked");
        end else begin
          spi_edge(SCK_ACTIVE, armed[BITS-1-k],
                   "S6 MISO still follows the declared edge while a partial byte is clocked");
          spi_edge(SCK_IDLE, armed[BITS-1-k],
                   "S6 MISO still follows the declared edge while a partial byte is clocked");
        end
      end
      check32(bit_count_o, BITS - 1, "S6 bit_count_o reports the bits of the partial byte");
      deselect_slave();
      check(rx_pulse_count == pulses_before, "S6 a partial byte reports no byte");
      check32(rx_count_o, bytes_before, "S6 a partial byte does not advance rx_count_o");
      check32(incomplete_count_o, errors_before + 1, "S6 a partial byte is counted as incomplete");
      check(incomplete_error_o, "S6 a partial byte sets the sticky incomplete flag");
    end
    select_slave();
    deselect_slave();
    check32(incomplete_count_o, errors_before + ((BITS >= 2) ? 1 : 0),
            "S6 a selection with no clock edge is empty, not incomplete");
    check32(bit_count_o, 0, "S6 an empty selection leaves bit_count_o at 0");

    // S7 two whole bytes inside one selection: two reports, no incomplete byte,
    // and MISO returning to 0 once the armed byte is exhausted.
    armed = pattern_b();
    master = pattern_a();
    arm_byte(armed);
    pulses_before = rx_pulse_count;
    bytes_before = rx_count_o;
    errors_before = incomplete_count_o;
    select_slave();
    spi_bits(master, armed, "S7 the first byte of a two-byte selection is assembled");
    spi_bits(pattern_b(), ZERO_BYTE, "S7 the exhausted arm register keeps shifting zeros");
    deselect_slave();
    check(rx_pulse_count == pulses_before + 2, "S7 a two-byte selection reports two bytes");
    check32(rx_count_o, bytes_before + 2, "S7 rx_count_o counts both bytes");
    check32(bit_count_o, 0, "S7 a two-byte selection ends on a byte boundary");
    check32(incomplete_count_o, errors_before, "S7 two whole bytes are not an incomplete byte");
    check(tx_ready_o, "S7 the arm register is free again after the selection was consumed");

    // A last reset must leave the peer deselected and idle.
    @(negedge clk_i);
    rst_ni = 1'b0;
    tx_request_valid_i = 1'b0;
    cs_i = CS_INACTIVE;
    sck_i = SCK_IDLE;
    #1;
    check(miso_o === 1'b0, "final: reset drives MISO to 0");
    tick();   // the synchronous reset is applied on this edge
    check(miso_o === 1'b0, "final: MISO stays 0 under reset");
    check(!selected_o, "final: reset clears the selection");
    check(!tx_armed_o, "final: reset clears the arm register");
    check(!rx_valid_o, "final: reset clears rx_valid_o");
    check32(rx_count_o, 0, "final: reset clears rx_count_o");
    $display({"NOTE: received bytes=%0d clocks while selected=%0d clocks while deselected=%0d ",
              "incomplete=%0d"},
             rx_pulse_count, clock_count_o, deselected_clock_count_o, incomplete_count_o);
    $display("RESULT: PASS");
    $finish;
  end
endmodule

// ---------------------------------------------------------------------------
// GPIO peer
// ---------------------------------------------------------------------------
module soc_gpio_peer_tb #(
    parameter integer PINS = 1,
    parameter integer DEFAULT_INPUT_LEVEL = 0,
    parameter integer CONTENTION_IS_ERROR = 0,
    parameter integer NEGATIVE_CONTROL = 0
) ();
  localparam logic DEFAULT_LEVEL = (DEFAULT_INPUT_LEVEL == 0) ? 1'b0 : 1'b1;
  localparam logic CONTENTION_LEVEL = 1'b0;
  localparam [PINS-1:0] ALL_ZERO = {PINS{1'b0}};
  localparam [PINS-1:0] ALL_ONES = {PINS{1'b1}};
  localparam [PINS-1:0] DEFAULT_VECTOR = {PINS{DEFAULT_LEVEL}};
  localparam [PINS-1:0] CONTENTION_VECTOR = {PINS{CONTENTION_LEVEL}};
  // The one expectation the negative control corrupts: "no contention at all".
  localparam [PINS-1:0] NOT_CONTENDING = (NEGATIVE_CONTROL != 0) ? ALL_ONES : ALL_ZERO;

  logic            clk_i = 1'b0;
  logic            rst_ni = 1'b0;
  logic [PINS-1:0] peer_drive_valid_i = {PINS{1'b0}};
  logic [PINS-1:0] peer_drive_value_i = {PINS{1'b0}};
  logic [PINS-1:0] component_out_i;
  logic [PINS-1:0] component_dir_i;
  logic [PINS-1:0] pin_o;
  logic [PINS-1:0] pin_value_o;
  logic [PINS-1:0] direction_o;
  logic [PINS-1:0] contention_o;
  logic [31:0]     contention_count_o;
  logic            contention_error_o;

  // The component side of the pin model: a register pair the bench writes, plus
  // the pin-input register and change flag of a component that samples its pins.
  logic [PINS-1:0] stub_dir_q = {PINS{1'b0}};
  logic [PINS-1:0] stub_out_q = {PINS{1'b0}};
  logic [PINS-1:0] stub_in_q = {PINS{1'b0}};
  logic            stub_change_q = 1'b0;

  assign component_out_i = stub_out_q;
  assign component_dir_i = stub_dir_q;

  soc_gpio_peer #(
      .PINS(PINS),
      .DEFAULT_INPUT_LEVEL(DEFAULT_INPUT_LEVEL),
      .CONTENTION_IS_ERROR(CONTENTION_IS_ERROR)
  ) dut (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .peer_drive_valid_i(peer_drive_valid_i),
      .peer_drive_value_i(peer_drive_value_i),
      .component_out_i(component_out_i),
      .component_dir_i(component_dir_i),
      .pin_o(pin_o),
      .pin_value_o(pin_value_o),
      .direction_o(direction_o),
      .contention_o(contention_o),
      .contention_count_o(contention_count_o),
      .contention_error_o(contention_error_o)
  );

  always #5 clk_i = ~clk_i;

  always @(posedge clk_i) begin
    if (rst_ni) begin
      stub_in_q <= pin_o;
      if (pin_o !== stub_in_q)
        stub_change_q <= 1'b1;
    end else begin
      stub_in_q <= ALL_ZERO;
      stub_change_q <= 1'b0;
    end
  end

  task automatic tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  task automatic fail(input [8*240-1:0] message);
    begin
      $display("RESULT: FAIL: %0s", message);
      $fatal(1, "soc_gpio_peer self-check failed");
    end
  endtask

  task automatic check(input bit condition, input [8*240-1:0] message);
    begin
      if (!condition)
        fail(message);
    end
  endtask

  task automatic check32(input [31:0] actual, input [31:0] expected, input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%0d expected=%0d", actual, expected);
        fail(message);
      end
    end
  endtask

  task automatic check_vec(input [PINS-1:0] actual, input [PINS-1:0] expected,
                           input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: actual=%b expected=%b", actual, expected);
        fail(message);
      end
    end
  endtask

  function automatic [PINS-1:0] pattern_a;
    integer k;
    begin
      pattern_a = ALL_ZERO;
      for (k = 0; k < PINS; k = k + 1)
        pattern_a[k] = ((k % 2) == 0);
    end
  endfunction

  function automatic [PINS-1:0] pattern_b;
    integer k;
    begin
      pattern_b = ALL_ZERO;
      for (k = 0; k < PINS; k = k + 1)
        pattern_b[k] = ((k % 2) == 1);
    end
  endfunction

  function automatic integer count_ones(input [PINS-1:0] value);
    integer k;
    begin
      count_ones = 0;
      for (k = 0; k < PINS; k = k + 1)
        if (value[k])
          count_ones = count_ones + 1;
    end
  endfunction

  task automatic set_peer(input [PINS-1:0] drive_valid, input [PINS-1:0] drive_value);
    begin
      peer_drive_valid_i = drive_valid;
      peer_drive_value_i = drive_value;
    end
  endtask

  task automatic set_component(input [PINS-1:0] dir, input [PINS-1:0] value);
    begin
      stub_dir_q = dir;
      stub_out_q = value;
    end
  endtask

  integer count_before;
  integer k;
  logic [PINS-1:0] value;

  initial begin
    $display({"NOTE: soc_gpio_peer_tb PINS=%0d DEFAULT_INPUT_LEVEL=%0d CONTENTION_IS_ERROR=%0d ",
              "NEGATIVE_CONTROL=%0d"},
             PINS, DEFAULT_INPUT_LEVEL, CONTENTION_IS_ERROR, NEGATIVE_CONTROL);
    $display("NOTE: suite=gpio");
    rst_ni = 1'b0;
    set_peer(ALL_ZERO, ALL_ZERO);
    set_component(ALL_ZERO, ALL_ZERO);
    #1;
    check_vec(pin_o, DEFAULT_VECTOR, "S0 an undriven pin carries the default input level");
    tick();   // the synchronous reset is applied on this edge
    check_vec(pin_value_o, ALL_ZERO, "S0 reset clears the observed pin vector");
    check_vec(direction_o, ALL_ZERO, "S0 reset clears the observed direction vector");
    check_vec(contention_o, ALL_ZERO, "S0 reset clears the contention flags");
    check32(contention_count_o, 0, "S0 reset clears the contention counter");
    check(!contention_error_o, "S0 reset clears the contention error flag");
    check_vec(pin_o, DEFAULT_VECTOR, "S0 an undriven pin keeps the default input level under reset");
    tick();
    check_vec(pin_value_o, ALL_ZERO, "S0 the reset keeps the observations clear");
    @(negedge clk_i);
    rst_ni = 1'b1;
    tick();
    check_vec(pin_value_o, DEFAULT_VECTOR,
              "S0 the observed pin vector follows the default level after reset");

    // S1 nobody drives: the default input level.
    set_peer(ALL_ZERO, ALL_ZERO);
    set_component(ALL_ZERO, ALL_ZERO);
    #1;
    check_vec(pin_o, DEFAULT_VECTOR, "S1 two high-impedance sides leave the default input level");
    tick();
    check_vec(pin_value_o, DEFAULT_VECTOR, "S1 the default level is observed");
    check_vec(contention_o, ALL_ZERO, "S1 an undriven pin is not contended");
    count_before = contention_count_o;

    // S2 the peer drives, the component is high impedance: the component reads
    // the peer's value, in the same cycle and through its pin-input register.
    @(negedge clk_i);
    value = pattern_a();
    set_peer(ALL_ONES, value);
    set_component(ALL_ZERO, ALL_ZERO);
    stub_change_q = 1'b0;
    #1;
    check_vec(pin_o, value, "S2 a pin driven by one side only carries that side's value");
    tick();
    check_vec(pin_value_o, value, "S2 the observed pin vector follows the peer drive");
    check_vec(direction_o, ALL_ZERO, "S2 the observed direction vector follows the component");
    check_vec(stub_in_q, value, "S2 the component pin input samples the peer drive");
    check(stub_change_q, "S2 the component sees the peer drive as a pin change");
    check_vec(contention_o, ALL_ZERO, "S2 one side driving is not a contention");
    check32(contention_count_o, count_before, "S2 one side driving counts no contention");

    // S3 the component drives, the peer is high impedance: the pin reads back
    // the component's own value.
    @(negedge clk_i);
    value = pattern_b();
    set_peer(ALL_ZERO, ALL_ZERO);
    set_component(ALL_ONES, value);
    #1;
    check_vec(pin_o, value, "S3 a pin driven by the component alone reads back its value");
    tick();
    check_vec(pin_value_o, value, "S3 the observed pin vector follows the component drive");
    check_vec(direction_o, ALL_ONES, "S3 the direction vector follows the component direction");
    check_vec(stub_in_q, value, "S3 the component samples its own drive");
    check_vec(contention_o, ALL_ZERO, "S3 a component drive alone is not a contention");
    check32(contention_count_o, count_before, "S3 a component drive alone counts no contention");

    // S4 direction change: one side at a time, then both sides driving the same
    // value, which is agreement and not a contention.
    @(negedge clk_i);
    value = pattern_a();
    set_peer(ALL_ONES, value);
    set_component(ALL_ZERO, value);
    #1;
    check_vec(pin_o, value,
              "S4 the pin returns to the peer drive when the component goes high impedance");
    tick();
    check_vec(direction_o, ALL_ZERO, "S4 the direction change is observed");
    @(negedge clk_i);
    set_component(ALL_ONES, value);   // the component now drives the same value
    #1;
    check_vec(pin_o, value, "S4 the pin keeps its value when the component drives the same value");
    tick();
    check_vec(direction_o, ALL_ONES, "S4 the direction change back is observed");
    check_vec(contention_o, NOT_CONTENDING,
              "S4 both sides driving the same value is not a contention");
    check32(contention_count_o, count_before, "S4 agreement counts no contention event");

    // S5 both sides drive opposite values: exactly the contending pins are
    // flagged, the resolved level is the documented one, and the counter moves
    // once per event and not once per cycle.
    @(negedge clk_i);
    set_peer(ALL_ONES, ALL_ONES);
    set_component(ALL_ONES, ALL_ZERO);
    #1;
    check_vec(pin_o, CONTENTION_VECTOR, "S5 a contended pin resolves to the documented level");
    check_vec(contention_o, ALL_ZERO, "S5 the contention flag is registered, not combinational");
    count_before = contention_count_o;
    tick();
    check_vec(contention_o, ALL_ONES, "S5 both sides driving opposite values flags every contending pin");
    check_vec(pin_value_o, CONTENTION_VECTOR, "S5 the observed pin vector carries the resolved level");
    check32(contention_count_o, count_before + PINS,
            "S5 every pin that enters contention counts once per event");
    if (CONTENTION_IS_ERROR != 0)
      check(contention_error_o, "S5 a contention raises the error flag when CONTENTION_IS_ERROR is set");
    else
      check(!contention_error_o, "S5 a contention leaves the error flag clear when CONTENTION_IS_ERROR is not set");
    for (k = 0; k < 8; k = k + 1) begin
      tick();
      check_vec(contention_o, ALL_ONES, "S5 the contention flag stays set while both sides keep driving");
      check32(contention_count_o, count_before + PINS,
              "S5 a contention held for many cycles counts once per pin, not once per cycle");
    end
    @(negedge clk_i);
    set_component(ALL_ONES, ALL_ONES);   // agreement again
    tick();
    check_vec(contention_o, ALL_ZERO, "S5 driving the same value again clears the flags");
    check_vec(pin_o, ALL_ONES, "S5 agreement resolves to the agreed value");
    check32(contention_count_o, count_before + PINS, "S5 leaving a contention counts nothing");
    if (CONTENTION_IS_ERROR != 0)
      check(contention_error_o, "S5 the contention error flag is sticky after the contention ends");
    else
      check(!contention_error_o, "S5 the contention error flag stays clear when contention is not an error");
    @(negedge clk_i);
    set_component(ALL_ONES, ALL_ZERO);
    tick();
    check32(contention_count_o, count_before + (2 * PINS),
            "S5 a second contention event counts every pin again");

    // S6 only some pins contend: the flags mark exactly those pins, and a steady
    // partial contention adds no further event.
    if (PINS >= 2) begin
      @(negedge clk_i);
      set_component(ALL_ONES, ALL_ONES);
      tick();
      check_vec(contention_o, ALL_ZERO, "S6 agreement clears every contention flag");
      count_before = contention_count_o;
      @(negedge clk_i);
      set_component(ALL_ONES, pattern_a());   // the peer drives every pin high
      tick();
      check_vec(contention_o, pattern_b(), "S6 only the pins both sides drive differently are flagged");
      check32(contention_count_o, count_before + count_ones(pattern_b()),
              "S6 every pin that enters contention is counted once");
      count_before = contention_count_o;
      for (k = 0; k < 4; k = k + 1) begin
        tick();
        check_vec(contention_o, pattern_b(), "S6 the partial contention flags stay set");
        check32(contention_count_o, count_before,
                "S6 a steady partial contention counts no further event");
      end
    end

    // A last reset must clear the peer.
    @(negedge clk_i);
    rst_ni = 1'b0;
    set_peer(ALL_ZERO, ALL_ZERO);
    set_component(ALL_ZERO, ALL_ZERO);
    #1;
    check_vec(pin_o, DEFAULT_VECTOR, "final: an undriven pin carries the default input level");
    tick();   // the synchronous reset is applied on this edge
    check_vec(pin_value_o, ALL_ZERO, "final: reset clears the observed pin vector");
    check_vec(contention_o, ALL_ZERO, "final: reset clears the contention flags");
    check32(contention_count_o, 0, "final: reset clears the contention counter");
    check(!contention_error_o, "final: reset clears the contention error flag");
    tick();
    check_vec(pin_value_o, ALL_ZERO, "final: the observations stay clear under reset");
    $display("NOTE: contention events=%0d default level=%0d", contention_count_o, DEFAULT_LEVEL);
    $display("RESULT: PASS");
    $finish;
  end
endmodule
