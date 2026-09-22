// Self-checking behavioural bench for soc_irq_edge_detect.
//
// One parameterization per run (iverilog -P overrides), one RESULT line.  The
// bench drives raw_i on the falling edge and samples irq_o just after the next
// rising edge, so every observation is a value the DUT's own flops hold for a
// whole cycle and no check depends on delta-cycle ordering.
//
// Every scenario resets the DUT with raw_i already at RESET_LEVEL, so the
// release itself is never an edge.  The transition under test is then driven
// explicitly, which is what makes each check independent of the polarity the
// parameterization happens to use.
`timescale 1ns/1ps

module soc_irq_edge_detect_tb;
  parameter integer EDGE = 0;
  parameter integer PULSE_CYCLES = 1;
  parameter integer RESET_LEVEL = 0;

  reg  clk_i = 1'b0;
  reg  rst_ni = 1'b0;
  reg  raw_i;
  wire irq_o;

  integer failures = 0;
  integer pulse_count = 0;
  integer pulse_width = 0;
  integer last_width = 0;
  integer index;
  integer expected_events = 0;
  reg     prev_irq = 1'b0;

  // 1 = rising, 0 = falling: the direction the current scenario just drove.
  reg     drove_high;

  soc_irq_edge_detect #(
      .EDGE(EDGE), .PULSE_CYCLES(PULSE_CYCLES), .RESET_LEVEL(RESET_LEVEL)
  ) dut (
      .clk_i(clk_i), .rst_ni(rst_ni), .raw_i(raw_i), .irq_o(irq_o)
  );

  always #5 clk_i = ~clk_i;

  task check(input condition, input [1023:0] label);
    begin
      if (!condition) begin
        failures = failures + 1;
        $display("CHECK-FAIL: %0s (raw=%b irq=%b pulses=%0d width=%0d)",
                 label, raw_i, irq_o, pulse_count, pulse_width);
      end
    end
  endtask

  // One cycle, and the pulse bookkeeping that goes with it.
  task step;
    begin
      @(posedge clk_i);
      #1;
      if (irq_o && !prev_irq) begin
        pulse_count = pulse_count + 1;
        pulse_width = 0;
      end
      if (irq_o)
        pulse_width = pulse_width + 1;
      if (prev_irq && !irq_o && last_width == 0)
        last_width = pulse_width;
      prev_irq = irq_o;
    end
  endtask

  task settle(input integer cycles);
    integer i;
    begin
      for (i = 0; i < cycles; i = i + 1)
        step();
    end
  endtask

  task reset_counters;
    begin
      pulse_count = 0;
      pulse_width = 0;
      last_width = 0;
      prev_irq = 1'b0;
      expected_events = 0;
    end
  endtask

  // Reset with raw_i already at the declared reference level, so releasing
  // reset is not itself an edge.
  task reset_at_reference;
    begin
      rst_ni = 1'b0;
      raw_i = (RESET_LEVEL != 0);
      step();
      step();
      check(!irq_o, "irq_o is low for the whole reset window");
      reset_counters();
      rst_ni = 1'b1;
      step();
    end
  endtask

  // Does this parameterization fire on the transition that was just driven?
  function fires_on_driven_edge;
    begin
      if (drove_high)
        fires_on_driven_edge = (EDGE == 0) || (EDGE == 2);
      else
        fires_on_driven_edge = (EDGE == 1) || (EDGE == 2);
    end
  endfunction

  task drive_transition(input to_level);
    begin
      drove_high = to_level;
      raw_i = to_level;
      step();
    end
  endtask

  initial begin
    raw_i = (RESET_LEVEL != 0);
    reset_counters();

    // --- S1: releasing reset at the reference level is not an edge ----------
    reset_at_reference();
    settle(32);
    check(pulse_count == 0, "S1 releasing reset at the reference level emits nothing");
    check(pulse_width == 0, "S1 no pulse was measured");

    // --- S2: the first explicit transition ---------------------------------
    reset_at_reference();
    settle(4);
    drive_transition(~RESET_LEVEL);
    if (fires_on_driven_edge())
      expected_events = expected_events + 1;
    settle(64);
    check(pulse_count == expected_events, "S2 only the declared edge direction fires");
    if (expected_events == 1)
      check(last_width == PULSE_CYCLES, "S2 the emitted pulse is PULSE_CYCLES wide");
    check(!irq_o, "S2 the output is idle once the pulse has finished");

    // --- S3: the level is now held; nothing repeats -------------------------
    settle(64);
    check(pulse_count == expected_events, "S3 holding a level never repeats the event");

    // --- S4: the return transition -----------------------------------------
    drive_transition(RESET_LEVEL);
    if (fires_on_driven_edge())
      expected_events = expected_events + 1;
    settle(64);
    check(pulse_count == expected_events, "S4 the opposite edge is counted only where declared");

    // --- S5: both-edges mode counts every transition -----------------------
    if (EDGE == 2) begin
      reset_at_reference();
      settle(4);
      drive_transition(~RESET_LEVEL);
      expected_events = expected_events + 1;
      settle(8);
      drive_transition(RESET_LEVEL);
      expected_events = expected_events + 1;
      settle(8);
      drive_transition(~RESET_LEVEL);
      expected_events = expected_events + 1;
      settle(64);
      check(pulse_count == 3, "S5 both-edges mode reports three transitions as three events");
      check(last_width == PULSE_CYCLES, "S5 every pulse is PULSE_CYCLES wide");
    end

    // --- S6: an edge inside a pulse merges into one longer assertion -------
    // Two events closer together than PULSE_CYCLES cannot be told apart at the
    // output, and they do not need to be: the controller keeps one pending bit
    // per source, so the honest contract is "one continuous assertion", not
    // "two pulses".  The check fixes both halves of that contract.
    if (PULSE_CYCLES > 1 && EDGE == 2) begin
      reset_at_reference();
      settle(4);
      drive_transition(~RESET_LEVEL);
      check(irq_o, "S6 the first pulse is in flight");
      drive_transition(RESET_LEVEL);
      check(pulse_count == 1, "S6 a second edge inside the pulse does not start a new pulse");
      check(irq_o, "S6 the assertion is still high after the second edge");
      settle(64);
      check(!irq_o, "S6 the merged pulse ends");
      check(last_width == PULSE_CYCLES + 1,
            "S6 the second edge extends the assertion by exactly one cycle");
    end

    // --- S7: reset discards a pulse in flight ------------------------------
    reset_at_reference();
    settle(4);
    drive_transition(~RESET_LEVEL);
    if (fires_on_driven_edge())
      check(irq_o, "S7 a pulse is in flight before reset is asserted");
    rst_ni = 1'b0;
    step();
    check(!irq_o, "S7 asserting reset discards the pulse immediately");
    settle(8);
    check(!irq_o, "S7 the output stays low while reset is held");

    if (failures == 0)
      $display("RESULT: PASS");
    else
      $display("RESULT: FAIL failures=%0d", failures);
    $finish;
  end

  // The bench must terminate: a hang is a failure, not a silent timeout.
  initial begin
    #400000;
    $display("RESULT: FAIL bench-timeout");
    $finish;
  end
endmodule
