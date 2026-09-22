// Self-checking behavioural testbench for soc_special_input_driver (Icarus).
//
//   iverilog -g2012 -s soc_special_input_driver_tb -o tb.vvp \
//       src/myfuzz/protocols/rtl/soc_special_input_driver.sv \
//       tests/fixtures/rtl/soc_special_input_driver_tb.sv
//   vvp tb.vvp
//
// The bench prints exactly one result line, "RESULT: PASS" or
// "RESULT: FAIL: <reason>", and finishes with $finish; a failure prints the
// FAIL line and then aborts through $fatal, so vvp exits non-zero.
//
// The parameterization is frozen by -P overrides and selects both the DUT
// configuration and the scenario suite that runs:
//
//   -P soc_special_input_driver_tb.WIDTH=8 -P soc_special_input_driver_tb.STRATEGY=2 \
//   -P soc_special_input_driver_tb.PULSE_CYCLES=5 -P soc_special_input_driver_tb.PULSE_MIN_GAP=3
//
// Scenario 0 (reset clears the registered output) runs for every strategy. The
// strategy suites then cover:
//
//   S1 cycle_value     offered cycles are applied, unoffered cycles hold, and a
//                      reset in the middle of an offer clears the output.
//   S2 reset_sampled   raw_i is tracked continuously while reset is asserted,
//                      the release edge latches the last sampled value, and that
//                      value then survives a walk over every other raw value; a
//                      second reset re-opens the sampling window.
//   S3/S4/S5 pulse     a request needs a rising edge of raw_i[0] that update_i
//                      offers; the pulse is exactly PULSE_CYCLES cycles wide
//                      with the latched payload; requests during a pulse and
//                      inside PULSE_MIN_GAP idle cycles are dropped, never
//                      queued and never extending a pulse; a request exactly at
//                      the gap boundary is accepted; a reset aborts a pulse.
//   S6 hold_ready      the value only moves while update_i and hold_ready_i are
//                      both offered and is bit-for-bit stable otherwise.
//   S7 hold_free       hold_ready_i is ignored and every offered update applies.
//
// NEGATIVE_CONTROL is a compile-time self-test hook: it corrupts exactly one
// expectation (the idle release in scenario 0) so the Python harness can prove
// that the bench really fails when an expectation is wrong. It is 0 in every
// real run.
module soc_special_input_driver_tb #(
    parameter integer WIDTH = 1,
    parameter integer STRATEGY = 0,
    parameter integer PULSE_CYCLES = 1,
    parameter integer PULSE_MIN_GAP = 0,
    parameter integer HOLD_ON_READY = 0,
    parameter integer NEGATIVE_CONTROL = 0
) ();
  localparam [WIDTH-1:0] ZERO = {WIDTH{1'b0}};
  localparam [WIDTH-1:0] MASK = {WIDTH{1'b1}};

  logic             clk_i = 1'b0;
  logic             rst_ni = 1'b0;
  logic [WIDTH-1:0] raw_i = ZERO;
  logic             update_i = 1'b0;
  logic             hold_ready_i = 1'b0;
  logic [WIDTH-1:0] value_o;
  logic             applied_o;

  soc_special_input_driver #(
      .WIDTH(WIDTH),
      .STRATEGY(STRATEGY),
      .PULSE_CYCLES(PULSE_CYCLES),
      .PULSE_MIN_GAP(PULSE_MIN_GAP),
      .HOLD_ON_READY(HOLD_ON_READY)
  ) dut (
      .clk_i(clk_i),
      .rst_ni(rst_ni),
      .raw_i(raw_i),
      .update_i(update_i),
      .hold_ready_i(hold_ready_i),
      .value_o(value_o),
      .applied_o(applied_o)
  );

  always #5 clk_i = ~clk_i;

  // ---------------------------------------------------------------------------
  // Stimulus values
  // ---------------------------------------------------------------------------
  // Payload of a pulse request: bit 0 is the request line, the upper bits are a
  // seed-dependent pattern, so two different seeds differ whenever WIDTH > 1.
  function automatic [WIDTH-1:0] trigger_value(input integer seed);
    integer k;
    begin
      trigger_value = {WIDTH{1'b0}};
      trigger_value[0] = 1'b1;
      for (k = 1; k < WIDTH; k = k + 1)
        if (((k + seed) % 2) == 1)
          trigger_value[k] = 1'b1;
    end
  endfunction

  // The same payload with the request line lowered.
  function automatic [WIDTH-1:0] quiet_value(input [WIDTH-1:0] value);
    begin
      quiet_value = value;
      quiet_value[0] = 1'b0;
    end
  endfunction

  // A deterministic walk over the raw values: consecutive indexes differ.
  function automatic [WIDTH-1:0] walk_value(input integer index);
    begin
      walk_value = (index + 1) & MASK;
    end
  endfunction

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  task automatic tick;
    begin
      @(posedge clk_i);
      #1;
    end
  endtask

  task automatic fail(input [8*240-1:0] message);
    begin
      $display("RESULT: FAIL: %0s", message);
      $fatal(1, "soc_special_input_driver self-check failed");
    end
  endtask

  task automatic check(input bit condition, input [8*240-1:0] message);
    begin
      if (!condition)
        fail(message);
    end
  endtask

  // Bit-for-bit comparison, so an unknown bit is a failure as well.
  task automatic check_equal(input [WIDTH-1:0] actual, input [WIDTH-1:0] expected,
                             input [8*240-1:0] message);
    begin
      if (actual !== expected) begin
        $display("NOTE: value_o=%b expected=%b", actual, expected);
        fail(message);
      end
    end
  endtask

  // Present a stimulus on the falling edge and stop in the middle of the cycle,
  // which is where a combinational path from raw_i to value_o would already show.
  task automatic present(input [WIDTH-1:0] raw, input bit update, input bit ready);
    begin
      @(negedge clk_i);
      raw_i = raw;
      update_i = update;
      hold_ready_i = ready;
      #1;
    end
  endtask

  // Present a stimulus on the falling edge, then let the DUT register it.
  task automatic step(input [WIDTH-1:0] raw, input bit update, input bit ready);
    begin
      present(raw, update, ready);
      tick();
    end
  endtask

  // Idle cycles with the request line low: nothing may be applied.
  task automatic gap_wait(input integer cycles);
    integer i;
    begin
      for (i = 0; i < cycles; i = i + 1) begin
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, ZERO, "S4 an idle cycle keeps value_o at 0");
        check(!applied_o, "S4 an idle cycle applies nothing");
      end
    end
  endtask

  // One complete pulse: the request line is low on entry, the pulse must be
  // exactly PULSE_CYCLES cycles wide and must carry its own latched payload, and
  // the driver is idle again on exit.
  task automatic run_pulse(input [WIDTH-1:0] payload, input [8*240-1:0] message);
    integer i;
    begin
      step(payload, 1'b1, 1'b0);
      check_equal(value_o, payload, message);
      check(applied_o, message);
      for (i = 2; i <= PULSE_CYCLES; i = i + 1) begin
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, payload, message);
        check(applied_o, message);
      end
      step(ZERO, 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S4 a pulse lasts exactly PULSE_CYCLES cycles");
      check(!applied_o, "S4 applied_o is 0 in the cycle after a pulse");
      step(ZERO, 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S4 no second pulse starts without a new request");
      check(!applied_o, "S4 an idle cycle after a pulse applies nothing");
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenario 0: reset for every strategy
  // ---------------------------------------------------------------------------
  task automatic common_reset_suite;
    integer i;
    begin
      check_equal(value_o, ZERO, "S0 reset clears value_o");
      check(!applied_o, "S0 reset clears applied_o");
      for (i = 0; i < 2; i = i + 1) begin
        tick();
        check_equal(value_o, ZERO, "S0 reset keeps value_o clear");
        check(!applied_o, "S0 reset keeps applied_o clear");
      end

      // Release with an idle stimulus: the driver may not invent an update.
      @(negedge clk_i);
      rst_ni = 1'b1;
      raw_i = ZERO;
      update_i = 1'b0;
      hold_ready_i = 1'b0;
      tick();
      check_equal(value_o, ZERO + NEGATIVE_CONTROL, "S0 an idle release leaves value_o clear");
      if (STRATEGY == 1)
        check(applied_o, "S0 the reset_sampled release cycle is applied");
      else
        check(!applied_o, "S0 an idle release applies nothing");
      for (i = 0; i < 2; i = i + 1) begin
        step(walk_value(2), 1'b0, 1'b0);
        check_equal(value_o, ZERO, "S0 nothing is applied without an offer");
        check(!applied_o, "S0 applied_o stays low without an offer");
      end

      // A reset in the middle of an active offer clears the driver. The
      // reset_sampled strategy is driven by its own suite instead, because its
      // sampling window deliberately follows raw_i while reset is asserted.
      if (STRATEGY != 1) begin
        @(negedge clk_i);
        rst_ni = 1'b0;
        raw_i = walk_value(3);
        update_i = 1'b1;
        hold_ready_i = 1'b1;
        #1;
        check_equal(value_o, ZERO, "S0 a reset in the middle of an offer clears value_o at once");
        check(!applied_o, "S0 a reset in the middle of an offer clears applied_o at once");
        tick();
        check_equal(value_o, ZERO, "S0 no value survives the reset edge");
        check(!applied_o, "S0 no apply survives the reset edge");
        for (i = 0; i < 2; i = i + 1) begin
          tick();
          check_equal(value_o, ZERO, "S0 value_o stays clear while reset is asserted");
          check(!applied_o, "S0 applied_o stays clear while reset is asserted");
        end
        @(negedge clk_i);
        rst_ni = 1'b1;
        raw_i = ZERO;
        update_i = 1'b0;
        hold_ready_i = 1'b0;
        tick();
        check_equal(value_o, ZERO, "S0 the driver is clear after the second release");
        check(!applied_o, "S0 the second release applies nothing");
        for (i = 0; i < 2; i = i + 1) begin
          step(walk_value(4), 1'b0, 1'b0);
          check_equal(value_o, ZERO, "S0 the driver stays clear until an offer arrives");
          check(!applied_o, "S0 applied_o stays low until an offer arrives");
        end
      end
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenario 1: STRATEGY 0 cycle_value
  // ---------------------------------------------------------------------------
  task automatic suite_cycle_value;
    integer i;
    logic [WIDTH-1:0] a;
    logic [WIDTH-1:0] b;
    begin
      a = trigger_value(0);
      b = trigger_value(1);

      step(a, 1'b1, 1'b0);
      check_equal(value_o, a, "S1 cycle_value applies raw_i in an offered cycle");
      check(applied_o, "S1 cycle_value marks the offered cycle as applied");
      step(b, 1'b1, 1'b0);
      check_equal(value_o, b, "S1 cycle_value follows raw_i on the next offer");
      check(applied_o, "S1 cycle_value marks the second offer as applied");

      // No combinational feed-through: raw_i moves in the middle of a cycle in
      // which no update is offered and value_o must not move with it.
      present(walk_value(6), 1'b0, 1'b0);
      check_equal(value_o, b, "S1 cycle_value does not let raw_i reach value_o without a register");
      tick();
      check_equal(value_o, b, "S1 cycle_value holds the previous value without an offer");
      check(!applied_o, "S1 cycle_value applies nothing without an offer");

      // Hold while raw_i walks over every value, with every handshake line in
      // every combination: only update_i may move the output.
      for (i = 0; i < 4 * (1 << WIDTH); i = i + 1) begin
        step(walk_value(i), 1'b0, 1'b1);
        check_equal(value_o, b, "S1 cycle_value holds while update_i is low");
        check(!applied_o, "S1 cycle_value does not apply while update_i is low");
      end

      step(a, 1'b1, 1'b0);
      check_equal(value_o, a, "S1 cycle_value applies a new offer after the hold");
      check(applied_o, "S1 cycle_value marks the new offer as applied");
      step(a, 1'b1, 1'b1);
      check_equal(value_o, a, "S1 cycle_value keeps an identical re-offer");
      check(applied_o, "S1 cycle_value marks an identical re-offer as applied");
      step(ZERO, 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S1 cycle_value applies an all-zero offer");
      check(applied_o, "S1 cycle_value marks the all-zero offer as applied");
      step(walk_value(5), 1'b0, 1'b0);
      check_equal(value_o, ZERO, "S1 cycle_value holds the all-zero value");
      check(!applied_o, "S1 cycle_value does not re-apply a held value");
      step(ZERO, 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S1 cycle_value keeps applying zero when it is offered");
      check(applied_o, "S1 cycle_value marks the repeated all-zero offer as applied");
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenario 2: STRATEGY 1 reset_sampled
  // ---------------------------------------------------------------------------
  task automatic suite_reset_sampled;
    integer i;
    logic [WIDTH-1:0] picked;
    logic [WIDTH-1:0] other;
    logic [WIDTH-1:0] second;
    begin
      picked = walk_value(2);
      other = walk_value(5);
      second = walk_value(6);

      // The sampling window: value_o follows raw_i continuously, with no apply.
      @(negedge clk_i);
      rst_ni = 1'b0;
      raw_i = ZERO;
      update_i = 1'b0;
      hold_ready_i = 1'b0;
      #1;
      check_equal(value_o, ZERO, "S2 reset_sampled tracks raw_i while reset is asserted");
      check(!applied_o, "S2 nothing is applied during the sampling window");
      for (i = 0; i < (1 << WIDTH); i = i + 1) begin
        raw_i = walk_value(i);
        #1;
        check_equal(value_o, walk_value(i), "S2 reset_sampled tracks every raw_i value in the window");
        check(!applied_o, "S2 the sampling window never applies a value");
      end

      // Leave a configuration on the port and release reset: it is latched.
      raw_i = picked;
      #1;
      check_equal(value_o, picked, "S2 the configuration picked in the window is on value_o");
      @(negedge clk_i);
      rst_ni = 1'b1;
      raw_i = picked;
      update_i = 1'b0;
      hold_ready_i = 1'b0;
      tick();
      check_equal(value_o, picked, "S2 the reset release latches the last sampled value");
      check(applied_o, "S2 applied_o is 1 in the release cycle");
      step(other, 1'b1, 1'b1);
      check_equal(value_o, picked, "S2 the sampled value is frozen after the release cycle");
      check(!applied_o, "S2 applied_o is 0 outside the release cycle");

      // The value must survive a long walk over every other raw value, with
      // update_i offered on every cycle.
      for (i = 0; i < 8 * (1 << WIDTH); i = i + 1) begin
        step(walk_value(i), 1'b1, 1'b1);
        check_equal(value_o, picked, "S2 the sampled value ignores raw_i and update_i completely");
        check(!applied_o, "S2 nothing is applied after the sampling window closed");
      end

      // A second reset re-opens the sampling window and a second release picks a
      // new value.
      @(negedge clk_i);
      rst_ni = 1'b0;
      raw_i = other;
      update_i = 1'b1;
      hold_ready_i = 1'b1;
      #1;
      check_equal(value_o, other, "S2 a second reset re-opens the sampling window");
      check(!applied_o, "S2 the re-opened window applies nothing");
      tick();
      check_equal(value_o, other, "S2 the re-opened window keeps tracking raw_i");
      check(!applied_o, "S2 the re-opened window applies nothing at its edges");
      @(negedge clk_i);
      raw_i = second;
      #1;
      check_equal(value_o, second, "S2 the re-opened window picks the new configuration");
      rst_ni = 1'b1;
      tick();
      check_equal(value_o, second, "S2 the second release latches the new sampled value");
      check(applied_o, "S2 the second release is the second applied cycle");
      step(walk_value(3), 1'b1, 1'b0);
      check_equal(value_o, second, "S2 the second sampled value is frozen too");
      check(!applied_o, "S2 the second release applies exactly once");
      for (i = 0; i < 4; i = i + 1) begin
        step(walk_value(4), 1'b1, 1'b0);
        check_equal(value_o, second, "S2 the second sampled value stays frozen");
        check(!applied_o, "S2 applied_o stays 0 after the release cycle");
      end
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenarios 3..5: STRATEGY 2 pulse
  // ---------------------------------------------------------------------------
  task automatic suite_pulse;
    integer i;
    integer idle_index;
    logic [WIDTH-1:0] p1;
    logic [WIDTH-1:0] p2;
    begin
      p1 = trigger_value(0);
      p2 = trigger_value(1);

      // (a) a request is a rising edge of raw_i[0] that update_i offers now.
      step(p1, 1'b0, 1'b0);
      check_equal(value_o, ZERO, "S3 pulse ignores a request that is not offered");
      check(!applied_o, "S3 an unoffered request applies nothing");
      step(p1, 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S3 pulse needs a rising edge, not a level");
      check(!applied_o, "S3 a request level that is already high applies nothing");
      step(quiet_value(p1), 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S3 pulse does not trigger on a falling edge");
      check(!applied_o, "S3 a falling edge applies nothing");

      // (b) a rising edge starts exactly one pulse with a latched payload.
      step(p1, 1'b1, 1'b0);
      check_equal(value_o, p1, "S3 the pulse latches raw_i as its payload");
      check(applied_o, "S3 applied_o is 1 in the first pulse cycle");
      if (PULSE_CYCLES == 1) begin
        // A one-cycle pulse leaves no room to lower the request line inside the
        // pulse, so it is lowered in the middle of that single cycle: the driver
        // must hold its payload and the line is low when the pulse ends.
        present(ZERO, 1'b1, 1'b0);
        check_equal(value_o, p1, "S3 the payload is held even when raw_i moves inside the pulse");
        check(applied_o, "S3 the single pulse cycle is applied");
        tick();
      end else begin
        for (i = 2; i <= PULSE_CYCLES; i = i + 1) begin
          if (i == 2) begin
            // The request line drops in the middle of the pulse.
            step(quiet_value(p2), 1'b1, 1'b0);
          end else if (i == 3) begin
            // A fresh rising edge in the middle of the pulse: it must be ignored,
            // and raw_i must not reach value_o before the next edge either.
            present(p2, 1'b1, 1'b0);
            check_equal(value_o, p1, "S3 raw_i never reaches value_o without a register");
            check(applied_o, "S3 the pulse is still applied in the middle of its payload");
            tick();
          end else begin
            step(ZERO, 1'b1, 1'b0);
          end
          check_equal(value_o, p1, "S3 an active pulse holds its payload in every cycle");
          check(applied_o, "S3 applied_o is 1 in every pulse cycle");
        end
      end

      // (c) and (d). The last pulse cycle left the request line low, so idle
      // cycle 1 can already carry a genuine rising edge.
      if (PULSE_MIN_GAP == 0) begin
        // No gap is enforced: the request in the first idle cycle applies. This
        // also proves that the first pulse was exactly PULSE_CYCLES cycles long,
        // because the pulse that starts here would otherwise be an extension.
        step(p1, 1'b1, 1'b0);
        check_equal(value_o, p1, "S3 PULSE_MIN_GAP=0 accepts a request in the first idle cycle");
        check(applied_o, "S3 the unenforced retrigger applies");
        for (i = 2; i <= PULSE_CYCLES; i = i + 1) begin
          step(ZERO, 1'b1, 1'b0);
          check_equal(value_o, p1, "S4 the unenforced retrigger holds its payload");
          check(applied_o, "S4 the unenforced retrigger has the exact pulse width");
        end
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, ZERO, "S4 the unenforced retrigger ends after PULSE_CYCLES cycles");
        check(!applied_o, "S4 applied_o drops after the unenforced retrigger");
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, ZERO, "S3 a request that arrived during a pulse is not queued");
        check(!applied_o, "S3 a request that arrived during a pulse never applies later");
      end else begin
        // Idle cycle 1: the pulse is over and the request is dropped, which also
        // makes the pulse length exact (no extension, no restart).
        step(quiet_value(p2), 1'b1, 1'b0);
        check_equal(value_o, ZERO, "S3 the pulse is exactly PULSE_CYCLES cycles long");
        check(!applied_o, "S3 applied_o is 0 in the cycle after the pulse");
        // Idle cycles 2..PULSE_MIN_GAP: a genuine rising edge is offered whenever
        // the line was low, and every one of them must be dropped. The last idle
        // cycle keeps the line low so that the boundary request is a real edge.
        for (idle_index = 2; idle_index <= PULSE_MIN_GAP; idle_index = idle_index + 1) begin
          if ((idle_index < PULSE_MIN_GAP) && (((PULSE_MIN_GAP - idle_index) % 2) == 1))
            step(p2, 1'b1, 1'b0);
          else
            step(quiet_value(p2), 1'b1, 1'b0);
          check_equal(value_o, ZERO, "S4 no pulse starts before PULSE_MIN_GAP idle cycles elapse");
          check(!applied_o, "S4 the minimum gap suppresses applied_o");
        end
        // Exactly PULSE_MIN_GAP idle cycles have elapsed and the request line has
        // been low for a full cycle, so this rising edge is right at the
        // boundary. It must be accepted with its own payload, which proves that
        // the requests dropped earlier were not queued.
        step(p1, 1'b1, 1'b0);
        check_equal(value_o, p1, "S4 a request exactly PULSE_MIN_GAP idle cycles later is accepted");
        check(applied_o, "S4 the request at the gap boundary applies");
        for (i = 2; i <= PULSE_CYCLES; i = i + 1) begin
          step(ZERO, 1'b1, 1'b0);
          check_equal(value_o, p1, "S4 the pulse at the gap boundary holds its own payload");
          check(applied_o, "S4 the pulse at the gap boundary has the exact width");
        end
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, ZERO, "S4 the pulse at the gap boundary ends after PULSE_CYCLES cycles");
        check(!applied_o, "S4 applied_o drops after the pulse at the gap boundary");
      end

      // (e) two well separated requests produce two independent pulses.
      gap_wait(PULSE_MIN_GAP + 2);
      run_pulse(p2, "S4 the first well-separated request produces its own pulse");
      gap_wait(PULSE_MIN_GAP + 2);
      run_pulse(p1, "S4 the second well-separated request produces its own pulse");
      gap_wait(PULSE_MIN_GAP + 2);

      // (f) a reset in the middle of a pulse aborts it and the next request
      // after the reset works.
      step(p1, 1'b1, 1'b0);
      check_equal(value_o, p1, "S5 the pulse is active before the reset");
      check(applied_o, "S5 the active pulse is applied before the reset");
      if (PULSE_CYCLES > 1) begin
        step(ZERO, 1'b1, 1'b0);
        check_equal(value_o, p1, "S5 the pulse is still active in its second cycle");
        check(applied_o, "S5 the second pulse cycle is applied");
      end
      @(negedge clk_i);
      rst_ni = 1'b0;
      raw_i = p1;
      update_i = 1'b1;
      hold_ready_i = 1'b1;
      #1;
      check_equal(value_o, ZERO, "S5 reset aborts the pulse and clears value_o at once");
      check(!applied_o, "S5 reset clears applied_o at once");
      tick();
      check_equal(value_o, ZERO, "S5 no pulse survives the reset edge");
      check(!applied_o, "S5 no apply survives the reset edge");
      for (i = 0; i < (PULSE_CYCLES + 2); i = i + 1) begin
        tick();
        check_equal(value_o, ZERO, "S5 the aborted pulse never resumes");
        check(!applied_o, "S5 the aborted pulse is never re-applied");
      end
      @(negedge clk_i);
      rst_ni = 1'b1;
      raw_i = p1;                      // the request line is still high
      update_i = 1'b1;
      hold_ready_i = 1'b1;
      tick();
      check_equal(value_o, ZERO, "S5 a request already high on release is not a new rising edge");
      check(!applied_o, "S5 a request already high on release applies nothing");
      // Lowering the line and raising it again is a genuine request, and the
      // reset re-armed the driver, so PULSE_MIN_GAP holds nothing back.
      step(quiet_value(p2), 1'b1, 1'b0);
      check_equal(value_o, ZERO, "S5 lowering the request line after the reset applies nothing");
      check(!applied_o, "S5 the falling edge after the reset applies nothing");
      run_pulse(p2, "S5 a fresh request after the reset produces a new pulse");
      gap_wait(2);
    end
  endtask

  // ---------------------------------------------------------------------------
  // Scenarios 6 and 7: STRATEGY 3 hold
  // ---------------------------------------------------------------------------
  task automatic suite_hold;
    integer i;
    logic [WIDTH-1:0] a;
    logic [WIDTH-1:0] b;
    logic [WIDTH-1:0] frozen;
    begin
      a = trigger_value(0);
      b = trigger_value(1);

      if (HOLD_ON_READY == 1) begin
        // (6) handshake hold: update_i and hold_ready_i must coincide.
        step(a, 1'b1, 1'b1);
        check_equal(value_o, a, "S6 hold applies an offered update while hold_ready_i is 1");
        check(applied_o, "S6 the accepted update is marked as applied");

        // raw_i walks over every value with an offer but without a ready: the
        // value must stay bit-for-bit identical.
        for (i = 0; i < 8 * (1 << WIDTH); i = i + 1) begin
          step(walk_value(i), 1'b1, 1'b0);
          check_equal(value_o, a, "S6 hold never moves the value while hold_ready_i is 0");
          check(!applied_o, "S6 hold applies nothing while hold_ready_i is 0");
        end
        for (i = 0; i < 2 * (1 << WIDTH); i = i + 1) begin
          step(walk_value(i + 3), 1'b0, 1'b0);
          check_equal(value_o, a, "S6 hold ignores raw_i without an offer");
          check(!applied_o, "S6 hold applies nothing without an offer");
        end

        // Ready without an offer is not an update either.
        step(walk_value(5), 1'b0, 1'b1);
        check_equal(value_o, a, "S6 hold needs update_i even when hold_ready_i is 1");
        check(!applied_o, "S6 a ready-only cycle applies nothing");

        // The first cycle with both signals applies the value offered then.
        step(b, 1'b1, 1'b1);
        check_equal(value_o, b, "S6 hold updates on the first cycle with update_i and hold_ready_i");
        check(applied_o, "S6 the handshake update is marked as applied");
        step(b, 1'b1, 1'b1);
        check_equal(value_o, b, "S6 hold keeps the value when the same value is offered again");
        check(applied_o, "S6 a repeated value is still marked as (re)applied");
        step(walk_value(2), 1'b1, 1'b0);
        check_equal(value_o, b, "S6 hold freezes again once hold_ready_i drops");
        check(!applied_o, "S6 nothing is applied once hold_ready_i drops");
      end else begin
        // (7) hold without the handshake: every offer applies, hold_ready_i is
        // ignored.
        step(a, 1'b1, 1'b0);
        check_equal(value_o, a, "S7 hold applies an offered update with hold_ready_i low");
        check(applied_o, "S7 the offer applies although hold_ready_i is low");
        for (i = 0; i < 2 * (1 << WIDTH); i = i + 1) begin
          step(walk_value(i), 1'b1, 1'b1);
          check_equal(value_o, walk_value(i), "S7 hold follows raw_i on every offered update");
          check(applied_o, "S7 every offered update is applied");
        end
        frozen = walk_value(2 * (1 << WIDTH) - 1);
        for (i = 0; i < 2 * (1 << WIDTH); i = i + 1) begin
          step(walk_value(i + 1), 1'b0, 1'b1);
          check_equal(value_o, frozen, "S7 hold keeps the value when no update is offered");
          check(!applied_o, "S7 nothing is applied without an offer");
        end
        step(a, 1'b1, 1'b0);
        check_equal(value_o, a, "S7 hold_ready_i is ignored when HOLD_ON_READY is 0");
        check(applied_o, "S7 the update applies although hold_ready_i is low");
      end
    end
  endtask

  // ---------------------------------------------------------------------------
  // Run
  // ---------------------------------------------------------------------------
  initial begin
    rst_ni = 1'b0;
    raw_i = ZERO;
    update_i = 1'b0;
    hold_ready_i = 1'b0;
    $display({"NOTE: soc_special_input_driver_tb WIDTH=%0d STRATEGY=%0d PULSE_CYCLES=%0d PULSE_MIN_GAP=%0d ",
              "HOLD_ON_READY=%0d NEGATIVE_CONTROL=%0d"},
             WIDTH, STRATEGY, PULSE_CYCLES, PULSE_MIN_GAP, HOLD_ON_READY, NEGATIVE_CONTROL);
    #1;   // let the combinational reset qualification settle before checking
    common_reset_suite();
    if (STRATEGY == 0) begin
      $display("NOTE: suite=cycle_value");
      suite_cycle_value();
    end else if (STRATEGY == 1) begin
      $display("NOTE: suite=reset_sampled");
      suite_reset_sampled();
    end else if (STRATEGY == 2) begin
      $display("NOTE: suite=pulse");
      suite_pulse();
    end else begin
      if (HOLD_ON_READY == 1)
        $display("NOTE: suite=hold_ready");
      else
        $display("NOTE: suite=hold_free");
      suite_hold();
    end

    // The driver must be idle and clear after one last reset.
    @(negedge clk_i);
    rst_ni = 1'b0;
    raw_i = ZERO;
    update_i = 1'b0;
    hold_ready_i = 1'b0;
    #1;
    check_equal(value_o, ZERO, "final: reset clears value_o");
    check(!applied_o, "final: reset clears applied_o");
    tick();
    check_equal(value_o, ZERO, "final: value_o stays clear under reset");
    check(!applied_o, "final: applied_o stays clear under reset");
    $display("RESULT: PASS");
    $finish;
  end
endmodule
