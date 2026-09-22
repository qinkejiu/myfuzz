// Same-domain edge-to-pulse normaliser for one interrupt source.
//
// ``soc_irq_controller`` captures a source by sampling its input on every
// clock, so a source that is already a bounded pulse needs no help: a pulse of
// at least one ``clk_i`` period is seen on the sampling edge and becomes a
// pending bit that stays set until CLAIM.  A source that instead *holds* an
// edge-shaped condition asserted (a level that means "an edge happened and has
// not been acknowledged") cannot be connected directly, because the controller
// would re-pend it one sampling edge after every COMPLETE.  This module is the
// converter for that case: it turns a held level into a single-cycle pulse, so
// the controller sees exactly one event per edge.
//
// Semantics, stated exactly:
//   * ``EDGE`` selects which transition of the *normalised* input fires:
//     0 = rising, 1 = falling, 2 = both.  "Normalised" means the input is
//     already active-high; polarity inversion of an active-low source is done
//     by the caller, before this module, so that a falling edge of an
//     active-low source is a rising edge here.
//   * ``PULSE_CYCLES`` is the width in ``clk_i`` periods of the emitted pulse,
//     and must be >= 1.  The default of 1 is what the controller's pending bit
//     needs; wider values exist so that a downstream consumer which is not the
//     controller can also observe the event.
//   * ``RESET_LEVEL`` is the raw input level the previous-level register is
//     initialised to, i.e. the reference level the first post-reset comparison
//     is made against.  It is NOT a guarantee that no event is reported on the
//     first cycle after reset: if ``raw_i`` is at the opposite level when
//     ``rst_ni`` is released, exactly one event IS emitted.  That is deliberate
//     -- an edge-shaped source holds its asserted level to mean "an event is
//     pending", so dropping it across reset would lose a real request.  A
//     caller that wants silence on release declares the level the source
//     actually holds.  Both behaviours are checked in
//     ``tests/fixtures/rtl/soc_irq_edge_detect_tb.sv``.
//   * ``irq_o`` is 0 for the whole reset window; a pulse in flight when reset
//     is asserted is discarded, not resumed.
//
// Known non-features, deliberately not implemented here:
//   * No clock-domain crossing.  A source in another clock domain must be
//     refused by the planner, never synchronised here; a two-flop synchroniser
//     in this module would make the composition look supported while the
//     planner's cross-domain refusal had been bypassed.
//   * No glitch filter and no minimum pulse width guarantee on the input: a
//     pulse shorter than one ``clk_i`` period may be missed, and the planner
//     records that as the declared capture contract of the source.
//   * No software-visible status: the only state is the previous input level,
//     which is not readable and not clearable.  The software-visible event
//     state belongs to the peripheral and to the controller's pending bitmap.
module soc_irq_edge_detect #(
    parameter integer EDGE = 0,          // 0 = rising, 1 = falling, 2 = both
    parameter integer PULSE_CYCLES = 1,  // emitted pulse width in clk_i periods, >= 1
    parameter integer RESET_LEVEL = 0    // raw input level assumed during reset
) (
    input  logic clk_i,
    input  logic rst_ni,   // active-low synchronous reset

    input  logic raw_i,    // active-high source, already polarity-normalised
    output logic irq_o     // active-high pulse, PULSE_CYCLES wide
);

  // Guard parameters at elaboration time instead of degrading silently.
  initial begin
    if ((EDGE < 0) || (EDGE > 2))
      $fatal(1, "soc_irq_edge_detect: EDGE must be 0 (rising), 1 (falling) or 2 (both)");
    if (PULSE_CYCLES < 1)
      $fatal(1, "soc_irq_edge_detect: PULSE_CYCLES must be >= 1");
    if ((RESET_LEVEL != 0) && (RESET_LEVEL != 1))
      $fatal(1, "soc_irq_edge_detect: RESET_LEVEL must be 0 or 1");
  end

  // Width of the down-counter that holds the pulse for PULSE_CYCLES cycles.
  // The counter counts PULSE_CYCLES..1 and 0 means idle, so the width has to
  // hold PULSE_CYCLES itself: $clog2(PULSE_CYCLES) + 1, which is 1 bit for the
  // default single-cycle pulse and is never zero-width.
  localparam integer COUNT_WIDTH = $clog2(PULSE_CYCLES) + 1;

  logic raw_q;                        // input as seen on the previous edge
  logic [COUNT_WIDTH-1:0] pulse_q;    // remaining cycles of the emitted pulse
  logic fire;                         // an edge is present on this edge

  always_comb begin
    fire = 1'b0;
    case (EDGE)
      0: fire = raw_i & ~raw_q;         // rising
      1: fire = ~raw_i & raw_q;         // falling
      default: fire = raw_i ^ raw_q;    // both
    endcase
  end

  // ``irq_o`` is the registered remaining count, so the pulse is a synchronous
  // output that cannot glitch with the input.
  assign irq_o = rst_ni && (pulse_q != {COUNT_WIDTH{1'b0}});

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      raw_q <= (RESET_LEVEL != 0);
      pulse_q <= {COUNT_WIDTH{1'b0}};
    end else begin
      raw_q <= raw_i;
      if (fire)
        // A new edge restarts the pulse; a pulse already in flight is not
        // extended past PULSE_CYCLES by a late edge, it is restarted.
        pulse_q <= COUNT_WIDTH'(PULSE_CYCLES);
      else if (pulse_q != {COUNT_WIDTH{1'b0}})
        pulse_q <= pulse_q - 1'b1;
    end
  end
endmodule
