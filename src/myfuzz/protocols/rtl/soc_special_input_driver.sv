// Generic driver for one special component input of a generated SoC.
//
// A component profile may mark an input port as special and give it one of four
// drive strategies. This module is the single writer of that component input:
// raw_i is a request stream, never a value, so every strategy registers the
// value it applies and a change on raw_i can only reach value_o through a
// register. There is exactly one deliberate exception, and it is required by the
// reset_sampled strategy: while rst_ni is low the environment is still picking
// the configuration, so value_o follows raw_i directly and the last raw value
// seen on the reset release edge is latched and frozen afterwards.
//
//   STRATEGY 0 cycle_value    apply raw_i in every cycle the environment offers
//                             an update, hold the previous value otherwise.
//   STRATEGY 1 reset_sampled  track raw_i while reset is asserted, latch the
//                             value present on the reset release edge and hold
//                             it from then on, ignoring raw_i and update_i.
//   STRATEGY 2 pulse          raw_i[0] is an edge-triggered request: latch raw_i
//                             as the payload and drive it for exactly
//                             PULSE_CYCLES cycles, then return to 0. A request
//                             that arrives while a pulse is active or before
//                             PULSE_MIN_GAP idle cycles have elapsed is dropped:
//                             it is never queued, never extends and never
//                             restarts a pulse. applied_o alone tells a pulse
//                             from an idle cycle, so an all-zero payload is a
//                             pulse like any other.
//   STRATEGY 3 hold           a registered hold. With HOLD_ON_READY the update
//                             needs update_i and hold_ready_i on the same edge;
//                             without it every offered update is taken.
//
// value_o and applied_o are registered on clk_i and are cleared by the
// synchronous active-low reset rst_ni. Both outputs additionally read 0 while
// rst_ni is asserted, so a reset is visible in the cycle it is applied instead
// of one edge later (the reset_sampled sampling window is the only case where
// value_o is not 0 during reset). applied_o marks a cycle in which value_o is
// applied or re-applied, even when the applied bits repeat the previous value.
module soc_special_input_driver #(
    parameter integer WIDTH = 1,           // port width in bits, >= 1
    parameter integer STRATEGY = 0,        // 0=cycle_value 1=reset_sampled 2=pulse 3=hold
    parameter integer PULSE_CYCLES = 1,    // STRATEGY==2 only: pulse length in cycles, >= 1
    parameter integer PULSE_MIN_GAP = 0,   // STRATEGY==2 only: idle cycles before a new pulse, >= 0
    parameter integer HOLD_ON_READY = 0    // STRATEGY==3 only: 1 = update only while hold_ready_i
) (
    input  logic                 clk_i,
    input  logic                 rst_ni,        // active-low synchronous reset
    input  logic [WIDTH-1:0]     raw_i,         // raw fuzz value for this segment, valid every cycle
    input  logic                 update_i,      // 1 = the environment offers a new value this cycle
    input  logic                 hold_ready_i,  // STRATEGY==3 with HOLD_ON_READY==1: 1 = may update now
    output logic [WIDTH-1:0]     value_o,       // the value actually applied to the component
    output logic                 applied_o      // 1 in a cycle where value_o is (re)applied
);
  localparam integer CYCLE_VALUE = 0;
  localparam integer RESET_SAMPLED = 1;
  localparam integer PULSE = 2;
  localparam integer HOLD = 3;

  logic [WIDTH-1:0] value_q;
  logic             applied_q;
  logic [WIDTH-1:0] pulse_payload_q;
  integer           pulse_left_q;      // remaining cycles of the active pulse, 0 = idle
  integer           pulse_gap_q;       // idle cycles seen since the last pulse ended (saturating)
  logic             raw_bit_q;         // raw_i[0] sampled on the previous edge
  logic             release_q;         // rst_ni sampled on the previous edge

  logic             release_edge;
  logic             trigger_edge;

  initial begin
    if ((WIDTH < 1) || (STRATEGY < CYCLE_VALUE) || (STRATEGY > HOLD) ||
        ((STRATEGY == PULSE) && (PULSE_CYCLES < 1)) ||
        ((STRATEGY == PULSE) && (PULSE_MIN_GAP < 0)) ||
        ((HOLD_ON_READY < 0) || (HOLD_ON_READY > 1)))
      $fatal(1, "invalid soc_special_input_driver parameters");
  end

  // The reset_sampled release edge is the first edge seen with rst_ni high after
  // a reset; release_q is held low for as long as reset is asserted.
  assign release_edge = rst_ni && !release_q;
  // A pulse request is a rising edge of raw_i[0] that the environment offers now.
  // A level that is simply still high is not a new request.
  assign trigger_edge = update_i && raw_i[0] && !raw_bit_q;

  // The registered state is the default source of the output. While reset is
  // asserted the driver reads 0 (the reset itself is synchronous, but a reset
  // must be observable in the same cycle), except in the reset_sampled sampling
  // window where value_o has to follow raw_i continuously.
  assign value_o = !rst_ni ? ((STRATEGY == RESET_SAMPLED) ? raw_i : {WIDTH{1'b0}}) : value_q;
  assign applied_o = rst_ni && applied_q;

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      value_q <= {WIDTH{1'b0}};
      applied_q <= 1'b0;
      pulse_payload_q <= {WIDTH{1'b0}};
      pulse_left_q <= 0;
      // The reset re-arms the driver: a pulse that the reset aborted is not a
      // pulse the next request has to keep PULSE_MIN_GAP idle cycles away from.
      pulse_gap_q <= PULSE_MIN_GAP;
      // The request line keeps being sampled during reset. The trigger is a
      // rising edge of raw_i[0], and a reset must not fabricate one: a request
      // that is already high when reset is released is not a new request, it
      // needs a genuine 0 -> 1 transition while the driver is running.
      raw_bit_q <= raw_i[0];
      release_q <= 1'b0;
    end else begin
      // Edge history is sampled every cycle, once reset has been released, and
      // rst_ni is remembered so that the next edge can be recognised as the
      // release edge.
      raw_bit_q <= raw_i[0];
      release_q <= 1'b1;

      if (STRATEGY == CYCLE_VALUE) begin
        // Every offered update is applied on the edge that offers it; without an
        // offer the previous value is held and applied_o reads 0.
        if (update_i) begin
          value_q <= raw_i;
          applied_q <= 1'b1;
        end else begin
          applied_q <= 1'b0;
        end
      end else if (STRATEGY == RESET_SAMPLED) begin
        // Only the release edge writes the value: from then on raw_i and update_i
        // are ignored completely until the next reset re-opens the window.
        if (release_edge) begin
          value_q <= raw_i;
          applied_q <= 1'b1;
        end else begin
          applied_q <= 1'b0;
        end
      end else if (STRATEGY == PULSE) begin
        if (pulse_left_q > 0) begin
          // An active pulse holds its latched payload for its whole length; a
          // request that arrives now is dropped and cannot extend or restart it.
          value_q <= pulse_payload_q;
          applied_q <= 1'b1;
          pulse_left_q <= pulse_left_q - 1;
          pulse_gap_q <= 0;
        end else if (trigger_edge && (pulse_gap_q >= PULSE_MIN_GAP)) begin
          // A fresh request starts exactly one pulse and latches its payload.
          value_q <= raw_i;
          applied_q <= 1'b1;
          pulse_payload_q <= raw_i;
          pulse_left_q <= PULSE_CYCLES - 1;
          pulse_gap_q <= 0;
        end else begin
          // Idle: the input is driven to 0 and the gap counter advances until it
          // has seen the number of idle cycles the profile requires.
          value_q <= {WIDTH{1'b0}};
          applied_q <= 1'b0;
          pulse_left_q <= 0;
          if (pulse_gap_q < PULSE_MIN_GAP)
            pulse_gap_q <= pulse_gap_q + 1;
        end
      end else begin
        // STRATEGY == HOLD: a registered hold, with or without a ready
        // handshake. Nothing but an accepted update may move the value.
        if (update_i && ((HOLD_ON_READY == 0) || hold_ready_i)) begin
          value_q <= raw_i;
          applied_q <= 1'b1;
        end else begin
          applied_q <= 1'b0;
        end
      end
    end
  end
endmodule
