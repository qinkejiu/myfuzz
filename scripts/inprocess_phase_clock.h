// The declared per-model clock-phase contract of the in-process host.
//
// One grid step is the greatest common half period of the declared models: with
// ``L`` the least common multiple of the declared frequencies it is
// ``1 / (2L)`` seconds.  A model whose declared half period is ``half`` grid
// steps keeps the low-first phase its own generated clock schedule states: its
// clock level for step s is ``(s / half) % 2``, so every clock starts low, its
// first rising edge is exactly at its own half period (s == half), and its
// falling edge is one half period later.  The reference CPU's half period is
// ``cpu_half`` grid steps, so one host tick - one reference CPU cycle -
// advances ``2 * cpu_half`` grid steps:
//
//   * ``cpu_half == 1`` is the historical integer-divider session: the CPU
//     toggles on every step and a ratio-R model toggles on every R-th step;
//   * ``cpu_half > 1`` is an exact rational ratio (50 MHz beside 30 MHz is
//     cpu_half 3 and half 5), and a model whose ``half`` is *below* ``cpu_half``
//     is declared faster than the CPU and takes several of its own edges inside
//     one host tick - the sub-stepping, driven by this same schedule.
//
// Nothing here rounds a frequency: the entry refuses a declared pair whose
// exact grid does not fit its bound.
//
// The host reads a model's registered protocol outputs in the low phase of a
// tick, one tick after the rising edge that produced them.  The three gates
// below say which of those reads are fresh for a model at a given tick, and
// they are stated over the tick's whole ``window`` of grid boundaries (the
// historical window is 2, one reference half period of a ratio-1 clock):
//
//   * ``trace``    - a rising edge happens inside this tick (any boundary of
//                    its window), so the level the low phase reads is the one
//                    that edge will latch: request/trace handshakes are
//                    pre-edge facts;
//   * ``response`` - the previous tick applied the rising edge that registered a
//                    response, so a response valid now was produced by it;
//   * ``probe``    - the post-edge probe sample (pins) can see a rising edge at
//                    the end of the previous tick or at this tick's first
//                    boundary.  The probe is read once per tick after that first
//                    boundary, so this gate is the same for every window.
//
// A ratio-1 model gets all three on every tick, which is exactly the historical
// one-tick loop.  A ratio-R model gets trace/probe on one tick in R and response
// on the following one, so its bus handshakes are counted once per its own cycle
// and a held level is never counted twice.
#pragma once

inline unsigned phase_level(unsigned step, unsigned half) {
  return (step / half) % 2u;
}

inline bool phase_rise_at(unsigned step, unsigned half) {
  return step != 0u && phase_level(step, half) != 0u
      && phase_level(step - 1u, half) == 0u;
}

struct PhaseSampleGates {
  bool trace;
  bool response;
  bool probe;
};

// ``step`` is the boundary whose level is already applied at the tick start and
// ``pending`` is whether this model's rising edge was applied since the previous
// low-phase sample (the host owns that one-tick memory; it is passed in so this
// header stays a pure function of the schedule).  ``window`` is the number of
// grid boundaries one host tick advances - ``2 * cpu_half`` - and defaults to
// the historical 2, so a ratio-1 or whole-divider session keeps its exact
// sequence.
inline PhaseSampleGates phase_sample_gates(unsigned step, unsigned half,
                                           bool pending, unsigned window = 2u) {
  PhaseSampleGates gates;
  gates.trace = false;
  for (unsigned offset = 1u; offset <= window; ++offset)
    gates.trace = gates.trace || phase_rise_at(step + offset, half);
  gates.response = pending;
  gates.probe = phase_rise_at(step, half) || phase_rise_at(step + 1u, half);
  return gates;
}
