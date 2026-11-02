"""The P2 exact rational clock grid: non-integer ratios, a faster model, asynchrony.

Three things are tested here, each by its own contract:

* the exact rational grid: ``lcm(declared rates)`` places every admitted rate
  pair - whole divisor, non-integer, or faster than the reference CPU - on one
  common grid, and the plan states the grid, the CPU half period in grid steps
  and each model's exact fraction of it; a whole-divisor session keeps exactly
  the numbers it stated before this round;
* a model declared *faster* than the reference CPU is sub-stepped, not refused:
  one host tick is exactly one CPU cycle (``2 * cpu_half`` grid steps), so the
  faster model takes several of its own rising edges inside a single tick;
* a pair whose exact grid does not fit the phase-grid bound (two independent
  oscillators) is refused by name with the exact grid and both step counts, and
  a timed model on a grid whose step is not whole picoseconds is refused by
  name: this host clocks every model from one synchronous grid and has no
  phase-independent sampler.

The host's own phase header is compiled and walked, because the schedule is a
C++ fact the Python plan has to agree with.  No Verilator model is built here;
the real runs are in ``runs/p2-timing-20261103`` and the last test reads their
measured counts.
"""
import json
import math
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.run_inprocess_f1f6 import (
    CLOCK_PHASE_POLICY, MAX_PHASE_RATIO, clock_assumption_text, clock_plan_header,
    common_grid_hz, declared_half_period_ps, faster_model_traffic_refusal,
    phase_clock_plan)

ROOT = Path(__file__).resolve().parents[2]
PHASE_HEADER = ROOT / 'scripts/inprocess_phase_clock.h'
EVIDENCE = ROOT / 'runs/p2-timing-20261103'


def row(name, hz, half=None):
    """One phase-plan input row (a model's declared clock and timed contract)."""
    return dict(role=name, name=name, frequency_hz=hz, timed_half_period_ps=half)


def plan_of(*rates):
    return phase_clock_plan([row('cpu', rates[0])] +
                            [row('target:%d' % index, hz)
                             for index, hz in enumerate(rates[1:])])


def ticks(plan):
    return {row['role']: row['half_period_ticks'] for row in plan['rows']}


# --- the exact rational grid ----------------------------------------------

def test_the_common_grid_is_the_least_common_multiple_of_the_declarations():
    assert common_grid_hz([50_000_000, 25_000_000]) == 50_000_000
    assert common_grid_hz([50_000_000, 30_000_000]) == 150_000_000
    assert common_grid_hz([50_000_000, 30_000_000, 60_000_000]) == 300_000_000
    assert common_grid_hz([50_000_000, 32_768]) == 12_800_000_000


def test_a_rational_pair_is_exact_and_not_rounded():
    """50 MHz beside 30 MHz: 5/3 half periods, exact in grid steps."""
    plan = plan_of(50_000_000, 30_000_000)
    assert plan['mode'] == 'per_model_ratio' and plan['assumed'] is False
    assert plan['grid_lcm_hz'] == 150_000_000
    # One grid step is 1 / (2 * 150 MHz); the CPU half period is 3 of them and
    # the 30 MHz target's is 5 - the exact 50:30 half-period ratio, 5/3.
    assert plan['grid_steps_per_cpu_half'] == 3
    assert plan['grid_steps_per_tick'] == 6
    assert ticks(plan) == {'cpu': 3, 'target:0': 5}
    assert plan['rows'][1]['half_period_of_cpu_half'] == dict(numerator=5, denominator=3)
    # The first rising edge is still exactly at each model's own half period.
    assert [r['first_rising_grid_step'] for r in plan['rows']] == [3, 5]
    # Every row states the fraction in lowest terms.
    for row_ in plan['rows']:
        fraction = row_['half_period_of_cpu_half']
        assert math.gcd(fraction['numerator'], fraction['denominator']) == 1
        assert fraction['numerator'] * plan['grid_steps_per_cpu_half'] \
            == row_['half_period_ticks'] * fraction['denominator']
    assert 'level (step // R) % 2' in plan['contract']
    assert '1 / (2 x 150000000) s' in plan['contract']


def test_a_whole_divisor_session_keeps_its_historical_numbers():
    """The integer-ratio plan is the one p1 saved: cpu 1, 25 MHz 2, 10 MHz 5."""
    plan = plan_of(50_000_000, 25_000_000, 10_000_000)
    assert plan['grid_lcm_hz'] == 50_000_000
    assert plan['grid_steps_per_cpu_half'] == 1
    assert plan['grid_steps_per_tick'] == 2
    assert ticks(plan) == {'cpu': 1, 'target:0': 2, 'target:1': 5}
    assert [r['first_rising_grid_step'] for r in plan['rows']] == [1, 2, 5]
    # Three rates with one common divisor: 50 : 30 : 75 is 6 : 10 : 4 steps.
    mixed = plan_of(50_000_000, 30_000_000, 75_000_000)
    assert mixed['grid_lcm_hz'] == 150_000_000
    assert ticks(mixed) == {'cpu': 3, 'target:0': 5, 'target:1': 2}


def test_an_equal_rate_session_states_its_one_step_grid():
    plan = phase_clock_plan([row('cpu', 50_000_000), row('target:a', 50_000_000)])
    assert plan['mode'] == 'equal_rates'
    assert plan['grid_lcm_hz'] == 50_000_000
    assert plan['grid_steps_per_cpu_half'] == 1 and plan['grid_steps_per_tick'] == 2
    assert ticks(plan) == {'cpu': 1, 'target:a': 1}


# --- a model declared faster than the reference CPU -----------------------

def test_a_model_faster_than_the_cpu_is_sub_stepped_not_refused():
    """50 MHz beside 75 MHz: the 75 MHz half period is 2/3 of a CPU one."""
    plan = plan_of(50_000_000, 75_000_000)
    assert plan['grid_lcm_hz'] == 150_000_000
    assert plan['grid_steps_per_cpu_half'] == 3
    assert plan['grid_steps_per_tick'] == 6
    assert ticks(plan) == {'cpu': 3, 'target:0': 2}
    fraction = plan['rows'][1]['half_period_of_cpu_half']
    assert fraction == dict(numerator=2, denominator=3)
    # The target's half period falls inside one host tick, which is the
    # sub-stepping the plan states rather than refuses.
    assert plan['rows'][1]['half_period_ticks'] < plan['grid_steps_per_cpu_half']
    assert 'inside one host tick' in plan['contract']
    # 50 : 60 is the same relation at a different grid: cpu 6 steps, target 5.
    other = plan_of(50_000_000, 60_000_000)
    assert other['grid_lcm_hz'] == 300_000_000
    assert ticks(other) == {'cpu': 6, 'target:0': 5}
    assert other['rows'][1]['half_period_of_cpu_half'] == dict(numerator=5, denominator=6)


def test_the_schedule_arithmetic_puts_several_target_edges_in_one_tick():
    """Walk the host's own schedule: one tick is 2 * cpu_half grid steps."""
    compile_phase_header(r'''
#include <cassert>
#include <cstdlib>
#include "inprocess_phase_clock.h"

// Count the rising edges a model with half period `half` really gets in
// `ticks` host ticks of `2 * cpu_half` grid steps each - the host's schedule.
static unsigned rises_in(unsigned ticks, unsigned cpu_half, unsigned half) {
  unsigned count = 0;
  const unsigned steps = ticks * 2u * cpu_half;
  for (unsigned step = 1; step <= steps; ++step)
    if (phase_rise_at(step, half)) ++count;
  return count;
}

int main() {
  // 50 MHz CPU (3 grid steps per half period) beside 75 MHz (2): ten CPU edges
  // and fifteen target edges - the declared 50:75 ratio exactly, with the faster
  // model taking three of its own edges in every two host ticks.
  assert(rises_in(10, 3, 3) == 10);
  assert(rises_in(10, 3, 2) == 15);
  // 50 MHz beside 30 MHz (5 grid steps per half period): six target edges in
  // ten CPU cycles, the declared 30:50 ratio.
  assert(rises_in(10, 3, 5) == 6);
  // 50 : 30 : 60 on the 300 MHz grid (cpu half 6 steps): ten CPU edges, six
  // 30 MHz edges and twelve 60 MHz edges in ten ticks.
  assert(rises_in(10, 6, 6) == 10);
  assert(rises_in(10, 6, 10) == 6);
  assert(rises_in(10, 6, 5) == 12);
  // The counts ARE the ratio: for any tick count the same step counter gives
  // one CPU edge per tick and the target counts within one half period of
  // `cpu * cpu_half / half`.
  for (unsigned n = 1; n <= 40; ++n) {
    const unsigned cpu = rises_in(n, 6, 6), fast = rises_in(n, 6, 5),
                   slow = rises_in(n, 6, 10);
    assert(cpu == n);                       // one CPU edge per host tick
    assert(fast >= cpu && slow <= cpu);      // 60 MHz faster, 30 MHz slower
    const int fast_err = int(fast) * 5 - int(cpu) * 6;
    const int slow_err = int(slow) * 10 - int(cpu) * 6;
    assert(fast_err <= 6 && fast_err >= -6);
    assert(slow_err <= 6 && slow_err >= -6);
  }
}
''')


def test_the_tick_window_gives_a_slower_model_one_sample_per_its_cycle():
    """The trace gate covers the whole tick, so a slow model is still seen."""
    compile_phase_header(r'''
#include <cassert>
#include <vector>
#include "inprocess_phase_clock.h"

int main() {
  // 50:30 with a 6-step tick: the 5-step target rises at 5, 15, 25, 35, 45, 55,
  // and the trace gate is true exactly on the six ticks that contain one of
  // them - one pre-edge sample per target rising edge, none doubled.
  std::vector<unsigned> sampled;
  for (unsigned step = 0; step < 60; step += 6)
    if (phase_sample_gates(step, 5, step != 0, 6).trace) sampled.push_back(step);
  assert((sampled == std::vector<unsigned>{0, 12, 24, 30, 42, 54}));
  assert(sampled.size() == 6);
  // A faster model really toggles inside one tick: its level at the tick's
  // boundaries moves twice inside a 6-step tick.
  assert(phase_level(0, 2) == 0u && phase_level(5, 2) == 0u
         && phase_level(6, 2) == 1u);
  // The historical window of 2 is the ratio-1 and whole-divider contract: the
  // same call sequence as before this round.
  assert(phase_sample_gates(0, 2, false).trace);
  assert(!phase_sample_gates(2, 2, true).trace);
  assert(phase_sample_gates(4, 2, false).trace);
}
''')


# --- refusals -------------------------------------------------------------

def test_traffic_to_a_sub_stepped_faster_model_is_refused_by_name():
    """The clock is sub-stepped; a case routed to its window is refused.

    One host tick is one CPU cycle and the host reads a model's protocol outputs
    once per tick, so a model whose whole cycle is shorter than that tick has an
    access window that can fall between two samples.  The record gate names it.
    """
    plan = plan_of(50_000_000, 30_000_000, 60_000_000)   # cpu 6, 30 MHz 10, 60 MHz 5
    assert faster_model_traffic_refusal(
        plan, [dict(flow='F2', target_index=0)]) is None
    with pytest.raises(ValueError) as caught:
        faster_model_traffic_refusal(plan, [dict(flow='F2', target_index=1)])
    text = str(caught.value)
    assert text.startswith(
        'unsupported-target-traffic:target:1:faster-than-reference-cpu:')
    # The refusal states both step counts, not the rate it cannot round.
    assert '10 grid steps' in text and '12-step tick' in text
    # F1 and F3 name no target: they run with the faster model clocked.
    assert faster_model_traffic_refusal(
        plan, [dict(flow='F1', target_index=None),
               dict(flow='F3', target_index=None)]) is None
    # A whole-divisor plan has no model faster than the CPU: nothing to refuse.
    legacy = plan_of(50_000_000, 25_000_000)
    assert faster_model_traffic_refusal(
        legacy, [dict(flow='F2', target_index=0)]) is None
    # A faster DMA model refuses the F6 record that would route to it.
    faster_dma = phase_clock_plan([row('cpu', 50_000_000), row('dma', 75_000_000)])
    assert faster_dma['grid_steps_per_cpu_half'] == 3
    assert faster_model_traffic_refusal(
        faster_dma, [dict(flow='F2', target_index=None)]) is None
    with pytest.raises(ValueError, match='dma:faster-than-reference-cpu'):
        faster_model_traffic_refusal(faster_dma, [dict(flow='F6', target_index=None)])


def test_a_pair_with_no_usable_common_grid_is_refused_by_name():
    """Two independent oscillators: exact grid known, unusable, refused."""
    for rate in (32_768, 49_999_999):
        with pytest.raises(ValueError) as caught:
            plan_of(50_000_000, rate)
        text = str(caught.value)
        assert str(rate) in text and '50000000' in text
        assert 'phase-grid bound' in text
        assert str(MAX_PHASE_RATIO) in text
        # The message states the exact grid rather than rounding the rates.
        assert str(common_grid_hz([50_000_000, rate])) in text
        # ... and the reason there is no fallback: one synchronous grid and no
        # phase-independent sampler in this host.
        assert 'no phase-independent sampler' in text
    # The RTC crystal is the slow side, the 49.999999 MHz oscillator the fine
    # side; both directions are the same named refusal.
    with pytest.raises(ValueError, match='phase-grid bound'):
        phase_clock_plan([row('cpu', 50_000_000), row('dma', 1)])
    assert MAX_PHASE_RATIO == 1024
    admitted = phase_clock_plan([row('cpu', MAX_PHASE_RATIO * 1000), row('dma', 1000)])
    assert admitted['rows'][1]['half_period_ticks'] == MAX_PHASE_RATIO


def test_a_timed_model_needs_a_whole_picosecond_grid_step():
    # A timed CV32E40P (50 MHz, half 10000 ps) beside an untimed 30 MHz target:
    # the exact grid is 150 MHz, whose step of 3333.33 ps cannot be advanced.
    with pytest.raises(ValueError, match='timed phase grid'):
        phase_clock_plan([row('cpu', 50_000_000, 10_000), row('target:a', 30_000_000)])
    # The timed whole-divisor sessions keep their exact grid unchanged.
    plan = phase_clock_plan([row('cpu', 50_000_000, 10_000),
                             row('target:a', 25_000_000, 20_000)])
    assert plan['grid_ps'] == 10_000 and plan['timed'] is True
    assert plan['grid_lcm_hz'] == 50_000_000
    with pytest.raises(ValueError, match='timed contract disagrees'):
        phase_clock_plan([row('cpu', 50_000_000, 10_000),
                          row('target:a', 25_000_000, 30_000)])


def test_a_declared_rate_is_still_never_rounded_or_half_driven():
    assert declared_half_period_ps(50_000_000) == 10_000
    assert declared_half_period_ps(30_000_000) is None
    with pytest.raises(ValueError, match='positive integer'):
        phase_clock_plan([row('cpu', 50_000_000), row('target:a', 30_000_001.0)])
    with pytest.raises(ValueError, match='needs the CPU first'):
        phase_clock_plan([row('target:a', 50_000_000)])
    with pytest.raises(ValueError, match='timed model contract'):
        phase_clock_plan([row('cpu', 50_000_000), row('target:a', 25_000_000, 0)])


# --- the rendered header and the statement the summary repeats ------------

def test_the_header_states_the_grid_the_half_period_counts_are_in():
    plan = plan_of(50_000_000, 30_000_000)
    lines = '\n'.join(clock_plan_header(plan))
    assert '#define CLOCK_GRID_LCM_HZ 150000000u' in lines
    assert '#define CLOCK_GRID_STEPS_PER_TICK 6u' in lines
    assert '#define CLOCK_CPU_HALF_TICKS 3u' in lines
    assert '#define CLOCK_IP_HALF_TICKS 5u' in lines
    # The whole-divisor header is exactly the p1 one plus the two grid macros.
    legacy = '\n'.join(clock_plan_header(plan_of(50_000_000, 25_000_000, 10_000_000)))
    assert '#define CLOCK_GRID_LCM_HZ 50000000u' in legacy
    assert '#define CLOCK_GRID_STEPS_PER_TICK 2u' in legacy
    assert '#define CLOCK_CPU_HALF_TICKS 1u' in legacy
    assert '#define CLOCK_IP_HALF_TICKS 2u, 5u' in legacy
    text = clock_assumption_text(plan)
    assert 'target:0=5' in text and '5/3' in text
    assert '150000000' in text


def test_the_saved_runs_measured_counts_are_the_declared_ratio():
    """Read the real evidence: the host's own rising-edge counts, not a plan."""
    rational = EVIDENCE / 'rows/rational-two-targets-30-60/run.log'
    pair = EVIDENCE / 'rows/pair-50-30-rational/run.log'
    if not rational.exists() or not pair.exists():
        pytest.skip('runs/p2-timing-20261103 rows are not present')
    summary = [line for line in rational.read_text().splitlines()
               if line.startswith('summary ')]
    assert len(summary) == 1
    fields = dict(re.findall(r'(\w+) (\S+)', summary[0]))
    cpu_half = int(fields['clock_cpu_half_ticks'])
    slow_half = int(fields['clock_target0_half_ticks'])
    fast_half = int(fields['clock_target1_half_ticks'])
    cpu_cycles = int(fields['clock_cpu_cycles'])
    slow_cycles = int(fields['clock_target0_cycles'])
    fast_cycles = int(fields['clock_target1_cycles'])
    # The plan the run states is the rational one: 300 MHz grid, cpu 6 steps.
    assert fields['clock_grid_lcm_hz'] == '300000000'
    assert int(fields['clock_grid_steps_per_tick']) == 12
    assert (cpu_half, slow_half, fast_half) == (6, 10, 5)
    # 30 MHz < 50 MHz < 60 MHz, measured as rising edges per session.
    assert slow_cycles < cpu_cycles < fast_cycles
    # The counts ARE the declared ratio: both come from the same step counter,
    # so `cycles * half_period` agrees to within one CPU/target half period (the
    # per-case window's own phase), never to a rounded frequency.
    assert abs(slow_cycles * slow_half - cpu_cycles * cpu_half) \
        <= (slow_half + cpu_half) // 2 + 2
    assert abs(fast_cycles * fast_half - cpu_cycles * cpu_half) \
        <= (fast_half + cpu_half) // 2 + 2
    # The faster model really took several of its own edges inside a tick.
    assert fast_cycles > cpu_cycles
    # The two-model 50:30 row states the exact 5/3 pair.
    pair_summary = [line for line in pair.read_text().splitlines()
                    if line.startswith('summary ')][0]
    pair_fields = dict(re.findall(r'(\w+) (\S+)', pair_summary))
    assert pair_fields['clock_grid_lcm_hz'] == '150000000'
    assert (int(pair_fields['clock_cpu_half_ticks']),
            int(pair_fields['clock_target0_half_ticks'])) == (3, 5)


# --- helpers --------------------------------------------------------------

def compile_phase_header(source):
    """Compile and run a small C++ program against the host's phase header."""
    compiler = shutil.which('c++')
    if compiler is None:
        pytest.skip('C++ compiler unavailable for the phase-header test')
    directory = PHASE_HEADER.parent
    source_path = directory / '.p2_phase_clock_test.cpp'
    binary = directory / '.p2_phase_clock_test'
    try:
        source_path.write_text(source)
        subprocess.run([compiler, '-std=c++17', '-I' + str(directory),
                        str(source_path), '-o', str(binary)],
                       check=True, capture_output=True, text=True)
        subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    finally:
        for path in (source_path, binary):
            if path.exists():
                path.unlink()
