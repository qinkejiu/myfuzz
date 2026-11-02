"""The per-model clock plan, phase scheduling and CPU capability gates.

Four things are tested here, each by its own contract:

* the declared-rate normalization (an exact rational half-period grid, the
  explicit ``assume_single_clock`` fallback as one mode among them, and a named
  refusal for a pair with no usable common grid; the rational/faster-model
  contract itself is covered by ``test_p2_timing_ratios.py``);
* the low-first per-model phase schedule and its three observation gates, by
  compiling the host's own header and walking the sequence;
* the CPU capability matrix: every checked-in CPU profile appears, a signal a
  model does not export is ``unknown``/``none``/a named refusal, never a zero;
* the F5/F6 capability gates, including the take-witness selection and the
  F6-named DMA-port refusals.

No Verilator model is compiled or run: artifact documents are the ones the entry
reads, and the phase header is plain C++.
"""
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.run_inprocess_f1f6 import (
    CLOCK_PHASE_POLICY, MAX_PHASE_RATIO, clock_assumption_text, clock_plan_header,
    cpu_dma_port_refusal, cpu_flow_witness_refusals, cpu_irq_take_witness,
    declared_half_period_ps, model_clock_rate, phase_clock_plan)

ROOT = Path(__file__).resolve().parents[2]


def row(name, hz, half=None):
    """One phase-plan input row (a model's declared clock and timed contract)."""
    return dict(role=name, name=name, frequency_hz=hz, timed_half_period_ps=half)


def simple_clock(hz):
    return dict(phase_policy=CLOCK_PHASE_POLICY,
                clocks=[dict(signal='clk', ratio=1, first_rising_fast_tick=1,
                             half_period_fast_ticks=1, frequency_hz=hz)])


# --- declared-rate normalization ------------------------------------------

def test_equal_declared_rates_keep_the_one_tick_plan():
    plan = phase_clock_plan([row('cpu', 50_000_000), row('target:a', 50_000_000)])
    assert plan['mode'] == 'equal_rates' and plan['assumed'] is False
    assert plan['grid_ps'] is None and plan['timed'] is False
    assert plan['reference_half_period_ps'] == 10_000
    assert [r['half_period_ticks'] for r in plan['rows']] == [1, 1]
    assert [r['first_rising_grid_step'] for r in plan['rows']] == [1, 1]


def test_a_whole_divisor_is_a_per_model_half_period_ratio():
    plan = phase_clock_plan([row('cpu', 50_000_000), row('target:a', 25_000_000),
                             row('target:b', 10_000_000)])
    assert plan['mode'] == 'per_model_ratio' and plan['assumed'] is False
    ticks = {r['role']: r['half_period_ticks'] for r in plan['rows']}
    assert ticks == {'cpu': 1, 'target:a': 2, 'target:b': 5}
    # The ratio is exactly the declared frequency ratio: half period is
    # proportional to 1/frequency and the reference half period is one step.
    assert plan['reference_half_period_ps'] == 10_000
    assert all(r['first_rising_grid_step'] == r['half_period_ticks']
               for r in plan['rows'])
    assert 'level (step // R) % 2' in plan['contract']


def test_a_timed_model_agrees_with_the_ratio_in_picoseconds():
    plan = phase_clock_plan([row('cpu', 50_000_000, 10_000),
                             row('target:a', 25_000_000, 20_000),
                             row('target:b', 10_000_000, 50_000)])
    assert plan['timed'] is True and plan['grid_ps'] == 10_000
    assert {r['role']: r['timed'] for r in plan['rows']} == {
        'cpu': True, 'target:a': True, 'target:b': True}


def test_a_non_integer_ratio_is_placed_on_the_exact_common_grid():
    """50:30 has no whole divisor; since P2 it is exact on the 150 MHz grid.

    This test used to assert the named refusal for this pair.  The refusal is
    gone because the capability was added (see
    ``tests/integration/test_p2_timing_ratios.py`` and
    ``docs/reports/p2-timing-ratios-async-20261103.md``), not because the
    declared rate is rounded: 150 MHz / 30 MHz = 5 grid steps per half period
    against the CPU's 3, i.e. exactly 5/3.
    """
    plan = phase_clock_plan([row('cpu', 50_000_000), row('target:a', 30_000_000)])
    assert plan['mode'] == 'per_model_ratio'
    assert plan['grid_lcm_hz'] == 150_000_000
    assert {r['role']: r['half_period_ticks'] for r in plan['rows']} == {
        'cpu': 3, 'target:a': 5}
    # A pair with no usable common grid keeps a named refusal that states the
    # exact grid and both step counts (the asynchronous case).
    try:
        phase_clock_plan([row('cpu', 50_000_000), row('target:a', 32_768)])
    except ValueError as error:
        text = str(error)
        assert '50000000' in text and '32768' in text and 'target:a' in text
        assert '12800000000' in text and 'phase-grid bound' in text
    else:  # pragma: no cover - the refusal is the contract
        raise AssertionError('a pair with no usable common grid was admitted')


def test_a_model_faster_than_the_reference_cpu_is_sub_stepped():
    """A faster model used to be refused; since P2 it is sub-stepped.

    The host advances one CPU cycle per host tick, so a 50 MHz model beside a
    25 MHz CPU is two of its cycles per tick and a model faster than the CPU
    takes several of its own edges inside one tick - the exact grid expresses
    both without rounding.
    """
    plan = phase_clock_plan([row('cpu', 25_000_000), row('target:a', 50_000_000)])
    assert plan['grid_lcm_hz'] == 50_000_000
    assert plan['grid_steps_per_cpu_half'] == 2
    assert plan['grid_steps_per_tick'] == 4
    assert {r['role']: r['half_period_ticks'] for r in plan['rows']} == {
        'cpu': 2, 'target:a': 1}
    assert plan['rows'][1]['half_period_of_cpu_half'] == dict(numerator=1, denominator=2)
    assert 'inside one host tick' in plan['contract']


def test_a_ratio_beyond_the_phase_grid_bound_is_refused():
    with pytest.raises(ValueError, match='phase-grid bound'):
        phase_clock_plan([row('cpu', 50_000_000), row('dma', 1)])
    assert MAX_PHASE_RATIO == 1024
    plan = phase_clock_plan([row('cpu', MAX_PHASE_RATIO * 1000),
                             row('dma', 1000)])
    assert plan['rows'][1]['half_period_ticks'] == MAX_PHASE_RATIO


def test_a_timed_contract_that_disagrees_with_the_ratio_is_refused():
    with pytest.raises(ValueError, match='timed contract disagrees'):
        phase_clock_plan([row('cpu', 50_000_000, 10_000),
                          row('target:a', 25_000_000, 30_000)])
    with pytest.raises(ValueError, match='timed phase grid'):
        # 24 MHz cannot state a whole-picosecond half period, so a timed model
        # beside it has no exact grid to advance to.
        phase_clock_plan([row('cpu', 24_000_000),
                          row('target:a', 12_000_000, 40_000)])


def test_the_explicit_assumption_is_one_mode_and_still_checks_timed_contracts():
    plan = phase_clock_plan([row('cpu', 50_000_000), row('dma', 1)],
                            assume_single_clock=True)
    assert plan['mode'] == 'assumed_single_clock' and plan['assumed'] is True
    assert [r['half_period_ticks'] for r in plan['rows']] == [1, 1]
    with pytest.raises(ValueError, match='timed models declare different half periods'):
        phase_clock_plan([row('cpu', 50_000_000, 10_000),
                          row('target:a', 25_000_000, 20_000)],
                         assume_single_clock=True)


def test_a_model_with_a_more_complex_declared_clock_is_refused_by_name():
    with pytest.raises(ValueError, match='requires one simple clock'):
        model_clock_rate(dict(clock_schedule=dict(clocks=[
            dict(signal='clk', ratio=2, first_rising_fast_tick=1,
                 half_period_fast_ticks=1, frequency_hz=50_000_000)],
            phase_policy=CLOCK_PHASE_POLICY)), 'cpu')
    with pytest.raises(ValueError, match='requires one simple clock'):
        model_clock_rate(dict(clock_schedule=dict(clocks=[],
                                                  phase_policy=CLOCK_PHASE_POLICY)),
                         'target:a')
    assert model_clock_rate(dict(clock_schedule=simple_clock(25_000_000)),
                            'target:a') == 25_000_000


def test_a_non_integral_picosecond_half_period_is_stated_not_rounded():
    assert declared_half_period_ps(50_000_000) == 10_000
    assert declared_half_period_ps(24_000_000) is None
    assert declared_half_period_ps(333_333_333) is None


def test_the_header_states_the_plan_the_summary_can_repeat():
    plan = phase_clock_plan([row('cpu', 50_000_000), row('target:a', 25_000_000),
                             row('target:b', 10_000_000)])
    lines = '\n'.join(clock_plan_header(plan))
    assert '#define CLOCK_PLAN_MODE "per_model_ratio"' in lines
    assert '#define CLOCK_ASSUMED_SINGLE 0' in lines
    assert '#define CLOCK_REFERENCE_HZ 50000000u' in lines
    assert '#define CLOCK_REFERENCE_HALF_PERIOD_PS 10000u' in lines
    assert '#define CLOCK_IP_HALF_TICKS 2u, 5u' in lines
    assert '#define CLOCK_CPU_HALF_TICKS 1u' in lines
    assert '#define CLOCK_ROW_COUNT 3u' in lines
    text = clock_assumption_text(plan)
    assert 'target:a=2' in text and 'target:b=5' in text


def test_the_declared_rate_variants_change_only_the_rate_and_keep_the_pinned_source():
    pinned = json.loads((ROOT / 'configs/peripherals/pulp_timer_irq/'
                                'component_profile.json').read_text())
    variants = {'pulp_timer_25mhz': 25_000_000, 'pulp_timer_10mhz': 10_000_000,
                'pulp_timer_10mhz_timed': 10_000_000}
    for name, hz in variants.items():
        document = json.loads((ROOT / 'configs/peripherals' / name /
                               'component_profile.json').read_text())
        assert document['source'] == pinned['source']
        assert document['clocks'][0]['frequency_hz'] == hz
        assert document['resets'] == pinned['resets']
        assert document['port_actions'] == pinned['port_actions']
    # The pinned profile itself keeps its 50 MHz declaration: a variant must never
    # be made by editing a pinned rate.
    assert pinned['clocks'][0]['frequency_hz'] == 50_000_000


# --- per-model phase scheduling -------------------------------------------

PHASE_HEADER = ROOT / 'scripts/inprocess_phase_clock.h'


def test_the_low_first_per_model_schedule_and_its_gates():
    compiler = shutil.which('c++')
    if compiler is None:
        pytest.skip('C++ compiler unavailable for the phase-header test')
    source = r'''
#include <cassert>
#include <vector>
#include "inprocess_phase_clock.h"

int main() {
  // A ratio-1 model toggles on every grid step and rises at 1, 3, 5, ...
  for (unsigned step = 0; step <= 7; ++step)
    assert(phase_level(step, 1) == (step % 2u));
  assert(phase_rise_at(1, 1) && phase_rise_at(3, 1) && phase_rise_at(5, 1));
  assert(!phase_rise_at(0, 1) && !phase_rise_at(2, 1));

  // A ratio-2 model is low for two steps, high for two, and rises at 2, 6, 10.
  const unsigned two[9] = {0, 0, 1, 1, 0, 0, 1, 1, 0};
  for (unsigned step = 0; step < 9; ++step) assert(phase_level(step, 2) == two[step]);
  assert(!phase_rise_at(1, 2) && phase_rise_at(2, 2) && !phase_rise_at(5, 2)
         && phase_rise_at(6, 2));

  // A ratio-5 model rises at 5 and 15 only inside the first 21 steps.
  std::vector<unsigned> rises5;
  for (unsigned step = 1; step <= 20; ++step)
    if (phase_rise_at(step, 5)) rises5.push_back(step);
  assert((rises5 == std::vector<unsigned>{5, 15}));

  // Every rising edge has exactly one falling edge one half period later.
  for (unsigned half = 1; half <= 5; ++half) {
    unsigned rises = 0, falls = 0;
    for (unsigned step = 1; step <= 200; ++step) {
      if (phase_rise_at(step, half)) ++rises;
      if (phase_level(step, half) == 0u && phase_level(step - 1u, half) != 0u)
        ++falls;
    }
    assert(rises == falls);
  }

  // The observation gates of a ratio-2 model at the start of tick 0 (step 0):
  // the end boundary of this tick is its rising edge, so the low phase is the
  // trace sample; no response has been registered yet; no probe is new.
  PhaseSampleGates tick0 = phase_sample_gates(0, 2, false);
  assert(tick0.trace && !tick0.response && !tick0.probe);
  // Tick 1 (step 2) is the response tick; the trace is not sampled again.
  PhaseSampleGates tick1 = phase_sample_gates(2, 2, true);
  assert(!tick1.trace && tick1.response && tick1.probe);
  // Tick 2 (step 4) is one full target cycle later: its end boundary is the
  // next rising edge, so the trace is sampled again while no response from the
  // previous cycle is pending and no probe has moved.
  PhaseSampleGates tick2 = phase_sample_gates(4, 2, false);
  assert(tick2.trace && !tick2.response && !tick2.probe);
  // A ratio-1 model gets all three gates on every tick.
  for (unsigned step = 2; step <= 8; step += 2) {
    PhaseSampleGates gates = phase_sample_gates(step, 1, true);
    assert(gates.trace && gates.response && gates.probe);
  }
  // A ratio-5 model is sampled once per five half periods, not once per tick:
  // the rising edges at 5, 15, 25, 35 are read in the ticks at steps 4, 14, 24,
  // 34, which is one trace sample per target cycle.
  std::vector<unsigned> trace_ticks;
  for (unsigned step = 0; step < 40; step += 2)
    if (phase_sample_gates(step, 5, step != 0).trace) trace_ticks.push_back(step);
  assert((trace_ticks == std::vector<unsigned>{4, 14, 24, 34}));
}
'''
    directory = PHASE_HEADER.parent
    source_path = directory / '.phase_clock_test.cpp'
    binary = directory / '.phase_clock_test'
    try:
        source_path.write_text(source)
        subprocess.run([compiler, '-std=c++17', '-I' + str(directory), str(source_path),
                        '-o', str(binary)], check=True, capture_output=True, text=True)
        subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    finally:
        for path in (source_path, binary):
            if path.exists():
                path.unlink()


# --- capability matrix ----------------------------------------------------

def obi_document(*, rvfi=(), runtime_ports=(), physical_extra=()):
    """The artifact fields the capability matrix reads, as a minimal OBI model."""
    exports = [dict(physical_port=name, direction='output', runtime_name=name)
               for name in rvfi]
    exports += list(physical_extra)
    backend = [dict(channel=channel, role=role, name=channel + '_' + role)
               for channel in ('i', 'd')
               for role in ('req_valid', 'req_ready', 'req_write', 'req_addr',
                            'req_wdata', 'req_be', 'rsp_valid', 'rsp_ready',
                            'rsp_rdata', 'rsp_error')]
    return dict(kind='obi_cpu', module_name='local_runtime_cpu',
                clock_schedule=simple_clock(50_000_000),
                physical_exports=exports, runtime_ports=list(runtime_ports),
                backend_ports=backend)


def capability_fixture(document):
    from scripts.cpu_capability_matrix import capability_row
    return capability_row(ROOT, ROOT / 'configs/cpus/ibex_rvfi_local/'
                                     'component_profile.json',
                          artifact=SimpleNamespace(runtime_document=document))


def test_a_model_without_rvfi_has_no_retirement_and_refuses_every_flow():
    row = capability_fixture(obi_document(runtime_ports=[]))
    assert row['retirement']['face'] == 'none'
    assert row['trap'] == 'none'
    assert row['flows'] == {flow: row['flows'][flow] for flow in
                            ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    assert all(value.startswith('refused:unsupported: F1 needs the CPU rvfi_*')
               for value in row['flows'].values())


def test_a_missing_trap_and_intr_field_is_unknown_or_none_never_zero():
    document = obi_document(rvfi=('rvfi_valid', 'rvfi_order', 'rvfi_insn',
                                  'rvfi_pc_rdata'),
                            runtime_ports=[dict(name='probe_irq_taken_pre',
                                                direction='output')])
    row = capability_fixture(document)
    assert row['retirement']['face'] == 'rvfi_ports'
    assert row['retirement']['fields'] == ['valid', 'order', 'insn', 'pc_rdata']
    assert row['retirement']['witness'] == 'none'
    assert row['trap'] == 'none'          # not exported, stated as none
    # The take probe is the witness, so F5/F6 stay admitted; the missing trap bit
    # never becomes a zero claim.
    assert row['flows']['F5'] == 'runnable'


def test_the_rvfi_intr_export_is_the_retirement_take_witness():
    document = obi_document(rvfi=('rvfi_valid', 'rvfi_order', 'rvfi_insn',
                                  'rvfi_pc_rdata', 'rvfi_trap', 'rvfi_intr'))
    row = capability_fixture(document)
    assert row['retirement']['witness'] == 'rvfi_intr'
    assert 'trap' in row['retirement']['fields']
    assert row['trap'] == 'rvfi_trap'
    assert row['flows']['F5'] == 'runnable' and row['flows']['F6'] == 'runnable'


def test_an_unknown_cpu_kind_is_kept_as_its_exact_refusal():
    from scripts.cpu_capability_matrix import capability_row
    document = obi_document(rvfi=('rvfi_valid',))
    document['kind'] = 'native_memory_cpu'
    row = capability_row(ROOT, ROOT / 'configs/cpus/picorv32/component_profile.json',
                         artifact=SimpleNamespace(runtime_document=document))
    assert row['row_status'] == 'refused'
    assert row['bus'] == 'refused:unsupported-cpu-kind:native_memory_cpu'
    assert all(value.startswith('refused:unsupported-cpu-kind')
               for value in row['flows'].values())


def test_every_checked_in_cpu_profile_is_in_the_checked_in_matrix():
    matrix = (ROOT / 'docs/cpu-capability-matrix.md').read_text()
    profiles = sorted((ROOT / 'configs/cpus').glob('*/component_profile.json'))
    assert profiles
    for path in profiles:
        relative = str(path.relative_to(ROOT))
        assert '`' + relative + '`' in matrix
    # The document must never state a flow as a numeric zero.
    assert '| 0 |' not in matrix


def test_the_checked_in_matrix_rows_for_two_profiles_are_current():
    from scripts.cpu_capability_matrix import _retirement, _flows
    document = obi_document(rvfi=('rvfi_valid', 'rvfi_order', 'rvfi_insn',
                                  'rvfi_pc_rdata', 'rvfi_trap', 'rvfi_intr',
                                  'rvfi_rd_addr', 'rvfi_rd_wdata'))
    witness, _ = cpu_irq_take_witness(document)
    flows = _flows('obi', _retirement(document, 'obi'), witness, None,
                   dict(width=1))
    assert flows['F1'] == 'runnable' and flows['F6'] == 'runnable'
    matrix = (ROOT / 'docs/cpu-capability-matrix.md').read_text()
    assert '| `configs/cpus/ibex_rvfi_local/component_profile.json` | obi |' in matrix


# --- F5/F6 capability gates -----------------------------------------------

def test_the_take_witness_is_a_declared_port_not_a_bus_success():
    probe = obi_document(runtime_ports=[dict(name='probe_irq_taken_pre',
                                             direction='output')])
    assert cpu_irq_take_witness(probe) == ('probe_irq_taken_pre', None)
    assert cpu_irq_take_witness(obi_document(rvfi=('rvfi_intr',)),
                                custom_irq=dict(eoi_runtime_name='irq_eoi')) == (
                                    'custom_eoi', None)
    assert cpu_irq_take_witness(obi_document(rvfi=('rvfi_intr',))) == (
        'rvfi_intr', None)
    witness, missing = cpu_irq_take_witness(obi_document(rvfi=('rvfi_valid',)))
    assert witness is None and 'probe_irq_taken_pre' in missing


def test_a_cpu_without_a_take_eoi_or_retirement_witness_refuses_f5_and_f6_by_name():
    refusals = cpu_flow_witness_refusals('obi', None, 'needs-one-of:probe_irq_taken_pre')
    assert refusals['F5'].startswith('unsupported-f5:cpu-take-witness-unexported:')
    assert refusals['F6'].startswith('unsupported-f6:cpu-take-witness-unexported:')
    assert 'needs-one-of' in refusals['F5']
    # A witness admits both flows; the bus-specific refusals are not restated.
    assert cpu_flow_witness_refusals('obi', 'probe_irq_taken_pre', None) == {}
    assert cpu_flow_witness_refusals('ahb', None, 'missing') == {}


def test_a_cpu_dma_combination_without_a_dma_port_refuses_f6_by_name():
    for bus, kind, custom, start in (
            ('ahb', 'wishbone_dma', True, 'unsupported-f6:cpu-dma-port-unexported:ahb'),
            ('axi4', 'wishbone_dma', True,
             'unsupported-f6:cpu-dma-port-unexported:axi4'),
            ('wishbone', 'wishbone_dma', False,
             'unsupported-f6:cpu-dma-port-unexported:wishbone'),
            ('obi', 'fifo_device', True,
             'unsupported-f6:requires-wishbone-dma:fifo_device')):
        refusal = cpu_dma_port_refusal(bus, kind, custom)
        assert refusal is not None and refusal.startswith(start)
    # The one supported combination is admitted; no DMA declared is not a refusal
    # of the CPU (the flow simply has no model and is refused elsewhere).
    assert cpu_dma_port_refusal('obi', 'wishbone_dma', False) is None
    assert cpu_dma_port_refusal('obi', None, False) is None
