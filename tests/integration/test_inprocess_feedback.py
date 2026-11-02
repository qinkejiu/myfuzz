import argparse
import json
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import load_component_profile
from scripts.inprocess_feedback import (F5_RULE, F6_RULE, F5TimerFeedback, F6DmaFeedback,
    derive_f6_record, derive_f6_words, derive_timer_values, feedback_line, hex_bytes,
    parse_host_line, raw_from_words, trigger_roles, words_from_raw)
from scripts.run_inprocess_irq import build_case, feedback_seed

ROOT = Path(__file__).resolve().parents[2]
TIMER_CONFIG = ROOT / 'configs/scenarios/inprocess-irq-pulp-timer-feedback.json'
MASK32 = 0xFFFFFFFF

F5_ZERO = ['NEED_RECORD 0 tick 0', 'CASE_INSTALLED 0', 'irq_source 72', 'irq_take 77',
           'ip_read 107 0', 'case 0 observations_passed irq_sources 1 takes 1 result 0',
           'NEED_RECORD 1 tick 134']
F5_NONZERO = ['NEED_RECORD 0 tick 0', 'CASE_INSTALLED 0', 'irq_source 73', 'irq_take 77',
              'ip_read 107 31', 'case 0 observations_passed irq_sources 1 takes 1 result 31',
              'NEED_RECORD 1 tick 134']
F6_CASE = ['NEED_RECORD 0 tick 22', 'CASE_INSTALLED 0',
           'dma_read 86 22000 1', 'dma_read 88 22004 2', 'dma_read 90 22008 3', 'dma_read 92 2200c 4',
           'dma_write 98 23000 1', 'dma_write 100 23004 2', 'dma_write 102 23008 3',
           'dma_write 104 2300c 4',
           'case 0 observations_passed reads 4 writes 4 irq_takes 1 irq_clears 1 values 1',
           'NEED_RECORD 1 tick 178']


def timer_roles():
    profile = load_component_profile(ROOT / 'configs/peripherals/pulp_timer_irq/component_profile.json')
    config = json.loads((ROOT / 'configs/scenarios/inprocess-irq-pulp-timer-profile.json').read_text())
    offsets = [offset for offset, _ in config['trigger_writes']]
    return offsets, trigger_roles(profile.address.registers, offsets)


def replay(lines):
    """Feed a recorded host transcript to a fresh F5 feedback loop."""
    loop = F5TimerFeedback([4, 8, 0], dict(ctrl=4, cmp=8, count=0), [0, 0, MASK32], cases=2)
    for line in lines:
        loop.note(line)
    return loop


def test_parse_host_line_reads_every_compact_record():
    assert parse_host_line('NEED_RECORD 2 tick 134') == dict(event='need_record', case=2, tick=134)
    assert parse_host_line('irq_source 72') == dict(event='irq_source', tick=72)
    assert parse_host_line('ip_read 204 31') == dict(event='ip_read', tick=204, value=31)
    assert parse_host_line('dma_write 98 23000 102')['data'] == 0x102
    f5 = parse_host_line('case 0 observations_passed irq_sources 1 takes 1 result 0')
    assert (f5['case'], f5['status'], f5['result']) == (0, 'observations_passed', 0)
    f6 = parse_host_line('case 1 observations_passed reads 4 writes 4 irq_takes 1 values 1')
    assert (f6['case'], f6['reads'], f6['writes'], f6['irq_takes']) == (1, 4, 4, 1)
    assert parse_host_line('summary observations_passed cases 2 ticks 335') is None
    assert parse_host_line('') is None


def test_trigger_roles_follow_the_declared_timer_registers():
    offsets, roles = timer_roles()
    assert offsets == [4, 8, 0]
    assert roles == dict(count=0, ctrl=4, cmp=8)


def test_trigger_roles_reject_undeclared_or_incomplete_registers():
    profile = load_component_profile(ROOT / 'configs/peripherals/pulp_timer_irq/component_profile.json')
    with pytest.raises(ValueError, match='not a declared register'):
        trigger_roles(profile.address.registers, [4, 8, 12])
    class Row:
        def __init__(self, offset, name):
            self.offset, self.name = offset, name

    with pytest.raises(ValueError, match='COUNT, CTRL and CMP'):
        trigger_roles([Row(0, 'FOO_COUNT'), Row(4, 'FOO_CTRL'), Row(8, 'FOO_BAR')], [0, 4, 8])
    with pytest.raises(ValueError, match='repeat the count role'):
        trigger_roles(profile.address.registers, [4, 16, 0])


def test_derive_timer_values_arms_only_after_a_zero_read():
    offsets, roles = timer_roles()
    values, record = derive_timer_values(dict(case=0, result=0, ip_read=0), offsets, roles)
    assert values == [1, 0, MASK32 - 1]
    assert record['rule'] == F5_RULE
    assert record['from_case'] == 0
    assert record['observed']['result'] == 0
    assert record['derived_next']['arm_delay'] == 1
    values, record = derive_timer_values(dict(case=1, result=31, ip_read=31), offsets, roles)
    assert values == [0, 0, MASK32]
    assert record['derived_next']['arm_delay'] == 0


def test_derive_timer_values_require_one_observed_read():
    offsets, roles = timer_roles()
    for observation in (dict(case=0), dict(case=0, result=None), dict(case=0, result=-1),
                        dict(case=0, result=1 << 32)):
        with pytest.raises(ValueError, match='observed result'):
            derive_timer_values(observation, offsets, roles)


def test_feedback_loop_derives_the_second_case_from_the_first_report():
    loop = replay(F5_ZERO[:6])
    assert loop.values(0) == [0, 0, MASK32]
    assert loop.observations == [dict(case=0, install_tick=0, result=0, ip_read=0,
                                      irq_tick=72, take_tick=77)]
    assert loop.values(1) == [1, 0, MASK32 - 1]
    assert [row['from_case'] for row in loop.records] == [0]
    assert loop.records[0]['observed']['irq_tick'] == 72
    assert loop.records[0]['derived_next']['values'] == [1, 0, MASK32 - 1]


def test_feedback_loop_is_not_precomputed():
    low = replay(F5_ZERO[:6])
    high = replay(F5_NONZERO[:6])
    assert low.values(1) == [1, 0, MASK32 - 1]
    assert high.values(1) == [0, 0, MASK32]
    assert low.values(1) != high.values(1)


def test_feedback_loop_requires_a_completed_previous_case():
    loop = replay([])
    with pytest.raises(RuntimeError, match='one report per finished case'):
        loop.values(1)
    loop = replay(F5_ZERO[:3])
    with pytest.raises(RuntimeError, match='one report per finished case'):
        loop.values(1)


def test_feedback_loop_rejects_a_mismatched_case_report():
    loop = replay(F5_ZERO[:2])
    loop.note('irq_source 72')
    with pytest.raises(RuntimeError, match='does not match'):
        loop.note('case 3 observations_passed irq_sources 1 takes 1 result 0')


def test_feedback_line_names_the_source_and_derived_values():
    line = feedback_line(dict(rule=F5_RULE, from_case=0, observed=dict(result=0, ip_read=0),
                              derived_next=dict(case=1, ctrl=1, count=MASK32 - 1, values=[1, 0, MASK32 - 1])))
    assert 'from_case 0' in line and 'rule ' + F5_RULE in line
    assert 'derived_count ' + str(MASK32 - 1) in line
    assert 'values 1,0,' + str(MASK32 - 1) in line and line.endswith('\n')


def test_f6_word_encoding_round_trips_and_rejects_invalid_input():
    raw = hex_bytes('0110c00008000000')
    assert words_from_raw(raw) == (1, 2, 3, 4)
    assert words_from_raw(raw_from_words((1, 2, 3, 4))) == (1, 2, 3, 4)
    with pytest.raises(ValueError, match='must differ'):
        raw_from_words((1, 1, 2, 3))
    with pytest.raises(ValueError, match='eight hexadecimal bytes'):
        hex_bytes('0110c0000800')
    with pytest.raises(ValueError, match='reserved'):
        words_from_raw(bytes.fromhex('0000000000001000'))
    with pytest.raises(ValueError, match='11-bit'):
        raw_from_words((1, 2, 3, 2048))


def test_f6_derivation_is_reproducible_and_uses_the_observed_words():
    observed = (1, 2, 3, 4)
    first = derive_f6_words(observed)
    assert first == derive_f6_words(observed)
    assert len(set(first)) == 4
    assert first != derive_f6_words((5, 6, 7, 8))
    assert first == (258, 516, 774, 1032)
    raw, record = derive_f6_record(dict(case=0, words=list(observed), writes=4, reads=4, irq_takes=1))
    assert raw.hex() == '022190c110080000'
    assert record['rule'] == F6_RULE and record['from_case'] == 0
    assert record['observed']['words'] == [1, 2, 3, 4]
    assert record['derived_next']['words'] == [258, 516, 774, 1032]


def test_f6_feedback_loop_derives_the_next_record_from_real_dma_writes():
    loop = F6DmaFeedback(hex_bytes('0110c00008000000'), cases=2)
    for line in F6_CASE[:11]:
        loop.note(line)
    assert loop.observations[0]['words'] == [1, 2, 3, 4]
    assert loop.observations[0]['irq_takes'] == 1
    assert loop.raw(0) == hex_bytes('0110c00008000000')
    assert loop.raw(1) == hex_bytes('022190c110080000')
    assert loop.records[0]['from_case'] == 0
    with pytest.raises(RuntimeError, match='one report per finished case'):
        F6DmaFeedback(hex_bytes('0110c00008000000'), cases=2).raw(1)


def test_f6_feedback_loop_requires_the_four_observed_writes():
    loop = F6DmaFeedback(hex_bytes('0110c00008000000'), cases=2)
    loop.note('NEED_RECORD 0 tick 22')
    loop.note('dma_write 98 23000 1')
    with pytest.raises(RuntimeError, match='four observed DMA writes'):
        loop.note('case 0 observations_passed reads 1 writes 1 irq_takes 1 values 0')


def test_declared_feedback_config_resolves_against_the_timer_profile():
    config = json.loads(TIMER_CONFIG.read_text())
    assert config['feedback_rule'] == F5_RULE
    offsets, roles = timer_roles()
    seed = feedback_seed(config, argparse.Namespace(seed=None), offsets, roles)
    assert seed == [0, 0, MASK32]  # ctrl, cmp, count in the declared trigger order
    overridden = feedback_seed(config, argparse.Namespace(seed='1,0,4294967294'), offsets, roles)
    assert overridden == [1, 0, MASK32 - 1]
    with pytest.raises(ValueError, match='one 32-bit value per trigger'):
        feedback_seed(config, argparse.Namespace(seed='1,0'), offsets, roles)


def test_online_program_is_unchanged_by_the_feedback_config():
    """The fixed polling loop, not the generator, still moves the values into MMIO."""
    config = json.loads(TIMER_CONFIG.read_text())
    cpu = load_component_profile(ROOT / config['cpu_profile'])
    ip = load_component_profile(ROOT / config['source_profile'])
    options, prefix = build_case(config, cpu, ip, boot=0x10080)
    assert options['trigger_writes'] == ((4, 0), (8, 0), (0, MASK32))
    assert prefix['firmware']['dynamic_start'] > 0
