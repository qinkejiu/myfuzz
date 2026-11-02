"""Pure-Python tests for the declared F1 short-program mode of the unified entry.

No RTL and no Verilator: every fact here is the record gate, the one RAM image,
the generated header, or the correspondence check the entry applies to a saved
case line.  The C++ host mirrors the same rules; those are exercised by the real
run evidence, not here.
"""
import json
from pathlib import Path

import pytest

from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from scripts.run_inprocess_f1f6 import (PROGRAM_DATA_WORDS, build_firmware, build_layout,
                                       case_observation_keys, correspondence,
                                       declared_windows, flow_arity, parse_record,
                                       render_bindings, validate_record)

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
WINDOWS = declared_windows(CONFIG, 16)
LAYOUT = build_layout(WINDOWS, 0x10080)
ISA = IsaContract(32, ('I', 'M'), instruction_alignment=4)
ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}


def word(name, **operands):
    return encode(name, xlen=32, **operands)


PROGRAM = (
    word('LUI', rd=5, imm=1),
    word('ADDI', rd=6, rs1=5, imm=5),
    word('ADD', rd=7, rs1=6, rs2=5),
    word('LW', rd=10, rs1=18, imm=4),
    word('SW', rs1=18, rs2=10, imm=8),
)


def record(text):
    return parse_record(text, windows=WINDOWS, arity=ARITY, f1_words=5)


def f1_text(words):
    return 'F1:' + ':'.join(format(value, '08x') for value in words)


def test_a_program_record_keeps_every_word_and_the_canonical_text():
    parsed = record(f1_text(PROGRAM))
    assert parsed['fields'] == PROGRAM
    assert parsed['text'] == f1_text(PROGRAM)
    assert parsed['message'] == 'CASE F1 ' + ' '.join(format(w, '08x') for w in PROGRAM)


def test_a_program_record_may_be_shorter_but_not_longer_than_declared():
    assert len(record(f1_text(PROGRAM[:2]))['fields']) == 2
    five = PROGRAM + (word('ADDI', rd=7, rs1=0, imm=1),)
    with pytest.raises(ValueError, match='needs 1 or 2 or 3 or 4'):
        parse_record(f1_text(five), windows=WINDOWS, arity=ARITY, f1_words=4)


def test_the_legacy_single_word_gate_is_unchanged():
    single = parse_record('F1:' + format(PROGRAM[0], '08x'), windows=WINDOWS,
                          arity=ARITY)
    assert single['fields'] == (PROGRAM[0],)
    assert validate_record(single, isa=ISA, windows=WINDOWS)['fields'] == (PROGRAM[0],)


def test_every_program_word_is_validated_and_the_legal_program_passes():
    parsed = record(f1_text(PROGRAM))
    # PROGRAM is five words, so the gate is asked for the declaration it parsed
    # under; the shared gate refuses a record longer than its declaration.
    assert validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=5)['flow'] == 'F1'


def test_subword_programs_require_explicit_opt_in_and_profile_isa():
    words = (word('LB', rd=5, rs1=18, imm=63),
             word('SH', rs1=18, rs2=5, imm=62))
    parsed = record(f1_text(words))
    with pytest.raises(ValueError, match='not LW or SW'):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4)
    assert validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4,
                           f1_subword=True) == parsed
    with pytest.raises(ValueError, match='xlen'):
        validate_record(parsed, isa=IsaContract(64, ('I',)), windows=WINDOWS,
                        f1_words=4, f1_subword=True)


def test_subword_program_gate_refuses_access_past_window():
    parsed = record(f1_text((word('LB', rd=5, rs1=18, imm=64),)))
    with pytest.raises(ValueError, match='window'):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4,
                        f1_subword=True)


@pytest.mark.parametrize('name,operands,match', [
    ('ADDI', dict(rd=8, rs1=0, imm=1), 'mailbox register x8'),
    ('ADDI', dict(rd=18, rs1=0, imm=1), 'data-window base register x18'),
    ('LW', dict(rd=8, rs1=18, imm=0), 'x8, x9 or x18'),
    ('ADDI', dict(rd=9, rs1=0, imm=1), 'slot base register x9'),
    ('LW', dict(rd=10, rs1=5, imm=0), 'must use x18'),
    ('LW', dict(rd=10, rs1=18, imm=PROGRAM_DATA_WORDS * 4), 'leaves the declared data window'),
    ('LB', dict(rd=10, rs1=18, imm=0), 'not LW or SW'),
    ('BEQ', dict(rs1=0, rs2=0, imm=8), 'control-flow'),
    ('JAL', dict(rd=0, imm=8), 'control-flow'),
])
def test_a_program_word_outside_the_trampoline_contract_is_refused(name, operands, match):
    words = PROGRAM[:2] + (word(name, **operands),)
    parsed = record(f1_text(words))
    with pytest.raises(ValueError, match=match):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4)


def test_an_m_word_on_an_i_only_profile_is_refused_by_the_isa_gate():
    parsed = record(f1_text((word('MUL', rd=7, rs1=6, rs2=5),)))
    with pytest.raises(ValueError, match='not legal for this profile'):
        validate_record(parsed, isa=IsaContract(32, ('I',)), windows=WINDOWS, f1_words=4)


def test_the_firmware_reserves_the_declared_program_and_points_x18_at_the_window():
    firmware = build_firmware(LAYOUT, irq=None, dma=None, interrupt_bootstrap=True,
                              f1_words=4)
    slot = firmware['images'][LAYOUT['slot']]
    assert len(slot) == 4 * 4 + 4
    assert firmware['f1_words'] == 4
    assert firmware['layout']['slot_return'] == firmware['slot_return']


def test_the_finalized_layout_states_the_real_return_label():
    firmware = build_firmware(LAYOUT, irq=None, dma=None, interrupt_bootstrap=True,
                              f1_words=2)
    assert firmware['layout']['slot_return'] == firmware['slot_return']
    assert firmware['slot_return'] > LAYOUT['main']
    assert firmware['slot_return'] % 4 == 0


def test_auipc_is_legal_in_program_mode_but_not_in_the_legacy_single_word_gate():
    auipc = word('AUIPC', rd=5, imm=1)
    program = record(f1_text((auipc, word('ADDI', rd=6, rs1=5, imm=7))))
    assert validate_record(program, isa=ISA, windows=WINDOWS, f1_words=4)['flow'] == 'F1'
    single = parse_record('F1:' + format(auipc, '08x'), windows=WINDOWS, arity=ARITY)
    with pytest.raises(ValueError):
        validate_record(single, isa=ISA, windows=WINDOWS)


def test_the_bounded_wait_length_is_validated_and_changes_the_image():
    irq = dict(port='irq', bit=0, trigger='level', polarity='active_high',
               pulse_ticks=0, status_offset=0, trigger_offsets=[0],
               status_kind='status', cause_declared=False, clear=None)
    with pytest.raises(ValueError, match='wait_iterations'):
        build_firmware(LAYOUT, irq=irq, dma=None, wait_iterations=0)
    with pytest.raises(ValueError, match='wait_iterations'):
        build_firmware(LAYOUT, irq=irq, dma=None, wait_iterations=2048)
    short = build_firmware(LAYOUT, irq=irq, dma=None, wait_iterations=16)
    long = build_firmware(LAYOUT, irq=irq, dma=None, wait_iterations=1024)
    assert short['images'][LAYOUT['main']] != long['images'][LAYOUT['main']]
    assert short['f1_words'] == long['f1_words'] == 1


def test_the_program_observation_keys_are_reported():
    keys = case_observation_keys('F1', 'apb3')
    for key in ('prog_words', 'prog_retires', 'prog_pc_ordered', 'prog_insns_match',
                'prog_rd_mask', 'prog_last_rd', 'prog_last_wdata', 'prog_traps',
                'data_hash_before', 'data_hash_after', 'data_changed'):
        assert key in keys


def program_case(status='observations_passed', successor=None, **override):
    words = len(PROGRAM)
    case = dict(index=0, flow='F1', record=f1_text(PROGRAM), status=status,
                fetch=LAYOUT['slot'], retire_pc=LAYOUT['slot'],
                retire_insn=PROGRAM[0], successor_pc=successor if successor is not None
                else LAYOUT['slot'] + 4 * words,
                prog_words=words, prog_retires=words, prog_pc_ordered=1,
                prog_insns_match=1, prog_traps=0)
    case.update(override)
    return case


def test_a_program_case_corresponds_when_every_word_retired():
    parsed = record(f1_text(PROGRAM))
    assert correspondence(parsed, program_case(), layout=LAYOUT, windows=WINDOWS,
                          irq=None, dma=None, bus='obi') is None


@pytest.mark.parametrize('override,match', [
    ({'prog_retires': 4}, 'retire every program word'),
    ({'prog_pc_ordered': 0}, 'address order'),
    ({'prog_insns_match': 0}, 'not installed'),
    ({'prog_traps': 1}, 'trapped'),
    ({'prog_words': 3}, 'length differs'),
    ({'successor_pc': LAYOUT['slot'] + 4}, 'no observed successor'),
])
def test_a_program_case_that_did_not_complete_is_mismatched(override, match):
    parsed = record(f1_text(PROGRAM))
    reason = correspondence(parsed, program_case(**override), layout=LAYOUT,
                            windows=WINDOWS, irq=None, dma=None, bus='obi')
    assert reason is not None and match in reason


def test_the_header_states_the_declared_case_tick_budget():
    from tests.integration.test_inprocess_f1f6_entry import (cpu_document, dma_document,
                                                             ip_document)
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                             LAYOUT, cpu_profile(), irq=None, dma=None, dma_irq=None,
                             case_tick_budget=12345)
    assert '#define CASE_TICK_BUDGET 12345u' in header


def test_the_header_states_the_declared_program_length_and_window():
    from tests.integration.test_inprocess_f1f6_entry import (ip_document, cpu_document,
                                                             dma_document)
    firmware = build_firmware(LAYOUT, irq=None, dma=None, interrupt_bootstrap=True,
                              f1_words=4)
    header = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                             LAYOUT, cpu_profile(), irq=None, dma=None, dma_irq=None,
                             f1_words=4)
    assert '#define F1_MAX_WORDS 4u' in header
    assert '#define PROGRAM_DATA_WORDS %du' % PROGRAM_DATA_WORDS in header
    assert '#define SLOT_RETURN %du' % firmware['slot_return'] in header


def cpu_profile():
    from myfuzz.composition.component_profile import load_component_profile
    return load_component_profile(ROOT / CONFIG['cpu_profile'])
