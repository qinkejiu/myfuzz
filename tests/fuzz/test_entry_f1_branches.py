"""Entry, strategy, host mirror and batch-status tests for F1 forward branches.

No RTL and no Verilator here.  Four kinds of facts are pinned:

  * the scenario flag reaches the gate, the generated header and ``f1_inputs``;
  * the strategy draws branch programs only after the declaration, and only
    trace-deterministic ones (a trace the reference model can state);
  * the entry's correspondence compares a branch case with the Python reference
    retirement trace (count, strictly increasing order, FNV-1a hash, successor,
    sampled data window) instead of the straight-line "every word retired" rule;
  * a trace mismatch fails the batch even when the host marked the case
    ``observations_passed``.

The C++ branch-target, trace-hash and provenance blocks are extracted between
their markers and compiled standalone, then compared with the Python authority.
The real fixed/fuzz branch batches live under ``runs/round1-f1-b/`` and are not
reproduced here.
"""
import json
import random
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from myfuzz.fuzz.f1_program_gate import (f1_gate_flags_from_scenario,
                                         f1_reference_expectation, trace_hash)
from myfuzz.fuzz.rv32_program import generate_program, mutate_program
from myfuzz.fuzz.strategy import FuzzStrategy, trace_deterministic
from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile
from scripts.run_inprocess_f1f6 import (PROGRAM_DATA_WORDS, apply_correspondence,
                                        build_layout, case_observation_keys,
                                        classify_case, correspondence,
                                        declared_windows, f1_window_hash,
                                        fuzz_collaborators, parse_record,
                                        render_bindings, validate_record)

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
BRANCH_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-zipdma-4w-branch-f1f6.json').read_text())
BRANCH_FUZZ_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-zipdma-4w-branch-fuzz.json').read_text())
WINDOWS = declared_windows(CONFIG, 16)
LAYOUT = build_layout(WINDOWS, 0x10080)
ISA = IsaContract(32, ('I', 'M'), instruction_alignment=4)
PROFILE = RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0)
ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
WINDOW = PROGRAM_DATA_WORDS * 4
BRANCH_FLAGS = dict(f1_program_words=4, f1_allow_branches=True)
#: The data window the firmware image really leaves at the F1 slot: the boot
#: stub published three words before any case ran.  The host prints the actual
#: sampled window per case, so this is only one realistic starting state.
DATA_WINDOW = (0xDEADBEEF, 0x11111111, 0x00000000) + (0,) * (PROGRAM_DATA_WORDS - 3)
ZERO_WINDOW = (0,) * PROGRAM_DATA_WORDS


def word(name, **operands):
    return encode(name, xlen=32, **operands)


#: The fixed batch's program: ADDI x5,1; BEQ x0,x0,+8; ADDI x6,0x55; ADDI x7,0x2a.
#: The branch skips the third word, so the real retirement sequence is three
#: words with PCs slot, slot+4, slot+12, and the successor is slot+16.
FIXED = (word('ADDI', rd=5, rs1=0, imm=1),
         word('BEQ', rs1=0, rs2=0, imm=8),
         word('ADDI', rd=6, rs1=0, imm=0x55),
         word('ADDI', rd=7, rs1=0, imm=0x2A))
#: A program with memory words: LW x5,0(x18); ADDI x6,x5,1; SW x6,8(x18).
MEMORY_PROGRAM = (word('LW', rd=5, rs1=18, imm=0),
                  word('ADDI', rd=6, rs1=5, imm=1),
                  word('SW', rs1=18, rs2=6, imm=8))


def f1_text(words):
    return 'F1:' + ':'.join(format(value, '08x') for value in words)


def record(words, f1_words=4):
    return parse_record(f1_text(words), windows=WINDOWS, arity=ARITY,
                        f1_words=f1_words)


def expectation_for(words, *, data_window=DATA_WINDOW):
    return f1_reference_expectation(
        {'flow': 'F1', 'fields': tuple(words)}, isa=ISA, window_bytes=WINDOW,
        flags=BRANCH_FLAGS, registers={18: LAYOUT['data_base']},
        memory={LAYOUT['data_base'] + 4 * index: value
                for index, value in enumerate(data_window)},
        data_base=LAYOUT['slot'])


def branch_case(words, *, data_window=DATA_WINDOW, **override):
    """The case line the C++ host would print for one branch program."""
    from scripts.run_inprocess_f1f6 import f1_rvfi_trace
    expectation = expectation_for(words, data_window=data_window)
    trace = f1_rvfi_trace(expectation)
    final = list(data_window)
    for address, value in expectation['memory_changes'].items():
        offset = address - LAYOUT['data_base']
        if 0 <= offset < WINDOW and offset % 4 == 0:
            final[offset // 4] = value
    case = dict(index=0, flow='F1', record=f1_text(words),
                status='observations_passed', fetch=LAYOUT['slot'],
                retire_pc=LAYOUT['slot'], retire_insn=words[0],
                successor_pc=LAYOUT['slot'] + 4 * len(words),
                prog_words=len(words),
                prog_retires=expectation['retired_count'],
                prog_pc_ordered=1, prog_insns_match=1,
                prog_trace_hash=int(trace_hash(trace).split(':')[1], 16),
                prog_trace_count=expectation['retired_count'], prog_pc_order=1,
                prog_traps=0, data_hash_before=f1_window_hash(data_window),
                data_hash_after=f1_window_hash(final),
                data_changed=sum(1 for before, after in zip(data_window, final)
                                 if before != after))
    case.update({'prog_data_%d' % index: value
                 for index, value in enumerate(data_window)})
    case.update(override)
    return case


def check(words, case, flags=BRANCH_FLAGS):
    return correspondence(record(words), case, layout=LAYOUT, windows=WINDOWS,
                          irq=None, dma=None, bus='obi', f1_flags=flags,
                          isa=ISA)


# ---------------------------------------------------------------------------
# The flag reaches the gate, the header and the saved fuzz inputs
# ---------------------------------------------------------------------------


def test_the_branch_flag_is_read_from_the_scenario_declaration():
    flags = f1_gate_flags_from_scenario(BRANCH_CONFIG)
    assert flags.allow_branches is True and flags.mode == 'branch'
    assert flags.as_dict()['f1_allow_branches'] is True
    off = f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=4))
    assert off.allow_branches is False and off.mode == 'legacy'
    for bad in (dict(CONFIG, f1_allow_branches='yes'),
                dict(CONFIG, f1_program_words=1, f1_allow_branches=True),
                dict(CONFIG, f1_program_words=4, f1_allow_branches=True,
                     f1_subword=True)):
        with pytest.raises(ValueError):
            f1_gate_flags_from_scenario(bad)


def test_the_header_states_the_declared_branch_fact():
    from tests.integration.test_inprocess_f1f6_entry import (cpu_document,
                                                             dma_document,
                                                             ip_document)
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(ROOT / CONFIG['cpu_profile'])
    on = render_bindings(BRANCH_CONFIG, cpu_document(), ip_document(),
                         dma_document(), LAYOUT, profile, irq=None, dma=None,
                         dma_irq=None, f1_words=4)
    assert '#define F1_ALLOW_BRANCHES 1' in on
    assert '#define F1_MAX_WORDS 4u' in on
    off = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                          LAYOUT, profile, irq=None, dma=None, dma_irq=None,
                          f1_words=1)
    assert '#define F1_ALLOW_BRANCHES 0' in off


def test_the_declared_fuzz_flow_subset_is_honoured_and_unknown_flows_are_refused():
    class _Address:
        registers = ()

    class _Profile:
        address = _Address()

    flags = f1_gate_flags_from_scenario(BRANCH_CONFIG)
    # Only F1 is declared servable here: the test is about the selection, and a
    # flow the declaration cannot serve must be refused by name.
    common = dict(base_dir=ROOT, windows=WINDOWS, arity={'F1': 1},
                  behavior_config={}, ip_profile=_Profile(), pins=None,
                  dma=None, f1_words=4, isa=ISA, refusals=None, label='APB',
                  seed=1, cases=4, seconds=None, output=None, f1_flags=flags)
    assert BRANCH_FUZZ_CONFIG['fuzz_flows'] == ['F1']
    f1_only = fuzz_collaborators(BRANCH_FUZZ_CONFIG, fuzz_flows=['F1'], **common)
    assert f1_only['document']['flows'] == ['F1']
    assert f1_only['document']['declared_flows'] == ['F1']
    with pytest.raises(ValueError, match='cannot serve'):
        fuzz_collaborators(BRANCH_FUZZ_CONFIG, fuzz_flows=['F9'], **common)
    with pytest.raises(ValueError, match='non-empty list'):
        fuzz_collaborators(BRANCH_FUZZ_CONFIG, fuzz_flows=['F1', 2], **common)


def test_the_saved_fuzz_inputs_state_the_branch_flag_and_reach_the_strategy():
    class _Address:
        registers = ()

    class _Profile:
        address = _Address()

    flags = f1_gate_flags_from_scenario(BRANCH_CONFIG)
    fuzz = fuzz_collaborators(
        BRANCH_CONFIG, base_dir=ROOT, windows=WINDOWS, arity={'F1': 1},
        behavior_config={}, ip_profile=_Profile(), pins=None, dma=None,
        f1_words=4, isa=ISA, refusals=None, label='APB', seed=1, cases=4,
        seconds=None, output=None, f1_flags=flags)
    document = fuzz['document']
    assert document['f1_flags']['f1_allow_branches'] is True
    assert document['f1_flags']['f1_program_words'] == 4
    assert fuzz['strategy'].f1_allow_branches is True


# ---------------------------------------------------------------------------
# The entry gate: branches are admitted only when declared, by name otherwise
# ---------------------------------------------------------------------------


def test_the_fixed_branch_program_passes_only_under_the_declared_flag():
    parsed = record(FIXED)
    assert validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4,
                           f1_flags=BRANCH_FLAGS)['flow'] == 'F1'
    with pytest.raises(ValueError, match='control-flow or system'):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4)
    with pytest.raises(ValueError, match='control-flow or system'):
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=4,
                        f1_flags={'f1_program_words': 4})


@pytest.mark.parametrize('words,match', [
    # a backward branch (=-8 bytes)
    ((word('ADDI', rd=5, rs1=0, imm=1),
      word('BEQ', rs1=0, rs2=0, imm=-8)), 'strictly forward'),
    # a branch past the appended return jump
    ((word('ADDI', rd=5, rs1=0, imm=1),
      word('BEQ', rs1=0, rs2=0, imm=16)), 'beyond the installed program'),
    # an unaligned displacement (2 bytes)
    ((word('ADDI', rd=5, rs1=0, imm=1), 0x00000163), 'not 4-byte aligned'),
    # funct3 2 is not one of the six branches
    ((word('ADDI', rd=5, rs1=0, imm=1), 0x00002063), 'not a B-type branch'),
    ((word('ADDI', rd=5, rs1=0, imm=1), word('JAL', rd=0, imm=8)),
     'control-flow or system'),
    ((word('ADDI', rd=5, rs1=0, imm=1), word('JALR', rd=0, rs1=0, imm=8)),
     'control-flow or system'),
    ((word('ADDI', rd=5, rs1=0, imm=1), 0x00000073), 'control-flow or system'),
    ((word('ADDI', rd=5, rs1=0, imm=1), 0x00004501), 'compressed'),
])
def test_a_control_transfer_outside_the_branch_rule_is_refused_by_name(words, match):
    # A compressed word is refused by ``parse_record`` before the gate, so the
    # record is built directly here to pin the gate's own refusal.
    raw = {'flow': 'F1', 'fields': tuple(words), 'text': f1_text(words),
           'message': 'CASE ' + f1_text(words).replace(':', ' ')}
    with pytest.raises(ValueError, match=match):
        validate_record(raw, isa=ISA, windows=WINDOWS, f1_words=8,
                        f1_flags={'f1_program_words': 8, 'f1_allow_branches': True})


def test_a_branch_to_the_appended_return_jump_is_a_legal_exit():
    words = (word('ADDI', rd=5, rs1=0, imm=1),
             word('BEQ', rs1=0, rs2=0, imm=4))
    assert validate_record(record(words), isa=ISA, windows=WINDOWS, f1_words=4,
                           f1_flags=BRANCH_FLAGS)['flow'] == 'F1'
    case = branch_case(words)
    assert case['prog_retires'] == 2
    assert check(words, case) is None, check(words, case)


# ---------------------------------------------------------------------------
# The fuzz strategy: branch programs are drawn only after the declaration
# ---------------------------------------------------------------------------


def _entry_gate(f1_words, flags):
    def gate(flow, fields):
        text = flow + ':' + ':'.join(format(int(value), '08x')
                                     for value in fields)
        parsed = parse_record(text, windows=WINDOWS, arity=ARITY,
                              f1_words=f1_words)
        validate_record(parsed, isa=ISA, windows=WINDOWS, f1_words=f1_words,
                        f1_flags=flags)
        return parsed['text'], parsed['message']
    return gate


def _has_branch(words):
    return any((word & 0x7F) == 0x63 for word in words)


def test_the_strategy_draws_branch_programs_only_after_the_declaration():
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(4, BRANCH_FLAGS),
        program_profile=PROFILE, f1_words=4, program_window=WINDOW, seed=7,
        f1_allow_branches=True)
    branches = 0
    for _ in range(12):
        fresh = strategy.fresh('F1')
        assert len(fresh.fields) >= 3
        assert _has_branch(fresh.fields), fresh.text
        assert trace_deterministic(fresh.fields), fresh.text
        mutated = strategy.mutate(fresh)
        assert trace_deterministic(mutated.fields), mutated.text
        assert len(mutated.fields) <= 4
        branches += int(_has_branch(mutated.fields))
    # A mutation may delete or replace the branch word, but it must stay a
    # trace-comparable program; most mutations keep the branch.
    assert branches >= 6, branches


def test_a_two_word_branch_declaration_still_draws_forward_branches():
    flags = {'f1_program_words': 2, 'f1_allow_branches': True}
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(2, flags), program_profile=PROFILE,
        f1_words=2, program_window=WINDOW, seed=3, f1_allow_branches=True)
    for _ in range(6):
        fresh = strategy.fresh('F1')
        assert len(fresh.fields) == 2 and _has_branch(fresh.fields), fresh.text
        assert trace_deterministic(fresh.fields), fresh.text


def test_a_flag_off_strategy_never_draws_a_branch():
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(4, {'f1_program_words': 4}),
        program_profile=PROFILE, f1_words=4, program_window=WINDOW, seed=7)
    for _ in range(30):
        assert not _has_branch(strategy.fresh('F1').fields)


def test_the_branch_flag_needs_program_mode_and_excludes_subword():
    with pytest.raises(ValueError, match='branch F1 needs program mode'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(1, {}),
                     program_profile=PROFILE, f1_words=1,
                     program_window=WINDOW, f1_allow_branches=True)
    with pytest.raises(ValueError, match='incompatible'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(4, {}),
                     program_profile=PROFILE, f1_words=4,
                     program_window=WINDOW, f1_subword=True,
                     f1_allow_branches=True)


def test_trace_deterministic_accepts_program_state_and_refuses_firmware_state():
    assert trace_deterministic(FIXED)
    # x5 is read before the program wrote it: firmware state, no expectation.
    assert not trace_deterministic((
        word('ADDI', rd=6, rs1=5, imm=1),
        word('ADDI', rd=7, rs1=0, imm=1),
        word('ADDI', rd=8, rs1=0, imm=1)))
    # The branch skips the only writer of x6, so the later read is firmware state.
    assert not trace_deterministic((
        word('ADDI', rd=5, rs1=0, imm=1),
        word('BEQ', rs1=0, rs2=0, imm=8),
        word('ADDI', rd=6, rs1=0, imm=9),
        word('ADD', rd=7, rs1=6, rs2=5)))
    # A load's destination is known: the host states the sampled window.
    assert trace_deterministic(MEMORY_PROGRAM)


def test_every_generated_branch_program_is_a_legal_record():
    deterministic = legal = 0
    for seed in range(16):
        program = generate_program(PROFILE, seed=seed, max_words=6,
                                   window_size=WINDOW, min_words=3,
                                   style='branch', allow_branches=True)
        assert _has_branch(program.words), (seed, program.words)
        validate_record(record(program.words, f1_words=6), isa=ISA,
                        windows=WINDOWS, f1_words=6,
                        f1_flags={'f1_program_words': 6,
                                  'f1_allow_branches': True})
        legal += 1
        deterministic += int(trace_deterministic(program.words))
    assert legal == 16
    # Most generated branch programs are trace-deterministic; the few that skip
    # the only writer of a later read register are legal records whose trace
    # would depend on firmware state, and the strategy refuses those draws.
    assert deterministic >= 10, deterministic


# ---------------------------------------------------------------------------
# Entry correspondence: the reference retirement trace is the authority
# ---------------------------------------------------------------------------


def test_the_fixed_branch_case_corresponds_with_three_retirements():
    case = branch_case(FIXED)
    assert case['prog_retires'] == 3 and case['prog_trace_count'] == 3
    assert case['successor_pc'] == LAYOUT['slot'] + 16
    assert check(FIXED, case) is None, check(FIXED, case)


def test_the_fixed_branch_expectation_is_the_documented_trace():
    expectation = expectation_for(FIXED)
    assert expectation['mode'] == 'branch'
    assert expectation['retired_count'] == 3
    assert expectation['pc_order'] == [LAYOUT['slot'], LAYOUT['slot'] + 4,
                                       LAYOUT['slot'] + 12]
    assert [entry['insn'] for entry in expectation['trace']] == [
        'ADDI', 'BEQ', 'ADDI']
    assert expectation['trace_hash'] == 'fnv1a32:d2403c87'


@pytest.mark.parametrize('override,match', [
    ({'prog_retires': 4}, 'retired 4 words'),
    ({'prog_trace_count': 2}, 'RVFI trace count'),
    ({'prog_trace_hash': 0}, 'RVFI trace hash'),
    ({'prog_pc_order': 0}, 'strictly increasing'),
    ({'prog_insns_match': 0}, 'not installed'),
    ({'successor_pc': LAYOUT['slot'] + 4}, 'no observed successor'),
    ({'prog_traps': 1}, 'trapped'),
    ({'data_hash_after': 0}, 'reference stores'),
    ({'data_changed': 3}, 'data_changed'),
])
def test_a_branch_case_that_differs_from_the_reference_is_mismatched(override, match):
    case = branch_case(FIXED)
    case.update(override)
    reason = check(FIXED, case)
    assert reason is not None and match in reason, reason


def test_a_tampered_sampled_window_breaks_the_window_binding():
    case = branch_case(FIXED)
    case['prog_data_0'] = 0x00000000
    assert 'does not hash to data_hash_before' in check(FIXED, case)
    # With a program that loads the window, the tampered word is a trace
    # difference too: the load's value comes from the sampled window.
    program = (word('LW', rd=5, rs1=18, imm=0),
               word('ADDI', rd=6, rs1=5, imm=1))
    good = branch_case(program)
    assert check(program, good) is None, check(program, good)
    good['prog_data_0'] = 0x00000000
    good['data_hash_before'] = f1_window_hash(
        (0,) + DATA_WINDOW[1:])
    assert check(program, good) is not None


def test_a_store_is_witnessed_by_the_sampled_window_not_the_trace():
    case = branch_case(MEMORY_PROGRAM)
    assert check(MEMORY_PROGRAM, case) is None, check(MEMORY_PROGRAM, case)
    # The RVFI trace carries no writeback for a store, so a wrong stored value
    # only shows in the after-window; the correspondence has to catch it.
    case['data_hash_after'] = f1_window_hash(DATA_WINDOW)
    assert 'reference stores' in check(MEMORY_PROGRAM, case)


def test_the_straight_line_criteria_are_unchanged_when_branches_are_off():
    program = (word('ADDI', rd=5, rs1=0, imm=1),
               word('ADDI', rd=6, rs1=0, imm=2),
               word('ADDI', rd=7, rs1=0, imm=3))
    legacy = {'f1_program_words': 4}
    case = dict(index=0, flow='F1', record=f1_text(program),
                status='observations_passed', fetch=LAYOUT['slot'],
                retire_pc=LAYOUT['slot'], retire_insn=program[0],
                successor_pc=LAYOUT['slot'] + 12, prog_words=3,
                prog_retires=3, prog_pc_ordered=1, prog_insns_match=1,
                prog_traps=0)
    assert check(program, case, flags=legacy) is None
    assert 'did not retire every program word' in check(
        program, dict(case, prog_retires=2), flags=legacy)


def test_the_branch_observation_keys_are_reported():
    keys = case_observation_keys('F1', 'apb3')
    for key in ('prog_trace_hash', 'prog_trace_count', 'prog_pc_order',
                'prog_retires', 'prog_insns_match'):
        assert key in keys


def test_the_classifier_uses_the_branch_retirement_facts():
    branch = dict(flow='F1', status='failed', prog_words=4, prog_retires=3,
                  prog_trace_count=3, prog_pc_order=1, prog_insns_match=1,
                  prog_pc_ordered=1)
    assert classify_case(branch)['failure_class'] == 'observation_mismatch'
    anomaly = classify_case(dict(branch, prog_pc_order=0))
    assert anomaly['failure_class'] == 'execution_anomaly'
    mismatch = classify_case(dict(branch, prog_trace_count=2))
    assert mismatch['failure_class'] == 'execution_anomaly'
    # Without the branch facts the straight-line rule still applies.
    legacy = classify_case(dict(flow='F1', status='failed', prog_words=4,
                                prog_retires=3, prog_pc_ordered=1,
                                prog_insns_match=1))
    assert legacy['failure_class'] == 'execution_anomaly'


# ---------------------------------------------------------------------------
# A correspondence mismatch is a batch failure, not only a recorded remark
# ---------------------------------------------------------------------------


def test_a_wrong_branch_trace_fails_the_batch():
    parsed = dict(cases=[dict(status='observations_passed')],
                  summary=dict(status='observations_passed'))
    result = dict(returncode=0)
    apply_correspondence(
        result, parsed, [record(FIXED)],
        ['F1 RVFI trace hash fnv1a32:00000000 differs from the reference '
         'fnv1a32:d2403c87'])
    assert result['status'] == 'failed'
    assert result['failure'].startswith('correspondence:')
    assert 'trace hash' in result['failure']


def test_a_matching_branch_case_keeps_the_passing_status():
    parsed = dict(cases=[dict(status='observations_passed')],
                  summary=dict(status='observations_passed'))
    result = dict(returncode=0)
    apply_correspondence(result, parsed, [record(FIXED)], [None])
    assert result['status'] == 'observations_passed'
    assert 'failure' not in result


def test_a_host_failed_case_still_fails_the_batch():
    parsed = dict(cases=[dict(status='failed')], summary=dict(status='failed'))
    result = dict(returncode=0)
    apply_correspondence(result, parsed, [record(FIXED)], [None])
    assert result['status'] == 'failed'


# ---------------------------------------------------------------------------
# The C++ host mirror: branch target, trace hash and provenance with branches
# ---------------------------------------------------------------------------

_HARNESS = '''#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
{blocks}
int main(int argc, char **argv) {{
  if (argc < 2) return 2;
  const std::string mode = argv[1];
  if (mode == "provenance") {{
    if (argc < 4) return 2;
    const unsigned window = unsigned(std::strtoul(argv[2], nullptr, 0));
    std::vector<uint32_t> words;
    for (int index = 3; index < argc; ++index)
      words.push_back(uint32_t(std::strtoul(argv[index], nullptr, 16)));
    const f1_provenance::Result result =
        f1_provenance::check(words.data(), unsigned(words.size()), window);
    std::printf("ok=%d index=%u message=%s\\n", int(result.ok), result.index,
                result.message.c_str());
    return 0;
  }}
  if (mode == "branch") {{
    if (argc < 4) return 2;
    const unsigned count = unsigned(std::strtoul(argv[2], nullptr, 0));
    const uint32_t slot = uint32_t(std::strtoul(argv[3], nullptr, 0));
    for (int index = 4; index < argc; ++index) {{
      const uint32_t value = uint32_t(std::strtoul(argv[index], nullptr, 16));
      if ((value & 0x7fu) != 0x63u) continue;
      const unsigned position = unsigned(index - 4);
      const f1_branch::Result result =
          f1_branch::check(value, position, count, slot);
      std::printf("ok=%d target=0x%08x message=%s\\n", int(result.ok),
                  result.target, result.message.c_str());
    }}
    return 0;
  }}
  if (mode == "trace") {{
    uint32_t hash = f1_trace::offset_basis();
    for (int index = 2; index + 3 < argc; index += 4)
      hash = f1_trace::entry(hash,
                             uint32_t(std::strtoul(argv[index], nullptr, 16)),
                             uint32_t(std::strtoul(argv[index + 1], nullptr, 16)),
                             uint32_t(std::strtoul(argv[index + 2], nullptr, 16)),
                             uint32_t(std::strtoul(argv[index + 3], nullptr, 16)));
    std::printf("hash=0x%08x\\n", hash);
    return 0;
  }}
  return 2;
}}
'''


def _marked_block(name):
    source = HOST.read_text()
    begin = source.index('// BEGIN ' + name)
    end = source.index('// END ' + name)
    return source[begin:end + len('// END ' + name)]


@pytest.fixture(scope='module')
def mirror(tmp_path_factory):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('g++ is required for the C++ branch mirror')
    directory = tmp_path_factory.mktemp('f1-branch-mirror')
    harness = directory / 'mirror.cpp'
    harness.write_text(_HARNESS.format(blocks='\n'.join(
        _marked_block(name) for name in
        ('F1_ADDRESS_PROVENANCE', 'F1_BRANCH_TARGET', 'F1_TRACE_HASH'))))
    binary = directory / 'mirror'
    completed = subprocess.run(
        [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O2',
         str(harness), '-o', str(binary)],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    return binary


def _run_mirror(binary, *arguments):
    completed = subprocess.run([str(binary), *map(str, arguments)],
                               capture_output=True, text=True, check=True)
    return completed.stdout.splitlines()


def test_the_mirror_admits_every_generated_branch_target(mirror):
    accepted = 0
    for seed in range(16):
        program = generate_program(PROFILE, seed=seed, max_words=6,
                                   window_size=WINDOW, min_words=3,
                                   style='branch', allow_branches=True)
        lines = _run_mirror(mirror, 'branch', len(program.words),
                            hex(LAYOUT['slot']),
                            *[format(value, '08x') for value in program.words])
        for index, line in enumerate(lines):
            assert line.startswith('ok=1'), (seed, index, line, program.words)
            accepted += 1
        assert accepted
    # Every generated program is legal, so the agreement is on the accepting
    # side; the named refusals are pinned below.
    assert accepted >= 16


@pytest.mark.parametrize('encoded,match', [
    (word('BEQ', rs1=0, rs2=0, imm=-8), 'backward'),
    (0x00000163, '4-byte aligned'),
    (0x00002063, 'funct3 2'),
    (word('BEQ', rs1=0, rs2=0, imm=4), None),
])
def test_the_mirror_refuses_the_same_branch_words_by_name(mirror, encoded, match):
    lines = _run_mirror(mirror, 'branch', 2, hex(LAYOUT['slot']),
                        format(word('ADDI', rd=5, rs1=0, imm=1), '08x'),
                        format(encoded, '08x'))
    ok, _, message = lines[0].partition(' target=')
    assert (ok == 'ok=1') is (match is None), (encoded, lines[0])
    if match is not None:
        assert match in message, message


def test_the_mirror_refuses_a_target_past_the_installed_image(mirror):
    # A 2-word program: the only legal target is the appended return jump at
    # index 2; +8 would reach index 3, outside the image.
    lines = _run_mirror(mirror, 'branch', 2, hex(LAYOUT['slot']),
                        format(word('ADDI', rd=5, rs1=0, imm=1), '08x'),
                        format(word('BEQ', rs1=0, rs2=0, imm=8), '08x'))
    assert lines[0].startswith('ok=0')
    assert 'outside the installed image' in lines[0]


def test_the_trace_hash_mirror_matches_the_python_authority(mirror):
    rng = random.Random(20261112)
    for _ in range(8):
        trace = [dict(pc=rng.getrandbits(32), insn='?',
                      insn_word=rng.getrandbits(32), rd=rng.randrange(32),
                      wdata=rng.getrandbits(32)) for _ in range(rng.randrange(0, 6))]
        lines = _run_mirror(
            mirror, 'trace',
            *[format(value, '08x')
              for entry in trace
              for value in (entry['pc'], entry['insn_word'], entry['rd'],
                            entry['wdata'])])
        expected = trace_hash(trace)[len('fnv1a32:'):]
        assert lines[0] == 'hash=0x' + expected, (trace, lines)


def test_the_provenance_pass_treats_a_branch_as_writing_no_register(mirror):
    # A branch's bits 11:7 are immediate bits, not a destination: this legal
    # +12 branch has 12 in those bits, so a pass that read them as ``rd`` would
    # clear x12's state (and, with the old code, mis-track every branch).
    branch = word('BEQ', rs1=0, rs2=0, imm=12)
    assert ((branch >> 7) & 31) == 12
    words = (word('ADDI', rd=6, rs1=18, imm=8), branch,
             word('ADDI', rd=10, rs1=0, imm=1),
             word('LW', rd=7, rs1=6, imm=0))
    assert _run_mirror(mirror, 'provenance', PROGRAM_DATA_WORDS,
                       *[format(value, '08x') for value in words])[0].startswith(
        'ok=1')
    from myfuzz.fuzz.rv32_program import validate_program_words
    validate_program_words(PROFILE, words, window_size=WINDOW,
                           allow_branches=True, allow_address_forms=True)
    # At the merge the two paths disagree (window(8,8) vs const 4), so the base
    # is not a proven data-window address and both authorities refuse it.
    merge = (word('ADDI', rd=5, rs1=18, imm=8),
             word('BEQ', rs1=0, rs2=0, imm=8),
             word('ADDI', rd=5, rs1=0, imm=4),
             word('LW', rd=6, rs1=5, imm=0))
    lines = _run_mirror(mirror, 'provenance', PROGRAM_DATA_WORDS,
                        *[format(value, '08x') for value in merge])
    assert lines[0].startswith('ok=0')
    assert 'statically proven' in lines[0]
    with pytest.raises(ValueError, match='statically proven'):
        validate_program_words(PROFILE, merge, window_size=WINDOW,
                               allow_branches=True, allow_address_forms=True)


def test_the_host_still_refuses_the_out_of_scope_shapes_by_name():
    source = HOST.read_text()
    assert re.search(r'#define F1_ALLOW_BRANCHES 0', source)
    assert 'is a branch; the trampoline program is ' in source
    assert 'unsupported-f1:no-rvfi-writeback:branch-trace-unobservable' in source
    assert 'F1 branch ' in source and 'only strictly forward branches are admitted' in source
