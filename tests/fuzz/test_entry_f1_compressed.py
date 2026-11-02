"""Entry, strategy, host mirror and batch-status tests for compressed F1 records.

No RTL and no Verilator here.  Five kinds of facts are pinned:

  * the scenario flag reaches the gate, the generated header and ``f1_inputs``;
    ``f1_allow_compressed`` is mutually exclusive with the computed-base address
    forms and with the subword widths;
  * the record gate admits a record word whose bits [1:0] are not ``11`` as two
    16-bit parcels (the low one at pc, the high one at pc + 2), refuses every
    compressed control/memory/stack/system/RV64 form by name, refuses a 32-bit
    instruction that would straddle a record word, and admits a *mixed* image
    whose 32-bit words follow the ordinary straight-line rules;
  * the strategy draws compressed programs only after the declaration, and only
    programs whose parcel-level retirement trace is decided by the state the
    entry can declare (``x0``, ``x18`` and the sampled data window);
  * the entry's correspondence compares a compressed case with the Python
    reference trace (count, order, FNV-1a hash over the 16-bit parcels, the
    successor at ``slot + 4 * words``) instead of the straight-line "every
    installed word retired" rule, and a mismatch fails the batch;
  * the C++ parcel block is extracted between its markers and compiled
    standalone, then compared exhaustively with
    :func:`myfuzz.fuzz.rv32_compressed.decode_compressed_parcel`.

The real fixed/fuzz compressed batches live under ``runs/round1-f1-c/`` and are
not reproduced here.
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
from myfuzz.fuzz.rv32_compressed import (decode_compressed_parcel,
                                         generate_compressed_program,
                                         image_instructions, pack_parcels,
                                         validate_compressed_program)
from myfuzz.fuzz.strategy import (FuzzStrategy, compressed_trace_deterministic,
                                  trace_deterministic)
from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile
from scripts.run_inprocess_f1f6 import (PROGRAM_DATA_WORDS, apply_correspondence,
                                        build_layout, case_observation_keys,
                                        classify_case, correspondence,
                                        declared_windows, f1_rvfi_trace,
                                        f1_window_hash, fuzz_collaborators,
                                        parse_record, render_bindings,
                                        validate_record)

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
COMPRESSED_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-zipdma-4w-compressed-f1f6.json').read_text())
COMPRESSED_FUZZ_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-zipdma-4w-compressed-fuzz.json').read_text())
WINDOWS = declared_windows(CONFIG, 16)
LAYOUT = build_layout(WINDOWS, 0x10080)
ISA = IsaContract(32, ('I', 'M'), instruction_alignment=4)
ISA_C = IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)
PROFILE = RiscvProfile(32, frozenset(('I', 'M', 'C')), 2, 32, 0)
ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
WINDOW = PROGRAM_DATA_WORDS * 4
COMPRESSED_FLAGS = dict(f1_program_words=4, f1_allow_compressed=True)
#: The window the firmware image leaves at the F1 slot (the boot stub published
#: three words before any case ran).  The host prints the sampled window per
#: case, so this is only one realistic starting state.
DATA_WINDOW = (0xDEADBEEF, 0x11111111, 0x00000000) + (0,) * (PROGRAM_DATA_WORDS - 3)


def parcel(name, **operands):
    return encode(name, xlen=32, **operands)


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def pair(low, high):
    return pack_parcels(low, high)


#: The fixed batch's program (``runs/round1-f1-c/fixed-compressed``): four record
#: words, eight parcels, every read satisfied by a write earlier in the image.
#:
#:   0: C.LI x12,5        C.LI x13,3
#:   1: C.ADDI x12,7      C.MV  x14,x12
#:   2: C.ADD x14,x13     C.ANDI x12,15
#:   3: C.ADDI x13,-1     C.SUB x14,x13
PARCELS = (parcel('C.LI', rd=12, imm=5),
           parcel('C.LI', rd=13, imm=3),
           parcel('C.ADDI', rd=12, imm=7),
           parcel('C.MV', rd=14, rs2=12),
           parcel('C.ADD', rd=14, rs2=13),
           parcel('C.ANDI', rd=12, imm=15),
           parcel('C.ADDI', rd=13, imm=-1),
           parcel('C.SUB', rd=14, rs2=13))
FIXED = tuple(pair(PARCELS[index], PARCELS[index + 1])
              for index in range(0, len(PARCELS), 2))
#: A mixed image: a whole 32-bit ADDI, two pair words, and a whole 32-bit ADDI.
MIXED = (word('ADDI', rd=12, rs1=0, imm=5),
         pair(parcel('C.LI', rd=13, imm=3),
              parcel('C.ADDI', rd=13, imm=4)),
         pair(parcel('C.MV', rd=14, rs2=12),
              parcel('C.ADD', rd=14, rs2=13)),
         word('ADDI', rd=5, rs1=0, imm=9))


def f1_text(words):
    return 'F1:' + ':'.join(format(value, '08x') for value in words)


def record(words, f1_words=4, compressed=True):
    return parse_record(f1_text(words), windows=WINDOWS, arity=ARITY,
                        f1_words=f1_words, f1_allow_compressed=compressed)


def expectation_for(words, *, data_window=DATA_WINDOW, flags=COMPRESSED_FLAGS):
    return f1_reference_expectation(
        {'flow': 'F1', 'fields': tuple(words)}, isa=ISA_C, window_bytes=WINDOW,
        flags=flags, registers={18: LAYOUT['data_base']},
        memory={LAYOUT['data_base'] + 4 * index: value
                for index, value in enumerate(data_window)},
        data_base=LAYOUT['slot'])


def first_instruction(word_value):
    """The first instruction of one record word: low parcel or whole word."""
    return (word_value & 0xFFFF) if (word_value & 3) != 3 else word_value


def compressed_case(words, *, data_window=DATA_WINDOW, **override):
    """The case line the C++ host would print for one compressed program."""
    expectation = expectation_for(words, data_window=data_window)
    trace = f1_rvfi_trace(expectation)
    final = list(data_window)
    for address, value in expectation['memory_changes'].items():
        offset = address - LAYOUT['data_base']
        if 0 <= offset < WINDOW and offset % 4 == 0:
            final[offset // 4] = value
    case = dict(index=0, flow='F1', record=f1_text(words),
                status='observations_passed', fetch=LAYOUT['slot'],
                retire_pc=LAYOUT['slot'],
                retire_insn=first_instruction(words[0]),
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


def check(words, case, flags=COMPRESSED_FLAGS):
    return correspondence(record(words), case, layout=LAYOUT, windows=WINDOWS,
                          irq=None, dma=None, bus='obi', f1_flags=flags,
                          isa=ISA_C)


# ---------------------------------------------------------------------------
# The flag reaches the gate, the header and the saved fuzz inputs
# ---------------------------------------------------------------------------


def test_the_compressed_flag_is_read_from_the_scenario_declaration():
    flags = f1_gate_flags_from_scenario(COMPRESSED_CONFIG)
    assert flags.allow_compressed is True and flags.mode == 'compressed'
    assert flags.as_dict()['f1_allow_compressed'] is True
    off = f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=4))
    assert off.allow_compressed is False and off.mode == 'legacy'
    for bad in (dict(CONFIG, f1_allow_compressed='yes'),
                dict(CONFIG, f1_program_words=1, f1_allow_compressed=True),
                dict(CONFIG, f1_program_words=4, f1_allow_compressed=True,
                     f1_allow_address_forms=True),
                dict(CONFIG, f1_program_words=4, f1_allow_compressed=True,
                     f1_subword=True)):
        with pytest.raises(ValueError):
            f1_gate_flags_from_scenario(bad)


def test_the_compressed_and_address_form_flags_are_refused_together_by_name():
    with pytest.raises(ValueError, match='incompatible'):
        f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=4,
                                         f1_allow_compressed=True,
                                         f1_allow_address_forms=True))
    with pytest.raises(ValueError, match='f1_subword is incompatible'):
        f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=4,
                                         f1_allow_compressed=True,
                                         f1_subword=True))
    with pytest.raises(ValueError, match='f1_program_words > 1'):
        f1_gate_flags_from_scenario(dict(CONFIG, f1_program_words=1,
                                         f1_allow_compressed=True))


def test_the_header_states_the_declared_compressed_fact():
    from tests.integration.test_inprocess_f1f6_entry import (cpu_document,
                                                             dma_document,
                                                             ip_document)
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(ROOT / CONFIG['cpu_profile'])
    on = render_bindings(COMPRESSED_CONFIG, cpu_document(), ip_document(),
                         dma_document(), LAYOUT, profile, irq=None, dma=None,
                         dma_irq=None, f1_words=4)
    assert '#define F1_ALLOW_COMPRESSED 1' in on
    assert '#define F1_MAX_WORDS 4u' in on
    off = render_bindings(CONFIG, cpu_document(), ip_document(), dma_document(),
                          LAYOUT, profile, irq=None, dma=None, dma_irq=None,
                          f1_words=1)
    assert '#define F1_ALLOW_COMPRESSED 0' in off


def test_the_saved_fuzz_inputs_state_the_compressed_flag_and_reach_the_strategy():
    class _Address:
        registers = ()

    class _Profile:
        address = _Address()

    flags = f1_gate_flags_from_scenario(COMPRESSED_CONFIG)
    fuzz = fuzz_collaborators(
        COMPRESSED_FUZZ_CONFIG, base_dir=ROOT, windows=WINDOWS, arity={'F1': 1},
        behavior_config={}, ip_profile=_Profile(), pins=None, dma=None,
        f1_words=4, isa=ISA_C, refusals=None, label='APB', seed=1, cases=4,
        seconds=None, output=None, f1_flags=flags, fuzz_flows=['F1'])
    document = fuzz['document']
    assert document['f1_flags']['f1_allow_compressed'] is True
    assert document['f1_flags']['f1_program_words'] == 4
    assert document['f1_flags']['f1_allow_address_forms'] is False
    assert fuzz['strategy'].f1_allow_compressed is True


# ---------------------------------------------------------------------------
# The record gate: two parcels per word, refused shapes named
# ---------------------------------------------------------------------------


def test_the_fixed_compressed_program_passes_only_under_the_declared_flag():
    parsed = record(FIXED)
    assert validate_record(parsed, isa=ISA_C, windows=WINDOWS, f1_words=4,
                           f1_flags=COMPRESSED_FLAGS)['flow'] == 'F1'
    # Without the declaration the lexical record parser refuses the word first.
    with pytest.raises(ValueError, match='must be one 32-bit instruction word'):
        record(FIXED, compressed=False)
    # And the shape gate refuses the same record when only the word count is
    # declared (the historical straight-line program mode).
    with pytest.raises(ValueError, match='is not one 32-bit word'):
        validate_record(parsed, isa=ISA_C, windows=WINDOWS, f1_words=4,
                        f1_flags={'f1_program_words': 4})
    with pytest.raises(ValueError, match='is not one 32-bit word'):
        validate_record(parsed, isa=ISA_C, windows=WINDOWS, f1_words=4)


def test_every_record_word_must_hold_two_admitted_parcels():
    # A legal pair word followed by a word whose high parcel is illegal: the
    # second word is what the gate must refuse, at its high half.
    words = (FIXED[0], pair(parcel('C.LI', rd=12, imm=1), 0x0000))
    with pytest.raises(ValueError,
                       match='record word 1 high parcel at pc\\+2'):
        validate_record({'flow': 'F1', 'fields': words}, isa=ISA_C,
                        windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)
    # The same pair with both halves admitted passes.
    words = (FIXED[0], pair(parcel('C.LI', rd=12, imm=1),
                            parcel('C.ADDI', rd=12, imm=2)))
    validate_record({'flow': 'F1', 'fields': words}, isa=ISA_C, windows=WINDOWS,
                    f1_words=4, f1_flags=COMPRESSED_FLAGS)


#: One refused 16-bit parcel per row, and the name the refusal must carry.  The
#: parcel is the *low* half of the second record word, so the image really does
#: contain the encoding at pc+4.
REFUSED_PARCELS = [
    (0xA001, 'compressed control transfer C.J'),
    (0x2001, 'compressed control transfer C.JAL'),
    (0xC001, 'compressed control transfer C.BEQZ'),
    (0xE001, 'compressed control transfer C.BNEZ'),
    (0x8002, 'compressed control transfer C.JR'),
    (0x9082, 'compressed control transfer C.JALR'),
    (0x4008, 'compressed memory instruction C.LW'),
    (0xC008, 'compressed memory instruction C.SW'),
    (0x4002, 'compressed memory instruction C.LWSP'),
    (0xC006, 'compressed memory instruction C.SWSP'),
    (0x6008, 'compressed memory instruction C.LD'),
    (0x2002, 'compressed memory instruction C.FLDSP'),
    (0x0000, 'compressed form C.ADDI4SPN'),
    (0x6101, 'compressed form C.ADDI16SP'),
    (0x9002, 'compressed form C.EBREAK'),
    (0x9C01, 'compressed word forms C.SUBW/C.ADDW require RV64'),
]


@pytest.mark.parametrize('parcel_value,match', REFUSED_PARCELS)
def test_a_compressed_control_memory_or_system_parcel_is_refused_by_name(parcel_value, match):
    words = (FIXED[0], pair(parcel_value, 0x4615))
    with pytest.raises(ValueError, match=re.escape(match)):
        validate_record({'flow': 'F1', 'fields': words}, isa=ISA_C,
                        windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)


def test_a_32_bit_instruction_may_not_straddle_a_record_word():
    # The high half starts a 32-bit-length encoding at pc+2: the only way this
    # layout could place an instruction at an odd (unaligned) PC.
    straddle = (FIXED[0] & 0xFFFF) | (0x0003 << 16)
    with pytest.raises(ValueError, match='may not straddle a record word'):
        validate_record({'flow': 'F1', 'fields': (straddle,)}, isa=ISA_C,
                        windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)
    # A 32-bit-length low half makes the whole record word one 32-bit
    # instruction: ADDI x12,x0,5 occupies the word and executes at pc.
    whole = word('ADDI', rd=12, rs1=0, imm=5)
    assert whole & 3 == 3
    validate_record({'flow': 'F1', 'fields': (whole,)}, isa=ISA_C,
                    windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)


#: The HINT encodings are written as their raw 16-bit parcels: the project's
#: encoder refuses to produce them, but a record handed to the host can carry one
#: and the gate has to refuse it by name.
@pytest.mark.parametrize('parcel_value,match', [
    (parcel('C.LI', rd=9, imm=1), 'outside the admitted x12..x15 range'),
    (parcel('C.ADDI', rd=8, imm=1), 'outside the admitted x12..x15 range'),
    (parcel('C.SLLI', rd=16, shamt=1), 'outside the admitted x12..x15 range'),
    (0x0601, 'C.ADDI with a zero immediate is a HINT and is refused'),
    (0x8201, 'C.SRLI with a zero shift amount is a HINT and is refused'),
    (0x0000, 'compressed form C.ADDI4SPN is refused'),
])
def test_a_parcel_outside_the_safe_subset_is_refused(parcel_value, match):
    with pytest.raises(ValueError, match=re.escape(match)):
        validate_record({'flow': 'F1', 'fields': (FIXED[0], pair(parcel_value, 0x4615))},
                        isa=ISA_C, windows=WINDOWS, f1_words=4,
                        f1_flags=COMPRESSED_FLAGS)


def test_a_compressed_record_needs_a_c_capable_isa():
    with pytest.raises(ValueError, match='requires the C extension'):
        validate_record(record(FIXED), isa=ISA, windows=WINDOWS, f1_words=4,
                        f1_flags=COMPRESSED_FLAGS)


def test_a_mixed_image_holds_whole_32_bit_words_beside_pair_words():
    parsed = record(MIXED)
    validate_record(parsed, isa=ISA_C, windows=WINDOWS, f1_words=4,
                    f1_flags=COMPRESSED_FLAGS)
    expectation = expectation_for(MIXED)
    assert expectation['retired_count'] == 6
    assert [entry['insn_word'] for entry in expectation['trace']] == list(MIXED[:1]) + [
        parcel('C.LI', rd=13, imm=3), parcel('C.ADDI', rd=13, imm=4),
        parcel('C.MV', rd=14, rs2=12), parcel('C.ADD', rd=14, rs2=13)] + list(MIXED[3:])
    # A mixed image's 32-bit words keep the straight-line rules: an LW against
    # x18 is admitted, a computed base is not (address forms are not declared).
    with_memory = MIXED[:3] + (word('LW', rd=15, rs1=18, imm=0),)
    validate_record({'flow': 'F1', 'fields': with_memory}, isa=ISA_C,
                    windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)
    computed = MIXED[:3] + (word('LW', rd=15, rs1=5, imm=0),)
    with pytest.raises(ValueError, match='must use x18'):
        validate_record({'flow': 'F1', 'fields': computed}, isa=ISA_C,
                        windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)


def test_a_branch_word_is_refused_without_the_branch_declaration():
    words = (FIXED[0], word('BEQ', rs1=0, rs2=0, imm=4))
    with pytest.raises(ValueError, match='control-flow or system'):
        validate_record({'flow': 'F1', 'fields': words}, isa=ISA_C,
                        windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)
    # With the branch declared the same word is a legal 32-bit member of the
    # mixed image (compressed and branches are not mutually exclusive).
    validate_record({'flow': 'F1', 'fields': words}, isa=ISA_C,
                    windows=WINDOWS, f1_words=4,
                    f1_flags={'f1_program_words': 4, 'f1_allow_compressed': True,
                              'f1_allow_branches': True})


# ---------------------------------------------------------------------------
# The fuzz strategy: compressed programs are drawn only after the declaration
# ---------------------------------------------------------------------------


def _entry_gate(f1_words, flags):
    def gate(flow, fields):
        text = flow + ':' + ':'.join(format(int(value), '08x')
                                     for value in fields)
        parsed = parse_record(text, windows=WINDOWS, arity=ARITY,
                              f1_words=f1_words, f1_allow_compressed=True)
        validate_record(parsed, isa=ISA_C, windows=WINDOWS, f1_words=f1_words,
                        f1_flags=flags)
        return parsed['text'], parsed['message']
    return gate


def _has_parcel(words):
    return any((word & 3) != 3 for word in words)


def test_the_strategy_draws_compressed_programs_only_after_the_declaration():
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(4, COMPRESSED_FLAGS),
        program_profile=PROFILE, f1_words=4, program_window=WINDOW, seed=7,
        f1_allow_compressed=True)
    for _ in range(10):
        fresh = strategy.fresh('F1')
        assert 1 <= len(fresh.fields) <= 4
        assert _has_parcel(fresh.fields), fresh.text
        assert compressed_trace_deterministic(fresh.fields), fresh.text
        mutated = strategy.mutate(fresh)
        assert _has_parcel(mutated.fields), mutated.text
        assert compressed_trace_deterministic(mutated.fields), mutated.text
        assert len(mutated.fields) <= 4


def test_a_flag_off_strategy_never_draws_a_parcel():
    strategy = FuzzStrategy(
        flows=('F1',), gate=_entry_gate(4, {'f1_program_words': 4}),
        program_profile=PROFILE, f1_words=4, program_window=WINDOW, seed=7)
    for _ in range(30):
        assert not _has_parcel(strategy.fresh('F1').fields)


def test_the_compressed_flag_needs_program_mode_a_c_profile_and_no_other_shape():
    with pytest.raises(ValueError, match='compressed F1 needs program mode'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(1, {}),
                     program_profile=PROFILE, f1_words=1,
                     program_window=WINDOW, f1_allow_compressed=True)
    with pytest.raises(ValueError, match='declares the C extension'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(4, {}),
                     program_profile=RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0),
                     f1_words=4, program_window=WINDOW,
                     f1_allow_compressed=True)
    with pytest.raises(ValueError, match='incompatible'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(4, {}),
                     program_profile=PROFILE, f1_words=4,
                     program_window=WINDOW, f1_subword=True,
                     f1_allow_compressed=True)
    with pytest.raises(ValueError, match='incompatible'):
        FuzzStrategy(flows=('F1',), gate=_entry_gate(4, {}),
                     program_profile=PROFILE, f1_words=4,
                     program_window=WINDOW, f1_allow_address_forms=True,
                     f1_allow_compressed=True)


def test_compressed_trace_deterministic_accepts_written_registers_only():
    assert compressed_trace_deterministic(FIXED)
    assert compressed_trace_deterministic(MIXED)
    # C.ADDI x12,7 as the first instruction reads firmware x12: the trace would
    # not be comparable, even though the record itself is legal.
    firmware_read = (pair(parcel('C.ADDI', rd=12, imm=7),
                          parcel('C.LI', rd=13, imm=1)),)
    assert not compressed_trace_deterministic(firmware_read)
    validate_record({'flow': 'F1', 'fields': firmware_read}, isa=ISA_C,
                    windows=WINDOWS, f1_words=4, f1_flags=COMPRESSED_FLAGS)
    # A C.MV reads only its source, so writing x14 first makes it decidable.
    assert compressed_trace_deterministic((
        pair(parcel('C.LI', rd=12, imm=1), parcel('C.LI', rd=13, imm=2)),
        pair(parcel('C.MV', rd=14, rs2=13), parcel('C.ADD', rd=14, rs2=12))))
    # A 32-bit branch is path-dependent and is not offered by this analysis.
    assert not compressed_trace_deterministic(
        (word('BEQ', rs1=0, rs2=0, imm=4),))


def test_every_generated_compressed_program_is_a_legal_record():
    deterministic = 0
    for seed in range(16):
        program = generate_compressed_program(PROFILE, seed=seed, max_words=4,
                                              window_size=WINDOW, min_words=2)
        assert all((value & 3) != 3 for value in program.words)
        validate_record(record(program.words), isa=ISA_C, windows=WINDOWS,
                        f1_words=4, f1_flags=COMPRESSED_FLAGS)
        deterministic += int(compressed_trace_deterministic(program.words))
    # Most module draws read a register the image never wrote; the strategy
    # refuses those draws (or repairs them), so only a few qualify directly.
    assert deterministic >= 1


def test_the_strategy_repairs_a_draw_that_reads_firmware_state():
    # A drawn program whose first parcel is not C.LI has no comparable trace; the
    # strategy's fallback must still hand the batch a deterministic image.
    for seed in range(8):
        strategy = FuzzStrategy(
            flows=('F1',), gate=_entry_gate(4, COMPRESSED_FLAGS),
            program_profile=PROFILE, f1_words=2, program_window=WINDOW,
            seed=seed, f1_allow_compressed=True)
        fresh = strategy.fresh('F1')
        assert compressed_trace_deterministic(fresh.fields), fresh.text


# ---------------------------------------------------------------------------
# Entry correspondence: the parcel-level reference trace is the authority
# ---------------------------------------------------------------------------


def test_the_fixed_compressed_case_corresponds_with_eight_retirements():
    case = compressed_case(FIXED)
    assert case['prog_retires'] == 8 and case['prog_trace_count'] == 8
    assert case['prog_words'] == 4
    assert case['successor_pc'] == LAYOUT['slot'] + 16
    assert check(FIXED, case) is None, check(FIXED, case)


def test_the_fixed_compressed_expectation_is_the_documented_trace():
    expectation = expectation_for(FIXED)
    assert expectation['mode'] == 'compressed'
    assert expectation['retired_count'] == 8
    assert expectation['pc_order'] == [LAYOUT['slot'] + 2 * index
                                       for index in range(8)]
    assert [entry['insn'] for entry in expectation['trace']] == [
        'C.LI', 'C.LI', 'C.ADDI', 'C.MV', 'C.ADD', 'C.ANDI', 'C.ADDI', 'C.SUB']
    # ``insn_word`` is the parcel the host's RVFI ``insn`` carries for a
    # compressed retirement, which is what makes the two hashes comparable.
    assert [entry['insn_word'] for entry in expectation['trace']] == list(PARCELS)
    assert expectation['trace_hash'] == 'fnv1a32:e232c69e'
    assert expectation['program_end'] == LAYOUT['slot'] + 16


def test_a_mixed_image_corresponds_with_its_whole_word_first():
    case = compressed_case(MIXED)
    assert case['prog_retires'] == 6
    assert case['retire_insn'] == MIXED[0]
    assert check(MIXED, case) is None, check(MIXED, case)
    # The first retirement of a pair-word program is its low parcel.
    pair_word = FIXED[0]
    assert first_instruction(pair_word) == pair_word & 0xFFFF


@pytest.mark.parametrize('override,match', [
    ({'prog_retires': 4}, 'retired 4 instructions'),
    ({'prog_trace_count': 4}, 'RVFI trace count'),
    ({'prog_trace_hash': 0}, 'RVFI trace hash'),
    ({'prog_pc_order': 0}, 'strictly increasing'),
    ({'prog_insns_match': 0}, 'parcel that was not installed'),
    ({'successor_pc': LAYOUT['slot'] + 4}, 'no observed successor'),
    ({'prog_traps': 1}, 'trapped'),
    ({'data_hash_after': 0}, 'reference stores'),
    ({'retire_insn': FIXED[0]}, 'retired word differs'),
])
def test_a_compressed_case_that_differs_from_the_reference_is_mismatched(override, match):
    case = compressed_case(FIXED)
    case.update(override)
    reason = check(FIXED, case)
    assert reason is not None and match in reason, reason


def test_a_compressed_trace_hash_binds_the_parcel_values():
    # Mutating one parcel of word 2 (C.ANDI x12,15 -> C.ANDI x12,31) changes the
    # trace hash: the same image with the original case's hash no longer matches.
    mutated = list(FIXED)
    mutated[2] = pair(PARCELS[4], parcel('C.ANDI', rd=12, imm=31))
    mutated = tuple(mutated)
    original = trace_hash(f1_rvfi_trace(expectation_for(FIXED)))
    assert trace_hash(f1_rvfi_trace(expectation_for(mutated))) != original
    case = compressed_case(mutated)
    case['prog_trace_hash'] = int(original.split(':')[1], 16)
    reason = check(mutated, case)
    assert reason is not None and 'RVFI trace hash' in reason


def test_the_straight_line_criteria_are_unchanged_when_compressed_is_off():
    program = (word('ADDI', rd=5, rs1=0, imm=1),
               word('ADDI', rd=6, rs1=0, imm=2))
    legacy = {'f1_program_words': 4}
    case = dict(index=0, flow='F1', record=f1_text(program),
                status='observations_passed', fetch=LAYOUT['slot'],
                retire_pc=LAYOUT['slot'], retire_insn=program[0],
                successor_pc=LAYOUT['slot'] + 8, prog_words=2,
                prog_retires=2, prog_pc_ordered=1, prog_insns_match=1,
                prog_traps=0)
    plain = parse_record(f1_text(program), windows=WINDOWS, arity=ARITY,
                         f1_words=4)
    assert correspondence(plain, case, layout=LAYOUT, windows=WINDOWS, irq=None,
                          dma=None, bus='obi', f1_flags=legacy, isa=ISA) is None
    assert 'did not retire every program word' in correspondence(
        plain, dict(case, prog_retires=1), layout=LAYOUT, windows=WINDOWS,
        irq=None, dma=None, bus='obi', f1_flags=legacy, isa=ISA)


def test_the_compressed_observation_keys_are_reported():
    keys = case_observation_keys('F1', 'apb3')
    for key in ('prog_trace_hash', 'prog_trace_count', 'prog_pc_order',
                'prog_retires', 'prog_insns_match', 'prog_last_insn'):
        assert key in keys


def test_the_classifier_uses_the_compressed_retirement_facts():
    compressed = dict(flow='F1', status='failed', prog_words=4, prog_retires=8,
                      prog_trace_count=8, prog_pc_order=1, prog_insns_match=1,
                      prog_pc_ordered=1)
    assert classify_case(compressed)['failure_class'] == 'observation_mismatch'
    anomaly = classify_case(dict(compressed, prog_pc_order=0))
    assert anomaly['failure_class'] == 'execution_anomaly'
    mismatch = classify_case(dict(compressed, prog_trace_count=7))
    assert mismatch['failure_class'] == 'execution_anomaly'


def test_a_wrong_compressed_trace_fails_the_batch():
    parsed = dict(cases=[dict(status='observations_passed')],
                  summary=dict(status='observations_passed'))
    result = dict(returncode=0)
    apply_correspondence(
        result, parsed, [record(FIXED)],
        ['F1 RVFI trace hash fnv1a32:00000000 differs from the reference '
         'fnv1a32:e232c69e'])
    assert result['status'] == 'failed'
    assert result['failure'].startswith('correspondence:')
    assert 'trace hash' in result['failure']


# ---------------------------------------------------------------------------
# The C++ host mirror: parcel admission, straddle rule, instruction count
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
  if (mode == "parcels") {{
    // One line per 16-bit parcel: ok=<0/1> name=<name> message=<text>
    for (int index = 2; index < argc; ++index) {{
      const uint32_t value = uint32_t(std::strtoul(argv[index], nullptr, 16));
      const f1_parcels::Result result =
          f1_parcels::check_parcel(value, 0u, 0u);
      std::printf("ok=%d name=%s message=%s\\n", int(result.ok), result.name,
                  result.message.c_str());
    }}
    return 0;
  }}
  if (mode == "words") {{
    // One line per 32-bit record word: ok=<0/1> count=<instructions>
    for (int index = 2; index < argc; ++index) {{
      const uint32_t value = uint32_t(std::strtoul(argv[index], nullptr, 16));
      const f1_parcels::Result result = f1_parcels::check_word(value, 0u);
      std::printf("ok=%d message=%s\\n", int(result.ok), result.message.c_str());
    }}
    return 0;
  }}
  if (mode == "layout") {{
    // The instruction count of an image and the first instruction of word 0.
    std::vector<uint32_t> words;
    for (int index = 2; index < argc; ++index)
      words.push_back(uint32_t(std::strtoul(argv[index], nullptr, 16)));
    const unsigned count =
        f1_parcels::instruction_count(words.data(), unsigned(words.size()));
    std::printf("count=%u first=0x%04x\\n", count,
                f1_parcels::first_instruction(words[0]) & 0xffffu);
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
        pytest.skip('g++ is required for the C++ compressed mirror')
    directory = tmp_path_factory.mktemp('f1-compressed-mirror')
    harness = directory / 'mirror.cpp'
    harness.write_text(_HARNESS.format(blocks=_marked_block('F1_COMPRESSED_PARCEL')))
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


def test_the_mirror_agrees_with_the_python_parcel_decoder_exhaustively(mirror):
    # Every 16-bit value: the host must admit exactly the parcels
    # ``decode_compressed_parcel`` admits, and name the same encoding.
    values = list(range(0x10000))
    lines = _run_mirror(mirror, 'parcels',
                        *[format(value, '04x') for value in values])
    assert len(lines) == len(values)
    admitted = refused = 0
    for value, line in zip(values, lines):
        fields = dict(part.split('=', 1) for part in line.split(' ', 1)
                      if '=' in part)
        ok = fields['ok'] == '1'
        try:
            decoded = decode_compressed_parcel(value)
        except ValueError:
            assert not ok, (value, line)
            refused += 1
            continue
        assert ok, (value, line)
        assert line.split(' name=')[1].split(' ')[0] == decoded.name, (value, line)
        admitted += 1
    # 13 admitted names over the x12..x15 encodings: a real subset, not a
    # blanket acceptance.
    assert admitted > 1000 and refused > 60000


def test_the_mirror_refuses_the_same_shapes_by_name(mirror):
    expected = [
        (0xA001, 'compressed control transfer C.J'),
        (0xC001, 'compressed control transfer C.BEQZ'),
        (0x4008, 'compressed memory instruction C.LW'),
        (0x4002, 'compressed memory instruction C.LWSP'),
        (0x0000, 'compressed form C.ADDI4SPN'),
        (0x9002, 'compressed form C.EBREAK'),
        (0x9C01, 'compressed word forms C.SUBW/C.ADDW require RV64'),
        (0x0601, 'C.ADDI with a zero immediate is a HINT'),
        (0x448D, 'C.LI dest x9 is outside the admitted x12..x15 range'),
    ]
    lines = _run_mirror(mirror, 'parcels',
                        *[format(value, '04x') for value, _ in expected])
    for (value, message), line in zip(expected, lines):
        assert line.startswith('ok=0'), (hex(value), line)
        assert message in line, (hex(value), line)


def test_the_mirror_refuses_a_32_bit_instruction_straddling_a_word(mirror):
    lines = _run_mirror(mirror, 'words',
                        format(FIXED[0], '08x'),
                        format(((FIXED[0] & 0xFFFF) | (0x0003 << 16)), '08x'),
                        format(word('ADDI', rd=12, rs1=0, imm=5), '08x'))
    assert lines[0].startswith('ok=1'), lines[0]
    assert lines[1].startswith('ok=0') and 'may not straddle' in lines[1], lines[1]
    # A 32-bit instruction word is admitted by this block: its own rules are the
    # 32-bit gate's, not the parcel subset's.
    assert lines[2].startswith('ok=1'), lines[2]


def test_the_mirror_counts_instructions_and_names_the_first_one(mirror):
    for words in (FIXED, MIXED):
        lines = _run_mirror(mirror, 'layout', *[format(value, '08x')
                                                for value in words])
        count = int(lines[0].split('count=')[1].split()[0])
        first = int(lines[0].split('first=')[1], 16)
        assert count == len(image_instructions(words)), (words, lines)
        assert first == (first_instruction(words[0]) & 0xFFFF)


def test_the_mirror_admits_every_generated_compressed_program(mirror):
    accepted = 0
    for seed in range(16):
        program = generate_compressed_program(PROFILE, seed=seed, max_words=4,
                                              window_size=WINDOW, min_words=2)
        lines = _run_mirror(mirror, 'words',
                            *[format(value, '08x') for value in program.words])
        for line in lines:
            assert line.startswith('ok=1'), (seed, line, program.words)
            accepted += 1
        validate_compressed_program(PROFILE, program.words,
                                    window_size=WINDOW)
    assert accepted >= 16


def test_the_host_still_refuses_the_out_of_scope_shapes_by_name():
    source = HOST.read_text()
    assert re.search(r'#define F1_ALLOW_COMPRESSED 0', source)
    assert 'is not one 32-bit word' in source
    assert 'compressed control transfer' in source
    assert 'compressed memory instruction' in source
    # The two halves of the straddle refusal are separate C++ string literals.
    assert 'high parcel starts a 32-bit instruction at pc+2' in source
    assert 'may not straddle a record word' in source
    assert 'unsupported-f1:no-rvfi-writeback:compressed-trace-unobservable' in source
    # The parcel block is self-contained between its markers so the mirror above
    # compiles exactly the code the host runs.
    assert '// BEGIN F1_COMPRESSED_PARCEL' in source
    assert '// END F1_COMPRESSED_PARCEL' in source
