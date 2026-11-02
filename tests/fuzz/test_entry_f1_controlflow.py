"""Entry, gate, model and host-mirror tests for the opt-in F1 control flow.

No RTL and no Verilator here.  Five kinds of facts are pinned:

  * the four new scenario flags (``f1_allow_jumps``, ``f1_allow_loops``,
    ``f1_allow_compressed_control``, ``f1_allow_compressed_memory``) reach the
    gate, the generated header and ``f1_inputs``, and the impossible
    combinations are refused by name;
  * ``JAL``/``JALR`` are admitted only with link x0/x1 and a statically proven,
    strictly forward target, and the reference trace carries the link writeback
    exactly as the RTL does (``rd=1``, ``wdata=pc+4``);
  * the canonical bounded loop is admitted only in its exact shape, its trip
    count is static, the reference model retires
    ``len + (K-1)*loop_length`` instructions and repeats the loop PCs, and a
    non-canonical or non-terminating loop is refused by name;
  * compressed control and memory parcels are admitted only with their flag,
    their target/base is the same statically proven one the 32-bit forms use,
    and a backward compressed transfer or an unproven base is refused;
  * the entry's correspondence compares the full reference trace (count, hash,
    and the repeated-PC count for a loop) and a mismatch fails the batch;
  * the C++ ``F1_CONTROL_FLOW`` block is extracted between its markers, compiled
    with the Python authority's blocks, and agrees with Python on the exact
    records the real runs used.

The real fixed/fuzz batches live under ``runs/round1-f1-controlflow/`` and are
not reproduced here.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from myfuzz.fuzz.f1_program_gate import (F1GateFlags, f1_gate_flags_from_scenario,
                                         f1_reference_expectation, trace_hash)
from myfuzz.fuzz.rv32_compressed import (CompressedPolicy,
                                         generate_compressed_control_program,
                                         generate_compressed_memory_program,
                                         image_instructions, pack_parcels,
                                         reference_run_compressed,
                                         validate_compressed_program)
from myfuzz.fuzz.rv32_program import (control_flow_analysis, generate_jump_program,
                                      generate_loop_program,
                                      mutate_control_program, reference_run,
                                      validate_program_words)
from myfuzz.fuzz.strategy import (FuzzStrategy, compressed_trace_deterministic,
                                  trace_deterministic)
from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile
from scripts.run_inprocess_f1f6 import (PROGRAM_DATA_WORDS, apply_correspondence,
                                        build_layout, correspondence,
                                        declared_windows, f1_rvfi_trace,
                                        f1_window_hash, parse_record,
                                        render_bindings, validate_record)

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp'
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-obi-apb-ibex-timer-zipdma-f1f6.json').read_text())
JUMPS_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-6w-jumps-f1f6.json').read_text())
LOOPS_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-6w-loops-f1f6.json').read_text())
CC_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-4w-compressed-control-f1f6.json').read_text())
CM_CONFIG = json.loads(
    (ROOT / 'configs/scenarios/'
     'inprocess-obi-apb-ibex-timer-4w-compressed-memory-f1f6.json').read_text())
WINDOWS = declared_windows(CONFIG, 16)
LAYOUT = build_layout(WINDOWS, 0x10080)
IMAGE_BASE = LAYOUT['slot']
ISA = IsaContract(32, ('I', 'M'), instruction_alignment=4)
ISA_C = IsaContract(32, ('I', 'M', 'C'), instruction_alignment=2)
PROFILE = RiscvProfile(32, frozenset(('I', 'M')), 4, 32, 0)
PROFILE_C = RiscvProfile(32, frozenset(('I', 'M', 'C')), 2, 32, 0)
ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2, 'F5': 3, 'F6': 4}
WINDOW = PROGRAM_DATA_WORDS * 4
DATA_WINDOW = (0xDEADBEEF, 0x11111111) + (0,) * (PROGRAM_DATA_WORDS - 2)

JUMPS_FLAGS = dict(f1_program_words=6, f1_allow_jumps=True)
LOOPS_FLAGS = dict(f1_program_words=6, f1_allow_branches=True,
                   f1_allow_loops=True)
CC_FLAGS = dict(f1_program_words=4, f1_allow_compressed=True,
                f1_allow_compressed_control=True)
CM_FLAGS = dict(f1_program_words=4, f1_allow_compressed=True,
                f1_allow_compressed_memory=True)


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def parcel(name, **operands):
    return encode(name, xlen=32, **operands)


def pair(low, high):
    return pack_parcels(low, high)


def f1_text(words):
    return 'F1:' + ':'.join(format(value, '08x') for value in words)


def record(words, f1_words=6, compressed=False):
    return parse_record(f1_text(words), windows=WINDOWS, arity=ARITY,
                        f1_words=f1_words, f1_allow_compressed=compressed)


def expectation_for(words, *, flags, isa=ISA, data_window=DATA_WINDOW):
    return f1_reference_expectation(
        {'flow': 'F1', 'fields': tuple(words)}, isa=isa, window_bytes=WINDOW,
        flags=flags, registers={18: LAYOUT['data_base']},
        memory={LAYOUT['data_base'] + 4 * index: value
                for index, value in enumerate(data_window)},
        data_base=IMAGE_BASE, image_base=IMAGE_BASE)


def first_instruction(value):
    return (value & 0xFFFF) if (value & 3) != 3 else value


def case_line(words, *, flags, isa=ISA, data_window=DATA_WINDOW, **override):
    """The case line the C++ host prints for one program of this shape."""
    expectation = expectation_for(words, flags=flags, isa=isa,
                                  data_window=data_window)
    trace = f1_rvfi_trace(expectation)
    final = list(data_window)
    for address, value in expectation['memory_changes'].items():
        offset = address - LAYOUT['data_base']
        if 0 <= offset < WINDOW and offset % 4 == 0:
            final[offset // 4] = value
    pcs = expectation['pc_order']
    repeats = sum(1 for previous, current in zip(pcs, pcs[1:])
                  if current <= previous)
    case = dict(index=0, flow='F1', record=f1_text(words),
                status='observations_passed', fetch=IMAGE_BASE,
                retire_pc=IMAGE_BASE,
                retire_insn=first_instruction(words[0]),
                successor_pc=IMAGE_BASE + 4 * len(words),
                prog_words=len(words),
                prog_retires=expectation['retired_count'],
                prog_pc_ordered=0 if repeats else 1, prog_insns_match=1,
                prog_trace_hash=int(trace_hash(trace).split(':')[1], 16),
                prog_trace_count=expectation['retired_count'],
                prog_pc_order=0 if repeats else 1, prog_pc_repeat=repeats,
                prog_traps=0, data_hash_before=f1_window_hash(data_window),
                data_hash_after=f1_window_hash(final),
                data_changed=sum(1 for before, after in zip(data_window, final)
                                 if before != after))
    case.update({'prog_data_%d' % index: value
                 for index, value in enumerate(data_window)})
    case.update(override)
    return case


def check(words, case, *, flags, isa=ISA, compressed=False, f1_words=6):
    return correspondence(record(words, f1_words=f1_words, compressed=compressed),
                          case, layout=LAYOUT, windows=WINDOWS, irq=None,
                          dma=None, bus='obi', f1_flags=flags, isa=isa)


# ---------------------------------------------------------------------------
# The flags reach the gate, the header and the record gate
# ---------------------------------------------------------------------------


def test_the_new_flags_are_read_from_the_scenario_declaration():
    flags = f1_gate_flags_from_scenario(JUMPS_CONFIG)
    assert flags.allow_jumps is True and flags.mode == 'jump'
    assert flags.as_dict()['f1_allow_jumps'] is True
    loops = f1_gate_flags_from_scenario(LOOPS_CONFIG)
    assert loops.allow_loops is True and loops.mode == 'branch-loop'
    control = f1_gate_flags_from_scenario(CC_CONFIG)
    assert control.allow_compressed_control is True
    assert control.mode == 'compressed-control'
    memory = f1_gate_flags_from_scenario(CM_CONFIG)
    assert memory.allow_compressed_memory is True
    assert memory.mode == 'compressed-memory'
    both = F1GateFlags(program_words=4, allow_compressed=True,
                       allow_compressed_control=True,
                       allow_compressed_memory=True)
    assert both.mode == 'compressed-control-memory'
    assert both.compressed and both.traced
    # Every historical mode name is unchanged.
    assert F1GateFlags().mode == 'single'
    assert F1GateFlags(program_words=4).mode == 'legacy'
    assert F1GateFlags(program_words=4, allow_branches=True).mode == 'branch'
    assert F1GateFlags(program_words=4, allow_address_forms=True).mode == 'address'
    assert F1GateFlags(program_words=4, allow_address_forms=True,
                       allow_branches=True).mode == 'extended'


@pytest.mark.parametrize('config, match', [
    (dict(CONFIG, f1_program_words=4, f1_allow_loops=True),
     'f1_allow_loops requires f1_allow_branches'),
    (dict(CONFIG, f1_program_words=4, f1_allow_jumps=True,
          f1_allow_compressed=True), 'incompatible'),
    (dict(CONFIG, f1_program_words=4, f1_allow_loops=True,
          f1_allow_branches=True, f1_allow_compressed=True), 'incompatible'),
    (dict(CONFIG, f1_program_words=4, f1_allow_compressed_control=True),
     'requires f1_allow_compressed'),
    (dict(CONFIG, f1_program_words=4, f1_allow_compressed_memory=True),
     'requires f1_allow_compressed'),
    (dict(CONFIG, f1_program_words=4, f1_allow_address_forms=True,
          f1_allow_jumps=True), 'not combined'),
    (dict(CONFIG, f1_program_words=4, f1_subword=True, f1_allow_jumps=True),
     'f1_subword is incompatible'),
    (dict(CONFIG, f1_program_words=1, f1_allow_jumps=True),
     'f1_program_words > 1'),
    (dict(CONFIG, f1_program_words=4, f1_allow_jumps='yes'),
     'must be a boolean'),
])
def test_an_impossible_flag_combination_is_refused_by_name(config, match):
    with pytest.raises(ValueError, match=match):
        f1_gate_flags_from_scenario(config)


def test_the_header_states_the_declared_control_flow_facts():
    from tests.integration.test_inprocess_f1f6_entry import (cpu_document,
                                                             dma_document,
                                                             ip_document)
    from myfuzz.composition.component_profile import load_component_profile
    profile = load_component_profile(ROOT / CONFIG['cpu_profile'])
    text = render_bindings(LOOPS_CONFIG, cpu_document(), ip_document(),
                           dma_document(), LAYOUT, profile, irq=None, dma=None,
                           dma_irq=None, f1_words=6)
    assert '#define F1_ALLOW_LOOPS 1' in text
    assert '#define F1_ALLOW_BRANCHES 1' in text
    assert '#define F1_ALLOW_JUMPS 0' in text
    assert '#define F1_ALLOW_COMPRESSED_CONTROL 0' in text
    assert '#define F1_ALLOW_COMPRESSED_MEMORY 0' in text
    text = render_bindings(CM_CONFIG, cpu_document(), ip_document(),
                           dma_document(), LAYOUT, profile, irq=None, dma=None,
                           dma_irq=None, f1_words=4)
    assert '#define F1_ALLOW_COMPRESSED_MEMORY 1' in text
    assert '#define F1_ALLOW_COMPRESSED_CONTROL 0' in text


def test_the_entry_record_gate_admits_and_refuses_the_new_shapes():
    loop = (word('ADDI', rd=5, rs1=0, imm=3),
            word('ADDI', rd=6, rs1=0, imm=1),
            word('ADDI', rd=6, rs1=6, imm=2),
            word('ADDI', rd=5, rs1=5, imm=-1),
            word('BNE', rs1=5, rs2=0, imm=-12))
    validate_record(record(loop), isa=ISA, windows=WINDOWS, f1_words=6,
                    f1_flags=f1_gate_flags_from_scenario(LOOPS_CONFIG))
    # The same program without the loop declaration is refused by name.
    with pytest.raises(ValueError, match='loops are refused'):
        validate_record(record(loop), isa=ISA, windows=WINDOWS, f1_words=6,
                        f1_flags=f1_gate_flags_from_scenario(
                            dict(LOOPS_CONFIG, f1_allow_loops=False)))
    jump = (word('ADDI', rd=5, rs1=0, imm=1),
            word('JAL', rd=1, imm=8),
            word('ADDI', rd=6, rs1=0, imm=0x55),
            word('ADDI', rd=7, rs1=0, imm=0x2a))
    validate_record(record(jump, f1_words=4), isa=ISA, windows=WINDOWS,
                    f1_words=6,
                    f1_flags=f1_gate_flags_from_scenario(JUMPS_CONFIG))
    with pytest.raises(ValueError, match='control-flow or system word'):
        validate_record(record(jump, f1_words=4), isa=ISA, windows=WINDOWS,
                        f1_words=6,
                        f1_flags=f1_gate_flags_from_scenario(
                            dict(JUMPS_CONFIG, f1_allow_jumps=False)))


# ---------------------------------------------------------------------------
# JAL / JALR
# ---------------------------------------------------------------------------

#: The fixed jump batch: ``addi x5,x0,1; jal x1,+8; addi x6,x0,0x55;
#: addi x7,x0,0x2a`` retires 3 instructions and writes x1 = pc + 4.
FIXED_JAL = (word('ADDI', rd=5, rs1=0, imm=1), word('JAL', rd=1, imm=8),
             word('ADDI', rd=6, rs1=0, imm=0x55),
             word('ADDI', rd=7, rs1=0, imm=0x2a))
#: The fixed JALR batch: a LUI/ADDI constant base, then ``jalr x1, 0(x7)`` to
#: word 5 over two skipped words.
FIXED_JALR = (word('LUI', rd=7, imm=0x12), word('ADDI', rd=7, rs1=7, imm=20),
              word('JALR', rd=1, rs1=7, imm=0),
              word('ADDI', rd=6, rs1=0, imm=0x55),
              word('ADDI', rd=10, rs1=0, imm=3),
              word('ADDI', rd=5, rs1=0, imm=0x2a))


def test_a_forward_jal_retires_its_link_writeback_exactly():
    flags = f1_gate_flags_from_scenario(JUMPS_CONFIG)
    validate_program_words(PROFILE, FIXED_JAL, window_size=WINDOW,
                           allow_jumps=True, image_base=IMAGE_BASE)
    result = reference_run(FIXED_JAL, registers={18: LAYOUT['data_base']},
                           memory={}, data_base=IMAGE_BASE, window_size=WINDOW,
                           allow_jumps=True)
    assert result['retired_count'] == 3
    assert result['pc_order'] == [IMAGE_BASE, IMAGE_BASE + 4, IMAGE_BASE + 12]
    # The link register is written pc+4, exactly what RVFI reports.
    assert result['trace'][1].rd == 1
    assert result['trace'][1].wdata == IMAGE_BASE + 8
    assert result['final_registers'][1] == IMAGE_BASE + 8
    expectation = expectation_for(FIXED_JAL, flags=flags)
    assert expectation['trace_hash'] == 'fnv1a32:20cee9b7'
    # The case line with that trace is accepted, and a wrong hash is not.
    case = case_line(FIXED_JAL, flags=flags)
    assert check(FIXED_JAL, case, flags=flags, f1_words=4) is None
    assert 'trace hash' in check(FIXED_JAL, dict(case, prog_trace_hash=0),
                                 flags=flags, f1_words=4)


def test_a_proven_jalr_target_is_admitted_and_an_unproven_one_is_refused():
    flags = f1_gate_flags_from_scenario(JUMPS_CONFIG)
    validate_program_words(PROFILE, FIXED_JALR, window_size=WINDOW,
                           allow_jumps=True, image_base=IMAGE_BASE)
    expectation = expectation_for(FIXED_JALR, flags=flags)
    assert expectation['retired_count'] == 4
    assert expectation['pc_order'] == [IMAGE_BASE, IMAGE_BASE + 4,
                                       IMAGE_BASE + 8, IMAGE_BASE + 20]
    assert expectation['trace_hash'] == 'fnv1a32:1bb7b41c'
    # A JALR whose base register the program never writes is refused: its
    # target would be firmware state, not a proven constant.
    unproven = (word('JALR', rd=0, rs1=5, imm=0), word('ADDI', rd=6, rs1=0, imm=1))
    with pytest.raises(ValueError, match='statically proven constant'):
        validate_program_words(PROFILE, unproven, window_size=WINDOW,
                               allow_jumps=True, image_base=IMAGE_BASE)
    # Without the image base an absolute jump cannot be resolved and is refused.
    with pytest.raises(ValueError, match='statically proven constant'):
        validate_program_words(PROFILE, FIXED_JALR, window_size=WINDOW,
                               allow_jumps=True)


@pytest.mark.parametrize('words, match', [
    # link destination x2 is not x0/x1
    ((word('JAL', rd=2, imm=8), word('ADDI', rd=5, rs1=0, imm=1)),
     'link destination x2'),
    # a backward JAL would be an unbounded loop
    ((word('ADDI', rd=5, rs1=0, imm=1), word('JAL', rd=0, imm=-4)),
     'not strictly forward'),
    # a target past the appended return jump leaves the image
    ((word('JAL', rd=0, imm=16), word('ADDI', rd=5, rs1=0, imm=1)),
     'beyond the installed program'),
    # a JALR target address that is not 4-byte aligned
    ((word('LUI', rd=7, imm=0x12), word('ADDI', rd=7, rs1=7, imm=2),
      word('JALR', rd=0, rs1=7, imm=0), word('ADDI', rd=5, rs1=0, imm=1)),
     'not 4-byte aligned'),
    # a JALR target outside the installed image
    ((word('LUI', rd=7, imm=0x12), word('ADDI', rd=7, rs1=7, imm=64),
      word('JALR', rd=0, rs1=7, imm=0), word('ADDI', rd=5, rs1=0, imm=1)),
     'outside the installed program'),
])
def test_a_jump_outside_the_proven_subset_is_refused_by_name(words, match):
    with pytest.raises(ValueError, match=match):
        validate_program_words(PROFILE, words, window_size=WINDOW,
                               allow_jumps=True, image_base=IMAGE_BASE)


def test_the_jump_generator_and_mutation_stay_legal_and_trace_deterministic():
    for seed in range(8):
        program = generate_jump_program(PROFILE, seed=seed, max_words=6,
                                        window_size=WINDOW,
                                        image_base=IMAGE_BASE)
        assert trace_deterministic(program.words, image_base=IMAGE_BASE)
        validate_program_words(PROFILE, program.words, window_size=WINDOW,
                               allow_jumps=True, image_base=IMAGE_BASE)
        mutated = mutate_control_program(PROFILE, program, seed=seed + 100,
                                         max_words=6, window_size=WINDOW,
                                         allow_jumps=True,
                                         image_base=IMAGE_BASE)
        # The mutator's contract is "a legal program of the same shape"; the
        # strategy additionally filters for a trace the entry can declare.
        validate_program_words(PROFILE, mutated.words, window_size=WINDOW,
                               allow_jumps=True, image_base=IMAGE_BASE)


# ---------------------------------------------------------------------------
# The canonical bounded loop
# ---------------------------------------------------------------------------

#: The fixed loop batch: K = 3 iterations of ``addi x6,x0,1; addi x6,x6,2``.
FIXED_LOOP = (word('ADDI', rd=5, rs1=0, imm=3),
              word('ADDI', rd=6, rs1=0, imm=1),
              word('ADDI', rd=6, rs1=6, imm=2),
              word('ADDI', rd=5, rs1=5, imm=-1),
              word('BNE', rs1=5, rs2=0, imm=-12))


def test_the_loop_trip_count_is_static_and_the_reference_trace_repeats_pcs():
    flags = f1_gate_flags_from_scenario(LOOPS_CONFIG)
    validate_program_words(PROFILE, FIXED_LOOP, window_size=WINDOW,
                           allow_branches=True, allow_loops=True)
    control = control_flow_analysis(FIXED_LOOP, allow_branches=True,
                                    allow_loops=True)
    assert len(control.loops) == 1
    loop = control.loops[0]
    assert (loop.init, loop.head, loop.step, loop.back_edge) == (0, 1, 3, 4)
    assert loop.trip_count == 3 and loop.induction == 5
    assert control.step_limit == 13
    result = reference_run(FIXED_LOOP, registers={18: LAYOUT['data_base']},
                           memory={}, data_base=IMAGE_BASE, window_size=WINDOW,
                           allow_branches=True, allow_loops=True)
    # 5 installed words, 3 iterations of the 4-word loop body: 13 retirements.
    assert result['retired_count'] == 13
    assert result['pc_order'] == [
        IMAGE_BASE, IMAGE_BASE + 4, IMAGE_BASE + 8, IMAGE_BASE + 12,
        IMAGE_BASE + 16, IMAGE_BASE + 4, IMAGE_BASE + 8, IMAGE_BASE + 12,
        IMAGE_BASE + 16, IMAGE_BASE + 4, IMAGE_BASE + 8, IMAGE_BASE + 12,
        IMAGE_BASE + 16]
    assert result['final_registers'][6] == 3
    expectation = expectation_for(FIXED_LOOP, flags=flags)
    assert expectation['trace_hash'] == 'fnv1a32:030a0aaf'
    case = case_line(FIXED_LOOP, flags=flags)
    assert case['prog_pc_order'] == 0 and case['prog_pc_repeat'] == 2
    assert check(FIXED_LOOP, case, flags=flags, f1_words=5) is None
    # The repeat count is a real observation: a wrong one fails the batch.
    mismatch = check(FIXED_LOOP, dict(case, prog_pc_repeat=1), flags=flags,
                     f1_words=5)
    assert 'repeated' in mismatch


@pytest.mark.parametrize('words, match', [
    # A BEQ back edge is not the canonical loop shape.
    ((word('ADDI', rd=5, rs1=0, imm=3), word('ADDI', rd=6, rs1=0, imm=1),
      word('ADDI', rd=5, rs1=5, imm=-1), word('BEQ', rs1=5, rs2=0, imm=-8)),
     'only the canonical BNE'),
    # No `addi xN, x0, K` init: no statically known trip count.
    ((word('ADDI', rd=5, rs1=0, imm=1), word('ADDI', rd=6, rs1=0, imm=1),
      word('ADDI', rd=5, rs1=5, imm=-1), word('BNE', rs1=5, rs2=0, imm=-8)),
     'trip count'),
    # The body writes the induction register.
    ((word('ADDI', rd=5, rs1=0, imm=3), word('ADDI', rd=5, rs1=0, imm=1),
      word('ADDI', rd=5, rs1=5, imm=-1), word('BNE', rs1=5, rs2=0, imm=-8)),
     'writes the induction register'),
    # A trip count outside 2..6 is not the admitted shape.
    ((word('ADDI', rd=5, rs1=0, imm=7), word('ADDI', rd=6, rs1=0, imm=1),
      word('ADDI', rd=5, rs1=5, imm=-1), word('BNE', rs1=5, rs2=0, imm=-8)),
     'trip count'),
    # A backward jump is not a loop back edge.
    ((word('ADDI', rd=5, rs1=0, imm=3), word('JAL', rd=0, imm=-4)),
     'unbounded loop'),
])
def test_a_non_canonical_loop_is_refused_by_name(words, match):
    with pytest.raises(ValueError, match=match):
        validate_program_words(PROFILE, words, window_size=WINDOW,
                               allow_branches=True, allow_loops=True,
                               allow_jumps=True, image_base=IMAGE_BASE)


def test_two_loops_must_be_disjoint_and_are_entered_only_at_their_init():
    # Two sequential loops are legal and each is proven on its own.
    two = (word('ADDI', rd=5, rs1=0, imm=2), word('ADDI', rd=6, rs1=0, imm=1),
           word('ADDI', rd=5, rs1=5, imm=-1), word('BNE', rs1=5, rs2=0, imm=-8),
           word('ADDI', rd=7, rs1=0, imm=2), word('ADDI', rd=10, rs1=0, imm=1),
           word('ADDI', rd=7, rs1=7, imm=-1), word('BNE', rs1=7, rs2=0, imm=-8))
    validate_program_words(PROFILE, two, window_size=WINDOW,
                           allow_branches=True, allow_loops=True)
    control = control_flow_analysis(two, allow_branches=True, allow_loops=True)
    assert [loop.trip_count for loop in control.loops] == [2, 2]
    # A forward branch that jumps into a loop's interior is refused.
    into = (word('BEQ', rs1=0, rs2=0, imm=12),
            word('ADDI', rd=5, rs1=0, imm=3),
            word('ADDI', rd=6, rs1=0, imm=1),
            word('ADDI', rd=5, rs1=5, imm=-1),
            word('BNE', rs1=5, rs2=0, imm=-8))
    with pytest.raises(ValueError, match='inside the bounded loop'):
        validate_program_words(PROFILE, into, window_size=WINDOW,
                               allow_branches=True, allow_loops=True)


def test_the_loop_generator_is_bounded_and_terminates_without_a_step_override():
    for seed in range(8):
        program = generate_loop_program(PROFILE, seed=seed, max_words=6,
                                        window_size=WINDOW)
        control = control_flow_analysis(program.words, allow_branches=True,
                                        allow_loops=True)
        assert len(control.loops) == 1
        assert 2 <= control.loops[0].trip_count <= 6
        result = reference_run(program.words, registers={},
                               memory={}, data_base=IMAGE_BASE,
                               window_size=WINDOW, allow_branches=True,
                               allow_loops=True)
        # No explicit max_steps: the static bound is what stops the loop.
        assert result['retired_count'] == control.step_limit
        assert trace_deterministic(program.words)
        mutated = mutate_control_program(PROFILE, program, seed=seed + 100,
                                         max_words=6, window_size=WINDOW,
                                         allow_branches=True, allow_loops=True)
        validate_program_words(PROFILE, mutated.words, window_size=WINDOW,
                               allow_branches=True, allow_loops=True)


# ---------------------------------------------------------------------------
# Compressed control and memory
# ---------------------------------------------------------------------------

#: ``C.LI x12,5; C.LI x13,3; C.ADDI x12,7; C.J +6; C.ADDI x13,-1;
#: C.ADDI x13,4; C.MV x14,x12; C.ADD x14,x13`` - the C.J skips one pair word.
FIXED_CJ = (pair(parcel('C.LI', rd=12, imm=5), parcel('C.LI', rd=13, imm=3)),
            pair(parcel('C.ADDI', rd=12, imm=7), parcel('C.J', imm=6)),
            pair(parcel('C.ADDI', rd=13, imm=-1), parcel('C.ADDI', rd=13, imm=4)),
            pair(parcel('C.MV', rd=14, rs2=12), parcel('C.ADD', rd=14, rs2=13)))
#: ``C.LUI x12,0x12; C.ADDI x12,12; C.JR x12`` reaches word 3 with a proven
#: constant base (C.JR has no catalog entry; its encoding is C.MV with rs2=x0).
FIXED_CJR = (pair(parcel('C.LUI', rd=12, imm=0x12),
                  parcel('C.ADDI', rd=12, imm=12)),
             pair(0x8002 | (12 << 7), parcel('C.LI', rd=13, imm=3)),
             pair(parcel('C.ADDI', rd=13, imm=1), parcel('C.ADDI', rd=13, imm=2)),
             pair(parcel('C.MV', rd=14, rs2=12), parcel('C.ADDI', rd=14, imm=1)))
#: ``ADDI x12,x18,0; C.LW x13,0(x12); C.ADDI x13,1; C.SW x13,4(x12);
#: C.MV x14,x13`` - a proven base and a real store.
FIXED_CLW = (word('ADDI', rd=12, rs1=18, imm=0),
             pair(parcel('C.LW', rd=13, rs1=12, imm=0),
                  parcel('C.ADDI', rd=13, imm=1)),
             pair(parcel('C.SW', rs2=13, rs1=12, imm=4),
                  parcel('C.MV', rd=14, rs2=13)))


def test_a_compressed_forward_control_transfer_is_admitted_and_traced():
    flags = f1_gate_flags_from_scenario(CC_CONFIG)
    validate_compressed_program(PROFILE_C, FIXED_CJ, window_size=WINDOW,
                                allow_compressed_control=True,
                                image_base=IMAGE_BASE)
    result = reference_run_compressed(
        FIXED_CJ, registers={18: LAYOUT['data_base']}, memory={},
        data_base=IMAGE_BASE, window_size=WINDOW,
        allow_compressed_control=True, image_base=IMAGE_BASE)
    assert result['retired_count'] == 6
    assert result['pc_order'] == [IMAGE_BASE, IMAGE_BASE + 2, IMAGE_BASE + 4,
                                  IMAGE_BASE + 6, IMAGE_BASE + 12,
                                  IMAGE_BASE + 14]
    expectation = expectation_for(FIXED_CJ, flags=flags, isa=ISA_C)
    assert expectation['trace_hash'] == 'fnv1a32:3ab734c9'
    case = case_line(FIXED_CJ, flags=flags, isa=ISA_C)
    assert check(FIXED_CJ, case, flags=flags, isa=ISA_C, compressed=True,
                 f1_words=4) is None


def test_a_compressed_constant_base_jump_is_admitted_and_an_unproven_one_is_not():
    flags = f1_gate_flags_from_scenario(CC_CONFIG)
    validate_compressed_program(PROFILE_C, FIXED_CJR, window_size=WINDOW,
                                allow_compressed_control=True,
                                image_base=IMAGE_BASE)
    expectation = expectation_for(FIXED_CJR, flags=flags, isa=ISA_C)
    assert expectation['retired_count'] == 5
    assert expectation['trace_hash'] == 'fnv1a32:a87e4a06'
    # The same C.JR without the constant load: the base is firmware state.
    unproven = (pair(0x8002 | (12 << 7), parcel('C.LI', rd=13, imm=3)),
                pair(parcel('C.ADDI', rd=13, imm=1),
                     parcel('C.ADDI', rd=13, imm=2)),
                pair(parcel('C.MV', rd=14, rs2=12), parcel('C.ADDI', rd=14, imm=1)))
    with pytest.raises(ValueError, match='statically proven constant'):
        validate_compressed_program(PROFILE_C, unproven, window_size=WINDOW,
                                    allow_compressed_control=True,
                                    image_base=IMAGE_BASE)


@pytest.mark.parametrize('words, match', [
    # C.J x0, 0: a backward compressed transfer would be a loop.
    ((pair(parcel('C.J', imm=-2), parcel('C.LI', rd=13, imm=3)),
      pair(parcel('C.ADDI', rd=13, imm=1), parcel('C.ADDI', rd=13, imm=2))),
     'branches backward'),
    # A C.LW base the image never sets from x18.
    ((word('ADDI', rd=12, rs1=0, imm=0),
      pair(parcel('C.LW', rd=13, rs1=12, imm=0),
           parcel('C.ADDI', rd=13, imm=1))),
     'not a statically proven data-window address'),
    # A proven base with an out-of-window offset.
    ((word('ADDI', rd=12, rs1=18, imm=0),
      pair(parcel('C.LW', rd=13, rs1=12, imm=0),
           parcel('C.SW', rs2=13, rs1=12, imm=124))),
     'leaves the declared data window'),
    # C.LWSP with a stack pointer the image never sets.
    ((word('ADDI', rd=12, rs1=18, imm=0),
      pair(parcel('C.LWSP', rd=13, imm=0), parcel('C.ADDI', rd=13, imm=1))),
     'not a statically proven data-window address'),
    # C.JR x0 is a reserved encoding.
    ((pair(0x8002, parcel('C.LI', rd=13, imm=3)),),
     'reserved encoding'),
])
def test_a_compressed_form_outside_the_proven_subset_is_refused_by_name(words,
                                                                        match):
    with pytest.raises(ValueError, match=match):
        validate_compressed_program(PROFILE_C, words, window_size=WINDOW,
                                    allow_compressed_control=True,
                                    allow_compressed_memory=True,
                                    image_base=IMAGE_BASE)


def test_a_compressed_memory_parcel_is_admitted_and_its_store_is_the_witness():
    flags = f1_gate_flags_from_scenario(CM_CONFIG)
    validate_compressed_program(PROFILE_C, FIXED_CLW, window_size=WINDOW,
                                allow_compressed_memory=True)
    expectation = expectation_for(FIXED_CLW, flags=flags, isa=ISA_C)
    assert expectation['retired_count'] == 5
    assert expectation['memory_changes'] == {LAYOUT['data_base'] + 4: 0xDEADBEF0}
    case = case_line(FIXED_CLW, flags=flags, isa=ISA_C)
    assert case['data_changed'] == 1
    assert check(FIXED_CLW, case, flags=flags, isa=ISA_C, compressed=True,
                 f1_words=4) is None
    # The after-window is the store witness: a case that claims no change fails.
    assert 'data window after' in check(FIXED_CLW, dict(case, data_changed=0,
                                                       data_hash_after=case['data_hash_before']),
                                       flags=flags, isa=ISA_C, compressed=True,
                                       f1_words=4)


def test_the_compressed_generators_are_legal_and_trace_deterministic():
    for seed in range(6):
        control = generate_compressed_control_program(
            PROFILE_C, seed=seed, max_words=4, window_size=WINDOW,
            image_base=IMAGE_BASE)
        assert compressed_trace_deterministic(control.words, control=True,
                                              image_base=IMAGE_BASE)
        names = {entry.name for entry in image_instructions(
            control.words, CompressedPolicy(True, False))}
        assert names & {'C.J', 'C.JAL', 'C.BEQZ', 'C.BNEZ', 'C.JR', 'C.JALR'}
        memory = generate_compressed_memory_program(
            PROFILE_C, seed=seed, max_words=4, window_size=WINDOW)
        assert compressed_trace_deterministic(memory.words, memory=True)
        names = {entry.name for entry in image_instructions(
            memory.words, CompressedPolicy(False, True))}
        assert names & {'C.LW', 'C.SW', 'C.LWSP', 'C.SWSP'}


def test_the_compressed_parcel_policy_default_keeps_the_alu_only_subset():
    # The historical decoder still refuses every control/memory parcel, and the
    # widened policy admits them: the default is not silently widened.
    from myfuzz.fuzz.rv32_compressed import (CompressedRefusal,
                                             decode_compressed_parcel)
    for name, operands in (('C.J', {'imm': 4}),
                           ('C.BEQZ', {'rs1': 12, 'imm': 4}),
                           ('C.LW', {'rd': 13, 'rs1': 12, 'imm': 0}),
                           ('C.LWSP', {'rd': 13, 'imm': 0})):
        value = parcel(name, **operands)
        with pytest.raises(CompressedRefusal):
            decode_compressed_parcel(value)
        assert decode_compressed_parcel(value, CompressedPolicy(True, True)).name


# ---------------------------------------------------------------------------
# The strategy offers only programs whose trace the entry can declare
# ---------------------------------------------------------------------------


def test_the_strategy_offers_the_new_shapes_and_only_deterministic_programs():
    def gate(flow, fields):
        return flow + ':' + ':'.join('%08x' % value for value in fields), 'CASE'

    for flags, isa in ((dict(f1_allow_jumps=True), ISA),
                       (dict(f1_allow_branches=True, f1_allow_loops=True), ISA),
                       (dict(f1_allow_compressed=True,
                             f1_allow_compressed_control=True), ISA_C),
                       (dict(f1_allow_compressed=True,
                             f1_allow_compressed_memory=True), ISA_C)):
        strategy = FuzzStrategy(flows=('F1',), gate=gate,
                                program_profile=PROFILE_C if isa is ISA_C else PROFILE,
                                f1_words=4, program_window=WINDOW, seed=11,
                                f1_image_base=IMAGE_BASE, **flags)
        for _ in range(4):
            offered = strategy.next_input()
            assert offered.flow == 'F1'
            words = tuple(offered.fields)
            if flags.get('f1_allow_compressed'):
                assert compressed_trace_deterministic(
                    words, control=flags.get('f1_allow_compressed_control',
                                             False),
                    memory=flags.get('f1_allow_compressed_memory', False),
                    image_base=IMAGE_BASE)
            else:
                assert trace_deterministic(words, image_base=IMAGE_BASE)


# ---------------------------------------------------------------------------
# The C++ control-flow block agrees with the Python authority
# ---------------------------------------------------------------------------

_HARNESS = '''#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
{blocks}
int main(int argc, char **argv) {{
  if (argc < 4) return 2;
  std::vector<uint32_t> words;
  for (int index = 3; index < argc; ++index)
    words.push_back(uint32_t(std::strtoul(argv[index], nullptr, 16)));
  const uint32_t slot = uint32_t(std::strtoul(argv[1], nullptr, 16));
  const unsigned window_words = unsigned(std::strtoul(argv[2], nullptr, 10));
  const f1_control::Result result =
      f1_control::check(words.data(), unsigned(words.size()), slot,
                        window_words);
  std::printf("ok=%d expected=%u exact=%d loop=%d repeats=%u message=%s\\n",
              int(result.ok), result.expected_retires, int(result.exact_retires),
              int(result.loop_mode), result.loop_repeats,
              result.message.c_str());
  return 0;
}}
'''


def _marked_block(name):
    source = HOST.read_text()
    begin = source.index('// BEGIN ' + name)
    end = source.index('// END ' + name)
    return source[begin:end + len('// END ' + name)]


@pytest.fixture(scope='module')
def control_mirror(tmp_path_factory):
    compiler = shutil.which('g++')
    if compiler is None:
        pytest.skip('g++ is required for the C++ control-flow mirror')
    directory = tmp_path_factory.mktemp('f1-control-mirror')
    harness = directory / 'mirror.cpp'
    harness.write_text(_HARNESS.format(
        blocks='\n'.join(_marked_block(name) for name in
                         ('F1_ADDRESS_PROVENANCE', 'F1_COMPRESSED_PARCEL',
                          'F1_CONTROL_FLOW'))))
    binary = directory / 'mirror'
    completed = subprocess.run(
        [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O2',
         '-DF1_ALLOW_JUMPS=1', '-DF1_ALLOW_LOOPS=1',
         '-DF1_ALLOW_COMPRESSED_CONTROL=1', '-DF1_ALLOW_COMPRESSED_MEMORY=1',
         str(harness), '-o', str(binary)],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    return binary


def _run_mirror(binary, words, *, slot=IMAGE_BASE, window=PROGRAM_DATA_WORDS):
    arguments = [str(binary), hex(slot), str(window)]
    arguments += [format(value, '08x') for value in words]
    completed = subprocess.run(arguments, capture_output=True, text=True,
                               check=True)
    fields = {}
    for token in completed.stdout.split():
        key, _, value = token.partition('=')
        fields[key] = value
    return fields


def test_the_mirror_agrees_with_python_on_the_records_the_runs_used(control_mirror):
    mirror = _run_mirror(control_mirror, FIXED_JAL)
    assert mirror['ok'] == '1' and mirror['expected'] == '0'
    mirror = _run_mirror(control_mirror, FIXED_JALR)
    assert mirror['ok'] == '1'
    mirror = _run_mirror(control_mirror, FIXED_LOOP, window=PROGRAM_DATA_WORDS)
    assert mirror['ok'] == '1'
    assert mirror['loop'] == '1' and mirror['exact'] == '1'
    assert mirror['expected'] == '13' and mirror['repeats'] == '2'
    mirror = _run_mirror(control_mirror, FIXED_CJ)
    assert mirror['ok'] == '1' and mirror['expected'] == '0'
    mirror = _run_mirror(control_mirror, FIXED_CJR)
    assert mirror['ok'] == '1'
    mirror = _run_mirror(control_mirror, FIXED_CLW)
    assert mirror['ok'] == '1'


def test_the_mirror_refuses_the_same_unproven_forms_as_python(control_mirror):
    backward_jal = (word('ADDI', rd=5, rs1=0, imm=1), word('JAL', rd=0, imm=-4))
    assert _run_mirror(control_mirror, backward_jal)['ok'] == '0'
    unproven_jalr = (word('JALR', rd=0, rs1=5, imm=0),
                     word('ADDI', rd=6, rs1=0, imm=1))
    assert _run_mirror(control_mirror, unproven_jalr)['ok'] == '0'
    unproven_clw = (word('ADDI', rd=12, rs1=0, imm=0),
                    pair(parcel('C.LW', rd=13, rs1=12, imm=0),
                         parcel('C.ADDI', rd=13, imm=1)))
    assert _run_mirror(control_mirror, unproven_clw)['ok'] == '0'
    backward_cj = (pair(parcel('C.J', imm=-2), parcel('C.LI', rd=13, imm=3)),)
    assert _run_mirror(control_mirror, backward_cj)['ok'] == '0'
    non_canonical = (word('ADDI', rd=5, rs1=0, imm=3),
                     word('ADDI', rd=6, rs1=0, imm=1),
                     word('ADDI', rd=5, rs1=5, imm=-1),
                     word('BEQ', rs1=5, rs2=0, imm=-12))
    assert _run_mirror(control_mirror, non_canonical)['ok'] == '0'
