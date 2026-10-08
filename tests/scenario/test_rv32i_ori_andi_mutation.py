"""Legal ORI/ANDI variation in the online RV32I arithmetic source."""

from dataclasses import replace

import pytest

from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
from myfuzz.scenario.rv32i_sources import (
    Rv32iInstruction,
    decode_instruction_fragment,
    fragment_bytes,
    instruction_operator_id,
    mutate_instruction,
    validate_instruction_bytes,
)
from myfuzz.scenario.session_runtime import OnlineInstruction


@pytest.mark.parametrize(('selector', 'operation', 'word'), [
    (0x07, 'ADDI', 0xFFF38313),
    (0x47, 'ORI', 0xFFF3E313),
    (0x87, 'XORI', 0xFFF3C313),
    (0xC7, 'ANDI', 0xFFF3F313),
])
def test_online_selector_preserves_register_and_selects_legal_operator(selector, operation, word):
    instructions = decode_instruction_fragment(bytes((2, 5, 0xFF, 0x0F, selector)))
    assert instructions == (Rv32iInstruction(operation, rd=6, rs1=7, immediate=-1),)
    assert instructions[0].word() == word
    data = fragment_bytes(instructions)
    validate_instruction_bytes(data)
    assert instruction_operator_id(data) == f'rv32i:{operation}'


@pytest.mark.parametrize(('selector', 'operation'), [(0x47, 'ORI'), (0xC7, 'ANDI')])
def test_eight_byte_online_input_has_distinct_candidate_identity(selector, operation):
    decoder = make_ibex_pulp_dual_source_online_decoder()
    for path_selector in range(256):
        case = decoder.decode(bytes((0, path_selector, 0, 2, 5, 0xFF, 0x0F, selector)))
        if isinstance(case.source, OnlineInstruction):
            break
    else:
        pytest.fail('CPU instruction source was never selected')
    metadata = decoder.decision_metadata(case)
    assert case.source.data == fragment_bytes((Rv32iInstruction(operation, rd=6, rs1=7, immediate=-1),))
    assert metadata['operator_id'] == f'rv32i:{operation}'
    old = replace(case, source=replace(case.source, data_hex=fragment_bytes((
        Rv32iInstruction('XORI', rd=6, rs1=7, immediate=-1),)).hex()))
    old_metadata = decoder.decision_metadata(old)
    assert metadata['candidate_id'] != old_metadata['candidate_id']
    assert metadata['path_id'] == old_metadata['path_id']
    assert metadata['source_id'] == old_metadata['source_id']


@pytest.mark.parametrize('operation', ['ORI', 'ANDI'])
def test_operand_mutation_keeps_new_instruction_class(operation):
    seed = Rv32iInstruction(operation, rd=5, rs1=6, immediate=0)
    changed = mutate_instruction(seed, bytes((2, 0xFF, 0x0F, 31)))
    assert changed == Rv32iInstruction(operation, rd=5, rs1=6, immediate=-1)
    validate_instruction_bytes(fragment_bytes((changed,)))


@pytest.mark.parametrize('funct3', [2, 3])
def test_other_op_imm_encodings_have_precise_rejection(funct3):
    # SLTI/SLTIU stay outside the legal subset. funct3 1 and 5 are now the
    # legal SLLI/SRLI/SRAI shifts and are covered by their own tests.
    word = (1 << 20) | (1 << 15) | (funct3 << 12) | (1 << 7) | 0x13
    with pytest.raises(ValueError, match='unsupported RV32I OP-IMM funct3'):
        validate_instruction_bytes(word.to_bytes(4, 'little'))


@pytest.mark.parametrize('funct3', [1, 5])
def test_shift_op_imm_encodings_with_reserved_bits_have_precise_rejection(funct3):
    # imm = 0x20 puts a one in imm[5], which RV32I reserves: funct3 1 and 5
    # are legal only with imm[11:5] == 0 (SLLI/SRLI) or 0b0100000 (SRAI).
    word = (0x20 << 20) | (1 << 15) | (funct3 << 12) | (1 << 7) | 0x13
    with pytest.raises(ValueError, match='unsupported RV32I shift immediate'):
        validate_instruction_bytes(word.to_bytes(4, 'little'))
