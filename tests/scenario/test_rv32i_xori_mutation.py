"""The online CPU source can vary a legal RV32I XORI operand."""

import pytest
from dataclasses import replace

from myfuzz.scenario.rv32i_sources import (
    Rv32iInstruction,
    decode_instruction_fragment,
    fragment_bytes,
    mutate_instruction,
    validate_instruction_bytes,
)
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
from myfuzz.scenario.session_runtime import OnlineInstruction


def test_xori_encoding_round_trips_through_online_instruction_validator():
    instruction = Rv32iInstruction("XORI", rd=5, rs1=6, immediate=-1)
    assert instruction.word() == 0xFFF34293
    validate_instruction_bytes(fragment_bytes((instruction,)))


def test_online_entropy_selects_xori_with_owned_register_and_signed_immediate():
    # Choice 2 is the ordinary single-word arithmetic source. The source
    # register byte's high bit selects XORI without changing its 5-bit index.
    decoded = decode_instruction_fragment(bytes((2, 4, 0xFF, 0x0F, 0x87)))
    assert decoded == (Rv32iInstruction("XORI", rd=5, rs1=7, immediate=-1),)
    validate_instruction_bytes(fragment_bytes(decoded))


def test_eight_byte_online_decoder_can_reach_xori_cpu_source():
    expected = fragment_bytes((Rv32iInstruction("XORI", rd=5, rs1=7,
                                                 immediate=-1),))
    for path_selector in range(256):
        decoder = make_ibex_pulp_dual_source_online_decoder()
        case = decoder.decode(bytes((0, path_selector, 0, 2, 4, 0xFF,
                                     0x0F, 0x87)))
        if isinstance(case.source, OnlineInstruction):
            assert case.source.data == expected
            return
    pytest.fail("declared CPU instruction source was never selected")


def test_candidate_identity_changes_with_instruction_operator():
    decoder = make_ibex_pulp_dual_source_online_decoder()
    for path_selector in range(256):
        case = decoder.decode(bytes((0, path_selector, 0, 2, 4, 0xFF,
                                     0x0F, 0x87)))
        if isinstance(case.source, OnlineInstruction):
            break
    else:
        pytest.fail('CPU source missing')
    xori = decoder.decision_metadata(case)
    addi_case = replace(case, source=replace(case.source,
        data_hex=fragment_bytes((Rv32iInstruction('ADDI', rd=5, rs1=7,
                                                   immediate=-1),)).hex()))
    addi = decoder.decision_metadata(addi_case)
    assert xori['operator_id'] == 'rv32i:XORI'
    assert addi['operator_id'] == 'rv32i:ADDI'
    assert xori['candidate_id'] != addi['candidate_id']
    assert xori['path_id'] == addi['path_id']
    assert xori['source_id'] == addi['source_id']


def test_xori_operand_mutation_remains_legal():
    seed = Rv32iInstruction("XORI", rd=5, rs1=6, immediate=0)
    changed = mutate_instruction(seed, bytes((2, 0xFF, 0x0F, 31)))
    assert changed == Rv32iInstruction("XORI", rd=5, rs1=6, immediate=-1)
    validate_instruction_bytes(fragment_bytes((changed,)))


def test_xori_register_mutation_changes_only_the_selected_operand():
    seed = Rv32iInstruction("XORI", rd=5, rs1=6, immediate=7)
    changed = mutate_instruction(seed, bytes((1, 0, 0, 31)))
    assert changed == Rv32iInstruction("XORI", rd=5, rs1=31, immediate=7)


def test_arithmetic_choice_without_high_bit_still_selects_addi():
    decoded = decode_instruction_fragment(bytes((2, 4, 0xFF, 0x0F, 7)))
    assert decoded == (Rv32iInstruction("ADDI", rd=5, rs1=7, immediate=-1),)


@pytest.mark.parametrize("kwargs", [
    {"rd": 32}, {"rs1": -1}, {"rs2": 1}, {"immediate": 2048},
    {"immediate": -2049}, {"immediate": True},
])
def test_xori_rejects_illegal_operands(kwargs):
    with pytest.raises(ValueError):
        Rv32iInstruction("XORI", **kwargs)


def test_validator_rejects_other_arithmetic_funct3():
    # SLTI remains outside the deliberately narrow arithmetic source contract.
    with pytest.raises(ValueError, match="unsupported"):
        validate_instruction_bytes((0x0010A093).to_bytes(4, "little"))
