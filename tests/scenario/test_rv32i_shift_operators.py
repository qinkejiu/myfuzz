"""Legal RV32I shift-immediate operators in the mutation and validation space.

SLLI, SRLI and SRAI are OP-IMM forms: opcode 0x13, funct3 1 (SLLI) or 5
(SRLI/SRAI), shamt in inst[24:20], and inst[31:25] reserved by RV32I -- zero
for SLLI/SRLI and 0b0100000 for SRAI, whose bit 30 is imm[10]. Every expected
word below is assembled field by field from those ISA facts (``_itype``) and
pinned again as a literal hex constant, never taken from
``Rv32iInstruction.word()``, so an encoding bug cannot agree with itself.

A 32-bit RV32I word cannot carry shamt 32..63 in its five-bit shamt field:
those abstract field values are refused as ``field.bad_shamt`` on the
instruction value object, and the words that try to encode them are refused
as ``isa.reserved_imm_bit``, which names the bits that actually fail.
"""

from __future__ import annotations

from typing import Callable

import pytest

from myfuzz.scenario import rejection_codes as rc
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_online_decoder,
)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.rv32i_sources import (
    MmioWindow,
    Rv32iInstruction,
    decode_instruction_fragment,
    fragment_bytes,
    instruction_operator_id,
    mmio_access_fragment,
    mutate_instruction,
    validate_instruction_bytes,
    validate_instruction_bytes_detailed,
)
from myfuzz.scenario.session_runtime import OnlineInstruction


OP_IMM = 0x13
SRA_HIGH = 0b0100000

#: (operation, rd, rs1, shamt, exact 32-bit word)
SHIFT_GOLDEN = (
    ("SLLI", 0, 0, 0, 0x00001013),
    ("SLLI", 5, 6, 7, 0x00731293),
    ("SLLI", 31, 31, 31, 0x01FF9F93),
    ("SRLI", 2, 3, 0, 0x0001D113),
    ("SRLI", 7, 8, 31, 0x01F45393),
    ("SRLI", 11, 21, 17, 0x011AD593),
    ("SRAI", 9, 10, 0, 0x40055493),
    ("SRAI", 9, 10, 3, 0x40355493),
    ("SRAI", 31, 31, 31, 0x41FFDF93),
    ("SRAI", 0, 0, 31, 0x41F05013),
)

SHIFT_OPERATIONS = ("SLLI", "SRLI", "SRAI")

#: (funct3, immediate, legal?) -- the RV32I reserved-bit matrix for shifts.
SHIFT_IMMEDIATE_MATRIX = (
    (1, 0x000, True),    # SLLI shamt 0
    (1, 0x01F, True),    # SLLI shamt 31
    (1, 0x020, False),   # SLLI imm[5] is reserved in RV32I
    (1, 0x03F, False),   # SLLI shamt field extended: reserved
    (1, 0x800, False),   # SLLI imm[11] reserved
    (5, 0x000, True),    # SRLI shamt 0
    (5, 0x01F, True),    # SRLI shamt 31
    (5, 0x020, False),   # SRLI imm[5] is not shamt[5] in RV32I
    (5, 0x400, True),    # SRAI shamt 0
    (5, 0x41F, True),    # SRAI shamt 31
    (5, 0x420, False),   # SRAI imm[5] set: reserved
    (5, 0x800, False),   # SRAI imm[11] set: reserved
    (5, 0xC00, False),   # SRAI imm[11] and imm[10] set: reserved
    (5, 0x600, False),   # SRAI imm[10] and imm[9] set: reserved
)


def _itype(funct3: int, shamt: int, rs1: int, rd: int, *,
           high: int = 0) -> int:
    """Assemble one RV32I OP-IMM word from its fields, independently."""
    immediate = (high << 5) | shamt
    return ((immediate << 20) | (rs1 << 15) | (funct3 << 12)
            | (rd << 7) | OP_IMM)


def _funct3(operation: str) -> int:
    return 1 if operation == "SLLI" else 5


def _high(operation: str) -> int:
    return SRA_HIGH if operation == "SRAI" else 0


def _bytes(word: int) -> bytes:
    return word.to_bytes(4, "little")


def _caught(call: Callable[[], object]) -> rc.Rejection:
    """Run a refused call and return the structured rejection it raised."""
    with pytest.raises(ValueError) as failure:
        call()
    rejection = rc.rejection_of(failure.value)
    assert rejection is not None, failure.value
    return rejection


def _shift_entropy(rd: int, shamt: int, rs1: int, variant: int) -> bytes:
    """Decoder entropy for the shift family, in the decoder's byte order.

    Byte 0 is choice 2, byte 1 sets rd = 1 + byte1 % 31, the immediate's low
    five bits are the shamt, byte 4 bit 5 opens the shift family and holds rs1,
    and byte 6 selects SLLI (0), SRLI (1) or SRAI (2) while staying below the
    0xc0 edit field.
    """
    assert 1 <= rd <= 31 and 0 <= shamt < 32 and 0 <= rs1 < 32
    return bytes((2, rd - 1, shamt, 0x0F, 0x20 | rs1, 0x00, variant,
                  0x00, 0x00, 0x00, 0x00, 0x00))


# --------------------------------------------------------------------------
# Encoding gold standard: bit-exact words and their field decomposition
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation,rd,rs1,shamt,word", SHIFT_GOLDEN)
def test_shift_golden_encoding_is_bit_exact(operation, rd, rs1, shamt, word):
    instruction = Rv32iInstruction(operation, rd=rd, rs1=rs1, immediate=shamt)
    assert instruction.word() == word
    assert instruction.word() == _itype(_funct3(operation), shamt, rs1, rd,
                                        high=_high(operation))
    # The same word, decomposed by hand: every field is where RV32I says.
    assert word & 0x7F == OP_IMM
    assert (word >> 12) & 7 == _funct3(operation)
    assert (word >> 7) & 31 == rd
    assert (word >> 15) & 31 == rs1
    assert (word >> 20) & 31 == shamt
    assert (word >> 25) & 0x7F == _high(operation)
    # rs2 is not a field of OP-IMM: the shamt high bit is not a register.
    assert instruction.rs2 == 0


@pytest.mark.parametrize("operation", SHIFT_OPERATIONS)
def test_rv32i_high_immediate_bits_are_zero_or_the_sra_flag(operation):
    for shamt in (0, 1, 31):
        word = Rv32iInstruction(operation, rd=3, rs1=4,
                                immediate=shamt).word()
        assert (word >> 25) & 0x7F == _high(operation)
        assert word & 3 == 3


def test_srli_and_srai_differ_only_in_the_sra_bit():
    srli = Rv32iInstruction("SRLI", rd=9, rs1=10, immediate=3).word()
    srai = Rv32iInstruction("SRAI", rd=9, rs1=10, immediate=3).word()
    assert srli == 0x00355493
    assert srai == 0x40355493
    assert srai ^ srli == 1 << 30
    assert instruction_operator_id(_bytes(srli)) == "rv32i:SRLI"
    assert instruction_operator_id(_bytes(srai)) == "rv32i:SRAI"


def test_slli_x0_x0_0_is_a_shift_and_not_the_canonical_nop():
    assert Rv32iInstruction("SLLI", rd=0, rs1=0, immediate=0).word() == 0x00001013
    assert instruction_operator_id(_bytes(0x00000013)) == "rv32i:NOP"
    assert instruction_operator_id(_bytes(0x00001013)) == "rv32i:SLLI"


# --------------------------------------------------------------------------
# Field boundaries: rd / rs1 / shamt
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation", SHIFT_OPERATIONS)
def test_register_field_boundaries_are_rv32i_registers(operation):
    for register in (0, 31):
        instruction = Rv32iInstruction(operation, rd=register, rs1=register,
                                       immediate=0)
        validate_instruction_bytes(fragment_bytes((instruction,)))
    for name in ("rd", "rs1"):
        for value in (-1, 32, True):
            rejection = _caught(lambda: Rv32iInstruction(
                operation, **{name: value}))
            assert (rejection.code, rejection.pointer) == (
                rc.RejectionCode.FIELD_BAD_REGISTER, f"instruction.{name}")


@pytest.mark.parametrize("shamt", [0, 1, 31])
def test_shamt_zero_and_thirty_one_are_legal_and_round_trip(shamt):
    for operation in SHIFT_OPERATIONS:
        instruction = Rv32iInstruction(operation, rd=11, rs1=21,
                                       immediate=shamt)
        data = fragment_bytes((instruction,))
        assert validate_instruction_bytes_detailed(data) is None
        assert validate_instruction_bytes(data) is None
        assert instruction_operator_id(data) == f"rv32i:{operation}"
        assert (instruction.word() >> 20) & 31 == shamt


@pytest.mark.parametrize("shamt", [32, 63, 64, -1, True])
def test_shamt_thirty_two_and_beyond_is_a_bad_shamt(shamt):
    for operation in SHIFT_OPERATIONS:
        rejection = _caught(lambda: Rv32iInstruction(
            operation, rd=1, rs1=2, immediate=shamt))
        assert (rejection.code, rejection.pointer) == (
            rc.RejectionCode.FIELD_BAD_SHAMT, "instruction.shamt")
        assert rejection.detail["immediate"] == shamt
        assert rejection.detail["operation"] == operation


@pytest.mark.parametrize("operation", SHIFT_OPERATIONS)
def test_shifts_have_no_rs2_operand(operation):
    rejection = _caught(lambda: Rv32iInstruction(
        operation, rd=1, rs1=2, rs2=3, immediate=4))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.ISA_UNEXPECTED_OPERAND, "instruction.rs2")
    assert rejection.detail == {"operation": operation, "value": 3}


# --------------------------------------------------------------------------
# Bit-exact word-level refusals for reserved immediate bits
# --------------------------------------------------------------------------

@pytest.mark.parametrize("funct3,immediate,legal", SHIFT_IMMEDIATE_MATRIX)
def test_word_level_reserved_shift_immediate_bits(funct3, immediate, legal):
    word = _itype(funct3, 0, 5, 3) | ((immediate & 0xFFF) << 20)
    data = _bytes(word)
    if legal:
        assert validate_instruction_bytes_detailed(data) is None
        validate_instruction_bytes(data)
        expected = "SRAI" if immediate & 0x400 else ("SLLI" if funct3 == 1
                                                     else "SRLI")
        assert instruction_operator_id(data) == f"rv32i:{expected}"
        return
    rejection = _caught(lambda: validate_instruction_bytes(data))
    assert rejection.code is rc.RejectionCode.ISA_RESERVED_IMM_BIT
    assert rejection.pointer == "fragment[0].immediate"
    assert rejection.detail["immediate"] == immediate
    assert rejection.detail["shamt"] == immediate & 31
    assert rejection.detail["funct3"] == funct3
    assert rejection.detail["opcode"] == OP_IMM


def test_reserved_immediate_pointer_names_the_failing_word():
    legal = _bytes(Rv32iInstruction("SLLI", rd=1, rs1=2, immediate=5).word())
    illegal = _bytes(_itype(1, 0, 5, 3) | (0x020 << 20))
    assert validate_instruction_bytes_detailed(legal * 2) is None
    rejection = _caught(lambda: validate_instruction_bytes(
        legal + illegal + legal))
    assert rejection.pointer == "fragment[4].immediate"
    assert rejection.detail["opcode"] == OP_IMM


def test_srai_imm10_is_the_only_legal_high_bit_and_imm11_is_not():
    legal = Rv32iInstruction("SRAI", rd=5, rs1=6, immediate=9).word()
    illegal = _itype(5, 9, 6, 5, high=0b1000000)
    assert legal == _itype(5, 9, 6, 5, high=SRA_HIGH)
    assert validate_instruction_bytes_detailed(_bytes(legal)) is None
    rejection = _caught(lambda: validate_instruction_bytes(_bytes(illegal)))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.ISA_RESERVED_IMM_BIT, "fragment[0].immediate")


@pytest.mark.parametrize("funct3", [2, 3])
def test_slti_and_sltiu_stay_outside_the_deliberate_legal_subset(funct3):
    """Shifts widen OP-IMM; SLTI/SLTIU remain refused with a precise funct3."""
    word = _itype(funct3, 0, 5, 3) | (1 << 20)
    rejection = _caught(lambda: validate_instruction_bytes(_bytes(word)))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.ISA_DISALLOWED_OPERATION, "fragment[0].funct3")
    assert rejection.detail == {"funct3": funct3, "opcode": OP_IMM}


# --------------------------------------------------------------------------
# Round trip: word -> validate -> operator identity
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation,rd,rs1,shamt,word", SHIFT_GOLDEN)
def test_golden_words_round_trip_through_validation(operation, rd, rs1, shamt,
                                                    word):
    data = _bytes(word)
    assert validate_instruction_bytes_detailed(data) is None
    validate_instruction_bytes(data)
    assert instruction_operator_id(data) == f"rv32i:{operation}"
    rebuilt = Rv32iInstruction(operation, rd=rd, rs1=rs1, immediate=shamt)
    assert rebuilt.word().to_bytes(4, "little") == data


def test_operator_identity_names_every_shift_in_sequence():
    program = (Rv32iInstruction("SLLI", rd=1, rs1=2, immediate=3),
               Rv32iInstruction("SRLI", rd=4, rs1=5, immediate=6),
               Rv32iInstruction("SRAI", rd=7, rs1=8, immediate=31),
               Rv32iInstruction("NOP"))
    data = fragment_bytes(program)
    assert instruction_operator_id(data) == "rv32i:SLLI+SRLI+SRAI+NOP"
    assert validate_instruction_bytes_detailed(data) is None


def test_shift_fragment_is_admitted_once_into_reserved_memory():
    memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                              initialization_seed=1, max_initialized_bytes=0x100)
    memory.declare_instruction_slots(0x1000, 1)
    instruction = Rv32iInstruction("SRAI", rd=9, rs1=10, immediate=3)
    memory.accept_instructions(0x1000, fragment_bytes((instruction,)),
                               source_event_id="case-1")
    snapshot = memory.read(0x1000, 4, transaction_id="fetch")
    assert snapshot.value == 0x40355493
    with pytest.raises(ValueError) as failure:
        memory.accept_instructions(0x1000, fragment_bytes((instruction,)),
                                   source_event_id="case-2")
    rejection = rc.rejection_of(failure.value,
                                occupant_writer_kinds=snapshot.writer_kinds)
    assert rejection.code is rc.RejectionCode.SLOT_ALREADY_CONSUMED


# --------------------------------------------------------------------------
# Mutation space: the online decoder can reach every new operator
# --------------------------------------------------------------------------

@pytest.mark.parametrize("variant,operation", [(0, "SLLI"), (1, "SRLI"),
                                               (2, "SRAI")])
def test_decoded_mutation_space_selects_each_shift_operator(variant, operation):
    decoded = decode_instruction_fragment(_shift_entropy(5, 5, 7, variant))
    assert decoded == (Rv32iInstruction(operation, rd=5, rs1=7,
                                        immediate=5),)
    data = fragment_bytes(decoded)
    assert validate_instruction_bytes_detailed(data) is None
    assert instruction_operator_id(data) == f"rv32i:{operation}"


def test_shift_family_does_not_change_legacy_arithmetic_choices():
    expected = ((0x07, "ADDI"), (0x47, "ORI"), (0x87, "XORI"), (0xC7, "ANDI"))
    for selector, operation in expected:
        decoded = decode_instruction_fragment(
            bytes((2, 5, 0xFF, 0x0F, selector)))
        assert decoded == (Rv32iInstruction(operation, rd=6, rs1=7,
                                            immediate=-1),)
        assert instruction_operator_id(fragment_bytes(decoded)) == \
            f"rv32i:{operation}"


def test_every_shift_entropy_this_decoder_accepts_is_admissible():
    seen = set()
    for byte_four in (0x20, 0x27, 0x3F, 0x67, 0xBF, 0xE7, 0xFF):
        for byte_six in range(0x40):
            for immediate_byte in (0x00, 0x01, 0x1F, 0x20, 0x3F, 0xFF):
                decoded = decode_instruction_fragment(bytes(
                    (2, 4, immediate_byte, 0x0F, byte_four, 0x00, byte_six)))
                assert len(decoded) == 1
                operation = decoded[0].operation
                assert operation in SHIFT_OPERATIONS, decoded
                assert 0 <= decoded[0].immediate < 32
                assert (decoded[0].word() >> 25) & 0x7F == _high(operation)
                data = fragment_bytes(decoded)
                validate_instruction_bytes(data)
                assert instruction_operator_id(data) == f"rv32i:{operation}"
                seen.add(operation)
    assert seen == set(SHIFT_OPERATIONS)


def test_sequence_edit_keeps_precedence_over_the_shift_family():
    """Byte six's high bits still select the LUI edit, shift flag or not."""
    for edit, operator in ((0x40, "rv32i:LUI+ADDI"), (0x80, "rv32i:LUI"),
                           (0xC0, "rv32i:LUI+XORI+ADDI")):
        entropy = bytes((2, 4, 0xFF, 0x0F, 0x27, 0x56, edit,
                         0x12, 0x34, 0x56, 0x78, 0))
        decoded = decode_instruction_fragment(entropy)
        assert instruction_operator_id(fragment_bytes(decoded)) == operator


@pytest.mark.parametrize("operation", SHIFT_OPERATIONS)
def test_shift_operand_mutation_keeps_the_operator_legal(operation):
    seed = Rv32iInstruction(operation, rd=5, rs1=6, immediate=0)
    rd_change = mutate_instruction(seed, bytes((0, 0, 0, 31)))
    rs1_change = mutate_instruction(seed, bytes((1, 0, 0, 7)))
    shamt_change = mutate_instruction(seed, bytes((2, 0, 0, 31)))
    assert rd_change == Rv32iInstruction(operation, rd=31, rs1=6, immediate=0)
    assert rs1_change == Rv32iInstruction(operation, rd=5, rs1=7, immediate=0)
    assert shamt_change == Rv32iInstruction(operation, rd=5, rs1=6,
                                             immediate=31)
    for changed in (rd_change, rs1_change, shamt_change):
        data = fragment_bytes((changed,))
        validate_instruction_bytes(data)
        assert instruction_operator_id(data) == f"rv32i:{operation}"
        assert (changed.word() >> 25) & 0x7F == _high(operation)


@pytest.mark.parametrize("operation", SHIFT_OPERATIONS)
def test_shift_instruction_is_not_an_mmio_operation(operation):
    rejection = _caught(lambda: mmio_access_fragment(
        operation, 0x40000000, windows=(MmioWindow(0x40000000, 4),),
        base_register=1, data_register=2))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.ISA_DISALLOWED_OPERATION, "mmio.operation")


# --------------------------------------------------------------------------
# The declared online decoder reaches the new operators from real records
# --------------------------------------------------------------------------

#: Directed eight-byte records for the declared online decoder. Each is the
#: one starting testcase the RFuzz client submits for ``--seed-input``, so a
#: real session can be pointed at one shift operator without changing code:
#: byte 4 selects choice 2, byte 5 is the register byte that also picks the
#: variant, byte 6 is the immediate whose low five bits become the shamt, and
#: byte 8 bit 5 opens the shift family with rs1 = 7.
ONLINE_SHIFT_RECORDS = {
    "SLLI": bytes.fromhex("0001000203050027"),
    "SRLI": bytes.fromhex("0000000204050027"),
    "SRAI": bytes.fromhex("0000000205050027"),
}


@pytest.mark.parametrize("operation,rd", [("SLLI", 4), ("SRLI", 5),
                                          ("SRAI", 6)])
def test_declared_online_decoder_selects_shifts_from_real_records(operation,
                                                                  rd):
    raw = ONLINE_SHIFT_RECORDS[operation]
    decoder = make_ibex_pulp_dual_source_online_decoder()
    case = decoder.decode(raw)
    assert isinstance(case.source, OnlineInstruction)
    expected = fragment_bytes((Rv32iInstruction(operation, rd=rd, rs1=7,
                                                immediate=5),))
    assert case.source.data == expected
    assert case.source.address == decoder.instruction_start
    metadata = decoder.decision_metadata(case)
    assert metadata["operator_id"] == f"rv32i:{operation}"
    assert metadata["source_id"] == "cpu.online_instruction"
    validate_instruction_bytes(case.source.data)
