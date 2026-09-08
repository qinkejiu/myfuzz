from __future__ import annotations

import pytest

from myfuzz.isa import IsaContract, RiscvInstructionTransducer


_C_ADDI4SPN_NZUIMM_MASK = (
    (1 << 12) | (0x3 << 11) | (0xF << 7) | (0x3 << 5)
)


def _compressed_operation(word: int, xlen: int) -> str | None:
    quadrant = word & 0x3
    funct3 = (word >> 13) & 0x7
    rd = (word >> 7) & 0x1F
    rs2 = (word >> 2) & 0x1F
    if quadrant == 0:
        return {
            0: "C.ADDI4SPN",
            2: "C.LW",
            3: "C.LD" if xlen == 64 else None,
            6: "C.SW",
            7: "C.SD" if xlen == 64 else None,
        }.get(funct3)
    if quadrant == 1:
        if funct3 == 0:
            return "C.ADDI"
        if funct3 == 1:
            return "C.JAL" if xlen == 32 else "C.ADDIW"
        if funct3 == 2:
            return "C.LI"
        if funct3 == 3:
            return "C.ADDI16SP" if rd == 2 else "C.LUI"
        if funct3 == 4:
            subform = (word >> 10) & 0x3
            if subform < 3:
                return ("C.SRLI", "C.SRAI", "C.ANDI")[subform]
            operation = (word >> 5) & 0x3
            if not (word >> 12) & 1:
                return ("C.SUB", "C.XOR", "C.OR", "C.AND")[operation]
            if xlen == 64 and operation < 2:
                return ("C.SUBW", "C.ADDW")[operation]
            return None
        return {5: "C.J", 6: "C.BEQZ", 7: "C.BNEZ"}.get(funct3)
    if quadrant == 2:
        if funct3 == 0:
            return "C.SLLI"
        if funct3 == 2:
            return "C.LWSP"
        if funct3 == 3:
            return "C.LDSP" if xlen == 64 else None
        if funct3 == 4:
            if not (word >> 12) & 1:
                return "C.JR" if rs2 == 0 else "C.MV"
            if rd == 0:
                return "C.EBREAK" if rs2 == 0 else None
            return "C.JALR" if rs2 == 0 else "C.ADD"
        return {
            6: "C.SWSP",
            7: "C.SDSP" if xlen == 64 else None,
        }.get(funct3)
    return None


def test_rv32im_repair_selects_multiple_legal_operations() -> None:
    tx = RiscvInstructionTransducer(IsaContract(32, ("I", "M")))
    choices = [tx.repair(selector, 0xFEDC_BA98) for selector in range(256)]

    assert len({item.operation for item in choices}) >= 10
    assert all(item.legal for item in choices)
    assert all(tx.provider.is_legal_word(item.word) for item in choices)


def test_addi_repairs_only_fixed_bits() -> None:
    tx = RiscvInstructionTransducer(IsaContract(32, ("I",)))
    result = tx.repair_for_operation("ADDI", 0xFFFF_FFFF)

    assert result.word & 0x7F == 0x13
    assert (result.word >> 12) & 7 == 0
    assert result.word & result.free_mask == 0xFFFF_FFFF & result.free_mask
    assert result.free_mask == (~((0x7F) | (7 << 12))) & 0xFFFF_FFFF


def test_rv32_templates_follow_i_and_m_capabilities() -> None:
    i_only = RiscvInstructionTransducer(IsaContract(32, ("I",)))
    with_m = RiscvInstructionTransducer(IsaContract(32, ("I", "M")))

    assert "MUL" not in {template.name for template in i_only.templates}
    assert {"MUL", "MULH", "DIV", "REMU"} <= {
        template.name for template in with_m.templates
    }
    with pytest.raises(ValueError, match="unavailable operation"):
        i_only.repair_for_operation("MUL", 0)


def test_rv32c_selector_range_produces_only_legal_compressed_forms() -> None:
    tx = RiscvInstructionTransducer(
        IsaContract(32, ("I", "C"), instruction_alignment=2)
    )
    choices = [
        tx.repair(selector, selector * 0x101, width=16)
        for selector in range(256)
    ]

    assert len({item.operation for item in choices}) >= 10
    assert {item.width for item in choices} == {16}
    assert all(item.legal for item in choices)
    assert all(
        tx.provider.is_legal_word(item.word, compressed=True) for item in choices
    )


@pytest.mark.parametrize(
    ("operation", "word"),
    (("C.SRLI", 0x9001), ("C.SRAI", 0x9401), ("C.ANDI", 0x9805)),
)
def test_rv64c_repair_preserves_legal_same_operation_bit_12(
    operation: str, word: int
) -> None:
    tx = RiscvInstructionTransducer(
        IsaContract(64, ("I", "C"), instruction_alignment=2)
    )
    assert tx.provider.is_legal_word(word, compressed=True)
    assert _compressed_operation(word, 64) == operation

    result = tx.repair_for_operation(operation, word)

    assert result.word == word
    assert result.free_mask & (1 << 12)


@pytest.mark.parametrize("xlen", (32, 64))
def test_every_legal_compressed_operation_is_a_repair_fixed_point(xlen: int) -> None:
    tx = RiscvInstructionTransducer(
        IsaContract(xlen, ("I", "M", "C"), instruction_alignment=2)
    )
    compressed_operations = {
        template.name for template in tx.templates if template.width == 16
    }
    seen: set[str] = set()
    for word in range(1 << 16):
        operation = _compressed_operation(word, xlen)
        if operation not in compressed_operations:
            continue
        if not tx.provider.is_legal_word(word, compressed=True):
            continue
        seen.add(operation)
        assert tx.repair_for_operation(operation, word).word == word

    assert seen == compressed_operations


@pytest.mark.parametrize("xlen", (32, 64))
@pytest.mark.parametrize("word", (0x9805, 0x9855, 0x987D, 0x8801, 0x887D))
def test_c_andi_legal_immediates_are_preserved_without_provider_filter(
    xlen: int, word: int,
) -> None:
    # Independent opcode oracle: quadrant 1, funct3=100, bits[11:10]=10.
    # https://github.com/riscv/riscv-opcodes/blob/master/extensions/rv_c
    # All six immediate bits (including the sign bit at bit 12) are legal.
    assert word & 0xEC03 == 0x8801
    tx = RiscvInstructionTransducer(
        IsaContract(xlen, ("I", "C"), instruction_alignment=2)
    )
    assert tx.provider.is_legal_word(word, compressed=True)
    choice = tx.repair_for_operation("C.ANDI", word)
    assert choice.word == word
    assert choice.free_mask & 0x107C == 0x107C


@pytest.mark.parametrize("xlen", (32, 64))
def test_i_only_never_generates_or_accepts_zicsr_instructions(xlen: int) -> None:
    tx = RiscvInstructionTransducer(IsaContract(xlen, ("I",)))
    assert not any(template.name.startswith("CSR") for template in tx.templates)
    for selector in range(256):
        word = tx.repair(selector, 0xFFFFFFFF).word
        assert not (word & 0x7F == 0x73 and (word >> 12) & 7 in (1, 2, 3, 5, 6, 7))
    for funct3 in (1, 2, 3, 5, 6, 7):
        assert not tx.provider.is_legal_word(0x30000073 | funct3 << 12)


@pytest.mark.parametrize(
    ("operation", "raw"),
    (
        ("C.ADDI4SPN", 0),
        ("C.ADDI", 0x0004),
        ("C.LI", 0),
        ("C.ADDI16SP", 0),
        ("C.LUI", 0),
        ("C.SRLI", 0),
        ("C.SRAI", 0),
        ("C.ANDI", 0xFFFF),
        ("C.SLLI", 0),
        ("C.LWSP", 0),
        ("C.JR", 0),
        ("C.MV", 0),
        ("C.JALR", 0),
        ("C.ADD", 0),
    ),
)
def test_compressed_reserved_encodings_are_minimally_repaired(
    operation: str, raw: int
) -> None:
    tx = RiscvInstructionTransducer(
        IsaContract(32, ("I", "C"), instruction_alignment=2)
    )

    result = tx.repair_for_operation(operation, raw)

    assert tx.provider.is_legal_word(result.word, compressed=True)
    assert result.word & result.free_mask == raw & result.free_mask


def test_all_rv32im_templates_preserve_every_reported_free_bit() -> None:
    tx = RiscvInstructionTransducer(IsaContract(32, ("I", "M")))
    payloads = (0, 0xFFFF_FFFF, 0xA5A5_5A5A)

    for template in tx.templates:
        if template.width != 32:
            continue
        for raw in payloads:
            choice = tx.repair_for_operation(template.name, raw)
            assert choice.word & choice.free_mask == raw & choice.free_mask
            assert tx.provider.is_legal_word(choice.word)


def test_illegal_class_is_disabled_by_default_and_explicit_when_enabled() -> None:
    tx = RiscvInstructionTransducer(IsaContract(32, ("I",)))

    assert tx.repair(0xFF, 0).legal
    illegal = tx.repair(0xFF, 0, illegal=True)
    assert not illegal.legal
    assert illegal.operation == "ILLEGAL"
    assert not tx.provider.is_legal_word(illegal.word)


@pytest.mark.parametrize(
    "contract",
    (
        IsaContract(32, ("I",)),
        IsaContract(32, ("I", "C"), instruction_alignment=2),
    ),
)
def test_explicit_illegal_class_is_one_rejected_32_bit_instruction(
    contract: IsaContract,
) -> None:
    tx = RiscvInstructionTransducer(contract)

    choice = tx.repair(255, 0x4000_4000, illegal=True)
    accepted = tx.provider.is_legal_word(choice.word)

    assert choice.width == 32
    assert choice.word & 0x3 == 0x3
    assert choice.word & 0x7F == 0x4B
    assert choice.legal == accepted
    assert not accepted


@pytest.mark.parametrize("raw", (0xFFFF, 0x1234_FFFF))
def test_explicit_16_bit_illegal_class_stays_compressed_and_rejected(
    raw: int,
) -> None:
    tx = RiscvInstructionTransducer(
        IsaContract(32, ("I", "C"), instruction_alignment=2)
    )

    choice = tx.repair(255, raw, illegal=True, width=16)
    accepted = tx.provider.is_legal_word(choice.word, compressed=True)

    assert choice.operation == "ILLEGAL"
    assert choice.width == 16
    assert 0 <= choice.word <= 0xFFFF
    assert choice.word & 0x3 == 0
    assert (choice.word >> 13) & 0x7 == 0
    assert choice.word & _C_ADDI4SPN_NZUIMM_MASK == 0
    assert choice.word & 0x1C == raw & 0x1C
    assert choice.legal == accepted
    assert not accepted
