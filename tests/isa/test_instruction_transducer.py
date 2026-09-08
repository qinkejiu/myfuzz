from __future__ import annotations

import pytest

from myfuzz.isa import IsaContract, RiscvInstructionTransducer


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
