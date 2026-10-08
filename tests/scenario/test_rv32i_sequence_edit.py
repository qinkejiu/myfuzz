"""Online sequence edits apply only to a still uncommitted instruction fragment."""

import pytest

from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.rv32i_sources import (
    Rv32iInstruction, decode_instruction_fragment, fragment_bytes,
    instruction_operator_id, validate_instruction_bytes,
)
from myfuzz.scenario.session_runtime import OnlineInstruction


def _entropy(edit: int) -> bytes:
    # Byte six controls the edit without changing the base sequence operands.
    return bytes((2, 4, 0xFF, 0x0F, 7, 0x56, edit, 0x12, 0x34, 0x56, 0x78, 0))


def _cpu_case(decoder, payload: bytes):
    for path_selector in range(256):
        case = decoder.decode(bytes((0, path_selector, 0, *payload)))
        if isinstance(case.source, OnlineInstruction):
            return case
    pytest.fail("online CPU source was not selected")


def test_sequence_edit_inserts_or_deletes_only_inside_uncommitted_fragment():
    base = decode_instruction_fragment(_entropy(0x40))
    deleted = decode_instruction_fragment(_entropy(0x80))
    inserted = decode_instruction_fragment(_entropy(0xC0))
    assert len(base) == 2
    assert base[0].operation == "LUI"
    assert base[1].operation == "ADDI"
    assert deleted == base[:1]
    assert inserted[:1] == base[:1]
    assert inserted[1].operation == "XORI"
    assert inserted[1].rd == inserted[1].rs1 == base[0].rd
    assert inserted[2:] == base[1:]
    assert tuple(map(len, map(fragment_bytes, (deleted, base, inserted)))) == (4, 8, 12)
    for program in (deleted, base, inserted):
        validate_instruction_bytes(fragment_bytes(program))


@pytest.mark.parametrize("edit_byte,words,operator", [
    (0x44, 2, "rv32i:LUI+ADDI"),
    (0x84, 1, "rv32i:LUI"),
    (0xC4, 3, "rv32i:LUI+XORI+ADDI"),
])
def test_online_edit_reserves_exact_future_words_and_operator_identity(edit_byte, words, operator):
    decoder = make_ibex_pulp_dual_source_online_decoder()
    # Online's five mutation bytes repeat to twelve; payload[1] becomes edit byte six.
    case = _cpu_case(decoder, bytes((2, edit_byte, 0xFF, 0x0F, 7)))
    assert len(case.source.data) == 4 * words
    assert instruction_operator_id(case.source.data) == operator
    start = decoder.instruction_cursor
    decoder.commit(case)
    assert decoder.instruction_cursor == start + 4 * words


def test_online_insert_at_last_word_falls_back_to_nop_without_cursor_overrun():
    decoder = make_ibex_pulp_dual_source_online_decoder()
    decoder.instruction_cursor = decoder.instruction_end - 4
    case = _cpu_case(decoder, bytes((2, 0xC4, 0xFF, 0x0F, 7)))
    assert case.source.data == fragment_bytes((Rv32iInstruction("NOP"),))
    decoder.commit(case)
    assert decoder.instruction_cursor == decoder.instruction_end


@pytest.mark.parametrize("occupant", ["admission_then_fetch", "store"])
def test_inserted_fragment_rejects_occupied_future_word_without_partial_write(occupant):
    memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                              initialization_seed=1, max_initialized_bytes=0x100)
    memory.declare_instruction_slots(0x1000, 4)
    if occupant == "admission_then_fetch":
        memory.accept_instructions(0x1008, fragment_bytes((Rv32iInstruction("NOP"),)),
                                   source_event_id="earlier")
        assert memory.read(0x1008, 4, transaction_id="fetch-earlier").value == 0x13
    else:
        memory.write(0x1008, 0x13, width_bytes=4, byte_enable=15,
                     writer_event_id="store-earlier")
    before = memory.state_summary()
    inserted = fragment_bytes(decode_instruction_fragment(_entropy(0xC0)))
    with pytest.raises(ValueError, match="overwrite determined bytes"):
        memory.accept_instructions(0x1000, inserted, source_event_id="later")
    assert memory.state_summary() == before
