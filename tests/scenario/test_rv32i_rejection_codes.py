"""Versioned rejection codes for RV32I fragments and online candidates.

Every code in ``candidate_rejection.v1`` has one real negative case here, built
from the public constructors of ``rv32i_sources``, ``MmioWindow``, the online
decoder and persistent memory. The natural-language message stays for humans;
the contract is the code plus the failing field pointer.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Callable

import pytest

from myfuzz.scenario import rejection_codes as rc
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.rv32i_sources import (
    MmioWindow, Rv32iInstruction, decode_instruction_fragment, fragment_bytes,
    fragment_image, instruction_operator_id, mmio_access_fragment,
    mmio_write_fragment, mutate_instruction, mutate_mmio_access,
    validate_instruction_bytes, validate_instruction_bytes_detailed,
)


NOP_BYTES = b"\x13\x00\x00\x00"
GOOD_WINDOW = MmioWindow(0x40000000, 0x1000)
#: funct3 2 (SLTI) stays outside the legal OP-IMM subset. funct3 1 and 5 are
#: now legal SLLI/SRLI/SRAI, so this refused fixture names the real SLTI form.
SLTI_WORD = ((1 << 20) | (1 << 15) | (2 << 12) | (1 << 7) | 0x13).to_bytes(4, "little")
MISALIGNED_LW = ((2 << 20) | (1 << 15) | (2 << 12) | (1 << 7) | 0x03).to_bytes(4, "little")
#: SLLI whose imm[5] is reserved by RV32I: a real, bit-exact refusal.
RESERVED_SHIFT_WORD = ((0x20 << 20) | (1 << 15) | (1 << 12) | (1 << 7) | 0x13).to_bytes(4, "little")


# --------------------------------------------------------------------------
# Fixtures built from public constructors only
# --------------------------------------------------------------------------

def _read_only_window() -> MmioWindow:
    return MmioWindow(0x40000000, 4, writable=False)


def _write_only_window() -> MmioWindow:
    return MmioWindow(0x40000000, 4, readable=False)


def _instruction_decoder(*, instruction_start: int = 0x1000,
                         instruction_end: int = 0x1004) -> OnlineCaseDecoder:
    return OnlineCaseDecoder(
        sources=(OnlineSource("cpu.it", "instruction", "cpu",
                              "CPU_TO_IP_TO_CPU", "cpu.path"),),
        ownership=compile_ownership((), ()), schedule=("cpu",),
        instruction_start=instruction_start, instruction_end=instruction_end)


def _pin_decoder(*, fields=(InputField("ip", "pin", 1),), owners=None,
                 width: int | None = None) -> OnlineCaseDecoder:
    if owners is None:
        owners = tuple(InputOwner(field.component_id, field.port, 0,
                                  field.width, "source", "external")
                       for field in fields)
    return OnlineCaseDecoder(
        sources=(OnlineSource("ip.pin", "source", "ip", "IP_TO_CPU", "ip.path",
                              port="pin", width=width or (fields[0].width if fields else 1)),),
        ownership=compile_ownership(fields, owners), schedule=("ip",),
        instruction_start=0x1000, instruction_end=0x1004)


def _mixed_decoder() -> OnlineCaseDecoder:
    return OnlineCaseDecoder(
        sources=(OnlineSource("cpu.it", "instruction", "cpu",
                              "CPU_TO_IP_TO_CPU", "cpu.path"),
                 OnlineSource("ip.pin", "source", "ip", "IP_TO_CPU", "ip.path",
                              port="pin", width=1)),
        ownership=compile_ownership(
            (InputField("ip", "pin", 1),),
            (InputOwner("ip", "pin", 0, 1, "source", "external"),)),
        schedule=("cpu", "ip"), instruction_start=0x1000,
        instruction_end=0x1004, support_words=1)


def _path_decoder(*, shared: bool = False) -> OnlineCaseDecoder:
    targets = (("shared.target", "shared.target") if shared
               else ("left.target", "right.target"))
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource("left", "source", "ip", ("IP_TO_CPU",), "left"),
                 OnlineDependencySource("right", "source", "ip", ("IP_TO_CPU",), "right")),
        rules=((DependencyRule("shared.target", ("left", "right"), "DATA_BINDING"),)
               if shared else
               (DependencyRule("left.target", ("left",), "DATA_BINDING"),
                DependencyRule("right.target", ("right",), "DATA_BINDING"))))
    return OnlineCaseDecoder(
        sources=(OnlineSource("left", "source", "ip", "IP_TO_CPU", targets[0], port="left"),
                 OnlineSource("right", "source", "ip", "IP_TO_CPU", targets[1], port="right")),
        ownership=compile_ownership(
            (InputField("ip", "left", 1), InputField("ip", "right", 1)),
            (InputOwner("ip", "left", 0, 1, "source", "external"),
             InputOwner("ip", "right", 0, 1, "source", "external"))),
        graph=graph, schedule=("ip",), instruction_start=0, instruction_end=4)


def _slot_memory(*, max_initialized_bytes: int = 0x100) -> PersistentMemory:
    memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                              initialization_seed=1,
                              max_initialized_bytes=max_initialized_bytes)
    memory.declare_instruction_slots(0x1000, 4)
    return memory


def _degraded_decoder() -> OnlineCaseDecoder:
    decoder = _instruction_decoder(instruction_end=0x1008)
    decoder.instruction_cursor = 0x1004
    return decoder


def _caught(call: Callable[[], object]) -> rc.Rejection:
    """Run a refused call and return the structured rejection it raised."""
    with pytest.raises(ValueError) as failure:
        call()
    rejection = rc.rejection_of(failure.value)
    assert rejection is not None, failure.value
    return rejection


def _select_raw(decoder: OnlineCaseDecoder, component: str,
                payload: bytes = bytes((7, 0, 0, 0, 0))) -> bytes:
    """Find one raw input that selects the wanted component."""
    for selector in range(256):
        raw = bytes((0, selector, 0, *payload))
        try:
            case = decoder.decode(raw)
        except ValueError:
            continue
        if case.source.component == component:
            return raw
    pytest.fail(f"no raw input selected {component}")


# --------------------------------------------------------------------------
# One real negative case per defined code
# --------------------------------------------------------------------------

def _triggers() -> dict[rc.RejectionCode, Callable[[], rc.Rejection]]:
    def memory_out_of_reservation() -> rc.Rejection:
        memory = _slot_memory()
        return _caught(lambda: memory.accept_instructions(
            0x1010, NOP_BYTES, source_event_id="later"))

    def memory_materialized() -> rc.Rejection:
        memory = _slot_memory()
        memory.write(0x1000, 0x13, width_bytes=4, byte_enable=15,
                     writer_event_id="store")
        with pytest.raises(ValueError) as failure:
            memory.accept_instructions(0x1000, NOP_BYTES, source_event_id="later")
        snapshot = memory.read(0x1000, 4, transaction_id="occupant-probe")
        return rc.rejection_of(failure.value,
                               occupant_writer_kinds=snapshot.writer_kinds)

    def memory_already_consumed() -> rc.Rejection:
        memory = _slot_memory()
        memory.accept_instructions(0x1000, NOP_BYTES, source_event_id="case-1")
        with pytest.raises(ValueError) as failure:
            memory.accept_instructions(0x1000, NOP_BYTES, source_event_id="case-2")
        snapshot = memory.read(0x1000, 4, transaction_id="occupant-probe")
        return rc.rejection_of(failure.value,
                               occupant_writer_kinds=snapshot.writer_kinds)

    def memory_budget() -> rc.Rejection:
        memory = _slot_memory(max_initialized_bytes=1)
        return _caught(lambda: memory.accept_instructions(
            0x1000, NOP_BYTES, source_event_id="case-1"))

    def declared_slots_materialized() -> rc.Rejection:
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                                  initialization_seed=1,
                                  max_initialized_bytes=0x100)
        memory.read(0x1000, 4, transaction_id="fetch")
        return _caught(lambda: memory.declare_instruction_slots(0x1000, 1))

    def decoder_out_of_reservation() -> rc.Rejection:
        decoder = _degraded_decoder()
        raw = _select_raw(decoder, "cpu", bytes((2, 0xC4, 0xFF, 0x0F, 7)))
        _, decision = decoder.decode_candidate(raw)
        assert decision.rejection is not None
        return decision.rejection

    def decoder_budget() -> rc.Rejection:
        decoder = _instruction_decoder()
        decoder.commit(decoder.decode(b"\x00\x00\x00"))
        _, decision = decoder.decode_candidate(b"\x01")
        assert decision.rejection is not None
        return decision.rejection

    def commit_out_of_reservation() -> rc.Rejection:
        decoder = _mixed_decoder()
        case = decoder.decode(_select_raw(decoder, "ip"))
        decoder.instruction_end = decoder.instruction_cursor
        decision = decoder.commit_candidate(case)
        assert decision.rejection is not None
        return decision.rejection

    def proposal_mismatch() -> rc.Rejection:
        decoder = _pin_decoder()
        foreign = _path_decoder(shared=True).decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
        decision = decoder.commit_candidate(foreign)
        assert decision.rejection is not None
        return decision.rejection

    def undeclared_path() -> rc.Rejection:
        decoder = _path_decoder()
        case = decoder.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
        return _caught(lambda: decoder.decision_metadata(
            replace(case, path_id="missing.target")))

    def source_mismatch() -> rc.Rejection:
        decoder = _path_decoder()
        case = decoder.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
        return _caught(lambda: decoder.decision_metadata(
            replace(case, source=replace(case.source, component="other"))))

    def unbounded_input() -> rc.Rejection:
        return _caught(lambda: _pin_decoder().decode(b""))

    def bad_hint() -> rc.Rejection:
        return _caught(lambda: _pin_decoder().decode(
            b"\x00\x00\x00", coverage_hints={"unknown": 1}))

    return {
        rc.RejectionCode.ISA_DISALLOWED_OPERATION:
            lambda: _caught(lambda: Rv32iInstruction("SLT", rd=1, rs1=2, rs2=3)),
        rc.RejectionCode.ISA_UNEXPECTED_OPERAND:
            lambda: _caught(lambda: Rv32iInstruction("LUI", rd=1, rs1=2)),
        rc.RejectionCode.ISA_RESERVED_IMM_BIT:
            lambda: _caught(lambda: validate_instruction_bytes(
                RESERVED_SHIFT_WORD)),
        rc.RejectionCode.FIELD_BAD_REGISTER:
            lambda: _caught(lambda: Rv32iInstruction("ADDI", rd=32, rs1=1)),
        rc.RejectionCode.FIELD_REGISTER_CONFLICT:
            lambda: _caught(lambda: mmio_access_fragment(
                "LW", 0x40000000, windows=(GOOD_WINDOW,),
                base_register=1, data_register=1)),
        rc.RejectionCode.FIELD_BAD_IMMEDIATE:
            lambda: _caught(lambda: Rv32iInstruction("ADDI", rd=1, rs1=1,
                                                     immediate=1 << 11)),
        rc.RejectionCode.FIELD_BAD_SHAMT:
            lambda: _caught(lambda: Rv32iInstruction("SLLI", rd=1, rs1=2,
                                                     immediate=32)),
        rc.RejectionCode.FIELD_BAD_ALIGNMENT:
            lambda: _caught(lambda: Rv32iInstruction("LW", rd=1, rs1=1,
                                                     immediate=2)),
        rc.RejectionCode.FIELD_BAD_ADDRESS:
            lambda: _caught(lambda: mmio_access_fragment(
                "LW", 1 << 32, windows=(GOOD_WINDOW,),
                base_register=1, data_register=2)),
        rc.RejectionCode.FRAGMENT_INVALID_SEQUENCE:
            lambda: _caught(lambda: fragment_bytes(())),
        rc.RejectionCode.FRAGMENT_EXCEEDS_ADDRESS_SPACE:
            lambda: _caught(lambda: fragment_image(
                "img", "cpu", 0xFFFFFFFC,
                (Rv32iInstruction("NOP"), Rv32iInstruction("NOP")))),
        rc.RejectionCode.MMIO_BAD_WINDOW:
            lambda: _caught(lambda: MmioWindow(0x40000000, 0)),
        rc.RejectionCode.MMIO_BAD_PERMISSION:
            lambda: _caught(lambda: MmioWindow(0x40000000, 4, readable=1)),
        rc.RejectionCode.MMIO_BAD_WIDTH:
            lambda: _caught(lambda: MmioWindow(0x40000000, 4, write_widths=(2,))),
        rc.RejectionCode.MMIO_NO_WINDOW:
            lambda: _caught(lambda: mmio_access_fragment(
                "LW", 0x40000000, windows=(), base_register=1, data_register=2)),
        rc.RejectionCode.MMIO_OUT_OF_WINDOW:
            lambda: _caught(lambda: mmio_access_fragment(
                "LW", 0x50000000, windows=(GOOD_WINDOW,),
                base_register=1, data_register=2)),
        rc.RejectionCode.MMIO_READ_ONLY:
            lambda: _caught(lambda: mmio_access_fragment(
                "SW", 0x40000000, windows=(_read_only_window(),),
                base_register=1, data_register=2)),
        rc.RejectionCode.MMIO_WRITE_ONLY:
            lambda: _caught(lambda: mmio_access_fragment(
                "LW", 0x40000000, windows=(_write_only_window(),),
                base_register=1, data_register=2)),
        rc.RejectionCode.MMIO_WINDOW_DENIED:
            lambda: _caught(lambda: mutate_mmio_access(
                "SB", b"\x00\x00\x00\x00", windows=(_read_only_window(),),
                base_register=1, data_register=2)),
        rc.RejectionCode.MMIO_NO_ALIGNED_ADDRESS:
            lambda: _caught(lambda: mutate_mmio_access(
                "LW", b"\x00\x00\x00\x00", windows=(MmioWindow(0x40000001, 3),),
                base_register=1, data_register=2)),
        rc.RejectionCode.DECODE_MALFORMED_RECORD:
            lambda: _caught(lambda: validate_instruction_bytes(b"\x13")),
        rc.RejectionCode.DECODE_MALFORMED_ENTROPY:
            lambda: _caught(lambda: mutate_instruction(
                Rv32iInstruction("NOP"), b"\x00")),
        rc.RejectionCode.DECODE_MALFORMED_SEED:
            lambda: _caught(lambda: mutate_instruction("NOP", b"\x00\x00\x00\x00")),
        rc.RejectionCode.DECODE_UNBOUNDED_INPUT: unbounded_input,
        rc.RejectionCode.DECODE_BAD_COVERAGE_HINT: bad_hint,
        rc.RejectionCode.OWNERSHIP_BOUND_INPUT:
            lambda: _caught(lambda: _pin_decoder(owners=(
                InputOwner("ip", "pin", 0, 1, "bound", "route"),))),
        rc.RejectionCode.OWNERSHIP_FIXED_INPUT:
            lambda: _caught(lambda: _pin_decoder(owners=(
                InputOwner("ip", "pin", 0, 1, "fixed", "constant"),))),
        rc.RejectionCode.OWNERSHIP_UNDECLARED_FIELD:
            lambda: _caught(lambda: _pin_decoder(fields=(), owners=(), width=1)),
        rc.RejectionCode.OWNERSHIP_RANGE_EXCEEDS_FIELD:
            lambda: _caught(lambda: _pin_decoder(width=2)),
        rc.RejectionCode.OWNERSHIP_AMBIGUOUS_PRODUCER:
            lambda: _caught(lambda: OnlineCaseDecoder(
                sources=(OnlineSource("ip.pin", "source", "ip", "IP_TO_CPU",
                                      "ip.path", port="pin", width=2),),
                ownership=compile_ownership(
                    (InputField("ip", "pin", 2),),
                    (InputOwner("ip", "pin", 0, 1, "source", "left"),
                     InputOwner("ip", "pin", 1, 1, "source", "right"))),
                schedule=("ip",), instruction_start=0x1000, instruction_end=0x1004)),
        rc.RejectionCode.SLOT_OUT_OF_RESERVATION: decoder_out_of_reservation,
        rc.RejectionCode.SLOT_MATERIALIZED: memory_materialized,
        rc.RejectionCode.SLOT_ALREADY_CONSUMED: memory_already_consumed,
        rc.RejectionCode.SLOT_PROPOSAL_MISMATCH: proposal_mismatch,
        rc.RejectionCode.BUDGET_EXHAUSTED: decoder_budget,
        rc.RejectionCode.PATH_UNDECLARED: undeclared_path,
        rc.RejectionCode.PATH_SOURCE_MISMATCH: source_mismatch,
    }


def _extra_triggers() -> dict[str, Callable[[], rc.Rejection]]:
    """Second, independent negative case for codes reached on several branches."""

    def malformed_metadata() -> rc.Rejection:
        return _caught(lambda: _path_decoder().decision_metadata("not-a-case"))

    def memory_out_of_reservation() -> rc.Rejection:
        memory = _slot_memory()
        return _caught(lambda: memory.accept_instructions(
            0x1010, NOP_BYTES, source_event_id="later"))

    def memory_budget() -> rc.Rejection:
        memory = _slot_memory(max_initialized_bytes=1)
        return _caught(lambda: memory.accept_instructions(
            0x1000, NOP_BYTES, source_event_id="case-1"))

    def declared_slots_materialized() -> rc.Rejection:
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                                  initialization_seed=1,
                                  max_initialized_bytes=0x100)
        memory.read(0x1000, 4, transaction_id="fetch")
        return _caught(lambda: memory.declare_instruction_slots(0x1000, 1))

    def commit_out_of_reservation() -> rc.Rejection:
        decoder = _mixed_decoder()
        case = decoder.decode(_select_raw(decoder, "ip"))
        decoder.instruction_end = decoder.instruction_cursor
        decision = decoder.commit_candidate(case)
        assert decision.rejection is not None
        return decision.rejection

    def srai_imm11_reserved() -> rc.Rejection:
        word = ((0x800 << 20) | (1 << 15) | (5 << 12) | (1 << 7) | 0x13)
        return _caught(lambda: validate_instruction_bytes(
            word.to_bytes(4, "little")))

    def srai_shamt_too_wide() -> rc.Rejection:
        return _caught(lambda: Rv32iInstruction("SRAI", rd=1, rs1=2,
                                                immediate=63))

    return {
        "decode.malformed_record:metadata": malformed_metadata,
        "slot.out_of_reservation:memory": memory_out_of_reservation,
        "slot.materialized:reservation": declared_slots_materialized,
        "budget.exhausted:memory": memory_budget,
        "slot.out_of_reservation:commit": commit_out_of_reservation,
        "isa.reserved_imm_bit:srai_imm11": srai_imm11_reserved,
        "field.bad_shamt:srai": srai_shamt_too_wide,
    }


# --------------------------------------------------------------------------
# Catalog and value object
# --------------------------------------------------------------------------

def test_catalog_is_versioned_and_frozen():
    catalog = rc.rejection_code_catalog()
    assert catalog["schema_version"] == "candidate_rejection_catalog.v1"
    assert catalog["rejection_schema_version"] == "candidate_rejection.v1"
    # 35 codes -> 37 with isa.reserved_imm_bit and field.bad_shamt. No existing
    # code was renamed or removed; only this digest changes.
    assert rc.rejection_code_catalog_sha256() == (
        "86d03337fa3955b18ea05429a1c0eaa8c3c5bb21a56332d02a6a390d7e560577")
    codes = [row["code"] for row in catalog["codes"]]
    assert codes == sorted(codes)
    assert codes == sorted(code.value for code in rc.RejectionCode)


def test_every_code_has_a_short_english_description():
    for code in rc.RejectionCode:
        description = rc.description_of(code)
        assert isinstance(description, str) and description
        assert description == description.strip()
        assert 10 <= len(description) <= 120


def test_every_defined_code_is_covered_by_a_trigger():
    assert set(_triggers()) == set(rc.RejectionCode)


@pytest.mark.parametrize("name", sorted(_extra_triggers()))
def test_secondary_triggers_reach_the_code_in_their_name(name):
    """Codes reached on several branches stay reachable on each of them."""
    rejection = _extra_triggers()[name]()
    assert rejection.code.value == name.split(":")[0]


@pytest.mark.parametrize("code", sorted(rc.RejectionCode, key=lambda item: item.value))
def test_each_code_has_a_real_negative_case(code):
    rejection = _triggers()[code]()
    assert rejection.code == code
    assert rejection.pointer
    assert rejection.schema_version == "candidate_rejection.v1"
    assert json.loads(json.dumps(rejection.document()))["code"] == code.value


def test_unknown_or_malformed_rejections_are_refused():
    good = rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "instruction.rd",
                        {"value": 32})
    assert good.schema_version == "candidate_rejection.v1"
    assert rc.Rejection("field.bad_register", "instruction.rd").code is \
        rc.RejectionCode.FIELD_BAD_REGISTER
    with pytest.raises(ValueError, match="unknown rejection code"):
        rc.Rejection("made.up.code", "instruction.rd")
    with pytest.raises(ValueError, match="unknown rejection code"):
        rc.Rejection(7, "instruction.rd")
    with pytest.raises(ValueError, match="schema"):
        rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "instruction.rd",
                     schema_version="candidate_rejection.v2")
    with pytest.raises(ValueError, match="pointer"):
        rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "")
    with pytest.raises(ValueError, match="pointer"):
        rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "not a path")
    with pytest.raises(ValueError, match="float"):
        rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "instruction.rd",
                     {"value": 0.5})
    with pytest.raises(ValueError, match="JSON"):
        rc.Rejection(rc.RejectionCode.FIELD_BAD_REGISTER, "instruction.rd",
                     {"value": object()})


def test_rejection_document_is_stable_and_round_trips():
    rejection = rc.Rejection(rc.RejectionCode.MMIO_OUT_OF_WINDOW, "mmio.address",
                             {"address": 0x50000000, "windows": ((0x40000000, 4),)})
    document = rejection.document()
    assert document == {
        "schema_version": "candidate_rejection.v1",
        "code": "mmio.out_of_window",
        "pointer": "mmio.address",
        "detail": {"address": 0x50000000, "windows": [[0x40000000, 4]]},
    }
    assert json.loads(json.dumps(document)) == document
    assert rc.Rejection.from_document(document) == rejection
    with pytest.raises(ValueError, match="unknown rejection code"):
        rc.Rejection.from_document({**document, "code": "made.up"})
    with pytest.raises(ValueError, match="schema"):
        rc.Rejection.from_document({**document, "schema_version": "nope"})
    with pytest.raises(ValueError, match="keys"):
        rc.Rejection.from_document({"code": "mmio.out_of_window"})


def test_rejection_is_immutable_and_hashable():
    rejection = rc.Rejection(rc.RejectionCode.FIELD_BAD_ALIGNMENT,
                             "instruction.immediate", {"immediate": 2})
    with pytest.raises(AttributeError):
        rejection.pointer = "other"
    assert len({rejection, rc.Rejection(rc.RejectionCode.FIELD_BAD_ALIGNMENT,
                                        "instruction.immediate",
                                        {"immediate": 2})}) == 1


def test_rejection_error_remains_a_value_error():
    error = rc.RejectionError("legacy message", rc.Rejection(
        rc.RejectionCode.ISA_DISALLOWED_OPERATION, "instruction.operation"))
    assert isinstance(error, ValueError)
    assert str(error) == "legacy message"
    assert rc.rejection_of(error).code is rc.RejectionCode.ISA_DISALLOWED_OPERATION
    assert rc.rejection_of(ValueError("no code here")) is None


# --------------------------------------------------------------------------
# Pointer precision: the failing field path, not just the code
# --------------------------------------------------------------------------

def test_instruction_field_rejections_point_at_the_failing_field():
    assert _caught(lambda: Rv32iInstruction("SLT")).pointer == "instruction.operation"
    assert _caught(lambda: Rv32iInstruction("ADDI", rd=-1)).pointer == "instruction.rd"
    assert _caught(lambda: Rv32iInstruction("ADDI", rs1=True)).pointer == "instruction.rs1"
    assert _caught(lambda: Rv32iInstruction("ADDI", rs2="1")).pointer == "instruction.rs2"
    assert _caught(lambda: Rv32iInstruction(
        "ADDI", immediate=1 << 11)).pointer == "instruction.immediate"
    assert _caught(lambda: Rv32iInstruction(
        "LUI", rd=1, immediate=1 << 20)).pointer == "instruction.immediate"
    assert _caught(lambda: Rv32iInstruction("LUI", rd=1, rs2=3)).pointer == "instruction.rs2"
    assert _caught(lambda: Rv32iInstruction("NOP", rs1=1)).pointer == "instruction.rs1"
    assert _caught(lambda: Rv32iInstruction(
        "NOP", immediate=1)).pointer == "instruction.immediate"
    assert _caught(lambda: Rv32iInstruction(
        "ADDI", rd=1, rs1=1, rs2=2)).pointer == "instruction.rs2"
    assert _caught(lambda: Rv32iInstruction(
        "SB", rd=1, rs1=2, rs2=3)).pointer == "instruction.rd"
    assert _caught(lambda: Rv32iInstruction(
        "SW", rs1=1, rs2=2, immediate=2)).pointer == "instruction.immediate"
    assert _caught(lambda: Rv32iInstruction(
        "SLLI", rd=1, rs1=2, immediate=32)).pointer == "instruction.shamt"
    assert _caught(lambda: Rv32iInstruction(
        "SRAI", rd=1, rs1=2, immediate=-1)).pointer == "instruction.shamt"
    assert _caught(lambda: Rv32iInstruction(
        "SRLI", rd=1, rs1=2, rs2=3)).pointer == "instruction.rs2"


def test_mmio_rejections_point_at_the_failing_field():
    assert _caught(lambda: MmioWindow("0x40000000", 4)).pointer == "window.base"
    assert _caught(lambda: MmioWindow(0x40000000, 0)).pointer == "window.size"
    assert _caught(lambda: MmioWindow(0xFFFFFFF0, 0x20)).pointer == "window.range"
    assert _caught(lambda: MmioWindow(
        0x40000000, 4, writable="yes")).pointer == "window.writable"
    assert _caught(lambda: MmioWindow(
        0x40000000, 4, readable=False, writable=False)).pointer == "window.permissions"
    assert _caught(lambda: MmioWindow(
        0x40000000, 4, write_widths=(1, 1))).pointer == "window.write_widths"
    assert _caught(lambda: mmio_access_fragment(
        "ADDI", 0x40000000, windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).pointer == "mmio.operation"
    assert _caught(lambda: mmio_access_fragment(
        "LW", 0x40000000, windows=(GOOD_WINDOW,), base_register=0,
        data_register=2)).pointer == "mmio.base_register"
    assert _caught(lambda: mmio_access_fragment(
        "LW", 0x40000000, windows=(GOOD_WINDOW,), base_register=1,
        data_register=1)).pointer == "mmio.data_register"
    assert _caught(lambda: mmio_access_fragment(
        "LW", 0x40000002, windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).pointer == "mmio.address"
    assert _caught(lambda: mmio_access_fragment(
        "LW", 0x40000000, windows=[GOOD_WINDOW], base_register=1,
        data_register=2)).pointer == "mmio.windows"
    assert _caught(lambda: mmio_write_fragment(
        "LW", 0x40000000, 1, windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).pointer == "mmio.operation"
    assert _caught(lambda: mmio_write_fragment(
        "SW", 0x40000000, 1 << 32, windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).pointer == "mmio.value"


def test_decode_and_fragment_rejections_point_at_the_failing_field():
    assert _caught(lambda: validate_instruction_bytes(b"")).pointer == "fragment.data"
    assert _caught(lambda: validate_instruction_bytes(b"\x13")).pointer == "fragment.data"
    assert _caught(lambda: validate_instruction_bytes(
        SLTI_WORD)).pointer == "fragment[0].funct3"
    assert _caught(lambda: validate_instruction_bytes(
        RESERVED_SHIFT_WORD)).pointer == "fragment[0].immediate"
    assert _caught(lambda: validate_instruction_bytes(
        MISALIGNED_LW)).pointer == "fragment[0].immediate"
    assert _caught(lambda: validate_instruction_bytes(
        NOP_BYTES + MISALIGNED_LW)).pointer == "fragment[4].immediate"
    assert _caught(lambda: fragment_bytes([Rv32iInstruction("NOP")])
                   ).pointer == "fragment.instructions"
    assert _caught(lambda: fragment_image(
        "img", "cpu", 2, (Rv32iInstruction("NOP"),))).pointer == "image.address"
    assert _caught(lambda: mutate_mmio_access(
        "LW", b"\x00", windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).pointer == "mutation.entropy"
    assert _caught(lambda: mutate_instruction(
        7, b"\x00\x00\x00\x00")).pointer == "mutation.seed"


def test_ownership_rejections_point_at_the_failing_source_field():
    bound = _caught(lambda: _pin_decoder(owners=(
        InputOwner("ip", "pin", 0, 1, "bound", "route"),)))
    assert (bound.code, bound.pointer) == (rc.RejectionCode.OWNERSHIP_BOUND_INPUT,
                                           "source.port")
    assert bound.detail == {"component": "ip", "port": "pin"}
    fixed = _caught(lambda: _pin_decoder(owners=(
        InputOwner("ip", "pin", 0, 1, "fixed", "constant"),)))
    assert (fixed.code, fixed.pointer) == (rc.RejectionCode.OWNERSHIP_FIXED_INPUT,
                                           "source.port")
    undeclared = _caught(lambda: _pin_decoder(fields=(), owners=(), width=1))
    assert undeclared.pointer == "source.port"
    ranged = _caught(lambda: _pin_decoder(width=2))
    assert ranged.pointer == "source.bit_offset"


def test_decision_rejections_point_at_the_failing_field():
    decoder = _path_decoder()
    case = decoder.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
    undeclared = _caught(lambda: decoder.decision_metadata(
        replace(case, path_id="missing.target")))
    assert (undeclared.code, undeclared.pointer) == (
        rc.RejectionCode.PATH_UNDECLARED, "case.path_id")
    mismatch = _caught(lambda: decoder.decision_metadata(
        replace(case, source=replace(case.source, component="other"))))
    assert (mismatch.code, mismatch.pointer) == (
        rc.RejectionCode.PATH_SOURCE_MISMATCH, "case.source.action_id")
    assert _caught(lambda: decoder.decision_metadata(
        "not-a-case")).pointer == "case"


def test_slot_and_budget_rejections_point_at_the_reservation():
    memory = _slot_memory()
    outside = _caught(lambda: memory.accept_instructions(
        0x1010, NOP_BYTES, source_event_id="later"))
    assert (outside.code, outside.pointer) == (
        rc.RejectionCode.SLOT_OUT_OF_RESERVATION, "memory.address")
    decoder = _instruction_decoder()
    decoder.commit(decoder.decode(b"\x00\x00\x00"))
    exhausted = _caught(lambda: decoder.decode(b"\x01"))
    assert (exhausted.code, exhausted.pointer) == (
        rc.RejectionCode.BUDGET_EXHAUSTED, "instruction.cursor")
    commit_rejection = _extra_triggers()["slot.out_of_reservation:commit"]()
    assert (commit_rejection.code, commit_rejection.pointer) == (
        rc.RejectionCode.SLOT_OUT_OF_RESERVATION, "instruction.cursor")


def test_materialized_and_consumed_slots_are_distinguished_by_writer_kind():
    materialized = _triggers()[rc.RejectionCode.SLOT_MATERIALIZED]()
    assert materialized.code is rc.RejectionCode.SLOT_MATERIALIZED
    assert materialized.detail == {"occupant": "STORE"}
    consumed = _triggers()[rc.RejectionCode.SLOT_ALREADY_CONSUMED]()
    assert consumed.code is rc.RejectionCode.SLOT_ALREADY_CONSUMED
    assert consumed.detail == {"occupant": "INSTRUCTION_SOURCE"}


# --------------------------------------------------------------------------
# One code per illegal input, whichever call path sees it
# --------------------------------------------------------------------------

def test_same_illegal_input_gets_one_code_on_every_call_path():
    from_bytes = _caught(lambda: validate_instruction_bytes(MISALIGNED_LW))
    from_operands = _caught(lambda: Rv32iInstruction("LW", rd=1, rs1=1, immediate=2))
    assert from_bytes.code is from_operands.code is rc.RejectionCode.FIELD_BAD_ALIGNMENT

    assert _caught(lambda: validate_instruction_bytes(
        SLTI_WORD)).code is rc.RejectionCode.ISA_DISALLOWED_OPERATION
    assert _caught(lambda: mmio_access_fragment(
        "ADDI", 0x40000000, windows=(GOOD_WINDOW,), base_register=1,
        data_register=2)).code is rc.RejectionCode.ISA_DISALLOWED_OPERATION

    decoder = _degraded_decoder()
    raw = _select_raw(decoder, "cpu", bytes((2, 0xC4, 0xFF, 0x0F, 7)))
    _, decision = decoder.decode_candidate(raw)
    memory = _slot_memory()
    from_memory = _caught(lambda: memory.accept_instructions(
        0x1010, NOP_BYTES, source_event_id="later"))
    assert decision.rejection.code is from_memory.code is \
        rc.RejectionCode.SLOT_OUT_OF_RESERVATION


def test_memory_admission_carries_the_instruction_level_code():
    memory = _slot_memory()
    rejection = _caught(lambda: memory.accept_instructions(
        0x1000, SLTI_WORD, source_event_id="case-1"))
    assert (rejection.code, rejection.pointer) == (
        rc.RejectionCode.ISA_DISALLOWED_OPERATION, "fragment[0].funct3")
    assert memory.state_summary()["initialized_bytes"] == 0
    misaligned = _caught(lambda: memory.accept_instructions(
        0x1000, MISALIGNED_LW, source_event_id="case-1"))
    assert misaligned.code is rc.RejectionCode.FIELD_BAD_ALIGNMENT


# --------------------------------------------------------------------------
# Candidate disposition
# --------------------------------------------------------------------------

def test_direct_source_selection_is_recorded_without_a_rejection():
    decoder = _pin_decoder()
    case, decision = decoder.decode_candidate(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
    assert case is not None
    assert decision.disposition == "admitted"
    assert decision.selection == "direct_source_byte"
    assert decision.rejection is None
    assert decision.document() == {
        "schema_version": "online_candidate_decision.v1",
        "candidate_disposition": "admitted",
        "candidate_disposition_reason": "decoder_case_ready",
        "source_selection_reason": "direct_source_byte",
        "rejection": None,
    }


def test_weight_fallback_selection_is_recorded():
    decoder = _path_decoder()
    case, decision = decoder.decode_candidate(bytes((0, 1, 9, 1, 0, 0, 0, 0)))
    assert case is not None
    assert decision.disposition == "admitted"
    assert decision.selection == "feedback_weighted_legal_source"
    assert decision.rejection is None


def test_rejected_candidate_carries_the_structured_code():
    decoder = _pin_decoder()
    case, decision = decoder.decode_candidate(b"")
    assert case is None
    assert decision.disposition == "rejected"
    assert decision.selection is None
    assert decision.rejection.code is rc.RejectionCode.DECODE_UNBOUNDED_INPUT
    assert decision.document()["candidate_disposition_reason"] == "decode_rejected"
    assert decision.document()["rejection"]["code"] == "decode.unbounded_input"


def test_reservation_fallback_is_a_recorded_degradation():
    decoder = _degraded_decoder()
    raw = _select_raw(decoder, "cpu", bytes((2, 0xC4, 0xFF, 0x0F, 7)))
    case, decision = decoder.decode_candidate(raw)
    assert case is not None
    assert case.source.data == NOP_BYTES
    assert decision.disposition == "degraded"
    assert decision.selection == "direct_source_byte"
    assert decision.rejection.code is rc.RejectionCode.SLOT_OUT_OF_RESERVATION
    assert decision.rejection.pointer == "instruction.cursor"
    decoder.commit(case)
    assert decoder.instruction_cursor == decoder.instruction_end


def test_commit_after_submit_failure_is_uncertain():
    decoder = _pin_decoder()
    case = decoder.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
    foreign = replace(case, case_id="foreign")
    decision = decoder.commit_candidate(foreign)
    assert decision.disposition == "uncertain"
    assert decision.rejection.code is rc.RejectionCode.SLOT_PROPOSAL_MISMATCH
    assert decision.document()["candidate_disposition_reason"] == \
        "commit_after_submit_uncertain"


def test_successful_commit_is_admitted_without_a_rejection():
    decoder = _pin_decoder()
    case = decoder.decode(bytes((0, 0, 0, 7, 0, 0, 0, 0)))
    decision = decoder.commit_candidate(case)
    assert decision.disposition == "admitted"
    assert decision.selection is None
    assert decision.rejection is None
    with pytest.raises(ValueError, match="current decoded proposal"):
        decoder.commit(case)


# --------------------------------------------------------------------------
# Positive controls: legal inputs stay rejection-free and side-effect free
# --------------------------------------------------------------------------

def test_legal_inputs_report_no_rejection():
    program = (Rv32iInstruction("LUI", rd=1, immediate=0x40000),
               Rv32iInstruction("LW", rd=2, rs1=1, immediate=0),
               Rv32iInstruction("NOP"))
    data = fragment_bytes(program)
    assert validate_instruction_bytes_detailed(data) is None
    assert validate_instruction_bytes(data) is None
    assert instruction_operator_id(data) == "rv32i:LUI+LW+NOP"
    assert fragment_image("img", "cpu", 0x1000, program).address == 0x1000
    assert mmio_access_fragment("LW", 0x40000000, windows=(GOOD_WINDOW,),
                                base_register=1, data_register=2)
    assert mmio_write_fragment("SW", 0x40000000, 7, windows=(GOOD_WINDOW,),
                               base_register=1, data_register=2)
    assert mutate_mmio_access("SW", b"\x00\x00\x00\x00", windows=(GOOD_WINDOW,),
                              base_register=1, data_register=2)
    assert mutate_instruction(Rv32iInstruction("NOP"), b"\x00\x00\x00\x00")
    assert decode_instruction_fragment(b"\x00\x00\x00\x00")
    assert rc.rejection_of(ValueError("unclassified")) is None


def test_legal_detailed_validation_has_no_side_effects():
    decoder = _instruction_decoder()
    before = (decoder.instruction_cursor, decoder._sequence)
    assert validate_instruction_bytes_detailed(NOP_BYTES) is None
    case, decision = decoder.decode_candidate(b"\x00\x00\x00")
    assert decision.rejection is None
    assert (decoder.instruction_cursor, decoder._sequence) == before
    decoder.commit(case)
    assert decoder._sequence == before[1] + 1


def test_detailed_validation_matches_the_raised_code():
    detail = validate_instruction_bytes_detailed(SLTI_WORD)
    raised = _caught(lambda: validate_instruction_bytes(SLTI_WORD))
    assert detail == raised
    assert validate_instruction_bytes_detailed(MISALIGNED_LW).code is \
        rc.RejectionCode.FIELD_BAD_ALIGNMENT


def test_decode_still_raises_plain_value_errors_for_callers():
    decoder = _pin_decoder()
    with pytest.raises(ValueError, match="nonempty bounded bytes"):
        decoder.decode(b"")
    with pytest.raises(ValueError, match="coverage hints"):
        decoder.decode(b"\x00\x00\x00", coverage_hints={"unknown": 1})
    decoder = _instruction_decoder()
    decoder.commit(decoder.decode(b"\x00\x00\x00"))
    with pytest.raises(ValueError, match="no online source remains"):
        decoder.decode(b"\x01")
