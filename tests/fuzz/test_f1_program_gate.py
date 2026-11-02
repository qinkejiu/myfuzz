"""The shared F1 program-space gate: validation, expectation, host criteria.

These tests pin the isolated gate module, not the entry or the C++ host.  The
legacy cases keep the entry's historical refusal text; the opt-in cases pin
the shared validators' rules (computed-base address forms, strictly-forward
branches, packed compressed parcels) and the reference model's retirement
witness.  No RTL is involved.
"""

import json

import pytest

from myfuzz.fuzz.f1_program_gate import (
    DEFAULT_WINDOW_BYTES, F1GateFlags, MAX_F1_PROGRAM_WORDS,
    canonical_trace, f1_gate_flags_from_scenario, f1_reference_expectation,
    host_mirror_spec, normalize_f1_gate_flags, trace_hash,
    validate_f1_program_record,
)
from myfuzz.fuzz.rv32_compressed import (
    generate_compressed_program, pack_parcels,
)
from myfuzz.fuzz.rv32_program import generate_program
from myfuzz.isa.constraints import IsaContract
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32I = RiscvProfile(32, frozenset({"I"}), 4, 32, 0)
RV32IM = RiscvProfile(32, frozenset({"I", "M"}), 4, 32, 0)
RV32IMC = RiscvProfile(32, frozenset({"I", "M", "C"}), 2, 32, 0)
ISA = IsaContract(32, ("I", "M"), instruction_alignment=4)
ISA_I = IsaContract(32, ("I",), instruction_alignment=4)
ISA_C = IsaContract(32, ("I", "M", "C"), instruction_alignment=2)
WINDOW = 64
_FNV_OFFSET = 2166136261
_FNV_PRIME = 16777619


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def raw_lw(rd, base, offset):
    """A hand-built LW so a misaligned immediate can be exercised."""
    return (((offset & 0xFFF) << 20) | (base << 15) | (2 << 12)
            | (rd << 7) | 0x03)


def flags(**overrides):
    values = dict(program_words=4)
    values.update(overrides)
    return F1GateFlags(**values)


def validate(words, *, isa=ISA, gate_flags=None, window=WINDOW):
    return validate_f1_program_record(
        {"flow": "F1", "fields": tuple(words)}, isa=isa,
        window_bytes=window, flags=gate_flags if gate_flags is not None
        else flags())


def expect(words, *, isa=ISA, gate_flags=None, window=WINDOW, **kwargs):
    return f1_reference_expectation(
        tuple(words), isa=isa, window_bytes=window,
        flags=gate_flags if gate_flags is not None else flags(), **kwargs)


def _fnv_trace(trace):
    digest = _FNV_OFFSET
    for entry in trace:
        for field in ("pc", "insn_word", "rd", "wdata"):
            for byte in entry[field].to_bytes(4, "little"):
                digest ^= byte
                digest = (digest * _FNV_PRIME) & 0xFFFFFFFF
    return f"fnv1a32:{digest:08x}"


def _legacy_program():
    return (
        word("LUI", rd=5, imm=1),
        word("ADDI", rd=6, rs1=5, imm=5),
        word("ADD", rd=7, rs1=6, rs2=5),
        word("LW", rd=10, rs1=18, imm=4),
        word("SW", rs1=18, rs2=10, imm=8),
    )


# ---------------------------------------------------------------------------
# Legacy records: validation and preserved refusal text
# ---------------------------------------------------------------------------


def test_a_legacy_program_record_still_validates():
    words = _legacy_program()
    assert validate(words, gate_flags=flags(program_words=5)) is None
    assert validate_f1_program_record(
        {"flow": "F1", "words": words}, isa=ISA, window_bytes=WINDOW,
        flags={"f1_program_words": 5}) is None


def test_a_legacy_record_may_be_shorter_than_the_declaration():
    assert validate(_legacy_program()[:2],
                    gate_flags=flags(program_words=5)) is None


@pytest.mark.parametrize("bad,message", [
    (word("ADDI", rd=8, rs1=0, imm=1),
     "F1 program instruction 0 writes the reserved mailbox register x8"),
    (word("ADDI", rd=9, rs1=0, imm=1),
     "F1 program instruction 0 writes the reserved slot base register x9"),
    (word("ADDI", rd=18, rs1=0, imm=1),
     "F1 program instruction 0 writes the reserved data-window base "
     "register x18"),
    (word("LW", rd=8, rs1=18, imm=0),
     "F1 program load 0 may not overwrite x8, x9 or x18"),
    (word("LW", rd=10, rs1=5, imm=0),
     "F1 program memory word 0 must use x18 as its base"),
    (word("LW", rd=10, rs1=18, imm=WINDOW),
     "F1 program memory word 0 memory access leaves the declared data window "
     "(offset 64)"),
    (raw_lw(10, 18, 2),
     "F1 program memory word 0 memory access leaves the declared data window "
     "(offset 2)"),
    (word("LB", rd=10, rs1=18, imm=0),
     "F1 program memory word 0 is not LW or SW"),
    (word("SB", rs1=18, rs2=10, imm=0),
     "F1 program memory word 0 is not LW or SW"),
    (word("BEQ", rs1=0, rs2=0, imm=8),
     "F1 program instruction 0 is a control-flow or system word; the "
     "trampoline program is straight-line"),
    (word("JAL", rd=0, imm=8),
     "F1 program instruction 0 is a control-flow or system word; the "
     "trampoline program is straight-line"),
    (0x00000000,
     "F1 instruction 0 is not one 32-bit word"),
    (0x00000001,
     "F1 instruction 0 is not one 32-bit word"),
])
def test_legacy_refusal_text_is_unchanged(bad, message):
    with pytest.raises(ValueError) as error:
        validate((bad,))
    assert str(error.value) == message


def test_a_legacy_m_word_on_an_i_only_profile_is_named():
    with pytest.raises(
            ValueError,
            match=r"F1 instruction 0 is not legal for this profile: MUL "
                  r"requires extension M"):
        validate((word("MUL", rd=7, rs1=6, rs2=5),), isa=ISA_I)


def test_auipc_is_admitted_in_program_mode():
    words = (word("AUIPC", rd=5, imm=1),
             word("ADDI", rd=6, rs1=5, imm=7))
    assert validate(words) is None
    result = expect(words)
    assert result["trace"][0]["insn"] == "AUIPC"
    assert result["retired_count"] == 2


def test_the_single_word_gate_keeps_its_fixed_contract():
    single = F1GateFlags()
    assert validate((word("ADDI", rd=5, rs1=0, imm=1),),
                    gate_flags=single) is None
    with pytest.raises(
            ValueError,
            match=r"F1 opcode 0x03 is outside the executed ALU subset"):
        validate((word("LW", rd=5, rs1=18, imm=0),), gate_flags=single)
    with pytest.raises(
            ValueError,
            match=r"unsupported first-stage RV32I instruction encoding"):
        validate((word("AUIPC", rd=5, imm=1),), gate_flags=single)
    with pytest.raises(
            ValueError,
            match=r"F1 instruction may not overwrite the fixed mailbox "
                  r"register x8"):
        validate((word("ADDI", rd=8, rs1=0, imm=1),), gate_flags=single)
    with pytest.raises(
            ValueError,
            match=r"F1 requires one 32-bit instruction; compressed input is "
                  r"unsupported"):
        validate((0x00000001,), gate_flags=single)
    with pytest.raises(ValueError, match=r"at most 1"):
        validate((word("ADDI", rd=5, rs1=0, imm=1),
                  word("ADDI", rd=6, rs1=0, imm=2)), gate_flags=single)


def test_a_record_longer_than_the_declaration_is_refused():
    with pytest.raises(ValueError, match=r"3 words.*at most 2"):
        validate(_legacy_program()[:3], gate_flags=flags(program_words=2))


def test_a_record_with_the_wrong_flow_is_refused():
    with pytest.raises(ValueError, match=r"flow 'F2' is not F1"):
        validate_f1_program_record(
            {"flow": "F2", "fields": (word("ADDI", rd=5, rs1=0, imm=1),)},
            isa=ISA, window_bytes=WINDOW, flags=flags())


# ---------------------------------------------------------------------------
# Computed-base address forms
# ---------------------------------------------------------------------------


def _address_program():
    return (word("ADDI", rd=5, rs1=18, imm=8),
            word("LW", rd=6, rs1=5, imm=0),
            word("ADDI", rd=7, rs1=18, imm=12),
            word("SW", rs1=7, rs2=6, imm=0))


def test_an_address_form_record_validates_and_executes():
    words = _address_program()
    assert validate(words, gate_flags=flags(allow_address_forms=True)) is None
    result = expect(words, gate_flags=flags(allow_address_forms=True),
                    registers={18: 0x100},
                    memory={0x108: 0xCAFEBABE, 0x10C: 0})
    assert result["mode"] == "address"
    assert result["pc_order"] == [0, 4, 8, 12]
    assert result["final_registers"][6] == 0xCAFEBABE
    assert result["final_registers"][7] == 0x10C
    assert result["memory_changes"] == {0x10C: 0xCAFEBABE}
    assert [entry["insn"] for entry in result["trace"]] == [
        "ADDI", "LW", "ADDI", "SW"]


def test_an_address_form_is_refused_without_the_flag():
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 1 must use x18 as its base"):
        validate(_address_program())


def test_an_address_form_requires_a_proven_window_base():
    words = (word("ADDI", rd=5, rs1=0, imm=8),
             word("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(
            ValueError,
            match=r"instruction 1 memory access base x5 is not a statically "
                  r"proven data-window address"):
        validate(words, gate_flags=flags(allow_address_forms=True))


def test_an_address_form_refuses_a_nonzero_computed_base_immediate():
    words = (word("ADDI", rd=5, rs1=18, imm=8),
             word("LW", rd=6, rs1=5, imm=4))
    with pytest.raises(
            ValueError,
            match=r"instruction 1 memory access with a computed base must "
                  r"use immediate 0"):
        validate(words, gate_flags=flags(allow_address_forms=True))


def test_an_address_form_refuses_an_out_of_window_displacement():
    words = (word("ADDI", rd=5, rs1=18, imm=WINDOW),
             word("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(
            ValueError,
            match=r"instruction 1 memory access leaves the declared data "
                  r"window"):
        validate(words, gate_flags=flags(allow_address_forms=True))


def test_address_forms_compose_with_branches():
    words = (word("ADDI", rd=5, rs1=18, imm=8),
             word("LW", rd=6, rs1=5, imm=0),
             word("BEQ", rs1=0, rs2=0, imm=8),
             word("ADDI", rd=7, rs1=0, imm=3),
             word("ADDI", rd=10, rs1=0, imm=4))
    gate_flags = flags(program_words=5, allow_address_forms=True,
                       allow_branches=True)
    assert validate(words, gate_flags=gate_flags) is None
    result = expect(words, gate_flags=gate_flags, registers={18: 0x100},
                    memory={0x108: 0x55})
    assert result["mode"] == "extended"
    assert result["pc_order"] == [0, 4, 8, 16]
    assert result["final_registers"] == {5: 0x108, 6: 0x55, 10: 4,
                                         18: 0x100}


# ---------------------------------------------------------------------------
# Strictly-forward branches
# ---------------------------------------------------------------------------


def test_a_forward_branch_validates_at_every_in_image_target():
    base = (word("ADDI", rd=5, rs1=0, imm=1),
            word("BEQ", rs1=5, rs2=0, imm=8),
            word("ADDI", rd=6, rs1=0, imm=2),
            word("ADDI", rd=7, rs1=0, imm=3))
    for target in (1, 2, 3, 4):
        words = (word("BEQ", rs1=0, rs2=0, imm=4 * target),) + base[1:]
        assert validate(words, gate_flags=flags(allow_branches=True)) is None


def test_a_branch_target_past_the_return_jump_is_refused():
    words = (word("BEQ", rs1=0, rs2=0, imm=20),
             word("ADDI", rd=1, rs1=0, imm=1),
             word("ADDI", rd=2, rs1=0, imm=1))
    with pytest.raises(
            ValueError,
            match=r"branch target index 5 is beyond the installed program"):
        validate(words, gate_flags=flags(program_words=3,
                                         allow_branches=True))


@pytest.mark.parametrize("offset", [-4, 0])
def test_a_would_be_loop_is_refused(offset):
    with pytest.raises(
            ValueError,
            match=r"branch target is not strictly forward"):
        validate((word("BEQ", rs1=0, rs2=0, imm=offset),),
                 gate_flags=flags(allow_branches=True))


def test_a_branch_target_must_be_word_aligned():
    with pytest.raises(ValueError, match=r"branch offset 2 is not 4-byte "
                                          r"aligned"):
        validate((word("BEQ", rs1=0, rs2=0, imm=2),),
                 gate_flags=flags(allow_branches=True))


def test_a_branch_is_refused_without_the_flag():
    with pytest.raises(ValueError, match=r"control-flow or system word"):
        validate((word("BEQ", rs1=0, rs2=0, imm=8),))


def test_a_generated_branch_program_passes_the_gate_and_model():
    for seed in range(10):
        program = generate_program(
            RV32IM, seed=seed, max_words=6, min_words=6, window_size=WINDOW,
            style="branch", allow_auipc=False, allow_branches=True)
        gate_flags = flags(program_words=6, allow_branches=True)
        assert validate(program.words, gate_flags=gate_flags) is None
        result = expect(program.words, gate_flags=gate_flags)
        assert result["retired_count"] >= 1
        assert result["pc_order"] == sorted(result["pc_order"])


def test_the_reference_branch_trace_skips_non_retired_words():
    words = (word("ADDI", rd=5, rs1=0, imm=1),
             word("BEQ", rs1=0, rs2=0, imm=8),
             word("ADDI", rd=6, rs1=0, imm=2),
             word("ADDI", rd=7, rs1=0, imm=3))
    result = expect(words, gate_flags=flags(allow_branches=True))
    assert result["pc_order"] == [0, 4, 12]
    assert [entry["insn"] for entry in result["trace"]] == [
        "ADDI", "BEQ", "ADDI"]
    assert result["final_registers"] == {5: 1, 7: 3}


# ---------------------------------------------------------------------------
# Packed compressed parcels
# ---------------------------------------------------------------------------


def _pair(low, high):
    return pack_parcels(low, high)


def _compressed_program():
    return (_pair(word("C.LI", rd=12, imm=5),
                  word("C.ADDI", rd=13, imm=-2)),
            _pair(word("C.ADD", rd=14, rs2=12),
                  word("C.ADD", rd=15, rs2=13)))


def test_a_packed_pair_record_validates_with_the_flag():
    words = _compressed_program()
    assert validate(words, isa=ISA_C,
                    gate_flags=flags(program_words=2,
                                     allow_compressed=True)) is None


def test_a_compressed_shape_is_refused_without_the_flag():
    with pytest.raises(ValueError,
                       match=r"F1 instruction 0 is not one 32-bit word"):
        validate(_compressed_program(), isa=ISA_C)


def test_compressed_parcels_retire_at_two_byte_pc_steps():
    result = expect(_compressed_program(), isa=ISA_C,
                    gate_flags=flags(program_words=2,
                                     allow_compressed=True))
    assert result["mode"] == "compressed"
    assert result["pc_order"] == [0, 2, 4, 6]
    assert result["retired_count"] == 4
    assert [entry["insn"] for entry in result["trace"]] == [
        "C.LI", "C.ADDI", "C.ADD", "C.ADD"]
    assert result["trace"][1]["wdata"] == 0xFFFFFFFE
    assert result["final_registers"] == {12: 5, 13: 0xFFFFFFFE, 14: 5,
                                         15: 0xFFFFFFFE}
    assert result["memory_changes"] == {}


def test_a_compressed_image_may_mix_a_32_bit_word():
    words = (_compressed_program()[0],
             word("ADDI", rd=5, rs1=0, imm=7))
    result = expect(words, isa=ISA_C,
                    gate_flags=flags(program_words=2,
                                     allow_compressed=True))
    assert result["pc_order"] == [0, 2, 4]
    assert [entry["insn"] for entry in result["trace"]] == [
        "C.LI", "C.ADDI", "ADDI"]
    assert result["final_registers"][5] == 7


def test_a_compressed_expectation_uses_the_absolute_pc_base():
    words = (_compressed_program()[0],)
    result = expect(words, isa=ISA_C,
                    gate_flags=flags(program_words=2,
                                     allow_compressed=True),
                    data_base=0x3000)
    assert result["pc_base"] == 0x3000
    assert result["program_end"] == 0x3004
    assert result["pc_order"] == [0x3000, 0x3002]


def test_a_compressed_branch_can_skip_a_parcel():
    words = (word("BEQ", rs1=0, rs2=0, imm=6),
             _pair(word("C.LI", rd=12, imm=1),
                   word("C.ADDI", rd=13, imm=1)))
    gate_flags = flags(program_words=2, allow_compressed=True,
                       allow_branches=True)
    assert validate(words, isa=ISA_C, gate_flags=gate_flags) is None
    result = expect(words, isa=ISA_C, gate_flags=gate_flags)
    assert result["pc_order"] == [0, 6]
    assert [entry["insn"] for entry in result["trace"]] == ["BEQ", "C.ADDI"]
    assert result["final_registers"] == {13: 1}


def test_a_compressed_branch_target_must_be_an_instruction_start():
    words = (word("BEQ", rs1=0, rs2=0, imm=2),
             _pair(word("C.LI", rd=12, imm=1),
                   word("C.ADDI", rd=13, imm=1)))
    with pytest.raises(
            ValueError,
            match=r"branch target pc\+2 is not an instruction start"):
        validate(words, isa=ISA_C,
                 gate_flags=flags(program_words=2,
                                  allow_compressed=True,
                                  allow_branches=True))


def test_a_compressed_branch_is_refused_without_the_branch_flag():
    words = (word("BEQ", rs1=0, rs2=0, imm=6),
             _pair(word("C.LI", rd=12, imm=1),
                   word("C.ADDI", rd=13, imm=1)))
    with pytest.raises(ValueError, match=r"control-flow or system"):
        validate(words, isa=ISA_C,
                 gate_flags=flags(program_words=2, allow_compressed=True))


def test_compressed_mode_requires_the_c_extension():
    with pytest.raises(
            ValueError,
            match=r"compressed mode requires the C extension"):
        validate(_compressed_program(), isa=ISA,
                 gate_flags=flags(program_words=2, allow_compressed=True))


def test_generated_compressed_programs_pass_the_gate():
    for seed in range(10):
        program = generate_compressed_program(
            RV32IMC, seed=seed, max_words=4, window_size=WINDOW)
        gate_flags = flags(program_words=4, allow_compressed=True)
        assert validate(program.words, isa=ISA_C,
                        gate_flags=gate_flags) is None
        result = expect(program.words, isa=ISA_C, gate_flags=gate_flags)
        assert result["retired_count"] == 2 * len(program.words)
        assert result["pc_order"] == [2 * index
                                      for index in range(result["retired_count"])]


# ---------------------------------------------------------------------------
# Reference trace, final state and canonical hash
# ---------------------------------------------------------------------------


def test_the_reference_trace_matches_hand_computed_adder_values():
    words = (word("ADDI", rd=5, rs1=0, imm=7),
             word("ADDI", rd=6, rs1=5, imm=3))
    result = expect(words, gate_flags=flags(program_words=2))
    assert result["retired_count"] == result["retires"] == 2
    assert result["pc_order"] == [0, 4]
    assert result["trace"] == [
        {"pc": 0, "insn": "ADDI", "insn_word": words[0], "rd": 5,
         "wdata": 7},
        {"pc": 4, "insn": "ADDI", "insn_word": words[1], "rd": 6,
         "wdata": 10},
    ]
    assert result["final_registers"] == {5: 7, 6: 10}
    assert result["memory_changes"] == {}
    assert result["trace_hash"] == _fnv_trace(result["trace"])


def test_the_reference_memory_delta_follows_the_store():
    words = (word("ADDI", rd=5, rs1=0, imm=0x11),
             word("SW", rs1=18, rs2=5, imm=0),
             word("LW", rd=6, rs1=18, imm=0))
    result = expect(words, gate_flags=flags(program_words=3),
                    memory={0: 0})
    assert result["memory_changes"] == {0: 0x11}
    assert result["final_registers"] == {5: 0x11, 6: 0x11}
    assert [entry["wdata"] for entry in result["trace"]] == [0x11, 0x11, 0x11]
    assert result["trace"][1]["rd"] == 0


def test_the_reference_pc_base_is_the_host_slot():
    words = (word("ADDI", rd=5, rs1=0, imm=1),
             word("ADDI", rd=6, rs1=0, imm=2))
    result = expect(words, gate_flags=flags(program_words=2),
                    data_base=0x2000)
    assert result["pc_base"] == 0x2000
    assert result["program_end"] == 0x2008
    assert result["pc_order"] == [0x2000, 0x2004]
    assert result["trace"][0]["pc"] == 0x2000


def test_the_reference_address_form_reads_the_absolute_window():
    words = (word("ADDI", rd=5, rs1=18, imm=8),
             word("LW", rd=6, rs1=5, imm=0))
    result = expect(words, gate_flags=flags(program_words=2,
                                            allow_address_forms=True),
                    registers={18: 0x100}, memory={0x108: 0xDEADBEEF})
    assert result["final_registers"][6] == 0xDEADBEEF
    assert result["memory_changes"] == {}


def test_the_trace_hash_is_the_documented_fnv1a():
    result = expect((word("ADDI", rd=5, rs1=0, imm=7),),
                    gate_flags=flags(program_words=1))
    assert result["trace_hash"] == _fnv_trace(result["trace"])
    assert result["trace_hash"].startswith("fnv1a32:")
    changed = [dict(entry) for entry in result["trace"]]
    changed[0]["wdata"] = 8
    assert trace_hash(changed) != result["trace_hash"]


def test_the_trace_hash_is_stable_across_calls():
    words = _legacy_program()
    first = expect(words, gate_flags=flags(program_words=5))
    second = expect(words, gate_flags=flags(program_words=5))
    assert first["trace_hash"] == second["trace_hash"]
    assert first["trace"] == second["trace"]


def test_the_expectation_can_carry_the_underlying_steps():
    words = (word("ADDI", rd=5, rs1=0, imm=7),)
    result = expect(words, gate_flags=flags(program_words=1), trace=True)
    assert "steps" in result
    assert len(result["steps"]) == result["retired_count"]


def test_canonical_trace_refuses_a_malformed_entry():
    with pytest.raises(ValueError, match=r"missing wdata"):
        canonical_trace([{"pc": 0, "insn": "ADDI", "insn_word": 1, "rd": 5}])
    with pytest.raises(ValueError, match=r"wdata is not a 32-bit"):
        canonical_trace([{"pc": 0, "insn": "ADDI", "insn_word": 1,
                          "rd": 5, "wdata": -1}])
    with pytest.raises(ValueError, match=r"insn is not a string"):
        canonical_trace([{"pc": 0, "insn": 5, "insn_word": 1,
                          "rd": 5, "wdata": 1}])


def test_a_subword_expectation_is_refused_by_name():
    subword = (word("LB", rd=5, rs1=18, imm=0),)
    gate_flags = flags(program_words=2, subword=True)
    assert validate(subword, gate_flags=gate_flags) is None
    with pytest.raises(ValueError, match=r"no subword retirement trace"):
        expect(subword, gate_flags=gate_flags)


# ---------------------------------------------------------------------------
# Scenario-configuration flag mapping
# ---------------------------------------------------------------------------


def test_scenario_flags_round_trip_through_the_declaration():
    gate_flags = f1_gate_flags_from_scenario({
        "f1_program_words": 4,
        "f1_subword": False,
        "f1_allow_branches": True,
        "f1_allow_address_forms": True,
        "f1_allow_compressed": False,
    })
    assert gate_flags.program_words == 4
    assert gate_flags.allow_branches is True
    assert gate_flags.allow_address_forms is True
    assert gate_flags.mode == "extended"
    assert normalize_f1_gate_flags(gate_flags.as_dict()) == gate_flags


def test_scenario_defaults_keep_the_legacy_single_word_gate():
    gate_flags = f1_gate_flags_from_scenario({})
    assert gate_flags == F1GateFlags()
    assert gate_flags.mode == "single"
    assert MAX_F1_PROGRAM_WORDS == 16
    assert DEFAULT_WINDOW_BYTES == 64


@pytest.mark.parametrize("config,match", [
    ({"f1_program_words": 0}, r"must be in 1\.\.16"),
    ({"f1_program_words": 17}, r"must be in 1\.\.16"),
    ({"f1_program_words": True}, r"must be an integer"),
    ({"f1_allow_branches": 1}, r"f1_allow_branches must be a boolean"),
    ({"f1_allow_branches": True}, r"require f1_program_words > 1"),
    ({"f1_allow_address_forms": True}, r"require f1_program_words > 1"),
    ({"f1_allow_compressed": True}, r"require f1_program_words > 1"),
    ({"f1_program_words": 4, "f1_allow_compressed": True,
      "f1_allow_address_forms": True}, r"incompatible"),
    ({"f1_program_words": 4, "f1_allow_compressed": True,
      "f1_subword": True}, r"f1_subword is incompatible"),
    ({"f1_program_words": 4, "f1_subword": True,
      "f1_allow_branches": True}, r"f1_subword is incompatible"),
])
def test_impossible_scenario_flag_combinations_are_refused(config, match):
    with pytest.raises(ValueError, match=match):
        f1_gate_flags_from_scenario(config)


def test_normalization_accepts_flags_mapping_and_scenario_mapping():
    expected = F1GateFlags(program_words=4, allow_branches=True)
    assert normalize_f1_gate_flags(None) == F1GateFlags()
    assert normalize_f1_gate_flags(expected) is expected
    assert normalize_f1_gate_flags(
        {"program_words": 4, "allow_branches": True}) == expected
    assert normalize_f1_gate_flags(
        {"f1_program_words": 4, "f1_allow_branches": True}) == expected
    with pytest.raises(ValueError, match=r"unknown F1 gate flag"):
        normalize_f1_gate_flags({"program_words": 4, "nonsense": True})


def test_every_shape_has_its_dispatch_name():
    assert F1GateFlags().mode == "single"
    assert flags().mode == "legacy"
    assert flags(allow_address_forms=True).mode == "address"
    assert flags(allow_branches=True).mode == "branch"
    assert flags(allow_address_forms=True, allow_branches=True).mode == "extended"
    assert flags(allow_compressed=True).mode == "compressed"
    assert flags(subword=True).mode == "subword"


def test_a_scenario_mapping_can_select_the_branch_validator_directly():
    words = (word("ADDI", rd=5, rs1=0, imm=1),
             word("BEQ", rs1=5, rs2=0, imm=8),
             word("ADDI", rd=6, rs1=0, imm=2),
             word("ADDI", rd=7, rs1=0, imm=3))
    assert validate(words, gate_flags={"f1_program_words": 4,
                                       "f1_allow_branches": True}) is None


# ---------------------------------------------------------------------------
# The documented C++ mirror
# ---------------------------------------------------------------------------


def test_host_mirror_spec_names_the_five_required_changes():
    spec = host_mirror_spec()
    assert spec["schema_version"] == "f1_host_mirror.v1"
    ids = {row["id"] for row in spec["requirements"]}
    assert {"record_flags", "branch_targets", "address_provenance",
            "compressed_fetch", "pc_step", "trace_hash"} <= ids
    assert spec["host_file"].endswith("inprocess_obi_apb_f1f4_spike.cpp")
    assert spec["trace_hash"]["algorithm"] == "fnv1a32"


def test_host_mirror_spec_is_json_ready_and_matches_the_hash_payload():
    spec = host_mirror_spec()
    rebuilt = json.loads(json.dumps(spec))
    assert rebuilt["trace_hash"]["offset_basis"] == _FNV_OFFSET
    assert rebuilt["trace_hash"]["prime"] == _FNV_PRIME
    assert "prog_trace_hash" in rebuilt["observation_keys"]
    text = " ".join(row["change"] for row in rebuilt["requirements"])
    assert "pc+2" in text or "steps 2" in text
    assert "parcel" in text
