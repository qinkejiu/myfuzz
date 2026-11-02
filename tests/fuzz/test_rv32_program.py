"""Trampoline program generation, mutation, validation and reference model.

The tests build profiles directly instead of loading component profiles: the
trampoline constraints are about RV32/RV32E register files and a declared data
window, not about a particular CPU's component JSON.

The second half covers the richer program space: ``analyze_program``'s data-flow
facts, the dependency skeleton ``style="chains"`` builds (multiple chains, load
-> store, store -> load, repeated addresses), the new ``min_words``/``style``/
``allow_auipc`` options, source rewiring in mutation, and the traced reference
model (``window_size``/``trace``).
"""

import json

import pytest

from myfuzz.fuzz.rv32_program import (
    DEFAULT_RESERVED_REGISTERS, AddressUse, ProgramWord, ShortProgram,
    address_provenance, address_provenance_details, analyze_program,
    generate_program, mutate_program, reference_run, run_program,
    validate_address_program, validate_program_words,
)
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32I = RiscvProfile(32, frozenset({"I"}), 4, 32, 0)
RV32IM = RiscvProfile(32, frozenset({"I", "M"}), 4, 32, 0)
RV32IMC = RiscvProfile(32, frozenset({"I", "M", "C"}), 2, 32, 0)
RV32E = RiscvProfile(32, frozenset({"E"}), 4, 16, 0)
RV64IM = RiscvProfile(64, frozenset({"I", "M"}), 4, 32, 0)

ALU_OPCODES = frozenset({0x37, 0x17, 0x13, 0x33})
ALL_OPCODES = ALU_OPCODES | {0x03, 0x23}


def _read_registers(item):
    return [item.operands[field] for field in ("rs1", "rs2")
            if field in item.operands]


def _unaligned(word, value):
    """Set a memory immediate field to a hand-built (unaligned) value."""
    return word | (value << 7) if word & 0x7F == 0x23 else word | (value << 20)


def _run(words, registers=None, memory=None, data_base=None):
    return reference_run(words, registers=registers or {},
                         memory=memory or {}, data_base=data_base)


def test_generation_is_deterministic_per_seed():
    first = generate_program(RV32IMC, seed=7, max_words=6, window_size=64)
    again = generate_program(RV32IMC, seed=7, max_words=6, window_size=64)
    other = generate_program(RV32IMC, seed=8, max_words=6, window_size=64)
    assert first.as_dict() == again.as_dict()
    assert first.text == again.text
    assert first.words == again.words
    assert other.text != first.text


def test_every_generated_program_passes_the_validator():
    for profile in (RV32I, RV32IM, RV32IMC, RV32E):
        for seed in range(20):
            for max_words in (1, 6):
                program = generate_program(profile, seed=seed,
                                           max_words=max_words, window_size=64)
                assert 1 <= len(program.words) <= max_words
                assert len(program.instructions) == len(program.words)
                validate_program_words(profile, program.words, window_size=64)


def test_words_are_32_bit_emittable_instructions():
    for seed in range(30):
        program = generate_program(RV32IMC, seed=seed, max_words=8,
                                   window_size=128)
        for item in program.instructions:
            assert item.word & 3 == 3, item.assembly
            assert item.word & 0x7F in ALL_OPCODES, item.assembly
            assert item.assembly == item.assembly.strip()
            assert encode(item.name, xlen=32, **item.operands) == item.word


def test_single_word_mode_never_emits_memory_instructions():
    for seed in range(40):
        program = generate_program(RV32IMC, seed=seed, max_words=1,
                                   window_size=128)
        assert len(program.words) == 1
        for word in program.words:
            assert word & 0x7F in ALU_OPCODES, f"{word:#010x} uses memory"


def test_multi_word_mode_reaches_lw_and_sw_inside_the_window():
    seen = set()
    for seed in range(60):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   window_size=64)
        for item in program.instructions:
            if item.name not in ("LW", "SW"):
                continue
            seen.add(item.name)
            assert item.operands["rs1"] == 18, item.assembly
            offset = item.operands["imm"]
            assert offset % 4 == 0, item.assembly
            assert 0 <= offset <= 64 - 4, item.assembly
    assert seen == {"LW", "SW"}


def test_generator_never_writes_a_reserved_register():
    for profile in (RV32I, RV32IM, RV32IMC, RV32E):
        for seed in range(25):
            program = generate_program(profile, seed=seed, max_words=8,
                                       window_size=64)
            for item in program.instructions:
                rd = item.operands.get("rd")
                if rd is None:
                    continue
                assert rd != 0, item.assembly
                assert rd not in DEFAULT_RESERVED_REGISTERS, item.assembly


def test_register_dependencies_appear_across_one_hundred_programs():
    dependent = 0
    for seed in range(100):
        program = generate_program(RV32IMC, seed=seed, max_words=6,
                                   window_size=64)
        written = set()
        for item in program.instructions:
            if any(reg in written for reg in _read_registers(item)):
                dependent += 1
            if "rd" in item.operands:
                written.add(item.operands["rd"])
    assert dependent >= 1


def test_m_instructions_only_on_profiles_that_declare_m():
    m_words = 0
    for seed in range(40):
        plain = generate_program(RV32I, seed=seed, max_words=8, window_size=64)
        for word in plain.words:
            if word & 0x7F == 0x33:
                assert word >> 25 != 0x01, "M word on an I-only profile"
        rich = generate_program(RV32IM, seed=seed, max_words=8, window_size=64)
        m_words += sum(1 for word in rich.words
                       if word & 0x7F == 0x33 and word >> 25 == 0x01)
    assert m_words > 0


def test_rv32e_uses_only_x0_to_x15_and_never_touches_x18():
    program = generate_program(RV32E, seed=11, max_words=8, window_size=64)
    for item in program.instructions:
        for field in ("rd", "rs1", "rs2"):
            if field in item.operands:
                assert item.operands[field] < 16, item.assembly
        assert item.name not in ("LW", "SW"), item.assembly
    validate_program_words(RV32E, program.words, window_size=64)
    wide = generate_program(RV32IMC, seed=11, max_words=16, window_size=64)
    assert any(item.operands.get("rd", 0) >= 16 for item in wide.instructions)


def test_generator_refuses_non_32_bit_and_non_base_profiles():
    with pytest.raises(ValueError, match="xlen 32"):
        generate_program(RV64IM, seed=0, max_words=4, window_size=64)
    with pytest.raises(ValueError, match="I or E"):
        generate_program(RiscvProfile(32, frozenset({"M"}), 4, 32, 0), seed=0,
                         max_words=4, window_size=64)
    with pytest.raises(ValueError, match="RiscvProfile"):
        generate_program(object(), seed=0, max_words=4, window_size=64)


def test_validator_refuses_non_32_bit_and_non_base_profiles():
    words = (encode("ADDI", rd=1, rs1=0, imm=1),)
    with pytest.raises(ValueError, match="xlen 32"):
        validate_program_words(RV64IM, words, window_size=64)
    with pytest.raises(ValueError, match="I or E"):
        validate_program_words(RiscvProfile(32, frozenset({"A"}), 4, 32, 0),
                               words, window_size=64)


def test_generator_rejects_bad_max_words_window_and_seed():
    for bad in (0, 17):
        with pytest.raises(ValueError, match="max_words"):
            generate_program(RV32I, seed=0, max_words=bad, window_size=64)
    with pytest.raises(ValueError, match="4-byte aligned"):
        generate_program(RV32I, seed=0, max_words=4, window_size=6)
    with pytest.raises(ValueError, match="at least 4"):
        generate_program(RV32I, seed=0, max_words=4, window_size=2)
    with pytest.raises(ValueError, match="window_size must be an integer"):
        generate_program(RV32I, seed=0, max_words=4, window_size=64.0)
    with pytest.raises(ValueError, match="window_size must be an integer"):
        generate_program(RV32I, seed=0, max_words=4, window_size=None)
    with pytest.raises(ValueError, match="seed"):
        generate_program(RV32I, seed=-1, max_words=4, window_size=64)


def test_mutation_refuses_a_program_larger_than_its_budget():
    program = generate_program(RV32IM, seed=0, max_words=8, window_size=64)
    assert len(program.words) > 2
    with pytest.raises(ValueError, match="but max_words is 2"):
        mutate_program(RV32IM, program, seed=0, max_words=2, window_size=64)
    with pytest.raises(ValueError, match="must not contain memory"):
        mutate_program(RV32IM, generate_program(
            RV32IM, seed=3, max_words=6, window_size=64), seed=0, max_words=1,
            window_size=64)


def test_two_hundred_mutations_stay_legal_and_change_something():
    program = generate_program(RV32IMC, seed=3, max_words=6, window_size=64)
    distinct = {program.words}
    for step in range(200):
        mutated = mutate_program(RV32IMC, program, seed=step, max_words=6,
                                 window_size=64)
        assert isinstance(mutated, ShortProgram)
        assert mutated.seed == step
        assert 1 <= len(mutated.words) <= 6
        assert mutated.words != program.words
        validate_program_words(RV32IMC, mutated.words, window_size=64)
        distinct.add(mutated.words)
        program = mutated
    assert len(distinct) > 20


def test_mutation_never_exceeds_max_words_and_keeps_a_word():
    program = generate_program(RV32IM, seed=5, max_words=3, window_size=64)
    for step in range(80):
        program = mutate_program(RV32IM, program, seed=100 + step, max_words=3,
                                 window_size=64)
        assert 1 <= len(program.words) <= 3
        validate_program_words(RV32IM, program.words, window_size=64)


def test_mutation_is_deterministic_and_inserts_or_deletes_within_bounds():
    first = generate_program(RV32IM, seed=0, max_words=1, window_size=64)
    lengths = set()
    two_words = None
    for step in range(40):
        mutated = mutate_program(RV32IM, first, seed=step, max_words=2,
                                 window_size=64)
        lengths.add(len(mutated.words))
        if len(mutated.words) == 2 and two_words is None:
            two_words = mutated
    assert lengths == {1, 2}, "insert never applied"
    again = mutate_program(RV32IM, two_words, seed=7, max_words=2,
                           window_size=64)
    repeat = mutate_program(RV32IM, two_words, seed=7, max_words=2,
                            window_size=64)
    assert again.as_dict() == repeat.as_dict()
    lengths = set()
    for step in range(40):
        mutated = mutate_program(RV32IM, two_words, seed=step, max_words=2,
                                 window_size=64)
        lengths.add(len(mutated.words))
    assert lengths == {1, 2}, "delete never applied"


def test_a_large_declared_window_keeps_generated_offsets_encodable():
    for seed in range(40):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   window_size=4096)
        validate_program_words(RV32IM, program.words, window_size=4096)
        for item in program.instructions:
            if item.name in ("LW", "SW"):
                assert 0 <= item.operands["imm"] <= 2044, item.assembly
                assert item.operands["imm"] % 4 == 0, item.assembly
    # The validator bounds against the declared window, not the encoder limit.
    validate_program_words(RV32IM,
                           (encode("SW", rs2=1, rs1=18, imm=2000),),
                           window_size=4096)


def test_single_word_mutation_stays_single_word_without_memory():
    program = generate_program(RV32IM, seed=0, max_words=1, window_size=64)
    for step in range(40):
        program = mutate_program(RV32IM, program, seed=step, max_words=1,
                                 window_size=64)
        assert len(program.words) == 1
        assert program.words[0] & 0x7F in ALU_OPCODES, program.text
        validate_program_words(RV32IM, program.words, window_size=64)


def test_mutated_programs_still_avoid_reserved_register_writes():
    for profile in (RV32I, RV32E):
        program = generate_program(profile, seed=2, max_words=5,
                                   window_size=32)
        for step in range(50):
            program = mutate_program(profile, program, seed=step, max_words=5,
                                     window_size=32)
            for item in program.instructions:
                rd = item.operands.get("rd")
                assert rd not in DEFAULT_RESERVED_REGISTERS, item.assembly
                for field in ("rd", "rs1", "rs2"):
                    if field in item.operands:
                        assert item.operands[field] < profile.register_count


def test_validator_refuses_an_empty_program():
    with pytest.raises(ValueError, match="program has no instruction"):
        validate_program_words(RV32I, (), window_size=64)


def test_validator_refuses_compressed_words():
    legal = encode("ADDI", rd=1, rs1=0, imm=1)
    with pytest.raises(ValueError,
                       match="instruction 1 is compressed; a 32-bit word"):
        validate_program_words(RV32I, (legal, 0x0001), window_size=64)


@pytest.mark.parametrize("word", [
    encode("JAL", rd=1, imm=4),
    encode("JALR", rd=1, rs1=0, imm=0),
    encode("BEQ", rs1=1, rs2=2, imm=4),
])
def test_validator_refuses_control_flow_words(word):
    with pytest.raises(ValueError, match="instruction 0 is a control-flow"):
        validate_program_words(RV32I, (word,), window_size=64)


def test_validator_refuses_csr_system_words():
    word = encode("CSRRW", rd=1, rs1=2, csr=0x300)
    with pytest.raises(ValueError, match="control-flow or system instruction"):
        validate_program_words(RV32I, (word,), window_size=64)


def test_validator_refuses_reserved_register_writes():
    words = (encode("ADDI", rd=1, rs1=0, imm=1),
             encode("ADDI", rd=8, rs1=0, imm=1))
    with pytest.raises(
            ValueError,
            match="instruction 1 writes the reserved mailbox register x8"):
        validate_program_words(RV32I, words, window_size=64)
    with pytest.raises(
            ValueError,
            match="instruction 0 writes the reserved slot base register x9"):
        validate_program_words(RV32I, (encode("LUI", rd=9, imm=0),),
                               window_size=64)
    with pytest.raises(
            ValueError, match="reserved data-window base register x18"):
        validate_program_words(
            RV32I, (encode("LW", rd=18, rs1=18, imm=0),), window_size=64)


def test_validator_allows_x0_destinations_but_not_reserved_ones():
    validate_program_words(RV32I, (encode("ADDI", rd=0, rs1=0, imm=7),),
                           window_size=64)
    with pytest.raises(ValueError, match="reserved"):
        validate_program_words(RV32I, (encode("ADDI", rd=8, rs1=0, imm=1),),
                               window_size=64, reserved=(8, 9, 18))


def test_validator_refuses_a_memory_instruction_with_another_base():
    with pytest.raises(ValueError, match="must use x18 as its base"):
        validate_program_words(RV32I, (encode("SW", rs2=1, rs1=5, imm=0),),
                               window_size=64)


def test_validator_refuses_unaligned_and_out_of_window_memory_accesses():
    aligned_sw = encode("SW", rs2=1, rs1=18, imm=0)
    with pytest.raises(ValueError,
                       match="offset 2 is not 4-byte aligned"):
        validate_program_words(RV32I, (_unaligned(aligned_sw, 2),),
                               window_size=64)
    with pytest.raises(
            ValueError,
            match=r"leaves the declared data window \(offset 64\)"):
        validate_program_words(RV32I,
                               (encode("SW", rs2=1, rs1=18, imm=64),),
                               window_size=64)
    with pytest.raises(
            ValueError,
            match=r"leaves the declared data window \(offset -4\)"):
        validate_program_words(RV32I,
                               (encode("LW", rd=1, rs1=18, imm=-4),),
                               window_size=64)
    # window_size=None skips only the bound, not the encoding rules.
    validate_program_words(RV32I, (encode("LW", rd=1, rs1=18, imm=-4),),
                           window_size=None)


def test_validator_refuses_instructions_the_profile_lacks():
    mul = encode("MUL", rd=1, rs1=2, rs2=3)
    with pytest.raises(ValueError,
                       match="instruction 0 is not legal for this profile"):
        validate_program_words(RV32I, (mul,), window_size=64)
    validate_program_words(RV32IM, (mul,), window_size=64)
    with pytest.raises(ValueError, match="only LW is emittable as a load"):
        validate_program_words(RV32I, (encode("LB", rd=1, rs1=18, imm=0),),
                               window_size=64)
    with pytest.raises(ValueError, match="not a legal trampoline instruction"):
        validate_program_words(RV32I, (encode("FENCE", pred=15, succ=15),),
                               window_size=64)


def test_validator_accepts_a_legal_program_without_side_effects():
    program = generate_program(RV32IMC, seed=9, max_words=6, window_size=64)
    words = program.words
    assert validate_program_words(RV32IMC, words, window_size=64) is None
    assert validate_program_words(RV32IMC, list(words), window_size=64) is None
    assert program.words == words
    assert DEFAULT_RESERVED_REGISTERS == (8, 9, 18)


def test_reference_run_addi_negative_and_write_trace():
    result = _run((encode("ADDI", rd=1, rs1=0, imm=-1),))
    assert result["schema_version"] == "rv32_reference_run.v1"
    assert result["retires"] == 1
    assert result["final_registers"] == {1: 0xFFFFFFFF}
    assert result["register_writes"] == [
        {"index": 0, "pc": 0, "name": "ADDI", "rd": 1, "value": 0xFFFFFFFF}]
    assert result["memory_changes"] == {}


def test_reference_run_add_and_sub_wrap_at_32_bits():
    words = (encode("ADD", rd=3, rs1=1, rs2=2),
             encode("SUB", rd=4, rs1=2, rs2=1))
    result = _run(words, {1: 0xFFFFFFFF, 2: 1})
    assert result["final_registers"] == {1: 0xFFFFFFFF, 2: 1, 4: 2}
    assert [item["value"] for item in result["register_writes"]] == [0, 2]


def test_reference_run_shift_semantics():
    words = (encode("SLL", rd=3, rs1=1, rs2=2),
             encode("SRA", rd=4, rs1=5, rs2=6),
             encode("SLLI", rd=7, rs1=1, shamt=31))
    result = _run(words, {1: 3, 2: 30, 5: 0x80000000, 6: 4})
    assert result["final_registers"][3] == (3 << 30) & 0xFFFFFFFF
    assert result["final_registers"][4] == 0xF8000000
    assert result["final_registers"][7] == 0x80000000


def test_reference_run_signed_and_unsigned_compares():
    words = (encode("SLTIU", rd=3, rs1=1, imm=-1),
             encode("SLTI", rd=4, rs1=1, imm=-1),
             encode("SLTIU", rd=5, rs1=2, imm=0),
             encode("SLTI", rd=6, rs1=2, imm=0))
    result = _run(words, {1: 0x7FFFFFFF, 2: 0xFFFFFFFF})
    assert result["final_registers"][3] == 1  # 0x7fffffff < 0xffffffff
    assert 4 not in result["final_registers"]  # 0x7fffffff < -1 is false
    assert 5 not in result["final_registers"]  # 0xffffffff < 0 is false
    assert result["final_registers"][6] == 1  # -1 < 0


def test_reference_run_lui_and_auipc_use_the_instruction_pc():
    words = (encode("LUI", rd=1, imm=0x80000),
             encode("AUIPC", rd=2, imm=1),
             encode("AUIPC", rd=3, imm=0))
    based = _run(words, data_base=0x1000)
    assert based["final_registers"] == {1: 0x80000000, 2: 0x2004, 3: 0x1008}
    flat = _run((encode("AUIPC", rd=2, imm=1),))
    assert flat["final_registers"] == {2: 0x1000}


def test_reference_run_mul_and_mulhu_split_the_product():
    words = (encode("MUL", rd=3, rs1=1, rs2=2),
             encode("MULHU", rd=4, rs1=1, rs2=2))
    result = _run(words, {1: 0xFFFFFFFF, 2: 2})
    assert result["final_registers"][3] == 0xFFFFFFFE
    assert result["final_registers"][4] == 1


def test_reference_run_division_and_remainder_edge_cases():
    words = (encode("DIV", rd=3, rs1=1, rs2=0),
             encode("DIVU", rd=4, rs1=1, rs2=0),
             encode("DIV", rd=5, rs1=6, rs2=7),
             encode("REM", rd=10, rs1=6, rs2=7),
             encode("REM", rd=11, rs1=1, rs2=0),
             encode("REMU", rd=12, rs1=1, rs2=0),
             encode("DIV", rd=13, rs1=14, rs2=15),
             encode("REM", rd=16, rs1=14, rs2=15))
    result = _run(words, {1: 7, 6: 0x80000000, 7: 0xFFFFFFFF,
                          14: 7, 15: 0xFFFFFFFE})
    registers = result["final_registers"]
    assert registers[3] == 0xFFFFFFFF  # DIV by zero
    assert registers[4] == 0xFFFFFFFF  # DIVU by zero
    assert registers[5] == 0x80000000  # INT_MIN / -1
    assert 10 not in registers         # REM overflow
    assert registers[11] == 7          # REM by zero keeps the dividend
    assert registers[12] == 7          # REMU by zero keeps the dividend
    assert registers[13] == 0xFFFFFFFD  # 7 / -2 truncates toward zero
    assert registers[16] == 1          # 7 % -2


def test_reference_run_lw_sw_round_trip_and_memory_changes():
    words = (encode("LW", rd=1, rs1=18, imm=0),
             encode("ADDI", rd=1, rs1=1, imm=5),
             encode("SW", rs2=1, rs1=18, imm=0),
             encode("LW", rd=2, rs1=18, imm=4),
             encode("SW", rs2=2, rs1=18, imm=4))
    result = _run(words, {18: 0x1000}, {0x1000: 7, 0x1004: 11})
    assert result["retires"] == 5
    assert result["final_registers"][1] == 12
    assert result["final_registers"][2] == 11
    assert result["memory_changes"] == {0x1000: 12}


def test_reference_run_keeps_x0_hard_wired():
    words = (encode("ADDI", rd=0, rs1=0, imm=5),
             encode("ADD", rd=0, rs1=1, rs2=2),
             encode("ADDI", rd=3, rs1=0, imm=1))
    result = _run(words, {1: 3, 2: 4})
    assert 0 not in result["final_registers"]
    assert result["final_registers"][3] == 1
    assert [item["rd"] for item in result["register_writes"]] == [3]


def test_reference_run_dependency_chain_values():
    words = (encode("ADDI", rd=1, rs1=0, imm=3),
             encode("ADDI", rd=2, rs1=1, imm=4),
             encode("ADD", rd=3, rs1=2, rs2=1))
    result = _run(words)
    assert result["final_registers"] == {1: 3, 2: 7, 3: 10}
    assert [item["value"] for item in result["register_writes"]] == [3, 7, 10]
    assert [item["pc"] for item in result["register_writes"]] == [0, 4, 8]


def test_reference_run_validates_the_words_first():
    with pytest.raises(ValueError, match="reserved mailbox register x8"):
        _run((encode("ADDI", rd=8, rs1=0, imm=1),))
    with pytest.raises(ValueError, match="control-flow or system"):
        _run((encode("ECALL",),))
    with pytest.raises(ValueError, match="must use x18 as its base"):
        _run((encode("LW", rd=1, rs1=5, imm=0),), {5: 0x1000})


def test_reference_run_refuses_a_misaligned_effective_address():
    with pytest.raises(ValueError, match="not 4-byte aligned"):
        _run((encode("LW", rd=1, rs1=18, imm=0),), {18: 0x1002})
    with pytest.raises(ValueError, match="not 4-byte aligned"):
        _run((encode("SW", rs2=1, rs1=18, imm=0),), {18: 0x1002, 1: 5})


def test_reference_run_reads_unset_memory_as_zero():
    result = _run((encode("LW", rd=1, rs1=18, imm=8),), {18: 0x2000})
    assert 1 not in result["final_registers"]
    assert result["memory_changes"] == {}


def test_reference_run_rejects_malformed_state():
    with pytest.raises(ValueError, match="register number"):
        _run((encode("ADDI", rd=1, rs1=0, imm=1),), {32: 1})
    with pytest.raises(ValueError, match="32-bit unsigned"):
        _run((encode("ADDI", rd=1, rs1=0, imm=1),), {1: -1})
    with pytest.raises(ValueError, match="memory address"):
        _run((encode("ADDI", rd=1, rs1=0, imm=1),), memory={-4: 0})
    with pytest.raises(ValueError, match="data_base"):
        _run((encode("ADDI", rd=1, rs1=0, imm=1),), data_base=-1)


def test_as_dict_is_json_serializable():
    program = generate_program(RV32IMC, seed=4, max_words=5, window_size=32)
    data = program.as_dict()
    assert data["schema_version"] == "rv32_short_program.v1"
    assert data["seed"] == 4
    assert data["max_words"] == 5
    assert data["words"] == list(program.words)
    assert data["text"] == ":".join(f"{word:08x}" for word in program.words)
    assert data["profile"]["register_count"] == 32
    assert data["profile"]["extensions"] == ["C", "I", "M"]
    assert len(data["instructions"]) == len(program.words)
    assert isinstance(program.instructions[0], ProgramWord)
    assert json.loads(json.dumps(data)) == data


# ---------------------------------------------------------------------------
# Data-flow analysis, the dependency skeleton and the traced reference model
# ---------------------------------------------------------------------------

ALL_I_M_ALU_NAMES = frozenset({
    "LUI", "AUIPC", "ADDI", "SLTI", "SLTIU", "XORI", "ORI", "ANDI",
    "SLLI", "SRLI", "SRAI", "ADD", "SUB", "SLL", "SLT", "SLTU", "XOR", "SRL",
    "SRA", "OR", "AND", "MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU",
    "REM", "REMU",
})


def test_analysis_reports_register_dependency_edges():
    words = (encode("ADDI", rd=5, rs1=0, imm=3),
             encode("ADDI", rd=6, rs1=5, imm=4),
             encode("ADD", rd=7, rs1=6, rs2=5))
    analysis = analyze_program(words)
    assert analysis["schema_version"] == "rv32_program_analysis.v1"
    assert analysis["dependency_edges"] == 3
    assert analysis["dependencies"] == [
        {"producer": 0, "consumer": 1, "register": 5},
        {"producer": 1, "consumer": 2, "register": 6},
        {"producer": 0, "consumer": 2, "register": 5},
    ]
    assert analysis["chains"] == [
        {"register": 5, "indices": [0, 1, 2]},
        {"register": 6, "indices": [1, 2]},
    ]
    assert analysis["repeated_source_registers"] == [5]
    assert analysis["self_contained"] is True
    assert analysis["external_reads"] == []
    assert analysis["memory"] == []


def test_analysis_reports_memory_data_flow_pairs():
    words = (encode("ADDI", rd=5, rs1=0, imm=7),
             encode("SW", rs2=5, rs1=18, imm=0),
             encode("LW", rd=6, rs1=18, imm=0),
             encode("SW", rs2=6, rs1=18, imm=4),
             encode("LW", rd=7, rs1=18, imm=4))
    analysis = analyze_program(words)
    assert analysis["store_to_load"] == [
        {"store": 1, "load": 2, "offset": 0},
        {"store": 3, "load": 4, "offset": 4},
    ]
    assert analysis["load_to_store"] == [
        {"load": 2, "store": 3, "register": 6, "from_offset": 0, "to_offset": 4},
    ]
    assert analysis["repeated_offsets"] == [0, 4]
    assert [item["offset"] for item in analysis["memory"]] == [0, 0, 4, 4]
    assert analysis["load_feeds_alu"] == []


def test_analysis_flags_firmware_reads_but_not_the_data_base():
    external = analyze_program((encode("ADDI", rd=1, rs1=5, imm=1),))
    assert external["self_contained"] is False
    assert external["external_reads"] == [
        {"index": 0, "register": 5, "field": "rs1"}]
    # x18 is read as the declared memory base, which is the trampoline contract
    # rather than a hidden input, so a load-only program is self-contained.
    load_only = analyze_program((encode("LW", rd=1, rs1=18, imm=0),))
    assert load_only["self_contained"] is True
    assert load_only["external_reads"] == []


def test_analysis_ignores_x0_and_is_json_ready():
    words = (encode("ADDI", rd=0, rs1=0, imm=5),
             encode("SW", rs2=1, rs1=18, imm=0),
             encode("ADDI", rd=1, rs1=0, imm=1))
    analysis = analyze_program(words)
    assert analysis["words"] == list(words)
    assert analysis["instructions"][0]["write"] is None
    assert analysis["instructions"][1]["write"] is None
    assert analysis["instructions"][2]["write"] == 1
    # The store reads x1 before the program wrote it: it is a firmware read, and
    # x0 never becomes a dependency.
    assert analysis["external_reads"] == [
        {"index": 1, "register": 1, "field": "rs2"}]
    assert all(edge["register"] != 0 for edge in analysis["dependencies"])
    assert json.loads(json.dumps(analysis)) == analysis


def test_analysis_refuses_malformed_input():
    with pytest.raises(ValueError, match="program has no instruction"):
        analyze_program(())
    with pytest.raises(ValueError, match="32-bit unsigned word"):
        analyze_program((-1,))
    with pytest.raises(ValueError, match="32-bit unsigned word"):
        analyze_program(("00000013",))
    with pytest.raises(ValueError, match="outside the subset"):
        analyze_program((0x0001,))


def test_min_words_bounds_the_generated_length():
    for style in ("random", "chains", "mixed"):
        for seed in range(25):
            program = generate_program(RV32IM, seed=seed, max_words=5,
                                       min_words=4, window_size=64, style=style)
            assert 4 <= len(program.words) <= 5, program.text
    single = generate_program(RV32IM, seed=0, max_words=1, min_words=1,
                              window_size=64, style="chains")
    assert len(single.words) == 1
    with pytest.raises(ValueError, match="min_words must be at least 1"):
        generate_program(RV32IM, seed=0, max_words=4, window_size=64,
                         min_words=0)
    with pytest.raises(ValueError, match="must not exceed max_words"):
        generate_program(RV32IM, seed=0, max_words=4, window_size=64,
                         min_words=5)
    with pytest.raises(ValueError, match="min_words must be an integer"):
        generate_program(RV32IM, seed=0, max_words=4, window_size=64,
                         min_words=1.5)


def test_generator_refuses_bad_style_and_auipc_flag():
    with pytest.raises(ValueError, match="style must be one of"):
        generate_program(RV32IM, seed=0, max_words=4, window_size=64,
                         style="rich")
    with pytest.raises(ValueError, match="allow_auipc must be a boolean"):
        generate_program(RV32IM, seed=0, max_words=4, window_size=64,
                         allow_auipc=1)
    program = generate_program(RV32IM, seed=0, max_words=4, window_size=64)
    with pytest.raises(ValueError, match="allow_auipc must be a boolean"):
        mutate_program(RV32IM, program, seed=0, max_words=4, window_size=64,
                       allow_auipc="yes")


def test_chains_style_always_contains_a_cross_instruction_dependency():
    for seed in range(60):
        for max_words in (2, 4, 8):
            program = generate_program(RV32IM, seed=seed,
                                       max_words=max_words, min_words=2,
                                       window_size=64, style="chains",
                                       allow_auipc=False)
            analysis = analyze_program(program.words)
            assert 2 <= len(program.words) <= max_words, program.text
            assert analysis["dependency_edges"] >= 1, program.text
            # The skeleton starts with a root and its first consumer, so the
            # very first edge is word 0 -> word 1.
            assert analysis["dependencies"][0]["producer"] == 0
            assert analysis["dependencies"][0]["consumer"] == 1
            assert analysis["self_contained"] is True
            validate_program_words(RV32IM, program.words, window_size=64)


def test_chains_style_builds_multiple_chains_and_repeated_sources():
    for seed in range(40):
        program = generate_program(RV32IM, seed=seed, max_words=12,
                                   min_words=8, window_size=64, style="chains",
                                   allow_auipc=False)
        analysis = analyze_program(program.words)
        assert len(program.words) >= 8
        assert analysis["dependency_edges"] >= 3, program.text
        assert len(analysis["chains"]) >= 2, program.text
        # A computed register is read by more than one instruction; x18 is the
        # memory base, not a computed value, so it does not count.
        computed = [reg for reg in analysis["repeated_source_registers"]
                    if reg != 18]
        assert computed, program.text


def test_chains_style_emits_store_load_and_load_store_flows():
    for seed in range(40):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=8, window_size=64,
                                   style="chains")
        analysis = analyze_program(program.words)
        assert analysis["store_to_load"], program.text
        assert analysis["load_to_store"], program.text
        assert analysis["repeated_offsets"], program.text
        for item in program.instructions:
            if item.name not in ("LW", "SW"):
                continue
            assert item.operands["rs1"] == 18, item.assembly
            offset = item.operands["imm"]
            assert offset % 4 == 0, item.assembly
            assert 0 <= offset <= 60, item.assembly
        for pair in analysis["store_to_load"]:
            assert pair["store"] < pair["load"]
        for pair in analysis["load_to_store"]:
            assert pair["load"] < pair["store"]


def test_chains_style_programs_are_self_contained_and_ordered():
    # Lengths whose last skeleton role reads an earlier register:
    # a store, a load consumer, an M word, a shift or a final join.
    last_word_consumer = {8, 11, 13, 14, 15, 16}
    for seed in range(30):
        program = generate_program(RV32IM, seed=seed, max_words=16,
                                   min_words=8, window_size=64, style="chains")
        analysis = analyze_program(program.words)
        assert analysis["self_contained"] is True, program.text
        assert analysis["load_feeds_alu"], program.text
        for edge in analysis["dependencies"]:
            assert edge["producer"] < edge["consumer"], program.text
        if len(program.words) in last_word_consumer:
            assert any(edge["consumer"] == len(program.words) - 1
                       for edge in analysis["dependencies"]), program.text


def test_chains_style_covers_every_i_and_m_alu_name():
    seen = set()
    for seed in range(120):
        for style, min_words in (("chains", 16), ("random", 1)):
            program = generate_program(RV32IM, seed=seed, max_words=16,
                                       min_words=min_words, window_size=64,
                                       style=style, allow_auipc=True)
            seen.update(item.name for item in program.instructions)
    assert seen >= ALL_I_M_ALU_NAMES, sorted(ALL_I_M_ALU_NAMES - seen)


def test_allow_auipc_false_keeps_auipc_out_of_the_program():
    for seed in range(80):
        for style in ("chains", "random"):
            program = generate_program(RV32IM, seed=seed, max_words=16,
                                       min_words=4, window_size=64, style=style,
                                       allow_auipc=False)
            assert all(item.name != "AUIPC" for item in program.instructions), \
                program.text
    auipc = sum(1 for seed in range(80)
                for item in generate_program(
                    RV32IM, seed=seed, max_words=16, min_words=4,
                    window_size=64, style="chains",
                    allow_auipc=True).instructions
                if item.name == "AUIPC")
    assert auipc > 0


def test_chains_style_without_memory_still_depends():
    for seed in range(40):
        program = generate_program(RV32E, seed=seed, max_words=8, min_words=8,
                                   window_size=64, style="chains")
        analysis = analyze_program(program.words)
        assert all(item.name not in ("LW", "SW")
                   for item in program.instructions), program.text
        assert analysis["dependency_edges"] >= 1, program.text
        assert analysis["memory"] == []
        validate_program_words(RV32E, program.words, window_size=64)
    single = generate_program(RV32IM, seed=3, max_words=1, window_size=64,
                              style="chains")
    assert len(single.words) == 1
    assert single.words[0] & 0x7F in ALU_OPCODES, single.text


def test_mutation_can_introduce_a_dependency():
    parent = ShortProgram(RV32IM, 0, 6,
                          (encode("ADDI", rd=1, rs1=0, imm=1),
                           encode("ADD", rd=2, rs1=3, rs2=4)), ())
    assert analyze_program(parent.words)["dependency_edges"] == 0
    gained = 0
    for seed in range(200):
        mutated = mutate_program(RV32IM, parent, seed=seed, max_words=6,
                                 window_size=64)
        validate_program_words(RV32IM, mutated.words, window_size=64)
        if analyze_program(mutated.words)["dependency_edges"]:
            gained += 1
    assert gained > 0


def test_mutation_from_a_chains_parent_stays_legal_and_deterministic():
    parent = generate_program(RV32IM, seed=6, max_words=16, min_words=16,
                              window_size=64, style="chains",
                              allow_auipc=False)
    for seed in range(60):
        mutated = mutate_program(RV32IM, parent, seed=seed, max_words=16,
                                 window_size=64, allow_auipc=False)
        assert 1 <= len(mutated.words) <= 16
        assert mutated.style == "mutation"
        assert mutated.words != parent.words
        validate_program_words(RV32IM, mutated.words, window_size=64)
        for item in mutated.instructions:
            assert item.operands.get("rd") not in DEFAULT_RESERVED_REGISTERS
            if item.name in ("LW", "SW"):
                assert item.operands["rs1"] == 18
                assert 0 <= item.operands["imm"] <= 60
    again = mutate_program(RV32IM, parent, seed=11, max_words=16,
                           window_size=64, allow_auipc=False)
    repeat = mutate_program(RV32IM, parent, seed=11, max_words=16,
                            window_size=64, allow_auipc=False)
    assert again.as_dict() == repeat.as_dict()


def test_reference_run_traces_addresses_values_and_sources():
    words = (encode("ADDI", rd=5, rs1=0, imm=7),
             encode("SW", rs2=5, rs1=18, imm=0),
             encode("LW", rd=6, rs1=18, imm=0),
             encode("ADD", rd=7, rs1=6, rs2=5))
    result = reference_run(words, registers={18: 0x1000}, memory={},
                          window_size=64, trace=True)
    steps = result["steps"]
    assert [step["index"] for step in steps] == [0, 1, 2, 3]
    assert steps[0] == {"index": 0, "pc": 0, "name": "ADDI",
                        "reads": {"x0": 0}, "rd": 5, "value": 7}
    assert steps[1] == {"index": 1, "pc": 4, "name": "SW",
                        "address": 0x1000, "value": 7}
    assert steps[2] == {"index": 2, "pc": 8, "name": "LW",
                        "address": 0x1000, "value": 7, "rd": 6}
    assert steps[3]["reads"] == {"x6": 7, "x5": 7}
    assert steps[3]["value"] == 14
    assert result["memory_changes"] == {0x1000: 7}
    assert result["retires"] == 4
    assert "steps" not in reference_run(words, registers={18: 0x1000},
                                        memory={}, window_size=64)


def test_reference_run_trace_agrees_with_the_writeback_list():
    program = generate_program(RV32IM, seed=9, max_words=12, min_words=12,
                               window_size=64, style="chains",
                               allow_auipc=False)
    result = reference_run(program.words, registers={18: 0x14000},
                           memory={0x14000: 0xDEADBEEF, 0x14004: 0x11111111},
                           window_size=64, trace=True)
    steps = result["steps"]
    writes = result["register_writes"]
    assert len(steps) == result["retires"] == len(program.words)
    assert [step["pc"] for step in steps] == [4 * index
                                             for index in range(len(steps))]
    by_index = {write["index"]: write for write in writes}
    for step in steps:
        if step["name"] in ("LW", "SW"):
            assert isinstance(step["address"], int)
            assert step["address"] % 4 == 0
            continue
        if step["rd"]:
            assert by_index[step["index"]]["rd"] == step["rd"]
            assert by_index[step["index"]]["value"] == step["value"]
        else:
            assert step["index"] not in by_index
    assert len(writes) == sum(1 for step in steps if step.get("rd"))


def test_model_and_analysis_agree_on_store_to_load_pairs():
    for seed in range(25):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=8, window_size=64, style="chains")
        analysis = analyze_program(program.words)
        result = reference_run(program.words, registers={18: 0x14000},
                               memory={0x14000: 0xDEADBEEF,
                                       0x14004: 0x11111111},
                               window_size=64, trace=True)
        steps = result["steps"]
        assert analysis["store_to_load"], program.text
        for pair in analysis["store_to_load"]:
            store = steps[pair["store"]]
            load = steps[pair["load"]]
            assert store["address"] == 0x14000 + pair["offset"]
            assert load["address"] == store["address"]
            # The load reads back exactly the value the nearest earlier store
            # at that address left, which is the model's own store value.
            assert load["value"] == store["value"], program.text


def test_reference_run_window_size_refuses_an_out_of_window_word():
    word = encode("LW", rd=1, rs1=18, imm=16)
    with pytest.raises(ValueError, match="leaves the declared data window"):
        reference_run((word,), registers={18: 0x1000}, memory={},
                      window_size=16)
    assert reference_run((word,), registers={18: 0x1000}, memory={},
                         window_size=64)["retires"] == 1
    with pytest.raises(ValueError, match="leaves the declared data window"):
        validate_program_words(RV32IM, (word,), window_size=16)


def test_reference_run_refuses_a_non_boolean_trace():
    with pytest.raises(ValueError, match="trace must be a boolean"):
        reference_run((encode("ADDI", rd=1, rs1=0, imm=1),), registers={},
                      memory={}, trace=1)


def test_the_program_document_states_the_style():
    chains = generate_program(RV32IM, seed=1, max_words=6, min_words=4,
                              window_size=64, style="chains")
    assert chains.style == "chains"
    assert chains.as_dict()["style"] == "chains"
    random_style = generate_program(RV32IM, seed=1, max_words=6, min_words=4,
                                    window_size=64, style="random")
    assert random_style.style == "random"
    assert random_style.as_dict()["style"] == "random"


def test_a_sixteen_word_program_is_the_declared_maximum():
    program = generate_program(RV32IM, seed=0, max_words=16, min_words=16,
                               window_size=64, style="chains",
                               allow_auipc=False)
    assert len(program.words) == 16, program.text
    validate_program_words(RV32IM, program.words, window_size=64)
    analysis = analyze_program(program.words)
    assert analysis["self_contained"] is True
    assert analysis["dependency_edges"] >= 10, analysis["dependency_edges"]
    assert analysis["store_to_load"] and analysis["load_to_store"]
    # The same words replayed by the model retire all sixteen times.
    result = reference_run(program.words, registers={18: 0x14000}, memory={},
                          window_size=64)
    assert result["retires"] == 16
    with pytest.raises(ValueError, match="max_words"):
        generate_program(RV32IM, seed=1, max_words=17, window_size=64)


# ---------------------------------------------------------------------------
# Opt-in address forms (static provenance, soundness gate, generation)
# ---------------------------------------------------------------------------


def _address_form_of(program):
    """The address-form prefixes a generated program used, as role tuples."""
    forms = []
    instructions = program.instructions

    def memory_at(index, register):
        if index >= len(instructions):
            return False
        item = instructions[index]
        return (item.name in ("LW", "SW")
                and item.operands.get("rs1") == register
                and item.operands.get("imm") == 0)

    for index, item in enumerate(instructions):
        if item.name == "ADDI" and item.operands.get("rs1") == 18:
            if memory_at(index + 1, item.operands["rd"]):
                forms.append(("addi", index))
            continue
        if item.name != "ADD" or 18 not in (item.operands.get("rs1"),
                                            item.operands.get("rs2")):
            continue
        if not memory_at(index + 1, item.operands["rd"]):
            continue
        previous = instructions[index - 1] if index >= 1 else None
        if previous is not None and previous.name == "ANDI":
            forms.append(("andi", index))
        elif previous is not None and previous.name == "ADDI":
            before = instructions[index - 2] if index >= 2 else None
            if before is not None and before.name == "LUI":
                forms.append(("lui", index))
            else:
                forms.append(("add", index))
    return forms


def test_address_provenance_reports_the_legacy_x18_offset():
    words = (encode("ADDI", rd=5, rs1=0, imm=7),
             encode("SW", rs2=5, rs1=18, imm=8),
             encode("LW", rd=6, rs1=18, imm=12))
    uses = address_provenance(words, window_bytes=64)
    assert uses == [AddressUse(1, 18, 8, 4), (2, 18, 12, 4)]
    assert [tuple(use) for use in uses] == [(1, 18, 8, 4), (2, 18, 12, 4)]
    details = address_provenance_details(words, window_bytes=64)
    assert details == [
        {"index": 1, "base_reg": 18, "offset": 8, "width": 4,
         "low": 8, "high": 8},
        {"index": 2, "base_reg": 18, "offset": 12, "width": 4,
         "low": 12, "high": 12},
    ]
    assert validate_address_program(words, 64) is None


def test_address_provenance_accepts_addi_and_add_forms():
    addi = (encode("ADDI", rd=5, rs1=18, imm=12),
            encode("LW", rd=6, rs1=5, imm=0))
    uses = address_provenance(addi, window_bytes=64)
    assert uses == [(1, 5, 0, 4)]
    assert address_provenance_details(addi, window_bytes=64)[0]["low"] == 12
    validate_address_program(addi, 64)

    # ADD with a constant register, both operand orders.
    for words in (
            (encode("ADDI", rd=5, rs1=0, imm=20),
             encode("ADD", rd=6, rs1=18, rs2=5),
             encode("SW", rs2=7, rs1=6, imm=0)),
            (encode("ADDI", rd=5, rs1=0, imm=20),
             encode("ADD", rd=6, rs1=5, rs2=18),
             encode("SW", rs2=7, rs1=6, imm=0))):
        uses = address_provenance(words, window_bytes=64)
        assert uses == [(2, 6, 0, 4)]
        assert address_provenance_details(words, window_bytes=64)[0] == {
            "index": 2, "base_reg": 6, "offset": 0, "width": 4,
            "low": 20, "high": 20}

    # A constant built by LUI + ADDI is proven too.
    lui = (encode("LUI", rd=5, imm=0),
           encode("ADDI", rd=5, rs1=5, imm=24),
           encode("ADD", rd=6, rs1=18, rs2=5),
           encode("LW", rd=7, rs1=6, imm=0))
    assert address_provenance_details(lui, window_bytes=64)[0]["low"] == 24
    validate_address_program(lui, 64)


def test_address_provenance_folds_a_masked_constant_offset():
    # The sound masking idiom masks the *offset* before adding x18: 45 & 60 = 44.
    words = (encode("ADDI", rd=5, rs1=0, imm=45),
             encode("ANDI", rd=5, rs1=5, imm=60),
             encode("ADD", rd=6, rs1=18, rs2=5),
             encode("LW", rd=7, rs1=6, imm=0))
    details = address_provenance_details(words, window_bytes=64)
    assert details == [{"index": 3, "base_reg": 6, "offset": 0, "width": 4,
                        "low": 44, "high": 44}]
    assert validate_address_program(words, 64) is None
    # Masking the absolute address is NOT sound: AND clears the base's high
    # bits, so (data_base + 60) & 60 is 60, a bare offset outside the window.
    address_mask = (encode("ADDI", rd=5, rs1=18, imm=60),
                    encode("ANDI", rd=5, rs1=5, imm=60),
                    encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match="not a statically proven"):
        address_provenance(address_mask, window_bytes=64)
    with pytest.raises(ValueError, match="not a statically proven"):
        validate_address_program(address_mask, 64)


def test_address_provenance_refuses_unproven_and_out_of_window_bases():
    unproven = (encode("LW", rd=6, rs1=5, imm=0),)
    with pytest.raises(ValueError, match="base x5 is not a statically proven"):
        validate_address_program(unproven, 64)
    high = (encode("ADDI", rd=5, rs1=18, imm=64),
            encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError,
                       match=r"leaves the declared data window \(offset range "
                             r"64\.\.64"):
        validate_address_program(high, 64)
    negative = (encode("ADDI", rd=5, rs1=18, imm=-4),
                encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match=r"offset range -4\.\.-4"):
        validate_address_program(negative, 64)
    unaligned = (encode("ADDI", rd=5, rs1=18, imm=6),
                 encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match="not 4-byte aligned"):
        validate_address_program(unaligned, 64)
    # Overwriting x18 loses the window base for every later address.
    clobbered = (encode("ADDI", rd=18, rs1=18, imm=4),
                 encode("LW", rd=6, rs1=18, imm=0))
    with pytest.raises(ValueError, match="base x18 is not a statically proven"):
        validate_address_program(clobbered, 64)


def test_validate_program_words_admits_address_forms_only_on_request():
    words = (encode("ADDI", rd=5, rs1=18, imm=12),
             encode("LW", rd=6, rs1=5, imm=0))
    validate_program_words(RV32IM, words, window_size=64,
                           allow_address_forms=True)
    with pytest.raises(ValueError, match="must use x18 as its base"):
        validate_program_words(RV32IM, words, window_size=64)
    nonzero = (encode("ADDI", rd=5, rs1=18, imm=12),
               encode("LW", rd=6, rs1=5, imm=4))
    with pytest.raises(ValueError, match="must use immediate 0"):
        validate_program_words(RV32IM, nonzero, window_size=64,
                               allow_address_forms=True)
    out_of_window = (encode("ADDI", rd=5, rs1=18, imm=64),
                     encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match="leaves the declared data window"):
        validate_program_words(RV32IM, out_of_window, window_size=64,
                               allow_address_forms=True)
    masked_offset = (encode("ADDI", rd=5, rs1=0, imm=45),
                     encode("ANDI", rd=5, rs1=5, imm=60),
                     encode("ADD", rd=6, rs1=18, rs2=5),
                     encode("LW", rd=7, rs1=6, imm=0))
    validate_program_words(RV32IM, masked_offset, window_size=64,
                           allow_address_forms=True)
    masked_address = (encode("ADDI", rd=5, rs1=18, imm=60),
                      encode("ANDI", rd=5, rs1=5, imm=60),
                      encode("LW", rd=6, rs1=5, imm=0))
    with pytest.raises(ValueError, match="not a statically proven"):
        validate_program_words(RV32IM, masked_address, window_size=64,
                               allow_address_forms=True)


def test_generated_address_style_is_sound_and_uses_a_computed_base():
    for seed in range(16):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=6, window_size=64,
                                   style="address",
                                   allow_address_forms=True)
        assert program.style == "address"
        validate_program_words(RV32IM, program.words, window_size=64,
                               allow_address_forms=True)
        memory = [item for item in program.instructions
                  if item.name in ("LW", "SW")]
        assert memory, program.text
        # The generated memory words really use a computed base, not only x18.
        assert any(item.operands["rs1"] != 18 for item in memory), program.text
        uses = address_provenance(program.words, window_bytes=64)
        assert len(uses) == len(memory)
        for index, base_reg, offset, width in uses:
            assert width == 4 and offset == 0
            assert 0 <= base_reg < 32
        for detail in address_provenance_details(program.words,
                                                 window_bytes=64):
            assert 0 <= detail["low"] <= detail["high"] <= 60
            assert detail["low"] % 4 == 0 and detail["high"] % 4 == 0
        # The bounded PC interpreter replays the image with those addresses.
        result = reference_run(program.words, registers={18: 0x1000},
                               memory={}, window_size=64,
                               allow_address_forms=True)
        assert result["retires"] == len(program.words)
        assert all(write["pc"] == 4 * write["index"]
                   for write in result["register_writes"])


def test_address_style_covers_every_sound_form():
    forms = set()
    for seed in range(24):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=8, window_size=64,
                                   style="address",
                                   allow_address_forms=True)
        validate_address_program(program.words, 64)
        forms.update(form for form, _ in _address_form_of(program))
        # The masked form only ever folds a constant offset: never an ANDI whose
        # source is the x18-derived address register.
        instructions = program.instructions
        for index, item in enumerate(instructions):
            if item.name != "ANDI":
                continue
            assert index >= 1
            previous = instructions[index - 1]
            assert previous.name == "ADDI" and previous.operands["rs1"] == 0, \
                program.text
    assert forms == {"addi", "add", "lui", "andi"}, forms


def test_address_style_respects_the_declared_window_size():
    for window in (4, 8, 32, 2048, 4096):
        for seed in range(8):
            program = generate_program(RV32IM, seed=seed, max_words=8,
                                       min_words=6, window_size=window,
                                       style="address",
                                       allow_address_forms=True)
            validate_program_words(RV32IM, program.words,
                                   window_size=window,
                                   allow_address_forms=True)
            validate_address_program(program.words, window)
            for detail in address_provenance_details(program.words,
                                                     window_bytes=window):
                assert 0 <= detail["low"] <= detail["high"] <= window - 4


def test_address_form_mutation_stays_sound_and_refuses_without_the_flag():
    parent = generate_program(RV32IM, seed=5, max_words=8, min_words=8,
                              window_size=64, style="address",
                              allow_address_forms=True)
    with pytest.raises(ValueError,
                       match="allow_address_forms=True is required"):
        mutate_program(RV32IM, parent, seed=0, max_words=8, window_size=64)
    for seed in range(40):
        mutated = mutate_program(RV32IM, parent, seed=seed, max_words=8,
                                 window_size=64,
                                 allow_address_forms=True)
        assert mutated.words != parent.words
        validate_address_program(mutated.words, 64)
        validate_program_words(RV32IM, mutated.words, window_size=64,
                               allow_address_forms=True)
    first = mutate_program(RV32IM, parent, seed=3, max_words=8,
                           window_size=64, allow_address_forms=True)
    again = mutate_program(RV32IM, parent, seed=3, max_words=8,
                           window_size=64, allow_address_forms=True)
    assert first.as_dict() == again.as_dict()


def test_reference_run_executes_address_forms_at_the_proven_addresses():
    words = (encode("ADDI", rd=5, rs1=18, imm=12),
             encode("LW", rd=6, rs1=5, imm=0),
             encode("ADDI", rd=7, rs1=0, imm=45),
             encode("ANDI", rd=7, rs1=7, imm=60),
             encode("ADD", rd=10, rs1=18, rs2=7),
             encode("SW", rs2=6, rs1=10, imm=0))
    result = reference_run(words, registers={18: 0x1000},
                           memory={0x100C: 0xAB}, window_size=64,
                           allow_address_forms=True, trace=True)
    assert result["pc_order"] == [0, 4, 8, 12, 16, 20]
    steps = result["steps"]
    assert steps[1] == {"index": 1, "pc": 4, "name": "LW",
                        "address": 0x100C, "value": 0xAB, "rd": 6}
    assert steps[5] == {"index": 5, "pc": 20, "name": "SW",
                        "address": 0x102C, "value": 0xAB}
    assert result["memory_changes"] == {0x102C: 0xAB}
    assert result["trace"][1] == (4, "LW", 6, 0xAB)
    assert result["trace"][5] == (20, "SW", 0, 0xAB)


def test_opt_in_flags_default_off_keep_the_old_program_space():
    branch = encode("BEQ", rs1=0, rs2=0, imm=4)
    for seed in range(20):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=8, window_size=64,
                                   style="chains")
        assert program.compressed is False
        assert all(word & 3 == 3 for word in program.words)
        assert not any(word & 0x7F == 0x63 for word in program.words)
        assert all(item.operands["rs1"] == 18
                   for item in program.instructions
                   if item.name in ("LW", "SW"))
        data = program.as_dict()
        assert data["compressed"] is False
        assert json.loads(json.dumps(data)) == data
    with pytest.raises(ValueError, match="straight-line"):
        validate_program_words(RV32IM, (branch,), window_size=64)
    # run_program is the same interpreter reference_run validates with.
    straight = (encode("ADDI", rd=1, rs1=0, imm=3),)
    assert run_program(straight, registers={}, memory={}) == \
        reference_run(straight, registers={}, memory={})
