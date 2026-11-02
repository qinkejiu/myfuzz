"""Forward-branch programs: validation, PC interpretation, analysis, mutation.

The branch subset is opt-in and deliberately tiny: only the six B-type branches,
only strictly forward targets inside the installed image, and the target index
``len(words)`` names the return jump the host appends to the slot.  These tests
pin the static rules, the PC-indexed interpreter (retirement order, skip trace,
step bound), the branch-aware may-analysis and the branch-target mutation.
"""

import pytest

from myfuzz.fuzz.rv32_program import (
    ShortProgram, analyze_program, generate_program, mutate_program,
    reference_run, run_program, validate_program_words,
)
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32IM = RiscvProfile(32, frozenset({"I", "M"}), 4, 32, 0)


def _run(words, *, registers=None, memory=None, allow_branches=True, **kwargs):
    return reference_run(words, registers=registers or {},
                         memory=memory or {}, allow_branches=allow_branches,
                         **kwargs)


def _selftest_branch(offset, index=0):
    return encode("BEQ", rs1=0, rs2=0, imm=offset)


# ---------------------------------------------------------------------------
# Static admission
# ---------------------------------------------------------------------------


def test_forward_branch_targets_are_admitted_up_to_the_return_jump():
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BEQ", rs1=5, rs2=0, imm=8),
             encode("ADDI", rd=6, rs1=0, imm=2),
             encode("ADDI", rd=7, rs1=0, imm=3))
    assert validate_program_words(RV32IM, words, window_size=64,
                                  allow_branches=True) is None
    # In these four words a branch at index 0 may target indices 1..4; index 4
    # is the appended return jump.
    for target in (1, 2, 3, 4):
        branch = encode("BEQ", rs1=0, rs2=0, imm=4 * target)
        validate_program_words(RV32IM, (branch,) + words[1:],
                               window_size=64, allow_branches=True)
    # A single-word image may branch straight to the return jump at index 1.
    validate_program_words(RV32IM, (encode("BEQ", rs1=0, rs2=0, imm=4),),
                           window_size=64, allow_branches=True)
    # A branch that lands past index 4 in a four-word image is refused.
    with pytest.raises(ValueError, match="beyond the installed program"):
        validate_program_words(
            RV32IM, (encode("BEQ", rs1=0, rs2=0, imm=20),) + words[1:],
            window_size=64, allow_branches=True)


def test_branch_target_bounds_are_named():
    words = (encode("ADDI", rd=1, rs1=0, imm=1),
             encode("BEQ", rs1=1, rs2=0, imm=-4),
             encode("ADDI", rd=2, rs1=0, imm=1))
    with pytest.raises(ValueError, match="not strictly forward"):
        validate_program_words(RV32IM, words, window_size=64,
                               allow_branches=True)
    with pytest.raises(ValueError, match="not strictly forward"):
        validate_program_words(RV32IM, (_selftest_branch(0),), window_size=64,
                               allow_branches=True)
    # Target index 5 in a three-word image is past the appended return jump.
    with pytest.raises(ValueError, match="beyond the installed program"):
        validate_program_words(
            RV32IM, (_selftest_branch(20), encode("ADDI", rd=1, rs1=0, imm=1),
                     encode("ADDI", rd=2, rs1=0, imm=1)),
            window_size=64, allow_branches=True)
    # A target that is not 4-byte aligned is refused even though the encoding
    # only requires 2-byte alignment.
    with pytest.raises(ValueError, match="not 4-byte aligned"):
        validate_program_words(RV32IM, (_selftest_branch(2),), window_size=64,
                               allow_branches=True)


def test_branch_target_sign_extension_uses_the_b_type_fields():
    # imm[12|10:5|4:1|11] spreads the displacement; a negative offset must decode
    # back to the same value and be refused as backward rather than wrapping.
    negative = encode("BEQ", rs1=1, rs2=2, imm=-8)
    with pytest.raises(ValueError, match="offset -8"):
        validate_program_words(RV32IM, (negative,), window_size=64,
                               allow_branches=True)
    # The largest encodable forward displacement lands far outside a 16-word
    # image, naming the computed target index.
    large = encode("BEQ", rs1=1, rs2=2, imm=4092)
    with pytest.raises(ValueError, match="target index 1023"):
        validate_program_words(RV32IM, (large,), window_size=64,
                               allow_branches=True)
    # A 16-word image accepts a target on its last word (offset 60 at index 0).
    program = generate_program(RV32IM, seed=4, max_words=16, min_words=16,
                               window_size=64, style="chains",
                               allow_auipc=False)
    last = encode("BEQ", rs1=0, rs2=0, imm=60)
    validate_program_words(RV32IM, (last,) + program.words[1:],
                           window_size=64, allow_branches=True)


def test_branches_stay_refused_without_the_flag():
    branch = _selftest_branch(4)
    with pytest.raises(ValueError, match="straight-line"):
        validate_program_words(RV32IM, (branch,), window_size=64)
    with pytest.raises(ValueError, match="is a control-flow or system"):
        validate_program_words(RV32IM, (encode("JAL", rd=1, imm=4),),
                               window_size=64, allow_branches=True)
    with pytest.raises(ValueError, match="is a control-flow or system"):
        validate_program_words(RV32IM, (encode("JALR", rd=1, rs1=0, imm=0),),
                               window_size=64, allow_branches=True)


def test_branch_profile_register_rules_apply():
    rv32e = RiscvProfile(32, frozenset({"E"}), 4, 16, 0)
    branch = encode("BEQ", rs1=20, rs2=0, imm=4)
    with pytest.raises(ValueError, match="rs1 x20 does not exist"):
        validate_program_words(rv32e, (branch,), window_size=64,
                               allow_branches=True)
    validate_program_words(rv32e, (encode("BEQ", rs1=1, rs2=2, imm=4),),
                           window_size=64, allow_branches=True)


# ---------------------------------------------------------------------------
# PC-indexed interpretation
# ---------------------------------------------------------------------------


def test_a_taken_branch_skips_words_and_retires_in_pc_order():
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BEQ", rs1=0, rs2=0, imm=8),   # skip index 2
             encode("ADDI", rd=6, rs1=0, imm=2),
             encode("ADDI", rd=7, rs1=0, imm=3))
    result = _run(words)
    assert result["retires"] == result["retired_count"] == 3
    assert result["pc_order"] == [0, 4, 12]
    assert result["final_registers"] == {5: 1, 7: 3}
    assert 6 not in result["final_registers"]
    assert [write["index"] for write in result["register_writes"]] == [0, 3]
    assert result["trace"][1].insn == "BEQ"
    assert result["trace"][1].rd == 0 and result["trace"][1].wdata == 0
    # The trace is a tuple of (pc, insn, rd, wdata).
    pc, insn, rd, wdata = result["trace"][0]
    assert (pc, insn, rd, wdata) == (0, "ADDI", 5, 1)


def test_a_not_taken_branch_falls_through():
    # BEQ x0, x0 is always taken and skips the middle word...
    words = (encode("BEQ", rs1=0, rs2=0, imm=8),
             encode("ADDI", rd=5, rs1=0, imm=7),
             encode("ADDI", rd=6, rs1=0, imm=8))
    result = _run(words)
    assert result["pc_order"] == [0, 8]
    assert result["final_registers"] == {6: 8}
    # ...while BNE x0, x0 is never taken and the fall-through runs.
    words = (encode("BNE", rs1=0, rs2=0, imm=8),
             encode("ADDI", rd=5, rs1=0, imm=7),
             encode("ADDI", rd=6, rs1=0, imm=8))
    result = _run(words)
    assert result["pc_order"] == [0, 4, 8]
    assert result["final_registers"] == {5: 7, 6: 8}


def test_a_branch_to_the_program_end_retires_only_the_prefix():
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BEQ", rs1=5, rs2=5, imm=8),
             encode("ADDI", rd=6, rs1=0, imm=2))
    result = _run(words)
    assert result["pc_order"] == [0, 4]
    assert result["final_registers"] == {5: 1}


def test_branch_condition_semantics():
    cases = [
        ("BEQ", 3, 3, True), ("BEQ", 3, 4, False),
        ("BNE", 3, 4, True), ("BNE", 3, 3, False),
        ("BLT", 0xFFFFFFFF, 1, True), ("BLT", 1, 0xFFFFFFFF, False),
        ("BGE", 0xFFFFFFFF, 0xFFFFFFFF, True),
        ("BLTU", 1, 0xFFFFFFFF, True), ("BLTU", 0xFFFFFFFF, 1, False),
        ("BGEU", 0xFFFFFFFF, 1, True), ("BGEU", 1, 0xFFFFFFFF, False),
    ]
    for name, left, right, taken in cases:
        words = (encode(name, rs1=1, rs2=2, imm=8),
                 encode("ADDI", rd=3, rs1=0, imm=1),
                 encode("ADDI", rd=4, rs1=0, imm=1))
        result = reference_run(words, registers={1: left, 2: right},
                               memory={}, allow_branches=True)
        assert result["pc_order"] == ([0, 8] if taken else [0, 4, 8]), name


def test_the_step_cap_stops_a_would_be_loop():
    # A structurally illegal self-branch is refused statically...
    with pytest.raises(ValueError, match="not strictly forward"):
        validate_program_words(RV32IM, (_selftest_branch(0),), window_size=64,
                               allow_branches=True)
    # ...and the bounded interpreter still terminates on it (explicit bound and
    # the implicit one-per-word bound), instead of hanging.
    with pytest.raises(ValueError, match="exceeded the 4-step bound"):
        run_program((_selftest_branch(0),), registers={}, memory={},
                    allow_branches=True, max_steps=4, validate=False)
    with pytest.raises(ValueError, match="exceeded the 2-step bound"):
        run_program((_selftest_branch(0),), registers={}, memory={},
                    allow_branches=True, validate=False)
    # A legal forward-branch program never hits the implicit bound.
    words = (encode("BEQ", rs1=0, rs2=0, imm=8),
             encode("ADDI", rd=5, rs1=0, imm=1))
    assert run_program(words, registers={}, memory={},
                       allow_branches=True)["retires"] == 1


def test_branch_steps_report_condition_and_target():
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BNE", rs1=5, rs2=0, imm=8),
             encode("ADDI", rd=6, rs1=0, imm=2))
    result = reference_run(words, registers={}, memory={}, allow_branches=True,
                           trace=True)
    branch_step = result["steps"][1]
    assert branch_step == {"index": 1, "pc": 4, "name": "BNE",
                           "reads": {"x5": 1, "x0": 0}, "taken": True,
                           "target_pc": 12}
    assert result["pc_order"] == [0, 4]


def test_reference_run_keeps_old_fields_and_adds_the_witness():
    words = (encode("ADDI", rd=1, rs1=0, imm=1),
             encode("SW", rs2=1, rs1=18, imm=0))
    result = reference_run(words, registers={18: 0x1000}, memory={},
                           window_size=64)
    assert result["schema_version"] == "rv32_reference_run.v1"
    assert result["retires"] == 2
    assert result["retired_count"] == 2
    assert result["pc_order"] == [0, 4]
    assert result["trace"] == [(0, "ADDI", 1, 1), (4, "SW", 0, 1)]
    assert result["register_writes"] == [
        {"index": 0, "pc": 0, "name": "ADDI", "rd": 1, "value": 1}]
    assert result["memory_changes"] == {0x1000: 1}
    # The historical trace flag still adds one step per retired instruction.
    traced = reference_run(words, registers={18: 0x1000}, memory={},
                           window_size=64, trace=True)
    assert traced["steps"][1] == {"index": 1, "pc": 4, "name": "SW",
                                  "address": 0x1000, "value": 1}


# ---------------------------------------------------------------------------
# Branch-aware analysis
# ---------------------------------------------------------------------------


def test_analysis_reports_branches_and_may_producers():
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BEQ", rs1=0, rs2=0, imm=8),
             encode("ADDI", rd=5, rs1=0, imm=2),
             encode("ADD", rd=6, rs1=5, rs2=0))
    analysis = analyze_program(words)
    assert analysis["control_flow"] == "forward_branches"
    assert analysis["branches"] == [
        {"index": 1, "pc": 4, "name": "BEQ", "rs1": 0, "rs2": 0,
         "offset": 8, "target_index": 3}]
    # x5 at index 3 can come from index 0 (via the branch) or index 2 (fall
    # through), so both are real producers on some path.
    assert analysis["dependencies"] == [
        {"producer": 0, "consumer": 3, "register": 5},
        {"producer": 2, "consumer": 3, "register": 5},
    ]
    assert analysis["chains"] == [{"register": 5, "indices": [0, 2, 3]}]
    assert analysis["self_contained"] is True
    # The same words without the branch are a single-producer straight line.
    straight = analyze_program((words[0], words[2], words[3]))
    assert straight["control_flow"] == "straight_line"
    assert straight["branches"] == []
    assert straight["dependencies"] == [
        {"producer": 1, "consumer": 2, "register": 5}]


def test_analysis_keeps_memory_pairs_across_a_branch():
    words = (encode("ADDI", rd=5, rs1=0, imm=7),
             encode("SW", rs2=5, rs1=18, imm=0),
             encode("BEQ", rs1=0, rs2=0, imm=12),   # jump straight to the load
             encode("ADDI", rd=5, rs1=0, imm=9),
             encode("SW", rs2=5, rs1=18, imm=0),
             encode("LW", rd=6, rs1=18, imm=0))
    analysis = analyze_program(words)
    # The load can read the first store (branch path) or the second one (fall
    # through): both are real producers on some path.
    assert analysis["store_to_load"] == [
        {"store": 1, "load": 5, "offset": 0},
        {"store": 4, "load": 5, "offset": 0},
    ]
    assert analysis["repeated_offsets"] == [0]


# ---------------------------------------------------------------------------
# Generation and mutation
# ---------------------------------------------------------------------------


def test_branch_style_requires_the_flag():
    with pytest.raises(ValueError, match="requires allow_branches=True"):
        generate_program(RV32IM, seed=0, max_words=5, window_size=64,
                         style="branch")
    with pytest.raises(ValueError, match="allow_branches=True"):
        generate_program(RV32IM, seed=0, max_words=5, window_size=64,
                         style="extended", allow_address_forms=True)


def test_branch_style_programs_are_sound_and_retire_in_pc_order():
    for seed in range(20):
        program = generate_program(RV32IM, seed=seed, max_words=8,
                                   min_words=5, window_size=64,
                                   style="branch", allow_branches=True)
        assert program.style == "branch"
        validate_program_words(RV32IM, program.words, window_size=64,
                               allow_branches=True)
        branches = [item for item in program.instructions
                    if item.name in ("BEQ", "BNE", "BLT", "BGE", "BLTU",
                                     "BGEU")]
        assert branches, program.text
        result = reference_run(program.words, registers={18: 0x1000},
                               memory={}, window_size=64,
                               allow_branches=True)
        assert result["retires"] <= len(program.words)
        assert result["pc_order"] == sorted(result["pc_order"])
        assert result["retired_count"] == len(result["trace"])
        # Every branch target is inside the image or is its end.
        for index, item in enumerate(program.instructions):
            if item.name not in ("BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU"):
                continue
            target = index + item.operands["imm"] // 4
            assert 0 < target <= len(program.words)


def test_branch_generation_is_deterministic_per_seed():
    first = generate_program(RV32IM, seed=11, max_words=9, min_words=6,
                             window_size=64, style="branch",
                             allow_branches=True)
    again = generate_program(RV32IM, seed=11, max_words=9, min_words=6,
                             window_size=64, style="branch",
                             allow_branches=True)
    other = generate_program(RV32IM, seed=12, max_words=9, min_words=6,
                             window_size=64, style="branch",
                             allow_branches=True)
    assert first.as_dict() == again.as_dict()
    assert first.text == again.text
    assert other.text != first.text


def test_mutation_retargets_branches_and_stays_legal():
    parent = generate_program(RV32IM, seed=6, max_words=6, min_words=6,
                              window_size=64, style="branch",
                              allow_branches=True)
    targets = set()
    lengths = set()
    for seed in range(80):
        mutated = mutate_program(RV32IM, parent, seed=seed, max_words=6,
                                 window_size=64, allow_branches=True)
        assert mutated.style == "mutation"
        assert mutated.words != parent.words
        validate_program_words(RV32IM, mutated.words, window_size=64,
                               allow_branches=True)
        lengths.add(len(mutated.words))
        for index, item in enumerate(mutated.instructions):
            if item.name in ("BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU"):
                target = index + item.operands["imm"] // 4
                assert 0 < target <= len(mutated.words), mutated.text
                targets.add((index, target))
        # Every mutation is also replayable by the bounded interpreter.
        reference_run(mutated.words, registers={18: 0x1000}, memory={},
                      window_size=64, allow_branches=True)
    assert {4, 5, 6} & lengths, lengths
    assert len(targets) > 2


def test_mutation_refuses_branch_programs_without_the_flag():
    parent = generate_program(RV32IM, seed=2, max_words=6, min_words=4,
                              window_size=64, style="branch",
                              allow_branches=True)
    with pytest.raises(ValueError, match="allow_branches=True is required"):
        mutate_program(RV32IM, parent, seed=0, max_words=6, window_size=64)


def test_branch_mutation_is_deterministic():
    parent = generate_program(RV32IM, seed=9, max_words=7, min_words=5,
                              window_size=64, style="branch",
                              allow_branches=True)
    first = mutate_program(RV32IM, parent, seed=5, max_words=7,
                           window_size=64, allow_branches=True)
    again = mutate_program(RV32IM, parent, seed=5, max_words=7,
                           window_size=64, allow_branches=True)
    assert first.as_dict() == again.as_dict()


def test_mutation_of_a_branch_with_no_other_target_stays_legal():
    # The only branch is the last word, so it already points at the return jump
    # and has no alternative target: the mutator must still change the program
    # in a legal way.
    words = (encode("ADDI", rd=5, rs1=0, imm=1),
             encode("BEQ", rs1=0, rs2=0, imm=4))
    program = ShortProgram(RV32IM, 0, 2, words, ())
    for seed in range(60):
        mutated = mutate_program(RV32IM, program, seed=seed, max_words=2,
                                 window_size=64, allow_branches=True)
        assert mutated.words != words
        validate_program_words(RV32IM, mutated.words, window_size=64,
                               allow_branches=True)
    single = ShortProgram(RV32IM, 0, 1,
                          (encode("BEQ", rs1=0, rs2=0, imm=4),), ())
    for seed in range(30):
        mutated = mutate_program(RV32IM, single, seed=seed, max_words=1,
                                 window_size=64, allow_branches=True)
        assert mutated.words != single.words
        validate_program_words(RV32IM, mutated.words, window_size=64,
                               allow_branches=True)
