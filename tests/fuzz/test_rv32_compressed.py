"""Compressed (two-parcel) images: packing, admission, interpretation, mutation.

A 32-bit record word holds either one 32-bit instruction or two 16-bit parcels;
the low half executes first at ``pc`` and the high half at ``pc + 2``.  These
tests pin the admitted safe ALU subset (the one the unified entry already
accepts), the by-name refusals, the parcel/word PC granularity, the parcel-level
trace against hand-computed values, the bounded interpreter, and the opt-in
generator/mutator.
"""

import json

import pytest

from myfuzz.fuzz.rv32_compressed import (
    COMPRESSED_ALU_NAMES, CompressedRefusal, decode_compressed_parcel,
    generate_compressed_program, image_instructions, mutate_compressed_program,
    pack_parcels, parcel_is_admitted, reference_run_compressed,
    split_record_word, validate_compressed_program,
)
from myfuzz.fuzz.rv32_program import (
    ShortProgram, analyze_program, generate_program, mutate_program,
    reference_run, validate_program_words,
)
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32IM = RiscvProfile(32, frozenset({"I", "M"}), 4, 32, 0)
RV32IMC = RiscvProfile(32, frozenset({"I", "M", "C"}), 2, 32, 0)
RV32EC = RiscvProfile(32, frozenset({"E", "C"}), 2, 16, 0)


def _c(name, **operands):
    return encode(name, xlen=32, **operands)


def _pair(low, high):
    return pack_parcels(low, high)


def _run(words, *, registers=None, memory=None, window_size=64, **kwargs):
    return reference_run_compressed(words, registers=registers or {},
                                    memory=memory or {},
                                    window_size=window_size, **kwargs)


# ---------------------------------------------------------------------------
# Parcel packing and decoding
# ---------------------------------------------------------------------------


def test_pack_and_split_keep_the_low_parcel_first():
    low = _c("C.LI", rd=12, imm=5)
    high = _c("C.ADDI", rd=13, imm=-2)
    word = _pair(low, high)
    assert word == low | high << 16
    assert split_record_word(word) == (low, high)
    layout = image_instructions((word,))
    assert [entry.pc_offset for entry in layout] == [0, 2]
    assert [entry.width for entry in layout] == [2, 2]
    assert [entry.name for entry in layout] == ["C.LI", "C.ADDI"]
    assert [entry.half for entry in layout] == [0, 1]
    with pytest.raises(ValueError, match="32-bit-length"):
        pack_parcels(0x0003, 0x0001)
    with pytest.raises(ValueError, match="16-bit"):
        pack_parcels(0x10000, 0x0001)
    with pytest.raises(ValueError, match="32 bits"):
        split_record_word(-1)


@pytest.mark.parametrize("name,operands", [
    ("C.ADDI", {"rd": 12, "imm": 5}),
    ("C.ADDI", {"rd": 15, "imm": -32}),
    ("C.LI", {"rd": 13, "imm": -3}),
    ("C.LUI", {"rd": 14, "imm": 2}),
    ("C.SLLI", {"rd": 15, "shamt": 3}),
    ("C.SRLI", {"rd": 12, "shamt": 31}),
    ("C.SRAI", {"rd": 13, "shamt": 1}),
    ("C.ANDI", {"rd": 14, "imm": -32}),
    ("C.MV", {"rd": 12, "rs2": 15}),
    ("C.ADD", {"rd": 13, "rs2": 14}),
    ("C.SUB", {"rd": 12, "rs2": 13}),
    ("C.XOR", {"rd": 14, "rs2": 15}),
    ("C.OR", {"rd": 12, "rs2": 15}),
    ("C.AND", {"rd": 15, "rs2": 12}),
])
def test_every_admitted_parcel_round_trips(name, operands):
    parcel = _c(name, **operands)
    decoded = decode_compressed_parcel(parcel)
    assert decoded.name == name
    assert decoded.operands == operands
    assert decoded.assembly.startswith(name.lower())
    assert parcel_is_admitted(parcel)
    assert name in COMPRESSED_ALU_NAMES
    # A whole image of one pair validates and the PC order is 0, 2.
    validate_compressed_program(RV32IMC, (_pair(parcel, parcel),),
                                window_size=64)


@pytest.mark.parametrize("parcel,name,fragment", [
    (_c("C.J", imm=4), "C.J", "compressed control transfer C.J"),
    (0x2005, "C.JAL", "compressed control transfer C.JAL"),
    (0x8002 | 12 << 7, "C.JR", "compressed control transfer C.JR"),
    (0x9002 | 12 << 7, "C.JALR", "compressed control transfer C.JALR"),
    (_c("C.BEQZ", rs1=12, imm=4), "C.BEQZ",
     "compressed control transfer C.BEQZ"),
    (_c("C.BNEZ", rs1=12, imm=4), "C.BNEZ",
     "compressed control transfer C.BNEZ"),
    (_c("C.LW", rd=8, rs1=8, imm=0), "C.LW", "compressed memory instruction"),
    (_c("C.SW", rs2=8, rs1=8, imm=0), "C.SW", "compressed memory instruction"),
    (_c("C.LWSP", rd=8, imm=0), "C.LWSP", "compressed memory instruction"),
    (_c("C.SWSP", rs2=8, imm=0), "C.SWSP", "compressed memory instruction"),
    (_c("C.ADDI4SPN", rd=8, imm=4), "C.ADDI4SPN", "compressed form C.ADDI4SPN"),
    (0x6105, "C.ADDI16SP", "compressed form C.ADDI16SP"),
    (0x0001, "C.NOP", "compressed form C.NOP"),
    (0x9002, "C.EBREAK", "compressed form C.EBREAK"),
])
def test_refused_parcels_are_named(parcel, name, fragment):
    with pytest.raises(CompressedRefusal) as error:
        decode_compressed_parcel(parcel)
    assert fragment in str(error.value)
    assert name not in COMPRESSED_ALU_NAMES
    assert not parcel_is_admitted(parcel)


@pytest.mark.parametrize("parcel,fragment", [
    (_c("C.ADDI", rd=12, imm=0), "HINT"),
    (_c("C.LI", rd=12, imm=0), "HINT"),
    (0x0002 | 12 << 7, "HINT"),          # C.SLLI rd=x12, shamt=0
    (_c("C.MV", rd=14, rs2=5), "x12..x15"),
    (_c("C.ADD", rd=5, rs2=14), "x12..x15"),
    (_c("C.SRLI", rd=8, shamt=2), "x12..x15"),
])
def test_hint_and_out_of_range_parcels_are_refused(parcel, fragment):
    with pytest.raises(CompressedRefusal, match=fragment):
        decode_compressed_parcel(parcel)


# ---------------------------------------------------------------------------
# Image validation
# ---------------------------------------------------------------------------


def test_validation_requires_a_c_capable_profile():
    words = (_pair(_c("C.LI", rd=12, imm=1), _c("C.ADDI", rd=12, imm=1)),)
    with pytest.raises(ValueError, match="declares the C extension"):
        validate_compressed_program(RV32IM, words, window_size=64)
    unaligned = RiscvProfile(32, frozenset({"I", "C"}), 4, 32, 0)
    with pytest.raises(ValueError, match="2-byte instruction alignment"):
        validate_compressed_program(unaligned, words, window_size=64)
    validate_compressed_program(RV32IMC, words, window_size=64)
    # RV32EC (16 registers) still has x12..x15 for the admitted parcels.
    validate_compressed_program(RV32EC, words, window_size=64)


def test_validation_names_the_refused_parcel_and_the_straddle_rule():
    legal = _c("C.ADDI", rd=12, imm=5)
    refused = _c("C.J", imm=8)
    with pytest.raises(CompressedRefusal,
                       match=r"record word 0 high parcel at pc\+2"):
        validate_compressed_program(RV32IMC, (_pair(legal, refused),),
                                    window_size=64)
    # A high half that starts a 32-bit instruction would straddle two record
    # words, so it is refused.
    straddle = legal | (0x0003 << 16)
    with pytest.raises(CompressedRefusal, match="may not straddle"):
        validate_compressed_program(RV32IMC, (straddle,), window_size=64)
    # A 32-bit memory word keeps the straight-line x18 rule.
    with pytest.raises(ValueError, match="must use x18 as its base"):
        validate_compressed_program(
            RV32IMC, (_c("LW", rd=5, rs1=7, imm=0), _pair(legal, legal)),
            window_size=64)
    with pytest.raises(ValueError, match="leaves the declared data window"):
        validate_compressed_program(
            RV32IMC, (_c("LW", rd=5, rs1=18, imm=64), _pair(legal, legal)),
            window_size=64)


def test_validation_refuses_reserved_parcel_destinations():
    words = (_pair(_c("C.ADDI", rd=12, imm=5), _c("C.ADDI", rd=13, imm=5)),)
    with pytest.raises(ValueError, match="writes the reserved .* x12"):
        validate_compressed_program(RV32IMC, words, window_size=64,
                                    reserved=(12,))


# ---------------------------------------------------------------------------
# PC-indexed interpretation
# ---------------------------------------------------------------------------


def test_pc_advances_by_two_for_parcels_and_four_for_words():
    image = (_c("LW", rd=5, rs1=18, imm=0),
             _pair(_c("C.ADDI", rd=12, imm=1), _c("C.ADDI", rd=12, imm=1)),
             _c("ADDI", rd=6, rs1=0, imm=9))
    result = _run(image, registers={18: 0x2000}, memory={0x2000: 0xAB},
                  trace=True)
    assert result["pc_order"] == [0, 4, 6, 8]
    assert [step["width"] for step in result["steps"]] == [4, 2, 2, 4]
    assert [step["half"] for step in result["steps"]] == [0, 0, 1, 0]
    assert result["retires"] == result["retired_count"] == 4
    assert result["trace"] == [
        (0, "LW", 5, 0xAB), (4, "C.ADDI", 12, 1),
        (6, "C.ADDI", 12, 2), (8, "ADDI", 6, 9)]
    assert result["final_registers"] == {5: 0xAB, 6: 9, 12: 2, 18: 0x2000}
    assert result["steps"][0]["address"] == 0x2000
    assert result["register_writes"] == [
        {"index": 0, "pc": 0, "name": "LW", "rd": 5, "value": 0xAB},
        {"index": 1, "pc": 4, "half": 0, "name": "C.ADDI", "rd": 12,
         "value": 1},
        {"index": 1, "pc": 6, "half": 1, "name": "C.ADDI", "rd": 12,
         "value": 2},
        {"index": 2, "pc": 8, "name": "ADDI", "rd": 6, "value": 9}]


def test_parcel_trace_matches_a_hand_computed_program():
    parcels = [
        _c("C.LI", rd=12, imm=5),      # x12 = 5
        _c("C.ADDI", rd=12, imm=-2),   # x12 = 3
        _c("C.SLLI", rd=12, shamt=3),  # x12 = 24
        _c("C.MV", rd=13, rs2=12),     # x13 = 24
        _c("C.ADD", rd=14, rs2=13),    # x14 = 0 + 24
        _c("C.ANDI", rd=13, imm=28),   # x13 = 24 & 28 = 24
        _c("C.SRLI", rd=12, shamt=1),  # x12 = 12
        _c("C.XOR", rd=15, rs2=12),    # x15 = 0 ^ 12 = 12
    ]
    image = tuple(_pair(parcels[2 * index], parcels[2 * index + 1])
                  for index in range(len(parcels) // 2))
    result = _run(image)
    assert result["pc_order"] == [0, 2, 4, 6, 8, 10, 12, 14]
    assert result["trace"] == [
        (0, "C.LI", 12, 5),
        (2, "C.ADDI", 12, 3),
        (4, "C.SLLI", 12, 24),
        (6, "C.MV", 13, 24),
        (8, "C.ADD", 14, 24),
        (10, "C.ANDI", 13, 24),
        (12, "C.SRLI", 12, 12),
        (14, "C.XOR", 15, 12),
    ]
    assert result["final_registers"] == {12: 12, 13: 24, 14: 24, 15: 12}


def test_compressed_branch_targets_use_parcel_granularity():
    pair = _pair(_c("C.ADDI", rd=12, imm=1), _c("C.ADDI", rd=13, imm=1))
    # The 32-bit branch at word 0 occupies pc+0..pc+3, so pc+4 (the low parcel of
    # word 1) and pc+6 (its high parcel) are the instruction starts it can name.
    for target, expected in ((4, [0, 4, 6]), (6, [0, 6]), (8, [0])):
        image = (_c("BEQ", rs1=0, rs2=0, imm=target), pair)
        validate_compressed_program(RV32IMC, image, window_size=64,
                                    allow_branches=True)
        result = reference_run_compressed(image, registers={}, memory={},
                                          window_size=64, allow_branches=True)
        assert result["pc_order"] == expected
    # The same branch without the opt-in flag is refused.
    with pytest.raises(ValueError, match="straight-line"):
        validate_compressed_program(RV32IMC, (_c("BEQ", rs1=0, rs2=0, imm=2),
                                              pair), window_size=64)
    # A target inside a 32-bit instruction is refused, not guessed.
    with pytest.raises(ValueError, match="not an instruction start"):
        validate_compressed_program(
            RV32IMC, (_c("BEQ", rs1=0, rs2=0, imm=6),
                      _c("LW", rd=5, rs1=18, imm=0)), window_size=64,
            allow_branches=True)
    # A branch may not name its own second half either (pc+2 inside a 32-bit
    # word is not an instruction start).
    with pytest.raises(ValueError, match="not an instruction start"):
        validate_compressed_program(
            RV32IMC, (_c("BEQ", rs1=0, rs2=0, imm=2), pair), window_size=64,
            allow_branches=True)
    # A B-type offset is always even, so only structural faults remain: a
    # zero offset is not strictly forward and a target past the image is out.
    with pytest.raises(ValueError, match="not strictly forward"):
        validate_compressed_program(
            RV32IMC, (_c("BEQ", rs1=0, rs2=0, imm=0), pair),
            window_size=64, allow_branches=True)
    with pytest.raises(ValueError, match="not an instruction start"):
        validate_compressed_program(
            RV32IMC, (_c("BEQ", rs1=0, rs2=0, imm=10), pair),
            window_size=64, allow_branches=True)
    # Backward branches are refused, and the bounded interpreter still stops a
    # would-be loop when structural validation is bypassed.
    loop = (pair, _c("BEQ", rs1=0, rs2=0, imm=-4))
    with pytest.raises(ValueError, match="not strictly forward"):
        validate_compressed_program(RV32IMC, loop, window_size=64,
                                    allow_branches=True)
    with pytest.raises(ValueError, match="exceeded the 6-step bound"):
        reference_run_compressed(loop, registers={}, memory={},
                                 window_size=64, allow_branches=True,
                                 max_steps=6, validate=False)


# ---------------------------------------------------------------------------
# Generation and mutation
# ---------------------------------------------------------------------------


def test_generation_is_sound_deterministic_and_needs_c():
    for seed in range(15):
        program = generate_compressed_program(RV32IMC, seed=seed, max_words=5,
                                              min_words=3, window_size=64)
        assert program.compressed is True
        assert program.style == "compressed"
        assert 3 <= len(program.words) <= 5
        validate_compressed_program(RV32IMC, program.words, window_size=64)
        layout = image_instructions(program.words)
        assert len(layout) == 2 * len(program.words)
        assert all(entry.width == 2 for entry in layout)
        assert all(entry.name in COMPRESSED_ALU_NAMES for entry in layout)
        # The interpreter replays every parcel in PC order.
        result = _run(program.words)
        assert result["retires"] == 2 * len(program.words)
        assert result["pc_order"] == [2 * index
                                      for index in range(len(layout))]
    first = generate_compressed_program(RV32IMC, seed=4, max_words=4,
                                        window_size=64)
    again = generate_compressed_program(RV32IMC, seed=4, max_words=4,
                                       window_size=64)
    assert first.as_dict() == again.as_dict()
    with pytest.raises(ValueError, match="declares the C extension"):
        generate_compressed_program(RV32IM, seed=0, max_words=4,
                                    window_size=64)
    with pytest.raises(ValueError, match="no allocatable compressed register"):
        generate_compressed_program(RV32IMC, seed=0, max_words=4,
                                    window_size=64,
                                    reserved=(12, 13, 14, 15))


def test_generate_program_delegates_the_compressed_style():
    direct = generate_compressed_program(RV32IMC, seed=7, max_words=5,
                                        min_words=4, window_size=64)
    style = generate_program(RV32IMC, seed=7, max_words=5, min_words=4,
                             window_size=64, style="compressed",
                             allow_compressed=True)
    assert style.words == direct.words
    with pytest.raises(ValueError, match="requires allow_compressed=True"):
        generate_program(RV32IMC, seed=7, max_words=5, window_size=64,
                         style="compressed")
    # The default flags leave the classic 32-bit space untouched.
    classic = generate_program(RV32IM, seed=7, max_words=5, min_words=4,
                               window_size=64, style="chains")
    assert classic.compressed is False
    assert all(word & 3 == 3 for word in classic.words)


def test_compressed_mutation_changes_parcels_and_stays_legal():
    parent = generate_compressed_program(RV32IMC, seed=2, max_words=5,
                                         min_words=4, window_size=64)
    single_parcel_edits = 0
    for seed in range(40):
        mutated = mutate_compressed_program(RV32IMC, parent, seed=seed,
                                            max_words=5, window_size=64)
        assert mutated.style == "mutation"
        assert mutated.compressed is True
        assert mutated.words != parent.words
        validate_compressed_program(RV32IMC, mutated.words, window_size=64)
        reference_run_compressed(mutated.words, registers={}, memory={},
                                 window_size=64)
        if len(mutated.words) == len(parent.words):
            before = [split_record_word(word) for word in parent.words]
            after = [split_record_word(word) for word in mutated.words]
            halves = [(old, new) for pair_before, pair_after in zip(before, after)
                      for old, new in zip(pair_before, pair_after)
                      if old != new]
            if len(halves) == 1:
                single_parcel_edits += 1
    assert single_parcel_edits > 0
    first = mutate_compressed_program(RV32IMC, parent, seed=9, max_words=5,
                                      window_size=64)
    again = mutate_compressed_program(RV32IMC, parent, seed=9, max_words=5,
                                      window_size=64)
    assert first.as_dict() == again.as_dict()


def test_mutate_program_delegates_and_gates_compressed_images():
    parent = generate_compressed_program(RV32IMC, seed=1, max_words=4,
                                         min_words=3, window_size=64)
    with pytest.raises(ValueError, match="allow_compressed=True"):
        mutate_program(RV32IMC, parent, seed=0, max_words=4, window_size=64)
    mutated = mutate_program(RV32IMC, parent, seed=0, max_words=4,
                             window_size=64, allow_compressed=True)
    assert mutated.compressed is True
    validate_compressed_program(RV32IMC, mutated.words, window_size=64)


def test_the_compressed_program_document_names_both_parcels():
    program = generate_compressed_program(RV32IMC, seed=0, max_words=3,
                                          min_words=3, window_size=64)
    data = program.as_dict()
    assert data["compressed"] is True
    assert data["style"] == "compressed"
    assert len(data["instructions"]) == len(program.words)
    assert all("+" in item["name"] for item in data["instructions"])
    assert json.loads(json.dumps(data)) == data
    # The straight-line analysis does not decode parcels: it is the 32-bit
    # authority, and the compressed module owns the parcel-level facts.
    with pytest.raises(ValueError, match="outside the subset"):
        analyze_program(program.words)


def test_mutation_preserves_each_record_word_instruction_width():
    image = (_c("LW", rd=5, rs1=18, imm=0),
             _pair(_c("C.ADDI", rd=12, imm=1), _c("C.ADDI", rd=13, imm=1)),
             _c("ADDI", rd=6, rs1=0, imm=9),
             _pair(_c("C.SLLI", rd=12, shamt=3),
                   _c("C.SRLI", rd=13, shamt=2)))
    assert [entry.width for entry in image_instructions(image)] == \
        [4, 2, 2, 4, 2, 2]
    program = ShortProgram(RV32IMC, 0, 4, image, ())
    for seed in range(40):
        mutated = mutate_compressed_program(RV32IMC, program, seed=seed,
                                            max_words=4, window_size=64)
        validate_compressed_program(RV32IMC, mutated.words, window_size=64)
        if len(mutated.words) == len(image):
            # The main actions keep the width of the word they replace, so the
            # instruction-start map (and a branch target at pc+2) is unchanged.
            for before, after in zip(image, mutated.words):
                assert (before & 3 == 3) == (after & 3 == 3)


def test_branch_bearing_compressed_images_mutate_in_place():
    image = (_c("BEQ", rs1=0, rs2=0, imm=8),
             _pair(_c("C.ADDI", rd=12, imm=1), _c("C.ADDI", rd=13, imm=1)),
             _c("ADDI", rd=6, rs1=0, imm=9))
    program = ShortProgram(RV32IMC, 0, 3, image, ())
    targets = set()
    for seed in range(40):
        mutated = mutate_compressed_program(RV32IMC, program, seed=seed,
                                            max_words=3, window_size=64,
                                            allow_branches=True)
        assert len(mutated.words) == len(image)
        validate_compressed_program(RV32IMC, mutated.words, window_size=64,
                                    allow_branches=True)
        layout = image_instructions(mutated.words)
        starts = {entry.pc_offset for entry in layout}
        for entry in layout:
            if entry.width != 4 or entry.name not in (
                    "BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU"):
                continue
            target = entry.pc_offset + entry.operands["imm"]
            assert target == 4 * len(mutated.words) or target in starts
            assert target > entry.pc_offset
            targets.add(target)
        reference_run_compressed(mutated.words, registers={}, memory={},
                                 window_size=64, allow_branches=True)
    assert len(targets) > 1
