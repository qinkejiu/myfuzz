"""Byte/halfword F1 data-window programs: generation, gate, model and end-to-end.

The host and the unified entry still admit only ``LW``/``SW`` until the
integration patch in ``docs/patches/subword-host-integration.md`` lands.  The
tests that exercise the legacy gate therefore assert its current refusal by
name (``not LW`` / ``not SW``); they are the documented "pending integration"
contract, not a claim that the host can execute a subword word today.
"""

import pytest

from myfuzz.fuzz.rv32_program import (
    generate_program, reference_run, validate_program_words,
)
from myfuzz.fuzz.rv32_subword import (
    LOAD_NAMES, STORE_NAMES, generate_subword_program, mutate_subword_program,
    reference_run_subword, subword_access, validate_subword_program,
)
from myfuzz.fuzz.strategy import FuzzStrategy
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32IM = RiscvProfile(32, frozenset(("I", "M")), 4, 32, 0)
RV32E = RiscvProfile(32, frozenset(("I",)), 4, 16, 0)
WINDOW = 64
BASE = 0x1000


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def memory_word(name, *, base=18, target=1, offset=0):
    """Encode a load/store with the natural operand name for its family."""
    if name in LOAD_NAMES:
        return word(name, rd=target, rs1=base, imm=offset)
    return word(name, rs2=target, rs1=base, imm=offset)


_LOAD_FUNCT3 = {"LB": 0, "LH": 1, "LW": 2, "LBU": 4, "LHU": 5}
_STORE_FUNCT3 = {"SB": 0, "SH": 1, "SW": 2}


def raw_load(name, *, base=18, target=1, offset=0):
    """Build a load word without the encoder's natural-alignment refusal."""
    raw = offset & 0xFFF
    return (((raw << 20) | (base << 15) | (_LOAD_FUNCT3[name] << 12)
             | (target << 7) | 0x03))


def raw_store(name, *, base=18, target=1, offset=0):
    """Build a store word without the encoder's natural-alignment refusal."""
    raw = offset & 0xFFF
    return ((((raw >> 5) & 0x7F) << 25 | (target << 20) | (base << 15)
             | (_STORE_FUNCT3[name] << 12) | ((raw & 0x1F) << 7) | 0x23))


def raw_memory(name, *, base=18, target=1, offset=0):
    return (raw_load if name in LOAD_NAMES else raw_store)(
        name, base=base, target=target, offset=offset)


def accesses(words):
    return [subword_access(item) for item in words
            if item & 0x7F in (0x03, 0x23)]


# ---------------------------------------------------------------------------
# Decoding: the single authority the entry gate and the host patch share.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,operands,expected", [
    ("LB", dict(rd=3, rs1=18, imm=7), ("LB", 1, True, 18, 3, 7)),
    ("LH", dict(rd=4, rs1=18, imm=6), ("LH", 2, True, 18, 4, 6)),
    ("LW", dict(rd=5, rs1=18, imm=4), ("LW", 4, False, 18, 5, 4)),
    ("LBU", dict(rd=6, rs1=18, imm=1), ("LBU", 1, False, 18, 6, 1)),
    ("LHU", dict(rd=7, rs1=18, imm=2), ("LHU", 2, False, 18, 7, 2)),
    ("SB", dict(rs2=3, rs1=18, imm=1), ("SB", 1, False, 18, 3, 1)),
    ("SH", dict(rs2=4, rs1=18, imm=2), ("SH", 2, False, 18, 4, 2)),
    ("SW", dict(rs2=5, rs1=18, imm=4), ("SW", 4, False, 18, 5, 4)),
])
def test_subword_access_decodes_every_width_and_sign(name, operands, expected):
    assert subword_access(word(name, **operands)) == expected


def test_subword_access_returns_none_for_non_memory_and_names_a_bad_funct3():
    assert subword_access(word("ADDI", rd=1, rs1=0, imm=1)) is None
    with pytest.raises(ValueError, match="memory funct3 3 is not LB/LH/LW/LBU/LHU"):
        subword_access((3 << 12) | (18 << 15) | (1 << 7) | 0x03)
    with pytest.raises(ValueError, match="memory funct3 6 is not SB/SH/SW"):
        subword_access((6 << 12) | (18 << 15) | (1 << 20) | 0x23)
    with pytest.raises(ValueError, match="not a 32-bit unsigned word"):
        subword_access("LB")


def test_subword_access_negative_store_offset_is_sign_extended():
    access = subword_access(word("SB", rs2=1, rs1=18, imm=-1))
    assert access == ("SB", 1, False, 18, 1, -1)


# ---------------------------------------------------------------------------
# Admission: widths, alignment, window, base and reserved registers.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,offset", [
    ("LB", 63), ("LBU", 63), ("LH", 62), ("LHU", 62), ("LW", 60),
    ("SB", 63), ("SH", 62), ("SW", 60),
])
def test_validator_accepts_every_width_at_its_window_edge(name, offset):
    validate_subword_program(RV32IM, (memory_word(name, offset=offset),),
                             window_size=WINDOW)


@pytest.mark.parametrize("name,offset", [
    ("LH", 1), ("LH", 61), ("LHU", 1), ("LHU", 61),
    ("LW", 1), ("LW", 2), ("LW", 62),
    ("SH", 1), ("SH", 61), ("SW", 1), ("SW", 2), ("SW", 62),
])
def test_validator_refuses_misaligned_half_and_word_offsets(name, offset):
    with pytest.raises(ValueError, match="not [124]-byte aligned"):
        validate_subword_program(RV32IM, (raw_memory(name, offset=offset),),
                                 window_size=WINDOW)


@pytest.mark.parametrize("name,offset", [
    ("LB", 64), ("LBU", 64), ("LH", 64), ("LHU", 64), ("LW", 64),
    ("SB", 64), ("SH", 64), ("SW", 64),
])
def test_validator_refuses_an_access_that_leaves_the_window(name, offset):
    with pytest.raises(ValueError, match="leaves the declared data window"):
        validate_subword_program(RV32IM, (raw_memory(name, offset=offset),),
                                 window_size=WINDOW)


@pytest.mark.parametrize("name,offset", [
    ("LB", -1), ("LBU", -1), ("LH", -2), ("LHU", -2), ("LW", -4),
    ("SB", -1), ("SH", -2), ("SW", -4),
])
def test_validator_refuses_a_negative_offset(name, offset):
    with pytest.raises(ValueError, match="leaves the declared data window"):
        validate_subword_program(
            RV32IM, (raw_memory(name, offset=offset),), window_size=WINDOW)


@pytest.mark.parametrize("name", ["LB", "LH", "LW", "LBU", "LHU", "SB", "SH", "SW"])
def test_validator_refuses_a_base_other_than_x18(name):
    with pytest.raises(ValueError, match="must use x18 as its base"):
        validate_subword_program(RV32IM, (memory_word(name, base=5),),
                                 window_size=WINDOW)


@pytest.mark.parametrize("register", [8, 9, 18])
@pytest.mark.parametrize("name", ["LB", "LH", "LW", "LBU", "LHU"])
def test_validator_refuses_a_load_that_writes_a_reserved_register(name, register):
    with pytest.raises(ValueError, match="writes the reserved"):
        validate_subword_program(
            RV32IM, (memory_word(name, target=register),), window_size=WINDOW)


@pytest.mark.parametrize("register", [8, 9, 18])
@pytest.mark.parametrize("name", ["SB", "SH", "SW"])
def test_validator_allows_a_store_to_use_a_reserved_register_as_data(name, register):
    validate_subword_program(
        RV32IM, (memory_word(name, target=register),), window_size=WINDOW)


@pytest.mark.parametrize("register,label", [
    (8, "mailbox register x8"),
    (9, "slot base register x9"),
    (18, "data-window base register x18"),
])
def test_validator_delegates_non_memory_reserved_writes_to_the_legacy_gate(
        register, label):
    with pytest.raises(ValueError, match=label):
        validate_subword_program(
            RV32IM, (word("ADDI", rd=register, rs1=0, imm=1),),
            window_size=WINDOW)


@pytest.mark.parametrize("name,operands", [
    ("BEQ", dict(rs1=0, rs2=0, imm=8)),
    ("JAL", dict(rd=0, imm=8)),
    ("CSRRW", dict(rd=1, rs1=2, csr=0x300)),
])
def test_validator_refuses_control_flow_and_system_words(name, operands):
    with pytest.raises(ValueError, match="control-flow"):
        validate_subword_program(RV32IM, (word(name, **operands),),
                                 window_size=WINDOW)


def test_validator_refuses_an_empty_or_non_sequence_program():
    with pytest.raises(ValueError, match="no instruction"):
        validate_subword_program(RV32IM, (), window_size=WINDOW)
    with pytest.raises(ValueError, match="sequence"):
        validate_subword_program(RV32IM, "LB", window_size=WINDOW)
    with pytest.raises(ValueError, match="not a 32-bit unsigned word"):
        validate_subword_program(RV32IM, (0x1_0000_0000,), window_size=WINDOW)


def test_validator_refuses_a_memory_word_on_a_profile_without_x18():
    with pytest.raises(ValueError, match="x18 does not exist"):
        validate_subword_program(RV32E, (memory_word("LB"),), window_size=WINDOW)


def test_validator_names_the_real_index_of_the_failing_memory_word():
    words = (word("ADDI", rd=1, rs1=0, imm=1),
             word("SB", rs2=1, rs1=18, imm=0),
             raw_load("LH", target=2, offset=1))
    with pytest.raises(ValueError, match="instruction 2 LH offset 1"):
        validate_subword_program(RV32IM, words, window_size=WINDOW)


# ---------------------------------------------------------------------------
# Generation: determinism, legality and width coverage.
# ---------------------------------------------------------------------------

def test_generator_is_deterministic_for_a_seed():
    first = generate_subword_program(RV32IM, seed=1234, max_words=8,
                                     window_size=WINDOW)
    second = generate_subword_program(RV32IM, seed=1234, max_words=8,
                                      window_size=WINDOW)
    assert first == second
    assert first != generate_subword_program(RV32IM, seed=1235, max_words=8,
                                             window_size=WINDOW)


def test_generator_returns_legal_programs_for_hundreds_of_seeds():
    for seed in range(300):
        words = generate_subword_program(RV32IM, seed=seed, max_words=8,
                                         window_size=WINDOW)
        assert 1 <= len(words) <= 8
        validate_subword_program(RV32IM, words, window_size=WINDOW)
        for item in words:
            assert type(item) is int and 0 <= item <= 0xFFFFFFFF
        for name, size, _signed, base, target, offset in accesses(words):
            assert base == 18
            assert offset % size == 0
            assert 0 <= offset <= WINDOW - size
            if name in LOAD_NAMES:
                assert target not in (8, 9, 18)


def test_generator_covers_byte_half_and_word_widths_across_seeds():
    seen = set()
    for seed in range(300):
        words = generate_subword_program(RV32IM, seed=seed, max_words=8,
                                         window_size=WINDOW)
        for item in words:
            if item & 0x7F in (0x03, 0x23):
                seen.add((item & 0x7F, (item >> 12) & 7))
    assert seen >= {(0x03, 0), (0x03, 1), (0x03, 2), (0x03, 4), (0x03, 5),
                    (0x23, 0), (0x23, 1), (0x23, 2)}
    names = set()
    for seed in range(300):
        names.update(name for name, *_ in
                     accesses(generate_subword_program(
                         RV32IM, seed=seed, max_words=8, window_size=WINDOW)))
    assert {"LB", "LH", "LW", "LBU", "LHU", "SB", "SH", "SW"} <= names


def test_generator_only_rewrites_the_base_program_memory_words():
    for seed in range(50):
        base = generate_program(RV32IM, seed=seed, max_words=8,
                                window_size=WINDOW, allow_auipc=False)
        subword = generate_subword_program(RV32IM, seed=seed, max_words=8,
                                           window_size=WINDOW)
        assert len(base.words) == len(subword)
        for original, generated in zip(base.words, subword):
            if original & 0x7F in (0x03, 0x23):
                assert generated & 0x7F in (0x03, 0x23)
            else:
                assert generated == original


def test_generator_offsets_stay_inside_the_signed_immediate():
    for seed in range(200):
        for name, _size, _signed, _base, _target, offset in accesses(
                generate_subword_program(RV32IM, seed=seed, max_words=16,
                                         window_size=4096)):
            assert -2048 <= offset <= 2047


# ---------------------------------------------------------------------------
# Mutation: exactly one memory operation, still legal.
# ---------------------------------------------------------------------------

MIXED = (word("ADDI", rd=5, rs1=0, imm=1),
         word("SB", rs2=5, rs1=18, imm=0),
         word("LH", rd=6, rs1=18, imm=2),
         word("SW", rs2=6, rs1=18, imm=4),
         word("LBU", rd=7, rs1=18, imm=1))


def test_mutation_changes_exactly_one_memory_operation():
    for seed in range(64):
        changed = mutate_subword_program(RV32IM, MIXED, seed=seed,
                                         window_size=WINDOW)
        validate_subword_program(RV32IM, changed, window_size=WINDOW)
        differing = [index for index, (left, right)
                     in enumerate(zip(MIXED, changed)) if left != right]
        assert len(differing) == 1
        index = differing[0]
        assert MIXED[index] & 0x7F in (0x03, 0x23)
        before = subword_access(MIXED[index])
        after = subword_access(changed[index])
        assert before[3:5] == after[3:5]  # same base and rd/rs2
        assert before[0] != after[0]  # the width (and sign) changed


def test_mutation_is_deterministic_and_varies_with_the_seed():
    first = mutate_subword_program(RV32IM, MIXED, seed=9, window_size=WINDOW)
    assert first == mutate_subword_program(RV32IM, MIXED, seed=9,
                                           window_size=WINDOW)
    variants = {mutate_subword_program(RV32IM, MIXED, seed=seed,
                                       window_size=WINDOW)
                for seed in range(16)}
    assert len(variants) > 4


def test_mutation_refuses_a_program_without_memory_operations():
    with pytest.raises(ValueError, match="no memory operation"):
        mutate_subword_program(RV32IM, (word("ADDI", rd=1, rs1=0, imm=1),),
                               seed=1, window_size=WINDOW)


def test_mutation_refuses_an_illegal_input():
    with pytest.raises(ValueError, match="leaves the declared data window"):
        mutate_subword_program(RV32IM, (word("LB", rd=1, rs1=18, imm=64),),
                               seed=1, window_size=WINDOW)


# ---------------------------------------------------------------------------
# Reference model: sign extension, little-endian lanes, partial stores.
# ---------------------------------------------------------------------------

def test_reference_run_subword_preserves_other_lanes_and_sign_extends():
    words = (word("SB", rs1=18, rs2=1, imm=1),
             word("LB", rd=2, rs1=18, imm=1),
             word("LBU", rd=3, rs1=18, imm=1),
             word("SH", rs1=18, rs2=4, imm=2),
             word("LH", rd=5, rs1=18, imm=2),
             word("LHU", rd=6, rs1=18, imm=2),
             word("LW", rd=7, rs1=18, imm=0))
    result = reference_run_subword(words, registers={18: BASE, 1: 0x80,
                                                     4: 0x8001},
                                   memory={BASE: 0xAABBCCDD},
                                   window_size=4)
    assert result["final_registers"][2] == 0xFFFFFF80
    assert result["final_registers"][3] == 0x80
    assert result["final_registers"][5] == 0xFFFF8001
    assert result["final_registers"][6] == 0x8001
    assert result["final_registers"][7] == 0x800180DD
    assert result["memory_changes"] == {BASE: 0x800180DD}


@pytest.mark.parametrize("name,offset,stored,expected", [
    ("SB", 0, 0x11223344, 0xAABBCC44),
    ("SB", 1, 0x11223344, 0xAABB44DD),
    ("SB", 3, 0x11223344, 0x44BBCCDD),
    ("SH", 0, 0x11223344, 0xAABB3344),
    ("SH", 2, 0x11223344, 0x3344CCDD),
    ("SW", 0, 0x11223344, 0x11223344),
])
def test_reference_run_subword_partial_store_preserves_other_lanes(
        name, offset, stored, expected):
    words = (word(name, rs1=18, rs2=1, imm=offset),)
    result = reference_run_subword(words, registers={18: BASE, 1: stored},
                                   memory={BASE: 0xAABBCCDD},
                                   window_size=4)
    assert result["memory_changes"] == {BASE: expected}


@pytest.mark.parametrize("name,offset", [
    ("LB", 0), ("LB", 3), ("LBU", 0), ("LBU", 3),
    ("LH", 0), ("LH", 2), ("LHU", 0), ("LHU", 2),
    ("LW", 0),
])
def test_reference_run_subword_store_then_load_roundtrip(name, offset):
    store = {"LB": "SB", "LBU": "SB", "LH": "SH", "LHU": "SH",
             "LW": "SW"}[name]
    load = name
    words = (word(store, rs1=18, rs2=1, imm=offset),
             word(load, rd=2, rs1=18, imm=offset))
    result = reference_run_subword(words, registers={18: BASE, 1: 0xDEADBEEF},
                                   memory={BASE: 0},
                                   window_size=4)
    size = subword_access(words[0])[1]
    mask = (1 << (8 * size)) - 1
    value = 0xDEADBEEF & mask
    if load in ("LB", "LH"):
        expected = value - (1 << (8 * size)) if value >> (8 * size - 1) else value
        expected &= 0xFFFFFFFF
    else:
        expected = value
    assert result["final_registers"][2] == expected
    assert result["memory_changes"] == {BASE: value << (8 * offset)}


def test_reference_run_subword_mixes_alu_and_memory_words():
    words = (word("LUI", rd=1, imm=0x12345),
             word("ADDI", rd=1, rs1=1, imm=0x67),
             word("SB", rs1=18, rs2=1, imm=1),
             word("LBU", rd=2, rs1=18, imm=1))
    result = reference_run_subword(words, registers={18: BASE},
                                   memory={BASE: 0x00},
                                   window_size=4)
    assert result["final_registers"][1] == 0x12345067
    assert result["final_registers"][2] == 0x67
    assert result["retires"] == 4
    assert [write["index"] for write in result["register_writes"]] == [0, 1, 3]


def test_reference_run_subword_ignores_x0_and_reports_only_changed_words():
    words = (word("LB", rd=0, rs1=18, imm=0),
             word("SB", rs1=18, rs2=0, imm=0))
    result = reference_run_subword(words, registers={18: BASE},
                                   memory={BASE: 0x12345678},
                                   window_size=4)
    assert result["retires"] == 2
    assert 0 not in result["final_registers"]
    assert result["register_writes"] == []
    assert result["memory_changes"] == {BASE: 0x12345600}


def test_reference_run_subword_refuses_an_illegal_program():
    with pytest.raises(ValueError, match="not 2-byte aligned"):
        reference_run_subword((raw_load("LH", offset=1),),
                              registers={18: BASE}, memory={}, window_size=4)
    with pytest.raises(ValueError, match="leaves the declared data window"):
        reference_run_subword((raw_load("LB", offset=4),),
                              registers={18: BASE}, memory={}, window_size=4)


# ---------------------------------------------------------------------------
# Strategy opt-in and the current legacy host gate.
# ---------------------------------------------------------------------------

def test_strategy_can_opt_in_to_subword_generation_and_mutation():
    def gate(flow, fields):
        validate_subword_program(RV32IM, fields, window_size=WINDOW)
        return flow + ":" + ":".join(f"{item:08x}" for item in fields), "CASE F1"

    strategy = FuzzStrategy(flows=("F1",), gate=gate, program_profile=RV32IM,
                            f1_words=8, program_window=WINDOW, seed=17,
                            f1_subword=True)
    seen = False
    for _ in range(100):
        item = strategy.fresh("F1")
        validate_subword_program(RV32IM, item.fields, window_size=WINDOW)
        if any((field & 0x7F) in (3, 35) and ((field >> 12) & 7) != 2
               for field in item.fields):
            child = strategy.mutate(item)
            validate_subword_program(RV32IM, child.fields, window_size=WINDOW)
            assert child.fields != item.fields
            seen = True
            break
    assert seen


def test_strategy_without_the_opt_in_never_emits_a_subword_word():
    def gate(flow, fields):
        validate_program_words(RV32IM, fields, window_size=WINDOW)
        return flow, "CASE F1"

    strategy = FuzzStrategy(flows=("F1",), gate=gate, program_profile=RV32IM,
                            f1_words=8, program_window=WINDOW, seed=17)
    for _ in range(100):
        item = strategy.fresh("F1")
        assert all((field & 0x7F) not in (3, 35)
                   or ((field >> 12) & 7) == 2 for field in item.fields)


def test_legacy_host_gate_still_refuses_subword_pending_integration():
    """Documents the current C++/entry rule; the integration patch changes it."""
    with pytest.raises(ValueError, match="not LW; only LW is emittable"):
        validate_program_words(RV32IM, (word("LB", rd=1, rs1=18, imm=0),),
                               window_size=WINDOW)
    with pytest.raises(ValueError, match="not SW; only SW is emittable"):
        validate_program_words(RV32IM, (word("SH", rs2=1, rs1=18, imm=0),),
                               window_size=WINDOW)
    # The legacy gate is still the strategy's default gate, so an opt-in
    # strategy with the old gate degrades to LW/SW-only programs.
    def legacy_gate(flow, fields):
        validate_program_words(RV32IM, fields, window_size=WINDOW)
        return flow, "CASE F1"

    strategy = FuzzStrategy(flows=("F1",), gate=legacy_gate,
                            program_profile=RV32IM, f1_words=8,
                            program_window=WINDOW, seed=17,
                            f1_subword=True, max_attempts=32)
    for _ in range(100):
        item = strategy.fresh("F1")
        assert all((field & 0x7F) not in (3, 35)
                   or ((field >> 12) & 7) == 2 for field in item.fields)


# ---------------------------------------------------------------------------
# Synthetic end-to-end: a byte-addressed RAM independent of the reference model.
# ---------------------------------------------------------------------------

class ByteRam:
    """A tiny little-endian byte-addressed RAM used only by these tests."""

    def __init__(self, base, words):
        self.base = base
        self.bytes = {}
        for address, value in words.items():
            self.write(address, 4, value)

    def write(self, address, size, value):
        for lane in range(size):
            self.bytes[address + lane] = (value >> (8 * lane)) & 0xFF

    def read(self, address, size):
        return sum(self.bytes.get(address + lane, 0) << (8 * lane)
                   for lane in range(size))

    def word(self, address):
        return self.read(address, 4)


def _run_byte_model(words, registers, ram, *, window_size, data_base=0):
    """Execute the program at byte granularity, using the model only for ALU."""
    state = dict(registers)
    state[0] = 0
    for index, item in enumerate(words):
        access = subword_access(item)
        if access is None:
            step = reference_run((item,), registers=state, memory={},
                                 data_base=(data_base + 4 * index) & 0xFFFFFFFF,
                                 window_size=window_size)
            state = dict(step["final_registers"])
            state[0] = 0
            continue
        name, size, signed, base, target, offset = access
        address = (state.get(base, 0) + offset) & 0xFFFFFFFF
        assert address % size == 0
        if name in STORE_NAMES:
            ram.write(address, size, state.get(target, 0) & ((1 << (8 * size)) - 1))
        else:
            value = ram.read(address, size)
            if signed and value & (1 << (8 * size - 1)):
                value = (value - (1 << (8 * size))) & 0xFFFFFFFF
            state[target] = value
    return state


def test_synthetic_byte_ram_end_to_end():
    words = (word("LUI", rd=1, imm=0x11223),
             word("ADDI", rd=1, rs1=1, imm=0x344),
             word("SB", rs1=18, rs2=1, imm=1),
             word("SH", rs1=18, rs2=1, imm=2),
             word("SW", rs1=18, rs2=1, imm=4),
             word("LB", rd=2, rs1=18, imm=1),
             word("LBU", rd=3, rs1=18, imm=5),
             word("LH", rd=4, rs1=18, imm=2),
             word("LHU", rd=5, rs1=18, imm=6),
             word("LW", rd=6, rs1=18, imm=4),
             word("SB", rs1=18, rs2=1, imm=0),
             word("SH", rs1=18, rs2=1, imm=6))
    initial = {BASE: 0xAAAAAAAA}
    reference = reference_run_subword(words, registers={18: BASE},
                                      memory=initial, window_size=8)
    ram = ByteRam(BASE, initial)
    state = _run_byte_model(words, {18: BASE}, ram, window_size=8)
    assert reference["retires"] == len(words)
    assert reference["final_registers"] == {reg: value for reg, value
                                            in state.items() if reg and value}
    assert reference["memory_changes"] == {BASE: 0x33444444,
                                          BASE + 4: 0x33443344}
    assert ram.word(BASE) == 0x33444444
    assert ram.word(BASE + 4) == 0x33443344
    assert [ram.bytes[BASE + lane] for lane in range(8)] == [
        0x44, 0x44, 0x44, 0x33, 0x44, 0x33, 0x44, 0x33]


def test_synthetic_generated_program_matches_the_byte_ram_model():
    initial = {BASE: 0xA1B2C3D4, BASE + 4: 0x01020304,
               BASE + 8: 0xDEADBEEF, BASE + 12: 0x5A5A5A5A}
    for seed in range(40):
        words = generate_subword_program(RV32IM, seed=seed, max_words=12,
                                         window_size=16)
        reference = reference_run_subword(words, registers={18: BASE},
                                          memory=initial, window_size=16)
        ram = ByteRam(BASE, initial)
        state = _run_byte_model(words, {18: BASE}, ram, window_size=16)
        assert reference["final_registers"] == {
            reg: value for reg, value in state.items() if reg and value}
        assert reference["memory_changes"] == {
            address: ram.word(address) for address in initial
            if ram.word(address) != initial[address]}
