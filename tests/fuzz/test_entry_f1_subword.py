"""Proposed entry-gate contract for subword F1 programs (integration patch).

This file is deliberately **not** an entry test: it does not import the
unified entry, the executor or the C++ host.  It defines a local
``validate_subword_program`` -- the exact gate the integration patch should add
to the entry -- and pins the refusal messages that gate must produce, so the
patch can be reviewed against a stable contract.

The proposed gate delegates non-memory words to the shared
``rv32_program.validate_program_words`` authority and decodes memory words with
``rv32_subword.subword_access``.  That is the same split the module already
uses, so the entry only has to choose it when ``f1_subword`` is true; the
message prefixes below are the entry's own ("F1 program ...").

The integration patch is described in
``docs/patches/subword-host-integration.md``.
"""

import ast
from pathlib import Path

import pytest

from myfuzz.fuzz.rv32_program import validate_program_words
from myfuzz.fuzz.rv32_subword import (
    LOAD_NAMES, STORE_NAMES, generate_subword_program, subword_access,
    validate_subword_program as validate_module_subword,
)
from myfuzz.riscv.encoding import encode
from myfuzz.riscv.profile import RiscvProfile

RV32IM = RiscvProfile(32, frozenset(("I", "M")), 4, 32, 0)
RV32E = RiscvProfile(32, frozenset(("I",)), 4, 16, 0)
WINDOW = 64
_PLACEHOLDER = 0x00000013
_LOAD_FUNCT3 = {"LB": 0, "LH": 1, "LW": 2, "LBU": 4, "LHU": 5}
_STORE_FUNCT3 = {"SB": 0, "SH": 1, "SW": 2}


def word(name, **operands):
    return encode(name, xlen=32, **operands)


def raw_load(name, *, base=18, target=1, offset=0):
    raw = offset & 0xFFF
    return ((raw << 20) | (base << 15) | (_LOAD_FUNCT3[name] << 12)
            | (target << 7) | 0x03)


def raw_store(name, *, base=18, target=1, offset=0):
    raw = offset & 0xFFF
    return ((((raw >> 5) & 0x7F) << 25) | (target << 20) | (base << 15)
            | (_STORE_FUNCT3[name] << 12) | ((raw & 0x1F) << 7) | 0x23)


def raw_memory(name, *, base=18, target=1, offset=0):
    return (raw_load if name in LOAD_NAMES else raw_store)(
        name, base=base, target=target, offset=offset)


def memory_word(name, *, base=18, target=1, offset=0):
    if name in LOAD_NAMES:
        return word(name, rd=target, rs1=base, imm=offset)
    return word(name, rs2=target, rs1=base, imm=offset)


def validate_subword_program(profile, words, *, window_size):
    """The proposed entry gate: local contract, not the real entry.

    Rules mirror ``myfuzz.fuzz.rv32_subword.validate_subword_program`` and the
    messages are the entry-facing ones.  Non-memory words are checked by the
    shared validator at their real indices (memory words are replaced by a
    legal no-op so indices do not shift).
    """
    words = tuple(words)
    if not words:
        raise ValueError("F1 program has no instruction")
    masked = []
    memory_indices = []
    for index, item in enumerate(words):
        if type(item) is not int or not 0 <= item <= 0xFFFFFFFF:
            raise ValueError(
                f"F1 program instruction {index} is not one 32-bit word")
        if item & 0x7F in (0x03, 0x23):
            masked.append(_PLACEHOLDER)
            memory_indices.append(index)
        else:
            masked.append(item)
    try:
        validate_program_words(profile, tuple(masked), window_size=window_size)
    except ValueError as error:
        message = str(error)
        if message.startswith("instruction "):
            message = "F1 program " + message
        raise ValueError(message) from None
    for index in memory_indices:
        try:
            name, size, _signed, base, target, offset = subword_access(
                words[index])
        except ValueError as error:
            raise ValueError(
                f"F1 program memory word {index} {error}") from None
        if base != 18:
            raise ValueError(
                f"F1 program memory word {index} must use x18 as its base")
        if base >= profile.register_count:
            raise ValueError(
                f"F1 program memory word {index} is not legal for this "
                "profile: x18 does not exist")
        field = "rd" if name in LOAD_NAMES else "rs2"
        if target >= profile.register_count:
            raise ValueError(
                f"F1 program memory word {index} is not legal for this "
                f"profile: {field} x{target} does not exist")
        if name in LOAD_NAMES and target in (8, 9, 18):
            raise ValueError(
                f"F1 program load {index} may not overwrite x8, x9 or x18")
        if offset % size:
            raise ValueError(
                f"F1 program memory word {index} offset {offset} is not "
                f"{size}-byte aligned")
        if offset < 0 or offset + size > window_size:
            raise ValueError(
                f"F1 program memory word {index} memory access leaves the "
                f"declared data window (offset {offset}, size {size})")


def validate_record(fields, *, f1_subword):
    """The proposed ``validate_record`` branch: the flag selects the gate."""
    words = tuple(fields)
    if not f1_subword:
        for index, item in enumerate(words):
            if item & 0x7F in (0x03, 0x23) and ((item >> 12) & 7) != 2:
                raise ValueError(
                    f"F1 program memory word {index} is not LW or SW")
        try:
            validate_program_words(RV32IM, words, window_size=WINDOW)
        except ValueError as error:
            message = str(error)
            if message.startswith("instruction "):
                message = "F1 program " + message
            raise ValueError(message) from None
        return words
    validate_subword_program(RV32IM, words, window_size=WINDOW)
    return words


# ---------------------------------------------------------------------------
# The contract is local: no entry, executor or host import.
# ---------------------------------------------------------------------------

def test_the_contract_does_not_import_the_entry_or_the_host():
    tree = ast.parse(Path(__file__).read_text())
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert imported
    assert all(not name.startswith("scripts") for name in imported)
    assert all("inprocess_obi_apb" not in name for name in imported)


# ---------------------------------------------------------------------------
# Acceptance.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,offset", [
    ("LB", 63), ("LBU", 63), ("LH", 62), ("LHU", 62), ("LW", 60),
    ("SB", 63), ("SH", 62), ("SW", 60),
])
def test_proposed_gate_accepts_every_width_at_its_window_edge(name, offset):
    assert validate_record((memory_word(name, offset=offset),),
                           f1_subword=True) == (
        memory_word(name, offset=offset),)


def test_proposed_gate_accepts_a_mixed_sign_extension_program():
    words = (word("LUI", rd=1, imm=0x11223),
             word("ADDI", rd=1, rs1=1, imm=0x344),
             word("SB", rs1=18, rs2=1, imm=1),
             word("SH", rs1=18, rs2=1, imm=2),
             word("SW", rs1=18, rs2=1, imm=4),
             word("LB", rd=2, rs1=18, imm=1),
             word("LBU", rd=3, rs1=18, imm=1),
             word("LH", rd=4, rs1=18, imm=2),
             word("LHU", rd=5, rs1=18, imm=2),
             word("LW", rd=6, rs1=18, imm=4))
    assert validate_record(words, f1_subword=True) == words


# ---------------------------------------------------------------------------
# Refusal messages the patch must produce.
# ---------------------------------------------------------------------------

def test_proposed_gate_names_a_bad_funct3():
    words = (word("ADDI", rd=1, rs1=0, imm=1),
             (3 << 12) | (18 << 15) | (1 << 7) | 0x03)
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 1 memory funct3 3 is not "
                  r"LB/LH/LW/LBU/LHU"):
        validate_record(words, f1_subword=True)
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 0 memory funct3 3 is not SB/SH/SW"):
        validate_record(((3 << 12) | (18 << 15) | (1 << 20) | 0x23,),
                        f1_subword=True)


def test_proposed_gate_refuses_a_base_other_than_x18():
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 0 must use x18 as its base"):
        validate_record((memory_word("LB", base=5),), f1_subword=True)
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 1 must use x18 as its base"):
        validate_record((word("ADDI", rd=1, rs1=0, imm=1),
                         memory_word("SH", base=19)), f1_subword=True)


@pytest.mark.parametrize("name,offset", [
    ("LH", 1), ("LHU", 1), ("LW", 2), ("SH", 1), ("SW", 2),
])
def test_proposed_gate_refuses_misaligned_half_and_word_offsets(name, offset):
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 0 offset \d+ is not [124]-byte "
                  r"aligned"):
        validate_record((raw_memory(name, offset=offset),), f1_subword=True)


@pytest.mark.parametrize("name,offset", [
    ("LB", 64), ("LH", 64), ("LW", 64), ("SB", 64), ("SH", 64), ("SW", 64),
])
def test_proposed_gate_refuses_an_access_that_leaves_the_window(name, offset):
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 0 memory access leaves the declared "
                  r"data window"):
        validate_record((raw_memory(name, offset=offset),), f1_subword=True)


@pytest.mark.parametrize("register", [8, 9, 18])
@pytest.mark.parametrize("name", ["LB", "LH", "LW", "LBU", "LHU"])
def test_proposed_gate_refuses_a_load_that_writes_a_reserved_register(
        name, register):
    with pytest.raises(
            ValueError,
            match=r"F1 program load 0 may not overwrite x8, x9 or x18"):
        validate_record((memory_word(name, target=register),),
                        f1_subword=True)


@pytest.mark.parametrize("register", [8, 9, 18])
@pytest.mark.parametrize("name", ["SB", "SH", "SW"])
def test_proposed_gate_allows_a_store_to_use_a_reserved_register(
        name, register):
    words = (memory_word(name, target=register),)
    assert validate_record(words, f1_subword=True) == words


def test_proposed_gate_prefixes_the_shared_non_memory_refusals():
    with pytest.raises(
            ValueError,
            match=r"F1 program instruction 0 writes the reserved mailbox "
                  r"register x8"):
        validate_record((word("ADDI", rd=8, rs1=0, imm=1),), f1_subword=True)
    with pytest.raises(
            ValueError,
            match=r"F1 program instruction 1 is a control-flow or system"):
        validate_record((word("ADDI", rd=1, rs1=0, imm=1),
                         word("BEQ", rs1=0, rs2=0, imm=8)), f1_subword=True)


def test_proposed_gate_refuses_an_rv32e_profile():
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 0 is not legal for this profile: "
                  r"x18 does not exist"):
        validate_subword_program(RV32E, (memory_word("LB"),),
                                 window_size=WINDOW)


def test_proposed_gate_names_the_real_index_of_a_failing_word():
    words = (word("ADDI", rd=1, rs1=0, imm=1),
             word("SB", rs2=1, rs1=18, imm=0),
             raw_load("LH", target=2, offset=1))
    with pytest.raises(
            ValueError,
            match=r"F1 program memory word 2 offset 1 is not 2-byte aligned"):
        validate_record(words, f1_subword=True)


# ---------------------------------------------------------------------------
# The opt-in flag and the legacy refusal it must keep when off.
# ---------------------------------------------------------------------------

def test_the_legacy_flag_still_refuses_subword_by_name():
    words = (memory_word("LB"), memory_word("SH", offset=2))
    with pytest.raises(ValueError, match=r"memory word 0 is not LW or SW"):
        validate_record(words, f1_subword=False)
    assert validate_record(words, f1_subword=True) == words


def test_the_opt_in_is_not_implicit():
    legal_lw = (memory_word("LW", offset=4),)
    assert validate_record(legal_lw, f1_subword=False) == legal_lw
    assert validate_record(legal_lw, f1_subword=True) == legal_lw


# ---------------------------------------------------------------------------
# Generated programs and the shared module authority agree with the contract.
# ---------------------------------------------------------------------------

def test_generated_subword_programs_pass_the_proposed_gate():
    for seed in range(200):
        words = generate_subword_program(RV32IM, seed=seed, max_words=8,
                                         window_size=WINDOW)
        assert validate_record(words, f1_subword=True) == words
        validate_module_subword(RV32IM, words, window_size=WINDOW)


def test_the_module_validator_and_the_proposed_gate_agree_on_legality():
    legal = (memory_word("LB", offset=3), memory_word("SH", offset=2),
             memory_word("LW", offset=4))
    illegal = ((raw_load("LH", offset=1),),
               (memory_word("LB", base=5),),
               (memory_word("LB", target=8),),
               (raw_memory("SB", offset=64),))
    validate_module_subword(RV32IM, legal, window_size=WINDOW)
    validate_record(legal, f1_subword=True)
    for words in illegal:
        with pytest.raises(ValueError):
            validate_module_subword(RV32IM, words, window_size=WINDOW)
        with pytest.raises(ValueError):
            validate_record(words, f1_subword=True)
