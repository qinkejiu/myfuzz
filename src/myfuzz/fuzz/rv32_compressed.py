"""Opt-in compressed (two-parcel) RV32 trampoline images.

The F1 trampoline slot is an array of 32-bit record words, but a CPU that
implements the ``C`` extension fetches 16-bit parcels.  A record word therefore
holds either one 32-bit instruction (``word & 3 == 3``) or two 16-bit parcels:
the *low* half executes first at ``pc`` and the *high* half at ``pc + 2``.  This
module is the single Python authority for that second layout:

* :func:`decode_compressed_parcel` -- classify/decode one 16-bit parcel;
* :func:`validate_compressed_program` -- the admission gate for an image;
* :func:`image_instructions` -- PC-ordered instruction starts (2- or 4-byte);
* :func:`reference_run_compressed` -- a bounded, PC-indexed parcel interpreter
  with a parcel-level retirement trace;
* :func:`generate_compressed_program` / :func:`mutate_compressed_program` --
  deterministic generation and one-step mutation for the safe subset;
* :func:`generate_compressed_control_program` /
  :func:`generate_compressed_memory_program` -- the opt-in control and memory
  shapes described below.

Admitted subset
---------------
Only the safe straight-line ALU parcels are admitted, and the destination
register of every parcel must be in ``x12..x15``.  This is exactly the set the
unified entry's record gate already accepts at
``myfuzz/scenario/rv32i_sources.py:419-441``:

``C.ADDI``, ``C.LI``, ``C.LUI``, ``C.SLLI``, ``C.SRLI``, ``C.SRAI``,
``C.ANDI``, ``C.MV``, ``C.ADD``, ``C.SUB``, ``C.XOR``, ``C.OR``, ``C.AND``.

HINT encodings are refused even though the entry gate would accept them, because
their effect is implementation-defined: ``C.ADDI``/``C.LI`` with a zero
immediate and ``C.SLLI``/``C.SRLI``/``C.SRAI`` with a zero shift amount.

Opt-in control and memory (``CompressedPolicy``)
------------------------------------------------
A :class:`CompressedPolicy` widens the admitted set.  The scenario flags are
``f1_allow_compressed_control`` and ``f1_allow_compressed_memory``; the default
policy is the historical ALU-only subset, so every existing caller is unchanged.

* Control: ``C.J``, ``C.JAL``, ``C.JR``, ``C.JALR``, ``C.BEQZ``, ``C.BNEZ``.
  Every target must be a strictly forward instruction start of the image (or the
  appended return jump): a backward compressed transfer would be an unbounded
  loop, so it is refused by name.  ``C.J``/``C.JAL``/``C.BEQZ``/``C.BNEZ`` are
  PC-relative; ``C.JR``/``C.JALR`` are absolute and are admitted only when their
  base register is statically proven to hold one exact constant (the same
  ``LUI``/``ADDI``/``MV``/``ADD``/``ANDI`` provenance the 32-bit address forms
  use) that equals the image base plus an instruction start.  ``C.JR x0`` does
  not exist as an encoding (it is reserved) and is refused by name.
* Memory: ``C.LW``/``C.SW`` (base in ``x8..x15``) and ``C.LWSP``/``C.SWSP``
  (base ``x2``).  The base must be statically proven to hold a data-window
  address (``x18`` itself, or a register the image set from it), and the whole
  proven interval plus the parcel's own 4-byte aligned offset must stay inside
  the declared window.  A load destination may not be a reserved register.
* Floating-point, ``C.LD``/``C.SD``/``C.LDSP``/``C.SDSP``, ``C.ADDI4SPN``,
  ``C.ADDI16SP``, ``C.EBREAK`` and the RV64-only forms stay refused by name.

A 32-bit instruction in a mixed image must occupy a whole record word: a 32-bit
instruction may not straddle two record words.  Such words are checked by the
same straight-line rules as :mod:`myfuzz.fuzz.rv32_program` (and the same
forward-branch rules when the flag is on).

Soundness of the model
----------------------
``reference_run_compressed`` is a bounded PC interpreter: ``pc`` advances by two
bytes per parcel and four per 32-bit instruction, a forward branch may redirect
it, and execution stops at the return jump the host appends at
``4 * len(words)``.  The step bound (one per instruction start plus one, or an
explicit ``max_steps``) makes a malformed image terminate with an error instead
of looping.  Nothing here claims real RTL execution.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import NamedTuple

from ..riscv.encoding import encode, format_assembly
from ..riscv.profile import RiscvProfile
from .rv32_program import (
    DEFAULT_RESERVED_REGISTERS, ProgramWord, ShortProgram, _BRANCH_NAMES,
    _BRANCH_OPCODE, _IllegalEncoding, _MASK32, _MEMORY_BASE, _UNKNOWN,
    _check_max_words, _check_min_words, _check_memory_state, _check_profile,
    _check_register_state, _check_seed, _check_window, _chosen_length, _decode,
    _decode_branch, _execute_word, _extension_available, _flow_states,
    _merge_provenance, _provenance_kind, _require_window, _reserved_label,
    _reserved_set, _sext, _signed, _validate_word,
)

# --- parcel encoding facts ---------------------------------------------------

_PRIME_REGS = (12, 13, 14, 15)
_MIN_PRIME, _MAX_PRIME = _PRIME_REGS[0], _PRIME_REGS[-1]
#: The stack pointer a C.LWSP/C.SWSP names implicitly.
_STACK_POINTER = 2


class CompressedPolicy(NamedTuple):
    """Which opt-in parcel groups an image may use.

    The default policy is the historical safe-ALU-only subset, so every
    existing caller keeps its exact behaviour.  ``control`` adds
    ``C.J``/``C.JAL``/``C.JR``/``C.JALR``/``C.BEQZ``/``C.BNEZ`` and ``memory``
    adds ``C.LW``/``C.SW``/``C.LWSP``/``C.SWSP``.  Admission is still decided by
    the whole-image validation: a control target must be a proven instruction
    start, a ``C.JR``/``C.JALR`` base must be a proven constant, and a memory
    base must be a proven in-window address.
    """

    control: bool = False
    memory: bool = False

    def as_dict(self) -> dict[str, bool]:
        return {"compressed_control": self.control,
                "compressed_memory": self.memory}


#: The historical ALU-only policy: compressed control and memory are refused.
ALU_ONLY = CompressedPolicy()


def _shamt(parcel: int) -> int:
    """The 5-bit shift amount plus its RV32C high bit."""
    return ((parcel >> 2) & 0x1F) | (((parcel >> 12) & 1) << 5)


def _imm6(parcel: int) -> int:
    """The sign-extended 6-bit immediate of a CI/CANDI parcel."""
    return _sext(_shamt(parcel), 6)


def _rd(parcel: int) -> int:
    return (parcel >> 7) & 0x1F


def _rs2(parcel: int) -> int:
    return (parcel >> 2) & 0x1F


def _prime_rd(parcel: int) -> int:
    return 8 + ((parcel >> 7) & 7)


def _prime_rs2(parcel: int) -> int:
    return 8 + ((parcel >> 2) & 7)


# --- the opt-in control/memory immediates ------------------------------------
#: The 12-bit CJ displacement, sign-extended.
def _cj_imm(parcel: int) -> int:
    raw = (((parcel >> 12) & 1) << 11
           | ((parcel >> 11) & 1) << 4
           | ((parcel >> 9) & 3) << 8
           | ((parcel >> 8) & 1) << 10
           | ((parcel >> 7) & 1) << 6
           | ((parcel >> 6) & 1) << 7
           | ((parcel >> 3) & 7) << 1
           | ((parcel >> 2) & 1) << 5)
    return _sext(raw, 12)


#: The 9-bit CB branch displacement, sign-extended.
def _cb_imm(parcel: int) -> int:
    raw = (((parcel >> 12) & 1) << 8
           | ((parcel >> 10) & 3) << 3
           | ((parcel >> 5) & 3) << 6
           | ((parcel >> 3) & 3) << 1
           | ((parcel >> 2) & 1) << 5)
    return _sext(raw, 9)


#: The 7-bit unsigned C.LW/C.SW word offset.
def _cl_imm(parcel: int) -> int:
    return (((parcel >> 10) & 7) << 3
            | ((parcel >> 6) & 1) << 2
            | ((parcel >> 5) & 1) << 6)


#: The 8-bit unsigned C.LWSP word offset.
def _clsp_imm(parcel: int) -> int:
    return (((parcel >> 12) & 1) << 5
            | ((parcel >> 4) & 7) << 2
            | ((parcel >> 2) & 3) << 6)


#: The 8-bit unsigned C.SWSP word offset.
def _cssp_imm(parcel: int) -> int:
    return (((parcel >> 9) & 0xF) << 2
            | ((parcel >> 7) & 3) << 6)


#: The compressed control transfers, by name.  They are admitted only when the
#: scenario declares ``f1_allow_compressed_control``.
COMPRESSED_CONTROL_NAMES = frozenset((
    "C.J", "C.JAL", "C.JR", "C.JALR", "C.BEQZ", "C.BNEZ",
))
#: The compressed word loads/stores, by name.  They are admitted only when the
#: scenario declares ``f1_allow_compressed_memory``.
COMPRESSED_MEMORY_NAMES = frozenset((
    "C.LW", "C.SW", "C.LWSP", "C.SWSP",
))

#: Parcels this module generates and admits, by name.
COMPRESSED_ALU_NAMES = frozenset((
    "C.ADDI", "C.LI", "C.LUI", "C.SLLI", "C.SRLI", "C.SRAI", "C.ANDI",
    "C.MV", "C.ADD", "C.SUB", "C.XOR", "C.OR", "C.AND",
))
#: Compressed control transfers refused by name, whatever the profile says.
REFUSED_CONTROL_NAMES = frozenset((
    "C.J", "C.JAL", "C.JR", "C.JALR", "C.BEQZ", "C.BNEZ",
))
#: Compressed loads/stores refused by name.
REFUSED_MEMORY_NAMES = frozenset((
    "C.LW", "C.SW", "C.LWSP", "C.SWSP", "C.LD", "C.SD", "C.LDSP", "C.SDSP",
    "C.FLDSP", "C.FSDSP", "C.FLWSP", "C.FSWSP",
))
#: Stack-pointer and system forms refused by name.
REFUSED_OTHER_NAMES = frozenset((
    "C.ADDI4SPN", "C.ADDI16SP", "C.NOP", "C.EBREAK", "C.RESERVED",
))

#: The reference image profile: a maximal RV32IMC machine (C implies 2-byte
#: alignment).  Validation of a compressed image uses it so a program generated
#: for any C-capable 32-bit profile can be replayed.
_REFERENCE_C_PROFILE = RiscvProfile(
    xlen=32, extensions=frozenset(("I", "M", "C")), instruction_alignment=2,
    register_count=32, reset_vector=0)


class CompressedRefusal(ValueError):
    """A parcel is outside the admitted safe subset."""


@dataclass(frozen=True, slots=True)
class Parcel:
    """One decoded 16-bit parcel of the admitted subset."""

    parcel: int
    name: str
    operands: dict[str, int]
    assembly: str


class CompressedInstruction(NamedTuple):
    """One PC-ordered instruction start in a compressed image."""

    index: int
    half: int
    pc_offset: int
    width: int
    word: int
    parcel: int | None
    name: str
    operands: dict[str, int]
    assembly: str


class ParcelTrace(NamedTuple):
    """One retired parcel (or 32-bit word) in a compressed image.

    ``pc`` is the absolute instruction address (``data_base`` plus the byte
    offset), matching :class:`myfuzz.fuzz.rv32_program.RetirementTrace`;
    ``insn`` is the decoded name, ``rd`` the destination (``0`` when there is
    none) and ``wdata`` the written value (for a store, the stored value).  This
    is the parcel-level retirement witness.
    """

    pc: int
    insn: str
    rd: int
    wdata: int


def _refusal(name: str) -> str | None:
    """A human-readable refusal for a recognised-but-refused parcel name."""
    if name in REFUSED_CONTROL_NAMES:
        return (f"compressed control transfer {name} is refused; only forward "
                "32-bit branches are admitted")
    if name in REFUSED_MEMORY_NAMES:
        return (f"compressed memory instruction {name} is refused; use a 32-bit "
                f"LW/SW against x{_MEMORY_BASE}")
    if name in REFUSED_OTHER_NAMES:
        return (f"compressed form {name} is refused; only safe ALU parcels with "
                "a destination in x12..x15 are admitted")
    return None


def _classify_parcel(parcel: int,
                     policy: CompressedPolicy = ALU_ONLY,
                     ) -> tuple[str, dict[str, int], str | None]:
    """Return ``(name, operands, refusal)`` for one 16-bit parcel.

    The classification is structural: every quadrant/funct3 combination of the
    RV32C space is named, and the admitted set is decided by the same register
    constraints the unified entry applies.  A non-``None`` refusal names a
    recognised encoding that must not execute in the slot; an encoding this
    table cannot name raises :class:`CompressedRefusal` directly.

    ``policy`` decides whether the opt-in control transfers and word loads/
    stores are admitted.  The default is the historical ALU-only subset, so
    every existing caller (and the exhaustive 16-bit classifier test) keeps its
    exact behaviour.  An admitted control/memory parcel still carries its
    operands: the target and address rules are the whole-image validation's job.
    """
    quadrant = parcel & 3
    funct3 = (parcel >> 13) & 7
    if quadrant == 0:
        if funct3 == 2 and policy.memory:
            # The CL format: rd' is bits 4:2 and rs1' is bits 9:7 (the CA/CB
            # prime fields are the other way round).
            return "C.LW", {"rd": 8 + ((parcel >> 2) & 7),
                            "rs1": 8 + ((parcel >> 7) & 7),
                            "imm": _cl_imm(parcel)}, None
        if funct3 == 6 and policy.memory:
            return "C.SW", {"rs2": _prime_rs2(parcel),
                            "rs1": 8 + ((parcel >> 7) & 7),
                            "imm": _cl_imm(parcel)}, None
        names = {0: "C.ADDI4SPN", 2: "C.LW", 3: "C.LD", 6: "C.SW", 7: "C.SD"}
        name = names.get(funct3)
        if name is None:
            raise CompressedRefusal(
                f"compressed parcel {parcel:#06x} has reserved quadrant 0 "
                f"funct3 {funct3}")
        return name, {}, _refusal(name)
    if quadrant == 1:
        if funct3 == 0:
            immediate = _imm6(parcel)
            rd = _rd(parcel)
            if rd == 0:
                name = "C.NOP" if immediate == 0 else "C.RESERVED"
                return name, {}, _refusal(name)
            operands = {"rd": rd, "imm": immediate}
            if not (_MIN_PRIME <= rd <= _MAX_PRIME):
                return "C.ADDI", operands, (
                    f"C.ADDI dest x{rd} is outside the admitted x12..x15 range")
            if immediate == 0:
                return "C.ADDI", operands, (
                    "C.ADDI with a zero immediate is a HINT and is refused")
            return "C.ADDI", operands, None
        if funct3 == 1:
            if policy.control:
                return "C.JAL", {"rd": 1, "imm": _cj_imm(parcel)}, None
            name = "C.JAL"
            return name, {}, _refusal(name)
        if funct3 == 2:
            immediate = _imm6(parcel)
            rd = _rd(parcel)
            operands = {"rd": rd, "imm": immediate}
            if not (_MIN_PRIME <= rd <= _MAX_PRIME):
                return "C.LI", operands, (
                    f"C.LI dest x{rd} is outside the admitted x12..x15 range")
            if immediate == 0:
                return "C.LI", operands, (
                    "C.LI with a zero immediate is a HINT and is refused")
            return "C.LI", operands, None
        if funct3 == 3:
            immediate = _imm6(parcel)
            rd = _rd(parcel)
            if rd == 2:
                name = "C.ADDI16SP"
                return name, {}, _refusal(name)
            operands = {"rd": rd, "imm": immediate}
            if not (_MIN_PRIME <= rd <= _MAX_PRIME):
                return "C.LUI", operands, (
                    f"C.LUI dest x{rd} is outside the admitted x12..x15 range")
            if immediate == 0:
                return "C.LUI", operands, (
                    "C.LUI with a zero immediate is reserved")
            return "C.LUI", operands, None
        if funct3 in (5, 6, 7):
            name = {5: "C.J", 6: "C.BEQZ", 7: "C.BNEZ"}[funct3]
            if policy.control:
                if funct3 == 5:
                    return "C.J", {"imm": _cj_imm(parcel)}, None
                return name, {"rs1": _prime_rd(parcel),
                              "imm": _cb_imm(parcel)}, None
            operands = ({} if funct3 == 5
                        else {"rs1": _prime_rd(parcel), "imm": 0})
            return name, operands, _refusal(name)
        # funct3 == 4: the shift / AND-immediate / register-op group.
        operation = (parcel >> 10) & 3
        shamt = _shamt(parcel)
        if operation != 3:
            name = {0: "C.SRLI", 1: "C.SRAI", 2: "C.ANDI"}[operation]
            rd = _prime_rd(parcel)
            operands = ({"rd": rd, "imm": _imm6(parcel)} if name == "C.ANDI"
                        else {"rd": rd, "shamt": shamt})
            if not (_MIN_PRIME <= rd <= _MAX_PRIME):
                return name, operands, (
                    f"{name} dest x{rd} is outside the admitted x12..x15 range")
            if name != "C.ANDI" and shamt == 0:
                return name, operands, (
                    f"{name} with a zero shift amount is a HINT and is refused")
            return name, operands, None
        if (parcel >> 12) & 1:
            # RV64 C.SUBW / C.ADDW, or a reserved RV32 encoding.
            return "C.SUBW", {}, (
                "compressed word forms C.SUBW/C.ADDW require RV64 and are "
                "refused on RV32")
        name = {0: "C.SUB", 1: "C.XOR", 2: "C.OR", 3: "C.AND"}[(parcel >> 5) & 3]
        rd, rs2 = _prime_rd(parcel), _prime_rs2(parcel)
        operands = {"rd": rd, "rs2": rs2}
        if not (_MIN_PRIME <= rd <= _MAX_PRIME
                and _MIN_PRIME <= rs2 <= _MAX_PRIME):
            return name, operands, (
                f"{name} registers x{rd}/x{rs2} are outside the admitted "
                "x12..x15 range")
        return name, operands, None
    # quadrant == 2
    if funct3 == 0:
        rd, shamt = _rd(parcel), _shamt(parcel)
        operands = {"rd": rd, "shamt": shamt}
        if not (_MIN_PRIME <= rd <= _MAX_PRIME):
            return "C.SLLI", operands, (
                f"C.SLLI dest x{rd} is outside the admitted x12..x15 range")
        if shamt == 0:
            return "C.SLLI", operands, (
                "C.SLLI with a zero shift amount is a HINT and is refused")
        return "C.SLLI", operands, None
    if funct3 in (1, 3, 5, 7):
        name = {1: "C.FLDSP", 3: "C.FLWSP", 5: "C.FSDSP", 7: "C.FSWSP"}[funct3]
        return name, {}, _refusal(name)
    if funct3 == 2:
        if policy.memory:
            rd = _rd(parcel)
            if rd == 0:
                return "C.LWSP", {"rd": 0, "imm": _clsp_imm(parcel)}, (
                    "C.LWSP with rd=x0 is a HINT and is refused")
            return "C.LWSP", {"rd": rd, "rs1": _STACK_POINTER,
                              "imm": _clsp_imm(parcel)}, None
        return "C.LWSP", {}, _refusal("C.LWSP")
    if funct3 == 6:
        if policy.memory:
            return "C.SWSP", {"rs2": _rs2(parcel), "rs1": _STACK_POINTER,
                              "imm": _cssp_imm(parcel)}, None
        return "C.SWSP", {}, _refusal("C.SWSP")
    # funct3 == 4: C.MV / C.ADD (and the C.JR / C.JALR / C.EBREAK aliases).
    rd, rs2 = _rd(parcel), _rs2(parcel)
    if not ((parcel >> 12) & 1):
        if rd == 0:
            # C.JR with rs1 = x0 does not exist; the encoding is reserved.
            if not policy.control:
                return "C.JR", {}, _refusal("C.JR")
            return "C.JR", {}, (
                "C.JR with rs1 = x0 is a reserved encoding and is refused")
        if rs2 == 0:
            if policy.control:
                return "C.JR", {"rs1": rd}, None
            return "C.JR", {}, _refusal("C.JR")
        operands = {"rd": rd, "rs2": rs2}
        if not (_MIN_PRIME <= rd <= _MAX_PRIME
                and _MIN_PRIME <= rs2 <= _MAX_PRIME):
            return "C.MV", operands, (
                f"C.MV registers x{rd}/x{rs2} are outside the admitted "
                "x12..x15 range")
        return "C.MV", operands, None
    if rd == 0:
        return "C.EBREAK", {}, _refusal("C.EBREAK")
    if rs2 == 0:
        if policy.control:
            return "C.JALR", {"rd": 1, "rs1": rd}, None
        return "C.JALR", {}, _refusal("C.JALR")
    operands = {"rd": rd, "rs2": rs2}
    if not (_MIN_PRIME <= rd <= _MAX_PRIME and _MIN_PRIME <= rs2 <= _MAX_PRIME):
        return "C.ADD", operands, (
            f"C.ADD registers x{rd}/x{rs2} are outside the admitted x12..x15 "
            "range")
    return "C.ADD", operands, None


#: Instructions whose encoding is a C.MV/C.ADD alias, so the catalog names only
#: the alias: C.JR is ``jalr x0, 0(rs1)`` and C.JALR is ``jalr x1, 0(rs1)``.
#: ``C.JAL`` is the RV32-only ``C.J`` encoding with funct3 = 1 and has no
#: catalog entry either; it is encoded/rendered here.
_ALIAS_EXTENSION = {"C.JR": "C", "C.JALR": "C", "C.JAL": "C"}


def _encode_cj(immediate: int, *, link: bool) -> int:
    """Encode ``C.J`` (link False) or ``C.JAL`` (link True) with one immediate."""
    if type(immediate) is not int or immediate % 2 or not -2048 <= immediate <= 2046:
        raise ValueError(
            f"C.J/C.JAL immediate {immediate!r} is not a 2-byte aligned 12-bit "
            "displacement")
    parcel = encode("C.J", xlen=32, imm=immediate)
    return (parcel & ~0xE000) | (0x2000 if link else 0xA000)


def _parcel_extension(name: str) -> str:
    from ..riscv.catalog import CATALOG

    return _ALIAS_EXTENSION.get(name) or CATALOG[name].extension


def _parcel_assembly(name: str, operands: dict[str, int]) -> str:
    """Render one parcel, including the aliases the catalog omits."""
    if name == "C.JR":
        return f"c.jr x{operands['rs1']}"
    if name == "C.JALR":
        return f"c.jalr x{operands['rs1']}"
    if name == "C.JAL":
        return f"c.jal {operands['imm']}"
    return format_assembly(name, operands)


def decode_compressed_parcel(parcel: int,
                             policy: CompressedPolicy = ALU_ONLY) -> Parcel:
    """Decode one admitted 16-bit parcel.

    Raises :class:`CompressedRefusal` (a :class:`ValueError`) for a refused or
    illegal encoding, naming the encoding.  The returned operands carry
    sign-extended immediates and the real register numbers.  ``policy`` admits
    the opt-in control/memory groups; the default is the ALU-only subset.
    """
    if type(parcel) is not int or not 0 <= parcel <= 0xFFFF:
        raise ValueError(
            f"compressed parcel {parcel!r} is not a 16-bit unsigned integer")
    if parcel & 3 == 3:
        raise CompressedRefusal(
            f"parcel {parcel:#06x} is a 32-bit-length encoding, not a 16-bit "
            "parcel")
    name, operands, refusal = _classify_parcel(parcel, policy)
    if refusal is not None:
        raise CompressedRefusal(refusal)
    return Parcel(parcel, name, dict(operands),
                  _parcel_assembly(name, operands))


def parcel_is_admitted(parcel: int) -> bool:
    """Whether ``parcel`` is one of the admitted safe ALU parcels."""
    try:
        decode_compressed_parcel(parcel)
    except ValueError:
        return False
    return True


def pack_parcels(low: int, high: int) -> int:
    """Pack two 16-bit parcels into one record word; ``low`` executes first."""
    for value in (low, high):
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise ValueError(f"parcel {value!r} is not a 16-bit unsigned integer")
        if value & 3 == 3:
            raise ValueError(
                f"parcel {value:#06x} is a 32-bit-length encoding")
    return low | (high << 16)


def split_record_word(word: int) -> tuple[int, int]:
    """Split one record word into ``(low_parcel, high_parcel)``."""
    if type(word) is not int or not 0 <= word <= _MASK32:
        raise ValueError(f"record word {word!r} is not 32 bits")
    return word & 0xFFFF, word >> 16


def compressed_program_word(word: int,
                            policy: CompressedPolicy | None = None
                            ) -> ProgramWord:
    """Build the ``ProgramWord`` a compressed ``ShortProgram`` reports.

    One entry per *record word* keeps ``len(instructions) == len(words)``; a pair
    word is named ``C.A+C.B`` and its assembly joins both parcels.  Detailed
    per-parcel data is available from :func:`image_instructions`.  ``policy``
    admits the opt-in control/memory groups; ``None`` tries the ALU-only subset
    first and falls back to the full policy so a control/memory image still
    reports its real mnemonics.
    """
    if word & 3 == 3:
        name, operands = _decode(word, allow_branch=True)
        return ProgramWord(word, format_assembly(name, operands), name,
                           dict(operands))
    policies = ((policy,) if policy is not None
                else (ALU_ONLY, CompressedPolicy(True, True)))
    for candidate in policies:
        parts = []
        names = []
        for half in (word & 0xFFFF, word >> 16):
            try:
                parcel = decode_compressed_parcel(half, candidate)
            except CompressedRefusal:
                break
            names.append(parcel.name)
            parts.append(parcel.assembly)
        else:
            return ProgramWord(word, "; ".join(parts), "+".join(names), {})
    parts = []
    names = []
    for half in (word & 0xFFFF, word >> 16):
        try:
            parcel = decode_compressed_parcel(half, policies[-1])
        except CompressedRefusal:
            names.append("ILLEGAL")
            parts.append(f"{half:#06x}")
        else:
            names.append(parcel.name)
            parts.append(parcel.assembly)
    return ProgramWord(word, "; ".join(parts), "+".join(names), {})


# --- image layout and validation ---------------------------------------------


def _check_c_profile(profile: object) -> RiscvProfile:
    profile = _check_profile(profile)
    if not profile.has("C"):
        raise ValueError(
            "compressed programs require a profile that declares the C "
            f"extension, not {sorted(profile.extensions)}")
    if profile.instruction_alignment != 2:
        raise ValueError(
            "compressed programs require a 2-byte instruction alignment, not "
            f"{profile.instruction_alignment}")
    return profile


def _image_layout(words,
                  policy: CompressedPolicy = ALU_ONLY,
                  ) -> list[CompressedInstruction]:
    """Decode every instruction start of an image, PC-ordered.

    A record word is either one 32-bit instruction or two 16-bit parcels; a
    32-bit instruction may not straddle a record word.  Refused parcels raise
    :class:`CompressedRefusal` with the word index and PC offset.  ``policy``
    admits the opt-in control/memory parcels; the default is the ALU-only
    subset.
    """
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit record words")
    try:
        sequence = tuple(words)
    except TypeError:
        raise ValueError(
            "words must be a sequence of 32-bit record words") from None
    if not sequence:
        raise ValueError("program has no instruction")
    layout: list[CompressedInstruction] = []
    for index, word in enumerate(sequence):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"record word {index} is not a 32-bit unsigned word: {word!r}")
        pc = 4 * index
        if word & 3 == 3:
            try:
                name, operands = _decode(word, allow_branch=True)
            except _IllegalEncoding as error:
                raise ValueError(
                    f"record word {index} is not a legal trampoline "
                    f"instruction: {error}") from None
            layout.append(CompressedInstruction(
                index, 0, pc, 4, word, None, name, dict(operands),
                format_assembly(name, operands)))
            continue
        low, high = word & 0xFFFF, word >> 16
        for half, parcel, offset in ((0, low, 0), (1, high, 2)):
            if parcel & 3 == 3:
                raise CompressedRefusal(
                    f"record word {index} high parcel starts a 32-bit "
                    f"instruction at pc+{offset}; a 32-bit instruction may not "
                    "straddle a record word")
            try:
                decoded = decode_compressed_parcel(parcel, policy)
            except CompressedRefusal as error:
                raise CompressedRefusal(
                    f"record word {index} {'low' if half == 0 else 'high'} "
                    f"parcel at pc+{offset}: {error}") from None
            layout.append(CompressedInstruction(
                index, half, pc + offset, 2, word, parcel, decoded.name,
                dict(decoded.operands), decoded.assembly))
    return layout


def _instruction_starts(layout: list[CompressedInstruction]) -> tuple[int, ...]:
    return tuple(entry.pc_offset for entry in layout)


def validate_compressed_program(profile: RiscvProfile, words, *,
                                window_size: int | None,
                                reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                                allow_branches: bool = False,
                                allow_compressed_control: bool = False,
                                allow_compressed_memory: bool = False,
                                image_base: int | None = None,
                                ) -> None:
    """Raise :class:`ValueError` unless every instruction of the image is legal.

    The image is checked as a whole: both halves of every record word are decoded
    (refused parcels are named), the profile must declare ``C`` with 2-byte
    alignment, destinations must not be reserved, every register must exist, and
    every 32-bit load/store keeps the straight-line ``x18`` rule.  A 32-bit
    forward branch is admitted only with ``allow_branches=True``; its target must
    be an instruction start of this image (2-byte granularity) or the appended
    return jump at the image end.  ``window_size=None`` skips only the
    data-window bound.

    ``allow_compressed_control`` admits ``C.J``/``C.JAL``/``C.JR``/``C.JALR``/
    ``C.BEQZ``/``C.BNEZ``: every target must be a strictly forward instruction
    start of this image (or the appended return jump), and a ``C.JR``/``C.JALR``
    base register must be statically proven to hold one exact constant address
    (``image_base`` plus an instruction start).  ``allow_compressed_memory``
    admits ``C.LW``/``C.SW``/``C.LWSP``/``C.SWSP``: the base register (the
    ``x8..x15`` subset, or the stack pointer a ``C.LWSP``/``C.SWSP`` names) must
    be statically proven to hold a data-window address, and the whole proven
    interval plus the parcel's own offset must be 4-byte aligned and inside the
    declared window.  The function has no side effects.
    """
    profile = _check_c_profile(profile)
    window = _check_window(window_size)
    reserved_set = _reserved_set(reserved)
    if not isinstance(allow_branches, bool):
        raise ValueError("allow_branches must be a boolean")
    if not isinstance(allow_compressed_control, bool):
        raise ValueError("allow_compressed_control must be a boolean")
    if not isinstance(allow_compressed_memory, bool):
        raise ValueError("allow_compressed_memory must be a boolean")
    if image_base is not None and (type(image_base) is not int
                                   or not 0 <= image_base <= _MASK32):
        raise ValueError("image_base must be a 32-bit unsigned integer or None")
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit record words")
    try:
        sequence = tuple(words)
    except TypeError:
        raise ValueError(
            "words must be a sequence of 32-bit record words") from None
    policy = CompressedPolicy(allow_compressed_control,
                              allow_compressed_memory)
    layout = _image_layout(sequence, policy)
    starts = set(_instruction_starts(layout))
    program_end = 4 * len(sequence)
    for entry in layout:
        if entry.width == 4:
            word = entry.word
            if word & 0x7F == _BRANCH_OPCODE:
                if not allow_branches:
                    raise ValueError(
                        f"instruction {entry.index} is a control-flow or "
                        "system instruction; the trampoline program is "
                        "straight-line")
                _validate_compressed_branch(profile, entry, starts,
                                            program_end)
                continue
            # Every other 32-bit word follows the same straight-line rules as
            # the base validator, at its own record-word index.
            _validate_word(profile, entry.index, word, window, reserved_set,
                           length=len(sequence))
            continue
        for field in ("rd", "rs1", "rs2"):
            register = entry.operands.get(field)
            if register is not None and register >= profile.register_count:
                raise ValueError(
                    f"instruction {entry.index} parcel at pc+{entry.pc_offset} "
                    f"is not legal for this profile: {field} x{register} does "
                    f"not exist in a profile with {profile.register_count} "
                    "registers")
        if not _parcel_extension_available(profile, entry.name):
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} requires "
                f"extension {_parcel_extension(entry.name)}, profile declares "
                f"{sorted(profile.extensions)}")
        rd = entry.operands.get("rd")
        if rd is not None and rd != 0 and rd in reserved_set:
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} writes the "
                f"reserved {_reserved_label(rd)} x{rd}")
        if entry.name in COMPRESSED_CONTROL_NAMES:
            if not allow_compressed_control:  # pragma: no cover - layout gate
                raise ValueError(
                    f"instruction {entry.index} is a compressed control "
                    "transfer; f1_allow_compressed_control is not declared")
            _validate_compressed_control_parcel(entry, starts, program_end)
        if entry.name in COMPRESSED_MEMORY_NAMES:
            if not allow_compressed_memory:  # pragma: no cover - layout gate
                raise ValueError(
                    f"instruction {entry.index} is a compressed memory "
                    "instruction; f1_allow_compressed_memory is not declared")
    if allow_compressed_control or allow_compressed_memory:
        states = _parcel_states(layout, image_base=image_base)
        if allow_compressed_control:
            _check_compressed_control(layout, states, image_base=image_base,
                                      starts=starts, program_end=program_end)
        if allow_compressed_memory:
            _check_compressed_memory(layout, states, window=window)


def _parcel_extension_available(profile: RiscvProfile, name: str) -> bool:
    extension = _parcel_extension(name)
    return any(item.upper() == extension.upper()
               for item in profile.extensions)


def _extension_of(name: str) -> str:
    from ..riscv.catalog import CATALOG

    return CATALOG[name].extension


def _validate_compressed_branch(profile: RiscvProfile,
                                entry: CompressedInstruction,
                                starts: set[int], program_end: int) -> None:
    """Check one 32-bit B-type branch of a compressed image."""
    name, operands = _decode_branch(entry.word)
    for field in ("rs1", "rs2"):
        register = operands[field]
        if register >= profile.register_count:
            raise ValueError(
                f"instruction {entry.index} is not legal for this profile: "
                f"{field} x{register} does not exist in a profile with "
                f"{profile.register_count} registers")
    if not _extension_available(profile, name):
        raise ValueError(
            f"instruction {entry.index} is not legal for this profile: {name} "
            f"requires extension {_extension_of(name)}, profile declares "
            f"{sorted(profile.extensions)}")
    offset = operands["imm"]
    if offset % 2:
        raise ValueError(
            f"instruction {entry.index} branch offset {offset} is not "
            "2-byte aligned")
    if offset <= 0:
        raise ValueError(
            f"instruction {entry.index} branch target is not strictly forward "
            f"(offset {offset}); loops are refused")
    target = entry.pc_offset + offset
    if target != program_end and target not in starts:
        raise ValueError(
            f"instruction {entry.index} branch target pc+{target} is not an "
            "instruction start of this image")
    if target <= entry.pc_offset:
        raise ValueError(
            f"instruction {entry.index} branch target is not strictly forward")


def image_instructions(words,
                       policy: CompressedPolicy = ALU_ONLY,
                       ) -> list[CompressedInstruction]:
    """Every instruction start of the image, in PC order.

    The returned entries carry ``index`` (record word), ``half`` (0/1 for a
    parcel, 0 for a 32-bit word), ``pc_offset`` (bytes from the image base),
    ``width`` (2 or 4), the record word, the parcel value (``None`` for a 32-bit
    word), the decoded name and operands, and a rendered assembly line.
    ``policy`` admits the opt-in control/memory parcels.
    """
    return _image_layout(words, policy)


# --- opt-in compressed control and memory: whole-image proof ------------------


def _validate_compressed_control_parcel(entry: CompressedInstruction,
                                        starts: set[int],
                                        program_end: int) -> None:
    """The relative half of a compressed control transfer's target rule.

    ``C.J``/``C.JAL``/``C.BEQZ``/``C.BNEZ`` carry a PC-relative displacement, so
    their target is decided here: 2-byte aligned, strictly forward and an
    instruction start of this image (or the appended return jump).  ``C.JR``/
    ``C.JALR`` are absolute and are decided by the whole-image pass, which owns
    the constant provenance they need.
    """
    if entry.name in ("C.JR", "C.JALR"):
        return
    offset = entry.operands["imm"]
    if offset % 2:
        raise ValueError(
            f"instruction {entry.index} parcel {entry.name} at "
            f"pc+{entry.pc_offset} offset {offset} is not 2-byte aligned")
    if offset <= 0:
        raise ValueError(
            f"instruction {entry.index} parcel {entry.name} at "
            f"pc+{entry.pc_offset} branches backward (offset {offset}); a "
            "backward compressed transfer would be a loop and compressed loops "
            "are refused")
    target = entry.pc_offset + offset
    if target != program_end and target not in starts:
        raise ValueError(
            f"instruction {entry.index} parcel {entry.name} at "
            f"pc+{entry.pc_offset} target pc+{target} is not an instruction "
            "start of this image")


def _compressed_target(entry: CompressedInstruction, state,
                       image_base: int | None) -> int | None:
    """The statically known target byte offset of one control parcel."""
    if entry.name in ("C.JR", "C.JALR"):
        provenance = state[entry.operands["rs1"]]
        if _provenance_kind(provenance) != "const" or image_base is None:
            return None
        return int(provenance[1]) - int(image_base)
    return entry.pc_offset + entry.operands["imm"]


def _parcel_successors(layout: list[CompressedInstruction],
                       states, *, image_base: int | None,
                       ) -> list[tuple[int, ...]]:
    """Successor indices of every instruction of a compressed image."""
    position_of = {entry.pc_offset: position
                   for position, entry in enumerate(layout)}
    successors: list[tuple[int, ...]] = []
    for position, entry in enumerate(layout):
        fall_through = position + 1 if position + 1 < len(layout) else None
        if entry.name in COMPRESSED_CONTROL_NAMES:
            target = _compressed_target(entry, states[position], image_base)
            edge = None if target is None else position_of.get(target)
            if entry.name in ("C.BEQZ", "C.BNEZ"):
                edges = [value for value in (fall_through, edge)
                         if value is not None]
            else:
                edges = [] if edge is None else [edge]
            successors.append(tuple(dict.fromkeys(edges)))
            continue
        if entry.width == 4 and entry.name in _BRANCH_NAMES:
            target = entry.pc_offset + entry.operands["imm"]
            edge = position_of.get(target)
            successors.append(tuple(dict.fromkeys(
                [value for value in (fall_through, edge)
                 if value is not None])))
            continue
        successors.append(() if fall_through is None else (fall_through,))
    return successors


def _parcel_states(layout: list[CompressedInstruction], *,
                   image_base: int | None):
    """Least-fixpoint may-provenance of a compressed image.

    The edge set grows monotonically (a ``C.JR`` edge, once its base register is
    proven constant, stays), so the iteration terminates; the final state set is
    recomputed with the final edges and every jump base is re-checked against it.
    """
    decoded = [(entry.name, dict(entry.operands)) for entry in layout]
    if not decoded:
        return []
    successors = _parcel_successors(layout, [[_UNKNOWN] * 32] * len(layout),
                                    image_base=None)
    states = _flow_states(decoded, successors)
    for _ in range(len(layout) + 2):
        grown = _parcel_successors(layout, states, image_base=image_base)
        merged = [tuple(dict.fromkeys(old + new))
                  for old, new in zip(successors, grown)]
        if merged == list(successors):
            break
        successors = merged
        states = _flow_states(decoded, successors)
    return _flow_states(decoded, successors)


def _check_compressed_control(layout: list[CompressedInstruction], states, *,
                              image_base: int | None, starts: set[int],
                              program_end: int) -> None:
    """Resolve every ``C.JR``/``C.JALR`` base and re-check every target."""
    for position, entry in enumerate(layout):
        if entry.name not in COMPRESSED_CONTROL_NAMES:
            continue
        target = _compressed_target(entry, states[position], image_base)
        if target is None:
            if image_base is None:
                raise ValueError(
                    f"instruction {entry.index} parcel {entry.name} at "
                    f"pc+{entry.pc_offset} is an absolute compressed jump and "
                    "the declared image base is unknown; it is refused rather "
                    "than guessed")
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} base x{entry.operands['rs1']} is not a "
                "statically proven constant address; an indirect compressed "
                "jump is refused")
        if target <= entry.pc_offset:
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} target pc+{target} is not strictly "
                "forward; a backward compressed transfer would be a loop and "
                "compressed loops are refused")
        if target != program_end and target not in starts:
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} target pc+{target} is not an instruction "
                "start of this image")


def _check_compressed_memory(layout: list[CompressedInstruction], states, *,
                             window: int | None) -> None:
    """Prove every compressed load/store address inside the declared window."""
    for position, entry in enumerate(layout):
        if entry.name not in COMPRESSED_MEMORY_NAMES:
            continue
        base = entry.operands["rs1"]
        provenance = states[position][base]
        if _provenance_kind(provenance) != "window":
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} base x{base} is not a statically proven "
                "data-window address")
        low = provenance[1] + entry.operands["imm"]
        high = provenance[2] + entry.operands["imm"]
        if low % 4 or high % 4:
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} address is not 4-byte aligned (offset "
                f"range {low}..{high})")
        if window is not None and (low < 0 or high > window - 4):
            raise ValueError(
                f"instruction {entry.index} parcel {entry.name} at "
                f"pc+{entry.pc_offset} leaves the declared data window (offset "
                f"range {low}..{high}, window {window})")


# --- interpreter -------------------------------------------------------------


def _execute_parcel(entry: CompressedInstruction, state: list[int],
                    memory_state: dict[int, int], *, pc: int) -> "_Executed":
    """Execute one admitted parcel against the mutable machine state.

    Returns the same :class:`myfuzz.fuzz.rv32_program._Executed` record the
    32-bit interpreter returns, so both models project a retirement onto
    ``(pc, insn, rd, wdata)`` the same way.  A ``C.JAL``/``C.JALR`` writes
    ``pc + 2`` to ``x1`` exactly as the RTL does; a ``C.J``/``C.JR`` writes no
    register.  A ``C.LW``/``C.LWSP`` reports the value it read and a
    ``C.SW``/``C.SWSP`` the value it stored (which RVFI does not write back).
    """
    from .rv32_program import _Executed

    name, operands = entry.name, entry.operands
    rd = operands.get("rd")
    next_pc = (pc + 2) & _MASK32
    if name in ("C.J", "C.JAL"):
        target = (pc + operands["imm"]) & _MASK32
        if name == "C.JAL":
            state[1] = next_pc
            return _Executed(name, 1, next_pc, target, {}, target_pc=target)
        return _Executed(name, None, 0, target, {}, target_pc=target)
    if name in ("C.JR", "C.JALR"):
        target = (state[operands["rs1"]] & _MASK32) & ~1
        if name == "C.JALR":
            state[1] = next_pc
            return _Executed(name, 1, next_pc, target, {}, target_pc=target)
        return _Executed(name, None, 0, target, {}, target_pc=target)
    if name in ("C.BEQZ", "C.BNEZ"):
        left = state[operands["rs1"]]
        taken = (left == 0) if name == "C.BEQZ" else (left != 0)
        target = (pc + operands["imm"]) & _MASK32
        reads = {"x" + str(operands["rs1"]): left}
        return _Executed(name, None, 0, target if taken else next_pc, reads,
                         taken=taken, target_pc=target)
    if name in ("C.LW", "C.LWSP"):
        address = (state[operands["rs1"]] + operands["imm"]) & _MASK32
        if address % 4:
            raise ValueError(
                f"parcel {name} effective address {address:#010x} is not "
                "4-byte aligned")
        value = memory_state.get(address, 0)
        if rd:
            state[rd] = value
        return _Executed(name, rd, value, next_pc, {}, address=address,
                         load=True)
    if name in ("C.SW", "C.SWSP"):
        address = (state[operands["rs1"]] + operands["imm"]) & _MASK32
        if address % 4:
            raise ValueError(
                f"parcel {name} effective address {address:#010x} is not "
                "4-byte aligned")
        stored = state[operands["rs2"]]
        memory_state[address] = stored
        return _Executed(name, None, stored, next_pc, {}, address=address,
                         store=True)
    if name == "C.ADDI":
        value = (state[rd] + operands["imm"]) & _MASK32
    elif name == "C.LI":
        value = operands["imm"] & _MASK32
    elif name == "C.LUI":
        value = (operands["imm"] << 12) & _MASK32
    elif name == "C.SLLI":
        value = (state[rd] << operands["shamt"]) & _MASK32
    elif name == "C.SRLI":
        value = state[rd] >> operands["shamt"]
    elif name == "C.SRAI":
        value = (_signed(state[rd]) >> operands["shamt"]) & _MASK32
    elif name == "C.ANDI":
        value = state[rd] & (operands["imm"] & _MASK32)
    elif name == "C.MV":
        value = state[operands["rs2"]]
    elif name == "C.ADD":
        value = (state[rd] + state[operands["rs2"]]) & _MASK32
    elif name == "C.SUB":
        value = (state[rd] - state[operands["rs2"]]) & _MASK32
    elif name == "C.XOR":
        value = state[rd] ^ state[operands["rs2"]]
    elif name == "C.OR":
        value = state[rd] | state[operands["rs2"]]
    elif name == "C.AND":
        value = state[rd] & state[operands["rs2"]]
    else:  # pragma: no cover - the admitted set is closed
        raise AssertionError(f"unhandled compressed parcel {name}")
    if rd:
        state[rd] = value
    return _Executed(name, rd, value, next_pc, {})


def reference_run_compressed(words, *, registers: dict[int, int],
                             memory: dict[int, int],
                             data_base: int | None = None,
                             window_size: int | None = None,
                             trace: bool = False,
                             allow_branches: bool = False,
                             allow_compressed_control: bool = False,
                             allow_compressed_memory: bool = False,
                             image_base: int | None = None,
                             max_steps: int | None = None,
                             validate: bool = True) -> dict[str, object]:
    """Execute a compressed image with a bounded, parcel-level PC interpreter.

    ``pc`` advances by two bytes for a parcel and four for a 32-bit instruction;
    execution starts at ``data_base`` (default 0) and stops when it reaches the
    return jump the host appends at ``4 * len(words)``.  A control parcel
    (``C.J``/``C.JAL``/``C.JR``/``C.JALR``/``C.BEQZ``/``C.BNEZ``) redirects the
    PC to its statically proven target; ``allow_compressed_control`` admits them
    and ``allow_compressed_memory`` admits ``C.LW``/``C.SW``/``C.LWSP``/
    ``C.SWSP``.  ``image_base`` is the absolute address of the first instruction
    (needed to resolve a ``C.JR``/``C.JALR`` base constant).  The image is
    validated first; ``validate=False`` admits structural control-flow faults so
    the step bound can be exercised by tests.  ``window_size`` is passed to
    validation and defaults to ``None`` (skip only the data-window bound).

    The result keeps the ``rv32_reference_run.v1`` field names and adds the
    parcel-level witness: ``trace`` is one :class:`ParcelTrace` per retired
    instruction, ``pc_order`` its PC sequence and ``retired_count`` its length.
    ``steps`` (only with ``trace=True``) additionally names the record word, the
    half and the instruction width, and carries ``address`` for memory words.
    """
    from .rv32_program import _check_step_bound

    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit record words")
    words = tuple(words)
    policy = CompressedPolicy(allow_compressed_control,
                              allow_compressed_memory)
    layout = _image_layout(words, policy)
    if not isinstance(trace, bool):
        raise ValueError("trace must be a boolean")
    if validate:
        validate_compressed_program(_REFERENCE_C_PROFILE, words,
                                    window_size=window_size,
                                    allow_branches=allow_branches,
                                    allow_compressed_control=(
                                        allow_compressed_control),
                                    allow_compressed_memory=(
                                        allow_compressed_memory),
                                    image_base=image_base)
    state = _check_register_state(registers)
    initial_memory = _check_memory_state(memory)
    memory_state = dict(initial_memory)
    if data_base is not None and (type(data_base) is not int
                                  or not 0 <= data_base <= _MASK32):
        raise ValueError("data_base must be a 32-bit unsigned integer or None")
    pc_base = 0 if data_base is None else data_base
    program_end = 4 * len(words)
    by_pc = {entry.pc_offset: entry for entry in layout}
    cap = _check_step_bound(max_steps, len(layout))

    writes: list[dict[str, int | str]] = []
    steps: list[dict[str, object]] = []
    retirement: list[ParcelTrace] = []
    offset = 0
    steps_taken = 0
    while offset != program_end:
        entry = by_pc.get(offset)
        if entry is None:
            raise ValueError(
                f"pc+{offset} is not an instruction start of the installed "
                f"image ({len(words)} record word(s))")
        pc = (pc_base + offset) & _MASK32
        steps_taken += 1
        if steps_taken > cap:
            raise ValueError(
                f"program exceeded the {cap}-step bound; the image is not a "
                "bounded straight-line or forward-branch program")
        if entry.width == 4:
            executed = _execute_word(entry.word, state, memory_state, pc=pc,
                                     index=entry.index,
                                     allow_branches=allow_branches)
            next_offset = offset + 4
            if entry.word & 0x7F == _BRANCH_OPCODE:
                next_offset = (executed.next_pc - pc_base) & _MASK32
        else:
            executed = _execute_parcel(entry, state, memory_state, pc=pc)
            next_offset = offset + 2
            if entry.name in COMPRESSED_CONTROL_NAMES:
                next_offset = (executed.next_pc - pc_base) & _MASK32
        if executed.rd:
            write = {"index": entry.index, "pc": pc,
                     "name": executed.name, "rd": executed.rd,
                     "value": executed.value}
            if entry.width == 2:
                write["half"] = entry.half
            writes.append(write)
        if trace:
            if executed.store or executed.load:
                steps.append({"index": entry.index, "pc": pc,
                              "half": entry.half, "width": entry.width,
                              "name": executed.name,
                              "address": executed.address,
                              "value": executed.value})
            elif executed.name in _BRANCH_NAMES or executed.name in (
                    "C.BEQZ", "C.BNEZ"):
                steps.append({"index": entry.index, "pc": pc,
                              "half": entry.half, "width": entry.width,
                              "name": executed.name,
                              "reads": executed.reads,
                              "taken": executed.taken,
                              "target_pc": executed.target_pc})
            elif executed.name in ("C.J", "C.JAL", "C.JR", "C.JALR"):
                steps.append({"index": entry.index, "pc": pc,
                              "half": entry.half, "width": entry.width,
                              "name": executed.name,
                              "target_pc": executed.target_pc,
                              "link": executed.rd if executed.rd else None,
                              "link_value": (executed.value
                                             if executed.rd else None)})
            else:
                steps.append({"index": entry.index, "pc": pc,
                              "half": entry.half, "width": entry.width,
                              "name": executed.name,
                              "reads": executed.reads,
                              "rd": executed.rd if executed.rd else None,
                              "value": executed.value})
        retirement.append(ParcelTrace(
            pc, executed.name, executed.rd or 0,
            executed.value if (executed.rd or executed.store) else 0))
        offset = next_offset

    final_registers = {reg: value for reg, value in enumerate(state) if value}
    memory_changes = {
        address: value
        for address, value in sorted(memory_state.items())
        if initial_memory.get(address, 0) != value
    }
    result: dict[str, object] = {
        "schema_version": "rv32_reference_run.v1",
        "retires": len(retirement),
        "retired_count": len(retirement),
        "register_writes": writes,
        "final_registers": final_registers,
        "memory_changes": memory_changes,
        "trace": retirement,
        "pc_order": [entry.pc for entry in retirement],
    }
    if trace:
        result["steps"] = steps
    return result


# --- generation --------------------------------------------------------------


def _nonzero_imm6(rng: random.Random) -> int:
    return rng.choice([value for value in range(-32, 32) if value])


def _parcel(rng: random.Random, name: str, registers: tuple[int, ...]) -> int:
    """Encode one admitted parcel of ``name`` over ``registers``."""
    if name in ("C.ADDI", "C.LI", "C.LUI"):
        return encode(name, xlen=32, rd=rng.choice(registers),
                      imm=_nonzero_imm6(rng))
    if name == "C.ANDI":
        return encode(name, xlen=32, rd=rng.choice(registers),
                      imm=rng.randrange(-32, 32))
    if name in ("C.SLLI", "C.SRLI", "C.SRAI"):
        return encode(name, xlen=32, rd=rng.choice(registers),
                      shamt=rng.randrange(1, 32))
    first = rng.choice(registers)
    second = rng.choice([register for register in registers
                         if register != first] or list(registers))
    if name in ("C.MV", "C.ADD"):
        return encode(name, xlen=32, rd=first, rs2=second)
    return encode(name, xlen=32, rd=first, rs2=second)


_PARCEL_FAMILIES = ("addi", "li", "lui", "andi", "shift", "move", "add", "alu")
_FAMILY_NAMES = {
    "addi": ("C.ADDI",),
    "li": ("C.LI",),
    "lui": ("C.LUI",),
    "andi": ("C.ANDI",),
    "shift": ("C.SLLI", "C.SRLI", "C.SRAI"),
    "move": ("C.MV",),
    "add": ("C.ADD",),
    "alu": ("C.SUB", "C.XOR", "C.OR", "C.AND"),
}


def _fresh_pair(rng: random.Random,
                registers: tuple[int, ...]) -> tuple[int, int]:
    """Two admitted parcels that form one record word."""
    families = list(_PARCEL_FAMILIES)
    if len(registers) < 2:
        families = [family for family in families
                    if family not in ("move", "add", "alu")]
    parcels = []
    for _ in range(2):
        family = rng.choice(families)
        name = rng.choice(_FAMILY_NAMES[family])
        parcels.append(_parcel(rng, name, registers))
    return parcels[0], parcels[1]


def generate_compressed_program(profile: RiscvProfile, *, seed: int,
                                max_words: int, window_size: int,
                                reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                                min_words: int = 1) -> ShortProgram:
    """Generate one deterministic legal compressed program.

    Every record word holds two admitted parcels, so the record length is exactly
    the classic 1..``max_words`` draw.  Registers come from ``x12..x15`` minus
    the reserved set; the first parcel is ``C.LI`` and every later parcel is drawn
    from the admitted families.  The result is validated before it is returned,
    and ``ShortProgram.compressed`` is true.  The profile must declare ``C`` and
    2-byte alignment; ``window_size`` is validated (and reserved for images that
    mix in 32-bit memory words) even though the generated ALU parcels never touch
    memory.
    """
    profile = _check_c_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    registers = tuple(register for register in _PRIME_REGS
                      if register not in reserved_set)
    if not registers:
        raise ValueError(
            "no allocatable compressed register in x12..x15 for this profile")
    rng = random.Random(seed)
    length = _chosen_length(rng, max_words, min_length)
    parcels: list[int] = [encode("C.LI", xlen=32, rd=registers[0],
                                 imm=_nonzero_imm6(rng))]
    while len(parcels) < 2 * length:
        low, high = _fresh_pair(rng, registers)
        parcels.extend((low, high))
    parcels = parcels[:2 * length]
    words = tuple(pack_parcels(parcels[index], parcels[index + 1])
                  for index in range(0, len(parcels), 2))
    validate_compressed_program(profile, words, window_size=window,
                                reserved=reserved)
    from .rv32_program import _program_from_words

    return _program_from_words(profile, seed, max_words, words, "compressed")


def _encode_cjr(register: int, link: bool) -> int:
    """Encode ``C.JR xR`` (link False) or ``C.JALR xR`` (link True).

    The two forms are the ``C.MV``/``C.ADD`` encodings with ``rs2 = x0``; the
    catalog names only those aliases, so the two control mnemonics are encoded
    here and decoded by :func:`_classify_parcel`.
    """
    if type(register) is not int or not 1 <= register < 32:
        raise ValueError(
            f"C.JR/C.JALR base register {register!r} is not a real register")
    return (0x9002 if link else 0x8002) | (register << 7)


def _constant_parcels(register: int, value: int) -> tuple[int, ...]:
    """One or two parcels that load an exact 32-bit constant into ``register``.

    ``C.LUI`` carries bits 17:12 and ``C.ADDI`` the signed 6-bit low part, so a
    value whose low 12 bits are zero needs one parcel and any other admitted
    value needs two.  A value that does not fit is refused rather than rounded.
    """
    upper = value >> 12
    lower = value & 0xFFF
    if lower & 0x800:
        upper += 1
        lower -= 0x1000
    if not -32 <= upper <= 31 or not -32 <= lower <= 31:
        raise ValueError(
            f"constant {value:#x} is not encodable as C.LUI/C.ADDI")
    if lower == 0:
        return (encode("C.LUI", xlen=32, rd=register, imm=upper),)
    return (encode("C.LUI", xlen=32, rd=register, imm=upper),
            encode("C.ADDI", xlen=32, rd=register, imm=lower))


def generate_compressed_control_program(
        profile: RiscvProfile, *, seed: int, max_words: int, window_size: int,
        reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
        min_words: int = 2,
        image_base: int | None = None) -> ShortProgram:
    """Generate one deterministic legal image with compressed control flow.

    The image starts with two ``C.LI`` roots, then one control parcel drawn from
    ``C.J``/``C.JAL``/``C.BEQZ``/``C.BNEZ`` (all forward, target an instruction
    start of the image or the appended return jump) or - when ``image_base`` is
    given - a ``C.LUI``/``C.ADDI``/``C.JR``/``C.JALR`` sequence whose base is an
    exact constant address.  The fillers read only registers the image wrote
    first, so the reference retirement trace is a function of declared state.
    The result is validated before it is returned.
    """
    profile = _check_c_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    registers = tuple(register for register in _PRIME_REGS
                      if register not in reserved_set)
    if len(registers) < 2:
        raise ValueError(
            "compressed control generation needs two allocatable registers")
    rng = random.Random(seed)
    length = _chosen_length(rng, max_words, max(min_length, 2))
    parcels: list[int] = [
        encode("C.LI", xlen=32, rd=registers[0], imm=_nonzero_imm6(rng)),
        encode("C.LI", xlen=32, rd=registers[1], imm=_nonzero_imm6(rng)),
    ]
    total = 2 * length
    kinds = ["j", "jal", "beqz", "bnez"]
    if image_base is not None and total >= 2 + 4:
        kinds.append("jr")
    kind = rng.choice(kinds)
    if kind in ("j", "jal"):
        start = len(parcels)
        target = rng.randint(start + 2, total)
        offset = 2 * (target - start)
        parcels.append(_encode_cj(offset, link=(kind == "jal")))
    elif kind in ("beqz", "bnez"):
        start = len(parcels)
        target = rng.randint(start + 2, total)
        parcels.append(encode("C.BEQZ" if kind == "beqz" else "C.BNEZ",
                              xlen=32, rs1=registers[0],
                              imm=2 * (target - start)))
    else:
        base = registers[2] if len(registers) > 2 else registers[1]
        start = len(parcels)
        target = rng.randint(start + 4, total)
        parcels.extend(_constant_parcels(base, int(image_base) + 2 * target))
        parcels.append(_encode_cjr(base, rng.random() < 0.5))
    # The fillers read only the two roots the image writes before the control
    # transfer, so every read is satisfied on every path and the reference
    # retirement trace is a function of declared state.
    filler_registers = (registers[0], registers[1])
    while len(parcels) < total:
        parcels.append(_parcel(rng, rng.choice(
            ("C.ADDI", "C.ANDI", "C.SLLI", "C.SRLI", "C.MV", "C.ADD")),
            filler_registers))
    parcels = parcels[:total]
    words = tuple(pack_parcels(parcels[index], parcels[index + 1])
                  for index in range(0, len(parcels), 2))
    validate_compressed_program(profile, words, window_size=window,
                                reserved=reserved,
                                allow_compressed_control=True,
                                image_base=image_base)
    from .rv32_program import _program_from_words

    return _program_from_words(profile, seed, max_words, words,
                               "compressed-control")


def generate_compressed_memory_program(
        profile: RiscvProfile, *, seed: int, max_words: int, window_size: int,
        reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
        min_words: int = 2,
        image_base: int | None = None) -> ShortProgram:
    """Generate one deterministic legal image with compressed word memory.

    A whole 32-bit ``ADDI`` word sets a proven data-window base (``x12`` from
    ``x18``, or the stack pointer ``x2`` for the ``C.LWSP``/``C.SWSP`` variant),
    then the admitted compressed loads/stores use it with 4-byte aligned,
    in-window offsets.  Every loaded value is stored back, so the host's
    after-window sample is the store witness.  The result is validated before it
    is returned.
    """
    profile = _check_c_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    if profile.register_count <= _MEMORY_BASE:
        raise ValueError(
            "compressed memory generation needs an x18 data-window base")
    if window < 8:
        raise ValueError("compressed memory generation needs an 8-byte window")
    registers = tuple(register for register in _PRIME_REGS
                      if register not in reserved_set)
    if len(registers) < 2:
        raise ValueError(
            "compressed memory generation needs two allocatable registers")
    rng = random.Random(seed)
    # A store is the after-window witness, so the shortest useful image is one
    # whole 32-bit base word plus one pair holding a load and a store.
    length = _chosen_length(rng, max_words, min(max(min_length, 3), max_words))
    stack_form = rng.random() < 0.5
    base = _STACK_POINTER if stack_form else registers[0]
    load_rd = registers[1]
    offsets = [4 * index for index in range(min(4, window // 4))]
    first = rng.choice(offsets)
    second = rng.choice(offsets)
    words: list[int] = [encode("ADDI", xlen=32, rd=base, rs1=_MEMORY_BASE,
                               imm=0)]
    pair: list[int] = []
    if stack_form:
        pair.append(encode("C.LWSP", xlen=32, rd=load_rd, imm=first))
        pair.append(encode("C.ADDI", xlen=32, rd=load_rd, imm=1))
        pair.append(encode("C.SWSP", xlen=32, rs2=load_rd, imm=second))
    else:
        pair.append(encode("C.LW", xlen=32, rd=load_rd, rs1=base, imm=first))
        pair.append(encode("C.ADDI", xlen=32, rd=load_rd, imm=1))
        pair.append(encode("C.SW", xlen=32, rs2=load_rd, rs1=base, imm=second))
    while len(pair) < 2 * (length - 1):
        fill = (load_rd,) if stack_form else (load_rd, base)
        pair.append(_parcel(rng, rng.choice(("C.ADDI", "C.ANDI", "C.MV",
                                             "C.ADD", "C.SUB", "C.XOR")),
                            fill))
    pair = pair[:2 * (length - 1)]
    for index in range(0, len(pair), 2):
        words.append(pack_parcels(pair[index], pair[index + 1]))
    validate_compressed_program(profile, tuple(words), window_size=window,
                                reserved=reserved,
                                allow_compressed_memory=True,
                                image_base=image_base)
    from .rv32_program import _program_from_words

    return _program_from_words(profile, seed, max_words, tuple(words),
                               "compressed-memory")


# --- mutation ----------------------------------------------------------------


def _compressed_safe_word(rng: random.Random,
                          registers: tuple[int, ...]) -> int:
    low = encode("C.LI", xlen=32, rd=registers[0], imm=_nonzero_imm6(rng))
    second = registers[1] if len(registers) > 1 else registers[0]
    high = encode("C.ADDI", xlen=32, rd=second, imm=_nonzero_imm6(rng))
    return pack_parcels(low, high)


def mutate_compressed_program(profile: RiscvProfile, program: ShortProgram, *,
                              seed: int, max_words: int, window_size: int,
                              reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                              allow_branches: bool = False,
                              allow_compressed_control: bool = False,
                              allow_compressed_memory: bool = False,
                              image_base: int | None = None) -> ShortProgram:
    """Apply exactly one structured mutation to a compressed program.

    Actions are: replace one 16-bit parcel of a pair word, replace a whole record
    word, retarget a 32-bit or compressed forward control transfer when the image
    holds one, insert a record word when there is room and the image has no
    control transfer, or delete one record word when more than one remains and
    the image has no control transfer.  Insert and delete are withheld from
    control-bearing images because they move every later PC; such an image keeps
    in-place actions only.  The input and the result are both validated with the
    same declaration (``allow_compressed_control``/``allow_compressed_memory``
    admit the opt-in parcel groups), and the result is marked ``style
    "mutation"`` and ``compressed`` (the base ``mutate_program`` delegates here
    while ``allow_compressed=True``).
    """
    profile = _check_c_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    if not isinstance(program, ShortProgram):
        raise ValueError("program must be a ShortProgram")
    if len(program.words) > max_words:
        raise ValueError(
            f"program has {len(program.words)} words but max_words is "
            f"{max_words}")
    policy = CompressedPolicy(allow_compressed_control,
                              allow_compressed_memory)
    validate_compressed_program(
        profile, program.words, window_size=window, reserved=reserved,
        allow_branches=allow_branches,
        allow_compressed_control=allow_compressed_control,
        allow_compressed_memory=allow_compressed_memory,
        image_base=image_base)
    registers = tuple(register for register in _PRIME_REGS
                      if register not in reserved_set)
    if not registers:
        raise ValueError(
            "no allocatable compressed register in x12..x15 for this profile")
    original = tuple(program.words)
    words = list(program.words)
    layout = _image_layout(tuple(words), policy)
    starts = {entry.pc_offset for entry in layout}
    program_end = 4 * len(words)
    branch_indices = [entry.index for entry in layout
                      if entry.width == 4
                      and entry.word & 0x7F == _BRANCH_OPCODE]
    control_entries = [entry for entry in layout
                       if entry.name in ("C.J", "C.JAL", "C.BEQZ", "C.BNEZ")]
    pair_indices = [index for index, word in enumerate(words)
                    if word & 3 != 3]
    rng = random.Random(seed)

    actions = ["parcel", "word"]
    if branch_indices:
        actions.append("branch")
    if control_entries:
        actions.append("control")
    if not branch_indices and not control_entries:
        if len(words) < max_words:
            actions.append("insert")
        if len(words) > 1:
            actions.append("delete")
    action = rng.choice(actions)

    def validate_current() -> None:
        validate_compressed_program(
            profile, tuple(words), window_size=window, reserved=reserved,
            allow_branches=allow_branches,
            allow_compressed_control=allow_compressed_control,
            allow_compressed_memory=allow_compressed_memory,
            image_base=image_base)

    def valid(candidate: list[int]) -> bool:
        try:
            validate_compressed_program(
                profile, tuple(candidate), window_size=window,
                reserved=reserved, allow_branches=allow_branches,
                allow_compressed_control=allow_compressed_control,
                allow_compressed_memory=allow_compressed_memory,
                image_base=image_base)
        except ValueError:
            return False
        return tuple(candidate) != original

    if action == "delete":
        del words[rng.randrange(len(words))]
    elif action == "insert":
        position = rng.randrange(len(words) + 1)
        words.insert(position, _fresh_pair_word(rng, registers))
    elif action == "branch":
        index = rng.choice(branch_indices)
        name, operands = _decode_branch(words[index])
        current = (4 * index + operands["imm"])
        choices = [target for target in sorted(starts | {program_end})
                   if target > 4 * index and target != current]
        if not choices:  # pragma: no cover - program_end is always forward
            index = rng.randrange(len(words))
            words[index] = _replacement_word(rng, words[index], profile,
                                             reserved_set, registers)
        else:
            target = rng.choice(choices)
            words[index] = encode(name, xlen=32, rs1=operands["rs1"],
                                  rs2=operands["rs2"],
                                  imm=target - 4 * index)
    elif action == "control":
        entry = rng.choice(control_entries)
        current = entry.pc_offset + entry.operands["imm"]
        choices = [target for target in sorted(starts | {program_end})
                   if target > entry.pc_offset and target != current]
        if not choices:  # pragma: no cover - program_end is always forward
            index = rng.randrange(len(words))
            words[index] = _replacement_word(rng, words[index], profile,
                                             reserved_set, registers)
        else:
            target = rng.choice(choices)
            offset = target - entry.pc_offset
            name = entry.name
            if name in ("C.J", "C.JAL"):
                parcel = _encode_cj(offset, link=(name == "C.JAL"))
            else:
                parcel = encode(name, xlen=32, rs1=entry.operands["rs1"],
                                imm=offset)
            half = entry.half
            words[entry.index] = ((words[entry.index]
                                   & ~(0xFFFF << (16 * half)))
                                  | (parcel << (16 * half)))
    elif action == "parcel":
        if not pair_indices:
            index = rng.randrange(len(words))
            words[index] = _replacement_word(rng, words[index], profile,
                                             reserved_set, registers)
        else:
            index = rng.choice(pair_indices)
            half = rng.randrange(2)
            current = (words[index] >> (16 * half)) & 0xFFFF
            candidates = _parcel_candidates(rng, registers, current)
            placed = False
            for candidate in candidates:
                trial = list(words)
                trial[index] = ((trial[index] & ~(0xFFFF << (16 * half)))
                                | (candidate << (16 * half)))
                if valid(trial):
                    words[:] = trial
                    placed = True
                    break
            if not placed:
                index = rng.randrange(len(words))
                words[index] = _replacement_word(rng, words[index], profile,
                                                 reserved_set, registers)
    else:  # "word"
        index = rng.randrange(len(words))
        replacement = _replacement_word(rng, words[index], profile,
                                        reserved_set, registers)
        if replacement == words[index]:
            replacement = _compressed_safe_word(rng, registers)
        words[index] = replacement

    if not valid(words):
        for index in rng.sample(range(len(words)), len(words)):
            trial = list(words)
            trial[index] = _replacement_word(rng, words[index], profile,
                                             reserved_set, registers)
            if valid(trial):
                words[:] = trial
                break
        else:
            # Deterministic last resort: a 32-bit ADDI writes one allocatable
            # register, is legal in every mode, and cannot coincide with three
            # different immediates at the same word.
            destination = _zero_register(profile, reserved_set)
            for index in range(len(words)):
                for immediate in (1, 2, 3):
                    trial = list(words)
                    trial[index] = encode("ADDI", xlen=32, rd=destination,
                                          rs1=0, imm=immediate)
                    if valid(trial):
                        words[:] = trial
                        break
                else:
                    continue
                break
            else:  # pragma: no cover - three immediates cannot all coincide
                raise ValueError("no legal compressed mutation exists")
    from .rv32_program import _program_from_words

    return _program_from_words(profile, seed, max_words, tuple(words),
                               "mutation")


def _fresh_pair_word(rng: random.Random, registers: tuple[int, ...]) -> int:
    low, high = _fresh_pair(rng, registers)
    return pack_parcels(low, high)


def _zero_register(profile: RiscvProfile,
                   reserved: frozenset[int]) -> int:
    """A register the image may write with a 32-bit filler word."""
    for register in range(1, profile.register_count):
        if register not in reserved:
            return register
    raise ValueError("no allocatable register for a 32-bit filler word")


def _fresh_word32(rng: random.Random, profile: RiscvProfile,
                  reserved: frozenset[int]) -> int:
    """A legal 32-bit ALU word, used when a record word really is 32-bit.

    Every record word is four bytes, so a width change does not move later words;
    it does add or remove the parcel boundary at ``pc + 2`` of the replaced word.
    A replacement therefore keeps the width of the word it replaces, which leaves
    the image's instruction-start map (and any branch target inside that word)
    exactly as it was.
    """
    destination = _zero_register(profile, reserved)
    return encode("ADDI", xlen=32, rd=destination, rs1=0,
                  imm=rng.choice((1, 2, 3, 5, 8, 13)))


def _replacement_word(rng: random.Random, word: int, profile: RiscvProfile,
                      reserved: frozenset[int],
                      registers: tuple[int, ...]) -> int:
    """A fresh legal replacement that keeps the record word's instruction width."""
    if word & 3 == 3:
        return _fresh_word32(rng, profile, reserved)
    return _fresh_pair_word(rng, registers)


def _parcel_candidates(rng: random.Random, registers: tuple[int, ...],
                       current: int) -> list[int]:
    """Deterministic candidate parcels that differ from ``current``."""
    candidates: list[int] = []
    for family in _PARCEL_FAMILIES:
        for name in _FAMILY_NAMES[family]:
            if len(registers) < 2 and family in ("move", "add", "alu"):
                continue
            for _ in range(3):
                candidate = _parcel(rng, name, registers)
                if candidate != current and candidate not in candidates:
                    candidates.append(candidate)
    return candidates


__all__ = [
    "ALU_ONLY", "COMPRESSED_ALU_NAMES", "COMPRESSED_CONTROL_NAMES",
    "COMPRESSED_MEMORY_NAMES", "CompressedInstruction", "CompressedPolicy",
    "CompressedRefusal", "Parcel", "ParcelTrace", "REFUSED_CONTROL_NAMES",
    "REFUSED_MEMORY_NAMES", "REFUSED_OTHER_NAMES", "compressed_program_word",
    "decode_compressed_parcel", "generate_compressed_control_program",
    "generate_compressed_memory_program", "generate_compressed_program",
    "image_instructions", "mutate_compressed_program", "pack_parcels",
    "parcel_is_admitted", "reference_run_compressed", "split_record_word",
    "validate_compressed_program",
]
