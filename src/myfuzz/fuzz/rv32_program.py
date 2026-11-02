"""Bounded RV32 trampoline programs: generation, mutation, validation, model.

The unified in-process F1 executor places a short, straight-line program in a
fixed 32-bit trampoline RAM slot and jumps to it; the program falls through to
a fixed return jump.  The host firmware establishes three registers before the
jump and the program must not overwrite them:

* ``x8``  -- pointer to the host mailbox/counter word.  The polling loop and
  the case delimiter depend on it.
* ``x9``  -- slot base address.
* ``x18`` -- base of the declared 32-bit RAM data window (4-byte aligned).

A :class:`ShortProgram` is therefore just 1..``max_words`` consecutive 32-bit
instruction words.  This module holds the generator, one-step structured
mutation, the shared validator and the reference RV32IM model used to check the
executor's observations.  It is pure: no I/O, no clocks, no environment, and
``random.Random(seed)`` is the only source of choice.

Enforced rules
--------------
1. The profile is RV32 (``xlen == 32``) and declares ``I`` or ``E``.  RV32E
   (``register_count == 16``) only has ``x0..x15``: a reserved register at or
   above 16 does not exist, and neither does ``x18``, so RV32E programs never
   contain memory instructions.
2. Every word is a 32-bit instruction (``word & 3 == 3``); compressed
   encodings are refused here.  The opt-in compressed image layout (rule 16)
   lives in :mod:`myfuzz.fuzz.rv32_compressed` and is never produced by the
   default paths.
3. Allowed opcodes are ``0x37`` LUI, ``0x17`` AUIPC, ``0x13`` OP-IMM and
   ``0x33`` OP, plus ``0x03`` LOAD and ``0x23`` STORE when ``max_words > 1``.
   With ``max_words == 1`` the program is the legacy single-word F1 input and
   no memory instruction is generated; the validator itself has no
   ``max_words`` and accepts memory words either way.
4. Only ``LW`` and ``SW`` (both ``funct3 == 2``) touch memory.  They must use
   ``rs1 == 18`` and a 4-byte aligned offset inside ``[0, window_size - 4]``;
   ``window_size`` is a multiple of four and at least four.  Generated and
   mutated offsets also stay inside the signed 12-bit immediate range (at most
   2044), so a window larger than 2048 bytes is only exercised near its start.
   ``LW`` must not write a reserved register; ``SW`` may store the base value
   itself.
5. No instruction writes a reserved register.  ``x0`` writes are allowed and
   ignored.  Reads of reserved registers are allowed; only writes are unsafe.
6. Destinations come from ``1..register_count - 1`` minus the reserved set;
   sources come from ``{0}`` plus registers written earlier in the same
   program.  A source bias keeps real dependencies common.  ``M`` instructions
   are emitted only on a profile that declares ``M``; ``C`` is emitted only by
   the opt-in compressed path (rule 16).
7. ``generate_program`` emits ``min(max_words, chosen_length)`` words with
   ``chosen_length`` in ``1..max_words``; multi-word mode prefers a length in
   ``2..max_words``.  ``max_words`` is in ``1..16`` and generation is
   deterministic per seed.  ``min_words`` (default 1) raises the lower bound,
   never above ``max_words``.
8. ``style`` selects the generator's shape.  ``"random"`` is the pre-expansion
   emitter (independent draws from the instruction families).  ``"chains"``
   builds a data-flow skeleton: a fresh root, ALU words that read registers the
   program itself wrote, a second chain, ``SW``/``LW`` pairs on the same offset
   (store feeds load) and a final consumer, so several dependency chains and
   repeated uses of computed registers exist by construction.  ``"mixed"``
   (default) draws a per-seed coin between the two, only when the program can
   hold more than one word.  The classic length draw is unchanged, so
   ``style="random"`` reproduces the earlier programs word for word, and a
   one-word ``mixed`` program is the same word as a ``random`` one;
   ``style="chains"`` fills the same length with the skeleton's first steps
   (roles are truncated, so every prefix of the skeleton is emitted).
   Memory roles degrade to ALU words when ``max_words == 1`` or the profile has
   no ``x18`` (RV32E), and instruction selection stays inside the profile's
   declared extensions.  ``allow_auipc=False`` refuses to emit ``AUIPC`` (see
   the host note below).
9. ``mutate_program`` applies exactly one structured mutation -- replace, change
   one operand, rewire a source to a register the program wrote earlier, insert
   when there is room, or delete when the program has more than one word -- and
   always returns a legal program.  The action is chosen among the applicable
   ones, so the fallback is deterministic: when an action cannot apply it is
   simply not selected, an operand mutation whose target has no alternative
   value falls back to a replacement, and a rewire with no earlier producer
   falls back the same way.
10. ``validate_program_words`` names the failing instruction and the exact
    reason.  Instruction indices in these messages are 0-based positions in
    ``words``.  A legal program is accepted without side effects.
11. ``analyze_program`` reports the same program's structural data flow without
    executing it: per-instruction reads and writes, register dependency edges,
    dependency chains, repeated source registers, memory offsets and the
    ``store -> load`` / ``load -> store`` pairs, plus ``self_contained`` (every
    value the program reads was written by the program itself, apart from ``x0``
    and the ``x18`` memory base).  A self-contained program's results do not
    depend on firmware state, which is what a retirement comparison needs.
12. ``reference_run`` models exactly the emittable subset with RV32I+RV32M
    semantics.  It validates the words first against a maximal RV32IM profile
    (32 registers, ``I`` and ``M`` declared); ``window_size`` is passed through
    to that validation and defaults to ``None``, which skips only the data-window
    bound while still checking encodings, register existence, the
    reserved-register rules and the ``x18`` base rule.  ``trace=True`` adds one
    step per instruction: the effective address and observed value for ``LW``/
    ``SW``, and the source values, destination and result for arithmetic.  The
    step list is absent by default, so the default result document is unchanged.
13. *Address forms (opt-in, ``allow_address_forms=True``).*  A memory word may
    name a register other than ``x18`` as its base when that register is
    *statically proven* to hold a data-window address.  The proven shapes are
    deliberately tiny and bounded:

    * ``ADDI xd, x18, k`` with ``k`` a 4-byte aligned displacement the declared
      window can hold;
    * ``ADD xd, x18, xm`` (or ``ADD xd, xm, x18``) where ``xm`` is proven to hold
      an in-window constant, e.g. ``ADDI xm, x0, k`` or ``LUI xm, 0`` followed by
      ``ADDI xm, xm, k``;
    * the same with a masked *offset*: ``ANDI xm, xm, window_bytes - 4`` folds
      the constant first, so the resulting displacement is 4-byte aligned and at
      most ``window_bytes - 4``.

    A mask applies to the *displacement*, never to the absolute address: ``ANDI``
    clears every bit outside the mask, so ``ANDI xd, xd, 60`` on a value of
    ``data_base + 60`` yields ``60`` (the masked value would be ``0x3C``, not
    ``data_base + 0x3C``), which is outside the window.  The analysis therefore
    folds ``ANDI`` only where its operand is a proven constant and reports a
    masked window address as unproven; this is the sound reading of the masking
    idiom and it needs no assumption about the window's alignment.

    Such a memory word must use immediate 0 (the displacement is in the base
    register).  :func:`address_provenance` reports every memory use as an
    ``(index, base_reg, offset, width)`` tuple, :func:`address_provenance_details`
    adds the proven displacement interval, and :func:`validate_address_program`
    is the soundness gate: the whole proven interval must stay inside
    ``[data_base, data_base + window_bytes)`` and keep 4-byte alignment.  The
    legacy ``x18 + imm`` form is unchanged and is always accepted.
14. *Forward branches (opt-in, ``allow_branches=True``).*  Only the six B-type
    branches are admitted; ``CSR``/``FENCE`` stay refused.  A branch target must
    be 4-byte aligned, strictly forward, and inside the installed image: the
    target word index is in ``(index, len(words)]``, where ``len(words)`` names
    the return jump the host appends to the slot.  Without ``allow_loops`` the
    static rule makes loops impossible, so execution always falls through or
    reaches the appended return jump.

14b. *Jumps (opt-in, ``allow_jumps=True``).*  ``JAL`` and ``JALR`` are admitted
    with a link destination of ``x0`` or ``x1`` only, and only with a
    *statically known* target: ``JAL`` is PC-relative (``index + imm/4``), and
    ``JALR`` needs ``rs1 == x0`` or a register the static provenance proves to
    hold one exact 32-bit constant (``LUI``/``ADDI``/``ADD``/``ANDI`` chains,
    and ``x0`` itself), so its absolute target is ``const + imm``.  A target
    must be an instruction start of the installed image (index in
    ``[0, len(words)]``) and strictly forward; a backward jump would be an
    unbounded loop and is refused by name.  ``JALR`` is an absolute transfer,
    so its validation needs the image base (``image_base``): without one the
    form is refused rather than guessed.  The reference model writes ``pc + 4``
    to the link register, exactly as the RTL does.

14c. *Bounded loops (opt-in, ``allow_loops=True``).*  A loop is one canonical
    shape with a statically known trip count ``K`` in ``2..6``::

        addi xN, x0, K          # the only predecessor of the head
        head:  <body>           # zero or more non-control words, never writes xN
        dec:   addi xN, xN, -1
        back:  bne xN, x0, head # the only backward transfer of the image

    ``N`` is not ``x0`` and not a reserved register.  Every backward transfer
    must be such a back edge, loop intervals must be disjoint and sequential,
    and no other transfer may target the interior of a loop (so a loop is
    entered only at its init).  The recognizer proves the trip count, so
    termination is static: the reference model's default step bound is the
    exact retirement bound ``len(words) + sum((K-1) * loop_length)``.  A
    backward ``JAL``/``JALR`` is refused: the bounded-loop back edge is the
    ``BNE`` above.  A loop body may not contain a branch, jump or CSR word.
15. *PC-indexed reference model.*  ``reference_run`` is a bounded PC interpreter:
    it executes words in retirement order rather than assuming the ``i``-th word
    runs at ``pc = data_base + 4 * i``, follows forward branches, and stops at
    ``len(words)`` or at an explicit ``max_steps`` bound (raising instead of
    looping).  For straight-line programs the old result fields keep their exact
    values; ``trace``, ``retired_count`` and ``pc_order`` are added.  ``trace``
    holds ``(pc, insn, rd, wdata)`` retirement tuples (``RetirementTrace``), one
    per retired instruction, which is the witness an RVFI retirement stream
    provides.
16. *Compressed parcels (opt-in, ``allow_compressed=True``).*  A record word may
    hold two 16-bit parcels: the low half executes first at ``pc`` and the high
    half at ``pc + 2``.  The admitted subset is the safe straight-line
    ``C.ADDI``/``C.LI``/``C.LUI``/``C.SLLI``/``C.SRLI``/``C.SRAI``/``C.ANDI``/
    ``C.MV``/``C.ADD``/``C.SUB``/``C.XOR``/``C.OR``/``C.AND`` set with destinations
    in ``x12..x15``, exactly the set the unified entry admits at
    ``myfuzz/scenario/rv32i_sources.py:419-441``.  Compressed loads/stores and
    compressed control transfers are refused by name.  The implementation lives in
    :mod:`myfuzz.fuzz.rv32_compressed`; :func:`generate_program` and
    :func:`mutate_program` delegate to it when the flag is on.
17. *Opt-in flags and styles.*  ``allow_branches``, ``allow_compressed`` and
    ``allow_address_forms`` default to ``False``, so every existing caller and
    seed keeps its exact behaviour.  The styles ``"address"``, ``"branch"`` and
    ``"compressed"`` require their matching flag and exercise one shape; the
    ``"mixed"`` style may draw an enabled shape per seed; ``"extended"`` combines
    the address and branch shapes.  ``generate_compressed_program`` is the
    standalone compressed entry point.

Host note (observed, not repaired here)
---------------------------------------
The C++ host admits opcode ``0x17`` (``AUIPC``) inside an F1 program, and this
module's validator and model accept it.  The unified entry's Python record gate
(``myfuzz.scenario.rv32i_sources.validate_instruction_bytes``) does not admit
``AUIPC``, so a record containing it is refused before the host ever sees it:
``allow_auipc=False`` keeps generated programs inside that gate.  Widening the
gate is an entry-side change, not a trampoline-contract change.

Reference-model conventions (deliberate, documented behaviours)
---------------------------------------------------------------
* All arithmetic wraps to 32 bits; ``x0`` reads as 0 and ignores writes.
* ``AUIPC`` uses the instruction's own PC: the ``i``-th instruction is at
  ``(data_base or 0) + 4 * i``.
* ``DIV``/``DIVU`` by zero give ``0xFFFFFFFF``; ``INT_MIN / -1`` gives
  ``INT_MIN``; ``REM``/``REMU`` by zero give the dividend; ``REM`` overflow
  gives 0.
* ``LW``/``SW`` use ``(rs1 + imm) mod 2**32``.  An address that is not
  4-byte aligned is refused, and an address with no initial value reads 0.
* ``register_writes`` omits writes to ``x0``; ``final_registers`` holds only
  non-zero registers (initial state included); ``memory_changes`` holds only
  addresses whose final value differs from their initial value.
* ``steps`` (only with ``trace=True``) is one entry per instruction in program
  order: ``index``, ``pc``, ``name`` and either ``address``, ``value`` and (for
  a load) ``rd`` for a memory word, or ``reads`` (source register to value),
  ``rd`` and ``value`` for arithmetic.  A ``SW`` step reports the value it
  stored; a ``LW`` step reports the value it read, with the same "unset memory
  reads 0" rule as the model itself.
* ``analyze_program`` reads only the words: it decodes them, never validates
  them against a data window, and never executes anything.  ``external_reads``
  names a register read before the program wrote it, which is how a caller sees
  that a result depends on firmware state.
"""

from __future__ import annotations

import random
from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple

from ..riscv.catalog import CATALOG
from ..riscv.encoding import encode, format_assembly
from ..riscv.profile import RiscvProfile

DEFAULT_RESERVED_REGISTERS: tuple[int, ...] = (8, 9, 18)

_MASK32 = 0xFFFFFFFF
_MAX_WORDS = 16
_MEMORY_BASE = 18
_DEPENDENCY_BIAS = 0.7
# The largest 4-byte aligned offset a signed 12-bit immediate can carry, so a
# larger declared window is only exercised near its beginning.
_MAX_MEMORY_OFFSET = 2044

# Generation styles.  ``random`` is the pre-expansion emitter, ``chains`` builds
# the dependency skeleton below, and ``mixed`` draws a per-seed coin between them.
# The opt-in shapes add ``address``, ``branch`` and ``compressed``; ``extended``
# combines the first two, and ``jump``/``loop`` exercise the static jumps and the
# bounded loop.  Every style past ``mixed`` needs its declaring flag.
_STYLES = ("random", "chains", "mixed", "address", "branch", "compressed",
           "extended", "jump", "loop")
_MIXED_CHAIN_CHANCE = 0.6
# Probability that a ``mixed`` program upgrades to an enabled opt-in shape.
_MIXED_OPT_IN_CHANCE = 0.5

# The skeleton ``style="chains"`` emits, one role per word.  Every role after the
# first root reads at least one register the program itself wrote, so any
# program of two or more words contains a cross-instruction dependency, and the
# memory roles form store/load pairs on one offset.  A shorter program is a
# prefix of this tuple, so the same properties hold for every length.
_STRUCTURED_TOUR = (
    "root",          # 0  a fresh chain root (writes a new register, reads x0)
    "derive",        # 1  depends on the root
    "store",         # 2  stores the computed value at a fresh window offset
    "load",          # 3  loads that offset back (store -> load, same address)
    "consume_load",  # 4  an ALU word whose first source is the loaded register
    "root",          # 5  a second chain root
    "join",          # 6  reads both chain registers (a real join)
    "copy_store",    # 7  stores the value loaded at 3 (load -> store)
    "load",          # 8  loads that second offset back
    "consume_load",  # 9  depends on the reloaded value
    "store_repeat",  # 10 rewrites an address already used (repeated address)
    "load",          # 11 reads the value just rewritten (store -> load again)
    "mul",           # 12 an M word when the profile declares M
    "shift",         # 13 a shift of the previous result
    "final",         # 14 depends on the shifted value and the first chain
    "final",         # 15 the same shape once more
)
_MEMORY_ROLES = frozenset(("store", "copy_store", "store_repeat", "load"))

# Labels used by the reserved-register refusals; any other reserved register
# is described generically.
_RESERVED_LABELS = {
    8: "mailbox register",
    9: "slot base register",
    18: "data-window base register",
}

# Canonical decodings.  ``funct7 == 0x00`` uses the base table, ``0x20`` the
# subtract/arithmetic-shift variants and ``0x01`` the RV32M table.
_R_FUNCT3 = ("ADD", "SLL", "SLT", "SLTU", "XOR", "SRL", "OR", "AND")
_R_ALT = {0: "SUB", 5: "SRA"}
_M_FUNCT3 = ("MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM", "REMU")
_I_FUNCT3 = {0: "ADDI", 2: "SLTI", 3: "SLTIU", 4: "XORI", 6: "ORI", 7: "ANDI"}
_UPPER_OPCODES = {0x37: "LUI", 0x17: "AUIPC"}
_LOAD_OPCODE = 0x03
_STORE_OPCODE = 0x23
_BRANCH_OPCODE = 0x63
_MEMORY_OPCODES = frozenset((_LOAD_OPCODE, _STORE_OPCODE))
_MEMORY_NAMES = ("LW", "SW")
#: The six B-type branches, keyed by funct3.  Only these control transfers are
#: ever admitted; ``CSR`` never executes inside the slot body.
_BRANCH_FUNCT3 = {0: "BEQ", 1: "BNE", 4: "BLT", 5: "BGE", 6: "BLTU", 7: "BGEU"}
_BRANCH_NAMES = frozenset(_BRANCH_FUNCT3.values())
_BRANCH_FUNCT3_BY_NAME = {name: funct3 for funct3, name in _BRANCH_FUNCT3.items()}
#: The two jumps.  Both are opt-in (``allow_jumps``) and both need a statically
#: known target; ``JALR`` is absolute and therefore needs the image base.
_JAL_OPCODE = 0x6F
_JALR_OPCODE = 0x67
_JUMP_NAMES = frozenset(("JAL", "JALR"))
_JUMP_OPCODES = frozenset((_JAL_OPCODE, _JALR_OPCODE))
#: The only link destinations a jump may name: x0 (no link) and x1 (the ABI
#: return-address register).  Any other destination would be an arbitrary
#: register write from a control transfer.
_JUMP_LINK_REGISTERS = frozenset((0, 1))
#: A bounded loop's back edge is this branch, its induction step is this word,
#: and its trip count is in this closed range.  The three facts are what make
#: termination static instead of observed.
_LOOP_BACK_EDGE = "BNE"
_LOOP_TRIP_MIN = 2
_LOOP_TRIP_MAX = 6
#: One record word of a compressed image holds two 16-bit parcels.
_COMPRESSED_PARCEL_BYTES = 2
#: The trampoline data window the host declares by default (16 words).
DEFAULT_WINDOW_BYTES = 64
# Straight-line refusals: branches (opt-in), jumps, SYSTEM/CSR and FENCE never
# execute as part of the slot body.  FENCE keeps the generic subset refusal
# because it is a memory-ordering instruction, not a control transfer.
_CONTROL_FLOW_OPCODES = frozenset((_BRANCH_OPCODE, 0x67, 0x6F, 0x73))
_JUMP_SYSTEM_OPCODES = frozenset((0x67, 0x6F, 0x73))

# Generation pools.  Shifts stay separate because SLLI/SRLI/SRAI carry a shamt.
_GEN_UPPER_NAMES = ("LUI", "AUIPC")
_GEN_IMM_NAMES = ("ADDI", "SLTI", "SLTIU", "XORI", "ORI", "ANDI")
_GEN_SHIFT_NAMES = ("SLLI", "SRLI", "SRAI")
_GEN_R_NAMES = ("ADD", "SUB", "SLL", "SLT", "SLTU", "XOR", "SRL", "SRA",
                "OR", "AND")
_GEN_M_NAMES = ("MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM",
                "REMU")

# The reference model accepts the full emittable subset regardless of the CPU
# a program was generated for; register existence is checked against x0..x31.
_REFERENCE_PROFILE = RiscvProfile(
    xlen=32, extensions=frozenset(("I", "M")), instruction_alignment=4,
    register_count=32, reset_vector=0)


class _IllegalEncoding(ValueError):
    """A word is outside the emittable trampoline subset."""


@dataclass(frozen=True, slots=True)
class ProgramWord:
    """One validated instruction word and its decoded metadata."""

    word: int
    assembly: str
    name: str
    operands: dict[str, int]


@dataclass(frozen=True, slots=True)
class ShortProgram:
    """A legal 1..``max_words``-word trampoline program.

    ``words`` is the executable image the host firmware copies into its slot;
    ``instructions`` is the same sequence decoded for reporting.  The program
    does not carry its data window or reserved set: callers pass both to
    :func:`validate_program_words` and :func:`mutate_program`.
    """

    profile: RiscvProfile
    seed: int
    max_words: int
    words: tuple[int, ...]
    instructions: tuple[ProgramWord, ...]
    style: str = "random"
    compressed: bool = False

    @property
    def text(self) -> str:
        """The words joined by ``':'`` as eight lower-case hex digits each."""
        return ":".join(f"{word:08x}" for word in self.words)

    def as_dict(self) -> dict[str, object]:
        """JSON-ready metadata; contains no timestamps or absolute paths."""
        return {
            "schema_version": "rv32_short_program.v1",
            "profile": {
                "component_id": self.profile.component_id,
                "xlen": self.profile.xlen,
                "extensions": sorted(self.profile.extensions),
                "instruction_alignment": self.profile.instruction_alignment,
                "register_count": self.profile.register_count,
                "reset_vector": self.profile.reset_vector,
            },
            "seed": self.seed,
            "max_words": self.max_words,
            "style": self.style,
            "compressed": self.compressed,
            "words": list(self.words),
            "text": self.text,
            "instructions": [
                {
                    "word": item.word,
                    "assembly": item.assembly,
                    "name": item.name,
                    "operands": dict(item.operands),
                }
                for item in self.instructions
            ],
        }


def _sext(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _branch_immediate(word: int) -> int:
    """Signed 13-bit B-type displacement held in the imm[12|10:5|4:1|11] fields."""
    raw = (((word >> 31) & 1) << 12
           | ((word >> 7) & 1) << 11
           | ((word >> 25) & 0x3F) << 5
           | ((word >> 8) & 0xF) << 1)
    return _sext(raw, 13)


def _jal_immediate(word: int) -> int:
    """Signed 21-bit J-type displacement held in imm[20|10:1|11|19:12]."""
    raw = (((word >> 31) & 1) << 20
           | ((word >> 12) & 0xFF) << 12
           | ((word >> 20) & 1) << 11
           | ((word >> 21) & 0x3FF) << 1)
    return _sext(raw, 21)


def _decode_branch(word: int) -> tuple[str, dict[str, int]]:
    """Decode one B-type branch into its name and catalog-style operands."""
    funct3 = (word >> 12) & 0x07
    name = _BRANCH_FUNCT3.get(funct3)
    if name is None:
        raise _IllegalEncoding(
            f"opcode 0x63 funct3 {funct3} is not a B-type branch")
    return name, {"rs1": (word >> 15) & 0x1F, "rs2": (word >> 20) & 0x1F,
                  "imm": _branch_immediate(word)}


def _decode_jump(word: int) -> tuple[str, dict[str, int]]:
    """Decode one JAL/JALR into its name and catalog-style operands."""
    opcode = word & 0x7F
    funct3 = (word >> 12) & 0x07
    if opcode == _JAL_OPCODE:
        # JAL has no funct3 field: bits 14:12 are imm[14:12], not an encoding
        # discriminant, so no funct3 check applies here.
        return "JAL", {"rd": (word >> 7) & 0x1F, "imm": _jal_immediate(word)}
    if opcode == _JALR_OPCODE:
        if funct3 != 0:
            raise _IllegalEncoding(
                f"opcode 0x67 funct3 {funct3} is not JALR")
        return "JALR", {"rd": (word >> 7) & 0x1F,
                        "rs1": (word >> 15) & 0x1F,
                        "imm": _sext(word >> 20, 12)}
    raise _IllegalEncoding(f"opcode {opcode:#04x} is not a jump")


def _decode(word: int, *, allow_branch: bool = False,
            allow_jump: bool = False) -> tuple[str, dict[str, int]]:
    """Decode one emittable word into its name and catalog-style operands.

    Only the subset this module can generate and model is decoded; every other
    encoding raises :class:`_IllegalEncoding` so validation and mutation share
    one definition of "emittable".  Decoding is structural and therefore
    canonical: the immediates, shift amounts and register fields are read from
    the fields themselves.  A 4-byte memory offset alignment is *not* enforced
    here -- the encoder refuses to build such a word, so
    :func:`validate_program_words` owns that check for hand-built or corrupted
    input.  ``allow_branch`` adds the six B-type branches and ``allow_jump`` the
    two jumps; both default to ``False``, which keeps the historical
    straight-line decoding.
    """
    opcode = word & 0x7F
    funct3 = (word >> 12) & 0x07
    rd = (word >> 7) & 0x1F
    rs1 = (word >> 15) & 0x1F
    rs2 = (word >> 20) & 0x1F
    name = _UPPER_OPCODES.get(opcode)
    if name is not None:
        operands = {"rd": rd, "imm": word >> 12}
    elif opcode == 0x13:
        if funct3 == 1:
            if word >> 25:
                raise _IllegalEncoding(
                    "SLLI may only carry a five-bit shift amount")
            name = "SLLI"
            operands = {"rd": rd, "rs1": rs1, "shamt": (word >> 20) & 0x1F}
        elif funct3 == 5:
            top = word >> 25
            if top not in (0x00, 0x20):
                raise _IllegalEncoding(
                    f"SRLI/SRAI funct7 {top:#04x} is not a base encoding")
            name = "SRLI" if top == 0x00 else "SRAI"
            operands = {"rd": rd, "rs1": rs1, "shamt": (word >> 20) & 0x1F}
        else:
            name = _I_FUNCT3.get(funct3)
            if name is None:
                raise _IllegalEncoding(f"OP-IMM funct3 {funct3} is not emittable")
            operands = {"rd": rd, "rs1": rs1,
                        "imm": _sext(word >> 20, 12)}
    elif opcode == 0x33:
        top = word >> 25
        if top == 0x00:
            name = _R_FUNCT3[funct3]
        elif top == 0x20:
            name = _R_ALT.get(funct3)
        elif top == 0x01:
            name = _M_FUNCT3[funct3]
        else:
            name = None
        if name is None:
            raise _IllegalEncoding(
                f"OP funct7 {top:#04x} funct3 {funct3} is not emittable")
        operands = {"rd": rd, "rs1": rs1, "rs2": rs2}
    elif opcode == _LOAD_OPCODE:
        if funct3 != 2:
            raise _IllegalEncoding(
                f"opcode 0x03 funct3 {funct3} is not LW; only LW is emittable "
                "as a load")
        name = "LW"
        operands = {"rd": rd, "rs1": rs1, "imm": _sext(word >> 20, 12)}
    elif opcode == _STORE_OPCODE:
        if funct3 != 2:
            raise _IllegalEncoding(
                f"opcode 0x23 funct3 {funct3} is not SW; only SW is emittable "
                "as a store")
        name = "SW"
        imm = ((word >> 25) << 5) | ((word >> 7) & 0x1F)
        operands = {"rs2": rs2, "rs1": rs1, "imm": _sext(imm, 12)}
    elif opcode == _BRANCH_OPCODE and allow_branch:
        return _decode_branch(word)
    elif opcode in _JUMP_OPCODES and allow_jump:
        return _decode_jump(word)
    else:
        raise _IllegalEncoding(f"opcode {opcode:#04x} is outside the subset")
    return name, operands


def _check_profile(profile: object) -> RiscvProfile:
    if not isinstance(profile, RiscvProfile):
        raise ValueError("profile must be a RiscvProfile")
    if profile.xlen != 32:
        raise ValueError(f"profile must be RV32 (xlen 32), not xlen {profile.xlen}")
    if not (profile.has("I") or profile.has("E")):
        raise ValueError(
            "profile must declare the I or E base extension, not "
            f"{sorted(profile.extensions)}")
    if profile.register_count not in (16, 32):
        raise ValueError(
            f"profile register_count must be 16 or 32, not {profile.register_count}")
    return profile


def _check_seed(seed: object) -> int:
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    return seed


def _check_max_words(max_words: object) -> int:
    if type(max_words) is not int or not 1 <= max_words <= _MAX_WORDS:
        raise ValueError(
            f"max_words must be an integer in 1..{_MAX_WORDS}, not {max_words!r}")
    return max_words


def _check_min_words(min_words: object, max_words: int) -> int:
    if type(min_words) is not int:
        raise ValueError("min_words must be an integer")
    if min_words < 1:
        raise ValueError(f"min_words must be at least 1, not {min_words}")
    if min_words > max_words:
        raise ValueError(
            f"min_words {min_words} must not exceed max_words {max_words}")
    return min_words


def _check_style(style: object) -> str:
    if style not in _STYLES:
        raise ValueError(f"style must be one of {_STYLES}, not {style!r}")
    return style  # type: ignore[return-value]


def _check_allow_auipc(allow_auipc: object) -> bool:
    if not isinstance(allow_auipc, bool):
        raise ValueError("allow_auipc must be a boolean")
    return allow_auipc


def _check_window(window_size: object) -> int | None:
    if window_size is None:
        return None
    if type(window_size) is not int:
        raise ValueError("window_size must be an integer or None")
    if window_size < 4:
        raise ValueError(f"window_size {window_size} must be at least 4 bytes")
    if window_size % 4:
        raise ValueError(f"window_size {window_size} must be 4-byte aligned")
    return window_size


def _offset_limit(window_size: int) -> int:
    """Largest 4-aligned offset both inside the window and encodable."""
    limit = min(window_size - 4, _MAX_MEMORY_OFFSET)
    return limit - limit % 4


def _require_window(window_size: object) -> int:
    """Generation and mutation always need a declared data window."""
    window = _check_window(window_size)
    if window is None:
        raise ValueError("window_size must be an integer, not None")
    return window


# ---------------------------------------------------------------------------
# Static address provenance for the opt-in address forms
# ---------------------------------------------------------------------------

#: Placeholder offset for a provenance value that is not derived from ``x18``.
_UNKNOWN: object = object()
# Provenance values are plain tuples so they compare structurally:
#   ("const", value)      an exactly known 32-bit constant
#   ("window", low, high) ``data_base + d`` for some ``d`` in the closed range
# ``_UNKNOWN`` covers everything else (firmware state, loads, unpredictable
# arithmetic).


def _provenance_kind(value: object) -> str:
    """The tag of a provenance value, with a safe tag for the unknown sentinel."""
    return value[0] if isinstance(value, tuple) else "unknown"


class AddressUse(NamedTuple):
    """One memory instruction's statically proven base.

    ``index`` is the 0-based word index, ``base_reg`` the ``rs1`` the word names,
    ``offset`` the word's own immediate and ``width`` the access width in bytes
    (always four here -- only ``LW``/``SW`` are admitted).  The proven
    displacement interval relative to ``x18`` is reported separately by
    :func:`address_provenance_details`; this tuple is the compact shape the entry
    and host can mirror.
    """

    index: int
    base_reg: int
    offset: int
    width: int


def _transfer_provenance(name: str, operands: dict[str, int],
                         state: Sequence[object]) -> object:
    """The provenance a written ``rd`` holds after one instruction."""
    if name == "LUI":
        return ("const", (operands["imm"] << 12) & _MASK32)
    if name == "AUIPC":
        return _UNKNOWN
    if name == "ADDI":
        source = state[operands["rs1"]]
        immediate = operands["imm"]
        if _provenance_kind(source) == "const":
            return ("const", (source[1] + immediate) & _MASK32)
        if _provenance_kind(source) == "window":
            # Register arithmetic is modulo 2**32, so the tracked displacement
            # stays exact for any integer -- even a negative one that only comes
            # back inside the window a later ADDI/ADD later.  In-window-ness is
            # checked where a value is actually dereferenced.
            return ("window", source[1] + immediate, source[2] + immediate)
        return _UNKNOWN
    if name == "ADD":
        left, right = state[operands["rs1"]], state[operands["rs2"]]
        if _provenance_kind(left) == "const" and _provenance_kind(right) == "const":
            return ("const", (left[1] + right[1]) & _MASK32)
        if _provenance_kind(left) == "window" and _provenance_kind(right) == "const":
            low, high = left[1] + right[1], left[2] + right[1]
        elif _provenance_kind(left) == "const" and _provenance_kind(right) == "window":
            low, high = right[1] + left[1], right[2] + left[1]
        else:
            return _UNKNOWN
        return ("window", low, high)
    if name == "ANDI":
        source = state[operands["rs1"]]
        if _provenance_kind(source) == "const":
            # Folding a *constant* is the only sound mask: an AND applied to a
            # proven window address clears the base's high bits, so the result
            # is a bare offset rather than an address and stays unknown.
            return ("const", source[1] & (operands["imm"] & _MASK32))
        return _UNKNOWN
    # The compressed ALU parcels share this transfer function with the 32-bit
    # words: the compressed image's provenance pass (and the host mirror) only
    # needs to know which constants and window displacements a parcel keeps.
    if name == "C.LI":
        return ("const", operands["imm"] & _MASK32)
    if name == "C.LUI":
        return ("const", (operands["imm"] << 12) & _MASK32)
    if name == "C.ADDI":
        return _transfer_provenance(
            "ADDI", {"rd": operands["rd"], "rs1": operands["rd"],
                     "imm": operands["imm"]}, state)
    if name == "C.ANDI":
        return _transfer_provenance(
            "ANDI", {"rd": operands["rd"], "rs1": operands["rd"],
                     "imm": operands["imm"]}, state)
    if name == "C.MV":
        return state[operands["rs2"]]
    if name == "C.ADD":
        return _transfer_provenance(
            "ADD", {"rd": operands["rd"], "rs1": operands["rd"],
                    "rs2": operands["rs2"]}, state)
    return _UNKNOWN


def _merge_provenance(left: object, right: object) -> object:
    """Join two provenance values at a control-flow merge.

    The union of the two proven ranges is a sound over-approximation; anything
    else becomes unknown.
    """
    if left == right:
        return left
    if _provenance_kind(left) == "window" and _provenance_kind(right) == "window":
        return ("window", min(left[1], right[1]), max(left[2], right[2]))
    return _UNKNOWN


def _successor_indices(name: str, operands: dict[str, int], index: int,
                       length: int) -> tuple[int, ...]:
    """Successor word indices of one instruction, clamped to the image.

    A branch always keeps its fall-through successor plus its (strictly forward)
    target; an out-of-image or non-forward target is ignored here because
    control-flow legality is a separate check in :func:`validate_program_words`.
    Restricting targets to ``> index`` keeps the control-flow graph a DAG, which
    is what lets every dataflow below run in one increasing-index pass.
    """
    successors = []
    if index + 1 <= length:
        successors.append(index + 1)
    if name in _BRANCH_NAMES and operands["imm"] % 4 == 0:
        target = index + operands["imm"] // 4
        if index < target <= length:
            successors.append(target)
    return tuple(dict.fromkeys(successors))


def _provenance_states(words: Sequence[int], *, window_bytes: int | None,
                       base_reg: int = _MEMORY_BASE,
                       ) -> tuple[list[list[object]], list[tuple[str, dict[str, int]]]]:
    """Forward may-dataflow of the ``x18``-relative value of every register.

    Returns the state *before* each instruction plus the decoded sequence.  The
    program is a DAG because branches are only admitted when they point strictly
    forward, so one pass in index order suffices; a merge takes the union of the
    two proven ranges, which stays sound.
    """
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    sequence = tuple(words)
    if not sequence:
        raise ValueError("program has no instruction")
    decoded: list[tuple[str, dict[str, int]]] = []
    for index, word in enumerate(sequence):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"instruction {index} is not a 32-bit unsigned word: {word!r}")
        decoded.append(_decode(word, allow_branch=True))
    initial = [_UNKNOWN] * 32
    initial[0] = ("const", 0)
    if 0 <= base_reg < 32:
        initial[base_reg] = ("window", 0, 0)
    states: list[list[object] | None] = [None] * len(sequence)
    states[0] = initial
    for index, (name, operands) in enumerate(decoded):
        current = states[index]
        if current is None:  # pragma: no cover - every index has a predecessor
            current = [_UNKNOWN] * 32
            states[index] = current
        write = operands.get("rd")
        outgoing = list(current)
        if write is not None:
            if write == 0:
                pass
            elif write == base_reg:
                # A program that rewrites x18 loses the data-window base: every
                # later address derived from it is unproven.
                outgoing[base_reg] = _UNKNOWN
            else:
                outgoing[write] = _transfer_provenance(name, operands,
                                                       current)
        for successor in _successor_indices(name, operands, index,
                                            len(sequence)):
            if successor >= len(sequence):
                continue
            existing = states[successor]
            if existing is None:
                states[successor] = list(outgoing)
            else:
                states[successor] = [_merge_provenance(a, b)
                                     for a, b in zip(existing, outgoing)]
    return [state if state is not None else [_UNKNOWN] * 32
            for state in states], decoded


def _memory_uses(words: Sequence[int], *,
                 window_bytes: int | None,
                 base_reg: int = _MEMORY_BASE,
                 ) -> tuple[list[AddressUse], list[dict[str, int]]]:
    """Prove every memory word's address, or raise naming the first failure."""
    states, decoded = _provenance_states(
        words, window_bytes=window_bytes, base_reg=base_reg)
    uses: list[AddressUse] = []
    details: list[dict[str, int]] = []
    for index, (name, operands) in enumerate(decoded):
        if name not in _MEMORY_NAMES:
            continue
        base = operands["rs1"]
        provenance = states[index][base]
        if _provenance_kind(provenance) != "window":
            raise ValueError(
                f"instruction {index} memory access base x{base} is not a "
                "statically proven data-window address")
        low = provenance[1] + operands["imm"]
        high = provenance[2] + operands["imm"]
        if low % 4 or high % 4:
            raise ValueError(
                f"instruction {index} memory access address is not 4-byte "
                f"aligned (offset range {low}..{high})")
        if window_bytes is not None and (low < 0 or high > window_bytes - 4):
            raise ValueError(
                f"instruction {index} memory access leaves the declared data "
                f"window (offset range {low}..{high}, window {window_bytes})")
        uses.append(AddressUse(index, base, operands["imm"], 4))
        details.append({"index": index, "base_reg": base,
                        "offset": operands["imm"], "width": 4,
                        "low": low, "high": high})
    return uses, details


def address_provenance(words: Sequence[int], *,
                       window_bytes: int | None = None,
                       base_reg: int = _MEMORY_BASE,
                       ) -> list[AddressUse]:
    """Report one proven address per memory instruction.

    Each entry is ``(index, base_reg, offset, width)``: the word index, the
    ``rs1`` the memory word names, that word's own immediate and the access width
    (four bytes).  The register provenance is computed statically from the words
    alone, following forward branches as a may-analysis.  A memory word whose
    base is not provably ``data_base + d`` raises :class:`ValueError` naming the
    instruction, as does a proven displacement that is unaligned or (when
    ``window_bytes`` is given) outside the declared window.

    The proof needs no assumption about the window's alignment: ``ANDI`` is
    folded only on a proven constant offset, never on a proven address (a mask
    applied to an address clears the base's high bits, so it cannot stay an
    address).
    """
    window = _check_window(window_bytes)
    uses, _ = _memory_uses(words, window_bytes=window, base_reg=base_reg)
    return uses


def address_provenance_details(words: Sequence[int], *,
                               window_bytes: int | None = None,
                               base_reg: int = _MEMORY_BASE,
                               ) -> list[dict[str, int]]:
    """Like :func:`address_provenance`, with the proven displacement interval.

    Each entry has ``index``, ``base_reg``, ``offset``, ``width``, ``low`` and
    ``high``; the effective address is in
    ``[data_base + low, data_base + high]`` (all values 4-byte aligned).
    """
    window = _check_window(window_bytes)
    _, details = _memory_uses(words, window_bytes=window, base_reg=base_reg)
    return details


def validate_address_program(words: Sequence[int], window_bytes: int, *,
                             base_reg: int = _MEMORY_BASE,
                             ) -> None:
    """Raise :class:`ValueError` unless every memory address is proven in-window.

    This is the soundness gate for the address forms: every ``LW``/``SW`` must
    name either ``x18`` with a 4-byte aligned in-window immediate (the legacy
    shape) or a register statically proven to hold ``data_base + d`` with an
    immediate of 0; the whole proven displacement interval must be 4-byte aligned
    and inside ``[0, window_bytes - 4]``.  The proof needs no assumption about
    the window's alignment.  The function has no side effects.
    """
    window = _check_window(window_bytes)
    if window is None:
        raise ValueError("window_bytes must be an integer, not None")
    _memory_uses(words, window_bytes=window, base_reg=base_reg)


def _reserved_set(reserved: object) -> frozenset[int]:
    try:
        values = tuple(reserved)  # type: ignore[arg-type]
    except TypeError:
        raise ValueError(
            "reserved must be a sequence of register numbers") from None
    for reg in values:
        if type(reg) is not int or not 0 <= reg < 32:
            raise ValueError(
                f"reserved register {reg!r} is not an integer in [0, 31]")
    return frozenset(values)


def _reserved_label(reg: int) -> str:
    return _RESERVED_LABELS.get(reg, "register")


def _extension_available(profile: RiscvProfile, name: str) -> bool:
    extension = CATALOG[name].extension
    if extension == "I":
        return profile.has("I") or profile.has("E")
    return profile.has(extension)


def _allocatable(profile: RiscvProfile, reserved: frozenset[int]) -> tuple[int, ...]:
    """Destination registers: x1..x(register_count-1) minus the reserved set."""
    return tuple(reg for reg in range(1, profile.register_count)
                 if reg not in reserved)


def _sources(profile: RiscvProfile, written: set[int]) -> tuple[int, ...]:
    """Legal source registers: x0 plus registers written earlier, sorted."""
    return tuple(sorted({0} | {reg for reg in written
                               if reg < profile.register_count}))


def _pick_source(rng: random.Random, sources: tuple[int, ...]) -> int:
    if len(sources) > 1 and rng.random() < _DEPENDENCY_BIAS:
        return rng.choice(sources[1:])
    return rng.choice(sources)


def _reg_names(profile: RiscvProfile) -> tuple[str, ...]:
    return _GEN_R_NAMES + _GEN_M_NAMES if profile.has("M") else _GEN_R_NAMES


def _emit_word(rng: random.Random, profile: RiscvProfile, dests: tuple[int, ...],
               sources: tuple[int, ...], allow_memory: bool,
               window_size: int, allow_auipc: bool = True,
               ) -> tuple[int, str, dict[str, int]]:
    """Emit one legal instruction of the emittable subset.

    ``dests`` and ``sources`` are the caller's per-position register choices, so
    dependencies and the reserved-register rule stay in one place.
    ``allow_auipc=False`` keeps ``AUIPC`` out of the upper-immediate family.
    """
    families = ["upper", "imm", "shift", "register"]
    if allow_memory:
        families.append("memory")
    family = rng.choice(families)
    if family == "memory":
        name = rng.choice(_MEMORY_NAMES)
        offset = _pick_offset(rng, window_size)
        if name == "LW":
            operands = {"rd": rng.choice(dests), "rs1": _MEMORY_BASE,
                        "imm": offset}
        else:
            operands = {"rs2": _pick_source(rng, sources), "rs1": _MEMORY_BASE,
                        "imm": offset}
    elif family == "upper":
        names = _GEN_UPPER_NAMES if allow_auipc else ("LUI",)
        name = rng.choice(names)
        operands = {"rd": rng.choice(dests), "imm": rng.randrange(1 << 20)}
    elif family == "imm":
        name = rng.choice(_GEN_IMM_NAMES)
        operands = {"rd": rng.choice(dests), "rs1": _pick_source(rng, sources),
                    "imm": rng.randrange(-2048, 2048)}
    elif family == "shift":
        name = rng.choice(_GEN_SHIFT_NAMES)
        operands = {"rd": rng.choice(dests), "rs1": _pick_source(rng, sources),
                    "shamt": rng.randrange(32)}
    else:
        name = rng.choice(_reg_names(profile))
        operands = {"rd": rng.choice(dests), "rs1": _pick_source(rng, sources),
                    "rs2": _pick_source(rng, sources)}
    return encode(name, xlen=32, **operands), name, operands


def _pick_offset(rng: random.Random, window_size: int) -> int:
    """One 4-byte aligned offset both inside the window and encodable."""
    return rng.randrange(_offset_limit(window_size) // 4 + 1) * 4


def _fresh_destination(rng: random.Random, dests: tuple[int, ...],
                       written: Sequence[int]) -> int:
    """A destination not written yet, or any allocatable one when all are used."""
    used = set(written)
    unused = tuple(reg for reg in dests if reg not in used)
    return rng.choice(unused) if unused else rng.choice(dests)


def _structured_root(rng: random.Random, rd: int, allow_auipc: bool) -> int:
    """A word that starts a chain: it reads only ``x0``.

    The immediate form keeps a non-zero immediate so a chain root is not a
    constant zero, which would make the dependent words less informative.
    """
    if allow_auipc and rng.random() < 0.35:
        return encode("AUIPC", xlen=32, rd=rd, imm=rng.randrange(1 << 20))
    if rng.random() < 0.65:
        return encode("LUI", xlen=32, rd=rd, imm=rng.randrange(1 << 20))
    name = rng.choice(("ADDI", "XORI", "ORI", "ANDI"))
    immediate = rng.randrange(-2048, 2048) or 1
    return encode(name, xlen=32, rd=rd, rs1=0, imm=immediate)


def _structured_derived(rng: random.Random, profile: RiscvProfile, rd: int,
                        sources: tuple[int, ...], force_m: bool = False) -> int:
    """An ALU word that reads at least one register the program already wrote."""
    if not sources:
        raise AssertionError("a derived word needs one earlier register")
    first = rng.choice(sources)
    second = rng.choice(sources) if len(sources) > 1 else first
    roll = rng.random()
    if force_m or roll < 0.34:
        names = _GEN_M_NAMES if (force_m and profile.has("M")) else _reg_names(profile)
        name = rng.choice(names)
        return encode(name, xlen=32, rd=rd, rs1=first, rs2=second)
    if roll < 0.62:
        name = rng.choice(_GEN_IMM_NAMES)
        return encode(name, xlen=32, rd=rd, rs1=first,
                      imm=rng.randrange(-2048, 2048))
    name = rng.choice(_GEN_SHIFT_NAMES)
    return encode(name, xlen=32, rd=rd, rs1=first, shamt=rng.randrange(32))


def _structured_words(rng: random.Random, profile: RiscvProfile,
                      dests: tuple[int, ...], length: int, window_size: int,
                      allow_auipc: bool) -> tuple[int, ...]:
    """Emit a dependency skeleton of exactly ``length`` words.

    The roles come from :data:`_STRUCTURED_TOUR`, truncated to ``length``, so
    every emitted program is a prefix of one shape: a chain root, ALU words that
    consume it, memory words that store a computed value and load the same
    offset back, a load value fed to a second store, a second chain joined to
    the first, repeated addresses and a final consumer.  Memory roles degrade to
    ALU words when the profile has no ``x18`` or the slot holds one word.
    """
    allow_memory = length > 1 and profile.register_count > _MEMORY_BASE
    written: list[int] = []
    offsets: list[int] = []
    chain: int | None = None
    prior_chain: int | None = None
    first_root: int | None = None
    last_loaded: int | None = None
    last_offset: int | None = None
    words: list[int] = []

    def pool() -> tuple[int, ...]:
        candidates = [reg for reg in (chain, last_loaded, first_root)
                      if reg is not None]
        candidates.extend(reversed(written))
        return tuple(dict.fromkeys(candidates))

    def derived(sources: tuple[int, ...] | None = None,
                force_m: bool = False) -> int:
        nonlocal chain
        rd = _fresh_destination(rng, dests, written)
        words.append(_structured_derived(rng, profile, rd,
                                         pool() if sources is None else sources,
                                         force_m))
        written.append(rd)
        chain = rd
        return rd

    def joined(first: int | None, second: int | None) -> None:
        """An R word that really reads both chain registers."""
        nonlocal chain
        left = first if first is not None else 0
        right = second if second is not None else left
        rd = _fresh_destination(rng, dests, written)
        name = rng.choice(_reg_names(profile))
        words.append(encode(name, xlen=32, rd=rd, rs1=left, rs2=right))
        written.append(rd)
        chain = rd

    for role in _STRUCTURED_TOUR[:length]:
        if role in _MEMORY_ROLES and not allow_memory:
            role = "derive"
        if role == "root":
            prior_chain = chain
            rd = _fresh_destination(rng, dests, written)
            words.append(_structured_root(rng, rd, allow_auipc))
            written.append(rd)
            chain = rd
            if first_root is None:
                first_root = rd
        elif role == "derive":
            derived()
        elif role == "consume_load":
            # The register a load just wrote is the first source, so the
            # load -> ALU edge exists by construction.
            derived((last_loaded,) if last_loaded is not None else None)
        elif role == "join":
            joined(chain, prior_chain)
        elif role == "store":
            offset = _pick_offset(rng, window_size)
            words.append(encode("SW", xlen=32, rs2=chain or 0,
                                rs1=_MEMORY_BASE, imm=offset))
            offsets.append(offset)
            last_offset = offset
        elif role == "copy_store":
            # The value a load brought into a register is stored again: a load
            # feeding a store at a fresh address.
            offset = _pick_offset(rng, window_size)
            source = last_loaded if last_loaded is not None else (chain or 0)
            words.append(encode("SW", xlen=32, rs2=source,
                                rs1=_MEMORY_BASE, imm=offset))
            offsets.append(offset)
            last_offset = offset
        elif role == "store_repeat":
            # Rewrite an address this program already used: a repeated address
            # whose final value is the one the next load reads back.
            offset = offsets[0] if offsets else _pick_offset(rng, window_size)
            source = last_loaded if last_loaded is not None else (chain or 0)
            words.append(encode("SW", xlen=32, rs2=source,
                                rs1=_MEMORY_BASE, imm=offset))
            offsets.append(offset)
            last_offset = offset
        elif role == "load":
            offset = last_offset if last_offset is not None else \
                _pick_offset(rng, window_size)
            rd = _fresh_destination(rng, dests, written)
            words.append(encode("LW", xlen=32, rd=rd, rs1=_MEMORY_BASE,
                                imm=offset))
            written.append(rd)
            chain = rd
            last_loaded = rd
        elif role == "mul":
            derived(force_m=True)
        elif role == "shift":
            rd = _fresh_destination(rng, dests, written)
            name = rng.choice(_GEN_SHIFT_NAMES)
            words.append(encode(name, xlen=32, rd=rd,
                                rs1=chain if chain is not None else 0,
                                shamt=rng.randrange(32)))
            written.append(rd)
            chain = rd
        else:  # "final"
            derived()
    return tuple(words)


_BRANCH_NAME_ORDER = ("BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU")
#: The opt-in address forms and how many words each needs (base word(s) plus the
#: memory word).  ``addi`` is the smallest; ``add`` proves a constant register
#: first; ``andi`` masks a displaced base and needs a declared base alignment.
_ADDRESS_FORMS = ("addi", "add", "andi")


def _check_flag_argument(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _plain_words(rng: random.Random, profile: RiscvProfile,
                 dests: tuple[int, ...], length: int, window_size: int,
                 allow_auipc: bool, allow_memory: bool) -> tuple[int, ...]:
    """The historical independent-draw emitter, reused as a filler."""
    built: list[int] = []
    written: set[int] = set()
    for _ in range(length):
        word, _, operands = _emit_word(
            rng, profile, dests, _sources(profile, written), allow_memory,
            window_size, allow_auipc)
        built.append(word)
        if "rd" in operands:
            written.add(operands["rd"])
    return tuple(built)


def _address_form_length(form: str) -> int:
    return {"addi": 2, "add": 3, "lui": 4, "andi": 4}[form]


def _address_memory_word(rng: random.Random, dests: tuple[int, ...],
                         base_reg: int,
                         written: Sequence[int]) -> tuple[int, int | None]:
    """An ``LW``/``SW`` at the proven base with immediate 0."""
    if rng.random() < 0.5:
        destination = _fresh_destination(rng, dests, written)
        return (encode("LW", xlen=32, rd=destination, rs1=base_reg, imm=0),
                destination)
    source = rng.choice(tuple(written)) if written else 0
    return encode("SW", xlen=32, rs2=source, rs1=base_reg, imm=0), None


def _address_words(rng: random.Random, profile: RiscvProfile,
                   dests: tuple[int, ...], length: int, window_size: int,
                   allow_auipc: bool) -> tuple[int, ...]:
    """A program whose memory words use a computed base register.

    Each form is a prefix followed by ``LW``/``SW xd, 0``:

    * ``ADDI xd, x18, k`` (two words);
    * ``ADDI xm, x0, k`` + ``ADD xd, x18, xm`` (three words);
    * ``LUI xm, 0`` + ``ADDI xm, xm, k`` + ``ADD xd, x18, xm`` (four words, the
      LUI/ADDI constant form);
    * ``ADDI xm, x0, k`` + ``ANDI xm, xm, window_size - 4`` + ``ADD xd, x18, xm``
      (four words; the mask folds the *offset*, which is the sound reading).

    Leftover slots are filled with ``_emit_word`` ALU words, never with an
    unproven memory word, so every emitted address is inside the window by
    construction.
    """
    if (length < 2 or profile.register_count <= _MEMORY_BASE or not dests):
        return _plain_words(rng, profile, dests, length, window_size,
                            allow_auipc, allow_memory=False)
    forms = ["addi"]
    if len(dests) >= 2:
        forms.extend(("add", "lui"))
        # The masking form needs its mask to be a signed 12-bit immediate.
        if window_size - 4 <= _MAX_MEMORY_OFFSET:
            forms.append("andi")
    words: list[int] = []
    written: list[int] = []
    while len(words) < length:
        remaining = length - len(words)
        available = [form for form in forms
                     if _address_form_length(form) <= remaining]
        if not available:
            word, _, operands = _emit_word(
                rng, profile, dests, _sources(profile, set(written)), False,
                window_size, allow_auipc)
            words.append(word)
            destination = operands.get("rd")
            if destination:
                written.append(destination)
            continue
        form = rng.choice(available)
        if form == "addi":
            displacement = 4 * rng.randrange(_offset_limit(window_size) // 4 + 1)
            base = _fresh_destination(rng, dests, written)
            words.append(encode("ADDI", xlen=32, rd=base, rs1=_MEMORY_BASE,
                                imm=displacement))
            written.append(base)
        elif form == "add":
            limit = min(60, _offset_limit(window_size))
            constant = 4 * rng.randrange(limit // 4 + 1)
            constant_reg = _fresh_destination(rng, dests, written)
            words.append(encode("ADDI", xlen=32, rd=constant_reg, rs1=0,
                                imm=constant))
            written.append(constant_reg)
            base = _fresh_destination(rng, dests, written)
            if rng.random() < 0.5:
                words.append(encode("ADD", xlen=32, rd=base,
                                    rs1=_MEMORY_BASE, rs2=constant_reg))
            else:
                words.append(encode("ADD", xlen=32, rd=base,
                                    rs1=constant_reg, rs2=_MEMORY_BASE))
            written.append(base)
        elif form == "lui":
            constant = 4 * rng.randrange(min(60, _offset_limit(window_size)) // 4 + 1)
            constant_reg = _fresh_destination(rng, dests, written)
            words.append(encode("LUI", xlen=32, rd=constant_reg, imm=0))
            words.append(encode("ADDI", xlen=32, rd=constant_reg,
                                rs1=constant_reg, imm=constant))
            written.append(constant_reg)
            base = _fresh_destination(rng, dests, written)
            words.append(encode("ADD", xlen=32, rd=base, rs1=_MEMORY_BASE,
                                rs2=constant_reg))
            written.append(base)
        else:  # "andi": mask the constant *offset* before adding x18.
            constant_reg = _fresh_destination(rng, dests, written)
            words.append(encode("ADDI", xlen=32, rd=constant_reg, rs1=0,
                                imm=rng.randrange(64)))
            words.append(encode("ANDI", xlen=32, rd=constant_reg,
                                rs1=constant_reg, imm=window_size - 4))
            written.append(constant_reg)
            base = _fresh_destination(rng, dests, written)
            words.append(encode("ADD", xlen=32, rd=base, rs1=_MEMORY_BASE,
                                rs2=constant_reg))
            written.append(base)
        word, destination = _address_memory_word(rng, dests, base, written)
        words.append(word)
        if destination:
            written.append(destination)
    return tuple(words)


def _forward_branch(rng: random.Random, dests: tuple[int, ...],
                    written: Sequence[int], index: int,
                    length: int) -> int:
    """One legal forward branch word at ``index``.

    The target is chosen from ``index + 2 .. length`` (so a word is skipped when
    the image is long enough) or exactly ``length``, the appended return jump.
    """
    name = rng.choice(_BRANCH_NAME_ORDER)
    candidates = [0] + [reg for reg in written if reg and reg in dests]
    if not candidates:  # pragma: no cover - generation always writes a root
        candidates = [0]
    rs1 = rng.choice(candidates)
    rs2 = rng.choice(candidates)
    lowest = index + 2
    if lowest > length:
        lowest = length
    target = rng.randint(lowest, length)
    return encode(name, xlen=32, rs1=rs1, rs2=rs2, imm=4 * (target - index))


def _branch_words(rng: random.Random, profile: RiscvProfile,
                  dests: tuple[int, ...], length: int, window_size: int,
                  allow_auipc: bool,
                  allow_memory: bool) -> tuple[int, ...]:
    """A dependency root, a forward branch over one or more words, then fillers."""
    if length < 2 or not dests:
        return _plain_words(rng, profile, dests, length, window_size,
                            allow_auipc, allow_memory=False)
    written: list[int] = []
    words: list[int] = []
    root = _fresh_destination(rng, dests, written)
    words.append(_structured_root(rng, root, allow_auipc))
    written.append(root)
    words.append(_forward_branch(rng, dests, written, 1, length))
    while len(words) < length:
        word, _, operands = _emit_word(
            rng, profile, dests, _sources(profile, set(written)), allow_memory,
            window_size, allow_auipc)
        words.append(word)
        destination = operands.get("rd")
        if destination:
            written.append(destination)
    if length >= 5 and rng.random() < 0.5:
        index = rng.randint(3, length - 2)
        words[index] = _forward_branch(rng, dests, written, index, length)
    return tuple(words)


def _extended_words(rng: random.Random, profile: RiscvProfile,
                    dests: tuple[int, ...], length: int, window_size: int,
                    allow_auipc: bool, allow_memory: bool) -> tuple[int, ...]:
    """Both opt-in shapes in one image: address-form memory word, then a branch."""
    if (length < 3 or profile.register_count <= _MEMORY_BASE or not dests):
        if length >= 2:
            return _address_words(rng, profile, dests, length, window_size,
                                  allow_auipc)
        return _plain_words(rng, profile, dests, length, window_size,
                            allow_auipc, allow_memory=False)
    displacement = 4 * rng.randrange(_offset_limit(window_size) // 4 + 1)
    base = _fresh_destination(rng, dests, ())
    words: list[int] = [encode("ADDI", xlen=32, rd=base, rs1=_MEMORY_BASE,
                               imm=displacement)]
    written: list[int] = [base]
    word, destination = _address_memory_word(rng, dests, base, written)
    words.append(word)
    if destination:
        written.append(destination)
    words.append(_forward_branch(rng, dests, written, 2, length))
    while len(words) < length:
        word, _, operands = _emit_word(
            rng, profile, dests, _sources(profile, set(written)), allow_memory,
            window_size, allow_auipc)
        words.append(word)
        destination = operands.get("rd")
        if destination:
            written.append(destination)
    return tuple(words)


def _delegate_compressed(profile: RiscvProfile, *, seed: int, max_words: int,
                         window_size: int, reserved: tuple[int, ...],
                         min_words: int) -> ShortProgram:
    """Build a compressed program through the dedicated module (lazy import)."""
    from .rv32_compressed import generate_compressed_program

    return generate_compressed_program(
        profile, seed=seed, max_words=max_words, window_size=window_size,
        reserved=reserved, min_words=min_words)


def _program_from_words(profile: RiscvProfile, seed: int, max_words: int,
                        words: tuple[int, ...],
                        style: str = "random") -> ShortProgram:
    compressed = any(word & 3 != 3 for word in words)
    if compressed:
        from .rv32_compressed import compressed_program_word

        instructions = [compressed_program_word(word) for word in words]
        return ShortProgram(profile, seed, max_words, words,
                            tuple(instructions), style, True)
    branching = any(word & 0x7F == _BRANCH_OPCODE for word in words)
    jumping = any(word & 0x7F in _JUMP_OPCODES for word in words)
    instructions = []
    for word in words:
        name, operands = _decode(word, allow_branch=branching,
                                 allow_jump=jumping)
        instructions.append(ProgramWord(word, format_assembly(name, operands),
                                        name, dict(operands)))
    return ShortProgram(profile, seed, max_words, words, tuple(instructions),
                        style)


def _written_before(words: tuple[int, ...], position: int,
                    allow_branches: bool = False) -> set[int]:
    written: set[int] = set()
    for word in words[:position]:
        _, operands = _decode(word, allow_branch=allow_branches)
        if "rd" in operands:
            written.add(operands["rd"])
    return written


def _chosen_length(rng: random.Random, max_words: int, min_words: int) -> int:
    """The classic length draw, raised to ``min_words`` when one is given."""
    if max_words == 1:
        return 1
    if min_words > 1:
        return rng.randint(min_words, max_words)
    if rng.random() < 0.25:
        return 1
    return rng.randint(2, max_words)


def generate_program(profile: RiscvProfile, *, seed: int, max_words: int,
                     window_size: int,
                     reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                     min_words: int = 1, style: str = "mixed",
                     allow_auipc: bool = True,
                     allow_branches: bool = False,
                     allow_address_forms: bool = False,
                     allow_compressed: bool = False,
                     allow_jumps: bool = False,
                     allow_loops: bool = False,
                     image_base: int | None = None,
                     ) -> ShortProgram:
    """Generate one deterministic legal trampoline program.

    ``max_words`` bounds the length (1..16) and selects the mode: with
    ``max_words == 1`` the program is the legacy single-word F1 input and never
    contains a memory instruction, while multi-word mode may use ``LW``/``SW``
    inside ``[0, window_size - 4]`` relative to ``x18``.  ``window_size`` is
    validated even in single-word mode where it is unused.

    ``min_words`` raises the lower bound (never above ``max_words``) so a caller
    can ask for programs long enough to hold a data flow.  ``style`` selects the
    emitter: ``"random"`` keeps the pre-expansion independent draws word for
    word, ``"chains"`` emits the dependency skeleton, ``"mixed"`` (default) draws
    a per-seed coin, and the opt-in styles ``"address"``, ``"branch"`` and
    ``"compressed"`` exercise the corresponding shape (each requires its flag).
    ``"extended"`` composes the address and branch shapes.  ``allow_auipc=False``
    keeps ``AUIPC`` out of the program, which is what the unified entry's record
    gate requires today.

    ``allow_address_forms`` lets a memory word use a statically proven computed
    base per :func:`address_provenance` (``ADDI``/``ADD`` with a constant, and a
    masked constant offset).
    ``allow_branches`` admits forward B-type branches.  ``allow_compressed``
    hands generation to :func:`myfuzz.fuzz.rv32_compressed.generate_compressed_program`
    and requires a profile declaring ``C`` with 2-byte alignment.
    ``allow_jumps``/``allow_loops`` hand generation to
    :func:`generate_jump_program`/:func:`generate_loop_program` (styles
    ``"jump"``/``"loop"``, or a ``"mixed"`` upgrade when enabled), and
    ``image_base`` is the slot address a ``JALR`` needs for its absolute target.
    Every flag defaults to ``False``, so all existing calls keep their exact
    output.
    """
    _check_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    style_name = _check_style(style)
    upper_immediate = _check_allow_auipc(allow_auipc)
    branches = _check_flag_argument(allow_branches, "allow_branches")
    address_forms = _check_flag_argument(allow_address_forms,
                                         "allow_address_forms")
    compressed = _check_flag_argument(allow_compressed, "allow_compressed")
    jumping = _check_flag_argument(allow_jumps, "allow_jumps")
    looping = _check_flag_argument(allow_loops, "allow_loops")
    if style_name == "address" and not address_forms:
        raise ValueError(
            "style 'address' requires allow_address_forms=True")
    if style_name == "branch" and not branches:
        raise ValueError("style 'branch' requires allow_branches=True")
    if style_name == "compressed" and not compressed:
        raise ValueError("style 'compressed' requires allow_compressed=True")
    if style_name == "extended" and not (address_forms and branches):
        raise ValueError(
            "style 'extended' requires allow_address_forms=True and "
            "allow_branches=True")
    if style_name == "jump" and not jumping:
        raise ValueError("style 'jump' requires allow_jumps=True")
    if style_name == "loop" and not looping:
        raise ValueError("style 'loop' requires allow_loops=True")
    if style_name == "jump":
        return generate_jump_program(profile, seed=seed, max_words=max_words,
                                     window_size=window, reserved=reserved,
                                     min_words=max(min_length, 3),
                                     image_base=image_base)
    if style_name == "loop":
        return generate_loop_program(profile, seed=seed, max_words=max_words,
                                     window_size=window, reserved=reserved,
                                     min_words=max(min_length, 4),
                                     image_base=image_base)
    dests = _allocatable(profile, reserved_set)
    if not dests:
        raise ValueError("no allocatable destination register for this profile")
    # x18 exists only on a full 32-register profile, and single-word mode is
    # the legacy F1 input, so both conditions gate every memory instruction.
    allow_memory = max_words > 1 and profile.register_count > _MEMORY_BASE
    rng = random.Random(seed)
    length = _chosen_length(rng, max_words, min_length)
    # A one-word program has no chain to build, so the coin is only drawn when
    # the program can hold one; that also keeps a ``mixed`` one-word program
    # word-for-word identical to a ``random`` one.
    use_chains = style_name == "chains" or (
        style_name == "mixed" and length > 1
        and rng.random() < _MIXED_CHAIN_CHANCE)
    shape = "chains" if use_chains else "random"
    if style_name in ("address", "branch", "compressed", "extended"):
        shape = style_name
    elif style_name == "mixed":
        enabled = [name for name, flag in (
            ("address", address_forms), ("branch", branches),
            ("compressed", compressed), ("jump", jumping),
            ("loop", looping)) if flag]
        # Only an explicitly enabled shape can upgrade a ``mixed`` draw, so a
        # default call consumes exactly the old random stream.
        if enabled and rng.random() < _MIXED_OPT_IN_CHANCE:
            shape = rng.choice(enabled)
    if shape == "compressed":
        return _delegate_compressed(profile, seed=seed, max_words=max_words,
                                    window_size=window, reserved=reserved,
                                    min_words=min_length)
    if shape == "jump":
        return generate_jump_program(profile, seed=seed, max_words=max_words,
                                     window_size=window, reserved=reserved,
                                     min_words=min(max(min_length, 3), max_words),
                                     image_base=image_base)
    if shape == "loop":
        return generate_loop_program(profile, seed=seed, max_words=max_words,
                                     window_size=window, reserved=reserved,
                                     min_words=min(max(min_length, 4), max_words),
                                     image_base=image_base)
    if shape == "address":
        words = _address_words(rng, profile, dests, length, window,
                               upper_immediate)
        validate_program_words(profile, words, window_size=window,
                               reserved=reserved, allow_address_forms=True)
    elif shape == "branch":
        words = _branch_words(rng, profile, dests, length, window,
                              upper_immediate, allow_memory)
        validate_program_words(profile, words, window_size=window,
                               reserved=reserved, allow_branches=True)
    elif shape == "extended":
        words = _extended_words(rng, profile, dests, length, window,
                                upper_immediate, allow_memory)
        validate_program_words(profile, words, window_size=window,
                               reserved=reserved, allow_branches=True,
                               allow_address_forms=True)
    elif shape == "chains":
        words = _structured_words(rng, profile, dests, length, window,
                                  upper_immediate)
    else:
        built: list[int] = []
        written: set[int] = set()
        for _ in range(length):
            word, _, operands = _emit_word(
                rng, profile, dests, _sources(profile, written), allow_memory,
                window, upper_immediate)
            built.append(word)
            if "rd" in operands:
                written.add(operands["rd"])
        words = tuple(built)
    return _program_from_words(profile, seed, max_words, tuple(words), shape)


def _has_alternative(choices: Sequence[int], current: int) -> bool:
    count = len(choices)
    if count == 0:
        return False
    if count == 1:
        return choices[0] != current
    return True


def _different_choice(rng: random.Random, choices: Sequence[int],
                      current: int) -> int | None:
    """Pick a value from ``choices`` that differs from ``current``."""
    count = len(choices)
    if count == 0:
        return None
    pick = rng.randrange(count)
    value = choices[pick]
    if value != current:
        return value
    if count == 1:
        return None
    # The successor of a rejected pick always differs from ``current``.
    return choices[(pick + 1) % count]


def _branch_target_offsets(index: int, length: int) -> tuple[int, ...]:
    """Every legal displacement for a branch at ``index``.

    The fall-through target (one word ahead) and every word up to the appended
    return jump at index ``length``; all are strictly forward and aligned.
    """
    return tuple(4 * (target - index)
                 for target in range(index + 1, length + 1))


# --- opt-in jump and loop generators ---------------------------------------


def _fresh_alu_word(rng: random.Random, profile: RiscvProfile,
                    dests: tuple[int, ...], sources: Sequence[int],
                    *, allow_memory: bool = False,
                    window_size: int = DEFAULT_WINDOW_BYTES) -> int:
    """One ALU word that reads a declared source and writes a fresh register."""
    name = rng.choice(_GEN_IMM_NAMES + _GEN_SHIFT_NAMES + _GEN_R_NAMES)
    destination = rng.choice(dests)
    source = rng.choice(tuple(sources) or (0,))
    if name in _GEN_IMM_NAMES:
        return encode(name, xlen=32, rd=destination, rs1=source,
                      imm=rng.choice((-3, -1, 1, 2, 3, 5, 7, 9, 11, 0x55, 0x2a)))
    if name in _GEN_SHIFT_NAMES:
        return encode(name, xlen=32, rd=destination, rs1=source,
                      shamt=rng.randrange(1, 16))
    return encode(name, xlen=32, rd=destination, rs1=source, rs2=source)


def _lui_addi_constant(register: int, value: int) -> tuple[int, ...]:
    """One or two words that load an exact 32-bit constant (LUI + ADDI)."""
    upper = (value >> 12) & 0xFFFFF
    lower = value & 0xFFF
    if lower & 0x800:
        upper = (upper + 1) & 0xFFFFF
        lower -= 0x1000
    if lower == 0:
        return (encode("LUI", xlen=32, rd=register, imm=upper),)
    return (encode("LUI", xlen=32, rd=register, imm=upper),
            encode("ADDI", xlen=32, rd=register, rs1=register, imm=lower))


def generate_jump_program(profile: RiscvProfile, *, seed: int, max_words: int,
                          window_size: int,
                          reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                          min_words: int = 3,
                          image_base: int | None = None,
                          allow_jalr: bool = True) -> ShortProgram:
    """Generate one deterministic legal program with a statically known jump.

    The image starts with a dependency root, then a ``JAL`` (or, when
    ``image_base`` is given and ``allow_jalr`` is set, a ``LUI``/``ADDI``/
    ``JALR`` sequence whose base register is a proven constant) that jumps
    forward over at least one word, then ALU fillers that read only registers
    the program wrote.  The result is validated with ``allow_jumps=True``
    before it is returned, so every target is an instruction start of the image
    and every ``JALR`` base is a statically proven constant.
    """
    profile = _check_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    if image_base is not None and (type(image_base) is not int
                                   or not 0 <= image_base <= _MASK32):
        raise ValueError("image_base must be a 32-bit unsigned integer or None")
    dests = _allocatable(profile, reserved_set)
    if not dests:
        raise ValueError("no allocatable destination register for this profile")
    if max_words < 3:
        raise ValueError("a jump program needs at least three words")
    rng = random.Random(seed)
    length = _chosen_length(rng, max_words, max(min_length, 3))
    words: list[int] = []
    written: list[int] = []
    root = _fresh_destination(rng, dests, written)
    words.append(_structured_root(rng, root, False))
    written.append(root)
    link = rng.choice((0, 1))
    use_jalr = (allow_jalr and image_base is not None
                and len(words) + 3 < length and rng.random() < 0.5)
    if use_jalr:
        base = _fresh_destination(rng, dests, written)
        target = rng.randint(len(words) + 3, length)
        words.extend(_lui_addi_constant(base, image_base + 4 * target))
        written.append(base)
        words.append(encode("JALR", xlen=32, rd=link, rs1=base, imm=0))
        if link:
            written.append(link)
    else:
        target = rng.randint(len(words) + 2, length)
        words.append(encode("JAL", xlen=32, rd=link, imm=4 * (target - 1)))
        if link:
            written.append(link)
    while len(words) < length:
        sources = (0, _MEMORY_BASE, *written) if profile.register_count > _MEMORY_BASE \
            else (0, *written)
        words.append(_fresh_alu_word(rng, profile, dests, sources))
    validate_program_words(profile, tuple(words), window_size=window,
                           reserved=reserved, allow_jumps=True,
                           image_base=image_base)
    return _program_from_words(profile, seed, max_words, tuple(words), "jump")


def generate_loop_program(profile: RiscvProfile, *, seed: int, max_words: int,
                          window_size: int,
                          reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                          min_words: int = 4,
                          image_base: int | None = None) -> ShortProgram:
    """Generate one deterministic legal program with a bounded loop.

    The canonical shape of the module docstring: ``addi xN, x0, K`` (K in
    2..6), a body of ALU words that never writes ``xN``, ``addi xN, xN, -1``,
    ``bne xN, x0, head``, then zero or more trailing words that execute once
    after the loop.  Every body read is satisfied by a word the body itself
    wrote first (or by ``x0``/``xN``), so the reference retirement trace is a
    function of the declared state.
    """
    profile = _check_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    min_length = _check_min_words(min_words, max_words)
    if max_words < 4:
        raise ValueError("a loop program needs at least four words")
    dests = tuple(register for register in _allocatable(profile, reserved_set)
                  if register not in _JUMP_LINK_REGISTERS)
    if len(dests) < 2:
        raise ValueError("a loop program needs two allocatable registers")
    rng = random.Random(seed)
    length = _chosen_length(rng, max_words, max(min_length, 4))
    induction, accumulator = dests[0], dests[1]
    trip = rng.randint(_LOOP_TRIP_MIN, _LOOP_TRIP_MAX)
    words: list[int] = [encode("ADDI", xlen=32, rd=induction, rs1=0, imm=trip)]
    head = len(words)
    body = length - 3
    # The body's first word writes the accumulator from x0, so every later body
    # word may read it; the induction register is read-only here.
    words.append(encode("ADDI", xlen=32, rd=accumulator, rs1=0,
                        imm=rng.choice((1, 2, 3, 5, 7))))
    for _ in range(body - 1):
        words.append(_fresh_alu_word(
            rng, profile, (accumulator,), (0, induction, accumulator)))
    words.append(encode("ADDI", xlen=32, rd=induction, rs1=induction, imm=-1))
    back_edge = len(words)
    words.append(encode("BNE", xlen=32, rs1=induction, rs2=0,
                        imm=4 * (head - back_edge)))
    while len(words) < length:
        words.append(_fresh_alu_word(
            rng, profile, (accumulator,), (0, induction, accumulator)))
    validate_program_words(profile, tuple(words), window_size=window,
                           reserved=reserved, allow_branches=True,
                           allow_loops=True, image_base=image_base)
    return _program_from_words(profile, seed, max_words, tuple(words), "loop")


def mutate_control_program(profile: RiscvProfile, program: ShortProgram, *,
                           seed: int, max_words: int, window_size: int,
                           reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                           allow_branches: bool = False,
                           allow_jumps: bool = False,
                           allow_loops: bool = False,
                           image_base: int | None = None) -> ShortProgram:
    """Apply exactly one structured mutation to a jump/loop program.

    The actions preserve the control-flow shape the flags admit: change a loop's
    trip count, retarget a ``JAL``, replace or re-immediate a non-control word,
    append one word when there is room, or delete the last word when it is not
    a control transfer.  The candidate is validated with the same whole-program
    pass as the generator; when no action produces a legal image the caller
    receives a freshly generated program of the same shape instead of an
    unverifiable one.
    """
    profile = _check_profile(profile)
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
    flags = dict(allow_branches=allow_branches, allow_jumps=allow_jumps,
                 allow_loops=allow_loops)
    validate_program_words(profile, program.words, window_size=window,
                           reserved=reserved, image_base=image_base, **flags)
    control = control_flow_analysis(program.words, image_base=image_base,
                                    reserved=reserved, **flags)
    control_indices = {entry.index for entry in control.jumps}
    control_indices.update(loop.back_edge for loop in control.loops)
    control_indices.update(loop.step for loop in control.loops)
    control_indices.update(loop.init for loop in control.loops)
    rng = random.Random(seed)
    dests = _allocatable(profile, reserved_set)
    words = list(program.words)
    original = tuple(program.words)

    def valid(candidate: list[int]) -> bool:
        if tuple(candidate) == original:
            return False
        try:
            validate_program_words(profile, tuple(candidate),
                                   window_size=window, reserved=reserved,
                                   image_base=image_base, **flags)
        except ValueError:
            return False
        return True

    actions = ["word"]
    if any(loop.trip_count for loop in control.loops):
        actions.append("trip")
    if control.jumps:
        actions.append("jump")
    if len(words) < max_words:
        actions.append("append")
    if len(words) > 1 and len(words) - 1 not in control_indices:
        actions.append("delete")
    rng.shuffle(actions)
    for action in actions:
        trial = list(words)
        if action == "trip":
            loop = rng.choice(control.loops)
            trip = rng.choice([value for value in
                               range(_LOOP_TRIP_MIN, _LOOP_TRIP_MAX + 1)
                               if value != loop.trip_count])
            trial[loop.init] = encode("ADDI", xlen=32, rd=loop.induction,
                                      rs1=0, imm=trip)
        elif action == "jump":
            jump = rng.choice(control.jumps)
            if jump.name != "JAL":
                continue
            choices = [target for target in range(jump.index + 1,
                                                 len(words) + 1)
                       if target != jump.target_index]
            if not choices:
                continue
            target = rng.choice(choices)
            trial[jump.index] = encode("JAL", xlen=32, rd=jump.link,
                                       imm=4 * (target - jump.index))
        elif action == "append":
            sources = (0, _MEMORY_BASE, *[register for register in range(1, 32)
                                          if register not in reserved_set])
            trial.append(_fresh_alu_word(rng, profile, dests, sources))
        elif action == "delete":
            del trial[-1]
        else:
            candidates = [index for index in range(len(trial))
                          if index not in control_indices]
            if not candidates:
                continue
            index = rng.choice(candidates)
            sources = (0, _MEMORY_BASE, *[register for register in range(1, 32)
                                          if register not in reserved_set])
            trial[index] = _fresh_alu_word(rng, profile, dests, sources)
        if valid(trial):
            return _program_from_words(profile, seed, max_words, tuple(trial),
                                       "mutation")
    # No in-place action kept the shape legal: a fresh program of the same shape
    # is still a legal input, and it is what the batch records.
    if allow_loops:
        return generate_loop_program(profile, seed=seed, max_words=max_words,
                                     window_size=window, reserved=reserved,
                                     image_base=image_base)
    return generate_jump_program(profile, seed=seed, max_words=max_words,
                                 window_size=window, reserved=reserved,
                                 image_base=image_base)


def _field_choices(name: str, field: str, profile: RiscvProfile,
                   reserved: frozenset[int],
                   window_size: int,
                   branch_offsets: Sequence[int] | None = None,
                   ) -> Sequence[int] | None:
    """Candidate values for one mutable operand field, or None if fixed."""
    if field == "rd":
        return _allocatable(profile, reserved)
    if field == "rs1":
        # Memory instructions are pinned to the x18 data-window base.
        return None if name in _MEMORY_NAMES else range(profile.register_count)
    if field == "rs2":
        return range(profile.register_count)
    if field == "shamt":
        return range(32)
    if field == "imm":
        if name in _MEMORY_NAMES:
            return range(0, _offset_limit(window_size) + 4, 4)
        if name in _BRANCH_NAMES:
            return branch_offsets if branch_offsets is not None else None
        if name in _GEN_UPPER_NAMES:
            return range(1 << 20)
        return range(-2048, 2048)
    raise AssertionError(f"unexpected operand field {field!r}")


def _distinct_replacement(rng: random.Random, profile: RiscvProfile,
                          dests: tuple[int, ...], sources: tuple[int, ...],
                          allow_memory: bool, window_size: int,
                          current: int, allow_auipc: bool = True) -> int:
    """A freshly emitted legal word that differs from ``current``."""
    for _ in range(6):
        word, _, _ = _emit_word(rng, profile, dests, sources, allow_memory,
                                window_size, allow_auipc)
        if word != current:
            return word
    # Deterministic last resort: `addi x0, x0, imm` writes only x0, so it is
    # legal in every mode, and three distinct immediates cannot all coincide
    # with the current word.
    for imm in (1, 2, 3):
        word = encode("ADDI", xlen=32, rd=0, rs1=0, imm=imm)
        if word != current:
            return word
    raise AssertionError("no distinct replacement word")  # pragma: no cover


def _rewire_targets(words: Sequence[int], profile: RiscvProfile,
                    allow_branches: bool = False,
                    ) -> list[tuple[int, str, dict[str, int], str, tuple[int, ...]]]:
    """Every (index, name, operands, field, candidates) a rewire can use.

    Candidates are the registers the program itself wrote before that word
    (plus ``x0``), so a rewire turns a source into a real dependency instead of
    a read of firmware state.  A store's ``rs2`` is included: rewiring it to a
    register that holds a loaded value is a load -> store flow.  A branch's two
    source fields are ordinary reads and are included.  The memory base is never
    a target.
    """
    targets = []
    written: set[int] = set()
    for index, word in enumerate(words):
        name, operands = _decode(word, allow_branch=allow_branches)
        candidates = _sources(profile, written)
        fields = ("rs2",) if name in _MEMORY_NAMES else ("rs1", "rs2")
        for field in fields:
            if field not in operands:
                continue
            current = operands[field]
            if any(value != current for value in candidates):
                targets.append((index, name, operands, field, candidates))
        if "rd" in operands:
            written.add(operands["rd"])
    return targets


def _shift_branch_targets(words: list[int], *, position: int,
                          inserting: bool, before: list[tuple[int, int]],
                          ) -> None:
    """Keep every branch target legal after an insert or a delete.

    ``before`` holds ``(branch_index, target_index)`` for each branch of the
    pre-edit image.  A word insertion shifts indices at or after ``position``; a
    deletion pulls them back.  A target that would no longer be strictly forward
    (the deleted word was the branch's own target) is repaired to the nearest
    legal target, falling back to the appended return jump.
    """
    length = len(words)
    for branch_index, target_index in before:
        if inserting:
            new_index = branch_index + (1 if branch_index >= position else 0)
            new_target = target_index + (1 if target_index >= position else 0)
        else:
            if branch_index == position:
                continue
            new_index = branch_index - (1 if branch_index > position else 0)
            new_target = target_index - (1 if target_index > position else 0)
        if new_target <= new_index:
            new_target = min(new_index + 2, length)
        if new_target <= new_index:
            new_target = length
        if new_target <= new_index:  # pragma: no cover - length always exceeds
            raise ValueError("no legal branch target remains after the edit")
        word = words[new_index]
        name, operands = _decode(word, allow_branch=True)
        if name not in _BRANCH_NAMES:  # pragma: no cover - shift keeps positions
            continue
        words[new_index] = encode(
            name, xlen=32, rs1=operands["rs1"], rs2=operands["rs2"],
            imm=4 * (new_target - new_index))


def _validate_program(profile: RiscvProfile, words: Sequence[int], *,
                      window: int, reserved: frozenset[int],
                      allow_branches: bool, allow_address_forms: bool) -> None:
    validate_program_words(profile, tuple(words), window_size=window,
                           reserved=tuple(sorted(reserved)),
                           allow_branches=allow_branches,
                           allow_address_forms=allow_address_forms)


def mutate_program(profile: RiscvProfile, program: ShortProgram, *, seed: int,
                   max_words: int, window_size: int,
                   reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                   allow_auipc: bool = True,
                   allow_branches: bool = False,
                   allow_address_forms: bool = False,
                   allow_compressed: bool = False,
                   ) -> ShortProgram:
    """Apply exactly one structured mutation to ``program``.

    The chosen action is one of: replace a word, change one operand of one word
    (``rd``/``rs1``/``rs2``/``imm``/``shamt``), rewire a source to a register the
    program wrote earlier, retarget a forward branch (only when the program has
    one), insert one word when the length is below ``max_words``, or delete one
    word when more than one word remains.  Only applicable actions are selected,
    so an unavailable action never needs a retry; an operand mutation with no
    alternative value falls back to a replacement, and a rewire with no earlier
    producer does too.  The input must hold between one and ``max_words`` words
    and is validated first, so a program generated with a larger budget is
    refused instead of silently shrinking.

    ``allow_branches``/``allow_address_forms`` admit those shapes (and maintain
    them: insert/delete retarget every branch, and a failed edit falls back to a
    legal no-op-form replacement), while ``allow_compressed=True`` delegates a
    compressed image to :func:`myfuzz.fuzz.rv32_compressed.mutate_compressed_program`.
    ``allow_auipc=False`` keeps an inserted or replaced word from being
    ``AUIPC``.  The result is always legal for
    ``profile``/``window_size``/``reserved`` and is marked ``style
    "mutation"``.
    """
    _check_profile(profile)
    _check_seed(seed)
    _check_max_words(max_words)
    window = _require_window(window_size)
    reserved_set = _reserved_set(reserved)
    upper_immediate = _check_allow_auipc(allow_auipc)
    branches = _check_flag_argument(allow_branches, "allow_branches")
    address_forms = _check_flag_argument(allow_address_forms,
                                         "allow_address_forms")
    compressed = _check_flag_argument(allow_compressed, "allow_compressed")
    if not isinstance(program, ShortProgram):
        raise ValueError("program must be a ShortProgram")
    if len(program.words) > max_words:
        raise ValueError(
            f"program has {len(program.words)} words but max_words is "
            f"{max_words}")
    if any(word & 3 != 3 for word in program.words):
        if not compressed:
            raise ValueError(
                "program contains compressed parcels; "
                "allow_compressed=True is required")
        from .rv32_compressed import mutate_compressed_program
        return mutate_compressed_program(
            profile, program, seed=seed, max_words=max_words,
            window_size=window, reserved=reserved, allow_branches=branches)
    uses_branches = any(word & 0x7F == _BRANCH_OPCODE for word in program.words)
    uses_address_forms = any(
        word & 0x7F in _MEMORY_OPCODES and ((word >> 15) & 0x1F) != _MEMORY_BASE
        for word in program.words)
    if uses_branches and not branches:
        raise ValueError(
            "program contains forward branches; allow_branches=True is "
            "required to mutate it")
    if uses_address_forms and not address_forms:
        raise ValueError(
            "program uses a computed memory base; allow_address_forms=True is "
            "required to mutate it")
    allow_branches = branches or uses_branches
    allow_address_forms = address_forms or uses_address_forms
    validate_program_words(profile, program.words, window_size=window,
                           reserved=reserved, allow_branches=allow_branches,
                           allow_address_forms=allow_address_forms)
    if max_words == 1 and any(word & 0x7F in _MEMORY_OPCODES
                              for word in program.words):
        raise ValueError(
            "a max_words 1 program must not contain memory instructions")
    dests = _allocatable(profile, reserved_set)
    if not dests:
        raise ValueError("no allocatable destination register for this profile")
    allow_memory = max_words > 1 and profile.register_count > _MEMORY_BASE
    original = tuple(program.words)
    words = list(program.words)
    rng = random.Random(seed)

    actions = ["replace", "operand", "rewire"]
    if uses_branches:
        actions.append("branch")
    if len(words) < max_words:
        actions.append("insert")
    if len(words) > 1:
        actions.append("delete")
    action = rng.choice(actions)

    def fallback_replacement() -> None:
        index = rng.randrange(len(words))
        sources = _sources(profile, _written_before(
            tuple(words), index, allow_branches))
        words[index] = _distinct_replacement(
            rng, profile, dests, sources, allow_memory, window, words[index],
            upper_immediate)

    def safe_replacement() -> None:
        """A legal one-word edit that no address or branch rule can invalidate."""
        candidates = [encode("ADDI", xlen=32, rd=0, rs1=0, imm=imm)
                      for imm in (1, 2, 3)]
        for offset in rng.sample(range(len(words)), len(words)):
            for candidate in candidates:
                if words[offset] == candidate:
                    continue
                trial = list(words)
                trial[offset] = candidate
                if tuple(trial) == original:
                    continue
                try:
                    _validate_program(
                        profile, trial, window=window, reserved=reserved_set,
                        allow_branches=allow_branches,
                        allow_address_forms=allow_address_forms)
                except ValueError:
                    continue
                words[:] = trial
                return
        raise ValueError(
            "no legal mutation exists for this program")  # pragma: no cover

    def branch_records() -> list[tuple[int, int]]:
        records = []
        for index, word in enumerate(words):
            if word & 0x7F != _BRANCH_OPCODE:
                continue
            _, operands = _decode_branch(word)
            records.append((index, index + operands["imm"] // 4))
        return records

    if action == "delete":
        position = rng.randrange(len(words))
        before = branch_records()
        del words[position]
        _shift_branch_targets(words, position=position, inserting=False,
                              before=before)
    elif action == "insert":
        position = rng.randrange(len(words) + 1)
        before = branch_records()
        sources = _sources(profile, _written_before(
            tuple(words), position, allow_branches))
        word, _, _ = _emit_word(rng, profile, dests, sources, allow_memory,
                                window, upper_immediate)
        words.insert(position, word)
        _shift_branch_targets(words, position=position, inserting=True,
                              before=before)
    elif action == "replace":
        fallback_replacement()
    elif action == "rewire":
        targets = _rewire_targets(words, profile, allow_branches)
        if not targets:
            fallback_replacement()
        else:
            index, name, operands, field, candidates = rng.choice(targets)
            value = _different_choice(rng, candidates, operands[field])
            if value is None:  # pragma: no cover - _rewire_targets excludes this
                fallback_replacement()
            else:
                operands[field] = value
                words[index] = encode(name, xlen=32, **operands)
    elif action == "branch":
        records = branch_records()
        if not records:
            fallback_replacement()
        else:
            index, current_target = rng.choice(records)
            name, operands = _decode_branch(words[index])
            choices = tuple(target for target in range(index + 1, len(words) + 1)
                            if target != current_target)
            if not choices:
                # The branch is the last word and already points at the return
                # jump: no other target exists, so change a word instead.
                safe_replacement()
            else:
                target = rng.choice(choices)
                words[index] = encode(name, xlen=32, rs1=operands["rs1"],
                                      rs2=operands["rs2"],
                                      imm=4 * (target - index))
    else:
        targets = []
        for index, word in enumerate(words):
            name, operands = _decode(word, allow_branch=allow_branches)
            branch_offsets = (_branch_target_offsets(index, len(words))
                              if name in _BRANCH_NAMES else None)
            for field, current in operands.items():
                choices = _field_choices(name, field, profile, reserved_set,
                                         window, branch_offsets)
                if choices is not None and _has_alternative(choices, current):
                    targets.append((index, name, operands, field, choices))
        if not targets:
            fallback_replacement()
        else:
            index, name, operands, field, choices = rng.choice(targets)
            value = _different_choice(rng, choices, operands[field])
            assert value is not None  # _has_alternative guarantees a value
            operands[field] = value
            words[index] = encode(name, xlen=32, **operands)

    if tuple(words) == original:
        safe_replacement()
    else:
        try:
            _validate_program(profile, words, window=window,
                              reserved=reserved_set,
                              allow_branches=allow_branches,
                              allow_address_forms=allow_address_forms)
        except ValueError:
            safe_replacement()
    return _program_from_words(profile, seed, max_words, tuple(words), "mutation")


def validate_program_words(profile: RiscvProfile, words: tuple[int, ...], *,
                           window_size: int | None,
                           reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                           allow_branches: bool = False,
                           allow_address_forms: bool = False,
                           allow_jumps: bool = False,
                           allow_loops: bool = False,
                           image_base: int | None = None,
                           ) -> None:
    """Raise :class:`ValueError` unless every word is a legal trampoline word.

    Instruction indices in the messages are 0-based positions in ``words``.
    ``window_size=None`` skips only the data-window bound (used by
    :func:`reference_run`); encodings, register existence, extension gating,
    the reserved-register rule and the ``x18`` base rule are always checked.
    ``allow_branches=True`` admits the six B-type branches, whose target must be
    4-byte aligned, forward (or, with ``allow_loops``, the canonical bounded
    loop back edge) and at most the appended return jump at index
    ``len(words)``; ``allow_address_forms=True`` admits a memory word whose
    proven base register is not ``x18`` and defers its address check to
    :func:`validate_address_program`.  ``allow_jumps=True`` admits ``JAL`` and
    ``JALR`` with a link register of x0/x1 and a statically known, strictly
    forward target (``JALR`` needs ``image_base``); ``allow_loops=True`` admits
    the canonical bounded loop of the module docstring.  The function has no
    side effects: ``words`` is only read.
    """
    profile = _check_profile(profile)
    window = _check_window(window_size)
    reserved_set = _reserved_set(reserved)
    if not isinstance(allow_branches, bool):
        raise ValueError("allow_branches must be a boolean")
    if not isinstance(allow_address_forms, bool):
        raise ValueError("allow_address_forms must be a boolean")
    if not isinstance(allow_jumps, bool):
        raise ValueError("allow_jumps must be a boolean")
    if not isinstance(allow_loops, bool):
        raise ValueError("allow_loops must be a boolean")
    if image_base is not None and (type(image_base) is not int
                                   or not 0 <= image_base <= _MASK32):
        raise ValueError("image_base must be a 32-bit unsigned integer or None")
    if allow_loops and not allow_branches:
        raise ValueError(
            "allow_loops requires allow_branches: a bounded loop's back edge "
            "is a B-type branch")
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    words = tuple(words)
    if not words:
        raise ValueError("program has no instruction")
    for index, word in enumerate(words):
        _validate_word(profile, index, word, window, reserved_set,
                       length=len(words), allow_branches=allow_branches,
                       allow_address_forms=allow_address_forms,
                       allow_jumps=allow_jumps, allow_loops=allow_loops)
    if allow_address_forms:
        if window is None:
            _memory_uses(words, window_bytes=None)
        else:
            validate_address_program(words, window)
    if allow_jumps or allow_loops or allow_branches:
        # The whole-program pass resolves every target, proves the bounded-loop
        # trip counts and (for JALR) needs the static constant provenance.  It
        # is skipped for the historical straight-line gate, which has no
        # control transfer to prove.
        control_flow_analysis(words, allow_branches=allow_branches,
                              allow_jumps=allow_jumps,
                              allow_loops=allow_loops,
                              image_base=image_base, reserved=reserved)


def _validate_word(profile: RiscvProfile, index: int, word: object,
                   window_size: int | None, reserved: frozenset[int], *,
                   length: int, allow_branches: bool = False,
                   allow_address_forms: bool = False,
                   allow_jumps: bool = False,
                   allow_loops: bool = False) -> None:
    if type(word) is not int or not 0 <= word <= _MASK32:
        raise ValueError(
            f"instruction {index} is not a 32-bit unsigned word: {word!r}")
    if word & 3 != 3:
        raise ValueError(
            f"instruction {index} is compressed; a 32-bit word is required")
    opcode = word & 0x7F
    if opcode in _CONTROL_FLOW_OPCODES:
        branch_exception = opcode == _BRANCH_OPCODE and allow_branches
        jump_exception = opcode in _JUMP_OPCODES and allow_jumps
        if not (branch_exception or jump_exception):
            raise ValueError(
                f"instruction {index} is a control-flow or system instruction; "
                "the trampoline program is straight-line")
    try:
        name, operands = _decode(word, allow_branch=allow_branches,
                                 allow_jump=allow_jumps)
    except _IllegalEncoding as error:
        raise ValueError(
            f"instruction {index} is not a legal trampoline instruction: "
            f"{error}") from None
    for field in ("rd", "rs1", "rs2"):
        reg = operands.get(field)
        if reg is not None and reg >= profile.register_count:
            raise ValueError(
                f"instruction {index} is not legal for this profile: {field} "
                f"x{reg} does not exist in a profile with "
                f"{profile.register_count} registers")
    if not _extension_available(profile, name):
        raise ValueError(
            f"instruction {index} is not legal for this profile: {name} "
            f"requires extension {CATALOG[name].extension}, profile declares "
            f"{sorted(profile.extensions)}")
    if name in _BRANCH_NAMES:
        _validate_branch_target(index, operands["imm"], length,
                                allow_loops=allow_loops)
        return
    if name in _JUMP_NAMES:
        _validate_jump_word(index, name, operands, length)
        return
    rd = operands.get("rd")
    if rd is not None and rd != 0 and rd in reserved:
        raise ValueError(
            f"instruction {index} writes the reserved "
            f"{_reserved_label(rd)} x{rd}")
    if opcode in _MEMORY_OPCODES:
        base = operands["rs1"]
        if base != _MEMORY_BASE:
            if allow_address_forms:
                if operands["imm"] != 0:
                    raise ValueError(
                        f"instruction {index} memory access with a computed "
                        "base must use immediate 0")
                return
            raise ValueError(
                f"instruction {index} memory access must use x18 as its base "
                f"(rs1 = x{base})")
        offset = operands["imm"]
        if offset % 4:
            raise ValueError(
                f"instruction {index} memory access offset {offset} is not "
                "4-byte aligned")
        if window_size is not None and not 0 <= offset <= window_size - 4:
            raise ValueError(
                f"instruction {index} memory access leaves the declared data "
                f"window (offset {offset})")


def _validate_branch_target(index: int, offset: int, length: int, *,
                            allow_loops: bool = False) -> None:
    """One branch target rule, shared by validation and analysis.

    ``offset`` is the encoded displacement in bytes and ``length`` the number of
    installed words; the host appends its return jump at index ``length``, so
    that index is the one legal "leave the program body" target.  A backward
    displacement is admitted only with ``allow_loops``, and then only as the
    canonical bounded-loop back edge, which :func:`control_flow_analysis`
    checks; this function still refuses a zero displacement (a self-loop).
    """
    if offset % 4:
        raise ValueError(
            f"instruction {index} branch offset {offset} is not 4-byte aligned")
    if offset <= 0 and not allow_loops:
        raise ValueError(
            f"instruction {index} branch target is not strictly forward "
            f"(offset {offset}); loops are refused")
    if offset == 0:
        raise ValueError(
            f"instruction {index} branch target is the branch itself "
            "(offset 0); an infinite self-loop is refused")
    target = index + offset // 4
    if target > length:
        raise ValueError(
            f"instruction {index} branch target index {target} is beyond the "
            f"installed program (length {length}); only a target up to the "
            "appended return jump is admitted")
    if target < 0:
        raise ValueError(
            f"instruction {index} branch target index {target} is before the "
            "installed program")


def _validate_jump_word(index: int, name: str, operands: dict[str, int],
                        length: int) -> None:
    """The per-word half of the jump rule: link register and alignment.

    The target itself is checked by :func:`control_flow_analysis`, which owns
    the static provenance ``JALR`` needs and the loop/interior rules a jump
    target must respect.
    """
    rd = operands["rd"]
    if rd not in _JUMP_LINK_REGISTERS:
        raise ValueError(
            f"instruction {index} {name} link destination x{rd} is not x0 or "
            "x1; only x0 and x1 are admitted")
    if name == "JAL":
        if operands["imm"] % 4:
            raise ValueError(
                f"instruction {index} JAL offset {operands['imm']} is not "
                "4-byte aligned")
        target = index + operands["imm"] // 4
        if target > length:
            raise ValueError(
                f"instruction {index} JAL target index {target} is beyond the "
                f"installed program (length {length}); only a target up to the "
                "appended return jump is admitted")
        if target < 0:
            raise ValueError(
                f"instruction {index} JAL target index {target} is before the "
                "installed program")


# ---------------------------------------------------------------------------
# Whole-program control flow: jump targets and the bounded-loop recognizer
# ---------------------------------------------------------------------------


class JumpTarget(NamedTuple):
    """One statically resolved jump of an installed image."""

    index: int
    name: str
    target_index: int
    link: int


class LoopInfo(NamedTuple):
    """One statically bounded loop of an installed image.

    ``init`` is the ``addi xN, x0, K`` word, ``head`` the first word the back
    edge targets, ``step`` the ``addi xN, xN, -1`` word and ``back_edge`` the
    ``bne xN, x0, head`` word.  ``trip_count`` is ``K``; ``induction`` is ``N``.
    """

    init: int
    head: int
    step: int
    back_edge: int
    trip_count: int
    induction: int

    @property
    def length(self) -> int:
        """Retirements of one loop iteration (``head`` through ``back_edge``)."""
        return self.back_edge - self.head + 1


class ControlFlow(NamedTuple):
    """The static control-flow facts one installed image states."""

    decoded: tuple[tuple[str, dict[str, int]], ...]
    successors: tuple[tuple[int, ...], ...]
    jumps: tuple[JumpTarget, ...]
    loops: tuple[LoopInfo, ...]
    step_limit: int

    @property
    def loop_repeats(self) -> int:
        """How many retirements the recognised loops repeat beyond one pass."""
        return sum((loop.trip_count - 1) * loop.length for loop in self.loops)


def _transfer_state(name: str, operands: dict[str, int],
                    current: Sequence[object], *,
                    base_reg: int = _MEMORY_BASE) -> list[object]:
    """The provenance state after one instruction, as a fresh list."""
    outgoing = list(current)
    if name in _JUMP_NAMES:
        # A jump's link register holds pc + 4, a value this analysis does not
        # model; every jump target must therefore be x0/x1 independent of it.
        rd = operands.get("rd")
        if rd:
            outgoing[rd] = _UNKNOWN
        return outgoing
    write = operands.get("rd")
    if write is None or write == 0:
        return outgoing
    if write == base_reg:
        outgoing[base_reg] = _UNKNOWN
    else:
        outgoing[write] = _transfer_provenance(name, operands, current)
    return outgoing


def _flow_states(decoded: Sequence[tuple[str, dict[str, int]]],
                 successors: Sequence[Sequence[int]], *,
                 base_reg: int = _MEMORY_BASE) -> list[list[object]]:
    """Least-fixpoint may-provenance over a control-flow graph.

    Every node starts unreachable (all-unknown) except the first, and a
    successor's state is the union merge of every incoming path.  Forward-only
    images converge in one pass in index order, exactly like the historical
    pass; a backward edge is iterated until the state stops changing.  The
    result is a sound over-approximation for every reachable node, and an
    unreachable node stays all-unknown (which is conservative).
    """
    count = len(decoded)
    initial: list[object] = [_UNKNOWN] * 32
    initial[0] = ("const", 0)
    if 0 <= base_reg < 32:
        initial[base_reg] = ("window", 0, 0)
    states: list[list[object] | None] = [None] * count
    if count:
        states[0] = list(initial)
    work = [0] if count else []
    # Each pop either first-reaches a node or strictly shrinks its state, and
    # every state is a 32-entry vector of a finite domain, so this is bounded.
    budget = (count + 1) * 32 * (count + 1) + 64
    while work:
        budget -= 1
        if budget < 0:  # pragma: no cover - monotone fixpoint cannot exceed it
            raise AssertionError("provenance fixpoint did not converge")
        index = work.pop()
        current = states[index]
        if current is None:  # pragma: no cover - only pushed when reached
            continue
        name, operands = decoded[index]
        outgoing = _transfer_state(name, operands, current, base_reg=base_reg)
        for successor in successors[index]:
            if not 0 <= successor < count:
                continue
            existing = states[successor]
            if existing is None:
                states[successor] = list(outgoing)
                work.append(successor)
                continue
            merged = [_merge_provenance(left, right)
                      for left, right in zip(existing, outgoing)]
            if merged != existing:
                states[successor] = merged
                work.append(successor)
    return [state if state is not None else [_UNKNOWN] * 32
            for state in states]


def _transfer_target(name: str, operands: dict[str, int], index: int,
                     state: Sequence[object], *,
                     image_base: int | None) -> int | None:
    """The statically known target index of one control transfer, or ``None``."""
    if name in _BRANCH_NAMES or name == "JAL":
        offset = operands["imm"]
        if offset % 4:
            return None
        return index + offset // 4
    if name == "JALR":
        provenance = state[operands["rs1"]]
        if _provenance_kind(provenance) != "const" or image_base is None:
            return None
        address = (provenance[1] + operands["imm"]) & _MASK32
        address &= ~1
        offset = (address - image_base) & _MASK32
        if offset % 4:
            return None
        return offset // 4
    return None


def _control_successors(decoded: Sequence[tuple[str, dict[str, int]]],
                        states: Sequence[Sequence[object]], *,
                        image_base: int | None) -> list[tuple[int, ...]]:
    """Successor indices of every instruction, clamped to the image."""
    count = len(decoded)
    successors: list[tuple[int, ...]] = []
    for index, (name, operands) in enumerate(decoded):
        fall_through = index + 1 if index + 1 <= count else None
        if name in _BRANCH_NAMES:
            edges = [index + 1]
            target = _transfer_target(name, operands, index, states[index],
                                      image_base=image_base)
            if target is not None:
                edges.append(target)
            successors.append(tuple(dict.fromkeys(edges)))
            continue
        if name in _JUMP_NAMES:
            target = _transfer_target(name, operands, index, states[index],
                                      image_base=image_base)
            # An unresolved jump contributes no edge: the words after it are
            # then unreachable (conservative), and validation refuses the jump.
            successors.append(() if target is None else (target,))
            continue
        successors.append(() if fall_through is None else (fall_through,))
    return successors


def _recognize_loops(decoded: Sequence[tuple[str, dict[str, int]]],
                     states: Sequence[Sequence[object]], *,
                     image_base: int | None,
                     reserved: frozenset[int]) -> tuple[LoopInfo, ...]:
    """Recognise every canonical bounded loop, or raise naming the failure.

    A backward branch is a loop back edge only when the whole canonical shape
    holds (see the module docstring, rule 14c); anything else is refused by
    name rather than interpreted.
    """
    count = len(decoded)
    loops: list[LoopInfo] = []
    for index, (name, operands) in enumerate(decoded):
        if name not in _BRANCH_NAMES:
            if name == "JAL":
                target = index + operands["imm"] // 4
                if target <= index:
                    raise ValueError(
                        f"instruction {index} JAL target index {target} is not "
                        "strictly forward; a backward jump would be an "
                        "unbounded loop, and the bounded loop back edge is the "
                        "canonical BNE form")
            elif name == "JALR":
                target = _transfer_target(name, operands, index, states[index],
                                          image_base=image_base)
                if target is not None and target <= index:
                    raise ValueError(
                        f"instruction {index} JALR target index {target} is "
                        "not strictly forward; a backward jump would be an "
                        "unbounded loop, and the bounded loop back edge is the "
                        "canonical BNE form")
            continue
        target = index + operands["imm"] // 4
        if target > index:
            continue
        if name != _LOOP_BACK_EDGE:
            raise ValueError(
                f"instruction {index} {name} branches backward to index "
                f"{target}; a backward branch is a loop and only the canonical "
                f"{_LOOP_BACK_EDGE} back edge of a bounded loop is admitted")
        induction = _loop_induction(operands)
        if induction is None:
            raise ValueError(
                f"instruction {index} backward {name} does not compare an "
                "induction register with x0; only "
                f"`{_LOOP_BACK_EDGE} xN, x0, head` is admitted")
        head = target
        step = index - 1
        init = head - 1
        if init < 0 or step < head:
            raise ValueError(
                f"instruction {index} backward branch has no room for the "
                "canonical loop shape (init, head, step, back edge)")
        init_name, init_operands = decoded[init]
        trip = _loop_init(init_name, init_operands, induction)
        if trip is None:
            raise ValueError(
                f"instruction {init} must be `addi x{induction}, x0, K` with "
                f"K in {_LOOP_TRIP_MIN}..{_LOOP_TRIP_MAX}; the loop at index "
                f"{index} has no statically known trip count")
        step_name, step_operands = decoded[step]
        if not _is_induction_step(step_name, step_operands, induction):
            raise ValueError(
                f"instruction {step} must be `addi x{induction}, x{induction}, "
                "-1`; the loop at index "
                f"{index} has no statically known induction step")
        if induction in reserved or induction == 0:
            raise ValueError(
                f"instruction {index} loop induction register x{induction} is "
                "x0 or a reserved register")
        for body_index in range(head, step):
            body_name, body_operands = decoded[body_index]
            if body_name in _BRANCH_NAMES or body_name in _JUMP_NAMES \
                    or body_operands.get("rd") == induction:
                raise ValueError(
                    f"instruction {body_index} is inside the loop at index "
                    f"{index} but "
                    + ("is a control transfer; a loop body may not branch"
                       if body_name in _BRANCH_NAMES
                       or body_name in _JUMP_NAMES else
                       f"writes the induction register x{induction}"))
        loops.append(LoopInfo(init, head, step, index, trip, induction))
    return tuple(loops)


def _loop_induction(operands: dict[str, int]) -> int | None:
    """The induction register of a ``bne xN, x0, ...`` back edge, or ``None``."""
    left, right = operands["rs1"], operands["rs2"]
    if right == 0 and left != 0:
        return left
    if left == 0 and right != 0:
        return right
    return None


def _loop_init(name: str, operands: dict[str, int],
               induction: int) -> int | None:
    """The trip count of ``addi xN, x0, K`` with ``K`` in the admitted range."""
    if name != "ADDI" or operands.get("rd") != induction \
            or operands.get("rs1") != 0:
        return None
    trip = operands.get("imm")
    if trip is None or not _LOOP_TRIP_MIN <= trip <= _LOOP_TRIP_MAX:
        return None
    return trip


def _is_induction_step(name: str, operands: dict[str, int],
                       induction: int) -> bool:
    """Whether the word is ``addi xN, xN, -1``."""
    return (name == "ADDI" and operands.get("rd") == induction
            and operands.get("rs1") == induction and operands.get("imm") == -1)


def _check_loop_targets(decoded: Sequence[tuple[str, dict[str, int]]],
                        states: Sequence[Sequence[object]],
                        loops: Sequence[LoopInfo], *, length: int,
                        image_base: int | None) -> None:
    """Every transfer target must respect the loop intervals.

    A loop is entered only through its own init (the word before the head), the
    head is reachable only from that init and from the loop's own back edge, and
    no transfer may land strictly inside a loop.  Two loops must be disjoint.
    """
    intervals = [(loop.init, loop.back_edge) for loop in loops]
    for left in range(len(intervals)):
        for right in range(left + 1, len(intervals)):
            low, high = intervals[left]
            other_low, other_high = intervals[right]
            if low <= other_high and other_low <= high:
                raise ValueError(
                    "two bounded loops overlap at indices "
                    f"{max(low, other_low)}..{min(high, other_high)}; nested or "
                    "interleaved loops are not admitted")
    for index, (name, operands) in enumerate(decoded):
        if name not in _BRANCH_NAMES and name not in _JUMP_NAMES:
            continue
        target = _transfer_target(name, operands, index, states[index],
                                  image_base=image_base)
        if target is None:
            if name == "JALR":
                provenance = states[index][operands["rs1"]]
                if _provenance_kind(provenance) == "const" \
                        and image_base is not None:
                    address = ((provenance[1] + operands["imm"]) & _MASK32) & ~1
                    if address % 4:
                        raise ValueError(
                            f"instruction {index} JALR target address "
                            f"{address:#010x} is not 4-byte aligned")
                raise ValueError(
                    f"instruction {index} JALR base x{operands['rs1']} is not a "
                    "statically proven constant address; an indirect jump is "
                    "refused")
            continue
        if target < 0 or target > length:
            raise ValueError(
                f"instruction {index} {name} target index {target} is outside "
                f"the installed program (length {length})")
        if target == index:
            raise ValueError(
                f"instruction {index} {name} target is the instruction itself; "
                "an infinite self-loop is refused")
        for loop in loops:
            own_edge = (index == loop.back_edge and target == loop.head)
            if own_edge:
                continue
            if loop.init <= target <= loop.back_edge:
                raise ValueError(
                    f"instruction {index} {name} target index {target} is "
                    f"inside the bounded loop at index {loop.back_edge} "
                    f"({loop.init}..{loop.back_edge}); a loop is entered only "
                    "through its own init and left only by falling through")
        if name in _JUMP_NAMES and target <= index:
            raise ValueError(
                f"instruction {index} {name} target index {target} is not "
                "strictly forward; a backward jump would be an unbounded loop, "
                "and the bounded loop back edge is the canonical BNE form")
        if target == length:
            # The appended return jump is the legal exit of the image.
            continue


def control_flow_analysis(words: Sequence[int], *,
                          allow_branches: bool = False,
                          allow_jumps: bool = False,
                          allow_loops: bool = False,
                          image_base: int | None = None,
                          reserved: tuple[int, ...] = DEFAULT_RESERVED_REGISTERS,
                          ) -> ControlFlow:
    """Statically resolve every control transfer of one 32-bit image.

    This is the single authority for jump targets, the bounded-loop shape and
    the retirement bound the reference model uses.  It decodes every word
    (branches and jumps are decoded regardless of the flags; legality is the
    caller's per-word gate), resolves ``JAL``/``JALR`` targets, recognises the
    canonical bounded loops and raises :class:`ValueError` naming the first
    control-flow fact it cannot prove.

    ``image_base`` is the address of the first installed word; a ``JALR`` is
    absolute and is refused without it (or with a base register that is not a
    proven constant).  ``allow_jumps`` admits jumps at all; ``allow_loops``
    admits the backward ``BNE`` back edge.  Without either flag a control
    transfer that this pass sees is refused, so a caller can use this as the
    whole-program gate for any program shape.
    """
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    sequence = tuple(words)
    if not sequence:
        raise ValueError("program has no instruction")
    decoded: list[tuple[str, dict[str, int]]] = []
    for index, word in enumerate(sequence):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"instruction {index} is not a 32-bit unsigned word: {word!r}")
        try:
            decoded.append(_decode(word, allow_branch=True, allow_jump=True))
        except _IllegalEncoding as error:
            raise ValueError(
                f"instruction {index} is not a legal trampoline instruction: "
                f"{error}") from None
    count = len(decoded)
    if image_base is not None and (type(image_base) is not int
                                   or not 0 <= image_base <= _MASK32):
        raise ValueError("image_base must be a 32-bit unsigned integer or None")
    # The edge set grows monotonically: a jump edge, once its base is proven,
    # stays, so the loop below terminates.  The final state set is recomputed
    # with the final edges, and the jump bases are re-checked against it.
    successors = _control_successors(decoded, [[_UNKNOWN] * 32] * count,
                                     image_base=None)
    states = _flow_states(decoded, successors)
    for _ in range(count + 2):
        grown = _control_successors(decoded, states, image_base=image_base)
        merged = [tuple(dict.fromkeys(old + new))
                  for old, new in zip(successors, grown)]
        if merged == [tuple(edge) for edge in successors]:
            break
        successors = merged
        states = _flow_states(decoded, successors)
    states = _flow_states(decoded, successors)
    loops = _recognize_loops(decoded, states, image_base=image_base,
                             reserved=_reserved_set(reserved)) \
        if allow_loops else ()
    if not allow_loops:
        for index, (name, operands) in enumerate(decoded):
            if name in _BRANCH_NAMES and operands["imm"] < 0:
                raise ValueError(
                    f"instruction {index} branch target is not strictly "
                    f"forward (offset {operands['imm']}); loops are refused")
    _check_loop_targets(decoded, states, loops, length=count,
                        image_base=image_base)
    jumps: list[JumpTarget] = []
    for index, (name, operands) in enumerate(decoded):
        if name not in _JUMP_NAMES:
            continue
        if name == "JALR":
            provenance = states[index][operands["rs1"]]
            if _provenance_kind(provenance) == "const" and image_base is not None:
                address = ((provenance[1] + operands["imm"]) & _MASK32) & ~1
                if address % 4:
                    raise ValueError(
                        f"instruction {index} JALR target address "
                        f"{address:#010x} is not 4-byte aligned")
        target = _transfer_target(name, operands, index, states[index],
                                  image_base=image_base)
        if target is None:
            raise ValueError(
                f"instruction {index} JALR base x{operands['rs1']} is not a "
                "statically proven constant address; an indirect jump is "
                "refused")
        if name == "JAL" and not allow_jumps:
            raise ValueError(
                f"instruction {index} is a jump; the trampoline program is "
                "straight-line")
        jumps.append(JumpTarget(index, name, target, operands["rd"]))
    if jumps and not allow_jumps:
        raise ValueError("the trampoline program is straight-line; jumps are "
                         "refused")
    if loops and not allow_loops:  # pragma: no cover - guarded above
        raise ValueError("loops are refused")
    step_limit = count + sum((loop.trip_count - 1) * loop.length
                             for loop in loops)
    return ControlFlow(tuple(decoded), tuple(successors), tuple(jumps),
                       tuple(loops), step_limit)


def analyze_program(words: Sequence[int]) -> dict[str, object]:
    """Report one program's structural data flow without executing it.

    Only the words are read: they are decoded, never validated against a data
    window and never run.  The result is JSON-ready and states, per instruction,
    which registers it reads and writes; every register dependency edge (the
    earlier instruction(s) that can write the register the consumer reads);
    the dependency chains keyed by that register; the source registers read by
    more than one instruction; every memory word's offset; the offsets used more
    than once; the ``SW -> LW`` pairs (a load that reads the value an earlier
    store at that offset left) and the ``LW -> SW`` pairs (a store whose
    stored register still holds a loaded value); and ``self_contained``, which
    is false when the program reads a register it never wrote (other than ``x0``
    and the ``x18`` memory base), i.e. when its values depend on firmware state.

    Branches are understood.  The analysis is a forward *may* dataflow over the
    program's DAG of word indices: a branch contributes its fall-through edge and
    its strictly forward target edge, and at a merge a register's producer set
    is the union of both paths.  A straight-line program therefore reports
    exactly one producer per dependency edge, as before; a branch program can
    report several producers for one consumer, all of which are real on some
    path.  ``branches`` lists the decoded B-type words with their target index
    and ``control_flow`` names the shape.
    """
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    sequence = tuple(words)
    if not sequence:
        raise ValueError("program has no instruction")
    decoded = []
    for position, word in enumerate(sequence):
        if type(word) is not int or not 0 <= word <= _MASK32:
            raise ValueError(
                f"instruction {position} is not a 32-bit unsigned word: {word!r}")
        name, operands = _decode(word, allow_branch=True)
        decoded.append((word, name, operands))

    length = len(decoded)
    successors = [_successor_indices(name, operands, index, length)
                  for index, (_, name, operands) in enumerate(decoded)]

    # May-provenance domains.  Each is a list of "state before instruction i";
    # every edge points forward, so one increasing pass reaches the fixpoint.
    writers: list[dict[int, frozenset[int]]] = [{} for _ in range(length)]
    stores: list[dict[int, frozenset[int]]] = [{} for _ in range(length)]
    loaded: list[dict[int, frozenset[tuple[int, int]]]] = [
        {} for _ in range(length)]

    def merge_into(target: dict, source: dict) -> None:
        for key, value in source.items():
            existing = target.get(key)
            target[key] = value if existing is None else existing | value

    for index, (_, name, operands) in enumerate(decoded):
        write = operands.get("rd")
        out_writers = dict(writers[index])
        if write is not None and write != 0:
            out_writers[write] = frozenset((index,))
        out_stores = dict(stores[index])
        if name == "SW":
            out_stores[operands["imm"]] = frozenset((index,))
        out_loaded = dict(loaded[index])
        if write is not None and write != 0:
            out_loaded.pop(write, None)
        if name == "LW":
            # A load's destination can hold the loaded value until something
            # else writes it, exactly like the old linear walk.
            out_loaded[operands["rd"]] = frozenset(
                ((index, operands["imm"]),))
        for successor in successors[index]:
            if successor >= length:
                continue
            merge_into(writers[successor], out_writers)
            merge_into(stores[successor], out_stores)
            merge_into(loaded[successor], out_loaded)

    instructions: list[dict[str, object]] = []
    dependencies: list[dict[str, int]] = []
    chains: dict[int, set[int]] = {}
    register_readers: dict[int, list[int]] = {}
    external: list[dict[str, int]] = []
    memory: list[dict[str, object]] = []
    offsets: list[int] = []
    store_to_load: list[dict[str, int]] = []
    load_to_store: list[dict[str, int]] = []
    branches: list[dict[str, int | str]] = []

    for index, (word, name, operands) in enumerate(decoded):
        reads: list[tuple[str, int]] = []
        if name in _MEMORY_NAMES:
            reads.append(("rs1", operands["rs1"]))
            if name == "SW":
                reads.append(("rs2", operands["rs2"]))
        else:
            # LUI and AUIPC read no register at all; an OP-IMM, shift or branch
            # word reads rs1 (and a branch also rs2).
            if "rs1" in operands:
                reads.append(("rs1", operands["rs1"]))
            if "rs2" in operands:
                reads.append(("rs2", operands["rs2"]))
        write = operands.get("rd")
        # One dependency edge per (consumer, register): an R word that reads the
        # same register in both source fields still depends on it once.
        seen: dict[int, str] = {}
        for field, reg in reads:
            if reg != 0:
                seen.setdefault(reg, field)
        for reg, field in seen.items():
            register_readers.setdefault(reg, []).append(index)
            producers = writers[index].get(reg)
            if producers:
                for producer in sorted(producers):
                    dependencies.append({"producer": producer,
                                         "consumer": index, "register": reg})
                    chains.setdefault(reg, set()).update((producer, index))
            elif name in _MEMORY_NAMES and field == "rs1" and reg == _MEMORY_BASE:
                # The firmware points x18 at the declared data window; reading it
                # is the trampoline contract, not a hidden input.
                pass
            else:
                external.append({"index": index, "register": reg, "field": field})
        if name in _BRANCH_NAMES:
            branches.append({
                "index": index,
                "pc": 4 * index,
                "name": name,
                "rs1": operands["rs1"],
                "rs2": operands["rs2"],
                "offset": operands["imm"],
                "target_index": index + operands["imm"] // 4,
            })
        if name in _MEMORY_NAMES:
            offset = operands["imm"]
            memory.append({"index": index, "name": name, "offset": offset})
            offsets.append(offset)
            if name == "SW":
                for load_index, load_offset in sorted(
                        loaded[index].get(operands["rs2"], ())):
                    load_to_store.append({"load": load_index, "store": index,
                                          "register": operands["rs2"],
                                          "from_offset": load_offset,
                                          "to_offset": offset})
            else:
                for store_index in sorted(stores[index].get(offset, ())):
                    store_to_load.append({"store": store_index, "load": index,
                                          "offset": offset})
        instructions.append({
            "index": index,
            "pc": 4 * index,
            "word": word,
            "name": name,
            "assembly": format_assembly(name, operands),
            "reads": {field: reg for field, reg in reads},
            "write": write if write else None,
        })

    repeated_sources = tuple(sorted(reg for reg, readers in register_readers.items()
                                    if len(readers) > 1))
    counts: dict[int, int] = {}
    for offset in offsets:
        counts[offset] = counts.get(offset, 0) + 1
    return {
        "schema_version": "rv32_program_analysis.v1",
        "words": list(sequence),
        "text": ":".join(f"{word:08x}" for word in sequence),
        "instructions": instructions,
        "dependencies": dependencies,
        "dependency_edges": len(dependencies),
        "chains": [
            {"register": reg, "indices": sorted(indices)}
            for reg, indices in sorted(chains.items())
        ],
        "register_readers": {"x" + str(reg): readers for reg, readers in
                             sorted(register_readers.items())},
        "repeated_source_registers": list(repeated_sources),
        "external_reads": external,
        "self_contained": not external,
        "memory": memory,
        "repeated_offsets": sorted(offset for offset, count in counts.items()
                                   if count > 1),
        "store_to_load": store_to_load,
        "load_to_store": load_to_store,
        # A load whose value an ALU word (not another memory word) consumes.
        "load_feeds_alu": sorted({(edge["producer"], edge["consumer"])
                                  for edge in dependencies
                                  if decoded[edge["producer"]][1] == "LW"
                                  and decoded[edge["consumer"]][1]
                                  not in _MEMORY_NAMES}),
        "branches": branches,
        "control_flow": "forward_branches" if branches else "straight_line",
    }


def _signed(value: int) -> int:
    return value - (1 << 32) if value & 0x80000000 else value


def _trunc_div(dividend: int, divisor: int) -> int:
    """Signed division truncated toward zero, as RV32 ``DIV`` requires."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def _alu_value(name: str, a: int, b: int, operands: dict[str, int]) -> int:
    """Evaluate one non-memory, non-PC-relative instruction."""
    if name == "ADDI":
        return (a + operands["imm"]) & _MASK32
    if name == "SLTI":
        return int(_signed(a) < operands["imm"])
    if name == "SLTIU":
        return int(a < (operands["imm"] & _MASK32))
    if name == "XORI":
        return a ^ (operands["imm"] & _MASK32)
    if name == "ORI":
        return a | (operands["imm"] & _MASK32)
    if name == "ANDI":
        return a & (operands["imm"] & _MASK32)
    if name == "SLLI":
        return (a << operands["shamt"]) & _MASK32
    if name == "SRLI":
        return a >> operands["shamt"]
    if name == "SRAI":
        return (_signed(a) >> operands["shamt"]) & _MASK32
    if name == "ADD":
        return (a + b) & _MASK32
    if name == "SUB":
        return (a - b) & _MASK32
    if name == "SLL":
        return (a << (b & 31)) & _MASK32
    if name == "SLT":
        return int(_signed(a) < _signed(b))
    if name == "SLTU":
        return int(a < b)
    if name == "XOR":
        return a ^ b
    if name == "SRL":
        return a >> (b & 31)
    if name == "SRA":
        return (_signed(a) >> (b & 31)) & _MASK32
    if name == "OR":
        return a | b
    if name == "AND":
        return a & b
    if name == "MUL":
        return (a * b) & _MASK32
    if name == "MULH":
        return ((_signed(a) * _signed(b)) >> 32) & _MASK32
    if name == "MULHSU":
        return ((_signed(a) * b) >> 32) & _MASK32
    if name == "MULHU":
        return ((a * b) >> 32) & _MASK32
    if name == "DIV":
        # Division by zero yields -1; the INT_MIN / -1 overflow wraps to
        # INT_MIN once the quotient is masked.
        if b == 0:
            return _MASK32
        return _trunc_div(_signed(a), _signed(b)) & _MASK32
    if name == "DIVU":
        if b == 0:
            return _MASK32
        return a // b
    if name == "REM":
        if b == 0:
            return a
        if (a, b) == (0x80000000, _MASK32):
            return 0
        dividend, divisor = _signed(a), _signed(b)
        quotient = _trunc_div(dividend, divisor)
        return (dividend - quotient * divisor) & _MASK32
    if name == "REMU":
        if b == 0:
            return a
        return a % b
    raise AssertionError(f"unhandled instruction {name}")  # pragma: no cover


def _check_register_state(registers: object) -> list[int]:
    if not isinstance(registers, dict):
        raise ValueError("registers must be a mapping of register number to value")
    state = [0] * 32
    for reg, value in registers.items():
        if type(reg) is not int or not 0 <= reg < 32:
            raise ValueError(f"register number {reg!r} is not an integer in [0, 31]")
        if type(value) is not int or not 0 <= value <= _MASK32:
            raise ValueError(
                f"register x{reg} value {value!r} is not a 32-bit unsigned integer")
        state[reg] = value
    state[0] = 0  # x0 is hard-wired; the initial state cannot change that.
    return state


def _check_memory_state(memory: object) -> dict[int, int]:
    if not isinstance(memory, dict):
        raise ValueError("memory must be a mapping of address to 32-bit value")
    for address, value in memory.items():
        if type(address) is not int or not 0 <= address <= _MASK32:
            raise ValueError(
                f"memory address {address!r} is not a 32-bit unsigned integer")
        if type(value) is not int or not 0 <= value <= _MASK32:
            raise ValueError(
                f"memory value at {address:#010x} is not a 32-bit unsigned "
                "integer")
    return dict(memory)


class RetirementTrace(NamedTuple):
    """One retired instruction's retirement witness.

    ``pc`` is the instruction's address, ``insn`` its decoded name, ``rd`` the
    architectural destination (``0`` when it writes none) and ``wdata`` the value
    written back (for a store, the value it stored; for a branch, ``0``).  The
    tuple is what an RVFI retirement stream exposes per instruction, so a host can
    be compared against it directly.
    """

    pc: int
    insn: str
    rd: int
    wdata: int


@dataclass(frozen=True, slots=True)
class _Executed:
    """One decoded, executed instruction and everything the model reports about it."""

    name: str
    rd: int | None
    value: int
    next_pc: int
    reads: dict[str, int]
    address: int | None = None
    store: bool = False
    load: bool = False
    taken: bool | None = None
    target_pc: int | None = None


def _branch_taken(name: str, left: int, right: int) -> bool:
    """Evaluate one B-type condition with RV32 signed/unsigned semantics."""
    if name == "BEQ":
        return left == right
    if name == "BNE":
        return left != right
    if name == "BLT":
        return _signed(left) < _signed(right)
    if name == "BGE":
        return _signed(left) >= _signed(right)
    if name == "BLTU":
        return left < right
    if name == "BGEU":
        return left >= right
    raise AssertionError(f"not a branch: {name}")  # pragma: no cover


def _execute_word(word: int, state: list[int], memory_state: dict[int, int], *,
                  pc: int, index: int, allow_branches: bool = False,
                  allow_jumps: bool = False) -> _Executed:
    """Execute one decoded 32-bit word against the mutable machine state.

    ``state`` is the 32-entry register file and ``memory_state`` the sparse
    word-addressed data window; both are mutated in place (a write to ``x0`` is
    dropped).  ``index`` is the word's position in the installed image and is
    used only in error messages.  The compressed interpreter reuses this helper
    for the 32-bit words a mixed image can hold, so both models share one
    definition of every instruction.

    A jump writes ``pc + 4`` to its link register exactly as the RTL does: the
    retirement witness reports ``rd`` 1 and ``wdata = pc + 4`` for ``rd = x1``,
    and ``rd``/``wdata`` 0 for ``rd = x0`` (RVFI's no-writeback rule).
    """
    name, operands = _decode(word, allow_branch=allow_branches,
                             allow_jump=allow_jumps)
    next_pc = (pc + 4) & _MASK32
    if name in _JUMP_NAMES:
        if name == "JAL":
            target = (pc + operands["imm"]) & _MASK32
        else:
            target = ((state[operands["rs1"]] + operands["imm"]) & _MASK32) & ~1
        link = operands["rd"]
        value = (pc + 4) & _MASK32
        if link:
            state[link] = value
        return _Executed(name, link or None, value, target, {},
                         target_pc=target)
    if name == "LUI":
        value = (operands["imm"] << 12) & _MASK32
    elif name == "AUIPC":
        value = (pc + (operands["imm"] << 12)) & _MASK32
    elif name in _BRANCH_NAMES:
        left = state[operands["rs1"]]
        right = state[operands["rs2"]]
        reads = {"x" + str(operands["rs1"]): left,
                 "x" + str(operands["rs2"]): right}
        taken = _branch_taken(name, left, right)
        target = (pc + operands["imm"]) & _MASK32
        return _Executed(name, None, 0, target if taken else next_pc, reads,
                         taken=taken, target_pc=target)
    elif name == "SW":
        address = (state[operands["rs1"]] + operands["imm"]) & _MASK32
        if address % 4:
            raise ValueError(
                f"instruction {index} SW effective address "
                f"{address:#010x} is not 4-byte aligned")
        stored = state[operands["rs2"]]
        memory_state[address] = stored
        return _Executed(name, None, stored, next_pc, {}, address=address,
                         store=True)
    elif name == "LW":
        address = (state[operands["rs1"]] + operands["imm"]) & _MASK32
        if address % 4:
            raise ValueError(
                f"instruction {index} LW effective address "
                f"{address:#010x} is not 4-byte aligned")
        value = memory_state.get(address, 0)
        rd = operands["rd"]
        if rd:
            state[rd] = value
        return _Executed(name, rd, value, next_pc, {}, address=address,
                         load=True)
    else:
        left = state[operands.get("rs1", 0)]
        right = state[operands["rs2"]] if "rs2" in operands else 0
        value = _alu_value(name, left, right, operands)
    # The source values are the ones this instruction read, i.e. the state
    # before its own writeback.
    reads = {"x" + str(operands[field]): state[operands[field]]
             for field in ("rs1", "rs2") if field in operands}
    rd = operands.get("rd")
    if rd:
        state[rd] = value
    return _Executed(name, rd, value, next_pc, reads)


def _check_step_bound(max_steps: object, length: int,
                      *, control: ControlFlow | None = None) -> int:
    if max_steps is None:
        if control is not None:
            # The static retirement bound of the recognised program: one per
            # installed word plus the retirements each bounded loop repeats.
            return control.step_limit + 1
        # A straight-line or forward-only program retires at most one
        # instruction per installed word, and the +1 absorbs the loop-entry
        # step of a malformed image.
        return length + 1
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be a positive integer or None")
    return max_steps


def run_program(words: tuple[int, ...], *, registers: dict[int, int],
                memory: dict[int, int], data_base: int | None = None,
                window_size: int | None = None, trace: bool = False,
                allow_branches: bool = False,
                allow_address_forms: bool = False,
                allow_jumps: bool = False,
                allow_loops: bool = False,
                max_steps: int | None = None,
                validate: bool = True) -> dict[str, object]:
    """Execute one trampoline image with a bounded, PC-indexed interpreter.

    Unlike a straight-line walk, this model follows the program counter: words
    are fetched at ``pc``, a 32-bit instruction advances ``pc`` by four, and a
    forward branch may redirect it.  Execution stops when ``pc`` reaches the
    return jump the host appends at index ``len(words)``.  The step bound (one
    per installed word plus one, or an explicit ``max_steps``) makes a would-be
    loop terminate with an error instead of hanging; that is a safety net for
    diagnostics, because :func:`validate_program_words` already refuses a
    non-forward target.

    ``validate=True`` runs the full trampoline gate first; ``validate=False``
    admits structural control-flow faults so the step bound itself can be
    exercised (tests and diagnostics only).  The result document extends the
    historical shape with ``trace`` (one :class:`RetirementTrace` per retired
    instruction), ``retired_count`` and ``pc_order``; ``retires`` keeps its old
    meaning and value for straight-line programs, and ``steps`` is still the
    optional human-readable trace enabled by ``trace=True``.
    """
    if isinstance(words, (str, bytes, bytearray)):
        raise ValueError("words must be a sequence of 32-bit instruction words")
    words = tuple(words)
    if not words:
        raise ValueError("program has no instruction")
    branching = _check_flag_argument(allow_branches, "allow_branches")
    address_forms = _check_flag_argument(allow_address_forms,
                                         "allow_address_forms")
    jumping = _check_flag_argument(allow_jumps, "allow_jumps")
    looping = _check_flag_argument(allow_loops, "allow_loops")
    _check_flag_argument(validate, "validate")
    if data_base is not None and (type(data_base) is not int
                                  or not 0 <= data_base <= _MASK32):
        raise ValueError("data_base must be a 32-bit unsigned integer or None")
    pc_base = 0 if data_base is None else data_base
    control: ControlFlow | None = None
    if validate:
        validate_program_words(_REFERENCE_PROFILE, words,
                               window_size=window_size,
                               allow_branches=branching,
                               allow_address_forms=address_forms,
                               allow_jumps=jumping, allow_loops=looping,
                               image_base=pc_base)
        if branching or jumping or looping:
            control = control_flow_analysis(
                words, allow_branches=branching, allow_jumps=jumping,
                allow_loops=looping, image_base=pc_base)
    state = _check_register_state(registers)
    initial_memory = _check_memory_state(memory)
    memory_state = dict(initial_memory)
    if data_base is not None and (type(data_base) is not int
                                  or not 0 <= data_base <= _MASK32):
        raise ValueError("data_base must be a 32-bit unsigned integer or None")
    if not isinstance(trace, bool):
        raise ValueError("trace must be a boolean")
    program_end = (pc_base + 4 * len(words)) & _MASK32
    cap = _check_step_bound(max_steps, len(words), control=control)

    writes: list[dict[str, int | str]] = []
    steps: list[dict[str, object]] = []
    retirement: list[RetirementTrace] = []
    pc = pc_base
    steps_taken = 0
    while pc != program_end:
        offset = (pc - pc_base) & _MASK32
        if offset % 4 or offset // 4 >= len(words):
            raise ValueError(
                f"pc {pc:#010x} is outside the installed program "
                f"({len(words)} word(s) at {pc_base:#010x})")
        index = offset // 4
        executed = _execute_word(words[index], state, memory_state, pc=pc,
                                 index=index, allow_branches=branching,
                                 allow_jumps=jumping)
        steps_taken += 1
        if steps_taken > cap:
            raise ValueError(
                f"program exceeded the {cap}-step bound; the image is not a "
                "bounded straight-line or forward-branch program")
        if executed.rd:
            writes.append({"index": index, "pc": pc, "name": executed.name,
                           "rd": executed.rd, "value": executed.value})
        if trace:
            if executed.store:
                steps.append({"index": index, "pc": pc,
                              "name": executed.name,
                              "address": executed.address,
                              "value": executed.value})
            elif executed.load:
                steps.append({"index": index, "pc": pc,
                              "name": executed.name,
                              "address": executed.address,
                              "value": executed.value,
                              "rd": executed.rd if executed.rd else None})
            elif executed.name in _BRANCH_NAMES:
                steps.append({"index": index, "pc": pc,
                              "name": executed.name, "reads": executed.reads,
                              "taken": executed.taken,
                              "target_pc": executed.target_pc})
            elif executed.name in _JUMP_NAMES:
                steps.append({"index": index, "pc": pc,
                              "name": executed.name,
                              "target_pc": executed.target_pc,
                              "link": executed.rd if executed.rd else None,
                              "link_value": (executed.value
                                             if executed.rd else None)})
            else:
                steps.append({"index": index, "pc": pc,
                              "name": executed.name, "reads": executed.reads,
                              "rd": executed.rd if executed.rd else None,
                              "value": executed.value})
        retirement.append(RetirementTrace(
            pc, executed.name, executed.rd or 0,
            executed.value if (executed.rd or executed.store) else 0))
        pc = executed.next_pc

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


def reference_run(words: tuple[int, ...], *, registers: dict[int, int],
                  memory: dict[int, int], data_base: int | None = None,
                  window_size: int | None = None,
                  trace: bool = False,
                  allow_branches: bool = False,
                  allow_address_forms: bool = False,
                  allow_jumps: bool = False,
                  allow_loops: bool = False,
                  max_steps: int | None = None) -> dict[str, object]:
    """Model one trampoline program with RV32I+RV32M semantics.

    ``registers`` is the initial register state (a mapping; missing registers
    start at 0) and ``memory`` the initial sparse data window.  ``data_base``
    is the address of the first instruction; it defaults to 0.

    The words are validated first against a maximal RV32IM profile.
    ``window_size`` is passed through to that validation and defaults to
    ``None``, which skips only the data-window bound: a caller can therefore
    replay a program generated for any 32-bit profile.  Passing the host's
    declared window refuses a memory word the trampoline could not execute.
    ``trace=True`` adds one ``steps`` entry per retired instruction (see the
    module docstring).  ``allow_branches``/``allow_address_forms``/
    ``allow_jumps``/``allow_loops`` admit the opt-in shapes, and the result
    always carries ``trace``/``retired_count``/``pc_order`` on top of the
    historical fields.  A loop legitimately repeats PCs, so ``pc_order`` is the
    observed retirement order, not a strictly increasing sequence.  The model
    itself never uses a reserved register and only reflects the state passed in.
    """
    return run_program(words, registers=registers, memory=memory,
                       data_base=data_base, window_size=window_size,
                       trace=trace, allow_branches=allow_branches,
                       allow_address_forms=allow_address_forms,
                       allow_jumps=allow_jumps, allow_loops=allow_loops,
                       max_steps=max_steps, validate=True)
