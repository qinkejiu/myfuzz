"""ZipCPU boot image for the real-CPU Wishbone integration test.

Why this file exists
--------------------
``tests/integration/rtl/soc_zipcpu_wishbone_tb.sv`` drives a *real* ZipCPU
(``third_party/soc-zipcpu/rtl/core/zipwb.v``) as a Wishbone master through the
project's ``wishbone_processor_memory_adapter`` into
``myfuzz_processor_memory_backend``.  That CPU executes a program, so the test
needs a program image -- and the program image has to be produced without the
vendored ZipCPU assembler.

The vendored assembler (``third_party/soc-zipcpu/sw/zasm``) does not build with a
modern toolchain: ``zparser.h`` declares an enumerator ``ZIP_SP`` that is textually
replaced by the ``#define ZIP_SP 0xd0000`` in ``zopcodes.h`` (zopcodes.h:54 /
zparser.h:75), and ``zdump.cpp`` calls a ``zipi_to_string`` that no longer exists.
Patching that untracked third-party tree is out of scope, so the handful of
encodings this test needs are ported here from the authoritative vendored sources.

Which vendored source is authoritative
--------------------------------------
``zparser.cpp`` carries the ``op_*()`` instruction builders, but its own header
warns that "the instructions built here are likely to be a generation or two out
of date" (zparser.h:15-17), and it *is* stale: its ``ZIPOP`` enum (zparser.h:87-105)
puts ``LDI`` at 22, while the RTL decodes LDI from ``w_cis_op[4:1] == 4'hc``
(idecode.v:206), i.e. 24, and the disassembler table wants ``0x06000000``
(zopcodes.cpp:207) rather than the ``0x05800000`` that ``op_ldi`` would build.
The same stale-swap affects BREV/MPY/MOV.  Every encoding below is therefore
taken from the pair (a) the RTL decode predicates in ``idecode.v`` and (b) the
disassembler pattern table in ``zopcodes.cpp``, which agree with each other; the
``zparser`` builders are cited only where they agree as well.  Each function
carries the exact source lines it was derived from.

Regenerate the fixture with::

    python3 tests/integration/zipcpu_boot_image.py --write

or verify the committed fixture is up to date with::

    python3 tests/integration/zipcpu_boot_image.py --check
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Architectural constants
# ---------------------------------------------------------------------------

#: General purpose register numbers.  ``zopcodes.cpp:52-65`` (``zip_regstr[]``)
#: names index 13/14/15 SP/CC/PC, and the RTL agrees:
#:   idecode.v:94   localparam [3:0] CPU_SP_REG = 4'hd;
#:   zipcore.v:135  localparam [3:0] CPU_CC_REG = 4'he;
#:   idecode.v:96  localparam [3:0] CPU_PC_REG = 4'hf;
R0, R1, R2, R3, R4, R5, R6, R7 = range(8)
R8, R9, R10, R11, R12 = range(8, 13)
SP = 0xD
CC = 0xE
PC = 0xF

#: Instruction opcode field (``iword[26:22]``, idecode.v:204 ``assign w_op = iword[26:22]``).
#: Values cross-checked against the disassembler table in ``zopcodes.cpp``.
OP_ADD = 0x02  # zopcodes.cpp:138  {"ADD", 0x87c40000, 0x00800000, ...}
OP_OR = 0x03  # zopcodes.cpp:141  {"OR",  0x87c40000, 0x00c00000, ...}
OP_LOD = 0x12  # zopcodes.cpp:189  {"LW",  0x87c40000, 0x04840000, ...}  (LOD)
OP_STO = 0x13  # zopcodes.cpp:191  {"SW",  0x87c40000, 0x04c40000, ...}  (STO)
#: LDI is op 0x18 / 0x19: ``assign w_ldi = (w_cis_op[4:1] == 4'hc)`` (idecode.v:206)
#: admits 0b11000 and 0b11001, and ``zopcodes.cpp:207`` matches LDI on
#: ``0x06000000`` with bit 22 masked out (LDIn sets bit 22).
OP_LDI = 0x18

#: ``assign IMMSEL = 18`` (idecode.v:99).  Bit 18 selects the 14-bit
#: "register + immediate" operand form (idecode.v:350) over the 18-bit
#: immediate form (idecode.v:349).  ``DBLREGOP`` (zparser.cpp:60-62) sets it.
IMMSEL = 18

MASK32 = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Program layout -- these constants are mirrored in the testbench
# ---------------------------------------------------------------------------

#: ``$readmemh`` fills ``ram[0]`` first, so the image starts at byte address 0.
IMAGE_BASE = 0x0000_0000
#: Word count of the testbench RAM (and therefore of the image).  The image is
#: zero padded so an uninitialised fetch returns a defined 0 rather than X.
IMAGE_WORDS = 1024

#: Must equal the testbench's ``zipwb`` ``RESET_ADDRESS`` parameter.
PROGRAM_BASE = 0x0000_0100
#: The two store targets the testbench checks in the RAM array.
STORE_A_ADDR = 0x0000_0200
STORE_B_ADDR = 0x0000_0204

#: Value loaded by ``LDI`` and stored to ``STORE_A_ADDR``.
IMMEDIATE_VALUE = 0x0000_BEEF
#: Value read back from ``STORE_A_ADDR``, incremented by the ALU, and stored to
#: ``STORE_B_ADDR``.  The second store can only hold this value if the CPU
#: really fetched, decoded and executed all of LDI/STO/LOD/ADD/STO.
INCREMENTED_VALUE = (IMMEDIATE_VALUE + 1) & MASK32


# ---------------------------------------------------------------------------
# Field builders (ported)
# ---------------------------------------------------------------------------

def _sign_extend(value: int, bits: int) -> int:
    """Sign extend ``value`` from ``bits``, returning a Python signed integer.

    Mirrors ``assign o_I = { {(32-22){r_I[22]}}, r_I[21:0] };`` (idecode.v:903)
    for the LDI form and the equivalent sign extension of the 18/14-bit operand
    forms at idecode.v:349-350.
    """
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def encode_ldi(immediate: int, ra: int) -> int:
    """``LDI imm, Ra`` -- load a 23-bit immediate.

    Field layout: bits 30:27 = Ra, bits 26:22 = opcode ``0b11000``, bits 22:0 =
    immediate.  The immediate is the low 23 bits of the instruction word:

      * idecode.v:347  ``2'b00: w_fullI = { iword[22:0] }; // LDI``
      * idecode.v:903  ``assign o_I = { {(32-22){r_I[22]}}, r_I[21:0] };``
        (sign extends from bit 22, so the immediate is 23-bit signed)
      * zopcodes.cpp:207 ``{ "LDI", 0x87800000, 0x06000000, ZIP_REGFIELD(27),
        ..., ZIP_IMMFIELD(23,0) }``

    ``zparser.cpp:108-112`` (``op_ldi``) is *not* used: it ORs in
    ``ZIPO_LDI << 22`` with the stale ``ZIPO_LDI == 22``, giving ``0x05800000``,
    which the RTL above would not decode as an LDI at all.

    Bit 22 is shared between the opcode field and the immediate, so the two
    halves of the pair are ``LDI`` (bit 22 clear, immediate ``0x000000`` to
    ``0x3fffff``) and ``LDIn`` (bit 22 set, the two's complement encoding of
    ``-0x400000`` to ``-1``).  Both load the same 23-bit signed value, so this
    function accepts the whole ``[-0x400000, 0x3fffff]`` range and lets the
    immediate choose the mnemonic.
    """
    if not -(1 << 22) <= immediate < (1 << 22):
        raise ValueError(f"LDI immediate out of 23-bit range: {immediate:#x}")
    if not 0 <= ra <= 0xF:
        raise ValueError(f"bad register: {ra}")
    return (((OP_LDI & 0x1F) << 22) | ((ra & 0xF) << 27) | (immediate & 0x7FFFFF)) & MASK32


def encode_lod(immediate: int, ra: int, rb: int) -> int:
    """``LOD imm(Rb), Ra`` -- word load.

    ``zparser.cpp:194-195`` builds ``DBLREGOP(ZIPO_LOD, cnd, imm, b, a)`` with
    ``ZIPO_LOD == 18`` (zparser.h:98), and ``DBLREGOP`` (zparser.cpp:60-62) is
    ``((OP&0x1f)<<22) | ((A&0xf)<<27) | ((CND&7)<<19) | (1<<18) | ((B&0xf)<<14)
    | (IMM & 0x03fff)``.  The RTL classifies it as a load with
    ``w_mem = (w_cis_op[4:3] == 2'b10) && (w_cis_op[2:1] != 2'b00)`` and
    ``w_sto = w_mem && w_cis_op[0]`` (idecode.v:214-215), so op 0x12 is a load
    and the disassembler spells it ``LW`` at ``zopcodes.cpp:189``.
    """
    if not -(1 << 13) <= immediate < (1 << 13):
        raise ValueError(f"LOD offset out of signed 14-bit range: {immediate:#x}")
    return (((OP_LOD & 0x1F) << 22) | ((ra & 0xF) << 27) | (1 << IMMSEL)
            | ((rb & 0xF) << 14) | (immediate & 0x3FFF)) & MASK32


def encode_sto(immediate: int, rv: int, rb: int) -> int:
    """``STO Rv, imm(Rb)`` -- word store.

    ``zparser.cpp:201-202`` builds ``DBLREGOP(ZIPO_STO, cnd, imm, b, v)``: the
    macro's ``A`` field (bits 30:27) carries the *value* register and its ``B``
    field (bits 17:14) carries the index register.  ``zopcodes.cpp:191-192``
    agrees -- ``{"SW", 0x87c40000, 0x04c00000, ZIP_OPUNUSED, ZIP_REGFIELD(27),
    ZIP_REGFIELD(14), ZIP_IMMFIELD(14,0), ...}`` -- and ``w_sto`` is the
    store half of the memory pair (idecode.v:215).
    """
    if not -(1 << 13) <= immediate < (1 << 13):
        raise ValueError(f"STO offset out of signed 14-bit range: {immediate:#x}")
    return (((OP_STO & 0x1F) << 22) | ((rv & 0xF) << 27) | (1 << IMMSEL)
            | ((rb & 0xF) << 14) | (immediate & 0x3FFF)) & MASK32


def encode_add(immediate: int, ra: int) -> int:
    """``ADD imm, Ra`` -- the 18-bit immediate form.

    ``zparser.cpp:226-230`` builds ``IMMOP(ZIPO_ADD, cnd, imm, a)`` and
    ``IMMOP`` (zparser.cpp:57-58) is ``((OP&0x01f)<<22)|((A&0x0f)<<27)
    |((CND&0x07)<<19)|(IMM & 0x03ffff)`` with bit 18 clear (that is the 18-bit
    immediate select, idecode.v:337-338).  ``zopcodes.cpp:138`` matches
    ``0x00800000`` for the no-index-register ADD.
    """
    if not -(1 << 17) <= immediate < (1 << 17):
        raise ValueError(f"ADD immediate out of signed 18-bit range: {immediate:#x}")
    return (((OP_ADD & 0x1F) << 22) | ((ra & 0xF) << 27) | (immediate & 0x3FFFF)) & MASK32


def encode_halt() -> int:
    """``HALT`` -- ``OR 0x10, CC``, bit 4 of CC is the sleep bit.

    ``zopcodes.cpp:104`` gives the exact word and mask:
    ``{ "HALT", 0xffc7ffff, 0x70c00010, ... }``; ``zparser.h:314-315``
    (``op_halt`` -> ``op_or(cond, 0x10, ZIP_CC)``) produces the same word with
    ``ZIP_CC == 14``, ``ZIPO_OR == 3``.
    """
    return 0x70C00010


def encode_noop() -> int:
    """``NOOP`` -- ``zopcodes.cpp:229`` ``{"NOOP", 0xf7ffffff, 0x77c00000, ...}``."""
    return 0x77C00000


def encode_break() -> int:
    """``BREAK``/``BRK`` -- ``zopcodes.cpp:209`` ``{"BRK", 0xf7ffffff, 0x77000000}``.

    Not emitted by the boot program; the testbench treats ``o_break`` as a hard
    failure, so the encoding is kept here for the self test and for the
    negative control that proves the ``o_break`` check can fire.

    ``zparser.cpp:127-128`` (``op_break()``) returns ``0x76400000``, which is
    stale in the same way as ``op_ldi``: that word decodes as ``LDIn`` under the
    RTL rules (``op 0x19``, idecode.v:206), not as a break.  The table value is
    used instead.
    """
    return 0x77000000


# ---------------------------------------------------------------------------
# Program
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Instruction:
    address: int
    word: int
    text: str

    @property
    def encoding(self) -> str:
        return f"{self.word:08x}"


def build_program() -> List[Instruction]:
    """The straight-line boot program, six instructions then a HALT.

    There is deliberately no branch: the point of the program is that the CPU
    *executes* it, and every value that ends up in RAM is a value that only this
    instruction stream can produce.

      * ``STORE_A_ADDR`` receives ``IMMEDIATE_VALUE`` from an ``LDI``.
      * ``STORE_B_ADDR`` receives the value *read back* from ``STORE_A_ADDR``
        and incremented by the ALU, so it proves the load path and the ALU as
        well as the store path.
    """
    return [
        Instruction(PROGRAM_BASE + 0x00, encode_ldi(STORE_A_ADDR, R1),
                    f"LDI   {STORE_A_ADDR:#010x}, R1"),
        Instruction(PROGRAM_BASE + 0x04, encode_ldi(IMMEDIATE_VALUE, R2),
                    f"LDI   {IMMEDIATE_VALUE:#010x}, R2"),
        Instruction(PROGRAM_BASE + 0x08, encode_sto(0, R2, R1),
                    "STO   R2, 0(R1)"),
        Instruction(PROGRAM_BASE + 0x0C, encode_lod(0, R3, R1),
                    "LOD   0(R1), R3"),
        Instruction(PROGRAM_BASE + 0x10, encode_add(1, R3),
                    "ADD   1, R3"),
        Instruction(PROGRAM_BASE + 0x14, encode_sto(4, R3, R1),
                    "STO   R3, 4(R1)"),
        Instruction(PROGRAM_BASE + 0x18, encode_halt(), "HALT"),
    ]


def expected_word(byte_address: int) -> int:
    """Expected RAM content at ``byte_address`` after the program has run."""
    if byte_address == STORE_A_ADDR:
        return IMMEDIATE_VALUE
    if byte_address == STORE_B_ADDR:
        return INCREMENTED_VALUE
    return 0


def render_image() -> str:
    """Render the ``$readmemh`` image: one 32-bit word per line, base first."""
    program = {item.address: item.word for item in build_program()}
    lines = []
    for word_index in range(IMAGE_WORDS):
        address = IMAGE_BASE + 4 * word_index
        if address in program:
            lines.append(f"{program[address]:08x}")
        elif address in (STORE_A_ADDR, STORE_B_ADDR):
            # Data words start cleared; the CPU is what writes them.
            lines.append("00000000")
        else:
            lines.append("00000000")
    return "\n".join(lines) + "\n"


FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "soc_zipcpu_wishbone_boot.hex"


def write_fixture(path: Path = FIXTURE_PATH) -> Path:
    path.write_text(render_image(), encoding="ascii")
    return path


# ---------------------------------------------------------------------------
# Decoder -- independent of the encoder, driven by the RTL decode predicates
# ---------------------------------------------------------------------------

def disassemble(word: int) -> str:
    """Decode one instruction word.

    This deliberately re-derives the fields the way ``idecode.v`` does instead of
    calling the encoder, so an encode/decode round trip in the tests is a real
    check and not a tautology.
    """
    word &= MASK32
    op = (word >> 22) & 0x1F
    ra = (word >> 27) & 0xF
    imm_sel = (word >> IMMSEL) & 1
    rb = (word >> 14) & 0xF

    if word == encode_halt():
        return "HALT"
    if word == encode_noop():
        return "NOOP"
    # idecode.v:206  assign w_ldi = (w_cis_op[4:1] == 4'hc);
    if (op >> 1) & 0xF == 0xC:
        # idecode.v:347/903 -- 23-bit immediate, sign extended from bit 22.
        immediate = _sign_extend(word & 0x7FFFFF, 23)
        mnemonic = "LDI" if op == OP_LDI else "LDIn"
        return f"{mnemonic}  {_signed(immediate)}, {_reg(ra)}"
    # idecode.v:214-215  w_mem / w_sto
    if (op >> 3) & 0x3 == 0b10 and (op >> 1) & 0x3 != 0:
        if not imm_sel:
            raise ValueError(f"memory op without an index register: {word:#010x}")
        immediate = _sign_extend(word & 0x3FFF, 14)  # idecode.v:350
        if op & 1:
            return f"STO   {_reg(ra)}, {_signed(immediate)}({_reg(rb)})"
        return f"LOD   {_signed(immediate)}({_reg(rb)}), {_reg(ra)}"
    if op == OP_ADD and not imm_sel:
        immediate = _sign_extend(word & 0x3FFFF, 18)  # idecode.v:349
        return f"ADD   {_signed(immediate)}, {_reg(ra)}"
    if op == OP_OR and not imm_sel:
        immediate = _sign_extend(word & 0x3FFFF, 18)
        return f"OR    {_signed(immediate)}, {_reg(ra)}"
    raise ValueError(f"unrecognised instruction word: {word:#010x}")


_REGNAMES = ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
             "R10", "R11", "R12", "SP", "CC", "PC"]


def _reg(index: int) -> str:
    return _REGNAMES[index & 0xF]


def _signed(value: int) -> str:
    """Render an already sign-extended immediate (``-0x1``, ``0x4``)."""
    return f"{value:#x}"


def program_listing() -> str:
    """Human readable listing used in reports and failure messages."""
    rows = ["addr     encoding  instruction"]
    for item in build_program():
        rows.append(f"{item.address:#08x} {item.encoding}  {item.text}")
    return "\n".join(rows)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true",
                        help="regenerate the committed $readmemh fixture")
    action.add_argument("--check", action="store_true",
                        help="fail if the committed fixture is out of date")
    action.add_argument("--list", action="store_true",
                        help="print the program listing and the fixture hash")
    args = parser.parse_args(argv)

    if args.list:
        print(program_listing())
        return 0

    rendered = render_image()
    if args.write:
        write_fixture()
        print(f"wrote {FIXTURE_PATH}")
        return 0
    current = FIXTURE_PATH.read_text(encoding="ascii") if FIXTURE_PATH.is_file() else ""
    if current != rendered:
        print(f"{FIXTURE_PATH} is out of date; re-run with --write")
        return 1
    print(f"{FIXTURE_PATH} is up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
