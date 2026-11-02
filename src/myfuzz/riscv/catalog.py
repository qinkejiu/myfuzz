"""Declarative RISC-V instruction table: names, extensions, formats, operands.

This table is the single source of truth for the generator and for future ISA
matrices.  It holds only facts (encoded fixed bits, operand classes, immediate
range/alignment, whether ``rd`` is written); encoding and generation live in
``encoding.py`` and ``program.py``.

Bit layouts were cross-checked (2026-10-30) against:

* the RISC-V ISA manual field layouts used by the vendored riscv-dv instruction
  lists (``third_party/rfuzz/upstream/ibex/vendor/google_riscv-dv/src/isa``),
  which name each instruction's format/extension but carry no raw opcode bits,
* clang's RISC-V integrated assembler,
  ``clang --target=riscv32|riscv64 -march=<ext> -c one.S`` followed by
  ``readelf -x .text``, for 100+ instructions (see tests/riscv/test_encoding),
* the repository's independent decoder
  ``myfuzz.isa.transducer.RiscvInstructionTransducer`` (I/M/C), used as a
  second opinion in the encoder tests.

Extension strings are normalized upper case: ``I``, ``M``, ``A``, ``C``,
``ZICSR``, ``ZIFENCEI``.  ``min_xlen`` marks RV64-only encodings.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InstructionSpec:
    """One instruction's static encoding facts.

    ``kind`` selects the field layout in ``encoding.py``.  ``imm_bits`` is the
    encoded immediate field width; ``imm_signed``/``imm_align``/``imm_nonzero``
    describe its range.  ``f1_safe`` marks instructions the existing F1
    validator (``myfuzz.scenario.rv32i_sources.validate_instruction_bytes``)
    admits; generated programs stay inside that set by default.
    """

    name: str
    extension: str
    kind: str
    fixed: int
    operands: tuple[str, ...]
    writes_rd: bool = False
    f1_safe: bool = False
    imm_bits: int = 0
    imm_signed: bool = True
    imm_align: int = 1
    imm_nonzero: bool = False
    min_xlen: int = 32
    compressed: bool = False
    control_flow: bool = False


def _r(name: str, funct3: int, funct7: int, *, opcode: int = 0x33,
       ext: str = "I", f1: bool = True, xlen: int = 32) -> InstructionSpec:
    return InstructionSpec(
        name, ext, "R", opcode | funct3 << 12 | funct7 << 25,
        ("rd", "rs1", "rs2"), writes_rd=True, f1_safe=f1, min_xlen=xlen,
    )


def _i(name: str, funct3: int, *, opcode: int = 0x13, ext: str = "I",
       f1: bool = True, align: int = 1, nonzero: bool = False,
       xlen: int = 32, control_flow: bool = False) -> InstructionSpec:
    return InstructionSpec(
        name, ext, "I", opcode | funct3 << 12, ("rd", "rs1", "imm"),
        writes_rd=True, f1_safe=f1, imm_bits=12, imm_align=align,
        imm_nonzero=nonzero, min_xlen=xlen, control_flow=control_flow,
    )


def _load(name: str, funct3: int, align: int, *, f1: bool = False,
          xlen: int = 32) -> InstructionSpec:
    return InstructionSpec(
        name, "I", "LOAD", 0x03 | funct3 << 12, ("rd", "rs1", "imm"),
        writes_rd=True, f1_safe=f1, imm_bits=12, imm_align=align,
        min_xlen=xlen,
    )


def _store(name: str, funct3: int, align: int, *, f1: bool = False,
           xlen: int = 32) -> InstructionSpec:
    return InstructionSpec(
        name, "I", "STORE", 0x23 | funct3 << 12, ("rs2", "rs1", "imm"),
        f1_safe=f1, imm_bits=12, imm_align=align, min_xlen=xlen,
    )


def _branch(name: str, funct3: int) -> InstructionSpec:
    return InstructionSpec(
        name, "I", "B", 0x63 | funct3 << 12, ("rs1", "rs2", "imm"),
        imm_bits=13, imm_align=2, control_flow=True,
    )


def _shift(name: str, funct3: int, arithmetic: bool, *, opcode: int = 0x13,
           xlen: int = 32, f1: bool = True) -> InstructionSpec:
    return InstructionSpec(
        name, "I", "SHIFT",
        opcode | funct3 << 12 | (0x400 << 20 if arithmetic else 0),
        ("rd", "rs1", "shamt"), writes_rd=True, f1_safe=f1,
        min_xlen=xlen,
    )


def _amo(name: str, funct5: int, *, load_reserved: bool = False) -> InstructionSpec:
    operands = ("rd", "rs1") if load_reserved else ("rd", "rs1", "rs2")
    return InstructionSpec(
        name, "A", "LR" if load_reserved else "AMO",
        0x2F | 2 << 12 | funct5 << 27, operands, writes_rd=True,
    )


def _csr(name: str, funct3: int, *, immediate: bool) -> InstructionSpec:
    operands = ("rd", "zimm", "csr") if immediate else ("rd", "rs1", "csr")
    return InstructionSpec(
        name, "ZICSR", "CSR_I" if immediate else "CSR",
        0x73 | funct3 << 12, operands, writes_rd=True,
    )


def _c(name: str, kind: str, fixed: int, operands: tuple[str, ...], *,
       writes_rd: bool = False, f1: bool = False, imm_bits: int = 0,
       imm_signed: bool = True, imm_align: int = 1,
       imm_nonzero: bool = False, control_flow: bool = False) -> InstructionSpec:
    return InstructionSpec(
        name, "C", kind, fixed, operands, writes_rd=writes_rd, f1_safe=f1,
        imm_bits=imm_bits, imm_signed=imm_signed, imm_align=imm_align,
        imm_nonzero=imm_nonzero, compressed=True, control_flow=control_flow,
    )


_SPECS: list[InstructionSpec] = []

# --- RV32I register/immediate ALU -------------------------------------------
for _name, _f3 in (("ADD", 0), ("SUB", 0), ("SLL", 1), ("SLT", 2), ("SLTU", 3),
                   ("XOR", 4), ("SRL", 5), ("SRA", 5), ("OR", 6), ("AND", 7)):
    _SPECS.append(_r(_name, _f3, 0x20 if _name in ("SUB", "SRA") else 0))
for _name, _f3 in (("ADDI", 0), ("SLTI", 2), ("SLTIU", 3), ("XORI", 4),
                   ("ORI", 6), ("ANDI", 7)):
    _SPECS.append(_i(_name, _f3))
for _name, _f3, _arith in (("SLLI", 1, False), ("SRLI", 5, False),
                           ("SRAI", 5, True)):
    _SPECS.append(_shift(_name, _f3, _arith))

# --- RV32I loads, stores, branches, upper immediates, jumps, system ---------
for _name, _f3, _align, _f1 in (("LB", 0, 1, False), ("LH", 1, 2, False),
                                ("LW", 2, 4, True), ("LBU", 4, 1, False),
                                ("LHU", 5, 2, False)):
    _SPECS.append(_load(_name, _f3, _align, f1=_f1))
for _name, _f3, _align, _f1 in (("SB", 0, 1, True), ("SH", 1, 2, False),
                                ("SW", 2, 4, True)):
    _SPECS.append(_store(_name, _f3, _align, f1=_f1))
for _name, _f3 in (("BEQ", 0), ("BNE", 1), ("BLT", 4), ("BGE", 5),
                   ("BLTU", 6), ("BGEU", 7)):
    _SPECS.append(_branch(_name, _f3))
_SPECS.append(InstructionSpec("LUI", "I", "U", 0x37, ("rd", "imm"),
                              writes_rd=True, f1_safe=True, imm_bits=20,
                              imm_signed=False))
_SPECS.append(InstructionSpec("AUIPC", "I", "U", 0x17, ("rd", "imm"),
                              writes_rd=True, imm_bits=20, imm_signed=False))
_SPECS.append(InstructionSpec("JAL", "I", "J", 0x6F, ("rd", "imm"),
                              writes_rd=True, imm_bits=21, imm_align=2,
                              control_flow=True))
_SPECS.append(_i("JALR", 0, opcode=0x67, f1=False, align=2,
                        control_flow=True))
_SPECS.append(InstructionSpec("FENCE", "I", "FENCE", 0x0F, ("pred", "succ")))
_SPECS.append(InstructionSpec("FENCE.I", "ZIFENCEI", "FENCEI", 0x100F, ()))
_SPECS.append(InstructionSpec("ECALL", "I", "SYSTEM", 0x73, ()))
_SPECS.append(InstructionSpec("EBREAK", "I", "SYSTEM", 0x100073, ()))

# --- RV32M ------------------------------------------------------------------
for _name, _f3 in (("MUL", 0), ("MULH", 1), ("MULHSU", 2), ("MULHU", 3),
                   ("DIV", 4), ("DIVU", 5), ("REM", 6), ("REMU", 7)):
    _SPECS.append(_r(_name, _f3, 1, ext="M"))

# --- RV32A atomics ----------------------------------------------------------
_SPECS.append(_amo("LR.W", 0b00010, load_reserved=True))
_SPECS.append(_amo("SC.W", 0b00011))
for _name, _funct5 in (("AMOSWAP.W", 0b00001), ("AMOADD.W", 0b00000),
                       ("AMOXOR.W", 0b00100), ("AMOAND.W", 0b01100),
                       ("AMOOR.W", 0b01000), ("AMOMIN.W", 0b10000),
                       ("AMOMAX.W", 0b10100), ("AMOMINU.W", 0b11000),
                       ("AMOMAXU.W", 0b11100)):
    _SPECS.append(_amo(_name, _funct5))

# --- Zicsr ------------------------------------------------------------------
for _name, _f3, _immediate in (("CSRRW", 1, False), ("CSRRS", 2, False),
                               ("CSRRC", 3, False), ("CSRRWI", 5, True),
                               ("CSRRSI", 6, True), ("CSRRCI", 7, True)):
    _SPECS.append(_csr(_name, _f3, immediate=_immediate))

# --- RV32C (only the F1-admissible subset is generated; all are encoded) -----
_SPECS.extend((
    _c("C.ADDI4SPN", "CIW", 0x0000, ("rd", "imm"), writes_rd=True,
       imm_bits=10, imm_signed=False, imm_align=4, imm_nonzero=True),
    _c("C.LW", "CL", 0x4000, ("rd", "rs1", "imm"), writes_rd=True,
       imm_bits=7, imm_signed=False, imm_align=4),
    _c("C.SW", "CL", 0xC000, ("rs2", "rs1", "imm"),
       imm_bits=7, imm_signed=False, imm_align=4),
    _c("C.NOP", "CNOP", 0x0001, ()),
    _c("C.ADDI", "CI", 0x0001, ("rd", "imm"), writes_rd=True, f1=True,
       imm_bits=6),
    _c("C.LI", "CI", 0x4001, ("rd", "imm"), writes_rd=True, f1=True,
       imm_bits=6),
    _c("C.LUI", "CI", 0x6001, ("rd", "imm"), writes_rd=True, f1=True,
       imm_bits=6, imm_nonzero=True),
    _c("C.MV", "CR", 0x8002, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.ADD", "CR", 0x9002, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.SUB", "CA", 0x8C01, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.XOR", "CA", 0x8C21, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.OR", "CA", 0x8C41, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.AND", "CA", 0x8C61, ("rd", "rs2"), writes_rd=True, f1=True),
    _c("C.SRLI", "CSHIFT", 0x8001, ("rd", "shamt"), writes_rd=True, f1=True),
    _c("C.SRAI", "CSHIFT", 0x8401, ("rd", "shamt"), writes_rd=True, f1=True),
    _c("C.SLLI", "CSHIFT", 0x0002, ("rd", "shamt"), writes_rd=True, f1=True),
    _c("C.ANDI", "CANDI", 0x8801, ("rd", "imm"), writes_rd=True, f1=True,
       imm_bits=6),
    _c("C.J", "CJ", 0xA001, ("imm",), imm_bits=12, imm_align=2,
       control_flow=True),
    _c("C.BEQZ", "CB", 0xC001, ("rs1", "imm"), imm_bits=9, imm_align=2,
       control_flow=True),
    _c("C.BNEZ", "CB", 0xE001, ("rs1", "imm"), imm_bits=9, imm_align=2,
       control_flow=True),
    _c("C.LWSP", "CLSP", 0x4002, ("rd", "imm"), writes_rd=True,
       imm_bits=8, imm_signed=False, imm_align=4),
    _c("C.SWSP", "CSSP", 0xC002, ("rs2", "imm"),
       imm_bits=8, imm_signed=False, imm_align=4),
))

# --- RV64 (encoders only; generated only on an xlen=64 profile) -------------
_SPECS.extend((
    _i("ADDIW", 0, opcode=0x1B, f1=False, xlen=64),
    _shift("SLLIW", 1, False, opcode=0x1B, xlen=64, f1=False),
    _shift("SRLIW", 5, False, opcode=0x1B, xlen=64, f1=False),
    _shift("SRAIW", 5, True, opcode=0x1B, xlen=64, f1=False),
    _load("LD", 3, 8, xlen=64),
    _store("SD", 3, 8, xlen=64),
    _load("LWU", 6, 4, xlen=64),
))
for _name, _f3, _f7 in (("ADDW", 0, 0x00), ("SUBW", 0, 0x20), ("SLLW", 1, 0x00),
                        ("SRLW", 5, 0x00), ("SRAW", 5, 0x20)):
    _SPECS.append(_r(_name, _f3, _f7, opcode=0x3B, f1=False, xlen=64))
for _name, _f3 in (("MULW", 0), ("DIVW", 4), ("DIVUW", 5), ("REMW", 6),
                   ("REMUW", 7)):
    _SPECS.append(_r(_name, _f3, 1, opcode=0x3B, ext="M", f1=False, xlen=64))

CATALOG: dict[str, InstructionSpec] = {spec.name: spec for spec in _SPECS}
if len(CATALOG) != len(_SPECS):  # duplicate names would break the single source
    raise RuntimeError("duplicate instruction name in catalog")


def shamt_limit(spec: InstructionSpec, xlen: int) -> int:
    """Largest shift amount legal for ``spec`` at ``xlen``.

    RV64 widens SLLI/SRLI/SRAI and the compressed shifts to 6 bits; the W-form
    shifts keep a 5-bit shamt even on RV64.
    """
    if spec.kind not in ("SHIFT", "CSHIFT"):
        raise ValueError(f"{spec.name} has no shift amount")
    if spec.name in ("SLLIW", "SRLIW", "SRAIW"):
        return 31
    return 63 if xlen == 64 else 31
