"""Pure, profile-independent RISC-V encoders.

Every public entry point validates its operands and raises :class:`EncodingError`
instead of truncating.  Field layouts follow the RISC-V ISA manual and were
checked against the clang-assembled reference words listed in
``tests/riscv/test_encoding.py`` (see ``catalog.py`` for the sources).
"""

from __future__ import annotations

from .catalog import CATALOG, InstructionSpec, shamt_limit


class EncodingError(ValueError):
    """An instruction name, operand, immediate or alignment is not encodable."""


def spec_for(name: str) -> InstructionSpec:
    """Return the catalog entry for ``name``."""
    spec = CATALOG.get(name)
    if spec is None:
        raise EncodingError(f"unknown instruction {name!r}")
    return spec


def _int(value: object, field: str) -> int:
    if type(value) is not int:
        raise EncodingError(f"{field} must be an integer")
    return value


def _reg(value: object, field: str, *, low: int = 0, high: int = 31,
         nonzero: bool = False) -> int:
    value = _int(value, field)
    if not low <= value <= high:
        raise EncodingError(f"{field} {value} outside [{low}, {high}]")
    if nonzero and value == 0:
        raise EncodingError(f"{field} must not be x0")
    return value


def _imm(spec: InstructionSpec, value: object) -> int:
    bits, signed, align = spec.imm_bits, spec.imm_signed, spec.imm_align
    value = _int(value, "imm")
    if signed:
        low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    else:
        low, high = 0, (1 << bits) - 1
    if not low <= value <= high:
        raise EncodingError(
            f"{spec.name} immediate {value} outside "
            f"{'signed' if signed else 'unsigned'} {bits}-bit range"
        )
    if value % align:
        raise EncodingError(
            f"{spec.name} immediate {value} not aligned to {align}"
        )
    if spec.imm_nonzero and value == 0:
        raise EncodingError(f"{spec.name} immediate must be nonzero")
    return value


def _check_operands(spec: InstructionSpec, operands: dict[str, object]) -> None:
    required = set(spec.operands)
    allowed = required | ({"aqrl"} if spec.kind in ("LR", "AMO") else set())
    if spec.kind == "FENCE" and not set(operands) - {"pred", "succ"}:
        return
    supplied = set(operands)
    if not required <= supplied <= allowed:
        missing = sorted(required - supplied)
        extra = sorted(supplied - allowed)
        raise EncodingError(
            f"{spec.name} operands {sorted(supplied)} must include "
            f"{sorted(required)} and allow {sorted(allowed)} "
            f"(missing={missing}, extra={extra})"
        )


def _branch_bits(offset: int) -> int:
    return (((offset >> 12) & 1) << 31 | ((offset >> 5) & 0x3F) << 25
            | ((offset >> 1) & 0xF) << 8 | ((offset >> 11) & 1) << 7)


def _jal_bits(offset: int) -> int:
    return (((offset >> 20) & 1) << 31 | ((offset >> 1) & 0x3FF) << 21
            | ((offset >> 11) & 1) << 20 | ((offset >> 12) & 0xFF) << 12)


def _store_bits(imm: int) -> int:
    return ((imm >> 5) & 0x7F) << 25 | (imm & 0x1F) << 7


def encode(name: str, xlen: int = 32, **operands: object) -> int:
    """Encode one instruction word; ``xlen`` gates RV64-only encodings."""
    spec = spec_for(name)
    if spec.min_xlen > xlen:
        raise EncodingError(f"{spec.name} requires xlen {spec.min_xlen}, not {xlen}")
    _check_operands(spec, operands)
    get = operands.get
    kind = spec.kind

    if kind == "R":
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15 | _reg(get("rs2"), "rs2") << 20)
    if kind == "I":
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15
                | (_imm(spec, get("imm")) & 0xFFF) << 20)
    if kind == "SHIFT":
        shamt = _int(get("shamt"), "shamt")
        if not 0 <= shamt <= shamt_limit(spec, xlen):
            raise EncodingError(
                f"{spec.name} shamt {shamt} outside [0, {shamt_limit(spec, xlen)}]"
            )
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15 | shamt << 20)
    if kind == "LOAD":
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15
                | (_imm(spec, get("imm")) & 0xFFF) << 20)
    if kind == "STORE":
        return (spec.fixed | _reg(get("rs1"), "rs1") << 15
                | _reg(get("rs2"), "rs2") << 20
                | _store_bits(_imm(spec, get("imm"))))
    if kind == "B":
        return (spec.fixed | _reg(get("rs1"), "rs1") << 15
                | _reg(get("rs2"), "rs2") << 20
                | _branch_bits(_imm(spec, get("imm"))))
    if kind == "U":
        return spec.fixed | _reg(get("rd"), "rd") << 7 | _imm(spec, get("imm")) << 12
    if kind == "J":
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _jal_bits(_imm(spec, get("imm"))))
    if kind == "FENCE":
        pred = _reg(get("pred", 0xF), "pred", high=15)
        succ = _reg(get("succ", 0xF), "succ", high=15)
        return spec.fixed | pred << 24 | succ << 20
    if kind in ("FENCEI", "SYSTEM"):
        return spec.fixed
    if kind == "LR":
        aqrl = _int(get("aqrl", 0), "aqrl")
        if not 0 <= aqrl <= 3:
            raise EncodingError(f"LR.W aqrl {aqrl} outside [0, 3]")
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15 | aqrl << 25)
    if kind == "AMO":
        aqrl = _int(get("aqrl", 0), "aqrl")
        if not 0 <= aqrl <= 3:
            raise EncodingError(f"{spec.name} aqrl {aqrl} outside [0, 3]")
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15
                | _reg(get("rs2"), "rs2") << 20 | aqrl << 25)
    if kind == "CSR":
        csr = _reg(get("csr"), "csr", high=0xFFF)
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | _reg(get("rs1"), "rs1") << 15 | csr << 20)
    if kind == "CSR_I":
        csr = _reg(get("csr"), "csr", high=0xFFF)
        zimm = _reg(get("zimm"), "zimm", high=31)
        return (spec.fixed | _reg(get("rd"), "rd") << 7
                | zimm << 15 | csr << 20)
    return _encode_compressed(spec, operands, xlen)


def _prime(value: object, field: str) -> int:
    return _reg(value, field, low=8, high=15)


def _encode_compressed(spec: InstructionSpec, operands: dict[str, object],
                       xlen: int) -> int:
    """Encode the 16-bit instruction kinds (always returned as a 16-bit word)."""
    get = operands.get
    kind = spec.kind
    if kind == "CNOP":
        return spec.fixed
    if kind == "CIW":
        rd = _prime(get("rd"), "rd")
        imm = _imm(spec, get("imm"))
        return (spec.fixed | ((imm >> 4) & 3) << 11 | ((imm >> 6) & 0xF) << 7
                | ((imm >> 2) & 1) << 6 | ((imm >> 3) & 1) << 5 | (rd - 8) << 2)
    if kind == "CL":
        imm = _imm(spec, get("imm"))
        word = (spec.fixed | ((imm >> 3) & 7) << 10
                | (_prime(get("rs1"), "rs1") - 8) << 7
                | ((imm >> 2) & 1) << 6 | ((imm >> 6) & 1) << 5)
        if "rd" in operands:
            return word | (_prime(get("rd"), "rd") - 8) << 2
        return word | (_prime(get("rs2"), "rs2") - 8) << 2
    if kind == "CI":
        rd = _reg(get("rd"), "rd")
        if spec.name == "C.LUI":
            if rd in (0, 2):
                raise EncodingError("C.LUI rd must not be x0 or x2 (sp)")
        elif spec.name == "C.LI":
            if rd == 0:
                raise EncodingError("C.LI rd must not be x0")
        elif rd == 0 and _imm(spec, get("imm")) != 0:
            raise EncodingError("C.ADDI rd=x0 only encodes C.NOP (imm 0)")
        imm = _imm(spec, get("imm"))
        return (spec.fixed | rd << 7 | (imm & 0x1F) << 2 | ((imm >> 5) & 1) << 12)
    if kind == "CA":
        return (spec.fixed | (_prime(get("rd"), "rd") - 8) << 7
                | (_prime(get("rs2"), "rs2") - 8) << 2)
    if kind == "CR":
        return (spec.fixed | _reg(get("rd"), "rd", nonzero=True) << 7
                | _reg(get("rs2"), "rs2") << 2)
    if kind == "CSHIFT":
        shamt = _int(get("shamt"), "shamt")
        limit = shamt_limit(spec, xlen)
        if not 1 <= shamt <= limit:
            raise EncodingError(f"{spec.name} shamt {shamt} outside [1, {limit}]")
        if spec.name == "C.SLLI":
            rd = _reg(get("rd"), "rd", nonzero=True)
            return (spec.fixed | rd << 7 | (shamt & 0x1F) << 2
                    | ((shamt >> 5) & 1) << 12)
        return (spec.fixed | (_prime(get("rd"), "rd") - 8) << 7
                | (shamt & 0x1F) << 2 | ((shamt >> 5) & 1) << 12)
    if kind == "CANDI":
        imm = _imm(spec, get("imm"))
        return (spec.fixed | (_prime(get("rd"), "rd") - 8) << 7
                | (imm & 0x1F) << 2 | ((imm >> 5) & 1) << 12)
    if kind == "CJ":
        imm = _imm(spec, get("imm"))
        return (spec.fixed | ((imm >> 11) & 1) << 12 | ((imm >> 4) & 1) << 11
                | ((imm >> 8) & 3) << 9 | ((imm >> 10) & 1) << 8
                | ((imm >> 6) & 1) << 7 | ((imm >> 7) & 1) << 6
                | ((imm >> 1) & 7) << 3 | ((imm >> 5) & 1) << 2)
    if kind == "CB":
        imm = _imm(spec, get("imm"))
        return (spec.fixed | ((imm >> 8) & 1) << 12 | ((imm >> 3) & 3) << 10
                | (_prime(get("rs1"), "rs1") - 8) << 7
                | ((imm >> 6) & 3) << 5 | ((imm >> 1) & 3) << 3
                | ((imm >> 5) & 1) << 2)
    if kind == "CLSP":
        imm = _imm(spec, get("imm"))
        return (spec.fixed | _reg(get("rd"), "rd", nonzero=True) << 7
                | ((imm >> 5) & 1) << 12 | ((imm >> 2) & 7) << 4
                | ((imm >> 6) & 3) << 2)
    if kind == "CSSP":
        imm = _imm(spec, get("imm"))
        return (spec.fixed | _reg(get("rs2"), "rs2") << 2
                | ((imm >> 2) & 0xF) << 9 | ((imm >> 6) & 3) << 7)
    raise EncodingError(f"{spec.name} has unsupported compressed kind {kind}")


def _half(word: object, field: str) -> int:
    value = _int(word, field)
    if not 0 <= value <= 0xFFFF:
        raise EncodingError(f"{field} {value} is not a 16-bit instruction")
    if value & 3 == 3:
        raise EncodingError(f"{field} {value:#06x} is a 32-bit-length encoding")
    return value


def pack_compressed_pair(first: int, second: int | None = None) -> bytes:
    """Pack two legal 16-bit instructions into one aligned 4-byte slot.

    ``second`` defaults to C.NOP for callers that pad a single instruction.
    Both halves stay inside the slot, so no instruction straddles the CPU fetch
    granularity.  The returned bytes are little endian, execution order first.
    """
    low = _half(first, "first")
    high = _half(0x0001 if second is None else second, "second")
    return (low | high << 16).to_bytes(4, "little")


_AMO_SUFFIX = {0: "", 1: ".aq", 2: ".rl", 3: ".aqrl"}


def format_assembly(name: str, operands: dict[str, object]) -> str:
    """Render one encoded instruction as conventional RISC-V assembly text."""
    spec = spec_for(name)
    get = operands.get
    op = lambda register: f"x{get(register)}"  # noqa: E731 - tiny local alias
    kind, mnemonic = spec.kind, name.lower()
    if kind == "R":
        return f"{mnemonic} {op('rd')}, {op('rs1')}, {op('rs2')}"
    if kind == "I":
        if name in {"LW", "LH", "LB", "LBU", "LHU", "LD", "LWU", "JALR"}:
            return f"{mnemonic} {op('rd')}, {get('imm')}({op('rs1')})"
        return f"{mnemonic} {op('rd')}, {op('rs1')}, {get('imm')}"
    if kind == "LOAD":
        return f"{mnemonic} {op('rd')}, {get('imm')}({op('rs1')})"
    if kind == "STORE":
        return f"{mnemonic} {op('rs2')}, {get('imm')}({op('rs1')})"
    if kind == "B":
        return f"{mnemonic} {op('rs1')}, {op('rs2')}, {get('imm')}"
    if kind == "U":
        return f"{mnemonic} {op('rd')}, 0x{get('imm'):x}"
    if kind == "J":
        return f"{mnemonic} {op('rd')}, {get('imm')}"
    if kind == "SHIFT":
        return f"{mnemonic} {op('rd')}, {op('rs1')}, {get('shamt')}"
    if kind == "FENCE":
        pred, succ = get("pred", 0xF), get("succ", 0xF)
        return "fence" if pred == succ == 0xF else f"fence {pred}, {succ}"
    if kind in ("FENCEI", "SYSTEM", "CNOP"):
        return mnemonic
    if kind in ("LR", "AMO"):
        suffix = _AMO_SUFFIX[get("aqrl", 0)]
        if kind == "LR":
            return f"{mnemonic}{suffix} {op('rd')}, ({op('rs1')})"
        return f"{mnemonic}{suffix} {op('rd')}, {op('rs2')}, ({op('rs1')})"
    if kind == "CSR":
        return f"{mnemonic} {op('rd')}, 0x{get('csr'):03x}, {op('rs1')}"
    if kind == "CSR_I":
        return f"{mnemonic} {op('rd')}, 0x{get('csr'):03x}, {get('zimm')}"
    if kind == "CIW":
        return f"{mnemonic} {op('rd')}, sp, {get('imm')}"
    if kind == "CL":
        source = op("rs1")
        if "rd" in operands:
            return f"{mnemonic} {op('rd')}, {get('imm')}({source})"
        return f"{mnemonic} {op('rs2')}, {get('imm')}({source})"
    if kind == "CI" and name == "C.LUI":
        return f"{mnemonic} {op('rd')}, 0x{get('imm') & 0xFFFFF:05x}"
    if kind in ("CI", "CANDI"):
        return f"{mnemonic} {op('rd')}, {get('imm')}"
    if kind in ("CA", "CR"):
        return f"{mnemonic} {op('rd')}, {op('rs2')}"
    if kind == "CSHIFT":
        return f"{mnemonic} {op('rd')}, {get('shamt')}"
    if kind == "CJ":
        return f"{mnemonic} {get('imm')}"
    if kind == "CB":
        return f"{mnemonic} {op('rs1')}, {get('imm')}"
    if kind == "CLSP":
        return f"{mnemonic} {op('rd')}, {get('imm')}(sp)"
    if kind == "CSSP":
        return f"{mnemonic} {op('rs2')}, {get('imm')}(sp)"
    raise EncodingError(f"no assembly format for {name}")
