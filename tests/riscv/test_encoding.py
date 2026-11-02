"""Encoder tests against independently assembled reference words.

The ``*_REFERENCE`` rows were produced with clang's RISC-V integrated assembler
on 2026-10-30::

    printf '<instruction>\\n' > one.S
    clang --target=riscv32|riscv64 -march=rv32ima_zicsr_zifencei,rv32imac,...
          -c one.S -o one.o
    readelf -x .text one.o

and are only used as expected values here; the encoder never invokes a tool.
``_fields`` is a small independent decoder so register/immediate placement is
checked, not just whole-word equality.  I/M/C words are additionally fed to the
repository's own decoder (:class:`RiscvInstructionProvider`) as a second opinion.
"""

import pytest

from myfuzz.isa.constraints import IsaContract, RiscvInstructionProvider
from myfuzz.riscv.catalog import CATALOG
from myfuzz.riscv.encoding import EncodingError, encode, pack_compressed_pair

_REFERENCE = [
    ("ADD", dict(rd=1, rs1=2, rs2=3), 0x003100B3, 32),
    ("SUB", dict(rd=4, rs1=5, rs2=6), 0x40628233, 32),
    ("SRA", dict(rd=22, rs1=23, rs2=24), 0x418BDB33, 32),
    ("SLLI", dict(rd=1, rs1=2, shamt=31), 0x01F11093, 32),
    ("SRAI", dict(rd=5, rs1=6, shamt=31), 0x41F35293, 32),
    ("ADDI", dict(rd=1, rs1=0, imm=1), 0x00100093, 32),
    ("SLTIU", dict(rd=9, rs1=10, imm=2047), 0x7FF53493, 32),
    ("ANDI", dict(rd=15, rs1=16, imm=255), 0x0FF87793, 32),
    ("LUI", dict(rd=5, imm=0x12345), 0x123452B7, 32),
    ("AUIPC", dict(rd=6, imm=0xABCDE), 0xABCDE317, 32),
    ("LW", dict(rd=5, rs1=6, imm=8), 0x00832283, 32),
    ("LBU", dict(rd=7, rs1=8, imm=10), 0x00A44383, 32),
    ("SW", dict(rs2=5, rs1=6, imm=8), 0x00532423, 32),
    ("SB", dict(rs2=1, rs1=2, imm=4), 0x00110223, 32),
    ("BEQ", dict(rs1=1, rs2=2, imm=8), 0x00208463, 32),
    ("BNE", dict(rs1=3, rs2=4, imm=-8), 0xFE419CE3, 32),
    ("JAL", dict(rd=0, imm=0), 0x0000006F, 32),
    ("JAL", dict(rd=1, imm=8), 0x008000EF, 32),
    ("JALR", dict(rd=2, rs1=3, imm=4), 0x00418167, 32),
    ("FENCE", {}, 0x0FF0000F, 32),
    ("FENCE.I", {}, 0x0000100F, 32),
    ("ECALL", {}, 0x00000073, 32),
    ("EBREAK", {}, 0x00100073, 32),
    ("MUL", dict(rd=6, rs1=7, rs2=8), 0x02838333, 32),
    ("MULHSU", dict(rd=12, rs1=13, rs2=14), 0x02E6A633, 32),
    ("DIVU", dict(rd=21, rs1=22, rs2=23), 0x037B5AB3, 32),
    ("REMU", dict(rd=27, rs1=28, rs2=29), 0x03DE7DB3, 32),
    ("LR.W", dict(rd=10, rs1=11), 0x1005A52F, 32),
    ("SC.W", dict(rd=12, rs1=14, rs2=13), 0x18D7262F, 32),
    ("AMOADD.W", dict(rd=4, rs1=6, rs2=5), 0x0053222F, 32),
    ("AMOMAXU.W", dict(rd=25, rs1=27, rs2=26), 0xE1ADACAF, 32),
    ("CSRRW", dict(rd=5, rs1=6, csr=0x300), 0x300312F3, 32),
    ("CSRRSI", dict(rd=12, zimm=0, csr=0x300), 0x30006673, 32),
    ("C.ADDI", dict(rd=12, imm=3), 0x060D, 32),
    ("C.LUI", dict(rd=14, imm=-31), 0x7705, 32),
    ("C.SUB", dict(rd=8, rs2=9), 0x8C05, 32),
    ("C.SLLI", dict(rd=10, shamt=3), 0x050E, 32),
    ("C.LW", dict(rd=9, rs1=10, imm=4), 0x4144, 32),
    ("C.SW", dict(rs2=11, rs1=12, imm=8), 0xC60C, 32),
    ("C.J", dict(imm=2), 0xA009, 32),
    ("C.BEQZ", dict(rs1=8, imm=4), 0xC011, 32),
    ("C.LWSP", dict(rd=1, imm=4), 0x4092, 32),
    ("C.SWSP", dict(rs2=2, imm=8), 0xC40A, 32),
    ("C.NOP", {}, 0x0001, 32),
    ("C.MV", dict(rd=4, rs2=5), 0x8216, 32),
    ("C.ANDI", dict(rd=11, imm=-2), 0x99F9, 32),
    ("C.ADDI4SPN", dict(rd=8, imm=4), 0x0040, 32),
    ("C.LI", dict(rd=13, imm=-1), 0x56FD, 32),
    ("C.ADD", dict(rd=6, rs2=7), 0x931E, 32),
    ("C.XOR", dict(rd=10, rs2=11), 0x8D2D, 32),
    ("C.OR", dict(rd=12, rs2=13), 0x8E55, 32),
    ("C.AND", dict(rd=14, rs2=15), 0x8F7D, 32),
    ("C.SRLI", dict(rd=8, shamt=1), 0x8005, 32),
    ("C.SRAI", dict(rd=9, shamt=2), 0x8489, 32),
    ("C.BNEZ", dict(rs1=9, imm=6), 0xE099, 32),
    ("C.J", dict(imm=-2), 0xBFFD, 32),
    ("C.J", dict(imm=2046), 0xAFFD, 32),
    ("C.LWSP", dict(rd=1, imm=252), 0x50FE, 32),
    ("C.SWSP", dict(rs2=2, imm=252), 0xDF8A, 32),
    ("C.ADDI4SPN", dict(rd=8, imm=1020), 0x1FE0, 32),
    ("C.LW", dict(rd=9, rs1=10, imm=124), 0x5D64, 32),
    ("C.SW", dict(rs2=11, rs1=12, imm=124), 0xDE6C, 32),
    ("C.BEQZ", dict(rs1=8, imm=254), 0xCC7D, 32),
    ("FENCE", dict(pred=1, succ=2), 0x0120000F, 32),
    ("JAL", dict(rd=1, imm=-8), 0xFF9FF0EF, 32),
    ("JAL", dict(rd=0, imm=2046), 0x7FE0006F, 32),
    ("AMOADD.W", dict(rd=30, rs1=1, rs2=31, aqrl=3), 0x07F0AF2F, 32),
    ("LR.W", dict(rd=28, rs1=29, aqrl=3), 0x160EAE2F, 32),
    ("ADDIW", dict(rd=1, rs1=2, imm=-2048), 0x8001009B, 64),
    ("SLLIW", dict(rd=3, rs1=4, shamt=31), 0x01F2119B, 64),
    ("LD", dict(rd=9, rs1=10, imm=8), 0x00853483, 64),
    ("SD", dict(rs2=11, rs1=12, imm=16), 0x00B63823, 64),
    ("LWU", dict(rd=13, rs1=14, imm=4), 0x00476683, 64),
    ("ADDW", dict(rd=15, rs1=16, rs2=17), 0x011807BB, 64),
    ("SUBW", dict(rd=18, rs1=19, rs2=20), 0x4149893B, 64),
    ("SLLW", dict(rd=21, rs1=22, rs2=23), 0x017B1ABB, 64),
    ("SRLW", dict(rd=24, rs1=25, rs2=26), 0x01ACDC3B, 64),
    ("SRAW", dict(rd=27, rs1=28, rs2=29), 0x41DE5DBB, 64),
    ("MULW", dict(rd=1, rs1=2, rs2=3), 0x023100BB, 64),
    ("DIVW", dict(rd=4, rs1=5, rs2=6), 0x0262C23B, 64),
    ("DIVUW", dict(rd=7, rs1=8, rs2=9), 0x029453BB, 64),
    ("REMW", dict(rd=10, rs1=11, rs2=12), 0x02C5E53B, 64),
    ("REMUW", dict(rd=13, rs1=14, rs2=15), 0x02F776BB, 64),
    ("SLLI", dict(rd=1, rs1=2, shamt=40), 0x02811093, 64),
    ("SRLI", dict(rd=3, rs1=4, shamt=63), 0x03F25193, 64),
    ("SRAI", dict(rd=5, rs1=6, shamt=40), 0x42835293, 64),
]


def _sign(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _fields(word):
    """Independent field decoder for a 32-bit instruction."""
    return {
        "opcode": word & 0x7F,
        "rd": (word >> 7) & 31,
        "funct3": (word >> 12) & 7,
        "rs1": (word >> 15) & 31,
        "rs2": (word >> 20) & 31,
        "funct7": (word >> 25) & 0x7F,
        "i_imm": _sign((word >> 20) & 0xFFF, 12),
        "u_imm": (word >> 12) & 0xFFFFF,
        "s_imm": _sign(((word >> 25) << 5) | ((word >> 7) & 31), 12),
        "b_imm": _sign((((word >> 31) & 1) << 12) | (((word >> 7) & 1) << 11)
                       | (((word >> 25) & 0x3F) << 5) | (((word >> 8) & 0xF) << 1),
                       13),
        "j_imm": _sign((((word >> 31) & 1) << 20) | (((word >> 12) & 0xFF) << 12)
                       | (((word >> 20) & 1) << 11) | (((word >> 21) & 0x3FF) << 1),
                       21),
    }


@pytest.mark.parametrize(("name", "operands", "expected", "xlen"), _REFERENCE)
def test_reference_encoding(name, operands, expected, xlen):
    assert encode(name, xlen=xlen, **operands) == expected
    spec = CATALOG[name]
    if spec.compressed:
        return
    fields = _fields(expected)
    assert fields["opcode"] == spec.fixed & 0x7F
    if spec.kind not in ("U", "J", "FENCE", "FENCEI", "SYSTEM"):
        assert fields["funct3"] == (spec.fixed >> 12) & 7
    if spec.kind == "R":
        assert (fields["rd"], fields["rs1"], fields["rs2"]) == (
            operands["rd"], operands["rs1"], operands["rs2"])
        assert fields["funct7"] == (spec.fixed >> 25) & 0x7F
    elif spec.kind == "I":
        assert (fields["rd"], fields["rs1"], fields["i_imm"]) == (
            operands["rd"], operands["rs1"], operands["imm"])
    elif spec.kind == "LOAD":
        assert (fields["rd"], fields["rs1"], fields["i_imm"]) == (
            operands["rd"], operands["rs1"], operands["imm"])
    elif spec.kind == "STORE":
        assert (fields["rs1"], fields["rs2"], fields["s_imm"]) == (
            operands["rs1"], operands["rs2"], operands["imm"])
    elif spec.kind == "B":
        assert (fields["rs1"], fields["rs2"], fields["b_imm"]) == (
            operands["rs1"], operands["rs2"], operands["imm"])
    elif spec.kind == "U":
        assert (fields["rd"], fields["u_imm"]) == (operands["rd"], operands["imm"])
    elif spec.kind == "J":
        assert (fields["rd"], fields["j_imm"]) == (operands["rd"], operands["imm"])


def test_reference_words_agree_with_repository_decoder():
    provider = RiscvInstructionProvider(
        IsaContract(32, ("I", "M", "C"), instruction_alignment=2))
    for name, operands, expected, xlen in _REFERENCE:
        spec = CATALOG[name]
        if xlen != 32 or spec.extension not in ("I", "M", "C"):
            continue
        assert provider.is_legal_word(expected, compressed=spec.compressed), name


def _minimal_operands(spec):
    operands = {}
    for name in spec.operands:
        if name == "rd":
            operands[name] = 8 if spec.kind in ("CIW", "CL", "CA", "CANDI", "CSHIFT") else 1
        elif name == "rs1":
            operands[name] = 8 if spec.kind in ("CL", "CIW", "CB") else 2
        elif name == "rs2":
            operands[name] = 8 if spec.kind in ("CL", "CA") else 2
        elif name == "imm":
            operands[name] = spec.imm_align or 1
        elif name == "shamt":
            operands[name] = 1
        elif name == "csr":
            operands[name] = 0x300
        elif name == "zimm":
            operands[name] = 1
        elif name in ("pred", "succ"):
            operands[name] = 0xF
    return operands


def test_every_catalog_entry_is_encodable():
    for spec in CATALOG.values():
        xlen = 64 if spec.min_xlen == 64 else 32
        word = encode(spec.name, xlen=xlen, **_minimal_operands(spec))
        assert 0 <= word <= (0xFFFF if spec.compressed else 0xFFFFFFFF), spec.name


@pytest.mark.parametrize(("name", "operands", "fragment"), [
    ("ADDI", dict(rd=32, rs1=0, imm=0), "rd"),
    ("ADDI", dict(rd=1, rs1=0, imm=2048), "immediate"),
    ("ADDI", dict(rd=1, rs1=0, imm=-2049), "immediate"),
    ("SW", dict(rs2=1, rs1=2, imm=6), "aligned"),
    ("BEQ", dict(rs1=1, rs2=2, imm=3), "aligned"),
    ("JAL", dict(rd=0, imm=-2049), "immediate"),
    ("SLLI", dict(rd=1, rs1=2, shamt=32), "shamt"),
    ("ADDI", dict(rd=1, rs1=2), "operands"),
    ("ADDI", dict(rd=1, rs1=2, imm=0, rs2=3), "operands"),
    ("LR.W", dict(rd=1, rs1=2, rs2=3), "operands"),
    ("C.ADDI", dict(rd=0, imm=1), "C.NOP"),
    ("C.LUI", dict(rd=2, imm=1), "x2"),
    ("C.LI", dict(rd=0, imm=1), "x0"),
    ("C.LW", dict(rd=7, rs1=8, imm=0), "rd"),
    ("C.SWSP", dict(rs2=1, imm=256), "immediate"),
    ("C.SLLI", dict(rd=12, shamt=0), "shamt"),
    ("FENCE", dict(pred=16, succ=1), "pred"),
    ("CSRRW", dict(rd=1, rs1=2, csr=0x1000), "csr"),
    ("AMOADD.W", dict(rd=1, rs1=2, rs2=3, aqrl=4), "aqrl"),
    ("UNKNOWN", {}, "unknown"),
    ("ADDIW", dict(rd=1, rs1=2, imm=0), "xlen"),
])
def test_illegal_encodings_are_rejected(name, operands, fragment):
    with pytest.raises(EncodingError, match=fragment):
        encode(name, **operands)


def test_rv64_encodings_require_xlen_64():
    assert encode("ADDIW", xlen=64, rd=1, rs1=2, imm=-1) == 0xFFF1009B
    with pytest.raises(EncodingError, match="xlen 64"):
        encode("ADDIW", rd=1, rs1=2, imm=-1)


def test_fence_defaults_and_system_words():
    assert encode("FENCE") == 0x0FF0000F
    assert encode("FENCE", pred=1, succ=2) == 0x0120000F
    assert encode("FENCE.I") == 0x0000100F
    assert encode("ECALL") == 0x00000073
    assert encode("EBREAK") == 0x00100073


def test_compressed_pair_packing():
    assert pack_compressed_pair(0x060D, 0x050E) == bytes.fromhex("0d060e05")
    assert pack_compressed_pair(0x060D) == bytes.fromhex("0d060100")
    with pytest.raises(EncodingError, match="16-bit"):
        pack_compressed_pair(0x00100093)
    with pytest.raises(EncodingError, match="32-bit-length"):
        pack_compressed_pair(0x4001, 0x0003)
