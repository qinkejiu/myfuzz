"""Pure RV32 encoders extracted from the existing fixed stream firmware."""

def _lui(rd: int, value: int) -> int:
    return ((value & 0xfffff) << 12) | (rd << 7) | 0x37

def _addi(rd: int, base: int, value: int) -> int:
    return ((value & 0xfff) << 20) | (base << 15) | (rd << 7) | 0x13

def _sw(rs: int, base: int, offset: int) -> int:
    return (((offset >> 5) & 127) << 25) | (rs << 20) | (base << 15) | \
        (2 << 12) | ((offset & 31) << 7) | 0x23

def _lw(rd: int, base: int, offset: int) -> int:
    return (offset << 20) | (base << 15) | (2 << 12) | (rd << 7) | 3

def _jal(pc: int, destination: int) -> int:
    """Encode and self-check one fixed JAL; no legalization is inferred."""
    offset = destination - pc
    if offset % 2 or not -(1 << 20) <= offset < 1 << 20:
        raise ValueError("fixed jump target exceeds JAL displacement")
    value = offset & 0x1fffff
    word = (((value >> 20) & 1) << 31) | (((value >> 1) & 0x3ff) << 21) | \
        (((value >> 11) & 1) << 20) | (((value >> 12) & 0xff) << 12) | 0x6f
    decoded = (((word >> 31) & 1) << 20) | (((word >> 21) & 0x3ff) << 1) | \
        (((word >> 20) & 1) << 11) | (((word >> 12) & 0xff) << 12)
    signed = decoded - (1 << 21) if decoded & (1 << 20) else decoded
    if signed != offset or word & 0xfff != 0x6f:
        raise ValueError("fixed JAL encoding does not reach instruction reservation")
    return word

def _lui_addi_load(rd: int, value: int) -> tuple[int, int]:
    """Encode ``lui rd, hi; addi rd, rd, lo`` for one 32-bit constant."""
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise ValueError("loaded constant must be a 32-bit word")
    high = (value + 0x800) >> 12
    low = value - (high << 12)
    if not -2048 <= low < 2048:
        raise ValueError("loaded constant does not fit one lui/addi pair")
    return _lui(rd, high), _addi(rd, rd, low)


def _branch(rs1,rs2,offset,*,funct3=0):
    """BEQ/BNE with a checked signed byte displacement."""
    if (any(type(v) is not int for v in (rs1,rs2,offset,funct3)) or not 0<=rs1<32 or not 0<=rs2<32
            or funct3 not in (0,1) or offset%2 or not -4096<=offset<4096):
        raise ValueError('fixed conditional branch operands')
    v=offset&0x1fff
    word=((v>>12)&1)<<31|((v>>5)&63)<<25|rs2<<20|rs1<<15|funct3<<12|((v>>1)&15)<<8|((v>>11)&1)<<7|0x63
    decoded=((word>>31)&1)<<12|((word>>7)&1)<<11|((word>>25)&63)<<5|((word>>8)&15)<<1
    if (decoded-8192 if decoded&4096 else decoded)!=offset:raise ValueError('fixed branch encoding')
    return word
