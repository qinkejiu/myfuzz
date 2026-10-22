"""Ibex firmware image for a one-word DMA transfer into Caliptra SHA."""

from .ibex_dma_example import DMA_BASE, ISR, MAIN, RESULT, SOURCE

SHA_BASE = 0x40002000
SHA_STATUS = 0x18
SHA_DIGEST0 = 0x100
SHA_POLL_LIMIT = 1000


def _addi(rd, rs, imm):
    return ((imm & 0xfff) << 20) | (rs << 15) | (rd << 7) | 0x13


def _andi(rd, rs, imm):
    return ((imm & 0xfff) << 20) | (rs << 15) | (7 << 12) | (rd << 7) | 0x13


def _lui(rd, value):
    return (value & 0xfffff000) | (rd << 7) | 0x37


def _sw(rs, base, offset):
    return (((offset >> 5) & 0x7f) << 25 | rs << 20 | base << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, base, offset):
    return ((offset & 0xfff) << 20 | base << 15 | 2 << 12 |
            rd << 7 | 0x03)


def _csr(csr, rs, rd=0):
    return csr << 20 | rs << 15 | 2 << 12 | rd << 7 | 0x73


def _branch(funct3, rs1, rs2, offset):
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | funct3 << 12 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _beq(rs1, rs2, offset):
    return _branch(0, rs1, rs2, offset)


def _bne(rs1, rs2, offset):
    return _branch(1, rs1, rs2, offset)


def _jal(offset=0):
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 |
            ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 | 0x6f)


def _encode(instructions):
    return b''.join(word.to_bytes(4, 'little') for word in instructions)


def _load32(rd, value):
    value &= 0xffffffff
    low = value & 0xfff
    signed_low = low - 0x1000 if low & 0x800 else low
    upper = (value - signed_low) & 0xfffff000
    return [_lui(rd, upper), _addi(rd, rd, signed_low)]


def ibex_dma_caliptra_sha_images(*, source_value: int,
                                  destination_address: int,
                                  start_key: int = 0xFED) -> dict[int, bytes]:
    """Build MAIN/ISR firmware and fixed source/result RAM images."""
    if type(source_value) is not int or not 0 <= source_value <= 0xffffffff:
        raise ValueError('source_value must be an unsigned 32-bit integer')
    if (type(destination_address) is not int or
            not 0 <= destination_address <= 0xffffffff or
            destination_address & 3):
        raise ValueError('destination_address must be an aligned 32-bit address')
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError('DMA start key must be 12 bits')

    # x1 DMA base, x2 source address, x4 destination, x5 result RAM.
    main = [_lui(1, DMA_BASE), _lui(2, SOURCE)] + _load32(4, destination_address)
    main += [_lui(5, RESULT)]
    # Vectored machine external interrupt entry is mtvec base + 11*4.
    main += _load32(7, (ISR - 44) | 1)
    main += [_csr(0x305, 7), _lui(7, 0x1000), _addi(7, 7, -0x800),
             _csr(0x304, 7), _addi(7, 0, 8), _csr(0x300, 7)]
    main += [_sw(2, 1, 8), _sw(4, 1, 12), _addi(3, 0, 1),
             _sw(3, 1, 4), _lui(3, start_key << 16),
             _addi(3, 3, 1), _sw(3, 1, 0), _jal()]

    # Save trap cause and DMA status, then check DMA completion status.
    isr = [_csr(0x342, 0, 6), _sw(6, 5, 0), _lw(7, 1, 0), _sw(7, 5, 4)]
    dma_error = len(isr)
    isr.append(0)

    # Bounded SHA status poll: accept bit 1, otherwise expire to failure.
    isr += [_lui(11, SHA_BASE), _addi(10, 0, SHA_POLL_LIMIT)]
    poll = len(isr)
    isr += [_lw(12, 11, SHA_STATUS), _andi(14, 12, 2)]
    ready_branch = len(isr)
    isr.append(0)
    isr += [_addi(10, 10, -1)]
    timeout_branch = len(isr)
    isr.append(0)
    isr += [_jal((poll - len(isr)) * 4)]
    failure = len(isr)
    # Error path gets a forward branch from the DMA status check and timeout.
    isr += [_addi(3, 0, -1), _sw(3, 5, 40), _jal()]
    digest = len(isr)
    for index in range(8):
        isr += [_lw(13, 11, SHA_DIGEST0 + index * 4),
                _sw(13, 5, 8 + index * 4)]
    isr += [_addi(3, 0, 1), _sw(3, 5, 40), 0x30200073]
    isr[dma_error] = _bne(7, 0, (failure - dma_error) * 4)
    isr[ready_branch] = _bne(14, 0, (digest - ready_branch) * 4)
    isr[timeout_branch] = _beq(10, 0, (failure - timeout_branch) * 4)

    return {MAIN: _encode(main), ISR: _encode(isr),
            SOURCE: source_value.to_bytes(4, 'little'), RESULT: bytes(44)}
