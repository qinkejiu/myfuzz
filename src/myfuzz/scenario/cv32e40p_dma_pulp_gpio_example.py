"""CV32E40P firmware for one ZipCPU DMA word into PULP GPIO PADOUT."""

from .ibex_dma_example import _addi, _bne, _csr, _lui, _lw, _sw
from .pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET


MAIN = 0x10000
ISR = 0x10200
DMA_BASE = 0x40002000
SOURCE = 0x22000
RESULT = 0x24000
SOURCE_VALUE = 0x5aa55aa5
PADOUT_ADDRESS = 0x40001000 + GPIO_PADOUT_OFFSET
MASK32 = 0xffffffff


def _li32(register: int, value: int) -> list[int]:
    low = value & 0xfff
    if low & 0x800:
        low -= 0x1000
    return [_lui(register, (value - low) & MASK32),
            _addi(register, register, low)]


def _csrrw(csr: int, register: int) -> int:
    return csr << 20 | register << 15 | 1 << 12 | 0x73


def cv32e40p_dma_pulp_gpio_images(
        *, destination_address: int, start_key: int = 0xfed) -> dict[int, bytes]:
    """Return boot, direct ISR, fixed source, and zeroed result RAM images."""
    if (type(destination_address) is not int
            or not 0 <= destination_address <= MASK32
            or destination_address % 4):
        raise ValueError('DMA destination must be an aligned 32-bit address')
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError('DMA start key must be 12 bits')

    main = []
    main += _li32(1, DMA_BASE)
    main += _li32(2, SOURCE)
    main += _li32(4, destination_address)
    main += _li32(7, ISR)
    main += [_csrrw(0x305, 7),
             _lui(7, 0x1000), _addi(7, 7, -0x800), _csr(0x304, 7),
             _addi(7, 0, 8), _csr(0x300, 7)]
    main += [_sw(2, 1, 8), _sw(4, 1, 12)]
    main += _li32(3, 1)
    main += [_sw(3, 1, 4)]
    main += _li32(3, (start_key << 16) | 1)
    main += [_sw(3, 1, 0), 0x0000006f]

    isr = [_csr(0x342, 0, 6)]
    isr += _li32(1, DMA_BASE)
    isr += [_lw(7, 1, 0)]
    isr += _li32(5, RESULT)
    isr += [_sw(6, 5, 0), _sw(7, 5, 4)]
    isr += _li32(2, PADOUT_ADDRESS)
    isr += [_lw(8, 2, 0), _sw(8, 5, 8)]
    isr += _li32(4, SOURCE)
    isr += [_lw(9, 4, 0), _sw(9, 5, 12)]
    status_branch = len(isr)
    isr.append(0)
    value_branch = len(isr)
    isr.append(0)
    isr += [_addi(10, 0, 1), _sw(10, 5, 16), 0x30200073]
    failure = len(isr)
    isr += [_addi(10, 0, -1), _sw(10, 5, 16), 0x30200073]
    isr[status_branch] = _bne(7, 0, (failure - status_branch) * 4)
    isr[value_branch] = _bne(8, 9, (failure - value_branch) * 4)

    def encode(words: list[int]) -> bytes:
        return b''.join((word & MASK32).to_bytes(4, 'little') for word in words)

    return {MAIN: encode(main), ISR: encode(isr),
            SOURCE: SOURCE_VALUE.to_bytes(4, 'little'), RESULT: bytes(20)}
