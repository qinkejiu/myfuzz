"""Firmware for one Ibex-configured wbdmac transfer into PULP GPIO PADOUT."""
from .ibex_dma_example import (
    DMA_BASE, ISR, MAIN, RESULT, SOURCE, _addi, _bne, _csr, _lui, _lw, _sw,
)
from .pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET

GPIO_BASE = 0x40001000
PADOUT_ADDRESS = GPIO_BASE + GPIO_PADOUT_OFFSET
MASK32 = (1 << 32) - 1


def _li32(register, value):
    """Emit LUI/ADDI for an unsigned RV32 value, including a signed low part."""
    value &= MASK32
    low = value & 0xFFF
    if low & 0x800:
        low -= 0x1000
    high = (value - low) & MASK32
    return [_lui(register, high), _addi(register, register, low)]


def ibex_dma_pulp_gpio_images(*, source_value: int,
        destination_address: int, start_key: int = 0xFED) -> dict[int, bytes]:
    """Build MAIN/ISR code and the RAM source/result images.

    `destination_address` remains a firmware input so a wrong-offset run can
    issue a real native DMA request. The route compiler still admits PADOUT
    only; the ISR always reads the registered PADOUT address.
    """
    if type(source_value) is not int or not 0 <= source_value <= MASK32:
        raise ValueError('DMA source word must be an unsigned 32-bit integer')
    if (type(destination_address) is not int or not 0 <= destination_address <= MASK32
            or destination_address % 4):
        raise ValueError('DMA destination must be an aligned 32-bit address')
    if type(start_key) is not int or not 0 <= start_key <= 0xFFF:
        raise ValueError('DMA start key must be 12 bits')

    main = []
    main += _li32(1, DMA_BASE)
    main += _li32(2, SOURCE)
    main += _li32(4, destination_address)
    main += _li32(5, RESULT)

    # Preserve the established Ibex machine-external interrupt setup used by
    # the real Ibex/wbdmac DMA-to-RAM fixture.
    main += [_lui(7, 0x10000), _addi(7, 7, 0x200), _csr(0x305, 7),
             _lui(7, 0x1000), _addi(7, 7, -0x800), _csr(0x304, 7),
             _addi(7, 0, 8), _csr(0x300, 7)]

    # wbdmac source/destination are word-addressed internally. Its length
    # register accepts a word count and the pinned RTL start key is 0xfed.
    main += [_sw(2, 1, 8), _sw(4, 1, 12)]
    main += _li32(3, 1)
    main += [_sw(3, 1, 4)]
    main += _li32(3, (start_key << 16) | 1)
    main += [_sw(3, 1, 0), 0x0000006F]  # jal x0, 0: wait for native IRQ.

    # The ISR saves the actual cause, status, PADOUT readback and source word.
    # A nonzero status or unequal data branches around success to marker -1.
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
    isr += [_addi(10, 0, 1), _sw(10, 5, 16), 0x30200073]  # success, mret
    failure = len(isr)
    isr += [_addi(10, 0, -1), _sw(10, 5, 16), 0x30200073]
    isr[status_branch] = _bne(7, 0, (failure - status_branch) * 4)
    isr[value_branch] = _bne(8, 9, (failure - value_branch) * 4)

    def encode(words):
        return b''.join((word & MASK32).to_bytes(4, 'little') for word in words)

    return {
        MAIN: encode(main),
        ISR: encode(isr),
        SOURCE: source_value.to_bytes(4, 'little'),
        RESULT: bytes(20),
    }
