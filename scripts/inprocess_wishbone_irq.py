"""Pico custom IRQ ABI support for independent Wishbone CPU models."""

from myfuzz.integration.rv32_fixed_firmware import (
    _addi, _branch, _jal, _lui_addi_load, _lw, _sw,
)


def custom_irq_segments(layout, *, irq_bit, vector, status, result, clear,
                        clear_value, flag):
    """Return real RV32/custom0 boot, vector and context-preserving ISR images.

    Only the CPU IRQ ABI is specific here; the ISR gets IP/DMA addresses from
    the common handler block, exactly like the machine-external implementation.
    """
    if type(irq_bit) is not int or not 3 <= irq_bit < 32:
        raise ValueError('custom IRQ needs an external bit in 3..31')
    boot, handler = layout['boot'], layout['handler']
    init = boot + 0x40
    scratch = layout['result'] + 16
    code = [*_lui_addi_load(8, layout['mailbox']),
            *_lui_addi_load(3, (~(1 << irq_bit)) & 0xffffffff),
            3 << 25 | 3 << 15 | 6 << 12 | 0x0b]
    code.append(_jal(init + 4 * len(code), layout['main']))
    save_q2 = 1 << 25 | 31 << 15 | 2 << 12 | 2 << 7 | 0x0b
    restore_q2 = 2 << 15 | 4 << 12 | 31 << 7 | 0x0b
    isr = [save_q2, *_lui_addi_load(31, scratch)]
    isr.extend(_sw(reg, 31, 4 * (reg - 12)) for reg in range(12, 16))
    isr.extend([_lw(12, 8, status), _lw(13, 12, 0),
                _lw(14, 8, result), _sw(13, 14, 0),
                _lw(12, 8, clear), _branch(12, 0, 12),
                _lw(15, 8, clear_value), _sw(15, 12, 0),
                _lw(14, 8, flag), _addi(15, 0, 1), _sw(15, 14, 0)])
    isr.extend(_lw(reg, 31, 4 * (reg - 12)) for reg in range(12, 16))
    isr.extend((restore_q2, 0x0400000b))

    def packed(words):
        return b''.join(word.to_bytes(4, 'little') for word in words)

    return {boot: packed([_jal(boot, init)]),
            vector: packed([_jal(vector, handler)]),
            init: packed(code), handler: packed(isr)}
