"""Instruction contract for the CV32E40P DMA-to-PULP GPIO firmware."""

import pytest

from myfuzz.scenario.cv32e40p_dma_pulp_gpio_example import (
    DMA_BASE, ISR, MAIN, RESULT, SOURCE, SOURCE_VALUE,
    cv32e40p_dma_pulp_gpio_images,
)
from myfuzz.scenario.pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET


PADOUT = 0x40001000 + GPIO_PADOUT_OFFSET
MASK32 = 0xffffffff


def _signed(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _words(image):
    assert len(image) % 4 == 0
    return [int.from_bytes(image[i:i + 4], 'little')
            for i in range(0, len(image), 4)]


def _decode(words):
    """Track constants and decode the firmware's memory and CSR operations."""
    registers = [0] * 32
    operations = []
    for index, word in enumerate(words):
        opcode = word & 0x7f
        rd = (word >> 7) & 31
        rs1 = (word >> 15) & 31
        rs2 = (word >> 20) & 31
        funct3 = (word >> 12) & 7
        if opcode == 0x37:
            registers[rd] = word & 0xfffff000
        elif opcode == 0x13 and funct3 == 0:
            registers[rd] = (registers[rs1] + _signed(word >> 20, 12)) & MASK32
            operations.append(('addi', index, rd, rs1, _signed(word >> 20, 12)))
        elif opcode == 0x73 and funct3 in (1, 2):
            operations.append(('csr', index, word >> 20, rs1, registers[rs1], funct3))
        elif opcode == 0x23 and funct3 == 2:
            imm = ((word >> 25) << 5) | rd
            address = (registers[rs1] + _signed(imm, 12)) & MASK32
            operations.append(('sw', index, address, rs2, registers[rs2]))
        elif opcode == 0x03 and funct3 == 2:
            address = (registers[rs1] + _signed(word >> 20, 12)) & MASK32
            operations.append(('lw', index, address, rd))
            registers[rd] = 0
        elif opcode == 0x63 and funct3 == 1:
            imm = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11
                   | ((word >> 25) & 63) << 5 | ((word >> 8) & 15) << 1)
            operations.append(('bne', index, rs1, rs2,
                               index + _signed(imm, 13) // 4))
        elif opcode == 0x6f:
            operations.append(('jal', index, rd, word))
        elif word == 0x30200073:
            operations.append(('mret', index))
        else:
            raise AssertionError(f'unexpected instruction {word:#010x} at {index}')
        registers[0] = 0
    return operations


@pytest.mark.parametrize('destination', (PADOUT, PADOUT + 4))
def test_cv32_firmware_programs_dma_and_checks_real_padout(destination):
    images = cv32e40p_dma_pulp_gpio_images(destination_address=destination)
    assert DMA_BASE == 0x40002000
    assert (MAIN, ISR, SOURCE, RESULT) == (0x10000, 0x10200, 0x22000, 0x24000)
    assert ISR % 256 == 0
    assert set(images) == {MAIN, ISR, SOURCE, RESULT}
    assert images[SOURCE] == SOURCE_VALUE.to_bytes(4, 'little')
    assert images[RESULT] == bytes(20)
    assert MAIN + len(images[MAIN]) <= ISR

    main = _decode(_words(images[MAIN]))
    assert [(op[2], op[4]) for op in main if op[0] == 'csr'] == [
        (0x305, ISR), (0x304, 0x800), (0x300, 8),
    ]
    assert [op[5] for op in main if op[0] == 'csr'] == [1, 2, 2]
    assert [(op[2], op[4]) for op in main if op[0] == 'sw'] == [
        (DMA_BASE + 8, SOURCE), (DMA_BASE + 12, destination),
        (DMA_BASE + 4, 1), (DMA_BASE, (0xfed << 16) | 1),
    ]
    assert main[-1][:3] == ('jal', len(_words(images[MAIN])) - 1, 0)
    assert main[-1][3] == 0x0000006f

    isr_words = _words(images[ISR])
    isr = _decode(isr_words)
    assert isr[0][:4] == ('csr', 0, 0x342, 0)
    assert [(op[2], op[3]) for op in isr if op[0] == 'lw'] == [
        (DMA_BASE, 7), (PADOUT, 8), (SOURCE, 9),
    ]
    assert [(op[2], op[3]) for op in isr if op[0] == 'sw'] == [
        (RESULT, 6), (RESULT + 4, 7), (RESULT + 8, 8),
        (RESULT + 12, 9), (RESULT + 16, 10), (RESULT + 16, 10),
    ]
    branches = [op for op in isr if op[0] == 'bne']
    assert [(op[2], op[3]) for op in branches] == [(7, 0), (8, 9)]
    assert branches[0][4] == branches[1][4]
    failure = branches[0][4]
    assert 0 <= failure < len(isr_words)
    assert isr_words[failure:failure + 3] == [
        0xfff00513, 0x00a2a823, 0x30200073,
    ]
    success = branches[1][1] + 1
    assert isr_words[success:success + 3] == [
        0x00100513, 0x00a2a823, 0x30200073,
    ]
    assert success + 3 == failure
