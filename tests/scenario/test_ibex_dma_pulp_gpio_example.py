"""Firmware contract for the real Ibex → DMA → PULP GPIO ISR fixture."""
import pytest

from myfuzz.scenario.ibex_dma_example import DMA_BASE, ISR, MAIN, RESULT, SOURCE
from myfuzz.scenario.pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET
from myfuzz.scenario.ibex_dma_pulp_gpio_example import (
    GPIO_BASE, ibex_dma_pulp_gpio_images,
)


PADOUT = GPIO_BASE + GPIO_PADOUT_OFFSET
MASK32 = (1 << 32) - 1


def _sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def _instructions(image):
    assert len(image) % 4 == 0
    return [int.from_bytes(image[index:index + 4], 'little')
            for index in range(0, len(image), 4)]


@pytest.mark.parametrize('destination', (PADOUT, PADOUT + 4))
def test_ibex_firmware_programs_one_word_dma_and_checks_the_real_target(destination):
    value = 0x5aa55aa5
    images = ibex_dma_pulp_gpio_images(source_value=value,
        destination_address=destination)

    assert set(images) == {MAIN, ISR, SOURCE, RESULT}
    assert images[SOURCE] == value.to_bytes(4, 'little')
    assert images[RESULT] == bytes(20)

    main = _instructions(images[MAIN])
    main_stores = _execute_stores(main)
    assert [(address, value) for address, value, _ in main_stores] == [
        (DMA_BASE + 8, SOURCE),
        (DMA_BASE + 12, destination),
        (DMA_BASE + 4, 1),
        (DMA_BASE, (0xfed << 16) | 1),
    ]
    assert main_stores[0][2] < main_stores[1][2] < main_stores[2][2] < main_stores[3][2]

    isr = _instructions(images[ISR])
    loads = _execute_load_addresses(isr)
    assert [address for address, _ in loads] == [DMA_BASE, PADOUT, SOURCE]
    assert [address for address, _, _ in _execute_stores(isr)] == [
        RESULT, RESULT + 4, RESULT + 8, RESULT + 12,
        RESULT + 16, RESULT + 16,
    ]

    branches = _bne_branches(isr)
    assert [(row['rs1'], row['rs2']) for row in branches] == [(7, 0), (8, 9)]
    assert branches[0]['target'] == branches[1]['target']
    failure = branches[0]['target']
    assert _addi_fields(isr[failure]) == (10, 0, -1)
    assert _store_fields(isr[failure + 1]) == (10, 5, 16)
    assert _addi_fields(isr[branches[1]['index'] + 1]) == (10, 0, 1)
    assert _store_fields(isr[branches[1]['index'] + 2]) == (10, 5, 16)
    assert branches[1]['index'] + 2 < failure
    assert isr[branches[1]['index'] + 3] == 0x30200073
    assert isr[failure + 2] == 0x30200073


def _execute_stores(instructions):
    registers = [0] * 32
    rows = []
    for index, word in enumerate(instructions):
        opcode = word & 0x7f
        rd = (word >> 7) & 0x1f
        if opcode == 0x37:
            registers[rd] = _sign_extend(word & 0xfffff000, 32) & MASK32
        elif opcode == 0x13 and ((word >> 12) & 7) == 0:
            rs1 = (word >> 15) & 0x1f
            registers[rd] = (registers[rs1] +
                _sign_extend(word >> 20, 12)) & MASK32
        elif opcode == 0x23 and ((word >> 12) & 7) == 2:
            rs1 = (word >> 15) & 0x1f
            rs2 = (word >> 20) & 0x1f
            immediate = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f)
            address = (registers[rs1] + _sign_extend(immediate, 12)) & MASK32
            rows.append((address, registers[rs2], index))
        elif opcode == 0x6f:
            break
    return rows


def _execute_load_addresses(instructions):
    registers = [0] * 32
    rows = []
    for index, word in enumerate(instructions):
        opcode = word & 0x7f
        rd = (word >> 7) & 0x1f
        if opcode == 0x37:
            registers[rd] = _sign_extend(word & 0xfffff000, 32) & MASK32
        elif opcode == 0x13 and ((word >> 12) & 7) == 0:
            rs1 = (word >> 15) & 0x1f
            registers[rd] = (registers[rs1] +
                _sign_extend(word >> 20, 12)) & MASK32
        elif opcode == 0x03 and ((word >> 12) & 7) == 2:
            rs1 = (word >> 15) & 0x1f
            address = (registers[rs1] + _sign_extend(word >> 20, 12)) & MASK32
            rows.append((address, index))
            registers[rd] = 0
    return rows


def _bne_branches(instructions):
    rows = []
    for index, word in enumerate(instructions):
        if (word & 0x7f) != 0x63:
            continue
        assert ((word >> 12) & 7) == 1  # BNE, not a different branch family.
        immediate = (((word >> 31) & 1) << 12
            | ((word >> 7) & 1) << 11
            | ((word >> 25) & 0x3f) << 5
            | ((word >> 8) & 0xf) << 1)
        target = index + _sign_extend(immediate, 13) // 4
        rows.append({'index': index, 'rs1': (word >> 15) & 0x1f,
            'rs2': (word >> 20) & 0x1f, 'target': target})
    return rows


def _addi_fields(word):
    assert (word & 0x7f) == 0x13 and ((word >> 12) & 7) == 0
    return ((word >> 7) & 0x1f, (word >> 15) & 0x1f,
        _sign_extend(word >> 20, 12))


def _store_fields(word):
    assert (word & 0x7f) == 0x23 and ((word >> 12) & 7) == 2
    immediate = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f)
    return ((word >> 20) & 0x1f, (word >> 15) & 0x1f,
        _sign_extend(immediate, 12))

