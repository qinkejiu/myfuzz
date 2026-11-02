"""Independently decode full CPU MMIO addresses above signed-12 SW range."""
import json
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]


def decoded_stores(program):
    from scripts.run_cv32e20_irq_smoke import fixed_program
    prefix = bytes.fromhex(fixed_program(program['boot'])['images'][str(program['boot'])])[:-4]
    code = bytes.fromhex(program['images'][str(program['boot'])])
    assert code.startswith(prefix)
    regs = [0] * 32
    stores = []
    for offset in range(len(prefix), len(code)-4, 4):
        word = int.from_bytes(code[offset:offset+4], 'little')
        rd, rs = word >> 7 & 31, word >> 15 & 31
        if word & 127 == 0x37:
            regs[rd] = word & 0xFFFFF000
        elif word & 127 == 0x13:
            imm = word >> 20
            if imm & 0x800: imm -= 4096
            regs[rd] = (regs[rs] + imm) & 0xFFFFFFFF
        elif word & 127 == 0x23:
            assert word >> 12 & 7 == 2
            imm = (word >> 25 << 5) | (word >> 7 & 31)
            if imm & 0x800: imm -= 4096
            stores.append(((regs[rs] + imm) & 0xFFFFFFFF, regs[word >> 20 & 31], imm))
        else:
            raise AssertionError('unexpected trigger instruction')
    return stores


def test_actual_SHA_configuration_encodes_full_AHB_offsets_without_wrapping():
    from scripts.run_timer_irq_smoke import source_options, timer_program
    options = source_options(json.loads((ROOT/'configs/peripherals/sha_declared_irq/smoke.json').read_text()))
    program = timer_program(0x10000, options['active_base'],
                            trigger_writes=options['trigger_writes'], window_size=4096)
    assert decoded_stores(program) == [(0x40001800, 1, 0), (0x40001804, 1, 0), (0x4000181C, 1, 0)]


@pytest.mark.parametrize('offset', [2044, 2048, 4092])
def test_boundary_immediates_use_exact_declared_address(offset):
    from scripts.run_timer_irq_smoke import timer_program
    program = timer_program(0x10080, 0x40001000, trigger_writes=((offset, 7),), window_size=4096)
    assert decoded_stores(program) == [(0x40001000+offset, 7, offset if offset < 2048 else 0)]


def test_actual_window_and_32bit_address_overflow_refuse():
    from scripts.run_timer_irq_smoke import timer_program
    with pytest.raises(ValueError):
        timer_program(0x10080, 0x40001000, trigger_writes=((4, 1),), window_size=4)
    with pytest.raises(ValueError):
        timer_program(0x10080, 0xFFFFF000, trigger_writes=((0, 1),), window_size=8192)
