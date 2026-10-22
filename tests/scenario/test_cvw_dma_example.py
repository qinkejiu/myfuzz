"""Software execution checks only: the test DMA is not evidence about RTL."""
import importlib

import pytest


def firmware():
    try:
        return importlib.import_module('myfuzz.scenario.cvw_dma_example')
    except ModuleNotFoundError:
        pytest.fail('CVW DMA firmware module is missing')


def signed(value, bits):
    return (value & ((1 << (bits - 1)) - 1)) - (value & (1 << (bits - 1)))


def execute(fw, *, key=0xfed, error=False, corrupt=None):
    """Independent RV32I subset decoder plus explicitly test-only DMA model."""
    images = fw.cvw_dma_images(start_key=key)
    memory = {address + i: byte for address, data in images.items()
              for i, byte in enumerate(data)}
    regs, stores, reads, controls = [0] * 32, [], [], {}
    pc, polls, copied = fw.MAIN, 0, False

    def load(address):
        return sum(memory.get(address + i, 0) << (i * 8) for i in range(4))

    def write(address, value):
        for i in range(4):
            memory[address + i] = (value >> (i * 8)) & 255

    for _ in range(1000):
        instruction = load(pc)
        op = instruction & 127
        rd, rs1, rs2 = (instruction >> 7) & 31, (instruction >> 15) & 31, (instruction >> 20) & 31
        funct = (instruction >> 12) & 7
        next_pc = pc + 4
        if op == 0x37:
            regs[rd] = instruction & 0xfffff000
        elif op == 0x13:
            imm = signed(instruction >> 20, 12)
            if funct == 0:
                regs[rd] = regs[rs1] + imm
            elif funct == 5 and instruction >> 25 == 0:
                regs[rd] = regs[rs1] >> (rs2 & 31)
            elif funct == 7:
                regs[rd] = regs[rs1] & imm
            else:
                raise AssertionError(hex(instruction))
        elif op == 0x23:
            assert funct == 2
            imm = signed(((instruction >> 25) << 5) | ((instruction >> 7) & 31), 12)
            address = (regs[rs1] + imm) & 0xffffffff
            value = regs[rs2]
            stores.append((address, value))
            if fw.DMA_BASE <= address < fw.DMA_BASE + 16:
                controls[address - fw.DMA_BASE] = value
            else:
                assert fw.MAIN <= address < fw.MAIN + 0x10000
                write(address, value)
        elif op == 3:
            assert funct == 2
            address = (regs[rs1] + signed(instruction >> 20, 12)) & 0xffffffff
            reads.append(address)
            if address == fw.DMA_BASE:
                polls += 1
                regs[rd] = 0x80000000 if polls < 3 else (0x40000000 if error else 0)
                if polls == 3 and key == 0xfed and not error:
                    assert controls == {8: fw.SOURCE, 12: fw.DESTINATION, 4: 4, 0: 0x0fed0004}
                    for i in range(4):
                        write(fw.DESTINATION + 4 * i, load(fw.SOURCE + 4 * i))
                    copied = True
                    if corrupt is not None:
                        write(corrupt, 0x999)
            else:
                assert fw.MAIN <= address < fw.MAIN + 0x10000
                regs[rd] = load(address)
        elif op == 0x63:
            immediate = (((instruction >> 31) & 1) << 12 | ((instruction >> 7) & 1) << 11
                         | ((instruction >> 25) & 63) << 5 | ((instruction >> 8) & 15) << 1)
            assert funct in (0, 1)
            equal = regs[rs1] == regs[rs2]
            if equal == (funct == 0):
                next_pc = pc + signed(immediate, 13)
        elif instruction == 0x0000006f:
            return load, stores, reads, controls, polls, copied
        else:
            raise AssertionError(f'Unsupported instruction {instruction:#x}')
        regs[rd if op in (0x37, 0x13, 3) else 0] &= 0xffffffff
        regs[0] = 0
        pc = next_pc
    pytest.fail('firmware failed to halt within software instruction budget')


def test_images_have_only_padded_boot_and_zero_destination_and_result():
    fw = firmware()
    images = fw.cvw_dma_images()
    assert fw.MAIN == 0xc0000000 and fw.BOOT_BYTES == 512
    assert (fw.DMA_BASE, fw.SOURCE, fw.DESTINATION, fw.RESULT) == (
        0xcfff1000, 0xc0001000, 0xc0002000, 0xc0003000)
    assert fw.WORDS == (0x135, 0x246, 0x357, 0x468)
    assert images.keys() == {fw.MAIN, fw.DESTINATION, fw.RESULT}
    assert len(images[fw.MAIN]) == 512
    assert images[fw.DESTINATION] == bytes(16)
    assert images[fw.RESULT] == bytes(24)
    wrong = fw.cvw_dma_images(start_key=0x3db)
    differing = [i for i in range(0, 512, 4) if images[fw.MAIN][i:i+4] != wrong[fw.MAIN][i:i+4]]
    assert len(differing) == 1


def test_cpu_stores_source_config_polls_and_loads_both_arrays():
    fw = firmware()
    load, stores, reads, controls, polls, copied = execute(fw)
    assert stores[:4] == [(fw.SOURCE + 4*i, value) for i, value in enumerate(fw.WORDS)]
    assert [item for item in stores if fw.DMA_BASE <= item[0] < fw.DMA_BASE+16] == [
        (fw.DMA_BASE+8, fw.SOURCE), (fw.DMA_BASE+12, fw.DESTINATION),
        (fw.DMA_BASE+4, 4), (fw.DMA_BASE, 0x0fed0004)]
    assert polls == 3 and copied
    assert not any(fw.DESTINATION <= address < fw.DESTINATION+16 for address, _ in stores)
    assert all(address in reads for base in (fw.SOURCE, fw.DESTINATION) for address in range(base, base+16, 4))
    assert load(fw.RESULT) == 0
    assert [load(fw.RESULT+4+4*i) for i in range(4)] == list(fw.WORDS)
    assert load(fw.RESULT+20) == 1


@pytest.mark.parametrize('mode', ['stale', 'error', 'destination', 'source'])
def test_cpu_failure_paths(mode):
    fw = firmware()
    load, _, _, controls, _, copied = execute(fw, key=0x3db if mode == 'stale' else 0xfed,
        error=mode == 'error', corrupt={'destination': fw.DESTINATION+12, 'source': fw.SOURCE+12}.get(mode))
    assert load(fw.RESULT+20) == 0xffffffff
    assert load(fw.RESULT) == (0x40000000 if mode == 'error' else 0)
    if mode == 'stale':
        assert controls[0] == 0x03db0004 and not copied
        assert all(load(fw.DESTINATION+4*i) == 0 for i in range(4))


@pytest.mark.parametrize('key', [-1, 0x1000, True, None, 'fed', 1.0])
def test_reject_invalid_keys(key):
    with pytest.raises(ValueError, match='12 bits'):
        firmware().cvw_dma_images(start_key=key)
