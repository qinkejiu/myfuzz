"""Shared RV32I CPU-programmed DMA RAM firmware image construction."""


def _lui(rd, value):
    return (value & 0xfffff000) | rd << 7 | 0x37


def _addi(rd, rs, immediate):
    return (immediate & 0xfff) << 20 | rs << 15 | rd << 7 | 0x13


def _lw(rd, base, offset):
    return (offset & 0xfff) << 20 | base << 15 | 2 << 12 | rd << 7 | 3


def _sw(rs, base, offset):
    return ((offset >> 5) & 127) << 25 | rs << 20 | base << 15 | 2 << 12 | (offset & 31) << 7 | 0x23


def _bne(a, b, offset):
    value = offset & 0x1fff
    return ((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25 | b << 20 | a << 15 | 1 << 12 | ((value >> 1) & 15) << 8 | ((value >> 11) & 1) << 7 | 0x63


def _srli(rd, rs, shift):
    return shift << 20 | rs << 15 | 5 << 12 | rd << 7 | 0x13


def dma_ram_images(*, main, source, destination, result, dma_base, words,
                   boot_bytes=512, start_key=0xfed, ordered_stores=False):
    """Build the bounded four-word RV32I DMA RAM slice.

    Addresses must be 32-bit page bases. Boot storage must fit the 192-byte
    program (252 bytes with ordered stores), cover whole 64-byte cache lines,
    and remain at most 64 KiB. Ordered stores add a FENCE after every SW.
    """
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError('DMA start key must be 12 bits')
    if type(ordered_stores) is not bool:
        raise ValueError('DMA ordered_stores must be boolean')
    addresses = (main, source, destination, result, dma_base)
    if any(type(address) is not int or not 0 <= address <= 0xfffff000
           or address % 0x1000 for address in addresses):
        raise ValueError('DMA addresses must be aligned 32-bit page bases')
    if (not isinstance(words, (tuple, list)) or len(words) != 4
            or any(type(word) is not int or not 0 <= word <= 0x7ff for word in words)
            or len(set(words)) != 4):
        raise ValueError('DMA source must contain four distinct 11-bit integer words')
    if (type(boot_bytes) is not int or not 192 <= boot_bytes <= 0x10000
            or boot_bytes % 64):
        raise ValueError('DMA boot size must be 192..65536 bytes in 64-byte lines')
    ranges = ((main, boot_bytes), (source, 16), (destination, 16),
              (result, 24), (dma_base, 16))
    for index, (address, size) in enumerate(ranges):
        if address + size > 0x100000000:
            raise ValueError('DMA layout exceeds 32-bit address space')
        if any(address < other + length and other < address + size
               for other, length in ranges[:index]):
            raise ValueError('DMA code, source, destination, result and control must not overlap')
    code = [_lui(1, dma_base), _lui(2, source),
            _lui(4, destination), _lui(5, result)]
    for index, word in enumerate(words):
        code.extend((_addi(3, 0, word), _sw(3, 2, index * 4)))
    code.extend((_sw(2, 1, 8), _sw(4, 1, 12), _addi(3, 0, len(words)),
                 _sw(3, 1, 4), _lui(3, start_key << 16),
                 _addi(3, 3, len(words)), _sw(3, 1, 0)))
    poll = len(code)
    code.extend((_lw(6, 1, 0), _srli(7, 6, 31)))
    poll_branch = len(code)
    code.append(0)
    code.extend((_sw(6, 5, 0), _srli(7, 6, 30),
                 1 << 20 | 7 << 15 | 7 << 12 | 7 << 7 | 0x13))  # ANDI x7,x7,1
    failures = [len(code)]
    code.append(0)  # Error bit checked independently from busy.
    for index in range(len(words)):
        code.extend((_lw(8, 4, index * 4), _sw(8, 5, 4 + index * 4),
                     _lw(9, 2, index * 4)))
        failures.append(len(code))
        code.append(0)
    code.extend((_addi(3, 0, 1), _sw(3, 5, 4 + len(words) * 4), 0x0000006f))
    failure = len(code)
    code.extend((_addi(3, 0, -1), _sw(3, 5, 4 + len(words) * 4), 0x0000006f))
    # Label positions refer to the unexpanded stream. Relocate them only after
    # inserting the requested software ordering instruction after every SW.
    relocated = {}
    expanded = []
    for index, instruction in enumerate(code):
        relocated[index] = len(expanded)
        expanded.append(instruction)
        if ordered_stores and instruction & 0x7f == 0x23:
            expanded.append(0x0ff0000f)  # FENCE iorw,iorw; no cache-flush claim.
    code = expanded
    code[relocated[poll_branch]] = _bne(
        7, 0, (relocated[poll] - relocated[poll_branch]) * 4)
    for index in failures:
        a, b = (7, 0) if index == failures[0] else (8, 9)
        code[relocated[index]] = _bne(
            a, b, (relocated[failure] - relocated[index]) * 4)
    boot = b''.join(word.to_bytes(4, 'little') for word in code)
    if len(boot) > boot_bytes:
        raise ValueError('DMA boot size cannot hold complete firmware')
    return {main: boot.ljust(boot_bytes, b'\0'), destination: bytes(len(words) * 4), result: bytes(8 + len(words) * 4)}
