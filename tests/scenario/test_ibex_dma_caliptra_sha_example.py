from myfuzz.scenario.ibex_dma_example import DMA_BASE, ISR, MAIN, RESULT, SOURCE


def _words(image):
    return [int.from_bytes(image[i:i + 4], 'little')
            for i in range(0, len(image), 4)]


def _decode(word):
    opcode = word & 0x7f
    rd = (word >> 7) & 31
    f3 = (word >> 12) & 7
    rs1 = (word >> 15) & 31
    rs2 = (word >> 20) & 31
    if opcode == 0x37:
        return ('lui', rd, word & 0xfffff000)
    if opcode == 0x13:
        imm = (word >> 20) & 0xfff
        op = 'andi' if f3 == 7 else 'addi'
        return (op, rd, rs1, imm - 0x1000 if imm & 0x800 else imm)
    if opcode in (0x03, 0x23):
        imm = (word >> 20) & 0xfff if opcode == 0x03 else (
            ((word >> 25) << 5) | ((word >> 7) & 31))
        if imm & 0x800:
            imm -= 0x1000
        if opcode == 0x03:
            return ('lw', rd, rs1, imm)
        return ('sw', rs2, rs1, imm)
    if opcode == 0x73 and f3 == 2:
        return ('csrrs', rd, (word >> 20) & 0xfff, rs1)
    if opcode == 0x63:
        off = (((word >> 31) & 1) << 12 | ((word >> 7) & 1) << 11 |
               ((word >> 25) & 0x3f) << 5 | ((word >> 8) & 0xf) << 1)
        if off & 0x1000:
            off -= 0x2000
        return ('branch', f3, rs1, rs2, off)
    if opcode == 0x6f:
        off = (((word >> 31) & 1) << 20 | ((word >> 12) & 0xff) << 12 |
               ((word >> 20) & 1) << 11 | ((word >> 21) & 0x3ff) << 1)
        if off & 0x100000:
            off -= 0x200000
        return ('jal', rd, off)
    return ('raw', word)


def test_caliptra_dma_image_configures_one_word_and_has_bounded_sha_isr():
    from myfuzz.scenario.ibex_dma_caliptra_sha_example import (
        ibex_dma_caliptra_sha_images,
    )

    source_value, destination, key = 0x76543210, 0x23000, 0xFED
    images = ibex_dma_caliptra_sha_images(source_value=source_value,
        destination_address=destination, start_key=key)
    assert set(images) == {MAIN, ISR, SOURCE, RESULT}
    assert images[SOURCE] == source_value.to_bytes(4, 'little')

    main = [_decode(w) for w in _words(images[MAIN])]
    accesses = [(i, op) for i, op in enumerate(main) if op[0] == 'sw']
    assert [op[1:] for _, op in accesses[-4:]] == [
        (2, 1, 8), (4, 1, 12), (3, 1, 4), (3, 1, 0)]
    before_start = main[:accesses[-1][0]]
    assert ('addi', 3, 0, 1) in before_start
    assert ('lui', 1, DMA_BASE) in main
    assert ('lui', 2, SOURCE) in main
    assert ('lui', 4, destination) in main
    assert not any(op[0] == 'sw' and op[2] == 2 for op in main)
    # The control low bits encode one word per DMA block, matching the
    # one-word transfer length programmed above.
    assert ('lui', 3, key << 16) in main
    assert ('addi', 3, 3, 1) in main
    assert sum(op[0] == 'sw' and op[2] == 1 for op in main) == 4

    isr = [_decode(w) for w in _words(images[ISR])]
    assert ('csrrs', 6, 0x342, 0) in isr  # mcause
    assert ('lw', 7, 1, 0) in isr          # DMA status
    assert ('sw', 7, 5, 4) in isr
    failure_index = next(i for i, op in enumerate(isr)
                         if op == ('addi', 3, 0, -1))
    dma_error_index = next(i for i, op in enumerate(isr)
        if op[0] == 'branch' and op[1] == 1 and op[2:4] == (7, 0))
    assert dma_error_index + isr[dma_error_index][4] // 4 == failure_index
    assert any(op[0] == 'addi' and op[1] == 10 and op[2] == 0 and op[3] > 0
               for op in isr)  # finite poll budget
    assert ('lui', 11, 0x40002000) in isr
    assert ('lw', 12, 11, 0x18) in isr
    assert ('andi', 14, 12, 2) in isr
    poll_index = next(i for i, op in enumerate(isr)
                      if op == ('lw', 12, 11, 0x18))
    assert isr[poll_index + 1] == ('andi', 14, 12, 2)
    ready_branch = isr[poll_index + 2]
    assert ready_branch[:4] == ('branch', 1, 14, 0)
    digest_start = next(i for i, op in enumerate(isr)
                        if op == ('lw', 13, 11, 0x100))
    assert poll_index + 2 + ready_branch[4] // 4 == digest_start
    assert isr[poll_index + 3] == ('addi', 10, 10, -1)
    timeout_branch = isr[poll_index + 4]
    assert timeout_branch[:4] == ('branch', 0, 10, 0)
    assert poll_index + 4 + timeout_branch[4] // 4 == failure_index
    back_edge = isr[poll_index + 5]
    assert back_edge == ('jal', 0, (poll_index - (poll_index + 5)) * 4)
    assert sum(op == ('lw', 13, 11, offset)
               for op in isr for offset in range(0x100, 0x120, 4)) == 8
    assert sum(op[0] == 'sw' and op[1] == 13 and op[2] == 5
               and op[3] >= 8 and op[3] < 40 for op in isr) == 8
    marker_stores = [i for i, op in enumerate(isr)
                     if op[0] == 'sw' and op[1] == 3 and op[2] == 5
                     and op[3] == 40]
    assert len(marker_stores) == 2
    success_marker = next(i for i, op in enumerate(isr)
                          if op == ('addi', 3, 0, 1))
    assert marker_stores[0] < success_marker < marker_stores[1]
    assert max(i for i, op in enumerate(isr)
               if op[0] == 'lw' and op[1] == 13) < success_marker
    assert any(op == ('addi', 3, 0, -1) for op in isr)
