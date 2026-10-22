"""RV64-safe BOOM firmware for the uncached shared-memory DMA fixture.

The returned image contains code only. The scenario factory owns destination
and result initialization, while BOOM itself writes the DMA source words.
"""
from __future__ import annotations

MAIN = 0x80000000
BOOT_BYTES = 512
SOURCE = 0x4100
DESTINATION = 0x4200
RESULT = 0x4300
DMA_BASE = 0x4400
WORDS = (135, 246, 357, 468)

_FENCE_IORW_IORW = 0x0ff0000f


def _lui(rd: int, immediate: int) -> int:
    return (immediate & 0xfffff000) | (rd << 7) | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return ((immediate & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13


def _lw(rd: int, rs1: int, offset: int) -> int:
    return ((offset & 0xfff) << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return (((offset >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | ((offset & 0x1f) << 7) | 0x23


def _srli(rd: int, rs1: int, shift: int) -> int:
    return (shift << 20) | (rs1 << 15) | (5 << 12) | (rd << 7) | 0x13


def _andi(rd: int, rs1: int, immediate: int) -> int:
    return ((immediate & 0xfff) << 20) | (rs1 << 15) | (7 << 12) | (rd << 7) | 0x13


def _branch(rs1: int, rs2: int, offset: int, *, funct3: int) -> int:
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31) | (((value >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (((value >> 1) & 0xf) << 8) | (((value >> 11) & 1) << 7) | 0x63


def _jal(rd: int, offset: int) -> int:
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31) | (((value >> 1) & 0x3ff) << 21) | (((value >> 11) & 1) << 20) | (((value >> 12) & 0xff) << 12) | (rd << 7) | 0x6f


def _firmware_words(start_key: int) -> list[int]:
    """Assemble labels then relocate them after adding the required fences."""
    stream: list[tuple[str, int | str]] = []

    def emit(word: int) -> None:
        stream.append(("word", word))

    def label(name: str) -> None:
        stream.append(("label", name))

    def branch(rs1: int, rs2: int, target: str, *, funct3: int) -> None:
        stream.append(("branch", (rs1, rs2, target, funct3)))

    def jump(target: str) -> None:
        stream.append(("jump", target))

    # Keep all CPU data pointers positive and inside the selected 0x4000 page.
    # LUI x1,4 forms the 0x4000 base; the four ADDIs add 0x100..0x400.
    # MAIN is supplied by the native bootstrap, never synthesized as an RV64
    # sign-extended LUI address in this program.
    emit(_lui(1, 0x4000))
    emit(_addi(2, 1, 0x100))
    emit(_addi(4, 1, 0x200))
    emit(_addi(5, 1, 0x300))
    emit(_addi(1, 1, 0x400))

    for index, word in enumerate(WORDS):
        emit(_addi(3, 0, word))
        emit(_sw(3, 2, index * 4))
    # Program source, destination, length, then start with the selected key.
    emit(_sw(2, 1, 8))
    emit(_sw(4, 1, 12))
    emit(_addi(3, 0, len(WORDS)))
    emit(_sw(3, 1, 4))
    emit(_lui(3, start_key << 16))
    emit(_addi(3, 3, len(WORDS)))
    emit(_sw(3, 1, 0))

    label("poll")
    emit(_lw(6, 1, 0))
    emit(_srli(7, 6, 31))
    branch(7, 0, "poll", funct3=1)  # BNE busy, zero, continue polling.
    emit(_sw(6, 5, 0))
    emit(_srli(7, 6, 30))
    emit(_andi(7, 7, 1))
    branch(7, 0, "failure", funct3=1)  # Independently reject error bit 30.

    for index in range(len(WORDS)):
        emit(_lw(8, 4, index * 4))
        emit(_sw(8, 5, 4 + index * 4))
        emit(_lw(9, 2, index * 4))
        branch(8, 9, "failure", funct3=1)
    emit(_addi(3, 0, 1))
    emit(_sw(3, 5, 20))
    jump("success_halt")

    label("failure")
    emit(_addi(3, 0, -1))
    emit(_sw(3, 5, 20))
    jump("failure_halt")
    label("success_halt")
    jump("success_halt")
    label("failure_halt")
    jump("failure_halt")

    # First pass expands each store into SW; FENCE, and maps all labels to the
    # expanded PC. Branches are encoded only after that relocation is known.
    expanded: list[tuple[str, object]] = []
    labels: dict[str, int] = {}
    for kind, item in stream:
        if kind == "label":
            labels[str(item)] = len(expanded)
            continue
        expanded.append((kind, item))
        if kind == "word" and int(item) & 0x7f == 0x23:
            expanded.append(("word", _FENCE_IORW_IORW))

    words: list[int] = []
    for pc, (kind, item) in enumerate(expanded):
        if kind == "word":
            words.append(int(item))
        elif kind == "branch":
            rs1, rs2, target, funct3 = item  # type: ignore[misc]
            offset = (labels[str(target)] - pc) * 4
            if offset % 2 or not -4096 <= offset <= 4094:
                raise ValueError("BOOM firmware branch target is out of range")
            words.append(_branch(int(rs1), int(rs2), offset, funct3=int(funct3)))
        elif kind == "jump":
            offset = (labels[str(item)] - pc) * 4
            if offset % 2 or not -(1 << 20) <= offset < (1 << 20):
                raise ValueError("BOOM firmware jump target is out of range")
            words.append(_jal(0, offset))
        else:
            raise AssertionError(f"unknown firmware record: {kind}")
    return words


def boom_dma_images(*, start_key: int = 0xfed) -> dict[int, bytes]:
    """Return a code-only 512-byte image for one bounded DMA key branch."""
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError("DMA start key must be an exact 12-bit integer")
    words = _firmware_words(start_key)
    code = b"".join(word.to_bytes(4, "little") for word in words)
    if len(code) > BOOT_BYTES:
        raise ValueError("BOOM DMA firmware exceeds its 512-byte image")
    return {MAIN: code.ljust(BOOT_BYTES, b"\0")}
