#!/usr/bin/env python3
"""Build the deterministic RV32I image for the real OpenTitan IP target."""

from __future__ import annotations

from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent
RESET_ENTRY_BYTES = 0x80


def main() -> int:
    binary = HERE / "mmio_exerciser.bin"
    subprocess.run(
        [
            "clang",
            "--target=riscv32-unknown-elf",
            "-march=rv32i",
            "-mabi=ilp32",
            "-nostdlib",
            str(HERE / "mmio_exerciser.S"),
            f"-Wl,-T,{HERE / 'link.ld'}",
            "-Wl,--oformat=binary",
            "-o",
            str(binary),
        ],
        check=True,
    )
    image = b"\x13\x00\x00\x00" * (RESET_ENTRY_BYTES // 4) + binary.read_bytes()
    image += bytes((-len(image)) % 4)
    words = [
        image[offset : offset + 4][::-1].hex()
        for offset in range(0, len(image), 4)
    ]
    (HERE / "mmio_exerciser.hex").write_text(
        "\n".join(words) + "\n", encoding="ascii"
    )
    binary.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
