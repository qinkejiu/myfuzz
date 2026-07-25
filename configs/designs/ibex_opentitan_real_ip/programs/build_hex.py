#!/usr/bin/env python3
"""Build the deterministic RV32I image for the real OpenTitan IP target."""

from __future__ import annotations

from pathlib import Path
import subprocess


HERE = Path(__file__).resolve().parent


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
    payload = binary.read_bytes()
    payload += bytes((-len(payload)) % 4)
    words = [
        payload[offset : offset + 4][::-1].hex()
        for offset in range(0, len(payload), 4)
    ]
    (HERE / "mmio_exerciser.hex").write_text(
        "\n".join(words) + "\n", encoding="ascii"
    )
    binary.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
