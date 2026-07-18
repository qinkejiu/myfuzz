"""Generate the generic Level 1 RV32I access-record execution image."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Mapping, Sequence

from .contracts import CpuExecutionProfile, canonical_json
from .input_model import InputValidationError


ROM_ARTIFACT_SCHEMA = "myfuzz.level1-rom-artifact/v1"


@dataclass(frozen=True)
class Level1IPWindow:
    instance_id: str
    base: int
    size: int

    def __post_init__(self) -> None:
        if not self.instance_id or self.base < 0 or self.size < 4 or self.size % 4:
            raise InputValidationError("Level 1 IP window must have an ID and word-aligned positive size")
        if self.size & (self.size - 1):
            raise InputValidationError(f"IP window {self.instance_id!r} size must be a power of two")
        if self.base % self.size:
            raise InputValidationError(f"IP window {self.instance_id!r} base is not size-aligned")
        if self.base + self.size > 1 << 32:
            raise InputValidationError(f"IP window {self.instance_id!r} exceeds the 32-bit address space")


@dataclass(frozen=True)
class Level1RomArtifact:
    profile_id: str
    semantic_digest: str
    image_digest: str
    toolchain: Mapping[str, str]
    inputs: Mapping[str, object]
    files: tuple[Mapping[str, object], ...]
    schema: str = ROM_ARTIFACT_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(command: Sequence[str], *, cwd: Path) -> str:
    completed = subprocess.run(command, cwd=cwd, check=False, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise InputValidationError(
            f"Level 1 ROM tool failed ({' '.join(command)}):\n{completed.stdout.strip()}"
        )
    return completed.stdout


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise InputValidationError(f"required Level 1 ROM tool is missing: {name}")
    return path


def _validate_layout(profile: CpuExecutionProfile, windows: Sequence[Level1IPWindow]) -> None:
    regions = [
        ("rom", profile.rom_window["base"], profile.rom_window["size"]),
        ("mailbox", profile.mailbox_window["base"], profile.mailbox_window["size"]),
        ("watchdog", profile.watchdog_window["base"], profile.watchdog_window["size"]),
        *((window.instance_id, window.base, window.size) for window in windows),
    ]
    for index, (name, base, size) in enumerate(regions):
        if base < 0 or size <= 0 or base + size > 1 << profile.address_width:
            raise InputValidationError(f"address region {name!r} is outside the CPU address space")
        for other_name, other_base, other_size in regions[:index]:
            if base < other_base + other_size and other_base < base + size:
                raise InputValidationError(f"address regions {other_name!r} and {name!r} overlap")
    reset = profile.reset_vector
    rom_base, rom_size = profile.rom_window["base"], profile.rom_window["size"]
    if not rom_base <= reset < rom_base + rom_size:
        raise InputValidationError("CPU reset vector is outside its ROM window")


def _assembly(profile: CpuExecutionProfile, windows: Sequence[Level1IPWindow]) -> str:
    mailbox = profile.mailbox_window["base"]
    watchdog = profile.watchdog_window["base"]
    default_error = 0xF0000000
    bases = ", ".join(f"0x{window.base:08x}" for window in windows) or "0"
    masks = ", ".join(f"0x{window.size - 4:08x}" for window in windows) or "0"
    return f"""/* Generated generic Level 1 ROM. No IP register semantics are encoded. */
.section .text.init
.globl _start
_start:
  li sp, 0x{profile.rom_window['base'] + profile.rom_window['size'] - 16:08x}
  li s0, 0x{mailbox:08x}
  li s1, 0x{watchdog:08x}

poll_record:
  lw t0, 0(s0)              /* valid */
  beqz t0, poll_record
  lw t1, 4(s0)              /* ip_select */
  lw t2, 8(s0)              /* read_write */
  lw t3, 12(s0)             /* word offset */
  lw t4, 16(s0)             /* write data */
  li t5, {len(windows)}
  bgeu t1, t5, unmapped
  slli t5, t1, 2
  la t6, ip_bases
  add t6, t6, t5
  lw a0, 0(t6)
  la t6, ip_offset_masks
  add t6, t6, t5
  lw a1, 0(t6)
  slli t3, t3, 2
  and t3, t3, a1
  add a0, a0, t3
  j issue

unmapped:
  li a0, 0x{default_error:08x}

issue:
  beqz t2, do_read
  sw t4, 0(a0)
  j access_done
do_read:
  lw a2, 0(a0)
access_done:
  sw t0, 20(s0)             /* software progress; monitor owns terminal ack */
  sw zero, 0(s1)            /* watchdog heartbeat */
  j poll_record

.section .rodata
.balign 4
ip_bases:
  .word {bases}
ip_offset_masks:
  .word {masks}
"""


def _linker_script(profile: CpuExecutionProfile) -> str:
    base, size = profile.rom_window["base"], profile.rom_window["size"]
    return f"""OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {{ ROM (rwx) : ORIGIN = 0x{base:08x}, LENGTH = 0x{size:x} }}
SECTIONS {{
  .text 0x{profile.reset_vector:08x} : {{ *(.text.init) *(.text*) }} > ROM
  .rodata : {{ *(.rodata*) }} > ROM
  /DISCARD/ : {{ *(.comment) *(.note*) *(.riscv.attributes) }}
}}
"""


def _binary_to_hex(binary: bytes) -> str:
    padded = binary + bytes((-len(binary)) % 4)
    return "".join(f"{int.from_bytes(padded[index:index + 4], 'little'):08x}\n"
                   for index in range(0, len(padded), 4))


def generate_level1_rom(
    profile: CpuExecutionProfile,
    ip_windows: Sequence[Level1IPWindow | Mapping[str, object]],
    output_dir: str | Path,
) -> Level1RomArtifact:
    windows = tuple(window if isinstance(window, Level1IPWindow) else Level1IPWindow(**window)
                    for window in ip_windows)
    if len({window.instance_id for window in windows}) != len(windows):
        raise InputValidationError("Level 1 IP window IDs must be unique")
    _validate_layout(profile, windows)

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    source = output / "level1_rom.S"
    linker = output / "level1_rom.ld"
    elf = output / "level1_rom.elf"
    obj = output / "level1_rom.o"
    binary = output / "level1_rom.bin"
    hex_file = output / "level1_rom.hex"
    disassembly = output / "level1_rom.disasm"

    source.write_text(_assembly(profile, windows), encoding="ascii")
    linker.write_text(_linker_script(profile), encoding="ascii")
    gcc = _tool("riscv64-unknown-elf-gcc")
    objcopy = _tool("riscv64-unknown-elf-objcopy")
    objdump = _tool("riscv64-unknown-elf-objdump")
    _run((gcc, "-march=rv32i", "-mabi=ilp32", "-c", "-o", obj.name, source.name), cwd=output)
    _run((gcc, "-march=rv32i", "-mabi=ilp32", "-nostdlib", "-nostartfiles",
          "-Wl,--build-id=none", "-Wl,-T,level1_rom.ld", "-o", elf.name, obj.name), cwd=output)
    _run((objcopy, "-O", "binary", elf.name, binary.name), cwd=output)
    disassembly.write_text(_run((objdump, "-d", "-M", "no-aliases", elf.name), cwd=output), encoding="ascii")
    hex_file.write_text(_binary_to_hex(binary.read_bytes()), encoding="ascii")

    version = _run((gcc, "--version"), cwd=output).splitlines()[0]
    semantic_inputs = {
        "isa": profile.isa,
        "reset_vector": profile.reset_vector,
        "rom_window": dict(profile.rom_window),
        "mailbox_window": dict(profile.mailbox_window),
        "watchdog_window": dict(profile.watchdog_window),
        "ip_windows": [asdict(window) for window in windows],
        "access_record_fields": ["ip_select", "read_write", "offset", "data"],
    }
    files = tuple({"name": path.name, "sha256": _sha256(path), "size": path.stat().st_size}
                  for path in (source, linker, elf, binary, hex_file, disassembly))
    artifact = Level1RomArtifact(
        profile_id=profile.cpu_id,
        semantic_digest=hashlib.sha256(canonical_json(semantic_inputs)).hexdigest(),
        image_digest=_sha256(binary),
        toolchain={"gcc": version, "objcopy": objcopy, "objdump": objdump},
        inputs=semantic_inputs,
        files=files,
    )
    manifest = output / "level1_rom.manifest.json"
    manifest.write_text(json.dumps(artifact.to_dict(), sort_keys=True, indent=2) + "\n", encoding="ascii")
    return artifact
