"""Generate the RV32I RawBits v3 control-plane executor ROM."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .contracts import CpuExecutionProfile, SoCIRV2, canonical_json
from .control_mailbox import ControlMailboxABI, build_control_mailbox_abi
from .control_plane import CONTROL_OPCODES, GeneratedControlPlane
from .input_model import InputValidationError
from .level1_rom import _binary_to_hex, _run, _sha256, _tool
from .system_services import SystemServicePlan


@dataclass(frozen=True)
class ControlRomArtifact:
    cpu_id: str
    image_digest: str
    semantic_digest: str
    control_plane_digest: str
    mailbox_abi_digest: str
    service_plan_digest: str
    files: tuple[Mapping[str, object], ...]
    schema: str = "myfuzz.control-rom-artifact/v1"


def generate_control_rom(
    profile: CpuExecutionProfile,
    soc: SoCIRV2,
    control: GeneratedControlPlane,
    services: SystemServicePlan,
    output_dir: str | Path,
) -> ControlRomArtifact:
    if control.control_ir.soc_digest != soc.digest:
        raise InputValidationError("control ROM received a ControlPlane for another SoCIR")
    if services.cpu_id != profile.cpu_id:
        raise InputValidationError("control ROM CPU profile and service plan differ")
    abi = build_control_mailbox_abi(control.control_ir, control.layout)
    assembly = _assembly(profile, soc, control, services, abi)
    output = Path(output_dir); output.mkdir(parents=True, exist_ok=True)
    source = output / "control_rom.S"; linker = output / "control_rom.ld"
    obj = output / "control_rom.o"; elf = output / "control_rom.elf"
    binary = output / "control_rom.bin"; hex_file = output / "control_rom.hex"
    disassembly = output / "control_rom.disasm"
    source.write_text(assembly, encoding="ascii")
    linker.write_text(_linker(profile), encoding="ascii")
    gcc = _tool("riscv64-unknown-elf-gcc"); objcopy = _tool("riscv64-unknown-elf-objcopy")
    objdump = _tool("riscv64-unknown-elf-objdump")
    _run((gcc, "-march=rv32i", "-mabi=ilp32", "-c", "-o", obj.name, source.name), cwd=output)
    _run((gcc, "-march=rv32i", "-mabi=ilp32", "-nostdlib", "-nostartfiles",
          "-Wl,--build-id=none", "-Wl,-T,control_rom.ld", "-o", elf.name, obj.name), cwd=output)
    _run((objcopy, "-O", "binary", elf.name, binary.name), cwd=output)
    disassembly.write_text(_run((objdump, "-d", "-M", "no-aliases", elf.name), cwd=output), encoding="ascii")
    rom_base = int(profile.rom_window["base"])
    reset_vector = int(profile.reset_vector)
    reset_offset = reset_vector - rom_base
    if reset_offset < 0 or reset_offset >= int(profile.rom_window["size"]):
        raise InputValidationError("control ROM reset vector lies outside the ROM window")
    if reset_offset % 4:
        raise InputValidationError("control ROM reset vector must be word aligned")
    install_kind = str(profile.rom_install_backend.get("kind", ""))
    word_offset = 0 if install_kind == "pre_reset_tcm_loader" else reset_offset // 4
    hex_file.write_text(_readmemh_image(binary.read_bytes(), word_offset), encoding="ascii")
    semantic = {
        "soc_digest": soc.digest, "control_plane_digest": control.control_ir.digest,
        "rawbits_layout_digest": control.layout.digest, "mailbox_abi_digest": abi.digest,
        "service_plan_digest": services.digest, "cpu_startup_fragment": profile.startup_fragment_digest,
        "operations": list(CONTROL_OPCODES),
    }
    files = tuple({"name": item.name, "sha256": _sha256(item), "size": item.stat().st_size}
                  for item in (source, linker, obj, elf, binary, hex_file, disassembly))
    artifact = ControlRomArtifact(
        profile.cpu_id, _sha256(binary), hashlib.sha256(canonical_json(semantic)).hexdigest(),
        control.control_ir.digest, abi.digest, services.digest, files,
    )
    (output / "control_rom.manifest.json").write_text(
        json.dumps(asdict(artifact), sort_keys=True, indent=2) + "\n", encoding="ascii",
    )
    return artifact


def _readmemh_image(binary: bytes, word_offset: int) -> str:
    image = _binary_to_hex(binary)
    if word_offset == 0:
        return image
    return f"@{word_offset:08x}\n{image}"


def _assembly(profile, soc, control, services, abi):
    mailbox = next(item for item in services.regions if item.kind == "control_mailbox")
    irq_mapper = next(item for item in services.regions if item.kind == "interrupt_mapper")
    offsets = {item.name: item.register_offset for item in abi.fields}
    required = {"opcode", "target_region", "address", "write_data", "write_strobe",
                "compare_data", "compare_mask", "wait_cycles", "timeout_cycles",
                "irq_value", "fault_kind"}
    missing = sorted(required - set(offsets))
    if missing:
        raise InputValidationError("control ROM is missing field(s): " + ", ".join(missing))
    views = tuple(sorted(soc.address_views, key=lambda item: str(item["instance_id"])))
    for view in views:
        size = int(view["size"])
        if size < 4 or size & (size - 1):
            raise InputValidationError(f"control ROM target {view['instance_id']} requires a power-of-two window")
    opcodes = {str(item["name"]): int(item["opcode"]) for item in control.control_ir.operations}
    if set(opcodes) != set(CONTROL_OPCODES):
        raise InputValidationError("control ROM operation set differs from ControlPlaneIR v1")
    dispatch = "\n".join(
        f"  li t1, {opcodes[name]}\n  beq t0, t1, op_{name.lower()}" for name in CONTROL_OPCODES
    )
    bases = ", ".join(f"0x{int(view['global_base']):08x}" for view in views)
    masks = ", ".join(f"0x{int(view['size']) - 1:08x}" for view in views)
    return f"""/* Generated RawBits v3 CPU executor. IP names and register semantics are absent. */
.section .text.init
.globl _start
_start:
  li sp, 0x{profile.rom_window['base'] + profile.rom_window['size'] - 16:08x}
  li s0, 0x{mailbox.base:08x}
poll_record:
  lw t0, 0(s0)
  beqz t0, poll_record
  lw t0, {offsets['opcode']}(s0)
{dispatch}
  j op_invalid

resolve_address:
  lw a0, {offsets['target_region']}(s0)
  li a3, {len(views)}
  bgeu a0, a3, resolve_bad
  slli a0, a0, 2
  la a1, target_bases
  add a1, a1, a0
  lw a2, 0(a1)
  la a1, target_masks
  add a1, a1, a0
  lw a1, 0(a1)
  lw a0, {offsets['address']}(s0)
  and a0, a0, a1
  add a2, a2, a0
  li a3, 0
  ret
resolve_bad:
  li a3, 1
  ret

op_mmio_read:
op_mem_read:
  jal ra, resolve_address
  bnez a3, op_invalid
  lw a1, 0(a2)
  j op_success
op_mmio_write:
op_mem_write:
  jal ra, resolve_address
  bnez a3, op_invalid
  lw t2, {offsets['write_data']}(s0)
  lw t3, {offsets['write_strobe']}(s0)
  andi t4, t3, 1
  beqz t4, write_lane1
  sb t2, 0(a2)
write_lane1:
  srli t2, t2, 8
  andi t4, t3, 2
  beqz t4, write_lane2
  sb t2, 1(a2)
write_lane2:
  srli t2, t2, 8
  andi t4, t3, 4
  beqz t4, write_lane3
  sb t2, 2(a2)
write_lane3:
  srli t2, t2, 8
  andi t4, t3, 8
  beqz t4, op_success_zero
  sb t2, 3(a2)
  j op_success_zero
op_mmio_rmw:
  jal ra, resolve_address
  bnez a3, op_invalid
  lw t2, 0(a2)
  lw t3, {offsets['compare_mask']}(s0)
  not t4, t3
  and t2, t2, t4
  lw t4, {offsets['write_data']}(s0)
  and t4, t4, t3
  or t2, t2, t4
  sw t2, 0(a2)
  mv a1, t2
  j op_success
op_poll:
  jal ra, resolve_address
  bnez a3, op_invalid
  lw t2, {offsets['timeout_cycles']}(s0)
poll_loop:
  lw a1, 0(a2)
  lw t3, {offsets['compare_mask']}(s0)
  and t4, a1, t3
  lw t5, {offsets['compare_data']}(s0)
  and t5, t5, t3
  beq t4, t5, op_success
  addi t2, t2, -1
  bnez t2, poll_loop
  j op_timeout
op_wait_cycles:
  lw t2, {offsets['wait_cycles']}(s0)
wait_loop:
  beqz t2, op_success_zero
  addi t2, t2, -1
  j wait_loop
op_wait_irq:
  li t6, 0x{irq_mapper.base:08x}
  lw t2, {offsets['timeout_cycles']}(s0)
  lw t3, {offsets['irq_value']}(s0)
irq_wait_loop:
  lw a1, 0(t6)
  and t4, a1, t3
  bnez t4, op_success
  addi t2, t2, -1
  bnez t2, irq_wait_loop
  j op_timeout
op_fence:
  fence iorw, iorw
  j op_success_zero
op_fault_access:
  jal ra, resolve_address
  bnez a3, op_invalid
  lw t2, {offsets['fault_kind']}(s0)
  andi t2, t2, 1
  bnez t2, fault_write
  lw a1, 0(a2)
  j op_success
fault_write:
  lw t2, {offsets['write_data']}(s0)
  sw t2, 0(a2)
  j op_success_zero
op_irq_ack:
  li t6, 0x{irq_mapper.base:08x}
  lw t2, {offsets['irq_value']}(s0)
  sw t2, 8(t6)
  j op_success_zero
op_set_external:
op_pulse_external:
op_reset_domain:
op_sequence_continue:
op_sequence_end:
  j op_success_zero
op_success_zero:
  li a1, 0
op_success:
  li a0, 1
  j complete
op_timeout:
  li a0, 2
  li a1, 0
  j complete
op_invalid:
  li a0, 3
  li a1, 0
complete:
  sw a1, 8(s0)
  sw a0, 4(s0)
  j poll_record

.section .rodata
.balign 4
target_bases:
  .word {bases}
target_masks:
  .word {masks}
"""


def _linker(profile):
    base = int(profile.rom_window["base"]); size = int(profile.rom_window["size"])
    return f"""OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY {{ ROM (rwx) : ORIGIN = 0x{base:08x}, LENGTH = 0x{size:x} }}
SECTIONS {{
  .text 0x{profile.reset_vector:08x} : {{ *(.text.init) *(.text*) }} > ROM
  .rodata : {{ *(.rodata*) }} > ROM
  /DISCARD/ : {{ *(.comment) *(.note*) *(.riscv.attributes) }}
}}
"""
