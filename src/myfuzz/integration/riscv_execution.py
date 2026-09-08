"""Bounded, fact-driven acceptance support for real RISC-V processors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Mapping, Sequence

from myfuzz.contracts import content_hash


class RiscvExecutionError(ValueError):
    """Raised when execution evidence is incomplete or inconsistent."""


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise RiscvExecutionError(f"{label}:invalid-hash")
    return value


@dataclass(frozen=True)
class RiscvExecutionFacts:
    isa: str
    xlen: int
    reset_vector: int
    pass_address: int
    pass_value: int
    protocol: tuple[str, str]
    max_cycles: int

    def __post_init__(self) -> None:
        if self.xlen not in {32, 64}:
            raise RiscvExecutionError("xlen:unsupported")
        if not isinstance(self.isa, str) or not self.isa.startswith(f"rv{self.xlen}"):
            raise RiscvExecutionError("isa:xlen-mismatch")
        if len(self.protocol) != 2 or not all(isinstance(item, str) and item for item in self.protocol):
            raise RiscvExecutionError("protocol:invalid")
        for name in ("reset_vector", "pass_address", "pass_value", "max_cycles"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RiscvExecutionError(f"{name}:invalid")
        if self.max_cycles < 1 or self.reset_vector % 4 or self.pass_address % 4:
            raise RiscvExecutionError("execution-bounds-or-alignment:invalid")
        if self.pass_value >= 1 << 32:
            raise RiscvExecutionError("pass_value:width")


@dataclass(frozen=True)
class BootImage:
    isa: str
    xlen: int
    reset_vector: int
    load_base: int
    elf_path: Path
    binary_path: Path
    memory_hex_path: Path
    elf_hash: str
    binary_hash: str
    memory_hex_hash: str
    binary_size: int
    compiler: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionEvent:
    reset_released: bool
    successful_fetches: int
    progress_events: int
    backend_completions: int
    pass_observed: bool
    cycles: int
    exit_reason: str


def _abi(xlen: int) -> str:
    return "ilp32" if xlen == 32 else "lp64"


def build_minimal_boot_image(facts: RiscvExecutionFacts, output_dir: Path) -> BootImage:
    """Build a minimal pass-signalling image using only declared ISA facts."""
    if not isinstance(facts, RiscvExecutionFacts):
        raise RiscvExecutionError("facts:type")
    compiler = shutil.which("clang")
    if compiler is None:
        raise RiscvExecutionError("tool-missing:clang")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    source = output / "boot.S"
    linker = output / "boot.ld"
    elf = output / "boot.elf"
    binary = output / "boot.bin"
    memory_hex = output / "boot.hex"
    source.write_text(
        ".section .text\n.globl _start\n_start:\n"
        f"  li t0, {facts.pass_address}\n"
        f"  li t1, {facts.pass_value}\n"
        "  sw t1, 0(t0)\n"
        "1:\n  j 1b\n",
        encoding="ascii",
    )
    linker.write_text(
        "ENTRY(_start)\nSECTIONS {\n"
        f"  . = 0x{facts.reset_vector:x};\n"
        "  .text : { *(.text*) }\n  /DISCARD/ : { *(.comment) *(.riscv.attributes) }\n}\n",
        encoding="ascii",
    )
    base = (
        compiler, f"--target=riscv{facts.xlen}-unknown-elf", f"-march={facts.isa}",
        f"-mabi={_abi(facts.xlen)}", "-nostdlib", "-Wl,--build-id=none",
        f"-Wl,-T,{linker}", str(source),
    )
    elf_command = (*base, "-o", str(elf))
    result = subprocess.run(elf_command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RiscvExecutionError("boot-elf-build:" + (result.stderr.strip() or "failed"))
    binary_command = (*base, "-Wl,--oformat=binary", "-o", str(binary))
    result = subprocess.run(binary_command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RiscvExecutionError("boot-binary-build:" + (result.stderr.strip() or "failed"))
    payload = binary.read_bytes()
    if not payload:
        raise RiscvExecutionError("boot-binary-empty")
    memory_hex.write_text(
        f"@{facts.reset_vector:08x}\n" + "".join(f"{byte:02x}\n" for byte in payload),
        encoding="ascii",
    )
    version = subprocess.run((compiler, "--version"), capture_output=True, text=True, timeout=5, check=False)
    return BootImage(
        isa=facts.isa, xlen=facts.xlen, reset_vector=facts.reset_vector,
        load_base=facts.reset_vector,
        elf_path=elf, binary_path=binary, memory_hex_path=memory_hex,
        elf_hash=_sha256(elf), binary_hash=_sha256(binary),
        memory_hex_hash=_sha256(memory_hex), binary_size=len(payload),
        compiler=version.stdout.splitlines()[0] if version.stdout else compiler,
        command=tuple(binary_command),
    )


def verify_execution_events(event: ExecutionEvent, facts: RiscvExecutionFacts) -> None:
    if not event.reset_released:
        raise RiscvExecutionError("reset_released:missing")
    for name in ("successful_fetches", "progress_events", "backend_completions"):
        if getattr(event, name) < 1:
            raise RiscvExecutionError(f"{name}:missing")
    if not event.pass_observed:
        raise RiscvExecutionError("pass_observed:missing")
    if event.exit_reason != "pass":
        raise RiscvExecutionError("exit_reason:not-pass")
    if not 0 < event.cycles <= facts.max_cycles:
        raise RiscvExecutionError("cycles:outside-bound")


def verify_repository_pins(path: Path, expected: Mapping[str, str]) -> dict[str, str]:
    try:
        recorded = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RiscvExecutionError("pin-record:invalid") from error
    normalized = {str(key): str(value) for key, value in sorted(expected.items())}
    if recorded != normalized:
        raise RiscvExecutionError("pin-mismatch")
    for revision in normalized.values():
        if not revision.startswith("git:") or len(revision) != 44:
            raise RiscvExecutionError("pin-format:invalid")
    return normalized


def build_protocol_blocker(
    *, protocol: tuple[str, str], available_protocols: Sequence[tuple[str, str]],
    missing_dependencies: Sequence[str] = (),
) -> dict[str, object]:
    if protocol in available_protocols:
        raise RiscvExecutionError("protocol-capability:already-available")
    protocol_id = f"{protocol[0]}@{protocol[1]}"
    return {
        "schema_version": "riscv_execution_blocker.v1",
        "status": "BLOCKED",
        "reason": f"protocol-capability:{protocol_id}",
        "missing_dependencies": sorted(set(missing_dependencies)),
        "work_item": {
            "kind": "generic-protocol-work-item",
            "protocol": list(protocol),
            "requirements": [
                "source-backed physical boundary facts",
                "generic adapter to processor-memory-beat@1",
                "bounded temporal RTL tests",
                "real processor execution evidence",
            ],
        },
    }


def build_run_manifest(
    *, facts: RiscvExecutionFacts, event: ExecutionEvent,
    revisions: Mapping[str, str], nested_pins: Mapping[str, str],
    tools: Mapping[str, str], elaboration: Mapping[str, object],
    hashes: Mapping[str, str], peak_rss_bytes: int,
    warning_summary: Mapping[str, object], log_summary: Mapping[str, str],
) -> dict[str, object]:
    verify_execution_events(event, facts)
    required_hashes = {"composition", "layout", "source", "binary", "config"}
    if set(hashes) != required_hashes:
        raise RiscvExecutionError("hashes:incomplete")
    if isinstance(peak_rss_bytes, bool) or not isinstance(peak_rss_bytes, int) or peak_rss_bytes < 1:
        raise RiscvExecutionError("peak_rss_bytes:invalid")
    payload: dict[str, object] = {
        "schema_version": "riscv_execution.v1",
        "facts": {**asdict(facts), "protocol": list(facts.protocol)},
        "image": {
            "load_base": facts.reset_vector,
            "reset_vector": facts.reset_vector,
            "address_encoding": "verilog-readmemh-address-directive",
        },
        "revisions": dict(sorted(revisions.items())),
        "nested_pins": dict(sorted(nested_pins.items())),
        "tools": dict(sorted(tools.items())),
        "elaboration": dict(elaboration),
        "hashes": {key: _hash(value, key) for key, value in sorted(hashes.items())},
        "metrics": asdict(event) | {"peak_rss_bytes": peak_rss_bytes},
        "warning_summary": dict(warning_summary),
        "log_summary": dict(sorted(log_summary.items())),
    }
    payload["manifest_hash"] = content_hash(payload)
    return payload


__all__ = [
    "BootImage", "ExecutionEvent", "RiscvExecutionError", "RiscvExecutionFacts",
    "build_minimal_boot_image", "build_protocol_blocker", "build_run_manifest",
    "verify_execution_events", "verify_repository_pins",
]
