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


def _identity(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RiscvExecutionError(f"{label}:invalid-identity")
    return value


@dataclass(frozen=True)
class RiscvExecutionProvenance:
    """Source-backed identities for the facts used to build and accept a run."""

    source_identity: str
    source_hash: str
    profile_identity: str
    profile_hash: str
    interface_identity: str
    interface_hash: str
    isa: str
    xlen: int
    reset_vector: int

    def __post_init__(self) -> None:
        for name in ("source_identity", "profile_identity", "interface_identity"):
            _identity(getattr(self, name), name)
        for name in ("source_hash", "profile_hash", "interface_hash"):
            _hash(getattr(self, name), name)
        if self.xlen not in {32, 64}:
            raise RiscvExecutionError("provenance:xlen-unsupported")
        if not isinstance(self.isa, str) or not self.isa.startswith(f"rv{self.xlen}"):
            raise RiscvExecutionError("provenance:isa-xlen-mismatch")
        if (
            isinstance(self.reset_vector, bool)
            or not isinstance(self.reset_vector, int)
            or self.reset_vector < 0
            or self.reset_vector % 4
        ):
            raise RiscvExecutionError("provenance:reset-vector-invalid")


@dataclass(frozen=True)
class RiscvExecutionFacts:
    isa: str
    xlen: int
    reset_vector: int
    pass_address: int
    pass_value: int
    protocol: tuple[str, str]
    max_cycles: int
    provenance: RiscvExecutionProvenance

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
        if not isinstance(self.provenance, RiscvExecutionProvenance):
            raise RiscvExecutionError("provenance:type")
        if self.provenance.isa != self.isa:
            raise RiscvExecutionError("provenance:isa-mismatch")
        if self.provenance.xlen != self.xlen:
            raise RiscvExecutionError("provenance:xlen-mismatch")
        if self.provenance.reset_vector != self.reset_vector:
            raise RiscvExecutionError("provenance:reset-vector-mismatch")


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
    first_fetch_data: int
    compiler: str
    command: tuple[str, ...]
    provenance: RiscvExecutionProvenance


@dataclass(frozen=True)
class RiscvExecutionEvent:
    reset_released: bool
    successful_fetches: int
    progress_events: int
    backend_completions: int
    pass_observed: bool
    cycles: int
    exit_reason: str
    first_fetch_address: int | None
    first_fetch_data: int | None
    illegal_or_trap_records: int


ExecutionEvent = RiscvExecutionEvent


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
    fetch_bytes = facts.xlen // 8
    if len(payload) < fetch_bytes:
        raise RiscvExecutionError("boot-binary-short-first-fetch")
    first_fetch_data = int.from_bytes(payload[:fetch_bytes], "little")
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
        first_fetch_data=first_fetch_data,
        compiler=version.stdout.splitlines()[0] if version.stdout else compiler,
        command=tuple(binary_command),
        provenance=facts.provenance,
    )


def verify_execution_events(
    event: RiscvExecutionEvent,
    facts: RiscvExecutionFacts,
    boot_image: BootImage | None = None,
) -> None:
    if not isinstance(event, RiscvExecutionEvent):
        raise RiscvExecutionError("event:type")
    if not isinstance(facts, RiscvExecutionFacts):
        raise RiscvExecutionError("facts:type")
    if boot_image is None:
        raise RiscvExecutionError("boot_image:missing")
    if not isinstance(boot_image, BootImage):
        raise RiscvExecutionError("boot_image:type")
    if boot_image.provenance != facts.provenance:
        raise RiscvExecutionError("provenance:mismatch")
    if (
        boot_image.isa != facts.isa
        or boot_image.xlen != facts.xlen
        or boot_image.reset_vector != facts.reset_vector
        or boot_image.load_base != facts.reset_vector
    ):
        raise RiscvExecutionError("boot_image:facts-mismatch")
    try:
        actual_binary_hash = _sha256(boot_image.binary_path)
        payload = boot_image.binary_path.read_bytes()
    except OSError as error:
        raise RiscvExecutionError("boot_image:unreadable") from error
    if actual_binary_hash != boot_image.binary_hash:
        raise RiscvExecutionError("boot_image:binary-hash-mismatch")
    fetch_bytes = facts.xlen // 8
    if len(payload) < fetch_bytes:
        raise RiscvExecutionError("boot_image:short-first-fetch")
    expected_first_fetch_data = int.from_bytes(payload[:fetch_bytes], "little")
    if boot_image.first_fetch_data != expected_first_fetch_data:
        raise RiscvExecutionError("boot_image:first-fetch-data-mismatch")
    if not event.reset_released:
        raise RiscvExecutionError("reset_released:missing")
    for name in ("successful_fetches", "progress_events", "backend_completions"):
        if getattr(event, name) < 1:
            raise RiscvExecutionError(f"{name}:missing")
    if not event.pass_observed:
        raise RiscvExecutionError("pass_observed:missing")
    if event.first_fetch_address != facts.reset_vector:
        raise RiscvExecutionError("first_fetch_address:mismatch")
    if event.first_fetch_data != expected_first_fetch_data:
        raise RiscvExecutionError("first_fetch_data:mismatch")
    if (
        isinstance(event.illegal_or_trap_records, bool)
        or not isinstance(event.illegal_or_trap_records, int)
        or event.illegal_or_trap_records < 0
    ):
        raise RiscvExecutionError("illegal_or_trap_records:invalid")
    if event.illegal_or_trap_records:
        raise RiscvExecutionError("illegal_or_trap_records:present")
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
    boot_image: BootImage | None = None,
    revisions: Mapping[str, str], nested_pins: Mapping[str, str],
    tools: Mapping[str, str], elaboration: Mapping[str, object],
    hashes: Mapping[str, str], peak_rss_bytes: int,
    warning_summary: Mapping[str, object], log_summary: Mapping[str, str],
) -> dict[str, object]:
    verify_execution_events(event, facts, boot_image)
    required_hashes = {"composition", "layout", "source", "binary", "config", "profile", "interface"}
    if not required_hashes.issubset(hashes):
        raise RiscvExecutionError("hashes:incomplete")
    validated_hashes = {key: _hash(value, key) for key, value in sorted(hashes.items())}
    for key, expected in (
        ("source", facts.provenance.source_hash),
        ("profile", facts.provenance.profile_hash),
        ("interface", facts.provenance.interface_hash),
        ("binary", boot_image.binary_hash),
    ):
        if validated_hashes[key] != expected:
            raise RiscvExecutionError(f"{key}-hash:mismatch")
    if isinstance(peak_rss_bytes, bool) or not isinstance(peak_rss_bytes, int) or peak_rss_bytes < 1:
        raise RiscvExecutionError("peak_rss_bytes:invalid")
    provenance = {
        "source": {"identity": facts.provenance.source_identity, "hash": facts.provenance.source_hash},
        "profile": {"identity": facts.provenance.profile_identity, "hash": facts.provenance.profile_hash},
        "interface": {"identity": facts.provenance.interface_identity, "hash": facts.provenance.interface_hash},
        "isa": facts.provenance.isa,
        "xlen": facts.provenance.xlen,
        "reset_vector": facts.provenance.reset_vector,
    }
    facts_document = asdict(facts)
    facts_document["protocol"] = list(facts.protocol)
    facts_document["provenance"] = provenance
    payload: dict[str, object] = {
        "schema_version": "riscv_execution.v1",
        "facts": facts_document,
        "image": {
            "load_base": facts.reset_vector,
            "reset_vector": facts.reset_vector,
            "address_encoding": "verilog-readmemh-address-directive",
            "first_fetch_address": facts.reset_vector,
            "first_fetch_data": boot_image.first_fetch_data,
        },
        "provenance": provenance,
        "revisions": dict(sorted(revisions.items())),
        "nested_pins": dict(sorted(nested_pins.items())),
        "tools": dict(sorted(tools.items())),
        "elaboration": dict(elaboration),
        "hashes": validated_hashes,
        "metrics": asdict(event) | {"peak_rss_bytes": peak_rss_bytes},
        "warning_summary": dict(warning_summary),
        "log_summary": dict(sorted(log_summary.items())),
    }
    payload["manifest_hash"] = content_hash(payload)
    return payload


__all__ = [
    "BootImage", "ExecutionEvent", "RiscvExecutionError", "RiscvExecutionEvent",
    "RiscvExecutionFacts", "RiscvExecutionProvenance",
    "build_minimal_boot_image", "build_protocol_blocker", "build_run_manifest",
    "verify_execution_events", "verify_repository_pins",
]
