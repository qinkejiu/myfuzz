"""Fail-closed RFUZZ dependency and transaction server contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Mapping

from ..input_model import InputValidationError


@dataclass(frozen=True)
class RFuzzDependencyManifest:
    source_url: str
    revision: str
    license_file: str
    license_sha256: str
    files: tuple[Mapping[str, object], ...]
    patches: tuple[Mapping[str, object], ...]
    build_tools: tuple[Mapping[str, object], ...]
    schema: str = "myfuzz.rfuzz-dependency/v1"
    def to_dict(self) -> dict[str, object]: return asdict(self)


@dataclass(frozen=True)
class TransactionServerContract:
    protocol: str
    rawbits_schema: str
    access_record_schema: str
    ready_valid_consume: bool
    operations: tuple[str, ...]
    terminal_events: tuple[str, ...]
    epoch_width: int
    schema: str = "myfuzz.transaction-server/v1"

    def __post_init__(self) -> None:
        operations = ("fixed_replay", "coverage_guided_mutation", "corpus_replay", "minimization",
                      "variable_length", "end_of_input")
        events = ("completed", "target_timeout", "process_crash", "reconnected")
        if (self.protocol != "transaction_paced" or not self.ready_valid_consume or
                self.operations != operations or self.terminal_events != events):
            raise InputValidationError("transaction server capabilities do not match v1")
        if self.rawbits_schema != "myfuzz.rawbits/v2" or self.access_record_schema != "myfuzz.access-record/v1":
            raise InputValidationError("transaction server data ABI does not match v1")
        if self.epoch_width <= 1: raise InputValidationError("epoch_width must exceed one bit")

    def to_dict(self) -> dict[str, object]: return asdict(self)


def verify_rfuzz_dependency(root: str | Path, manifest: RFuzzDependencyManifest) -> dict[str, object]:
    dependency_root = Path(root)
    if not dependency_root.is_dir():
        raise InputValidationError(f"RFUZZ dependency is missing: {dependency_root}")
    if not manifest.source_url or not manifest.revision:
        raise InputValidationError("RFUZZ source URL and pinned revision are required")
    checked = []
    entries = ({"path": manifest.license_file, "sha256": manifest.license_sha256},) + manifest.files
    for entry in entries:
        if set(entry) != {"path", "sha256"}: raise InputValidationError("invalid dependency file entry")
        relative = Path(str(entry["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise InputValidationError(f"RFUZZ dependency path escapes root: {relative}")
        path = dependency_root / relative
        if not path.is_file(): raise InputValidationError(f"RFUZZ dependency file is missing: {relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]: raise InputValidationError(f"RFUZZ dependency digest mismatch: {relative}")
        checked.append({"path": relative.as_posix(), "sha256": digest, "size": path.stat().st_size})
    marker = dependency_root / ".myfuzz-revision"
    if not marker.is_file() or marker.read_text(encoding="utf-8").strip() != manifest.revision:
        raise InputValidationError("RFUZZ dependency revision marker is missing or incorrect")
    return {"schema": "myfuzz.rfuzz-dependency-check/v1", "revision": manifest.revision,
            "files": checked, "status": "verified"}
