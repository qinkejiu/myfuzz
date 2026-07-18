"""Deterministic, read-only inventories for preserved experiment artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable, Mapping

from .contracts.experiment import content_digest
from .input_model import InputValidationError


_HASH_CHUNK_BYTES = 1024 * 1024


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_entry(entry: "ArtifactInventoryEntry") -> None:
    entry_path = Path(entry.path)
    if (
        not entry.path
        or entry_path.is_absolute()
        or entry_path.as_posix() != entry.path
        or ".." in entry_path.parts
    ):
        raise InputValidationError(f"invalid artifact inventory path: {entry.path!r}")
    if isinstance(entry.size, bool) or not isinstance(entry.size, int) or entry.size < 0:
        raise InputValidationError(f"invalid artifact inventory size for {entry.path}")
    if (
        len(entry.sha256) != 64
        or entry.sha256 != entry.sha256.lower()
        or any(character not in "0123456789abcdef" for character in entry.sha256)
    ):
        raise InputValidationError(f"invalid artifact inventory sha256 for {entry.path}")


@dataclass(frozen=True)
class ArtifactInventoryEntry:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ArtifactInventory:
    label: str
    root: str
    entries: tuple[ArtifactInventoryEntry, ...]
    total_bytes: int
    digest: str = ""
    schema: str = "myfuzz.artifact-inventory/v1"

    def __post_init__(self) -> None:
        if not self.label or not self.root:
            raise InputValidationError("artifact inventory label/root must be non-empty")
        if self.schema != "myfuzz.artifact-inventory/v1":
            raise InputValidationError(f"unsupported artifact inventory schema: {self.schema}")
        for entry in self.entries:
            _validate_entry(entry)
        paths = [entry.path for entry in self.entries]
        if not paths or paths != sorted(paths) or len(paths) != len(set(paths)):
            raise InputValidationError("artifact inventory paths must be unique and sorted")
        if self.total_bytes != sum(entry.size for entry in self.entries):
            raise InputValidationError("artifact inventory total_bytes mismatch")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("artifact inventory digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_artifact_inventory(
    root: str | Path,
    paths: Iterable[str | Path],
    *,
    label: str,
) -> ArtifactInventory:
    resolved_root = Path(root).resolve(strict=True)
    if not resolved_root.is_dir():
        raise InputValidationError("artifact inventory root must be a directory")
    files: set[Path] = set()
    for value in paths:
        candidate = Path(value)
        candidate = candidate if candidate.is_absolute() else resolved_root / candidate
        if candidate.is_symlink():
            raise InputValidationError(f"artifact inventory path must not be a symlink: {candidate}")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise InputValidationError(f"cannot resolve inventory path {candidate}: {exc}") from exc
        if resolved_root not in resolved.parents and resolved != resolved_root:
            raise InputValidationError(f"artifact inventory path escapes root: {candidate}")
        if resolved.is_dir():
            for path in resolved.rglob("*"):
                if path.is_symlink():
                    raise InputValidationError(
                        f"artifact inventory directory contains a symlink: {path}"
                    )
                if path.is_file():
                    files.add(path)
        elif resolved.is_file():
            files.add(resolved)
        else:
            raise InputValidationError(f"artifact inventory path is not a file/directory: {resolved}")
    if not files:
        raise InputValidationError("artifact inventory must contain at least one file")
    entries = tuple(
        ArtifactInventoryEntry(
            path.relative_to(resolved_root).as_posix(),
            os.path.getsize(path),
            _sha256_file(path),
        )
        for path in sorted(files, key=lambda item: item.relative_to(resolved_root).as_posix())
    )
    inventory = ArtifactInventory(label, resolved_root.as_posix(), entries, sum(item.size for item in entries))
    return replace(inventory, digest=content_digest(inventory.payload_dict()))


def artifact_inventory_from_dict(data: Mapping[str, object]) -> ArtifactInventory:
    if not isinstance(data, Mapping):
        raise InputValidationError("artifact inventory must be an object")
    expected_keys = {"label", "root", "entries", "total_bytes", "digest", "schema"}
    if set(data) != expected_keys:
        raise InputValidationError("artifact inventory fields do not match schema")
    for name in ("label", "root", "digest", "schema"):
        if not isinstance(data.get(name), str):
            raise InputValidationError(f"artifact inventory {name} must be a string")
    if (
        isinstance(data.get("total_bytes"), bool)
        or not isinstance(data.get("total_bytes"), int)
    ):
        raise InputValidationError("artifact inventory total_bytes must be an integer")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, (list, tuple)):
        raise InputValidationError("artifact inventory entries must be an array")
    entries: list[ArtifactInventoryEntry] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, Mapping) or set(raw_entry) != {"path", "size", "sha256"}:
            raise InputValidationError("artifact inventory entry fields do not match schema")
        if not isinstance(raw_entry.get("path"), str):
            raise InputValidationError("artifact inventory entry path must be a string")
        if (
            isinstance(raw_entry.get("size"), bool)
            or not isinstance(raw_entry.get("size"), int)
        ):
            raise InputValidationError("artifact inventory entry size must be an integer")
        if not isinstance(raw_entry.get("sha256"), str):
            raise InputValidationError("artifact inventory entry sha256 must be a string")
        entries.append(ArtifactInventoryEntry(
            path=raw_entry["path"],
            size=raw_entry["size"],
            sha256=raw_entry["sha256"],
        ))
    return ArtifactInventory(
        label=data["label"],
        root=data["root"],
        entries=tuple(entries),
        total_bytes=data["total_bytes"],
        digest=data["digest"],
        schema=data["schema"],
    )


def verify_artifact_inventory(
    inventory: ArtifactInventory,
    root: str | Path | None = None,
) -> None:
    inventory.__post_init__()
    expected_root = Path(inventory.root).resolve(strict=True)
    if not expected_root.is_dir():
        raise InputValidationError("artifact inventory root must be a directory")
    resolved_root = Path(root).resolve(strict=True) if root is not None else expected_root
    if resolved_root != expected_root:
        raise InputValidationError(
            f"artifact inventory root mismatch: expected {expected_root}, got {resolved_root}"
        )
    for entry in inventory.entries:
        candidate = resolved_root / entry.path
        if candidate.is_symlink():
            raise InputValidationError(
                f"artifact inventory entry became a symlink: {entry.path}"
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise InputValidationError(
                f"artifact inventory entry is missing: {entry.path}"
            ) from exc
        if resolved_root not in resolved.parents or not resolved.is_file():
            raise InputValidationError(
                f"artifact inventory entry is not a file below root: {entry.path}"
            )
        actual_size = os.path.getsize(resolved)
        if actual_size != entry.size:
            raise InputValidationError(
                f"artifact inventory size drift for {entry.path}: "
                f"expected {entry.size}, got {actual_size}"
            )
        actual_sha256 = _sha256_file(resolved)
        if actual_sha256 != entry.sha256:
            raise InputValidationError(
                f"artifact inventory SHA-256 drift for {entry.path}"
            )


def write_artifact_inventory(inventory: ArtifactInventory, output: str | Path) -> Path:
    inventory.__post_init__()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(inventory.to_dict(), sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    temporary.write_text(payload, encoding="ascii")
    os.replace(temporary, path)
    return path
