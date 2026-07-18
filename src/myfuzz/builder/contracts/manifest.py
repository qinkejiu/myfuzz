"""Immutable, content-addressed elaboration manifests and safe filelist expansion."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class ElaborationLimits:
    max_filelist_depth: int = 16
    max_files: int = 4096
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_include_dirs: int = 256
    max_defines: int = 1024


@dataclass(frozen=True)
class ResolvedFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class ElaborationManifest:
    schema: str
    stage: str
    top_module: str
    language: str
    sources: tuple[ResolvedFile, ...]
    include_dirs: tuple[str, ...]
    defines: tuple[str, ...]
    parameters: tuple[tuple[str, str], ...]
    tools: tuple[tuple[str, str], ...]
    parent_digest: str | None
    digest: str

    def payload(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _digest(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def build_elaboration_manifest(
    *,
    top_module: str,
    rtl_files: Iterable[str | Path] = (),
    filelists: Iterable[str | Path] = (),
    allow_roots: Iterable[str | Path],
    language: str = "systemverilog-2017",
    parameters: Mapping[str, int | str] | None = None,
    tools: Mapping[str, str] | None = None,
    limits: ElaborationLimits = ElaborationLimits(),
) -> ElaborationManifest:
    roots = tuple(sorted({Path(root).resolve(strict=True) for root in allow_roots}, key=str))
    if not roots:
        raise ManifestError("at least one allowlist root is required")
    sources: list[Path] = []
    include_dirs: list[Path] = []
    defines: list[str] = []
    active: set[Path] = set()

    def resolve(value: str | Path, base: Path) -> Path:
        candidate = Path(value)
        candidate = candidate if candidate.is_absolute() else base / candidate
        try:
            result = candidate.resolve(strict=True)
        except OSError as exc:
            raise ManifestError(f"cannot resolve {candidate}: {exc}") from exc
        if not _inside(result, roots):
            raise ManifestError(f"resolved path escapes allowlist roots: {candidate} -> {result}")
        return result

    def add_source(value: str | Path, base: Path) -> None:
        path = resolve(value, base)
        if not path.is_file():
            raise ManifestError(f"RTL source is not a file: {path}")
        if path not in sources:
            sources.append(path)
        if len(sources) > limits.max_files:
            raise ManifestError(f"source count exceeds limit {limits.max_files}")

    def expand(value: str | Path, base: Path, depth: int) -> None:
        if depth > limits.max_filelist_depth:
            raise ManifestError(f"filelist depth exceeds limit {limits.max_filelist_depth}")
        path = resolve(value, base)
        if path in active:
            raise ManifestError(f"filelist cycle detected at {path}")
        active.add(path)
        try:
            tokens = shlex.split(path.read_text(encoding="utf-8"), comments=True, posix=True)
            index = 0
            while index < len(tokens):
                token = tokens[index]
                if token in ("-f", "-F"):
                    index += 1
                    if index >= len(tokens):
                        raise ManifestError(f"{path}: {token} requires a path")
                    expand(tokens[index], path.parent, depth + 1)
                elif token.startswith("-f") and len(token) > 2:
                    expand(token[2:], path.parent, depth + 1)
                elif token.startswith("+incdir+"):
                    for item in token[len("+incdir+"):].split("+"):
                        include_dirs.append(resolve(item, path.parent))
                elif token in ("-I",):
                    index += 1
                    if index >= len(tokens):
                        raise ManifestError(f"{path}: -I requires a path")
                    include_dirs.append(resolve(tokens[index], path.parent))
                elif token.startswith("-I"):
                    include_dirs.append(resolve(token[2:], path.parent))
                elif token.startswith("+define+"):
                    defines.extend(item for item in token[len("+define+"):].split("+") if item)
                elif token.startswith("-D"):
                    if len(token) == 2:
                        raise ManifestError(f"{path}: -D requires a definition in the same token")
                    defines.append(token[2:])
                elif token.startswith("+") or token.startswith("-"):
                    raise ManifestError(f"{path}: unsupported filelist option {token!r}")
                else:
                    add_source(token, path.parent)
                index += 1
        finally:
            active.remove(path)

    cwd = Path.cwd()
    for value in rtl_files:
        add_source(value, cwd)
    for value in filelists:
        expand(value, cwd, 1)
    include_dirs = list(dict.fromkeys(include_dirs))
    defines = list(dict.fromkeys(defines))
    if len(include_dirs) > limits.max_include_dirs:
        raise ManifestError(f"include directory count exceeds limit {limits.max_include_dirs}")
    if len(defines) > limits.max_defines:
        raise ManifestError(f"define count exceeds limit {limits.max_defines}")
    resolved: list[ResolvedFile] = []
    total = 0
    for path in sources:
        size = os.path.getsize(path)
        if size > limits.max_file_bytes:
            raise ManifestError(f"{path}: size {size} exceeds limit {limits.max_file_bytes}")
        total += size
        if total > limits.max_total_bytes:
            raise ManifestError(f"total source bytes exceed limit {limits.max_total_bytes}")
        resolved.append(ResolvedFile(str(path), hashlib.sha256(path.read_bytes()).hexdigest(), size))
    manifest = ElaborationManifest(
        "myfuzz.elaboration-manifest/v1", "root", top_module, language, tuple(resolved),
        tuple(map(str, include_dirs)), tuple(defines),
        tuple(sorted((str(k), str(v)) for k, v in (parameters or {}).items())),
        tuple(sorted((str(k), str(v)) for k, v in (tools or {}).items())), None, "",
    )
    return replace(manifest, digest=_digest(manifest.payload()))


def derive_elaboration_manifest(
    parent: ElaborationManifest,
    *,
    stage: str,
    top_module: str | None = None,
    added_sources: Iterable[ResolvedFile] = (),
) -> ElaborationManifest:
    if not stage or stage == "root":
        raise ManifestError("derived stage must be a non-root name")
    manifest = replace(
        parent, stage=stage, top_module=top_module or parent.top_module,
        sources=parent.sources + tuple(added_sources), parent_digest=parent.digest, digest="",
    )
    return replace(manifest, digest=_digest(manifest.payload()))


def derive_rewritten_elaboration_manifest(
    parent: ElaborationManifest,
    *,
    stage: str,
    sources: Iterable[ResolvedFile],
    include_dirs: Iterable[str] | None = None,
    top_module: str | None = None,
) -> ElaborationManifest:
    """Derive a stage whose sources replace, rather than extend, its parent's RTL tree."""
    if not stage or stage == "root":
        raise ManifestError("derived stage must be a non-root name")
    rewritten = tuple(sources)
    if not rewritten:
        raise ManifestError("rewritten manifest must contain at least one source")
    manifest = replace(
        parent,
        stage=stage,
        top_module=top_module or parent.top_module,
        sources=rewritten,
        include_dirs=tuple(include_dirs) if include_dirs is not None else parent.include_dirs,
        parent_digest=parent.digest,
        digest="",
    )
    return replace(manifest, digest=_digest(manifest.payload()))
