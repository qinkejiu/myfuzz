"""Fail-closed RFuzz executable resolution and campaign config normalization."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from collections.abc import Mapping

from myfuzz.rfuzz_compat import (
    resolve_rfuzz_verilator,
    rfuzz_verilator_environment,
    validate_rfuzz_verilator_version,
)


_DEFAULT_CLIENT = Path("runs/rfuzz_client_native_build/target/debug/kfuzz")
_RFUZZ_FIELDS = frozenset({
    "client_binary", "verilator", "run_dir", "duration_seconds", "seed_cycles",
    "build_cache_dir", "arm",
})
_ARMS = frozenset({"direct_input", "constrained_baseline", "dependency_repair"})


class RfuzzToolchainError(ValueError):
    """A required official RFuzz tool is absent or has an unsafe identity."""


def normalize_rfuzz_config(config: Mapping[str, object]) -> dict[str, object]:
    """Merge the RFuzz subobject with legacy fields, refusing ambiguity."""
    nested = config.get("rfuzz", {})
    if not isinstance(nested, Mapping):
        raise ValueError("rfuzz:mapping-required")
    legacy_client = config.get("client")
    if "client" in config:
        for candidate in (config.get("client_binary"), nested.get("client_binary")):
            if candidate is not None and candidate != legacy_client:
                raise ValueError("rfuzz:conflict:client_binary")
    unknown = set(nested) - _RFUZZ_FIELDS
    if unknown:
        raise ValueError("rfuzz:unknown-field:" + sorted(unknown)[0])
    normal: dict[str, object] = {}
    for field in _RFUZZ_FIELDS:
        old = config.get(field)
        new = nested.get(field)
        if field in config and field in nested and old != new:
            raise ValueError(f"rfuzz:conflict:{field}")
        if field in nested:
            normal[field] = new
        elif field in config:
            normal[field] = old
    if "client" in config and "client_binary" not in normal:
        normal["client_binary"] = legacy_client
    if "client" in config and (not isinstance(legacy_client, str) or not legacy_client):
        raise ValueError("rfuzz:client_binary:nonempty-string-required")
    for source, value in (("client_binary", normal.get("client_binary")),):
        if source in config or source in nested:
            if not isinstance(value, str) or not value:
                raise ValueError(f"rfuzz:{source}:nonempty-string-required")
    normal.setdefault("verilator", "bundled")
    if normal["verilator"] != "bundled" and (
        not isinstance(normal["verilator"], str) or not normal["verilator"]
    ):
        raise ValueError("rfuzz:verilator:path-or-bundled-required")
    arm = normal.get("arm", "direct_input")
    if arm not in _ARMS:
        raise ValueError("rfuzz:arm:unsupported")
    normal["arm"] = arm
    return normal


def _regular_executable(path: Path, category: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RfuzzToolchainError(f"{category}: unavailable") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise RfuzzToolchainError(f"{category}: unavailable (regular executable required)")
    return path.resolve()


def _version(path: Path) -> str | None:
    """Return the tool's own version output; absence is never synthesized."""
    try:
        result = subprocess.run(
            [str(path), "--version"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = result.stdout.strip()
    return output or None


def _identity(path: Path, *, version: str | None, source: str) -> dict[str, object]:
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "version": version, "source": source}


def _path(root: Path, value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def _resolved_directory(root: Path, value: object, label: str, default: str) -> Path:
    if value is None:
        value = default
    if not isinstance(value, str) or not value:
        raise RfuzzToolchainError(f"{label}: invalid path")
    path = _path(root, value).resolve()
    return path


def _environment_hash(environment: Mapping[str, str]) -> str:
    payload = json.dumps(sorted((str(key), str(value)) for key, value in environment.items()),
                         ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_rfuzz_verilator_toolchain(
    root: Path, config: Mapping[str, object], *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Resolve the compiler half of the RFuzz toolchain for artifact builds."""
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("root:absolute-path-required")
    normal = normalize_rfuzz_config(config)
    effective_environment = os.environ if environment is None else dict(environment)
    requested = normal["verilator"]
    try:
        override = effective_environment.get("MYFUZZ_SERVER_VERILATOR_BIN")
        if requested == "bundled":
            selected = resolve_rfuzz_verilator(root, environment=effective_environment)
            source = "environment-override" if override else "bundled"
        elif isinstance(requested, str) and requested:
            selected = str(_path(root, requested))
            source = "controlled"
        else:
            raise ValueError("rfuzz:verilator:path-or-bundled-required")
        verilator = _regular_executable(Path(selected), "rfuzz-verilator-unavailable")
    except RfuzzToolchainError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise RfuzzToolchainError(f"rfuzz-verilator-unavailable: {error}") from error
    version = _version(verilator)
    try:
        validate_rfuzz_verilator_version(version or "")
    except ValueError as error:
        raise RfuzzToolchainError(
            f"rfuzz-verilator-version-mismatch: observed {version!r}") from error
    tool_environment = rfuzz_verilator_environment(
        root, str(verilator), environment=effective_environment)
    if tool_environment is None:
        tool_environment = dict(effective_environment)
    run_dir = _resolved_directory(root, normal.get("run_dir"), "rfuzz:run_dir", "runs/soc-rfuzz")
    cache_value = normal.get("build_cache_dir")
    cache_dir = (None if cache_value is None else str(_resolved_directory(
        root, cache_value, "rfuzz:build_cache_dir", "runs/soc-rfuzz-cache")))
    identity = _identity(verilator, version=version, source=source)
    identity["environment_sha256"] = _environment_hash(tool_environment)
    return {
        "schema_version": "rfuzz_verilator_toolchain.v1",
        "verilator": identity,
        "environment": dict(tool_environment),
        "environment_sha256": identity["environment_sha256"],
        "run_dir": str(run_dir),
        "build_cache_dir": cache_dir,
    }


def resolve_rfuzz_toolchain(
    root: Path, config: Mapping[str, object], *, environment: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Resolve only explicit/env/repository RFuzz tools, with auditable identities."""
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("root:absolute-path-required")
    try:
        normal = normalize_rfuzz_config(config)
    except ValueError as error:
        if str(error).startswith("rfuzz:client_binary:"):
            raise RfuzzToolchainError(
                "rfuzz-client-unavailable: " + str(error)) from error
        raise
    environment = os.environ if environment is None else environment
    if "client_binary" in normal and normal.get("client_binary") is not None:
        client_value = normal.get("client_binary")
        client_source = "explicit"
    else:
        client_value = environment.get("MYFUZZ_RFuzz_CLIENT")
        client_source = "environment"
    if not client_value:
        client_value, client_source = str(_DEFAULT_CLIENT), "repository-default"
    if not isinstance(client_value, str) or not client_value:
        raise RfuzzToolchainError("rfuzz-client-unavailable: invalid path")
    client = _regular_executable(_path(root, client_value), "rfuzz-client-unavailable")

    verilator_document = resolve_rfuzz_verilator_toolchain(
        root, config, environment=environment)
    tool_environment = verilator_document["environment"]
    run_dir = Path(verilator_document["run_dir"])
    client_document = _identity(client, version=_version(client), source=client_source)
    client_document["working_dir"] = str(run_dir)
    return {
        "schema_version": "rfuzz_toolchain.v1",
        "client": client_document,
        "verilator": verilator_document["verilator"],
        "verilator_environment": dict(tool_environment),
        "verilator_environment_sha256": verilator_document["environment_sha256"],
        "run_dir": verilator_document["run_dir"],
        "build_cache_dir": verilator_document["build_cache_dir"],
    }
