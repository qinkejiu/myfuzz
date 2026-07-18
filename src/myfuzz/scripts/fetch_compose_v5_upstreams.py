#!/usr/bin/env python3
"""Fetch and verify pinned compose-v5 qualification sources without shell expansion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_LOCK = ROOT / "materials" / "compose_v5" / "upstreams.json"
DEFAULT_COMMAND_TIMEOUT_SECONDS = 300


class SourceLockError(ValueError):
    pass


def _run(
    argv: list[str], *,
    cwd: Path | None = None,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> str:
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
    }
    try:
        result = subprocess.run(
            argv, cwd=cwd, env=environment, check=False, timeout=timeout_seconds,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise SourceLockError(
            f"command timed out after {timeout_seconds}s: {argv!r}"
        ) from exc
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SourceLockError(f"command failed ({result.returncode}): {argv!r}: {detail}")
    return result.stdout.strip()


def _load(path: Path) -> tuple[Mapping[str, object], ...]:
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceLockError(f"cannot read upstream lock {path}: {exc}") from exc
    if not isinstance(value, Mapping) or set(value) != {"schema", "targets"}:
        raise SourceLockError("upstream lock must contain only schema and targets")
    if value["schema"] != "myfuzz.compose-v5-upstreams/v1":
        raise SourceLockError("unsupported upstream lock schema")
    targets = value["targets"]
    if not isinstance(targets, list) or not targets or any(not isinstance(item, Mapping) for item in targets):
        raise SourceLockError("upstream lock targets must be a non-empty array of objects")
    expected = {
        "id", "url", "revision", "sparse_paths", "license_path", "license_sha256", "submodules",
    }
    identifiers: list[str] = []
    for item in targets:
        if set(item) != expected:
            raise SourceLockError(f"upstream target field mismatch: {item.get('id', '<unknown>')}")
        for field in ("id", "url", "revision", "license_path", "license_sha256"):
            if not isinstance(item[field], str) or not item[field]:
                raise SourceLockError(f"upstream target {field} must be a non-empty string")
        if len(item["revision"]) != 40 or len(item["license_sha256"]) != 64:
            raise SourceLockError(f"upstream target {item['id']} has an invalid digest")
        if not isinstance(item["sparse_paths"], list) or not isinstance(item["submodules"], list):
            raise SourceLockError(f"upstream target {item['id']} has invalid arrays")
        identifiers.append(item["id"])
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise SourceLockError("upstream targets must be unique and sorted")
    return tuple(targets)


def _verify(
    target: Mapping[str, object],
    destination: Path,
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> None:
    revision = str(target["revision"])
    actual = _run(["git", "-C", str(destination), "rev-parse", "HEAD"], timeout_seconds=timeout_seconds)
    if actual != revision:
        raise SourceLockError(f"{target['id']}: expected revision {revision}, got {actual}")
    license_path = destination / str(target["license_path"])
    try:
        license_digest = hashlib.sha256(license_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise SourceLockError(f"{target['id']}: cannot read license: {exc}") from exc
    if license_digest != target["license_sha256"]:
        raise SourceLockError(f"{target['id']}: license SHA-256 mismatch")
    for raw in target["submodules"]:
        if not isinstance(raw, Mapping) or set(raw) != {"path", "revision"}:
            raise SourceLockError(f"{target['id']}: invalid submodule lock")
        actual = _run(
            ["git", "-C", str(destination / str(raw["path"])), "rev-parse", "HEAD"],
            timeout_seconds=timeout_seconds,
        )
        if actual != raw["revision"]:
            raise SourceLockError(
                f"{target['id']}:{raw['path']}: expected {raw['revision']}, got {actual}"
            )


def _is_strict_subpath(path: str, parent: str) -> bool:
    return path != parent and path.startswith(parent.rstrip("/") + "/")


def _submodule_update_command(destination: Path, path: str, initialized_paths: tuple[str, ...]) -> list[str]:
    parent = ""
    for candidate in initialized_paths:
        if _is_strict_subpath(path, candidate) and len(candidate) > len(parent):
            parent = candidate
    if not parent:
        return ["git", "-C", str(destination), "submodule", "update", "--init", "--depth", "1", path]
    relative_path = path[len(parent.rstrip("/") + "/"):]
    return [
        "git", "-C", str(destination / parent),
        "submodule", "update", "--init", "--depth", "1", relative_path,
    ]


def _fetch(
    target: Mapping[str, object],
    cache: Path,
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> Path:
    destination = cache / str(target["id"])
    if not (destination / ".git").is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        _run(["git", "init", str(destination)], timeout_seconds=timeout_seconds)
        _run(
            ["git", "-C", str(destination), "remote", "add", "origin", str(target["url"])],
            timeout_seconds=timeout_seconds,
        )
    # Read the stored value directly. `remote get-url` applies the caller's
    # url.*.insteadOf rules and can turn an identical locked HTTPS URL into its
    # SSH display form.
    origin = _run([
        "git", "-C", str(destination), "config", "--local", "--get", "remote.origin.url",
    ], timeout_seconds=timeout_seconds)
    if origin != target["url"]:
        raise SourceLockError(f"{target['id']}: origin URL mismatch: {origin}")
    revision = str(target["revision"])
    _run(
        ["git", "-C", str(destination), "fetch", "--depth", "1", "origin", revision],
        timeout_seconds=timeout_seconds,
    )
    sparse_paths = [str(item) for item in target["sparse_paths"]]
    if sparse_paths:
        _run(
            ["git", "-C", str(destination), "sparse-checkout", "init", "--cone"],
            timeout_seconds=timeout_seconds,
        )
        _run(
            ["git", "-C", str(destination), "sparse-checkout", "set", *sparse_paths],
            timeout_seconds=timeout_seconds,
        )
    _run(["git", "-C", str(destination), "checkout", "--detach", revision], timeout_seconds=timeout_seconds)
    initialized_submodules: list[str] = []
    for raw in sorted(target["submodules"], key=lambda item: str(item["path"]).count("/")):
        path = str(raw["path"])
        _run(
            _submodule_update_command(destination, path, tuple(initialized_submodules)),
            timeout_seconds=timeout_seconds,
        )
        initialized_submodules.append(path)
    _verify(target, destination, timeout_seconds=timeout_seconds)
    return destination


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--command-timeout-seconds", type=int, default=DEFAULT_COMMAND_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command_timeout_seconds <= 0:
        raise SourceLockError("--command-timeout-seconds must be positive")
    targets = _load(args.lock)
    selected = set(args.target)
    known = {str(item["id"]) for item in targets}
    if selected - known:
        raise SourceLockError(f"unknown target(s): {', '.join(sorted(selected - known))}")
    targets = tuple(item for item in targets if not selected or item["id"] in selected)
    if args.list:
        for item in targets:
            print(f"{item['id']} {item['revision']} {item['url']}")
        return 0
    args.cache.mkdir(parents=True, exist_ok=True)
    for item in targets:
        destination = args.cache / str(item["id"])
        if args.verify_only:
            _verify(item, destination, timeout_seconds=args.command_timeout_seconds)
        else:
            destination = _fetch(item, args.cache, timeout_seconds=args.command_timeout_seconds)
        print(f"verified {item['id']} {item['revision']} {destination}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SourceLockError as exc:
        raise SystemExit(f"compose-v5 source acquisition: {exc}") from exc
