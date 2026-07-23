#!/usr/bin/env python3
"""Serialize memory-intensive host work with an owner-checked file lock."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable


DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_POLL_SECONDS = 0.25
LOCK_DIRECTORY_ENV = "MYFUZZ_MEMORY_GATE_DIR"
_LOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class GateError(RuntimeError):
    """Base error for a memory-gate operation."""


class LockBusyError(GateError):
    """The requested lock remains owned after bounded polling."""


class MemoryUnavailableError(GateError):
    """The host does not currently have the requested available memory."""


def default_lock_directory() -> Path:
    """Return the host-local directory used for untracked gate locks."""
    configured = os.environ.get(LOCK_DIRECTORY_ENV)
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "myfuzz-memory-gate"


def available_memory_mib() -> int:
    """Read Linux ``MemAvailable`` from procfs as whole MiB."""
    with Path("/proc/meminfo").open(encoding="utf-8") as stream:
        for line in stream:
            name, separator, value = line.partition(":")
            if name != "MemAvailable" or not separator:
                continue
            fields = value.split()
            if len(fields) != 2 or fields[1] != "kB":
                break
            return int(fields[0]) // 1024
    raise GateError("/proc/meminfo does not contain a valid MemAvailable entry")


def pid_is_alive(pid: int) -> bool:
    """Return whether a Linux/Unix PID currently exists."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _validate_name(value: str, label: str) -> None:
    if _LOCK_NAME.fullmatch(value) is None:
        raise GateError(f"{label} must contain only letters, digits, '.', '_' or '-'")


def _lock_path(lock_directory: Path, claim_name: str) -> Path:
    _validate_name(claim_name, "claim")
    return lock_directory / f"{claim_name}.lock"


def _read_record(lock_path: Path) -> dict[str, object] | None:
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _record_owner(record: dict[str, object] | None) -> str:
    if record is None or not isinstance(record.get("owner"), str):
        return "unknown owner"
    return record["owner"]


def _record_has_dead_pid(record: dict[str, object] | None, alive: Callable[[int], bool]) -> bool:
    if record is None:
        return False
    pid = record.get("pid")
    return isinstance(pid, int) and not isinstance(pid, bool) and not alive(pid)


def _write_lock(lock_path: Path, owner: str, memory_mib: int) -> None:
    record = {
        "owner": owner,
        "memory_mib": memory_mib,
        "pid": os.getpid(),
        "timestamp": datetime.now(UTC).isoformat(),
    }
    payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def claim(
    claim_name: str,
    memory_mib: int,
    owner: str,
    *,
    lock_directory: Path | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    available_memory_mib: Callable[[], int] = available_memory_mib,
    pid_is_alive: Callable[[int], bool] = pid_is_alive,
) -> Path:
    """Claim a named memory gate or raise after bounded polling."""
    _validate_name(owner, "owner")
    if memory_mib <= 0:
        raise GateError("memory_mib must be positive")
    if timeout_seconds < 0 or poll_seconds <= 0:
        raise GateError("timeout_seconds must be non-negative and poll_seconds must be positive")

    directory = default_lock_directory() if lock_directory is None else lock_directory
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = _lock_path(directory, claim_name)
    deadline = time.monotonic() + timeout_seconds
    last_available = available_memory_mib()
    last_owner = "unknown owner"

    while True:
        last_available = available_memory_mib()
        if last_available >= memory_mib:
            try:
                _write_lock(lock_path, owner, memory_mib)
                return lock_path
            except FileExistsError:
                record = _read_record(lock_path)
                last_owner = _record_owner(record)
                if _record_has_dead_pid(record, pid_is_alive):
                    try:
                        lock_path.unlink()
                    except FileNotFoundError:
                        pass
                    continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_available < memory_mib:
                raise MemoryUnavailableError(
                    f"memory gate '{claim_name}' requires {memory_mib} MiB, only {last_available} MiB available"
                )
            raise LockBusyError(f"memory gate '{claim_name}' is held by {last_owner}")
        time.sleep(min(poll_seconds, remaining))


def release(claim_name: str, owner: str, *, lock_directory: Path | None = None) -> bool:
    """Release a claim only when its lock record still identifies ``owner``."""
    _validate_name(owner, "owner")
    directory = default_lock_directory() if lock_directory is None else lock_directory
    lock_path = _lock_path(directory, claim_name)
    record = _read_record(lock_path)
    if record is None or record.get("owner") != owner:
        return False
    try:
        lock_path.unlink()
    except FileNotFoundError:
        return False
    return True


def _parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--claim", metavar="NAME")
    action.add_argument("--release", metavar="NAME")
    parser.add_argument("--memory-mib", type=int, default=0)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = _parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        if args.claim is not None:
            if args.memory_mib <= 0:
                raise GateError("--memory-mib must be positive when claiming a gate")
            lock_path = claim(
                args.claim,
                args.memory_mib,
                args.owner,
                timeout_seconds=args.timeout_seconds,
                poll_seconds=args.poll_seconds,
            )
            print(lock_path)
            return 0
        if release(args.release, args.owner):
            return 0
        print(f"memory gate '{args.release}' is not owned by {args.owner}", file=sys.stderr)
        return 1
    except GateError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
