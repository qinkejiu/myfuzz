#!/usr/bin/env python3
"""Serialize memory-intensive host work with a token-checked file lease."""

from __future__ import annotations

import argparse
import errno
import json
import math
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, Mapping, NamedTuple

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by importing on non-Unix hosts.
    fcntl = None  # type: ignore[assignment]


DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_POLL_SECONDS = 0.25
DEFAULT_RELEASE_TIMEOUT_SECONDS = 1.0
DEFAULT_GUARD_POLL_SECONDS = 0.01
LOCK_DIRECTORY_ENV = "MYFUZZ_MEMORY_GATE_DIR"
_LOCK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
_RECLAIM_GUARD_SUFFIX = ".reclaim"
_RESERVED_RECORD_FIELDS = frozenset({"owner", "memory_mib", "pid", "timestamp", "token"})
_MAX_LOCK_RECORD_BYTES = 64 * 1024


class GateError(RuntimeError):
    """Base error for a memory-gate operation."""


class LockBusyError(GateError):
    """The requested lock remains owned after bounded polling."""


class MemoryUnavailableError(GateError):
    """The host does not currently have the requested available memory."""


class Lease(os.PathLike[str]):
    """Identity required to release one specific memory-gate claim."""

    __slots__ = ("path", "owner", "token", "pid", "device", "inode", "_record_payload")

    def __init__(
        self,
        path: Path,
        owner: str,
        token: str,
        pid: int,
        device: int,
        inode: int,
        record_payload: bytes,
    ) -> None:
        self.path = path
        self.owner = owner
        self.token = token
        self.pid = pid
        self.device = device
        self.inode = inode
        if not isinstance(record_payload, bytes):
            raise TypeError("record_payload must be immutable bytes")
        self._record_payload = record_payload

    @property
    def record_payload(self) -> bytes:
        """Return the bounded immutable audit bytes persisted for this lease."""
        return self._record_payload

    @property
    def claim_name(self) -> str:
        return self.path.name.removesuffix(".lock")

    def __fspath__(self) -> str:
        return os.fspath(self.path)

    def __str__(self) -> str:
        return str(self.path)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Lease):
            return (
                self.path,
                self.owner,
                self.token,
                self.pid,
                self.device,
                self.inode,
                self.record_payload,
            ) == (
                other.path,
                other.owner,
                other.token,
                other.pid,
                other.device,
                other.inode,
                other.record_payload,
            )
        return self.path == other

    def __hash__(self) -> int:
        return hash(self.path)

    def __getattr__(self, name: str) -> object:
        return getattr(self.path, name)

    def as_dict(self) -> dict[str, object]:
        return {
            "lock_path": str(self.path),
            "owner": self.owner,
            "pid": self.pid,
            "token": self.token,
        }


class LeaseRetainedError(GateError):
    """An operation failed after creating a lease that the caller must retain."""

    def __init__(self, message: str, lease: Lease) -> None:
        super().__init__(message)
        self.lease = lease


class _LockObservation(NamedTuple):
    device: int
    inode: int
    payload: bytes
    record: dict[str, object] | None


class _UnlinkOutcome(NamedTuple):
    lease_retired: bool
    finalization_error: str | None


def default_lock_directory() -> Path:
    """Return the host-local directory used for untracked gate locks."""
    configured = os.environ.get(LOCK_DIRECTORY_ENV)
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "myfuzz-memory-gate"


def available_memory_mib() -> int:
    """Read Linux ``MemAvailable`` from procfs as whole MiB."""
    if not sys.platform.startswith("linux"):
        raise GateError("memory gate requires Linux /proc/meminfo")
    try:
        with Path("/proc/meminfo").open(encoding="utf-8") as stream:
            for line in stream:
                name, separator, value = line.partition(":")
                if name != "MemAvailable" or not separator:
                    continue
                fields = value.split()
                if len(fields) != 2 or fields[1] != "kB":
                    break
                try:
                    available_kib = int(fields[0])
                except ValueError as error:
                    raise GateError("invalid MemAvailable numeric value in /proc/meminfo") from error
                if available_kib < 0:
                    raise GateError("invalid MemAvailable numeric value in /proc/meminfo")
                return available_kib // 1024
    except GateError:
        raise
    except (OSError, UnicodeError) as error:
        raise GateError(f"cannot read Linux /proc/meminfo: {error}") from error
    raise GateError("/proc/meminfo does not contain a valid MemAvailable entry")


def pid_is_alive(pid: int) -> bool:
    """Return whether a Linux/Unix PID currently exists."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OverflowError as error:
        raise GateError(f"PID {pid} is outside the platform process-ID range") from error
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


def _try_acquire_reclaim_guard(lock_path: Path) -> int | None:
    """Serialize cooperative creation, reclamation, and release for one gate."""
    if fcntl is None:
        raise GateError("memory gate requires fcntl.flock support")
    guard_path = lock_path.with_name(f"{lock_path.name}{_RECLAIM_GUARD_SUFFIX}")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(guard_path, flags, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        assert descriptor is not None
        os.close(descriptor)
        return None
    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise GateError(f"cannot lock reclaim sidecar '{guard_path}': {error}") from error
    assert descriptor is not None
    return descriptor


def _release_reclaim_guard(descriptor: int) -> None:
    if fcntl is None:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise GateError("memory gate requires fcntl.flock support")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError as error:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise GateError(f"cannot unlock reclaim sidecar: {error}") from error
    try:
        os.close(descriptor)
    except OSError as error:
        raise GateError(f"cannot close reclaim sidecar: {error}") from error


def _acquire_reclaim_guard(lock_path: Path, timeout_seconds: float, poll_seconds: float) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        descriptor = _try_acquire_reclaim_guard(lock_path)
        if descriptor is not None:
            return descriptor
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(poll_seconds, remaining))


def _observe_lock(lock_path: Path, *, allow_unreadable: bool = False) -> _LockObservation | None:
    """Read a bounded regular-file record without following or blocking on special files."""
    try:
        path_metadata = lock_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise GateError(f"cannot inspect memory gate lock '{lock_path}': {error}") from error
    if not stat.S_ISREG(path_metadata.st_mode):
        return _LockObservation(path_metadata.st_dev, path_metadata.st_ino, b"", None)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(lock_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return _LockObservation(metadata.st_dev, metadata.st_ino, b"", None)
        payload_buffer = bytearray()
        while len(payload_buffer) <= _MAX_LOCK_RECORD_BYTES:
            try:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, _MAX_LOCK_RECORD_BYTES + 1 - len(payload_buffer)),
                )
            except InterruptedError:
                continue
            if not chunk:
                break
            payload_buffer.extend(chunk)
        payload = bytes(payload_buffer)
    except FileNotFoundError:
        return None
    except OSError as error:
        try:
            current_metadata = lock_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as inspect_error:
            raise GateError(
                f"cannot inspect memory gate lock '{lock_path}' after read failure: {inspect_error}"
            ) from inspect_error
        if not stat.S_ISREG(current_metadata.st_mode):
            return _LockObservation(current_metadata.st_dev, current_metadata.st_ino, b"", None)
        if allow_unreadable and error.errno in (errno.EACCES, errno.EPERM):
            return _LockObservation(current_metadata.st_dev, current_metadata.st_ino, b"", None)
        raise GateError(f"cannot read memory gate lock '{lock_path}': {error}") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(payload) > _MAX_LOCK_RECORD_BYTES:
        return _LockObservation(metadata.st_dev, metadata.st_ino, payload, None)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            parse_constant=_reject_nonfinite_json,
            parse_float=_parse_finite_json_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        record = None
    else:
        record = value if isinstance(value, dict) else None
    return _LockObservation(metadata.st_dev, metadata.st_ino, payload, record)


def _reject_nonfinite_json(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number: {value}")
    return parsed


def _read_record(lock_path: Path) -> dict[str, object] | None:
    observation = _observe_lock(lock_path)
    return None if observation is None else observation.record


def _unlink_if_observed(
    lock_path: Path,
    expected: _LockObservation,
    *,
    allow_unreadable: bool = False,
) -> bool:
    """Revalidate a lock before unlinking it under the cooperative sidecar.

    The sidecar is advisory. The final pathname unlink cannot be made conditional
    on inode identity against a writer that deliberately bypasses that protocol.
    """
    if _observe_lock(lock_path, allow_unreadable=allow_unreadable) != expected:
        return False
    try:
        lock_path.unlink()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise GateError(f"cannot remove memory gate lock '{lock_path}': {error}") from error
    _fsync_directory(lock_path.parent)
    return True


def _record_owner(record: dict[str, object] | None) -> str:
    if record is None or not isinstance(record.get("owner"), str):
        return "unknown owner"
    return record["owner"]


def _record_has_required_fields(record: dict[str, object] | None) -> bool:
    if record is None:
        return False
    owner = record.get("owner")
    memory_mib = record.get("memory_mib")
    pid = record.get("pid")
    timestamp = record.get("timestamp")
    if not isinstance(owner, str) or _LOCK_NAME.fullmatch(owner) is None:
        return False
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or memory_mib <= 0:
        return False
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if not isinstance(timestamp, str) or not timestamp:
        return False
    return True


def _record_has_dead_pid(record: dict[str, object] | None, alive: Callable[[int], bool]) -> bool:
    if not _record_has_required_fields(record):
        return False
    assert record is not None
    pid = record.get("pid")
    return isinstance(pid, int) and not isinstance(pid, bool) and not alive(pid)


def _validated_record_fields(record_fields: Mapping[str, object] | None) -> dict[str, object]:
    if record_fields is None:
        return {}
    if not isinstance(record_fields, Mapping):
        raise GateError("record_fields must be a mapping")
    fields = dict(record_fields)
    if any(not isinstance(name, str) or not name or name in _RESERVED_RECORD_FIELDS for name in fields):
        raise GateError("record_fields cannot replace required lock record fields")
    try:
        json.dumps(fields, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise GateError("record_fields must be JSON serializable") from error
    return fields


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        try:
            written = os.write(descriptor, remaining)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "write returned no progress")
        remaining = remaining[written:]


def _fsync_directory(directory: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        raise GateError(f"cannot open memory gate directory '{directory}' for fsync: {error}") from error

    sync_error: OSError | None = None
    close_error: OSError | None = None
    try:
        os.fsync(descriptor)
    except OSError as error:
        sync_error = error
    try:
        os.close(descriptor)
    except OSError as error:
        close_error = error

    if sync_error is not None:
        message = f"cannot fsync memory gate directory '{directory}': {sync_error}"
        if close_error is not None:
            message = f"{message}; close also failed: {close_error}"
        raise GateError(message) from sync_error
    if close_error is not None:
        raise GateError(f"cannot close memory gate directory '{directory}': {close_error}") from close_error


def _unlink_lock_identity(lock_path: Path, device: int, inode: int) -> _UnlinkOutcome:
    """Remove one lock identity without touching an uncooperative replacement."""
    try:
        current = lock_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return _UnlinkOutcome(True, None)
    except OSError as error:
        return _UnlinkOutcome(False, str(error))
    if (current.st_dev, current.st_ino) != (device, inode):
        return _UnlinkOutcome(True, None)

    try:
        lock_path.unlink()
    except FileNotFoundError:
        return _UnlinkOutcome(True, None)
    except OSError as error:
        return _UnlinkOutcome(False, str(error))

    try:
        _fsync_directory(lock_path.parent)
    except GateError as error:
        return _UnlinkOutcome(True, str(error))
    return _UnlinkOutcome(True, None)


def _unlink_created_lock(lock_path: Path, metadata: os.stat_result) -> _UnlinkOutcome:
    return _unlink_lock_identity(lock_path, metadata.st_dev, metadata.st_ino)


def _write_lock(
    lock_path: Path,
    owner: str,
    memory_mib: int,
    record_fields: Mapping[str, object] | None = None,
    *,
    pid: int | None = None,
    commit_check: Callable[[], None] | None = None,
) -> Lease:
    holder_pid = os.getpid() if pid is None else pid
    token = secrets.token_hex(16)
    record = {
        "owner": owner,
        "memory_mib": memory_mib,
        "pid": holder_pid,
        "timestamp": datetime.now(UTC).isoformat(),
        "token": token,
    }
    record.update(_validated_record_fields(record_fields))
    payload = (json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > _MAX_LOCK_RECORD_BYTES:
        raise GateError(f"memory gate lock record exceeds {_MAX_LOCK_RECORD_BYTES} byte limit")
    staging_path = lock_path.with_name(f".{lock_path.name}.{token}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(staging_path, flags, 0o600)
    except OSError as error:
        raise GateError(f"cannot create memory gate lock staging file '{staging_path}': {error}") from error
    metadata: os.stat_result | None = None
    persistence_error: OSError | None = None
    close_error: OSError | None = None
    try:
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
    except OSError as error:
        persistence_error = error
    try:
        os.close(descriptor)
    except OSError as error:
        close_error = error
        if persistence_error is None:
            persistence_error = error
    if persistence_error is not None:
        message = f"cannot persist memory gate lock '{lock_path}': {persistence_error}"
        if close_error is not None and close_error is not persistence_error:
            message = f"{message}; close also failed: {close_error}"
        try:
            os.unlink(staging_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            message = f"{message}; staging cleanup failed: {cleanup_error}"
        raise GateError(message) from persistence_error
    assert metadata is not None
    lease = Lease(lock_path, owner, token, holder_pid, metadata.st_dev, metadata.st_ino, payload)
    try:
        if commit_check is not None:
            commit_check()
    except BaseException as error:
        try:
            os.unlink(staging_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            raise GateError(f"{error}; staging cleanup failed: {cleanup_error}") from error
        raise
    try:
        os.link(staging_path, lock_path, follow_symlinks=False)
    except FileExistsError as error:
        try:
            os.unlink(staging_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            raise GateError(
                f"memory gate lock '{lock_path}' already exists; staging cleanup failed: {cleanup_error}"
            ) from error
        raise
    except OSError as error:
        message = f"cannot create memory gate lock '{lock_path}': {error}"
        try:
            os.unlink(staging_path)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            message = f"{message}; staging cleanup failed: {cleanup_error}"
        raise GateError(message) from error
    namespace_errors: list[tuple[str, BaseException]] = []
    try:
        os.unlink(staging_path)
    except OSError as error:
        namespace_errors.append(("staging cleanup failed", error))
    try:
        _fsync_directory(lock_path.parent)
    except GateError as error:
        namespace_errors.append(("directory fsync failed", error))
    if namespace_errors:
        details = "; ".join(f"{label}: {error}" for label, error in namespace_errors)
        raise LeaseRetainedError(
            f"memory gate lock '{lock_path}' was published but namespace finalization failed: {details}",
            lease,
        ) from namespace_errors[0][1]
    return lease


def _require_live_claim_pid(pid: int) -> None:
    try:
        alive = pid_is_alive(pid)
    except OSError as error:
        raise GateError(f"cannot verify --pid {pid} immediately before claiming: {error}") from error
    if not alive:
        raise GateError(f"--pid {pid} is no longer alive")


def _raise_revalidated_retained_error(
    error: LeaseRetainedError,
    diagnostic: str | None = None,
) -> None:
    message = str(error) if diagnostic is None else diagnostic
    try:
        retired = _lease_is_retired(error.lease)
    except BaseException as verification_error:
        raise LeaseRetainedError(
            f"{message}; cannot verify retained lease identity: {verification_error}",
            error.lease,
        ) from verification_error
    if retired:
        raise GateError(f"{message}; lease is no longer retained") from error
    if diagnostic is None:
        raise error
    raise LeaseRetainedError(message, error.lease) from error


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
    pid: int | None = None,
    record_fields: Mapping[str, object] | None = None,
) -> Lease:
    """Claim a named memory gate or raise after bounded polling."""
    _validate_name(owner, "owner")
    holder_pid = os.getpid() if pid is None else pid
    if isinstance(holder_pid, bool) or not isinstance(holder_pid, int) or holder_pid <= 0:
        raise GateError("pid must be a positive integer")
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool) or memory_mib <= 0:
        raise GateError("memory_mib must be a positive integer")
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise GateError("timeout_seconds must be finite and non-negative")
    if not math.isfinite(poll_seconds) or poll_seconds <= 0:
        raise GateError("poll_seconds must be finite and positive")

    directory = default_lock_directory() if lock_directory is None else lock_directory
    directory.mkdir(parents=True, exist_ok=True)
    lock_path = _lock_path(directory, claim_name)
    persisted_fields = _validated_record_fields(record_fields)
    commit_check = None if pid is None else lambda: _require_live_claim_pid(holder_pid)
    deadline = time.monotonic() + timeout_seconds
    last_available = available_memory_mib()
    last_owner = "unknown owner"

    while True:
        last_available = available_memory_mib()
        if last_available >= memory_mib:
            guard_descriptor = _try_acquire_reclaim_guard(lock_path)
            if guard_descriptor is not None:
                acquired_lease: Lease | None = None
                retained_error: LeaseRetainedError | None = None
                try:
                    try:
                        acquired_lease = _write_lock(
                            lock_path,
                            owner,
                            memory_mib,
                            persisted_fields,
                            pid=holder_pid,
                            commit_check=commit_check,
                        )
                    except FileExistsError:
                        observation = _observe_lock(lock_path)
                        record = None if observation is None else observation.record
                        last_owner = _record_owner(record)
                        if (
                            observation is not None
                            and _record_has_dead_pid(record, pid_is_alive)
                            and _unlink_if_observed(lock_path, observation)
                        ):
                            try:
                                acquired_lease = _write_lock(
                                    lock_path,
                                    owner,
                                    memory_mib,
                                    persisted_fields,
                                    pid=holder_pid,
                                    commit_check=commit_check,
                                )
                            except FileExistsError:
                                pass
                except LeaseRetainedError as error:
                    retained_error = error
                finally:
                    try:
                        _release_reclaim_guard(guard_descriptor)
                    except BaseException as error:
                        if acquired_lease is None:
                            if retained_error is not None:
                                _raise_revalidated_retained_error(
                                    retained_error,
                                    f"{retained_error}; cannot finalize memory gate claim "
                                    f"'{claim_name}': {error}",
                                )
                            raise
                        rollback = _unlink_lock_identity(
                            acquired_lease.path,
                            acquired_lease.device,
                            acquired_lease.inode,
                        )
                        if rollback.lease_retired:
                            message = (
                                f"cannot finalize memory gate claim '{claim_name}'; "
                                f"created lease was rolled back: {error}"
                            )
                            if rollback.finalization_error is not None:
                                message = (
                                    f"{message}; rollback namespace finalization failed: "
                                    f"{rollback.finalization_error}"
                                )
                            raise GateError(message) from error
                        raise LeaseRetainedError(
                            f"cannot finalize memory gate claim '{claim_name}' and rollback failed: "
                            f"{rollback.finalization_error}",
                            acquired_lease,
                        ) from error
                if retained_error is not None:
                    _raise_revalidated_retained_error(retained_error)
                if acquired_lease is not None:
                    return acquired_lease

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_available < memory_mib:
                raise MemoryUnavailableError(
                    f"memory gate '{claim_name}' requires {memory_mib} MiB, only {last_available} MiB available"
                )
            raise LockBusyError(f"memory gate '{claim_name}' is held by {last_owner}")
        time.sleep(min(poll_seconds, remaining))


def release(
    claim_name: str,
    owner: str,
    *,
    token: str | None = None,
    lock_directory: Path | None = None,
    cleanup_unreadable: bool = False,
    timeout_seconds: float = DEFAULT_RELEASE_TIMEOUT_SECONDS,
    poll_seconds: float = DEFAULT_GUARD_POLL_SECONDS,
) -> bool:
    """Release a claim only when its owner and lease token both match."""
    _validate_name(owner, "owner")
    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise GateError("timeout_seconds must be finite and non-negative")
    if not math.isfinite(poll_seconds) or poll_seconds <= 0:
        raise GateError("poll_seconds must be finite and positive")
    directory = default_lock_directory() if lock_directory is None else lock_directory
    lock_path = _lock_path(directory, claim_name)
    if not directory.is_dir():
        return False
    guard_descriptor = _acquire_reclaim_guard(lock_path, timeout_seconds, poll_seconds)
    if guard_descriptor is None:
        return False
    try:
        observation = _observe_lock(lock_path, allow_unreadable=cleanup_unreadable)
        if observation is None:
            return False
        record = observation.record
        if not _record_has_required_fields(record):
            return cleanup_unreadable and _unlink_if_observed(
                lock_path,
                observation,
                allow_unreadable=True,
            )
        assert record is not None
        if record.get("owner") != owner:
            return False
        if "token" in record:
            recorded_token = record["token"]
            if not isinstance(recorded_token, str) or _TOKEN.fullmatch(recorded_token) is None:
                return cleanup_unreadable and _unlink_if_observed(
                    lock_path,
                    observation,
                    allow_unreadable=True,
                )
            if (
                not isinstance(token, str)
                or _TOKEN.fullmatch(token) is None
                or not secrets.compare_digest(recorded_token, token)
            ):
                return False
        elif token is not None:
            return False
        return _unlink_if_observed(lock_path, observation)
    finally:
        _release_reclaim_guard(guard_descriptor)


def _parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--claim", metavar="NAME")
    action.add_argument("--release", metavar="NAME")
    parser.add_argument("--memory-mib", type=int, default=0)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--poll-seconds", type=float)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--token")
    parser.add_argument("--cleanup-unreadable", action="store_true")
    parser.add_argument("--exec", dest="command", nargs=argparse.REMAINDER)
    return parser.parse_args(arguments)


def _wait_for_child(child_pid: int) -> int:
    while True:
        try:
            waited_pid, status = os.waitpid(child_pid, 0)
        except InterruptedError:
            continue
        except OSError as error:
            raise GateError(f"cannot wait for gated workload PID {child_pid}: {error}") from error
        if waited_pid == child_pid:
            exit_code = os.waitstatus_to_exitcode(status)
            return 128 - exit_code if exit_code < 0 else exit_code
        raise GateError(f"waitpid returned unexpected PID {waited_pid} for gated workload PID {child_pid}")


def _lease_is_retired(lease: Lease) -> bool:
    observation = _observe_lock(lease.path)
    if observation is None:
        return True
    if (observation.device, observation.inode) != (lease.device, lease.inode):
        return True
    record = observation.record
    if record is not None:
        recorded_token = record.get("token")
        if (
            isinstance(recorded_token, str)
            and _TOKEN.fullmatch(recorded_token) is not None
            and not secrets.compare_digest(recorded_token, lease.token)
        ):
            return True
    return False


def _release_retained_lease(lease: Lease, failure_message: str) -> None:
    """Release a completed lease or preserve its capability on any uncertainty."""
    release_error: BaseException | None = None
    try:
        released = release(
            lease.claim_name,
            lease.owner,
            token=lease.token,
            lock_directory=lease.path.parent,
        )
    except BaseException as error:
        released = False
        release_error = error
    if released:
        return
    try:
        retired = _lease_is_retired(lease)
    except BaseException as error:
        diagnostic = f"{failure_message}; cannot verify retained lease identity: {error}"
        if release_error is not None:
            diagnostic = f"{failure_message}: {release_error}; cannot verify retained lease identity: {error}"
        raise LeaseRetainedError(
            diagnostic,
            lease,
        ) from error
    if retired:
        if release_error is None:
            return
        raise GateError(
            f"{failure_message}: {release_error}; lease is no longer retained"
        ) from release_error
    diagnostic = failure_message if release_error is None else f"{failure_message}: {release_error}"
    raise LeaseRetainedError(diagnostic, lease) from release_error


def _claim_and_exec(args: argparse.Namespace) -> int:
    if not args.command:
        raise GateError("--exec requires a command")
    try:
        read_descriptor, write_descriptor = os.pipe()
    except (AttributeError, OSError) as error:
        raise GateError(f"cannot start gated workload: {error}") from error
    try:
        child_pid = os.fork()
    except (AttributeError, OSError) as error:
        os.close(read_descriptor)
        os.close(write_descriptor)
        raise GateError(f"cannot start gated workload: {error}") from error

    if child_pid == 0:
        os.close(write_descriptor)
        try:
            start = os.read(read_descriptor, 1)
            os.close(read_descriptor)
            if start != b"1":
                os._exit(125)
            os.execvp(args.command[0], args.command)
        except OSError as error:
            message = f"cannot execute {args.command[0]}: {error}\n".encode("utf-8", errors="replace")
            try:
                os.write(sys.stderr.fileno(), message)
            finally:
                os._exit(127)

    try:
        os.close(read_descriptor)
    except OSError as error:
        try:
            os.close(write_descriptor)
        except OSError:
            pass
        try:
            _wait_for_child(child_pid)
        except BaseException as reap_error:
            raise GateError(
                f"cannot close gated workload start pipe: {error}; child reap failed: {reap_error}"
            ) from error
        raise GateError(f"cannot close gated workload start pipe: {error}") from error
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS if args.timeout_seconds is None else args.timeout_seconds
    poll_seconds = DEFAULT_POLL_SECONDS if args.poll_seconds is None else args.poll_seconds
    try:
        lease = claim(
            args.claim,
            args.memory_mib,
            args.owner,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
            pid=child_pid,
        )
    except BaseException as claim_error:
        try:
            os.close(write_descriptor)
        except OSError:
            pass
        try:
            _wait_for_child(child_pid)
        except BaseException as reap_error:
            diagnostic = f"{claim_error}; child reap failed: {reap_error}"
            if isinstance(claim_error, LeaseRetainedError):
                raise LeaseRetainedError(diagnostic, claim_error.lease) from claim_error
            raise GateError(diagnostic) from claim_error
        raise

    try:
        _write_all(write_descriptor, b"1")
    except OSError as error:
        close_error: OSError | None = None
        try:
            os.close(write_descriptor)
        except OSError as pipe_error:
            close_error = pipe_error
        reap_error: BaseException | None = None
        try:
            _wait_for_child(child_pid)
        except BaseException as child_error:
            reap_error = child_error
        diagnostic = f"cannot start gated workload: {error}"
        if close_error is not None:
            diagnostic = f"{diagnostic}; start pipe close failed: {close_error}"
        if reap_error is not None:
            diagnostic = f"{diagnostic}; child reap failed: {reap_error}"
        try:
            _release_retained_lease(
                lease,
                f"{diagnostic}; failed to release memory gate '{lease.claim_name}'",
            )
        except LeaseRetainedError as release_error:
            raise release_error from error
        raise GateError(diagnostic) from error
    else:
        close_error = None
        try:
            os.close(write_descriptor)
        except OSError as error:
            close_error = error

    try:
        child_status = _wait_for_child(child_pid)
    except BaseException as error:
        diagnostic = f"cannot confirm gated workload exit: {error}"
        if close_error is not None:
            diagnostic = f"{diagnostic}; start pipe close failed: {close_error}"
        raise LeaseRetainedError(diagnostic, lease) from error
    _release_retained_lease(
        lease,
        f"failed to release memory gate '{lease.claim_name}' after workload exit",
    )
    if close_error is not None:
        raise GateError(f"cannot close gated workload start pipe: {close_error}") from close_error
    return child_status


def main(arguments: list[str] | None = None) -> int:
    args = _parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        if args.claim is not None:
            if args.memory_mib <= 0:
                raise GateError("--memory-mib must be positive when claiming a gate")
            if args.token is not None:
                raise GateError("--token is valid only when releasing a gate")
            if args.cleanup_unreadable:
                raise GateError("--cleanup-unreadable is valid only when releasing a gate")
            if args.command is not None:
                if args.pid is not None:
                    raise GateError("--pid cannot be combined with --exec")
                return _claim_and_exec(args)
            if args.pid is None:
                raise GateError("--claim requires --pid or --exec so the recorded PID outlives acquisition")
            if not pid_is_alive(args.pid):
                raise GateError(f"--pid {args.pid} is not alive")
            timeout_seconds = DEFAULT_TIMEOUT_SECONDS if args.timeout_seconds is None else args.timeout_seconds
            poll_seconds = DEFAULT_POLL_SECONDS if args.poll_seconds is None else args.poll_seconds
            lease = claim(
                args.claim,
                args.memory_mib,
                args.owner,
                timeout_seconds=timeout_seconds,
                poll_seconds=poll_seconds,
                pid=args.pid,
            )
            print(json.dumps(lease.as_dict(), sort_keys=True))
            return 0
        if args.command is not None or args.pid is not None:
            raise GateError("--pid and --exec are valid only when claiming a gate")
        if args.token is None and not args.cleanup_unreadable:
            raise GateError("--release requires --token")
        timeout_seconds = (
            DEFAULT_RELEASE_TIMEOUT_SECONDS if args.timeout_seconds is None else args.timeout_seconds
        )
        poll_seconds = DEFAULT_GUARD_POLL_SECONDS if args.poll_seconds is None else args.poll_seconds
        if release(
            args.release,
            args.owner,
            token=args.token,
            cleanup_unreadable=args.cleanup_unreadable,
            timeout_seconds=timeout_seconds,
            poll_seconds=poll_seconds,
        ):
            return 0
        print(f"memory gate '{args.release}' is not owned by {args.owner}", file=sys.stderr)
        return 1
    except LeaseRetainedError as error:
        print(json.dumps(error.lease.as_dict(), sort_keys=True))
        print(error, file=sys.stderr)
        return 1
    except GateError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
