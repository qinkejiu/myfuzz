"""Process-shared, bounded memory-token accounting for integration jobs."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import json
import math
import os
from pathlib import Path
import resource
import secrets
import stat
import threading
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - integration hosts are Unix/Linux.
    fcntl = None  # type: ignore[assignment]


_STATE_VERSION = 1
_MAX_STATE_BYTES = 128 * 1024
_MAX_HISTORY = 32
_POLL_SECONDS = 0.02
_VALID_HISTORY_STATUSES = frozenset(("released", "failed", "reclaimed"))


def _peak_rss_bytes() -> int:
    own = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    # Linux reports KiB. The integration runtime is Linux-only because it uses
    # flock and /proc identity checks.
    return max(1, int(max(own, children)) * 1024)


def _process_identity(pid: int) -> tuple[str, int] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    closing = text.rfind(")")
    if closing < 0:
        return None
    fields = text[closing + 2 :].split()
    try:
        return fields[0], int(fields[19])
    except (IndexError, ValueError):
        return None


def _process_start_ticks(pid: int) -> int | None:
    identity = _process_identity(pid)
    return None if identity is None else identity[1]


def _pid_matches(pid: int, expected_start: int | None) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        return error.errno == errno.EPERM
    identity = _process_identity(pid)
    if identity is not None and identity[0] in {"Z", "X"}:
        return False
    if expected_start is None or identity is None:
        return True
    return identity[1] == expected_start


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise RuntimeError("memory token state write made no progress")
        offset += written


@dataclass(frozen=True, slots=True)
class TokenLease:
    task_id: str
    estimate_bytes: int
    exclusive_build: bool
    token: str
    acquired_at: float
    _pool: "MemoryTokenPool" = field(repr=False, compare=False)

    def __enter__(self) -> "TokenLease":
        return self

    def __exit__(self, error_type: object, _value: object, _traceback: object) -> None:
        self._pool._release(self, "failed" if error_type is not None else "released")


class MemoryTokenPool:
    """Coordinate memory estimates and exclusive builds through one state file."""

    def __init__(self, soft_limit_bytes: int, hard_limit_bytes: int, state_path: Path) -> None:
        if (
            isinstance(soft_limit_bytes, bool)
            or not isinstance(soft_limit_bytes, int)
            or soft_limit_bytes <= 0
        ):
            raise ValueError("soft_limit_bytes must be positive")
        if (
            isinstance(hard_limit_bytes, bool)
            or not isinstance(hard_limit_bytes, int)
            or hard_limit_bytes <= 0
        ):
            raise ValueError("hard_limit_bytes must be positive")
        if soft_limit_bytes > hard_limit_bytes:
            raise ValueError("soft_limit_bytes must not exceed hard_limit_bytes")
        if not isinstance(state_path, Path):
            raise TypeError("state_path must be a pathlib.Path")
        if fcntl is None:  # pragma: no cover - guarded by the supported host.
            raise RuntimeError("memory token state requires fcntl")

        self.soft_limit_bytes = soft_limit_bytes
        self.hard_limit_bytes = hard_limit_bytes
        self.state_path = state_path.absolute()
        self._lock_path = self.state_path.with_name(f".{self.state_path.name}.lock")
        self._condition = threading.Condition()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

        with self._condition, self._locked_state_file():
            state, created = self._read_state_locked()
            reclaimed = self._reclaim_stale(state)
            if created or reclaimed:
                self._write_state_locked(state)

    def acquire(
        self,
        task_id: str,
        estimate_bytes: int,
        *,
        exclusive_build: bool = False,
        wait_timeout: float = 0.0,
    ) -> TokenLease:
        self._validate_acquire(task_id, estimate_bytes, exclusive_build, wait_timeout)
        if estimate_bytes > self.hard_limit_bytes:
            raise MemoryError("estimate exceeds hard memory limit")

        timeout = float(wait_timeout)
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                lease = self._try_acquire(task_id, estimate_bytes, exclusive_build)
                if lease is not None:
                    return lease
                remaining = deadline - time.monotonic()
                if timeout == 0:
                    raise MemoryError(f"memory token unavailable for {task_id}")
                if remaining <= 0:
                    raise TimeoutError(f"memory token unavailable for {task_id}")
                self._condition.wait(timeout=min(remaining, _POLL_SECONDS))

    def release(self, lease: TokenLease) -> None:
        self._release(lease, "released")

    def snapshot(self) -> dict[str, object]:
        with self._condition, self._locked_state_file():
            state, created = self._read_state_locked()
            reclaimed = self._reclaim_stale(state)
            if created or reclaimed:
                self._write_state_locked(state)
            return self._public_snapshot(state)

    @contextmanager
    def lease(
        self,
        task_id: str,
        estimate_bytes: int,
        *,
        exclusive_build: bool = False,
        wait_timeout: float = 0.0,
    ) -> Iterator[TokenLease]:
        token = self.acquire(
            task_id,
            estimate_bytes,
            exclusive_build=exclusive_build,
            wait_timeout=wait_timeout,
        )
        try:
            yield token
        except BaseException:
            self._release(token, "failed")
            raise
        else:
            self._release(token, "released")

    def _validate_acquire(
        self,
        task_id: str,
        estimate_bytes: int,
        exclusive_build: bool,
        wait_timeout: float,
    ) -> None:
        if not isinstance(task_id, str) or not task_id or len(task_id.encode("utf-8")) > 1024:
            raise ValueError("task_id must be a bounded non-empty string")
        if (
            isinstance(estimate_bytes, bool)
            or not isinstance(estimate_bytes, int)
            or estimate_bytes <= 0
        ):
            raise ValueError("estimate_bytes must be positive")
        if not isinstance(exclusive_build, bool):
            raise TypeError("exclusive_build must be bool")
        if (
            isinstance(wait_timeout, bool)
            or not isinstance(wait_timeout, (int, float))
            or not math.isfinite(wait_timeout)
            or wait_timeout < 0
        ):
            raise ValueError("wait_timeout must be finite and non-negative")

    def _try_acquire(
        self,
        task_id: str,
        estimate_bytes: int,
        exclusive_build: bool,
    ) -> TokenLease | None:
        with self._locked_state_file():
            state, created = self._read_state_locked()
            reclaimed = self._reclaim_stale(state)
            leases = state["leases"]
            assert isinstance(leases, list)
            active_bytes = state["active_bytes"]
            active_builds = state["active_builds"]
            assert isinstance(active_bytes, int) and isinstance(active_builds, int)
            unavailable = (
                active_bytes + estimate_bytes > self.soft_limit_bytes
                or active_builds > 0
                or (exclusive_build and bool(leases))
            )
            if unavailable:
                if created or reclaimed:
                    self._write_state_locked(state)
                return None

            acquired_at = time.time()
            token = secrets.token_hex(16)
            peak_rss = _peak_rss_bytes()
            record: dict[str, object] = {
                "task_id": task_id,
                "estimate_bytes": estimate_bytes,
                "exclusive_build": exclusive_build,
                "token": token,
                "acquired_at": acquired_at,
                "pid": os.getpid(),
                "process_start_ticks": _process_start_ticks(os.getpid()),
                "peak_rss_bytes": peak_rss,
            }
            leases.append(record)
            state["active_bytes"] = active_bytes + estimate_bytes
            state["active_builds"] = active_builds + int(exclusive_build)
            state["max_active_builds"] = max(
                int(state["max_active_builds"]),
                int(state["active_builds"]),
            )
            self._write_state_locked(state)
            return TokenLease(
                task_id,
                estimate_bytes,
                exclusive_build,
                token,
                acquired_at,
                self,
            )

    def _release(self, lease: TokenLease, status: str) -> None:
        if not isinstance(lease, TokenLease) or lease._pool is not self:
            raise ValueError("lease does not belong to this pool")
        if status not in _VALID_HISTORY_STATUSES - {"reclaimed"}:
            raise ValueError("invalid lease status")
        with self._condition:
            try:
                with self._locked_state_file():
                    state, _created = self._read_state_locked()
                    self._reclaim_stale(state)
                    leases = state["leases"]
                    assert isinstance(leases, list)
                    match_index: int | None = None
                    match: Mapping[str, object] | None = None
                    for index, record in enumerate(leases):
                        assert isinstance(record, Mapping)
                        if record["token"] == lease.token:
                            match_index = index
                            match = record
                            break
                    if (
                        match_index is None
                        or match is None
                        or not self._lease_matches(match, lease)
                    ):
                        raise ValueError("lease is unknown or already released")
                    leases.pop(match_index)
                    state["active_bytes"] = int(state["active_bytes"]) - lease.estimate_bytes
                    state["active_builds"] = int(state["active_builds"]) - int(
                        lease.exclusive_build
                    )
                    self._append_history(
                        state,
                        match,
                        status,
                        max(int(match["peak_rss_bytes"]), _peak_rss_bytes()),
                    )
                    self._write_state_locked(state)
            finally:
                self._condition.notify_all()

    @staticmethod
    def _lease_matches(record: Mapping[str, object], lease: TokenLease) -> bool:
        recorded_start = record.get("process_start_ticks")
        current_start = _process_start_ticks(os.getpid())
        return (
            record.get("task_id") == lease.task_id
            and record.get("estimate_bytes") == lease.estimate_bytes
            and record.get("exclusive_build") is lease.exclusive_build
            and record.get("acquired_at") == lease.acquired_at
            and record.get("pid") == os.getpid()
            and (
                recorded_start is None
                or current_start is None
                or recorded_start == current_start
            )
        )

    def _initial_state(self) -> dict[str, object]:
        return {
            "version": _STATE_VERSION,
            "soft_limit_bytes": self.soft_limit_bytes,
            "hard_limit_bytes": self.hard_limit_bytes,
            "active_bytes": 0,
            "active_builds": 0,
            "max_active_builds": 0,
            "leases": [],
            "history": [],
        }

    @contextmanager
    def _locked_state_file(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._lock_path, flags, 0o600)
        except OSError as error:
            raise RuntimeError("cannot open memory token state lock") from error
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RuntimeError("memory token state lock must be a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _read_state_locked(self) -> tuple[dict[str, object], bool]:
        try:
            metadata = self.state_path.lstat()
        except FileNotFoundError:
            return self._initial_state(), True
        except OSError as error:
            raise RuntimeError("cannot inspect memory token state") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("memory token state must be a regular file")
        if metadata.st_size > _MAX_STATE_BYTES:
            raise RuntimeError("memory token state exceeds size limit")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.state_path, flags)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise RuntimeError("memory token state must be a regular file")
                payload = bytearray()
                while len(payload) <= _MAX_STATE_BYTES:
                    chunk = os.read(descriptor, min(65536, _MAX_STATE_BYTES + 1 - len(payload)))
                    if not chunk:
                        break
                    payload.extend(chunk)
            finally:
                os.close(descriptor)
        except RuntimeError:
            raise
        except OSError as error:
            raise RuntimeError("cannot read memory token state") from error
        if len(payload) > _MAX_STATE_BYTES:
            raise RuntimeError("memory token state exceeds size limit")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("memory token state is invalid JSON") from error
        return self._validate_state(decoded), False

    def _validate_state(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise RuntimeError("memory token state must be an object")
        if value.get("version") != _STATE_VERSION:
            raise RuntimeError("memory token state version is unsupported")
        if (
            value.get("soft_limit_bytes") != self.soft_limit_bytes
            or value.get("hard_limit_bytes") != self.hard_limit_bytes
        ):
            raise ValueError("memory token state limits do not match pool limits")
        for key in ("active_bytes", "active_builds", "max_active_builds"):
            item = value.get(key)
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise RuntimeError(f"memory token state {key} is invalid")
        leases = value.get("leases")
        history = value.get("history")
        if (
            not isinstance(leases, list)
            or not isinstance(history, list)
            or len(history) > _MAX_HISTORY
        ):
            raise RuntimeError("memory token state lease/history arrays are invalid")

        tokens: set[str] = set()
        total_bytes = 0
        total_builds = 0
        for record in leases:
            self._validate_lease_record(record)
            assert isinstance(record, dict)
            token = record["token"]
            assert isinstance(token, str)
            if token in tokens:
                raise RuntimeError("memory token state contains duplicate leases")
            tokens.add(token)
            total_bytes += int(record["estimate_bytes"])
            total_builds += int(bool(record["exclusive_build"]))
        if total_bytes != value["active_bytes"] or total_builds != value["active_builds"]:
            raise RuntimeError("memory token state counters do not match leases")
        if total_bytes > self.soft_limit_bytes or total_builds > 1:
            raise RuntimeError("memory token state exceeds pool capacity")
        if int(value["max_active_builds"]) < total_builds:
            raise RuntimeError("memory token state maximum is invalid")
        for record in history:
            self._validate_history_record(record)
        return value

    @staticmethod
    def _validate_lease_record(value: object) -> None:
        if not isinstance(value, dict):
            raise RuntimeError("memory token state lease is invalid")
        task_id = value.get("task_id")
        estimate = value.get("estimate_bytes")
        exclusive = value.get("exclusive_build")
        token = value.get("token")
        acquired = value.get("acquired_at")
        pid = value.get("pid")
        start = value.get("process_start_ticks")
        peak = value.get("peak_rss_bytes")
        if not isinstance(task_id, str) or not task_id:
            raise RuntimeError("memory token state lease task is invalid")
        if isinstance(estimate, bool) or not isinstance(estimate, int) or estimate <= 0:
            raise RuntimeError("memory token state lease estimate is invalid")
        if not isinstance(exclusive, bool):
            raise RuntimeError("memory token state lease exclusivity is invalid")
        if (
            not isinstance(token, str)
            or len(token) != 32
            or any(character not in "0123456789abcdef" for character in token)
        ):
            raise RuntimeError("memory token state lease token is invalid")
        if (
            not isinstance(acquired, (int, float))
            or isinstance(acquired, bool)
            or not math.isfinite(acquired)
        ):
            raise RuntimeError("memory token state lease timestamp is invalid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise RuntimeError("memory token state lease pid is invalid")
        if start is not None and (
            isinstance(start, bool) or not isinstance(start, int) or start <= 0
        ):
            raise RuntimeError("memory token state lease process identity is invalid")
        if isinstance(peak, bool) or not isinstance(peak, int) or peak <= 0:
            raise RuntimeError("memory token state lease peak RSS is invalid")

    @staticmethod
    def _validate_history_record(value: object) -> None:
        if not isinstance(value, dict):
            raise RuntimeError("memory token state history is invalid")
        if value.get("status") not in _VALID_HISTORY_STATUSES:
            raise RuntimeError("memory token state history status is invalid")
        for key in ("task_id",):
            if not isinstance(value.get(key), str) or not value[key]:
                raise RuntimeError("memory token state history task is invalid")
        for key in ("estimate_bytes", "peak_rss_bytes"):
            item = value.get(key)
            if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
                raise RuntimeError("memory token state history counter is invalid")
        if not isinstance(value.get("exclusive_build"), bool):
            raise RuntimeError("memory token state history exclusivity is invalid")
        for key in ("acquired_at", "released_at"):
            item = value.get(key)
            if (
                not isinstance(item, (int, float))
                or isinstance(item, bool)
                or not math.isfinite(item)
            ):
                raise RuntimeError("memory token state history timestamp is invalid")

    def _reclaim_stale(self, state: dict[str, object]) -> bool:
        leases = state["leases"]
        assert isinstance(leases, list)
        retained: list[dict[str, object]] = []
        changed = False
        for value in leases:
            assert isinstance(value, dict)
            pid = int(value["pid"])
            start = value["process_start_ticks"]
            assert start is None or isinstance(start, int)
            if _pid_matches(pid, start):
                retained.append(value)
                continue
            changed = True
            self._append_history(state, value, "reclaimed", int(value["peak_rss_bytes"]))
        if changed:
            state["leases"] = retained
            state["active_bytes"] = sum(int(record["estimate_bytes"]) for record in retained)
            state["active_builds"] = sum(
                int(bool(record["exclusive_build"])) for record in retained
            )
        return changed

    @staticmethod
    def _append_history(
        state: dict[str, object],
        record: Mapping[str, object],
        status: str,
        peak_rss_bytes: int,
    ) -> None:
        history = state["history"]
        assert isinstance(history, list)
        history.append(
            {
                "task_id": record["task_id"],
                "estimate_bytes": record["estimate_bytes"],
                "exclusive_build": record["exclusive_build"],
                "acquired_at": record["acquired_at"],
                "released_at": time.time(),
                "peak_rss_bytes": peak_rss_bytes,
                "status": status,
            }
        )
        del history[:-_MAX_HISTORY]

    def _write_state_locked(self, state: Mapping[str, object]) -> None:
        payload = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > _MAX_STATE_BYTES:
            raise RuntimeError("memory token state exceeds size limit")
        temporary = self.state_path.with_name(f".{self.state_path.name}.{secrets.token_hex(8)}.tmp")
        descriptor: int | None = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, self.state_path)
            try:
                directory = os.open(
                    self.state_path.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
            except OSError:
                # The file has already been atomically published. Raising here
                # would strand an active lease without returning its capability.
                return
            try:
                try:
                    os.fsync(directory)
                except OSError:
                    # File visibility is committed even when crash-durability of
                    # the directory entry cannot be confirmed on this host.
                    pass
            finally:
                try:
                    os.close(directory)
                except OSError:
                    pass
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _public_snapshot(state: Mapping[str, object]) -> dict[str, object]:
        leases = state["leases"]
        history = state["history"]
        assert isinstance(leases, list) and isinstance(history, list)
        return {
            "soft_limit_bytes": state["soft_limit_bytes"],
            "hard_limit_bytes": state["hard_limit_bytes"],
            "active_bytes": state["active_bytes"],
            "active_builds": state["active_builds"],
            "max_active_builds": state["max_active_builds"],
            "leases": [
                {
                    "task_id": record["task_id"],
                    "estimate_bytes": record["estimate_bytes"],
                    "exclusive_build": record["exclusive_build"],
                    "acquired_at": record["acquired_at"],
                    "peak_rss_bytes": record["peak_rss_bytes"],
                }
                for record in leases
                if isinstance(record, Mapping)
            ],
            "history": [dict(record) for record in history if isinstance(record, Mapping)],
        }
