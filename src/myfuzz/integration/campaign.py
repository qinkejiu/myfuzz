"""Low-resource process supervision for long-running campaigns.

The supervisor deliberately keeps its state small: it reads one child process's
RSS from procfs, retains only bounded JSON-line metrics, and owns the child's
process group so a resource violation cannot leave a worker behind.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time


_PROC_ROOT = Path("/proc")
_POLL_SECONDS = 0.1
_TERM_GRACE_SECONDS = 0.5
_KILL_GRACE_SECONDS = 0.5
_MAX_STATUS_BYTES = 64 * 1024
_MAX_JSON_LINE_BYTES = 64 * 1024
_MAX_METRICS = 1024
_MAX_DRAIN_BYTES_PER_POLL = 256 * 1024
_METRIC_KEYS = frozenset({"transactions", "protocol", "component", "coverage", "error"})


class CampaignError(RuntimeError):
    """Raised when the campaign cannot be supervised safely."""


def _positive_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _non_negative_integer(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class CampaignLimits:
    """Conservative per-worker RSS limits and the future retry budget."""

    soft_memory_bytes: int = 512 * 1024 * 1024
    hard_memory_bytes: int = 768 * 1024 * 1024
    max_restarts: int = 2

    def __post_init__(self) -> None:
        _positive_integer(self.soft_memory_bytes, "soft_memory_bytes")
        _positive_integer(self.hard_memory_bytes, "hard_memory_bytes")
        _non_negative_integer(self.max_restarts, "max_restarts")
        if self.hard_memory_bytes < self.soft_memory_bytes:
            raise ValueError("hard_memory_bytes must be at least soft_memory_bytes")


@dataclass(frozen=True, slots=True)
class CampaignOptions:
    """Immutable inputs for one supervised command invocation."""

    command: tuple[str, ...]
    output_dir: Path
    duration_seconds: int = 3600
    seed: int = 0
    checkpoint_seconds: int = 30
    limits: CampaignLimits = CampaignLimits()
    env: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.command, tuple) or not self.command:
            raise TypeError("command must be a non-empty tuple of strings")
        if any(not isinstance(argument, str) or not argument for argument in self.command):
            raise TypeError("command must be a non-empty tuple of strings")
        if not isinstance(self.output_dir, Path):
            raise TypeError("output_dir must be a pathlib.Path")
        _positive_integer(self.duration_seconds, "duration_seconds")
        _non_negative_integer(self.seed, "seed")
        _positive_integer(self.checkpoint_seconds, "checkpoint_seconds")
        if not isinstance(self.limits, CampaignLimits):
            raise TypeError("limits must be CampaignLimits")
        if not isinstance(self.env, Mapping):
            raise TypeError("env must be a mapping of strings")
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.env.items()
        ):
            raise TypeError("env must be a mapping of strings")


def read_rss_bytes(pid: int) -> int:
    """Read ``VmRSS`` for *pid*, failing closed on every procfs irregularity."""

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise CampaignError("procfs RSS requires a positive process ID")
    status_path = _PROC_ROOT / str(pid) / "status"
    try:
        payload = status_path.read_bytes()
    except (OSError, ValueError) as error:
        raise CampaignError(f"cannot read procfs RSS status for pid {pid}") from error
    if not payload or len(payload) > _MAX_STATUS_BYTES:
        raise CampaignError(f"procfs RSS status for pid {pid} is unavailable or malformed")
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignError(f"procfs RSS status for pid {pid} is not ASCII") from error

    matches = [line for line in text.splitlines() if line.startswith("VmRSS:")]
    if len(matches) != 1:
        raise CampaignError(f"procfs RSS status for pid {pid} has no unique VmRSS field")
    fields = matches[0].split()
    if len(fields) != 3 or fields[0] != "VmRSS:" or fields[2] != "kB":
        raise CampaignError(f"procfs RSS status for pid {pid} has malformed VmRSS")
    try:
        kilobytes = int(fields[1], 10)
    except ValueError as error:
        raise CampaignError(f"procfs RSS status for pid {pid} has malformed VmRSS") from error
    if kilobytes < 0:
        raise CampaignError(f"procfs RSS status for pid {pid} has negative VmRSS")
    return kilobytes * 1024


class _JsonLineMetrics:
    """Bounded incremental parser for the child's merged stdout/stderr pipe."""

    __slots__ = (
        "buffer",
        "discarding",
        "invalid_line_count",
        "last_output_line",
        "metric_count",
        "metrics",
        "metrics_truncated",
    )

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.discarding = False
        self.invalid_line_count = 0
        self.last_output_line: str | None = None
        self.metric_count = 0
        self.metrics: list[dict[str, object]] = []
        self.metrics_truncated = False

    def feed(self, payload: bytes) -> None:
        cursor = 0
        while cursor < len(payload):
            newline = payload.find(b"\n", cursor)
            if newline < 0:
                self._append_fragment(payload[cursor:])
                return
            self._append_fragment(payload[cursor:newline])
            if not self.discarding:
                self._consume_line(bytes(self.buffer))
            self.buffer.clear()
            self.discarding = False
            cursor = newline + 1

    def finish(self) -> None:
        if self.buffer and not self.discarding:
            self._consume_line(bytes(self.buffer))
        self.buffer.clear()
        self.discarding = False

    def _append_fragment(self, fragment: bytes) -> None:
        if self.discarding:
            return
        if len(self.buffer) + len(fragment) > _MAX_JSON_LINE_BYTES:
            self.buffer.clear()
            self.discarding = True
            return
        self.buffer.extend(fragment)

    def _consume_line(self, payload: bytes) -> None:
        if payload.endswith(b"\r"):
            payload = payload[:-1]
        if not payload:
            return
        try:
            line = payload.decode("utf-8")
            document = json.loads(line)
        except (UnicodeDecodeError, ValueError, RecursionError):
            self.invalid_line_count += 1
            return
        if not isinstance(document, dict) or not any(
            key in _METRIC_KEYS for key in document
        ):
            return
        self.metric_count += 1
        self.last_output_line = line
        if len(self.metrics) < _MAX_METRICS:
            self.metrics.append(document)
        else:
            self.metrics_truncated = True


def _prepare_output_dir(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            raise CampaignError("output_dir must be a directory")
    except OSError as error:
        raise CampaignError(f"cannot create campaign output directory: {path}") from error


def _atomic_write_json(path: Path, document: Mapping[str, object]) -> None:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    except OSError as error:
        raise CampaignError(f"cannot persist campaign checkpoint: {path}") from error
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def _checkpoint_document(
    options: CampaignOptions,
    *,
    status: str,
    pid: int,
    duration_seconds: float,
    peak_rss_bytes: int,
    metrics: _JsonLineMetrics,
    return_code: int | None,
    soft_limit_exceeded: bool,
) -> dict[str, object]:
    return {
        "status": status,
        "seed": options.seed,
        "pid": pid,
        "duration_seconds": duration_seconds,
        "peak_rss_bytes": peak_rss_bytes,
        "return_code": return_code,
        "transactions": sum(
            value
            for document in metrics.metrics
            for value in (document.get("transactions"),)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        ),
        "metric_count": metrics.metric_count,
        "metrics": metrics.metrics,
        "metrics_truncated": metrics.metrics_truncated,
        "invalid_metric_lines": metrics.invalid_line_count,
        "last_output_line": metrics.last_output_line,
        "soft_limit_exceeded": soft_limit_exceeded,
    }


def _group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(process: subprocess.Popen[str], pgid: int) -> str:
    """Terminate the owned process group, escalating from TERM to KILL."""

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return "SIGTERM"
    except OSError as error:
        raise CampaignError(f"cannot send SIGTERM to campaign process group {pgid}") from error

    deadline = time.monotonic() + _TERM_GRACE_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None and not _group_exists(pgid):
            return "SIGTERM"
        time.sleep(0.01)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return "SIGTERM"
    except OSError as error:
        raise CampaignError(f"cannot send SIGKILL to campaign process group {pgid}") from error
    kill_deadline = time.monotonic() + _KILL_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < kill_deadline:
        time.sleep(0.01)
    try:
        process.wait(timeout=max(0.0, kill_deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    return "SIGKILL"


def _read_available_output(
    selector: selectors.BaseSelector,
    metrics: _JsonLineMetrics,
    timeout: float,
) -> int:
    if not selector.get_map():
        time.sleep(max(0.0, timeout))
        return 0
    ready = selector.select(max(0.0, timeout))
    total = 0
    for key, _ in ready:
        descriptor = key.fd
        while total < _MAX_DRAIN_BYTES_PER_POLL:
            try:
                payload = os.read(
                    descriptor,
                    min(64 * 1024, _MAX_DRAIN_BYTES_PER_POLL - total),
                )
            except BlockingIOError:
                break
            except OSError:
                try:
                    selector.unregister(descriptor)
                except (KeyError, ValueError):
                    pass
                break
            if not payload:
                try:
                    selector.unregister(descriptor)
                except (KeyError, ValueError):
                    pass
                break
            total += len(payload)
            metrics.feed(payload)
    if total >= _MAX_DRAIN_BYTES_PER_POLL:
        time.sleep(0.001)
    return total


def _drain_output(
    selector: selectors.BaseSelector,
    metrics: _JsonLineMetrics,
    timeout: float,
) -> None:
    deadline = time.monotonic() + max(0.0, timeout)
    while selector.get_map() and time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if _read_available_output(selector, metrics, remaining) == 0:
            break
    metrics.finish()


def _startup_error(error_type: str, message: str) -> dict[str, object]:
    return {
        "status": "startup-error",
        "error": {"type": error_type, "message": message},
        "return_code": None,
        "returncode": None,
        "duration_seconds": 0.0,
        "peak_rss_bytes": 0,
        "metric_count": 0,
        "metrics": [],
        "metrics_truncated": False,
        "invalid_metric_lines": 0,
        "last_output_line": None,
        "soft_limit_exceeded": False,
        "pid": None,
        "termination_signal": None,
    }


def run_supervised_command(options: CampaignOptions) -> Mapping[str, object]:
    """Run one command in a new process group under a conservative RSS policy."""

    if not isinstance(options, CampaignOptions):
        raise TypeError("options must be CampaignOptions")
    try:
        read_rss_bytes(os.getpid())
    except CampaignError as error:
        return _startup_error("rss-unavailable", str(error))
    try:
        _prepare_output_dir(options.output_dir)
        environment = os.environ.copy()
        environment.update(options.env)
        process = subprocess.Popen(
            options.command,
            env=environment,
            start_new_session=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except (CampaignError, OSError) as error:
        return _startup_error("process-start-failed", str(error))

    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    metrics = _JsonLineMetrics()
    pid = process.pid
    started = time.monotonic()
    peak_rss_bytes = 0
    soft_limit_exceeded = False
    status = "completed"
    termination_signal: str | None = None
    monitor_error: CampaignError | None = None
    error_type: str | None = None
    checkpoint_path = options.output_dir / "checkpoint.json"
    pgid: int | None = None

    try:
        try:
            pgid = os.getpgid(pid)
        except OSError as error:
            raise CampaignError(f"cannot inspect campaign process group {pid}") from error
        if pgid == os.getpgrp():
            raise CampaignError("refusing to supervise a process in the parent process group")
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)

        next_rss_poll = started
        deadline = started + options.duration_seconds
        while True:
            return_code = process.poll()
            now = time.monotonic()
            if return_code is not None:
                _drain_output(selector, metrics, 0.2)
                if return_code != 0:
                    status = "crashed"
                break

            if now >= next_rss_poll:
                try:
                    rss_bytes = read_rss_bytes(pid)
                except CampaignError as error:
                    monitor_error = error
                    status = "startup-error"
                    termination_signal = _terminate_process_group(process, pgid)
                    _drain_output(selector, metrics, 0.2)
                    break
                peak_rss_bytes = max(peak_rss_bytes, rss_bytes)
                soft_limit_exceeded = soft_limit_exceeded or (
                    rss_bytes >= options.limits.soft_memory_bytes
                )
                next_rss_poll = now + _POLL_SECONDS
                if rss_bytes >= options.limits.hard_memory_bytes:
                    status = "resource-terminated"
                    termination_signal = _terminate_process_group(process, pgid)
                    _drain_output(selector, metrics, 0.2)
                    break

            if now >= deadline:
                status = "timed-out"
                termination_signal = _terminate_process_group(process, pgid)
                _drain_output(selector, metrics, 0.2)
                break

            wait_seconds = min(
                _POLL_SECONDS,
                max(0.0, next_rss_poll - time.monotonic()),
                max(0.0, deadline - time.monotonic()),
            )
            _read_available_output(selector, metrics, wait_seconds)

        return_code = process.wait()
    except (CampaignError, OSError) as error:
        monitor_error = (
            error if isinstance(error, CampaignError) else CampaignError(str(error))
        )
        status = "startup-error"
        error_type = "monitor-setup-failed"
        if pgid is not None:
            try:
                termination_signal = _terminate_process_group(process, pgid)
            except CampaignError:
                try:
                    process.kill()
                except OSError:
                    pass
        else:
            try:
                process.kill()
            except OSError:
                pass
        _drain_output(selector, metrics, 0.2)
        return_code = process.wait()
    finally:
        selector.close()
        process.stdout.close()

    duration_seconds = max(0.0, time.monotonic() - started)
    if status in {"resource-terminated", "timed-out", "startup-error"}:
        checkpoint = _checkpoint_document(
            options,
            status=status,
            pid=pid,
            duration_seconds=duration_seconds,
            peak_rss_bytes=peak_rss_bytes,
            metrics=metrics,
            return_code=return_code,
            soft_limit_exceeded=soft_limit_exceeded,
        )
        try:
            _atomic_write_json(checkpoint_path, checkpoint)
        except CampaignError as error:
            if monitor_error is None:
                monitor_error = error

    result: dict[str, object] = {
        "status": status,
        "pid": pid,
        "return_code": return_code,
        "returncode": return_code,
        "duration_seconds": duration_seconds,
        "peak_rss_bytes": peak_rss_bytes,
        "soft_limit_exceeded": soft_limit_exceeded,
        "metric_count": metrics.metric_count,
        "metrics": metrics.metrics,
        "metrics_truncated": metrics.metrics_truncated,
        "invalid_metric_lines": metrics.invalid_line_count,
        "last_output_line": metrics.last_output_line,
        "termination_signal": termination_signal,
        "checkpoint_path": str(checkpoint_path)
        if checkpoint_path.is_file()
        else None,
    }
    if monitor_error is not None:
        result["error"] = {
            "type": error_type
            if error_type is not None
            else ("rss-unavailable" if status == "startup-error" else "supervisor-error"),
            "message": str(monitor_error),
        }
    return result


__all__ = [
    "CampaignError",
    "CampaignLimits",
    "CampaignOptions",
    "read_rss_bytes",
    "run_supervised_command",
]
