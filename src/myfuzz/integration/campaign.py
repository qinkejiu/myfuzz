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
import time

from .campaign_report import (
    CampaignReportError,
    CampaignState,
    build_campaign_report,
    publish_campaign_report,
    write_checkpoint,
)


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
    composition_hash: str | None = None

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
        if self.composition_hash is not None and (
            not isinstance(self.composition_hash, str) or not self.composition_hash
        ):
            raise TypeError("composition_hash must be a non-empty string or None")


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
        "state",
    )

    def __init__(self, state: CampaignState | None = None) -> None:
        self.buffer = bytearray()
        self.discarding = False
        self.invalid_line_count = 0
        self.last_output_line: str | None = None
        self.metric_count = 0
        self.metrics: list[dict[str, object]] = []
        self.metrics_truncated = False
        self.state = state

    def feed(self, payload: bytes) -> None:
        cursor = 0
        while cursor < len(payload):
            newline = payload.find(b"\n", cursor)
            if newline < 0:
                self._append_fragment(payload[cursor:])
                return
            was_discarding = self.discarding
            self._append_fragment(payload[cursor:newline])
            if was_discarding or self.discarding:
                self.invalid_line_count += 1
                if self.state is not None:
                    self.state.record_error()
            else:
                self._consume_line(bytes(self.buffer))
            self.buffer.clear()
            self.discarding = False
            cursor = newline + 1

    def finish(self) -> None:
        if self.buffer and self.discarding:
            self.invalid_line_count += 1
            if self.state is not None:
                self.state.record_error()
        elif self.buffer:
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
            if self.state is not None:
                self.state.record_error()
            return
        if not isinstance(document, dict) or not any(
            key in _METRIC_KEYS for key in document
        ):
            return
        self.metric_count += 1
        self.last_output_line = line
        if self.state is not None:
            self.state.record_metric(document, line)
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


def _verify_process_group_support() -> None:
    """Fail closed before launch when this host cannot own a process group."""

    if os.name != "posix" or not all(
        callable(getattr(os, name, None)) for name in ("getpgid", "getpgrp", "killpg")
    ):
        raise CampaignError("process-group supervision is unavailable")
    try:
        current_pid = os.getpid()
        current_pgid = os.getpgid(current_pid)
        if current_pgid != os.getpgrp() or current_pgid <= 0:
            raise CampaignError("cannot verify the parent process group")
        os.killpg(current_pgid, 0)
    except CampaignError:
        raise
    except OSError as error:
        raise CampaignError("cannot verify process-group supervision") from error


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
        _verify_process_group_support()
    except CampaignError as error:
        return _startup_error("process-group-unavailable", str(error))
    try:
        _prepare_output_dir(options.output_dir)
        report_path = options.output_dir / "report.json"
        report_path.unlink(missing_ok=True)
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
    selector: selectors.BaseSelector | None = None
    pid = process.pid
    started = time.monotonic()
    state = CampaignState(
        seed=options.seed,
        composition_hash=options.composition_hash,
    )
    metrics = _JsonLineMetrics(state)
    peak_rss_bytes = 0
    soft_limit_exceeded = False
    status = "completed"
    termination_signal: str | None = None
    monitor_error: CampaignError | CampaignReportError | None = None
    error_type: str | None = None
    checkpoint_path = options.output_dir / "checkpoint.json"
    pgid: int | None = None

    def persist_checkpoint(current_status: str, duration: float) -> None:
        state.status = current_status
        state.duration_seconds = max(0.0, duration)
        state.peak_rss_bytes = peak_rss_bytes
        try:
            write_checkpoint(checkpoint_path, state)
        except CampaignReportError as error:
            raise CampaignError(str(error)) from error

    try:
        try:
            # start_new_session makes the child PID the process-group ID.  Keep
            # that safe fallback if a transient procfs lookup races process
            # startup so cleanup still targets the owned group.
            pgid = pid
            observed_pgid = os.getpgid(pid)
            if observed_pgid != pid:
                raise CampaignError("child did not enter an independent process group")
            pgid = observed_pgid
        except OSError as error:
            raise CampaignError(f"cannot inspect campaign process group {pid}") from error
        if pgid == os.getpgrp():
            raise CampaignError("refusing to supervise a process in the parent process group")
        selector = selectors.DefaultSelector()
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)

        next_rss_poll = started
        next_checkpoint = started + options.checkpoint_seconds
        deadline = started + options.duration_seconds
        while True:
            return_code = process.poll()
            now = time.monotonic()
            if return_code is not None:
                return_code = process.wait()
                if return_code != 0:
                    status = "crashed"
                if pgid is not None and _group_exists(pgid):
                    termination_signal = _terminate_process_group(process, pgid)
                if selector is not None:
                    _drain_output(selector, metrics, 0.2)
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
            now = time.monotonic()
            if now >= next_checkpoint:
                persist_checkpoint("running", now - started)
                while next_checkpoint <= now:
                    next_checkpoint += options.checkpoint_seconds

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
        if selector is not None:
            _drain_output(selector, metrics, 0.2)
        return_code = process.wait()
    except BaseException:
        # KeyboardInterrupt and parent-side shutdowns must not leave an owned
        # child group running after the monitoring stack unwinds.  Preserve the
        # original exception after best-effort group termination and reaping.
        try:
            if pgid is not None and _group_exists(pgid):
                _terminate_process_group(process, pgid)
            elif process.poll() is None:
                process.kill()
        except (CampaignError, OSError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait()
        except OSError:
            pass
        raise
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()

    duration_seconds = max(0.0, time.monotonic() - started)
    checkpoint_published = False
    try:
        persist_checkpoint(status, duration_seconds)
        checkpoint_published = True
    except CampaignError as error:
        if monitor_error is None:
            monitor_error = error
            error_type = "checkpoint-publish-failed"

    report_published = False
    if status in {"completed", "crashed", "resource-terminated"} and checkpoint_published:
        replay_command = options.command if status == "crashed" else None
        try:
            report = build_campaign_report(
                options,
                state,
                status,
                replay_command,
            )
            publish_campaign_report(report_path, report)
            report_published = True
        except CampaignReportError as error:
            if monitor_error is None:
                monitor_error = error
                error_type = "report-publish-failed"

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
        "report_path": str(report_path) if report_published else None,
        "iterations": state.iterations,
        "transactions": state.transactions,
        "protocol_transactions": dict(sorted(state.protocol_transactions.items())),
        "component_transactions": dict(sorted(state.component_transactions.items())),
        "coverage": sorted(state.coverage),
        "errors": state.errors,
        "checkpoint_count": state.checkpoint_count,
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
