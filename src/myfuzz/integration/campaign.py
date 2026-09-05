"""Low-resource process supervision for long-running campaigns.

The supervisor deliberately keeps its state small: it reads one child process's
RSS from procfs, retains only bounded JSON-line metrics, and owns the child's
process group so a resource violation cannot leave a worker behind.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import shlex
import shutil
import subprocess
import sys
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

    selector: selectors.BaseSelector | None = None
    pgid: int | None = None

    try:
        pid = process.pid
        # start_new_session makes the child PID the process-group ID. Record
        # that safe fallback before any further post-launch initialization so
        # parent-side shutdowns can always target the owned group.
        pgid = pid
        assert process.stdout is not None
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
                # Keep the recorded PID fallback if a transient procfs lookup
                # races process startup so cleanup still targets the owned group.
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
        # child group running after any post-launch initialization or
        # monitoring stack unwinds. Preserve the original exception after
        # best-effort group termination and reaping.
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


_IBEX_CAMPAIGN_SCHEMA = "ibex_campaign.v1"
_IBEX_SOURCE_LIST = "third_party/rfuzz/upstream/ibex/sources.f"
_IBEX_CAMPAIGN_DEFAULT_OUTPUT = "runs/ibex_protocol_campaign"
_IBEX_SOFT_MEMORY_CEILING = 512 * 1024 * 1024
_IBEX_HARD_MEMORY_CEILING = 768 * 1024 * 1024
_IBEX_TOKEN_MEMORY_CEILING = 64 * 1024 * 1024
_IBEX_COMMAND_MODES = frozenset({"real", "local-smoke"})
_IBEX_HDL_SUFFIXES = frozenset({".sv", ".v", ".svh", ".vh"})
_IBEX_SOURCE_LIST_MAX_BYTES = 4 * 1024 * 1024
_IBEX_SOURCE_FILE_MAX_BYTES = 32 * 1024 * 1024
_IBEX_MAX_NESTED_SOURCE_LISTS = 256
_IBEX_CAMPAIGN_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "design_config",
        "composition_manifest",
        "source_list",
        "duration_seconds",
        "checkpoint_seconds",
        "seed",
        "workers",
        "build_jobs",
        "waveforms",
        "soft_memory_bytes",
        "hard_memory_bytes",
        "token_bytes",
    }
)
_IBEX_CAMPAIGN_ALLOWED_KEYS = _IBEX_CAMPAIGN_REQUIRED_KEYS | frozenset(
    {
        "description",
        "output_dir",
        "max_restarts",
        "command_mode",
        "vcd",
    }
)


class _DuplicateCampaignJsonKey(ValueError):
    """Raised when a campaign document repeats a JSON object key."""


def _reject_duplicate_campaign_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _DuplicateCampaignJsonKey(key)
        document[key] = value
    return document


def _campaign_repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read_campaign_json(path: Path, label: str) -> dict[str, object]:
    try:
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_campaign_json_keys,
        )
    except _DuplicateCampaignJsonKey as error:
        raise ValueError(f"{label}:duplicate-key:{error}") from error
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label}:read-failed:{error}") from error
    if not isinstance(raw, dict):
        raise ValueError(f"{label}:object-required")
    return raw


def _resolve_campaign_path(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"{label}:path-required")
    candidate = Path(value)
    resolved_root = Path(root).resolve()
    resolved = (candidate if candidate.is_absolute() else resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError(f"{label}:outside-repository-root") from error
    return resolved


def _validate_campaign_integer(
    document: Mapping[str, object],
    key: str,
    *,
    positive: bool = False,
) -> int:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if positive and value <= 0:
        raise ValueError(f"{key} must be positive")
    if not positive and value < 0:
        raise ValueError(f"{key} must be non-negative")
    return value


@dataclass(frozen=True, slots=True)
class _IbexCampaignConfig:
    """Validated paths and low-resource values for one Ibex campaign."""

    root: Path
    config_path: Path
    design_config: Path
    composition_manifest: Path
    source_list: Path
    candidate_manifest: Path
    output_dir: Path
    duration_seconds: int
    checkpoint_seconds: int
    seed: int
    workers: int
    build_jobs: int
    waveforms: bool
    vcd: bool
    soft_memory_bytes: int
    hard_memory_bytes: int
    token_bytes: int
    max_restarts: int
    command_mode: str
    document: Mapping[str, object]


def _validate_design_flow_config(
    root: Path,
    path: Path,
    composition_manifest: Path,
    source_list: Path,
) -> None:
    document = _read_campaign_json(path, "design_config")
    required = {
        "top",
        "project_root",
        "flist",
        "out_dir",
        "composition",
        "candidate_manifest",
        "harness",
    }
    missing = sorted(required - set(document))
    if missing:
        raise ValueError(f"design_config:missing-field:{missing[0]}")
    if document.get("top") != "ibex_protocol_composition_top":
        raise ValueError("design_config.top must be ibex_protocol_composition_top")
    _resolve_campaign_path(root, document.get("out_dir"), "design_config.out_dir")
    project_root = _resolve_campaign_path(root, document.get("project_root"), "design_config.project_root")
    raw_flist = document.get("flist")
    if raw_flist != _IBEX_SOURCE_LIST:
        raise ValueError("design_config.flist must match fixed source_list")
    flist = _resolve_campaign_path(root, raw_flist, "design_config.flist")
    if flist != source_list:
        raise ValueError("design_config.flist must match source_list")
    if project_root == root:
        raise ValueError("design_config.project_root must identify the Ibex checkout")

    candidate_manifest = _resolve_campaign_path(
        root,
        document.get("candidate_manifest"),
        "design_config.candidate_manifest",
    )
    if not candidate_manifest.is_file():
        raise ValueError(f"design_config.candidate_manifest:missing-file:{candidate_manifest}")
    candidate_document = _read_campaign_json(candidate_manifest, "candidate_manifest")
    if candidate_document.get("schema_version") != "candidate_manifest.v1":
        raise ValueError("design_config.candidate_manifest.schema_version:unsupported")
    if not isinstance(candidate_document.get("top_port_abi"), list):
        raise ValueError("design_config.candidate_manifest.top_port_abi:array-required")
    if not isinstance(candidate_document.get("coverage_universe"), list):
        raise ValueError("design_config.candidate_manifest.coverage_universe:array-required")

    harness = document.get("harness")
    if not isinstance(harness, Mapping):
        raise ValueError("design_config.harness must be an object")
    manual_harness = harness.get("manual_harness")
    if not isinstance(manual_harness, str) or not manual_harness or "\0" in manual_harness:
        raise ValueError("design_config.harness.manual_harness:path-required")
    manual_harness_path = _resolve_campaign_path(
        root,
        manual_harness,
        "design_config.harness.manual_harness",
    )
    if not manual_harness_path.is_file():
        raise ValueError(
            f"design_config.harness.manual_harness:missing-file:{manual_harness_path}"
        )
    raw_width = harness.get("raw_width")
    if isinstance(raw_width, bool) or not isinstance(raw_width, int) or raw_width != 395:
        raise ValueError("design_config.harness.raw_width must be 395")
    for key in ("manual_harness_module", "manual_harness_input"):
        value = harness.get(key)
        if not isinstance(value, str) or not value or not value.replace("_", "a").isalnum():
            raise ValueError(f"design_config.harness.{key}:identifier-required")

    composition = document.get("composition")
    if not isinstance(composition, Mapping):
        raise ValueError("design_config.composition must be an object")
    allowed_composition = {"kind", "manifest", "protocol_manifest", "out_dir"}
    unknown = sorted(set(composition) - allowed_composition)
    if unknown:
        raise ValueError(f"design_config.composition:configuration-mixed:{unknown[0]}")
    if composition.get("kind") != "protocol_composition":
        raise ValueError("design_config.composition.kind must be protocol_composition")
    manifest_keys = [key for key in ("manifest", "protocol_manifest") if key in composition]
    if len(manifest_keys) != 1:
        raise ValueError("design_config.composition:configuration-mixed")
    if "out_dir" in composition:
        _resolve_campaign_path(root, composition["out_dir"], "design_config.composition.out_dir")
    manifest_path = _resolve_campaign_path(
        root,
        composition[manifest_keys[0]],
        "design_config.composition.manifest",
    )
    if manifest_path != composition_manifest:
        raise ValueError("design_config.composition.manifest must match composition_manifest")

    fuzz = document.get("fuzz", {})
    if fuzz is not None and not isinstance(fuzz, Mapping):
        raise ValueError("design_config.fuzz must be an object")
    if isinstance(fuzz, Mapping):
        server_count = fuzz.get("server_count", 1)
        if isinstance(server_count, bool) or not isinstance(server_count, int) or server_count != 1:
            raise ValueError("design_config.fuzz.server_count must be 1")
    server = document.get("server", {})
    if server is not None and not isinstance(server, Mapping):
        raise ValueError("design_config.server must be an object")
    if isinstance(server, Mapping) and server.get("parallel_verilator_build", False) is not False:
        raise ValueError("design_config.server.parallel_verilator_build must be false")
    for key in ("waveforms", "vcd"):
        if key in document and document[key] is not False:
            raise ValueError(f"design_config.{key} must be false")


def _parse_ibex_campaign_config(
    config_path: Path,
    *,
    root: Path,
) -> _IbexCampaignConfig:
    checkout_root = Path(root).resolve()
    path = _resolve_campaign_path(checkout_root, str(config_path), "campaign_config")
    document = _read_campaign_json(path, "campaign_config")
    missing = sorted(_IBEX_CAMPAIGN_REQUIRED_KEYS - set(document))
    if missing:
        raise ValueError(f"campaign_config:missing-field:{missing[0]}")
    if "command" in document or "local_smoke" in document:
        raise ValueError("campaign_config:configuration-mixed")
    unknown = sorted(set(document) - _IBEX_CAMPAIGN_ALLOWED_KEYS)
    if unknown:
        raise ValueError(f"campaign_config:unknown-field:{unknown[0]}")
    if document.get("schema_version") != _IBEX_CAMPAIGN_SCHEMA:
        raise ValueError("campaign_config.schema_version:unsupported")

    duration_seconds = _validate_campaign_integer(document, "duration_seconds", positive=True)
    checkpoint_seconds = _validate_campaign_integer(document, "checkpoint_seconds", positive=True)
    seed = _validate_campaign_integer(document, "seed")
    if seed > 0xFFFF_FFFF:
        raise ValueError("seed must be at most 4294967295")
    workers = _validate_campaign_integer(document, "workers", positive=True)
    if workers != 1:
        raise ValueError("workers must be exactly 1")
    build_jobs = _validate_campaign_integer(document, "build_jobs", positive=True)
    if build_jobs != 1:
        raise ValueError("build_jobs must be exactly 1")

    for key in ("waveforms", "vcd"):
        if key in document and document[key] is not False:
            raise ValueError(f"{key} must be false")
    waveforms = document["waveforms"]
    if not isinstance(waveforms, bool):
        raise ValueError("waveforms must be boolean")
    vcd = document.get("vcd", False)
    if not isinstance(vcd, bool):
        raise ValueError("vcd must be boolean")

    soft_memory_bytes = _validate_campaign_integer(document, "soft_memory_bytes", positive=True)
    hard_memory_bytes = _validate_campaign_integer(document, "hard_memory_bytes", positive=True)
    token_bytes = _validate_campaign_integer(document, "token_bytes", positive=True)
    if soft_memory_bytes > _IBEX_SOFT_MEMORY_CEILING:
        raise ValueError("soft_memory_bytes exceeds conservative ceiling")
    if hard_memory_bytes > _IBEX_HARD_MEMORY_CEILING:
        raise ValueError("hard_memory_bytes exceeds conservative ceiling")
    if token_bytes > _IBEX_TOKEN_MEMORY_CEILING:
        raise ValueError("token_bytes exceeds conservative ceiling")
    if soft_memory_bytes >= hard_memory_bytes:
        raise ValueError("soft_memory_bytes must be less than hard_memory_bytes")
    if token_bytes > soft_memory_bytes:
        raise ValueError("token_bytes must not exceed soft_memory_bytes")

    max_restarts = _validate_campaign_integer(
        {"max_restarts": document.get("max_restarts", 2)},
        "max_restarts",
    )
    command_mode = document.get("command_mode", "real")
    if not isinstance(command_mode, str) or command_mode not in _IBEX_COMMAND_MODES:
        raise ValueError("command_mode must be real or local-smoke")

    design_config = _resolve_campaign_path(
        checkout_root,
        document["design_config"],
        "design_config",
    )
    composition_manifest = _resolve_campaign_path(
        checkout_root,
        document["composition_manifest"],
        "composition_manifest",
    )
    if document.get("source_list") != _IBEX_SOURCE_LIST:
        raise ValueError("source_list must use the fixed Ibex upstream source_list")
    source_list = _resolve_campaign_path(
        checkout_root,
        document["source_list"],
        "source_list",
    )
    for label, required_path in (
        ("design_config", design_config),
        ("composition_manifest", composition_manifest),
    ):
        if not required_path.is_file():
            raise ValueError(f"{label}:missing-file:{required_path}")
    design_document = _read_campaign_json(design_config, "design_config")
    candidate_value = design_document.get("candidate_manifest")
    candidate_manifest = _resolve_campaign_path(
        checkout_root,
        candidate_value,
        "candidate_manifest",
    )
    output_value = document.get("output_dir", _IBEX_CAMPAIGN_DEFAULT_OUTPUT)
    if not isinstance(output_value, str) or not output_value or "\0" in output_value:
        raise ValueError("output_dir:path-required")
    output_dir = _resolve_campaign_path(checkout_root, output_value, "output_dir")

    _validate_design_flow_config(
        checkout_root,
        design_config,
        composition_manifest,
        source_list,
    )
    return _IbexCampaignConfig(
        root=checkout_root,
        config_path=path,
        design_config=design_config,
        composition_manifest=composition_manifest,
        source_list=source_list,
        candidate_manifest=candidate_manifest,
        output_dir=output_dir,
        duration_seconds=duration_seconds,
        checkpoint_seconds=checkpoint_seconds,
        seed=seed,
        workers=workers,
        build_jobs=build_jobs,
        waveforms=waveforms,
        vcd=vcd,
        soft_memory_bytes=soft_memory_bytes,
        hard_memory_bytes=hard_memory_bytes,
        token_bytes=token_bytes,
        max_restarts=max_restarts,
        command_mode=command_mode,
        document=document,
    )


def load_ibex_campaign_config(
    config_path: Path,
    *,
    root: Path | None = None,
) -> Mapping[str, object]:
    """Validate and return a strict Ibex campaign document without side effects."""

    spec = _parse_ibex_campaign_config(
        Path(config_path),
        root=_campaign_repository_root() if root is None else Path(root),
    )
    return dict(spec.document)


def _effective_campaign_value(
    value: int | None,
    default: int,
    label: str,
    *,
    positive: bool,
) -> int:
    selected = default if value is None else value
    if isinstance(selected, bool) or not isinstance(selected, int):
        raise ValueError(f"{label} must be an integer")
    if positive and selected <= 0:
        raise ValueError(f"{label} must be positive")
    if not positive and selected < 0:
        raise ValueError(f"{label} must be non-negative")
    if label == "seed" and selected > 0xFFFF_FFFF:
        raise ValueError("seed must be at most 4294967295")
    return selected


def _safe_source_path(source_root: Path, value: str, label: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError(f"source_list:{label}:path-required")
    if "\\" in value:
        raise ValueError(f"source_list:{label}:backslash-path-is-not-allowed")
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError(f"source_list:{label}:absolute-path-is-not-allowed")
    resolved_root = source_root.resolve()
    resolved = (resolved_root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError(f"source_list:{label}:outside-upstream-ibex") from error
    return resolved


def _validate_source_file(path: Path, label: str) -> None:
    if path.suffix.lower() not in _IBEX_HDL_SUFFIXES:
        raise ValueError(f"source_list:{label}:non-HDL-entry:{path.name}")
    try:
        if not path.is_file():
            raise ValueError(f"source_list:{label}:missing-file:{path}")
        if path.stat().st_size > _IBEX_SOURCE_FILE_MAX_BYTES:
            raise ValueError(f"source_list:{label}:file-too-large:{path}")
    except OSError as error:
        raise ValueError(f"source_list:{label}:stat-failed:{path}") from error


def _validate_source_list(root: Path, source_list: Path) -> tuple[Path, ...]:
    """Validate the fixed upstream HDL filelist without executing its flags.

    Only HDL files and a small, explicitly handled set of filelist directives
    are accepted.  Nested lists, include directories, and source files must
    remain below the upstream Ibex directory; this prevents a real campaign
    from silently compiling an arbitrary host path.
    """

    checkout_root = Path(root).resolve()
    source_path = Path(source_list).resolve()
    try:
        source_path.relative_to(checkout_root)
    except ValueError as error:
        raise ValueError("source_list:outside-repository-root") from error
    source_root = source_path.parent
    try:
        source_root.relative_to(checkout_root)
    except ValueError as error:
        raise ValueError("source_list:parent-outside-repository-root") from error

    seen_lists: set[Path] = set()
    seen_sources: set[Path] = set()
    stack: list[Path] = [source_path]

    while stack:
        current = stack.pop().resolve()
        if current in seen_lists:
            continue
        if len(seen_lists) >= _IBEX_MAX_NESTED_SOURCE_LISTS:
            raise ValueError("source_list:too-many-nested-filelists")
        try:
            current.relative_to(source_root)
        except ValueError as error:
            raise ValueError("source_list:nested-filelist-outside-upstream-ibex") from error
        seen_lists.add(current)
        try:
            payload = current.read_bytes()
        except OSError as error:
            raise ValueError(f"source_list:missing-file:{current}") from error
        if not payload or len(payload) > _IBEX_SOURCE_LIST_MAX_BYTES:
            raise ValueError(f"source_list:malformed-or-too-large:{current}")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"source_list:not-UTF8:{current}") from error

        for line_number, raw_line in enumerate(text.splitlines(), 1):
            line = raw_line.split("//", 1)[0].strip()
            if not line:
                continue
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError as error:
                raise ValueError(
                    f"source_list:{current}:{line_number}:invalid-shell-quoting"
                ) from error
            index = 0
            while index < len(tokens):
                token = tokens[index]
                if token in {"-f", "-F"}:
                    index += 1
                    if index >= len(tokens):
                        raise ValueError(
                            f"source_list:{current}:{line_number}:{token}-requires-path"
                        )
                    nested = _safe_source_path(
                        source_root,
                        tokens[index],
                        f"{current}:{line_number}",
                    )
                    stack.append(nested)
                    index += 1
                    continue
                if token.startswith("-f") and len(token) > 2:
                    stack.append(
                        _safe_source_path(
                            source_root,
                            token[2:],
                            f"{current}:{line_number}",
                        )
                    )
                    index += 1
                    continue
                if token.startswith("-F") and len(token) > 2:
                    stack.append(
                        _safe_source_path(
                            source_root,
                            token[2:],
                            f"{current}:{line_number}",
                        )
                    )
                    index += 1
                    continue
                if token == "-v":
                    index += 1
                    if index >= len(tokens):
                        raise ValueError(
                            f"source_list:{current}:{line_number}:-v-requires-path"
                        )
                    source = _safe_source_path(
                        source_root,
                        tokens[index],
                        f"{current}:{line_number}",
                    )
                    _validate_source_file(source, f"{current}:{line_number}")
                    seen_sources.add(source)
                    index += 1
                    continue
                if token.startswith("+incdir+"):
                    values = token[len("+incdir+"):].split("+")
                    if not values or any(not value for value in values):
                        raise ValueError(
                            f"source_list:{current}:{line_number}:invalid-include-directory"
                        )
                    for value in values:
                        include_dir = _safe_source_path(
                            source_root,
                            value,
                            f"{current}:{line_number}",
                        )
                        if not include_dir.is_dir():
                            raise ValueError(
                                f"source_list:{current}:{line_number}:missing-include-directory"
                            )
                    index += 1
                    continue
                if token in {"-I", "-y"}:
                    index += 1
                    if index >= len(tokens):
                        raise ValueError(
                            f"source_list:{current}:{line_number}:{token}-requires-path"
                        )
                    include_dir = _safe_source_path(
                        source_root,
                        tokens[index],
                        f"{current}:{line_number}",
                    )
                    if not include_dir.is_dir():
                        raise ValueError(
                            f"source_list:{current}:{line_number}:missing-include-directory"
                        )
                    index += 1
                    continue
                if token.startswith("-I") or token.startswith("-y"):
                    include_dir = _safe_source_path(
                        source_root,
                        token[2:],
                        f"{current}:{line_number}",
                    )
                    if not include_dir.is_dir():
                        raise ValueError(
                            f"source_list:{current}:{line_number}:missing-include-directory"
                        )
                    index += 1
                    continue
                if token.startswith("+") or token.startswith("-"):
                    # Defines, library extensions, warning switches, and other
                    # simulator flags do not name files and are intentionally
                    # ignored after the path-bearing directives above.
                    index += 1
                    continue

                source = _safe_source_path(
                    source_root,
                    token,
                    f"{current}:{line_number}",
                )
                _validate_source_file(source, f"{current}:{line_number}")
                seen_sources.add(source)
                index += 1

    if not seen_sources:
        raise ValueError("source_list:must-contain-at-least-one-HDL-entry")
    return tuple(sorted(seen_sources))


def _tool_path(name: str, environment_name: str | None = None) -> str:
    configured = os.environ.get(environment_name) if environment_name else None
    candidate = configured or name
    resolved = shutil.which(candidate)
    if resolved is None:
        label = environment_name or name
        raise ValueError(f"toolchain:{label}:not-executable")
    return resolved


def _validate_real_dependencies(root: Path, source_list: Path) -> dict[str, object]:
    """Check every dependency needed before spawning the real RFuzz flow."""

    checkout_root = Path(root).resolve()
    expected_source_list = (checkout_root / _IBEX_SOURCE_LIST).resolve()
    if Path(source_list).resolve() != expected_source_list:
        raise ValueError("source_list must match the fixed Ibex upstream source_list")
    source_files = _validate_source_list(checkout_root, expected_source_list)

    flow_root = checkout_root / "third_party" / "rfuzz" / "rfuzz_flow"
    if not flow_root.is_dir():
        raise ValueError(f"rfuzz_flow:missing-directory:{flow_root}")
    required_flow_paths = (
        flow_root / "tools" / "verilog_instrumentation" / "generate_rfuzz_harness.py",
        flow_root / "tools" / "verilog_instrumentation" / "build_rfuzz_server.py",
        flow_root / "fuzzer",
    )
    for required_path in required_flow_paths:
        if not required_path.exists():
            raise ValueError(f"rfuzz_flow:missing-path:{required_path}")

    fuzzer = flow_root / "fuzzer" / "target" / "release" / "kfuzz"
    cargo = None if fuzzer.is_file() else _tool_path("cargo")
    verilator = _tool_path("verilator", "MYFUZZ_SERVER_VERILATOR_BIN")
    return {
        "source_files": len(source_files),
        "rfuzz_flow": flow_root.as_posix(),
        "verilator": verilator,
        "cargo": cargo,
        "fuzzer": fuzzer.as_posix(),
    }


def _campaign_output_path(output_dir: Path, *, root: Path | None = None) -> Path:
    if not isinstance(output_dir, Path):
        raise TypeError("output_dir must be a pathlib.Path")
    candidate = output_dir.expanduser()
    resolved_root = Path(root).resolve() if root is not None else None
    if resolved_root is not None and not candidate.is_absolute():
        candidate = resolved_root / candidate
    resolved = candidate.resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError("output_dir must not be the filesystem root")
    if resolved_root is not None:
        try:
            resolved.relative_to(resolved_root)
        except ValueError as error:
            raise ValueError("output_dir:outside-repository-root") from error
        if resolved == resolved_root:
            raise ValueError("output_dir must be below the repository root")
    return resolved


def _validated_command(command: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(command, tuple) or not command:
        raise TypeError("command must be a non-empty tuple of strings")
    if any(not isinstance(argument, str) or not argument for argument in command):
        raise TypeError("command must be a non-empty tuple of strings")
    return command


def _composition_manifest_hash(path: Path) -> str:
    document = _read_campaign_json(path, "composition_manifest")
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _relative_campaign_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _upstream_dependency(
    spec: _IbexCampaignConfig,
    *,
    status: str | None = None,
) -> dict[str, object]:
    diagnostics: list[str] = []
    if status is None:
        try:
            _validate_real_dependencies(spec.root, spec.source_list)
        except ValueError as error:
            diagnostics.append(str(error))
    dependency_status = "available" if not diagnostics else "dependency-unavailable"
    if status is not None:
        dependency_status = status
    return {
        "status": dependency_status,
        "source_list": _relative_campaign_path(spec.root, spec.source_list),
        "required_for_real_target": True,
        "diagnostics": diagnostics,
    }


def _execution_metadata(spec: _IbexCampaignConfig) -> dict[str, object]:
    return {
        "worker_count": 1,
        "build_jobs": 1,
        "waveforms": False,
        "vcd": False,
        "soft_memory_bytes": spec.soft_memory_bytes,
        "hard_memory_bytes": spec.hard_memory_bytes,
        "token_bytes": spec.token_bytes,
    }


def _annotate_campaign_report(
    result: dict[str, object],
    metadata: Mapping[str, object],
) -> None:
    report_value = result.get("report_path")
    if not isinstance(report_value, str) or not report_value:
        return
    report_path = Path(report_value)
    try:
        document = _read_campaign_json(report_path, "campaign_report")
        document.update(metadata)
        publish_campaign_report(report_path, document)
    except (CampaignReportError, ValueError, OSError) as error:
        result["error"] = {
            "type": "report-publish-failed",
            "message": str(error),
        }
        result["report_path"] = None


def build_ibex_campaign_command(
    root: Path,
    config_path: Path,
    output_dir: Path,
    duration_seconds: int,
    seed: int,
) -> tuple[str, ...]:
    """Build the single-worker real Ibex design-flow command."""

    checkout_root = Path(root).resolve()
    spec = _parse_ibex_campaign_config(Path(config_path), root=checkout_root)
    _campaign_output_path(output_dir, root=checkout_root)
    duration = _effective_campaign_value(
        duration_seconds,
        spec.duration_seconds,
        "duration_seconds",
        positive=True,
    )
    selected_seed = _effective_campaign_value(
        seed,
        spec.seed,
        "seed",
        positive=False,
    )
    flow_script = checkout_root / "src" / "myfuzz" / "scripts" / "run_design_flow.py"
    return (
        sys.executable,
        flow_script.as_posix(),
        "--config",
        spec.design_config.as_posix(),
        "--manifest",
        spec.candidate_manifest.as_posix(),
        "--stage",
        "all",
        "--jobs",
        "1",
        "--fuzz-seconds",
        str(duration),
        "--seed",
        str(selected_seed),
    )


def _campaign_result_metadata(
    spec: _IbexCampaignConfig,
    dependency: Mapping[str, object],
    *,
    evidence: Mapping[str, object] | None = None,
) -> dict[str, object]:
    dependency_status = dependency.get("status")
    metadata: dict[str, object] = {
        "upstream_dependency": dict(dependency),
        "upstream_dependency_status": dependency_status,
        "dependency_status": dependency_status,
        "execution": _execution_metadata(spec),
    }
    if evidence is not None:
        metadata["evidence"] = dict(evidence)
    return metadata


def _dry_run_result(
    spec: _IbexCampaignConfig,
    output_dir: Path,
    command: tuple[str, ...],
    metadata: Mapping[str, object],
) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "dry-run",
        "command": list(command),
        "output_dir": output_dir.as_posix(),
        "report_path": None,
        "dry_run": True,
    }
    result.update(metadata)
    return result


def run_ibex_campaign(
    config_path: Path,
    output_dir: Path,
    *,
    duration_seconds: int | None = None,
    seed: int | None = None,
    checkpoint_seconds: int | None = None,
    command: tuple[str, ...] | None = None,
    dry_run: bool = False,
    max_restarts: int | None = None,
) -> Mapping[str, object]:
    """Run or dry-run one strict, real-target Ibex campaign."""

    spec = _parse_ibex_campaign_config(
        Path(config_path),
        root=_campaign_repository_root(),
    )
    if command is not None:
        raise ValueError("command override is not allowed; use the declared campaign mode")
    if spec.command_mode == "local-smoke":
        return run_ibex_local_smoke(
            config_path,
            output_dir,
            duration_seconds=duration_seconds,
            seed=seed,
            checkpoint_seconds=checkpoint_seconds,
            max_restarts=max_restarts,
            dry_run=dry_run,
        )
    selected_output = _campaign_output_path(output_dir, root=spec.root)
    selected_duration = _effective_campaign_value(
        duration_seconds,
        spec.duration_seconds,
        "duration_seconds",
        positive=True,
    )
    selected_seed = _effective_campaign_value(
        seed,
        spec.seed,
        "seed",
        positive=False,
    )
    selected_checkpoint = _effective_campaign_value(
        checkpoint_seconds,
        spec.checkpoint_seconds,
        "checkpoint_seconds",
        positive=True,
    )
    selected_restarts = _effective_campaign_value(
        max_restarts,
        spec.max_restarts,
        "max_restarts",
        positive=False,
    )

    selected_command = build_ibex_campaign_command(
        spec.root,
        spec.config_path,
        selected_output,
        selected_duration,
        selected_seed,
    )
    dependency = _upstream_dependency(spec)
    metadata = _campaign_result_metadata(spec, dependency)
    if dependency["status"] != "available":
        return {
            "status": "dependency-unavailable",
            "command": list(selected_command),
            "output_dir": selected_output.as_posix(),
            "report_path": None,
            "dry_run": dry_run,
            "missing_dependencies": [str(dependency["source_list"])],
            **metadata,
        }

    if dry_run:
        return _dry_run_result(spec, selected_output, selected_command, metadata)

    options = CampaignOptions(
        command=selected_command,
        output_dir=selected_output,
        duration_seconds=selected_duration,
        seed=selected_seed,
        checkpoint_seconds=selected_checkpoint,
        limits=CampaignLimits(
            soft_memory_bytes=spec.soft_memory_bytes,
            hard_memory_bytes=spec.hard_memory_bytes,
            max_restarts=selected_restarts,
        ),
        composition_hash=_composition_manifest_hash(spec.composition_manifest),
    )
    result = dict(run_supervised_command(options))
    result["command"] = list(selected_command)
    result["output_dir"] = selected_output.as_posix()
    result.update(metadata)
    _annotate_campaign_report(result, metadata)
    return result


def run_ibex_local_smoke(
    config_path: Path,
    output_dir: Path,
    *,
    duration_seconds: int | None = None,
    seed: int | None = None,
    checkpoint_seconds: int | None = None,
    max_restarts: int | None = None,
    dry_run: bool = False,
) -> Mapping[str, object]:
    """Run the deterministic local producer under the campaign supervisor."""

    spec = _parse_ibex_campaign_config(
        Path(config_path),
        root=_campaign_repository_root(),
    )
    selected_output = _campaign_output_path(output_dir, root=spec.root)
    selected_duration = _effective_campaign_value(
        duration_seconds,
        spec.duration_seconds,
        "duration_seconds",
        positive=True,
    )
    selected_seed = _effective_campaign_value(
        seed,
        spec.seed,
        "seed",
        positive=False,
    )
    selected_checkpoint = _effective_campaign_value(
        checkpoint_seconds,
        spec.checkpoint_seconds,
        "checkpoint_seconds",
        positive=True,
    )
    selected_restarts = _effective_campaign_value(
        max_restarts,
        spec.max_restarts,
        "max_restarts",
        positive=False,
    )
    producer = spec.root / "scripts" / "run_ibex_protocol_campaign_smoke.py"
    selected_command = (
        sys.executable,
        producer.as_posix(),
        "--duration-seconds",
        str(selected_duration),
        "--seed",
        str(selected_seed),
    )
    dependency = _upstream_dependency(spec)
    metadata = _campaign_result_metadata(
        spec,
        dependency,
        evidence={
            "kind": "local-json-producer",
            "rtl_compilation_claimed": False,
            "upstream_dependency_checked": True,
        },
    )
    if dry_run:
        return _dry_run_result(spec, selected_output, selected_command, metadata)

    options = CampaignOptions(
        command=selected_command,
        output_dir=selected_output,
        duration_seconds=selected_duration,
        seed=selected_seed,
        checkpoint_seconds=selected_checkpoint,
        limits=CampaignLimits(
            soft_memory_bytes=spec.soft_memory_bytes,
            hard_memory_bytes=spec.hard_memory_bytes,
            max_restarts=selected_restarts,
        ),
        composition_hash=_composition_manifest_hash(spec.composition_manifest),
    )
    result = dict(run_supervised_command(options))
    result["command"] = list(selected_command)
    result["output_dir"] = selected_output.as_posix()
    result["local_smoke"] = True
    result.update(metadata)
    _annotate_campaign_report(result, metadata)
    return result


__all__ = [
    "CampaignError",
    "CampaignLimits",
    "CampaignOptions",
    "build_ibex_campaign_command",
    "load_ibex_campaign_config",
    "read_rss_bytes",
    "run_ibex_campaign",
    "run_ibex_local_smoke",
    "run_supervised_command",
]
