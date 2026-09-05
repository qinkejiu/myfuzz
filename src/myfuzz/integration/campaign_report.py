"""Bounded checkpoint and evidence-report primitives for campaign runs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .campaign import CampaignOptions


_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_ENTRIES = 1024
_MAX_LINE_BYTES = 64 * 1024
_MAX_COUNTER_VALUE = (1 << 63) - 1
_REPORTABLE_STATUSES = frozenset({"completed", "crashed", "resource-terminated"})
_KNOWN_PROTOCOLS = frozenset({"apb", "apb4", "axi4-lite", "tl-ul"})


class CampaignReportError(ValueError):
    """Raised when a checkpoint or report cannot be safely published."""


def _bounded_counter(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CampaignReportError(f"{label} must be a non-negative integer")
    return min(value, _MAX_COUNTER_VALUE)


def _counter_map(value: Mapping[str, int] | None, label: str) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CampaignReportError(f"{label} must be a mapping")
    result: dict[str, int] = {}
    for key in sorted(value, key=str):
        if not isinstance(key, str) or not key:
            raise CampaignReportError(f"{label} contains an invalid key")
        if len(result) >= _MAX_ENTRIES:
            break
        result[key] = _bounded_counter(value[key], f"{label}.{key}")
    return result


def _coverage_set(value: object) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (set, frozenset, list, tuple)):
        values = value
    else:
        raise CampaignReportError("coverage must be a collection of strings")
    result: set[str] = set()
    for item in values:
        if not isinstance(item, str) or not item:
            raise CampaignReportError("coverage must contain non-empty strings")
        if len(result) >= _MAX_ENTRIES:
            break
        result.add(item)
    return result


@dataclass(slots=True)
class CampaignState:
    """Small mutable aggregate updated from accepted JSON-line samples."""

    seed: int
    iterations: int = 0
    transactions: int = 0
    protocol_transactions: dict[str, int] = field(default_factory=dict)
    component_transactions: dict[str, int] = field(default_factory=dict)
    coverage: set[str] = field(default_factory=set)
    errors: int = 0
    peak_rss_bytes: int = 0
    checkpoint_count: int = 0
    last_output_line: str | None = None
    duration_seconds: float = 0.0
    composition_hash: str | None = None
    status: str = "running"

    def __post_init__(self) -> None:
        self.seed = _bounded_counter(self.seed, "seed")
        self.iterations = _bounded_counter(self.iterations, "iterations")
        self.transactions = _bounded_counter(self.transactions, "transactions")
        self.protocol_transactions = _counter_map(
            self.protocol_transactions, "protocol_transactions"
        )
        self.component_transactions = _counter_map(
            self.component_transactions, "component_transactions"
        )
        self.coverage = _coverage_set(self.coverage)
        self.errors = _bounded_counter(self.errors, "errors")
        self.peak_rss_bytes = _bounded_counter(self.peak_rss_bytes, "peak_rss_bytes")
        self.checkpoint_count = _bounded_counter(
            self.checkpoint_count, "checkpoint_count"
        )
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ) or self.duration_seconds < 0:
            raise CampaignReportError("duration_seconds must be a non-negative number")
        try:
            duration_is_finite = math.isfinite(self.duration_seconds)
        except (OverflowError, TypeError):
            duration_is_finite = False
        if not duration_is_finite:
            raise CampaignReportError("duration_seconds must be finite")
        if self.last_output_line is not None:
            if not isinstance(self.last_output_line, str):
                raise CampaignReportError("last_output_line must be a string or None")
            if len(self.last_output_line.encode("utf-8")) > _MAX_LINE_BYTES:
                raise CampaignReportError("last_output_line exceeds the line limit")
        if self.composition_hash is not None and not isinstance(
            self.composition_hash, str
        ):
            raise CampaignReportError("composition_hash must be a string or None")
        if not isinstance(self.status, str) or not self.status:
            raise CampaignReportError("status must be a non-empty string")

    def record_error(self, count: int = 1) -> None:
        """Increment the bounded invalid-sample counter."""
        self.errors = min(
            _MAX_COUNTER_VALUE,
            self.errors + _bounded_counter(count, "error count"),
        )

    def _add_counter(self, counters: dict[str, int], key: str, amount: int) -> None:
        if key not in counters and len(counters) >= _MAX_ENTRIES:
            return
        counters[key] = min(_MAX_COUNTER_VALUE, counters.get(key, 0) + amount)

    def record_metric(self, document: Mapping[str, object], line: str) -> None:
        """Aggregate one bounded, recognized metric document without raising."""
        if not isinstance(document, Mapping):
            self.record_error()
            return

        amount = 1
        has_transaction_count = "transactions" in document
        if has_transaction_count:
            raw_amount = document.get("transactions")
            if isinstance(raw_amount, bool) or not isinstance(raw_amount, int) or raw_amount < 0:
                self.record_error()
                amount = 0
            else:
                amount = min(raw_amount, _MAX_COUNTER_VALUE)

        raw_iterations = document.get("iterations")
        if raw_iterations is not None:
            if (
                isinstance(raw_iterations, bool)
                or not isinstance(raw_iterations, int)
                or raw_iterations < 0
            ):
                self.record_error()
            else:
                self.iterations = min(
                    _MAX_COUNTER_VALUE,
                    self.iterations + min(raw_iterations, _MAX_COUNTER_VALUE),
                )
        elif has_transaction_count and amount:
            self.iterations = min(_MAX_COUNTER_VALUE, self.iterations + amount)

        if has_transaction_count:
            self.transactions = min(_MAX_COUNTER_VALUE, self.transactions + amount)

        raw_protocol = document.get("protocol")
        if raw_protocol is not None:
            if not isinstance(raw_protocol, str) or not raw_protocol:
                self.record_error()
            elif raw_protocol not in _KNOWN_PROTOCOLS:
                self.record_error()
            else:
                self._add_counter(self.protocol_transactions, raw_protocol, amount)

        raw_component = document.get("component")
        if raw_component is not None:
            if not isinstance(raw_component, str) or not raw_component:
                self.record_error()
            else:
                self._add_counter(self.component_transactions, raw_component, amount)

        raw_coverage = document.get("coverage")
        if raw_coverage is not None:
            values = [raw_coverage] if isinstance(raw_coverage, str) else raw_coverage
            if not isinstance(values, (list, tuple, set, frozenset)):
                self.record_error()
            else:
                for point in values:
                    if not isinstance(point, str) or not point:
                        self.record_error()
                        continue
                    if len(self.coverage) < _MAX_ENTRIES:
                        self.coverage.add(point)

        if "error" in document:
            raw_error = document.get("error")
            if isinstance(raw_error, bool) or not isinstance(raw_error, int) or raw_error < 0:
                self.record_error()
            else:
                self.record_error(min(raw_error, _MAX_COUNTER_VALUE))

        encoded_line = line.encode("utf-8")
        if len(encoded_line) <= _MAX_LINE_BYTES:
            self.last_output_line = line
        else:
            self.record_error()

    def document(self, checkpoint_count: int | None = None) -> dict[str, object]:
        """Return a deterministic JSON-compatible snapshot of the state."""
        count = self.checkpoint_count if checkpoint_count is None else checkpoint_count
        return {
            "schema_version": "campaign_checkpoint.v1",
            "seed": self.seed,
            "iterations": self.iterations,
            "transactions": self.transactions,
            "protocol_transactions": dict(
                sorted(self.protocol_transactions.items())
            ),
            "component_transactions": dict(
                sorted(self.component_transactions.items())
            ),
            "coverage": sorted(self.coverage),
            "errors": self.errors,
            "peak_rss_bytes": self.peak_rss_bytes,
            "checkpoint_count": count,
            "last_output_line": self.last_output_line,
            "duration_seconds": self.duration_seconds,
            "composition_hash": self.composition_hash,
            "status": self.status,
        }


def _encode(document: Mapping[str, object]) -> bytes:
    try:
        payload = (
            json.dumps(
                document,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise CampaignReportError("campaign document is not JSON serializable") from error
    if len(payload) > _MAX_JSON_BYTES:
        raise CampaignReportError("campaign document exceeds the 64 MiB limit")
    return payload


def _atomic_publish(path: Path, payload: bytes) -> None:
    if not isinstance(path, Path):
        raise TypeError("path must be a pathlib.Path")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise CampaignReportError(f"cannot create report directory: {path.parent}") from error

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
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
        raise CampaignReportError(f"cannot atomically publish {path}") from error
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


def write_checkpoint(path: Path, state: CampaignState) -> None:
    """Atomically publish the next bounded checkpoint and update its count."""
    if not isinstance(state, CampaignState):
        raise TypeError("state must be CampaignState")
    next_count = min(_MAX_COUNTER_VALUE, state.checkpoint_count + 1)
    payload = _encode(state.document(checkpoint_count=next_count))
    _atomic_publish(path, payload)
    state.checkpoint_count = next_count


def _composition_hash(options: CampaignOptions, state: CampaignState) -> str:
    if state.composition_hash:
        return state.composition_hash
    option_hash = getattr(options, "composition_hash", None)
    if isinstance(option_hash, str) and option_hash:
        return option_hash
    environment = getattr(options, "env", {})
    if isinstance(environment, Mapping):
        for key in ("MYFUZZ_COMPOSITION_HASH", "COMPOSITION_HASH"):
            value = environment.get(key)
            if isinstance(value, str) and value:
                return value
    return "unavailable"


def _replay_command(value: Sequence[str] | None) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)):
        raise CampaignReportError("replay_command must be a sequence of strings")
    result = list(value)
    if any(not isinstance(item, str) or not item for item in result):
        raise CampaignReportError("replay_command must contain non-empty strings")
    return result


def build_campaign_report(
    options: CampaignOptions,
    state: CampaignState,
    status: str,
    replay_command: Sequence[str] | None,
) -> dict[str, object]:
    """Build a deterministic evidence document without writing it."""
    if not isinstance(state, CampaignState):
        raise TypeError("state must be CampaignState")
    if not isinstance(status, str) or not status:
        raise CampaignReportError("status must be a non-empty string")
    if status == "crashed" and replay_command is None:
        raise CampaignReportError("crashed reports require a replay command")
    duration = state.duration_seconds
    if duration <= 0:
        configured_duration = getattr(options, "duration_seconds", 0)
        duration = float(configured_duration) if configured_duration > 0 else 0.0
    replay = _replay_command(replay_command)
    document: dict[str, object] = {
        "schema_version": "campaign_report.v1",
        "status": status,
        "composition_hash": _composition_hash(options, state),
        "seed": state.seed,
        "duration_seconds": duration,
        "configured_duration_seconds": getattr(options, "duration_seconds", None),
        "iterations": state.iterations,
        "throughput_iterations_per_second": state.iterations / max(duration, 1e-9),
        "transactions": state.transactions,
        "protocol_transactions": dict(sorted(state.protocol_transactions.items())),
        "component_transactions": dict(sorted(state.component_transactions.items())),
        "coverage": sorted(state.coverage),
        "errors": state.errors,
        "peak_rss_bytes": state.peak_rss_bytes,
        "checkpoint_count": state.checkpoint_count,
        "last_output_line": state.last_output_line,
        "replay_command": replay,
        "limits": {
            "soft_memory_bytes": getattr(getattr(options, "limits", None), "soft_memory_bytes", None),
            "hard_memory_bytes": getattr(getattr(options, "limits", None), "hard_memory_bytes", None),
        },
    }
    _encode(document)
    return document


def publish_campaign_report(path: Path, document: Mapping[str, object]) -> None:
    """Atomically publish only a complete terminal campaign report."""
    if not isinstance(document, Mapping):
        raise TypeError("document must be a mapping")
    if document.get("schema_version") != "campaign_report.v1":
        raise CampaignReportError("unsupported campaign report schema")
    status = document.get("status")
    if status not in _REPORTABLE_STATUSES:
        raise CampaignReportError(
            "campaign report status must be completed, crashed, or resource-terminated"
        )
    if status == "crashed" and not document.get("replay_command"):
        raise CampaignReportError("crashed reports require a replay command")
    payload = _encode(document)
    _atomic_publish(path, payload)


__all__ = [
    "CampaignReportError",
    "CampaignState",
    "build_campaign_report",
    "publish_campaign_report",
    "write_checkpoint",
]
