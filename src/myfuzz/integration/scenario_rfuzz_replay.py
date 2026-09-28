"""Replay RFuzz saved raw corpus through fresh independent scenario RTL."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable

from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.rfuzz_decoder import GenomeRecordDecoder, RECORD_BYTES
from myfuzz.scenario.runner import ScenarioRunner

from .rfuzz_wire import InputBatch
from .scenario_rfuzz import ScenarioRfuzzExecutor


@dataclass(frozen=True)
class CorpusReplayResult:
    total_entries: int
    matched_entries: int
    mismatches: tuple[str, ...]


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _wall_cut_factory(factory: Callable[[], ScenarioRunner], marker: dict):
    """Recreate a physical cutoff at its recorded semantic boundary."""
    if (not isinstance(marker, dict)
            or marker.get("kind") != "budget_exhausted"
            or marker.get("limit") != "max_wall_time_ms"
            or not isinstance(marker.get("semantic_prefix_sha256"), str)
            or type(marker.get("prefix_event_count")) is not int
            or not isinstance(marker.get("prefix_local_ticks"), dict)):
        raise ValueError("invalid saved wall cutoff")

    def make_runner():
        runner = factory()
        kwargs = {"prefix_event_count": marker["prefix_event_count"]}
        if marker.get("phase") in ("before_begin", "inflight_begin"):
            kwargs.update({"failed_component": marker["failed_component"],
                           "started_components": tuple(marker["started_components"])})
        runner.set_replay_wall_cut(
            sum(marker["prefix_local_ticks"].values()),
            marker["phase"], **kwargs)
        return runner

    return make_runner


def _wall_cut_mismatch(marker: dict, trace) -> str | None:
    prefix = marker["prefix_event_count"]
    if (type(prefix) is not int or prefix < 0
            or len(trace.events) != prefix + 1):
        return "wall cutoff budget marker missing or event count differs"
    if hashlib.sha256(_canonical(trace.events[:prefix])).hexdigest() != \
            marker["semantic_prefix_sha256"]:
        return "wall cutoff semantic prefix differs"
    actual = trace.events[prefix]
    for key in ("kind", "limit", "phase", "effect_may_have_occurred",
                "prefix_event_count", "prefix_local_ticks",
                "failed_component", "started_components",
                "status_before_finalize"):
        if _canonical(actual.get(key)) != _canonical(marker.get(key)):
            return f"wall cutoff {key} differs"
    if trace.status != "budget_exhausted" and not (
            marker["phase"] == "inflight_finalize"
            and trace.status == marker.get("status_before_finalize")):
        return "wall cutoff budget status differs"
    return None


def replay_scenario_rfuzz_corpus(
        output_dir: Path, factory: Callable[[], ScenarioRunner], *,
        checker: Callable | None = None) -> CorpusReplayResult:
    output = Path(output_dir)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "decoder_manifest.json").read_text(
        encoding="utf-8"))
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != report["decoder_manifest_sha256"]:
        raise ValueError("decoder manifest identity mismatch")
    decoder = GenomeRecordDecoder.from_document(manifest)
    targets = tuple(CoverageTarget(**item) for item in json.loads(
        (output / "targets.json").read_text(encoding="utf-8")))
    executor = ScenarioRfuzzExecutor(run_id="corpus-replay", decoder=decoder,
                                     factory=factory, targets=targets,
                                     checker=checker, replay_only=True)
    original: dict[str, dict] = {}
    with (output / "receipts.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            old = original.setdefault(row["raw_sha256"], row)
            comparable = ("genome_sha256", "path_id", "manifest_sha256",
                          "semantic_sha256", "status",
                          "total_local_ticks", "coverage_hex", "wall_cut")
            if any(old.get(key) != row.get(key) for key in comparable):
                raise ValueError("original receipts disagree for identical raw input")
    entries = sorted((output / "corpus").glob("entry_*.json"))
    if not entries:
        raise ValueError("RFuzz saved corpus is empty")
    mismatches: list[str] = []
    for index, path in enumerate(entries):
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("oversized RFuzz corpus entry")
        document = json.loads(path.read_text(encoding="utf-8"))
        raw_values = document.get("entry", {}).get("inputs")
        if (not isinstance(raw_values, list) or not raw_values
                or len(raw_values) % RECORD_BYTES
                or len(raw_values) // RECORD_BYTES > decoder.max_records
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in raw_values)):
            raise ValueError(f"invalid RFuzz corpus bytes: {path.name}")
        raw = bytes(raw_values)
        raw_hash = hashlib.sha256(raw).hexdigest()
        prior = original.get(raw_hash)
        if prior is None:
            mismatches.append(f"{path.name}: no original execution receipt")
            continue
        records = tuple(raw[offset:offset + RECORD_BYTES]
                        for offset in range(0, len(raw), RECORD_BYTES))
        marker = prior.get("wall_cut")
        if marker is not None:
            try:
                executor.factory = _wall_cut_factory(factory, marker)
            except (KeyError, TypeError, ValueError) as exc:
                mismatches.append(f"{path.name}: invalid wall cut: {exc}")
                continue
        else:
            executor.factory = factory
        executor.execute_batch(InputBatch(index, RECORD_BYTES, (records,)))
        actual = executor.receipts[-1]
        if marker is not None:
            if actual.trace is None:
                mismatches.append(f"{path.name}: replay budget trace missing")
                continue
            mismatch = _wall_cut_mismatch(marker, actual.trace)
            if mismatch is not None:
                mismatches.append(f"{path.name}: {mismatch}")
                continue
            for key in ("genome_sha256", "path_id", "manifest_sha256"):
                if getattr(actual, key) != prior[key]:
                    mismatches.append(f"{path.name}: {key} differs")
                    break
            continue
        for key in ("genome_sha256", "path_id", "manifest_sha256",
                    "semantic_sha256", "status",
                    "total_local_ticks", "coverage_hex"):
            if getattr(actual, key) != prior[key]:
                mismatches.append(f"{path.name}: {key} differs")
                break
    return CorpusReplayResult(len(entries), len(entries) - len(mismatches),
                              tuple(mismatches))
