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
from myfuzz.scenario.replay import ReplayComparison

from .rfuzz_wire import InputBatch
from .scenario_rfuzz import ScenarioRfuzzExecutor


@dataclass(frozen=True)
class CorpusReplayResult:
    total_entries: int
    matched_entries: int
    mismatches: tuple[str, ...]


@dataclass(frozen=True)
class ContinuousReplayResult:
    """Scope includes case checker replay and trace, plus decoder checker identity.

    RFuzz selection policies, per-candidate coverage and cumulative decoder
    checker verdicts are retained as evidence, not recomputed by this API.
    """
    comparison: ReplayComparison
    verification_scope: tuple[str, ...] = (
        "complete_admitted_session_prefix", "session_case_checker",
        "decoder_checker_identity")

    @property
    def matches(self) -> bool:
        return self.comparison.matches


def replay_scenario_rfuzz_continuous(
        output_dir: Path, factory: Callable[[], ScenarioRunner], *,
        session_checker=None, decoder_checker=None, checker_config=None,
        checker_identity_target=None) -> ContinuousReplayResult:
    """Replay an actual continuous admission prefix as one stateful testcase."""
    from myfuzz.scenario.event_journal import JsonlEventView, ZlibChunkEventView
    from myfuzz.scenario.replay import ScenarioTrace
    from myfuzz.scenario.session_runtime import replay_online_session, _checker_identity
    from .scenario_rfuzz_live import _verify_online_run_identity, _fresh_checker_identity

    output = Path(output_dir)
    report = json.loads((output / "report.json").read_bytes())
    if report.get("execution_mode") != "continuous_decoder":
        raise ValueError("continuous replay requires a saved continuous decoder run")
    trace_path = output / "online_final_trace.json"
    if not trace_path.is_file():
        trace_path = output / "online_final_trace.meta.json"
    document = json.loads(trace_path.read_bytes())
    if document.get("schema_version") == "online_trace_jsonl.v1":
        if document.get("events_file") != "online_events.jsonl":
            raise ValueError("invalid continuous JSONL trace metadata")
        document["events"] = JsonlEventView(output / document.pop("events_file"),
                                           document.pop("event_count"))
        document.pop("schema_version")
    elif document.get("schema_version") == "online_trace_zlib_chunks.v1":
        expected = {"schema_version", "events_file", "event_count",
                    "genome_sha256", "status", "local_ticks",
                    "semantic_sha256", "manifest_sha256"}
        if set(document) != expected or document["events_file"] != "online_events.zlib":
            raise ValueError("invalid continuous compressed trace metadata")
        view = ZlibChunkEventView(output / document.pop("events_file"),
                                  document.pop("event_count"))
        view.verify_trace_semantic(status=document["status"],
                                   local_ticks=document["local_ticks"],
                                   expected_sha256=document["semantic_sha256"])
        document["events"] = view
        document.pop("schema_version")
    reference = ScenarioTrace(**document)
    plan_path = output / "online_plan.json"
    identity = _verify_online_run_identity(output, plan_path=plan_path,
                                         trace_path=trace_path, trace=reference,
                                         decoder_checker=decoder_checker,
                                         checker_config=checker_config,
                                         checker_identity_target=checker_identity_target)
    if identity is None or identity.get("execution_mode") != "continuous_decoder":
        raise ValueError("continuous run identity is required")
    if identity.get("checker") != _checker_identity(session_checker):
        raise ValueError("continuous session checker identity mismatch")
    if identity.get("decoder_checker") != _fresh_checker_identity(
            decoder_checker, config=checker_config, identity_target=checker_identity_target):
        raise ValueError("continuous decoder checker identity mismatch")
    return ContinuousReplayResult(replay_online_session(
        plan_path.read_bytes(), factory, reference, checker=session_checker))


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
    if marker.get("phase") == "inflight_finalize":
        timeout_us = marker.get("finalize_timeout_us")
        if type(timeout_us) is not int or timeout_us < 0:
            raise ValueError("invalid finalize timeout in saved wall cutoff")

    def make_runner():
        runner = factory()
        kwargs = {"prefix_event_count": marker["prefix_event_count"]}
        if marker.get("phase") == "inflight_finalize":
            timeout_us = marker["finalize_timeout_us"]
            budget = getattr(runner, "_resource_budget", None)
            maximum_ms = getattr(budget, "max_wall_time_ms", None)
            if (type(maximum_ms) is int
                    and timeout_us > maximum_ms * 1000):
                raise ValueError(
                    "finalize timeout exceeds replay wall budget")
            kwargs["finalize_timeout_us"] = timeout_us
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
    for key in ("event_id", "kind", "limit", "phase",
                "effect_may_have_occurred", "local_ticks", "cleanup_errors",
                "prefix_event_count", "prefix_local_ticks",
                "step_timeout_us", "finalize_timeout_us",
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
        checker: Callable | None = None,
        checker_config: dict | None = None,
        checker_identity_target: Callable | None = None) -> CorpusReplayResult:
    output = Path(output_dir)
    admission_report = json.loads((output / "report.json").read_bytes())
    if admission_report.get("execution_mode") == "continuous_decoder":
        raise ValueError("continuous history requires replay_scenario_rfuzz_continuous")
    from .scenario_rfuzz_live import _verify_fresh_run_identity
    run_identity = _verify_fresh_run_identity(
        output, checker=checker, checker_config=checker_config,
        checker_identity_target=checker_identity_target)
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
    if run_identity is not None:
        executor._observe_fresh_identity(json.loads(
            (output / "runner_manifest.json").read_bytes()))
        executor._install_runtime_replay_identity(run_identity.get("runtime_paths"))
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
                    "total_local_ticks", "coverage_hex", "violations"):
            actual_value = getattr(actual, key)
            prior_value = prior.get(key, () if key == "violations" else None)
            if key == "violations":
                actual_value, prior_value = tuple(actual_value), tuple(prior_value)
            if actual_value != prior_value:
                mismatches.append(f"{path.name}: {key} differs")
                break
    return CorpusReplayResult(len(entries), len(entries) - len(mismatches),
                              tuple(mismatches))
