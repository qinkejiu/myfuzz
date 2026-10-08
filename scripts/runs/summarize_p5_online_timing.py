#!/usr/bin/env python3
"""Summarize a P5 online run after its independent fresh RTL replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.scenario.event_journal import ZlibChunkEventView  # noqa: E402
from scripts.runs.replay_p5_online_verified import TRUSTED_CLI_SHA256  # noqa: E402


PHASES = ("selection_decode", "rtl_submit", "trace_digest",
          "interaction_ingest", "checker", "feedback_credit", "receipt_build",
          "total")
RUNNER_PHASES = ("scheduler_batch", "runner_step", "router_enqueue",
                 "router_drain", "router_transact", "observed_output_route")
FINALIZATION_PHASES = ("session_finish", "plan_write", "trace_write",
                       "identity_write", "total_before_report")


def _quantile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    lower = math.floor(rank)
    upper = math.ceil(rank)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def _phase_summary(durations: dict[str, list[float]]) -> dict:
    return {name: {"p50": _quantile(values, 0.5),
                   "p95": _quantile(values, 0.95),
                   "sum": sum(values)}
            for name, values in durations.items() if values}


def _valid_timing(timing: object, names: tuple[str, ...]) -> bool:
    return isinstance(timing, dict) and all(
        name in timing and type(timing[name]) in (float, int)
        and math.isfinite(timing[name]) and timing[name] >= 0
        for name in names)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _identity_valid(output: Path, report: dict, replay: dict,
                    trace_format: str | None, event_file: str | None) -> tuple[bool, bool]:
    try:
        envelope = json.loads((output / "online_run_identity.json").read_bytes())
        identity = envelope["identity"]
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode()
        digest = hashlib.sha256(canonical).hexdigest()
        artifacts = identity["artifacts"]
        if (envelope["schema_version"] != "scenario_online_run_identity_envelope.v1"
                or identity["schema_version"] != "scenario_online_run_identity.v1"
                or envelope["sha256"] != digest
                or report.get("online_run_identity_sha256") != digest
                or identity["trace_format"] != trace_format
                or identity["genome"]["plan_sha256"] != _sha256_file(output / "online_plan.json")
                or not isinstance(artifacts, dict)
                or not {"online_plan.json", "online_final_trace.meta.json", event_file}
                <= set(artifacts)):
            return False, False
        for name, expected in artifacts.items():
            path = output / name
            if (not isinstance(name, str) or Path(name).is_absolute()
                    or ".." in Path(name).parts or not path.is_file()
                    or path.is_symlink() or not _is_digest(expected)
                    or _sha256_file(path) != expected):
                return False, False
        inputs = replay.get("inputs")
        wall_path = output.parent / "run-time.txt"
        manifest_path = output.parent / "snapshot.sha256"
        if not wall_path.is_file():
            wall_path = output / "run-time.txt"
        if not manifest_path.is_file():
            manifest_path = output / "snapshot.sha256"
        replay_paths = {name: output / name for name in (
            "online_plan.json", "online_final_trace.meta.json", event_file,
            "online_run_identity.json", "report.json")}
        replay_paths["run-time.txt"] = wall_path
        replay_paths["snapshot.sha256"] = manifest_path
        replay_valid = (replay.get("replay_exit_code") == 0
                        and replay.get("replay_cli_sha256") == TRUSTED_CLI_SHA256
                        and isinstance(inputs, dict)
                        and all(inputs.get(name) == _sha256_file(path)
                                for name, path in replay_paths.items()))
        return True, replay_valid
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return False, False


def summarize(output: Path, replay_path: Path, *,
              min_search_seconds: float = 600.0) -> dict:
    """Read receipts incrementally; trust trace equality only after fresh replay."""
    output = Path(output)
    report = json.loads((output / "report.json").read_bytes())
    replay = json.loads(Path(replay_path).read_bytes())
    durations = {name: [] for name in PHASES}
    runner_durations = {name: [] for name in RUNNER_PHASES}
    statuses: dict[str, int] = {}
    case_count = timed_case_count = runner_timed_case_count = consistent_case_count = 0
    violated_cases = checker_evidence_count = 0
    with (output / "receipts.jsonl").open(encoding="utf-8") as receipts:
        for line in receipts:
            row = json.loads(line)
            case_count += 1
            status = row["status"]
            statuses[status] = statuses.get(status, 0) + 1
            violations = row.get("violations")
            if isinstance(violations, list):
                checker_evidence_count += 1
                violated_cases += bool(violations)
            timing = row.get("online_phase_timing_seconds")
            if _valid_timing(timing, PHASES):
                timed_case_count += 1
                for name in PHASES:
                    durations[name].append(float(timing[name]))
            runner_timing = row.get("online_runner_timing_seconds")
            if _valid_timing(runner_timing, RUNNER_PHASES):
                runner_timed_case_count += 1
                for name in RUNNER_PHASES:
                    runner_durations[name].append(float(runner_timing[name]))
            if _valid_timing(timing, PHASES) and _valid_timing(runner_timing, RUNNER_PHASES):
                total = timing["total"]
                submit = timing["rtl_submit"]
                scheduler = runner_timing["scheduler_batch"]
                runner = runner_timing["runner_step"]
                if (total > 0 and submit > 0 and scheduler > 0 and runner > 0
                        and sum(timing[name] for name in PHASES if name != "total")
                        <= total + 1e-6
                        and submit <= total + 1e-6
                        and runner <= scheduler + 1e-6
                        and scheduler <= submit + 1e-6
                        and all(runner_timing[name] <= runner + 1e-6
                                for name in RUNNER_PHASES
                                if name not in ("scheduler_batch", "runner_step"))):
                    consistent_case_count += 1
    trace_meta = output / "online_final_trace.meta.json"
    trace_json = output / "online_final_trace.json"
    if trace_meta.is_file():
        metadata = json.loads(trace_meta.read_bytes())
        if metadata.get("schema_version") == "online_trace_zlib_chunks.v1":
            trace_format = "zlib_chunks.v1"
            event_file = "online_events.zlib"
        else:
            trace_format = "jsonl.v1"
            event_file = "online_events.jsonl"
        trace_present = (metadata.get("events_file") in (None, event_file)
                         and (output / event_file).is_file()
                         and (output / event_file).stat().st_size > 0)
        event_count = metadata.get("event_count")
        semantic_sha256 = metadata.get("semantic_sha256")
    elif trace_json.is_file():
        # Small traces have no separate metadata. This path reads only small runs.
        trace = json.loads(trace_json.read_bytes())
        trace_present = True
        trace_format = "json.v1"
        event_file = None
        event_count = len(trace.get("events", []))
        semantic_sha256 = trace.get("semantic_sha256")
    else:
        trace_present = False
        trace_format = None
        event_file = None
        event_count = semantic_sha256 = None
    trace_integrity = False
    if trace_present and trace_format == "zlib_chunks.v1" and type(event_count) is int:
        try:
            view = ZlibChunkEventView(output / event_file, event_count)
            view.verify_trace_semantic(status=metadata["status"],
                                       local_ticks=metadata["local_ticks"],
                                       expected_sha256=semantic_sha256)
            trace_integrity = True
        except (OSError, ValueError, TypeError, KeyError):
            pass
    elif trace_present:
        trace_integrity = True
    identity_valid, replay_inputs_valid = _identity_valid(
        output, report, replay, trace_format, event_file) if event_file else (False, False)
    search_seconds = report.get("effective_search_seconds")
    valid_search = (type(search_seconds) in (float, int)
                    and math.isfinite(search_seconds) and search_seconds > 0)
    finalization = report.get("finalization_timing_seconds", {})
    valid_finalization = (isinstance(finalization, dict) and all(
        type(finalization.get(name)) in (int, float)
        and math.isfinite(finalization[name]) and finalization[name] >= 0
        for name in FINALIZATION_PHASES)
        and finalization["total_before_report"] + 1e-6 >= sum(
            finalization[name] for name in FINALIZATION_PHASES
            if name != "total_before_report"))
    elapsed = report.get("elapsed_seconds")
    duration = None
    try:
        envelope = json.loads((output / "online_run_identity.json").read_bytes())
        duration = envelope["identity"]["run_config"]["duration_seconds"]
    except (OSError, ValueError, TypeError, KeyError):
        pass
    wall_seconds = None
    try:
        wall_path = (output.parent / "run-time.txt")
        if not wall_path.is_file():
            wall_path = output / "run-time.txt"
        for line in wall_path.read_text().splitlines():
            if line.startswith("run_wall_seconds="):
                wall_seconds = float(line.partition("=")[2])
    except (OSError, ValueError):
        pass
    valid_budget_evidence = (valid_search and type(elapsed) in (int, float)
                             and math.isfinite(elapsed) and elapsed >= search_seconds
                             and type(duration) in (int, float) and duration >= min_search_seconds
                             and type(wall_seconds) in (int, float)
                             and math.isfinite(wall_seconds)
                             and wall_seconds >= elapsed + finalization.get(
                                 "total_before_report", 0))
    checks = {
        "execution_complete": report.get("execution_status") == "complete",
        "case_count": report.get("tests") == case_count and case_count > 0,
        "status_accounting": report.get("statuses") == statuses,
        "all_cases_complete": statuses == {"complete": case_count},
        "all_case_timings": timed_case_count == case_count,
        "all_runner_timings": runner_timed_case_count == case_count,
        "timing_consistency": consistent_case_count == case_count,
        "checker_evidence": checker_evidence_count == case_count,
        "no_checker_violations": violated_cases == 0,
        "search_budget": (valid_search and search_seconds >= min_search_seconds
                          and valid_budget_evidence),
        "finalization_timings": valid_finalization,
        "trace_artifact": trace_present and type(event_count) is int
                          and event_count > 0,
        "trace_integrity": trace_integrity,
        "semantic_sha256": _is_digest(semantic_sha256),
        "run_identity": identity_valid,
        "online_plan": (output / "online_plan.json").is_file(),
        "fresh_replay": (replay.get("matches") is True
                         and replay.get("first_difference") is None),
        "replay_inputs": replay_inputs_valid,
    }
    failed_checks = [name for name, passed in checks.items() if not passed]
    return {
        "gate_passed": not failed_checks,
        "failed_checks": failed_checks,
        "case_count": case_count,
        "timed_case_count": timed_case_count,
        "runner_timed_case_count": runner_timed_case_count,
        "consistent_case_count": consistent_case_count,
        "checker_evidence_count": checker_evidence_count,
        "statuses": statuses,
        "violated_cases": violated_cases,
        "effective_search_seconds": search_seconds,
        "cases_per_search_second": (case_count / search_seconds if valid_search else None),
        "phase_seconds": _phase_summary(durations),
        "runner_phase_seconds": _phase_summary(runner_durations),
        "finalization_seconds": finalization,
        "evidence": {"trace_format": trace_format, "event_count": event_count,
                     "semantic_sha256": semantic_sha256,
                     "online_run_identity_sha256": report.get("online_run_identity_sha256"),
                     "fresh_replay_matches": replay.get("matches") is True,
                     "fresh_replay_first_difference": replay.get("first_difference")},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay-result", type=Path, required=True)
    parser.add_argument("--min-search-seconds", type=float, default=600.0)
    args = parser.parse_args(argv)
    summary = summarize(args.output, args.replay_result,
                        min_search_seconds=args.min_search_seconds)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0 if summary["gate_passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
