"""P5 timing summaries must preserve failed-case and replay evidence."""

import json
import hashlib
from pathlib import Path
import struct
import tempfile
import zlib

import pytest

from scripts.runs.summarize_p5_online_timing import summarize
from scripts.runs.replay_p5_online_verified import TRUSTED_CLI_SHA256


def _write_gate(root: Path, *, statuses=None, replay=True, seconds=600.0):
    statuses = statuses or ["complete", "complete"]
    phases = ("selection_decode", "rtl_submit", "trace_digest",
              "interaction_ingest", "checker", "feedback_credit",
              "receipt_build")
    runner_phases = ("scheduler_batch", "runner_step", "router_enqueue",
                     "router_drain", "router_transact", "observed_output_route")
    with (root / "receipts.jsonl").open("w") as handle:
        for index, status in enumerate(statuses):
            timing = {name: 0.01 * (index + 1) for name in phases}
            timing["total"] = sum(timing.values()) + 0.001
            handle.write(json.dumps({"status": status, "violations": [],
                                     "online_phase_timing_seconds": timing,
                                     "online_runner_timing_seconds": {
                                         name: 0.001 * (index + 1)
                                         for name in runner_phases}}) + "\n")
    report = {
        "tests": len(statuses), "statuses": {s: statuses.count(s) for s in set(statuses)},
        "execution_status": "complete", "effective_search_seconds": seconds,
        "elapsed_seconds": seconds,
        "finalization_timing_seconds": {"session_finish": 1.0,
            "plan_write": 0.1, "trace_write": 2.0,
            "identity_write": 0.3, "total_before_report": 3.5}}
    (root / "online_plan.json").write_text("{}")
    (root / "online_final_trace.meta.json").write_text(json.dumps({
        "event_count": 42, "semantic_sha256": "b" * 64}))
    (root / "online_events.jsonl").write_text("{}\n")
    _bind_evidence(root, report, replay)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bind_evidence(root: Path, report: dict, replay: bool = True):
    identity = {"schema_version": "scenario_online_run_identity.v1",
                "run_config": {"duration_seconds": report["effective_search_seconds"]},
                "trace_format": ("zlib_chunks.v1" if (root / "online_events.zlib").exists()
                                 else "jsonl.v1"),
                "genome": {"plan_sha256": _sha(root / "online_plan.json")},
                "artifacts": {name: _sha(root / name) for name in (
                    "online_plan.json", "online_final_trace.meta.json",
                    "online_events.zlib" if (root / "online_events.zlib").exists()
                    else "online_events.jsonl")}}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    (root / "online_run_identity.json").write_text(json.dumps({
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": digest, "identity": identity}))
    report["online_run_identity_sha256"] = digest
    (root / "report.json").write_text(json.dumps(report))
    (root / "run-time.txt").write_text(
        f"run_wall_seconds={report['effective_search_seconds'] + 4}\n")
    (root / "snapshot.sha256").write_text("fixture manifest\n")
    (root / "replay.json").write_text(json.dumps({
        "matches": replay, "first_difference": None if replay else "events[0]",
        "replay_exit_code": 0 if replay else 2,
        "replay_cli_sha256": TRUSTED_CLI_SHA256,
        "inputs": {name: _sha(root / name) for name in (
            "online_plan.json", "online_final_trace.meta.json",
            "online_events.zlib" if (root / "online_events.zlib").exists()
            else "online_events.jsonl", "online_run_identity.json",
            "report.json", "run-time.txt", "snapshot.sha256")}}))


def _write_zlib_trace(root: Path):
    event = {"type": "example"}
    raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    compressed = zlib.compress(raw)
    (root / "online_events.zlib").write_bytes(
        b"MFZ1" + struct.pack("<IIII", len(compressed), len(raw), 1,
                             zlib.crc32(raw)) + compressed)
    semantic = hashlib.sha256(b'{"events":[' + raw.rstrip(b"\n") +
                              b'],"local_ticks":{},"status":"complete"}').hexdigest()
    (root / "online_final_trace.meta.json").write_text(json.dumps({
        "schema_version": "online_trace_zlib_chunks.v1", "event_count": 1,
        "status": "complete", "local_ticks": {},
        "semantic_sha256": semantic, "events_file": "online_events.zlib"}))


def test_gate_reports_percentiles_and_evidence_without_loading_event_body():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        result = summarize(root, root / "replay.json", min_search_seconds=600)
        assert result["gate_passed"] is True
        assert result["cases_per_search_second"] == pytest.approx(2 / 600)
        assert result["phase_seconds"]["rtl_submit"]["p50"] == pytest.approx(0.015)
        assert result["phase_seconds"]["rtl_submit"]["p95"] == pytest.approx(0.0195)
        assert result["runner_phase_seconds"]["scheduler_batch"]["p95"] == pytest.approx(0.00195)
        assert result["runner_timed_case_count"] == 2
        assert result["finalization_seconds"]["trace_write"] == 2.0
        assert result["evidence"]["event_count"] == 42
        assert result["evidence"]["fresh_replay_matches"] is True


@pytest.mark.parametrize("statuses,replay,seconds", [
    (["complete", "timeout"], True, 600),
    (["complete", "complete"], False, 600),
    (["complete", "complete"], True, 599),
])
def test_gate_rejects_incomplete_status_replay_or_search_budget(statuses, replay, seconds):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root, statuses=statuses, replay=replay, seconds=seconds)
        assert summarize(root, root / "replay.json", min_search_seconds=600)["gate_passed"] is False


def test_gate_rejects_missing_per_case_timing():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        rows = (root / "receipts.jsonl").read_text().splitlines()
        row = json.loads(rows[1])
        del row["online_phase_timing_seconds"]["rtl_submit"]
        (root / "receipts.jsonl").write_text(rows[0] + "\n" + json.dumps(row) + "\n")
        result = summarize(root, root / "replay.json", min_search_seconds=600)
        assert result["gate_passed"] is False
        assert result["timed_case_count"] == 1
        assert "all_case_timings" in result["failed_checks"]


def test_gate_names_failed_replay_check():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root, replay=False)
        assert "fresh_replay" in summarize(
            root, root / "replay.json", min_search_seconds=600)["failed_checks"]


def test_gate_requires_checker_field_on_every_receipt():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        rows = (root / "receipts.jsonl").read_text().splitlines()
        row = json.loads(rows[0])
        del row["violations"]
        (root / "receipts.jsonl").write_text(json.dumps(row) + "\n" + rows[1] + "\n")
        assert "checker_evidence" in summarize(
            root, root / "replay.json", min_search_seconds=600)["failed_checks"]


def test_gate_rejects_missing_runner_timing():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        rows = (root / "receipts.jsonl").read_text().splitlines()
        row = json.loads(rows[0])
        del row["online_runner_timing_seconds"]["router_drain"]
        (root / "receipts.jsonl").write_text(json.dumps(row) + "\n" + rows[1] + "\n")
        result = summarize(root, root / "replay.json")
        assert result["runner_timed_case_count"] == 1
        assert "all_runner_timings" in result["failed_checks"]


def test_gate_accepts_compressed_event_file_and_rejects_missing_body():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        (root / "online_events.jsonl").unlink()
        _write_zlib_trace(root)
        _bind_evidence(root, json.loads((root / "report.json").read_text()))
        accepted = summarize(root, root / "replay.json")
        assert accepted["gate_passed"] is True
        assert accepted["evidence"]["trace_format"] == "zlib_chunks.v1"
        metadata = json.loads((root / "online_final_trace.meta.json").read_text())
        metadata["semantic_sha256"] = "0" * 64
        (root / "online_final_trace.meta.json").write_text(json.dumps(metadata))
        assert "trace_integrity" in summarize(root, root / "replay.json")["failed_checks"]
        _write_zlib_trace(root)
        metadata["event_count"] = True
        (root / "online_final_trace.meta.json").write_text(json.dumps(metadata))
        assert "trace_artifact" in summarize(root, root / "replay.json")["failed_checks"]
        _write_zlib_trace(root)
        (root / "online_events.zlib").write_bytes(b"MFZ1")
        assert "trace_integrity" in summarize(root, root / "replay.json")["failed_checks"]
        (root / "online_events.zlib").unlink()
        assert "trace_artifact" in summarize(root, root / "replay.json")["failed_checks"]


def test_gate_rejects_old_replay_bound_to_other_plan():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        replay = json.loads((root / "replay.json").read_text())
        replay["inputs"]["online_plan.json"] = "0" * 64
        (root / "replay.json").write_text(json.dumps(replay))
        assert "replay_inputs" in summarize(root, root / "replay.json")["failed_checks"]


def test_gate_rejects_zero_and_inconsistent_timing():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        rows = (root / "receipts.jsonl").read_text().splitlines()
        row = json.loads(rows[0])
        row["online_phase_timing_seconds"]["total"] = 0
        row["online_runner_timing_seconds"]["runner_step"] = 1.0
        (root / "receipts.jsonl").write_text(json.dumps(row) + "\n" + rows[1] + "\n")
        assert "timing_consistency" in summarize(root, root / "replay.json")["failed_checks"]


def test_gate_rejects_finalization_total_below_parts():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        report = json.loads((root / "report.json").read_text())
        report["finalization_timing_seconds"]["total_before_report"] = 1.0
        (root / "report.json").write_text(json.dumps(report))
        assert "finalization_timings" in summarize(root, root / "replay.json")["failed_checks"]


def test_gate_rejects_report_replacement_after_verified_replay():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        _write_gate(root)
        report = json.loads((root / "report.json").read_text())
        report["effective_search_seconds"] = 999
        (root / "report.json").write_text(json.dumps(report))
        assert "replay_inputs" in summarize(root, root / "replay.json")["failed_checks"]
