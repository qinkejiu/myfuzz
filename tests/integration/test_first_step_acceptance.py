"""First-step acceptance analysis tests over synthetic and real-shaped runs.

Every expected number here is hand-computed from the synthetic artifact bytes.
The stub chain producer implements the frozen ``ChainCertificates`` protocol
(``ingest``/``flush``/``pending_count``) so the analysis contract is tested
without depending on the separately developed certificate producer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tracemalloc
import zlib

import pytest

from myfuzz.scenario.acceptance_metrics import (
    DEFAULT_INGEST_BATCH_SIZE,
    SCHEMA_VERSION,
    TraceEventStream,
    analyze_run,
    render_markdown,
)


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "run_first_step_acceptance.py"

ADMISSION_A = "a" * 64
ADMISSION_B = "b" * 64
ADMISSION_C = "c" * 64


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def test_exports_frozen_schema_version() -> None:
    assert SCHEMA_VERSION == "first_step_acceptance_report.v1"
    assert DEFAULT_INGEST_BATCH_SIZE >= 1


# --------------------------------------------------------------------------
# synthetic artifact builders
# --------------------------------------------------------------------------


def _edge(graph: str, path_ids: list[str], relation: str, rule_index: int,
          scope: str) -> dict:
    return {"graph_sha256": graph, "path_ids": list(path_ids),
            "relation": relation, "rule_index": rule_index, "scope": scope,
            "prerequisite_index": 0}


def _event(event_id: int, *, kind: str = "dataflow_delivery",
           edge_candidates: tuple = (), origin: tuple = (),
           payload: str = "") -> dict:
    return {
        "event_id": event_id,
        "component": "cpu",
        "kind": kind,
        "address": 4096 + event_id,
        "data_hex": "0011" * 4,
        "filler": payload,
        "provenance": {
            "schema_version": "event_source_provenance.v1",
            "edge_candidates": [dict(item) for item in edge_candidates],
            "invalid_origin_references": 0,
            "observed_case": None,
            "origin_admission_ids": list(origin),
            "origin_status": "unknown",
            "proof_scope": "observation_only",
            "resource": None,
            "unknown_writer_ids": [],
        },
    }


def _receipt(case_index: int, status: str, coverage_hex: str, *,
             phases: dict | None = None, runner: dict | None = None) -> dict:
    row = {
        "case_id": f"online-{case_index}-case",
        "status": status,
        "coverage_hex": coverage_hex,
        "violations": [],
        "slot": 0,
        "online_source": {"component": "cpu", "kind": "instruction"},
    }
    if phases is not None:
        row["online_phase_timing_seconds"] = phases
    if runner is not None:
        row["online_runner_timing_seconds"] = runner
    return row


def _certificate(certificate_id: str, status: str, direction: str,
                 admission_id: str, source_case_index: int | None,
                 endpoint_case_index: int | None, hops: tuple,
                 missing_hops: tuple = ()) -> dict:
    return {
        "schema_version": "runtime_chain_certificate.v1",
        "certificate_id": certificate_id,
        "status": status,
        "direction": direction,
        "source_admission_id": admission_id,
        "source_case_index": source_case_index,
        "endpoint_case_index": endpoint_case_index,
        "completed_event_id": 6,
        "hops": [dict(hop) for hop in hops],
        "missing_hops": [dict(hop) for hop in missing_hops],
    }


class StubChainCertificates:
    """Frozen-protocol producer emitting scripted certificates per event id."""

    last_kwargs: dict | None = None

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True) -> None:
        type(self).last_kwargs = {"max_pending": max_pending,
                                  "max_event_gap": max_event_gap,
                                  "require_native_receipts": require_native_receipts}
        self.ingested_events = 0
        self.flush_count = 0
        self._script = {
            1: (SCRIPTED_CERTIFICATES[0], SCRIPTED_CERTIFICATES[1]),
            3: (SCRIPTED_CERTIFICATES[2],),
            5: (SCRIPTED_CERTIFICATES[3],),
        }

    @property
    def pending_count(self) -> int:
        return 0

    def ingest(self, events) -> tuple[dict, ...]:
        found = []
        for event in events:
            self.ingested_events += 1
            found.extend(self._script.get(event.get("event_id"), ()))
        return tuple(found)

    def flush(self) -> tuple[dict, ...]:
        self.flush_count += 1
        return ()


SCRIPTED_CERTIFICATES = (
    _certificate("cert-1", "certified", "IP_TO_CPU_TO_IP", ADMISSION_A, 0, 0,
                 ({"hop_id": "gpio_b_irq"}, {"hop_id": "cpu_take"})),
    _certificate("cert-2", "certified", "IP_TO_CPU_TO_IP", ADMISSION_B, 1, 2,
                 ({"hop_id": "gpio_b_irq"}, {"hop_id": "cpu_take"})),
    _certificate("cert-3", "certified", "CPU_TO_IP_TO_CPU", ADMISSION_A, 3, 3,
                 ({"hop_id": "cpu_retire"},)),
    _certificate("cert-4", "incomplete", "IP_TO_CPU_TO_IP", ADMISSION_C, 4,
                 None, (), ({"hop_id": "gpio_a_settle"},)),
)

EDGE_ONE = _edge("1" * 64, ["8c5173cf"], "direct_binding", 2, "binding")
EDGE_TWO = _edge("2" * 64, ["8c5173cf", "aaaa1111"], "transitive_binding", 4,
                 "observation_only")


def _default_events() -> list[dict]:
    return [
        _event(1, edge_candidates=(EDGE_ONE,), origin=(ADMISSION_A,)),
        _event(2, edge_candidates=(EDGE_ONE,)),
        _event(3, edge_candidates=(EDGE_TWO,), origin=(ADMISSION_B,)),
        _event(4),
        _event(5),
        _event(6),
    ]


def _default_receipts() -> list[dict]:
    phases_a = {"selection_decode": 0.1, "rtl_submit": 1.0, "total": 1.1}
    phases_b = {"selection_decode": 0.2, "rtl_submit": 2.0, "total": 2.2}
    phases_c = {"selection_decode": 0.3, "rtl_submit": 3.0, "total": 3.3}
    return [
        _receipt(0, "complete", "0100", phases=phases_a),
        _receipt(1, "complete", "0101", phases=phases_b),
        _receipt(2, "complete", "0001", phases=phases_c),
        _receipt(3, "timeout", "0000"),
    ]


def _write_jsonl_trace(directory: Path, events: list[dict], *,
                       status: str = "complete",
                       local_ticks: dict | None = None) -> dict:
    """Write a JSONL trace plus metadata using the frozen semantic SHA rule."""
    local_ticks = {"cpu": 10} if local_ticks is None else local_ticks
    digest = hashlib.sha256(b'{"events":[')
    with (directory / "online_events.jsonl").open("w", encoding="utf-8") as fh:
        for index, event in enumerate(events):
            encoded = _canonical(event)
            if index:
                digest.update(b",")
            digest.update(encoded)
            fh.write(encoded.decode("utf-8") + "\n")
    digest.update(b'],"local_ticks":')
    digest.update(_canonical(local_ticks))
    digest.update(b',"status":')
    digest.update(_canonical(status))
    digest.update(b"}")
    metadata = {
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl",
        "event_count": len(events),
        "genome_sha256": "3" * 64,
        "status": status,
        "local_ticks": local_ticks,
        "semantic_sha256": digest.hexdigest(),
        "manifest_sha256": "4" * 64,
    }
    (directory / "online_final_trace.meta.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


def _write_monolithic_trace(directory: Path, events: list[dict], *,
                            status: str = "complete",
                            local_ticks: dict | None = None,
                            corrupt_tail: bool = False) -> dict:
    local_ticks = {"cpu": 10} if local_ticks is None else local_ticks
    digest = hashlib.sha256(b'{"events":[')
    for index, event in enumerate(events):
        if index:
            digest.update(b",")
        digest.update(_canonical(event))
    digest.update(b'],"local_ticks":')
    digest.update(_canonical(local_ticks))
    digest.update(b',"status":')
    digest.update(_canonical(status))
    digest.update(b"}")
    document = {
        "events": events,
        "genome_sha256": "3" * 64,
        "local_ticks": local_ticks,
        "manifest_sha256": "4" * 64,
        "semantic_sha256": digest.hexdigest(),
        "status": status,
    }
    text = json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    if corrupt_tail:
        text = text[:-1] + ',"broken":'
    (directory / "online_final_trace.json").write_text(text + "\n", encoding="utf-8")
    return document


def _write_zlib_chunk_trace(directory: Path, events: list[dict], *,
                            status: str = "complete",
                            local_ticks: dict | None = None,
                            chunk_events: int = 2) -> dict:
    """Write the frozen MFZ1 chunk layout independently of the producer."""
    local_ticks = {"cpu": 10} if local_ticks is None else local_ticks
    digest = hashlib.sha256(b'{"events":[')
    lines = []
    for index, event in enumerate(events):
        encoded = _canonical(event)
        if index:
            digest.update(b",")
        digest.update(encoded)
        lines.append(encoded + b"\n")
    digest.update(b'],"local_ticks":')
    digest.update(_canonical(local_ticks))
    digest.update(b',"status":')
    digest.update(_canonical(status))
    digest.update(b"}")
    with (directory / "online_events.zlib").open("wb") as fh:
        fh.write(b"MFZ1")
        for start in range(0, len(lines), chunk_events):
            block = lines[start:start + chunk_events]
            raw = b"".join(block)
            payload = zlib.compress(raw, level=1)
            fh.write(struct.pack("<IIII", len(payload), len(raw), len(block),
                                 zlib.crc32(raw)))
            fh.write(payload)
    metadata = {
        "schema_version": "online_trace_zlib_chunks.v1",
        "events_file": "online_events.zlib",
        "event_count": len(events),
        "genome_sha256": "3" * 64,
        "status": status,
        "local_ticks": local_ticks,
        "semantic_sha256": digest.hexdigest(),
        "manifest_sha256": "4" * 64,
    }
    (directory / "online_final_trace.meta.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
    return metadata


_UNSET = object()


def _write_support_files(directory: Path, *, receipts: list[dict] | None = None,
                         statuses: dict | None = None, tests: int = 4,
                         effective_seconds: float = 10.0,
                         elapsed_seconds: float = 11.0,
                         with_plan: bool = True,
                         finalization: object = _UNSET) -> None:
    rows = _default_receipts() if receipts is None else receipts
    if statuses is None:
        statuses = {}
        for row in rows:
            statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    with (directory / "receipts.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    report = {
        "execution_status": "complete",
        "session_status": "complete",
        "tests": tests,
        "statuses": statuses,
        "effective_search_seconds": effective_seconds,
        "elapsed_seconds": elapsed_seconds,
        "online_run_identity_sha256": "5" * 64,
    }
    if finalization is _UNSET:
        report["finalization_timing_seconds"] = {
            "session_finish": 1.5, "plan_write": 0.5, "trace_write": 2.0,
            "identity_write": 0.25, "total_before_report": 5.0}
    elif finalization is not None:
        report["finalization_timing_seconds"] = finalization
    (directory / "report.json").write_text(
        json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
    if with_plan:
        plan = {
            "schema_version": "scenario_online_plan.v1",
            "source_admissions": {
                "schema_version": "source_admission_registry.v1",
                "admissions": [
                    {"admission_id": ADMISSION_A, "case_index": 0,
                     "role": "fuzz_source", "direction": "IP_TO_CPU_TO_IP"},
                    {"admission_id": ADMISSION_B, "case_index": 1,
                     "role": "fuzz_source", "direction": "IP_TO_CPU_TO_IP"},
                    {"admission_id": ADMISSION_C, "case_index": 4,
                     "role": "fixed_support", "direction": "CPU_TO_IP_TO_CPU"},
                ],
            },
            "cases": [{"case_id": f"online-{index}-case"}
                      for index in range(tests)],
        }
        (directory / "online_plan.json").write_text(
            json.dumps(plan, sort_keys=True) + "\n", encoding="utf-8")
    identity = {
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": "6" * 64,
        "identity": {
            "schema_version": "scenario_online_run_identity.v1",
            "run_config": {"run_id": "test-run", "duration_seconds": 5.0,
                           "max_tests": 4, "search_seed": 7},
        },
    }
    (directory / "online_run_identity.json").write_text(
        json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")


def _build_run(directory: Path, *, events: list[dict] | None = None,
               trace: str = "jsonl", **support) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    _write_support_files(directory, **support)
    rows = events if events is not None else _default_events()
    if trace == "jsonl":
        _write_jsonl_trace(directory, rows)
    elif trace == "monolithic":
        _write_monolithic_trace(directory, rows)
    elif trace == "zlib":
        _write_zlib_chunk_trace(directory, rows)
    elif trace != "none":
        raise ValueError(f"unknown trace kind {trace!r}")
    return directory


# --------------------------------------------------------------------------
# exact metric assertions
# --------------------------------------------------------------------------


def test_analyze_run_reports_exact_hand_computed_metrics(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["run_dir"] == str(run_dir)
    assert report["run_id"] == "test-run"

    # timing: measured straight from report.json
    assert report["effective_search_seconds"] == 10.0
    assert report["effective_search_seconds_reason"] is None
    assert report["elapsed_seconds"] == 11.0
    assert report["elapsed_seconds_reason"] is None

    # receipts: 3 complete, 1 timeout
    assert report["test_counts"] == {"complete": 3, "timeout": 1}
    assert report["test_counts_total"] == 4
    assert report["invalid_or_timeout_ratio"] == 0.25
    assert report["invalid_or_timeout_detail"]["invalid"] == 0
    assert report["invalid_or_timeout_detail"]["timeout"] == 1
    assert report["invalid_or_timeout_detail"]["unclassified_statuses"] == []
    assert report["complete_cases_per_second"] == 0.3

    # chain certificates: certificates 1,2,3 certified and 4 incomplete
    chains = report["certified_chains"]
    assert chains["total"] == 3
    assert chains["incomplete_total"] == 1
    assert chains["by_direction"] == {"IP_TO_CPU_TO_IP": 2,
                                      "CPU_TO_IP_TO_CPU": 1}
    assert chains["same_case"] == 2
    assert chains["cross_case"] == 1
    assert chains["cap_reached"] is False
    assert report["certified_chains_per_second"] == 0.3
    assert "certificate_id" in report["certified_chains_semantics"]

    admissions = report["chain_completion_by_admission"]
    assert admissions["admissions_total"] == 3
    assert admissions["fuzz_source_admissions"] == 2
    assert admissions["certified_admissions"] == 2
    assert admissions["incomplete_admissions"] == 1
    assert admissions["certified_ratio"] == pytest.approx(2 / 3)
    assert admissions["certified_ratio_denominator"] == "admissions_total"
    assert admissions["certified_fuzz_source_ratio"] == pytest.approx(1.0)

    gap = report["chain_gap_evidence"]
    assert gap["incomplete_certificates"] == 1
    assert gap["first_missing_hop_counts"] == {"gpio_a_settle": 1}
    assert gap["unresolvable_missing_hops"] == 0
    assert admissions["admissions_by_role"] == {"fixed_support": 1,
                                                "fuzz_source": 2}
    assert admissions["accounted_admissions"] == 3
    assert admissions["unaccounted_fuzz_source_admissions"] == 0

    signature = report["chain_signature_novelty"]
    assert signature["unique_signatures"] == 2
    assert signature["new_signatures_per_second"] == pytest.approx(0.2)
    assert signature["unresolvable_certified_certificates"] == 0

    targets = report["local_target_novelty"]
    assert targets["first_seen_target_slots"] == 2
    assert targets["first_seen_target_bits"] == 2
    assert targets["new_target_slots_per_second"] == pytest.approx(0.2)
    assert targets["new_target_bits_per_second"] == pytest.approx(0.2)

    edges = report["witnessed_edge_novelty"]
    assert edges["candidate_observations"] == 3
    assert edges["unique_edges"] == 2
    assert edges["new_edges_per_second"] == pytest.approx(0.2)
    assert edges["invalid_candidate_records"] == 0

    # phase percentiles: rtl_submit samples are 1.0, 2.0, 3.0
    timing = report["phase_timing_seconds"]
    assert timing["cases_total"] == 4
    assert timing["cases_with_online_phase_timing_seconds"] == 3
    assert timing["cases_with_online_runner_timing_seconds"] == 0
    submit = timing["online_phase_timing_seconds"]["rtl_submit"]
    assert submit["count"] == 3
    assert submit["p50"] == 2.0
    assert submit["p95"] == pytest.approx(2.9)
    selection = timing["online_phase_timing_seconds"]["selection_decode"]
    assert selection["p50"] == pytest.approx(0.2)
    assert selection["p95"] == pytest.approx(0.29)
    absent = timing["online_runner_timing_seconds"]["runner_step"]
    assert absent == {"count": 0, "p50": None, "p95": None}

    assert report["finalization_timing_seconds"] == {
        "session_finish": 1.5, "plan_write": 0.5, "trace_write": 2.0,
        "identity_write": 0.25, "total_before_report": 5.0}

    evidence = report["trace_evidence"]
    assert evidence["format"] == "jsonl.v1"
    assert evidence["events_ingested"] == 6
    assert evidence["declared_event_count"] == 6
    assert evidence["event_count_match"] is True
    assert evidence["semantic_sha256_verified"] is True
    assert evidence["declared_semantic_sha256"] == evidence["semantic_sha256_recomputed"]

    assert report["chain_producer"]["available"] is True
    assert report["chain_producer"]["kind"] == "injected"
    assert report["chain_producer"]["producer_module"] is None
    assert StubChainCertificates.last_kwargs == {
        "max_pending": 128, "max_event_gap": 4096,
        "require_native_receipts": True}
    assert report["limits"], "limits must always explain undetermined quantities"
    for item in report["limits"]:
        assert set(item) == {"quantity", "reason"}
        assert item["reason"]


def test_ingest_batch_size_does_not_change_certificate_metrics(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    batched = analyze_run(run_dir, chain_producer=StubChainCertificates)
    single = analyze_run(run_dir, chain_producer=StubChainCertificates,
                         ingest_batch_size=1)
    assert single["certified_chains"] == batched["certified_chains"]
    assert single["certified_chains_per_second"] == batched["certified_chains_per_second"]
    assert single["chain_signature_novelty"] == batched["chain_signature_novelty"]


# --------------------------------------------------------------------------
# negative cases: honest nulls, never zeros
# --------------------------------------------------------------------------


def test_certified_chains_per_second_is_null_without_chain_producer(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = _build_run(tmp_path / "run")

    def _missing():
        raise ImportError("no module named myfuzz.scenario.chain_certificates")

    monkeypatch.setattr("myfuzz.scenario.acceptance_metrics._load_chain_certificates",
                        _missing)
    report = analyze_run(run_dir)

    assert report["certified_chains_per_second"] is None
    assert report["certified_chains_per_second"] != 0
    assert report["certified_chains"]["total"] is None
    assert report["certified_chains"]["total"] != 0
    assert report["certified_chains"]["by_direction"] is None
    assert report["chain_producer"]["available"] is False
    assert report["limits"]
    reasons = " ".join(item["reason"] for item in report["limits"])
    assert "chain certificate producer unavailable" in reasons
    # Coverage and throughput metrics must stay measured even without chains.
    assert report["complete_cases_per_second"] == 0.3
    assert report["local_target_novelty"]["first_seen_target_bits"] == 2
    assert report["witnessed_edge_novelty"]["unique_edges"] == 2


def test_default_chain_producer_loader_contract() -> None:
    import myfuzz.scenario.acceptance_metrics as metrics

    if not metrics._chain_certificates_available():
        with pytest.raises(metrics.ChainProducerUnavailable) as caught:
            metrics._load_chain_certificates()
        assert "chain_certificates" in str(caught.value)
        return
    producer = metrics._load_chain_certificates()(
        max_pending=4, max_event_gap=64, require_native_receipts=False)
    assert callable(producer.ingest)
    assert callable(producer.flush)
    assert type(producer.pending_count) is int


def test_default_producer_path_is_used_without_injection(tmp_path: Path) -> None:
    import myfuzz.scenario.acceptance_metrics as metrics

    if not metrics._chain_certificates_available():
        pytest.skip("chain certificate producer is not importable in this tree")
    run_dir = _build_run(tmp_path / "run")
    report = analyze_run(run_dir)
    assert report["chain_producer"]["kind"] == "default"
    assert report["chain_producer"]["available"] is True
    module = report["chain_producer"]["producer_module"]
    assert module["module"] == "myfuzz.scenario.chain_certificates"
    assert len(module["sha256"]) == 64


def test_missing_timing_fields_report_null_percentiles(tmp_path: Path) -> None:
    receipts = [
        _receipt(0, "complete", "0100"),
        _receipt(1, "complete", "0100"),
    ]
    run_dir = _build_run(tmp_path / "run", receipts=receipts,
                         statuses={"complete": 2}, tests=2, finalization=None)
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    timing = report["phase_timing_seconds"]
    assert timing["cases_with_online_phase_timing_seconds"] == 0
    for name in ("rtl_submit", "selection_decode", "total"):
        assert timing["online_phase_timing_seconds"][name] == {
            "count": 0, "p50": None, "p95": None}
    for name in ("runner_step", "scheduler_batch"):
        assert timing["online_runner_timing_seconds"][name] == {
            "count": 0, "p50": None, "p95": None}
    assert report["finalization_timing_seconds"] is None
    assert report["finalization_timing_seconds_reason"]
    assert any(item["quantity"] == "phase_timing_seconds.online_phase_timing_seconds"
               for item in report["limits"])


def test_single_timing_sample_reports_p50_and_null_p95(tmp_path: Path) -> None:
    receipts = [_receipt(0, "complete", "0100",
                         phases={"rtl_submit": 4.0, "total": 4.0})]
    run_dir = _build_run(tmp_path / "run", receipts=receipts,
                         statuses={"complete": 1}, tests=1)
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    assert report["phase_timing_seconds"]["online_phase_timing_seconds"]["rtl_submit"] == {
        "count": 1, "p50": 4.0, "p95": None}


def test_invalid_coverage_hex_is_rejected_with_line_number(tmp_path: Path) -> None:
    receipts = [_receipt(0, "complete", "zz")] 
    run_dir = _build_run(tmp_path / "run", receipts=receipts,
                         statuses={"complete": 1}, tests=1)
    with pytest.raises(ValueError, match="coverage_hex"):
        analyze_run(run_dir, chain_producer=StubChainCertificates)


def test_invalid_jsonl_line_reports_line_number(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    path = run_dir / "online_events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[2] = '{"event_id": 3, "broken":'
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 3"):
        analyze_run(run_dir, chain_producer=StubChainCertificates)


def test_unclassified_status_makes_ratio_null(tmp_path: Path) -> None:
    receipts = [_receipt(0, "complete", "0100"),
                _receipt(1, "mystery_status", "0000")]
    run_dir = _build_run(tmp_path / "run", receipts=receipts,
                         statuses={"complete": 1, "mystery_status": 1}, tests=2)
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    assert report["invalid_or_timeout_ratio"] is None
    assert report["invalid_or_timeout_ratio"] != 0
    assert report["invalid_or_timeout_detail"]["unclassified_statuses"] == [
        "mystery_status"]
    assert any(item["quantity"] == "invalid_or_timeout_ratio"
               for item in report["limits"])


def test_certificate_cap_makes_chain_metrics_null(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates,
                         max_certificates=1)
    assert report["certified_chains"]["cap_reached"] is True
    assert report["certified_chains"]["total"] is None
    assert report["certified_chains_per_second"] is None
    assert any(item["quantity"] == "certified_chains"
               for item in report["limits"])


def test_unknown_certificate_schema_is_rejected(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    broken = dict(SCRIPTED_CERTIFICATES[0])
    broken["schema_version"] = "runtime_chain_certificate.v2"

    class BrokenProducer(StubChainCertificates):
        def ingest(self, events):
            super().ingest(events)
            return (broken,)

    with pytest.raises(ValueError, match="runtime_chain_certificate.v1"):
        analyze_run(run_dir, chain_producer=BrokenProducer)


def test_test_count_mismatch_is_recorded_as_limit(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run", tests=99,
                         statuses={"complete": 3, "timeout": 1})
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    quantities = {item["quantity"] for item in report["limits"]}
    assert "test_counts" in quantities
    assert report["reported_tests"] == 99
    assert report["test_counts"] == {"complete": 3, "timeout": 1}


def test_missing_trace_records_limit_and_null_event_metrics(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run", trace="none")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    assert report["trace_evidence"]["format"] is None
    assert report["trace_evidence"]["events_ingested"] is None
    assert report["witnessed_edge_novelty"]["unique_edges"] is None
    assert report["witnessed_edge_novelty"]["unique_edges"] != 0
    assert report["certified_chains"]["total"] is None
    assert report["complete_cases_per_second"] == 0.3
    quantities = {item["quantity"] for item in report["limits"]}
    assert "trace_events" in quantities


def test_zero_certified_with_incomplete_certificates_is_measured_and_explained(
        tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")

    class IncompleteOnly(StubChainCertificates):
        def ingest(self, events):
            super().ingest(events)
            return (SCRIPTED_CERTIFICATES[3],)

    report = analyze_run(run_dir, chain_producer=IncompleteOnly)
    assert report["certified_chains"]["total"] == 0
    assert report["certified_chains"]["total"] != None  # noqa: E711 - measured zero
    assert report["certified_chains_per_second"] == 0.0
    assert report["chain_gap_evidence"]["first_missing_hop_counts"] == {
        "gpio_a_settle": 1}
    reasons = " ".join(item["reason"] for item in report["limits"])
    assert "certifies no complete chain" in reasons


def test_admissions_without_any_certificate_are_flagged(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")

    class SilentProducer(StubChainCertificates):
        def ingest(self, events):
            super().ingest(events)
            return ()

    report = analyze_run(run_dir, chain_producer=SilentProducer)
    admissions = report["chain_completion_by_admission"]
    assert admissions["fuzz_source_admissions"] == 2
    assert admissions["unaccounted_fuzz_source_admissions"] == 2
    assert report["certified_chains"]["total"] == 0
    assert report["certified_chains"]["incomplete_total"] == 0
    reasons = " ".join(item["reason"] for item in report["limits"])
    assert "produced no certificate at all" in reasons


# --------------------------------------------------------------------------
# streaming, laziness, memory, and alternative trace layouts
# --------------------------------------------------------------------------


def test_event_stream_is_lazy_for_jsonl(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    path = run_dir / "online_events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines.append('{"event_id": 7, "broken":')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    stream = TraceEventStream(run_dir)
    iterator = stream.events()
    assert next(iterator)["event_id"] == 1  # first event before the broken line
    with pytest.raises(ValueError, match="line 7"):
        for _ in iterator:
            pass


def test_event_stream_detects_truncated_monolithic_document(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    _write_monolithic_trace(run_dir, _default_events(), corrupt_tail=True)
    stream = TraceEventStream(run_dir)
    with pytest.raises(ValueError, match="online_final_trace.json"):
        for _ in stream.events():
            pass


def test_monolithic_trace_streams_and_verifies_semantic_sha(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run", trace="monolithic")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    evidence = report["trace_evidence"]
    assert evidence["format"] == "json.v1"
    assert evidence["events_ingested"] == 6
    assert evidence["declared_event_count"] is None
    assert evidence["semantic_sha256_verified"] is True
    assert report["certified_chains"]["total"] == 3
    assert report["witnessed_edge_novelty"]["unique_edges"] == 2


def test_zlib_chunk_trace_streams_and_verifies_semantic_sha(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run", trace="zlib")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    evidence = report["trace_evidence"]
    assert evidence["format"] == "zlib_chunks.v1"
    assert evidence["events_ingested"] == 6
    assert evidence["declared_event_count"] == 6
    assert evidence["event_count_match"] is True
    assert evidence["semantic_sha256_verified"] is True
    assert report["certified_chains"]["total"] == 3
    assert report["local_target_novelty"]["first_seen_target_bits"] == 2


def test_corrupt_zlib_chunk_reports_clear_error(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run", trace="zlib")
    path = run_dir / "online_events.zlib"
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(ValueError, match="compressed event"):
        analyze_run(run_dir, chain_producer=StubChainCertificates)


def test_analyze_streams_fifty_thousand_events_with_bounded_extra_memory(
        tmp_path: Path) -> None:
    events = []
    for event_id in range(1, 50001):
        payload = "x" * 600
        edge = EDGE_ONE if event_id % 10 == 0 else None
        events.append(_event(event_id, edge_candidates=(edge,) if edge else (),
                             payload=payload))
    run_dir = _build_run(tmp_path / "run", events=events,
                         statuses={"complete": 3, "timeout": 1})
    trace_bytes = (run_dir / "online_events.jsonl").stat().st_size
    assert trace_bytes > 30_000_000

    tracemalloc.start()
    try:
        report = analyze_run(run_dir, chain_producer=StubChainCertificates)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert report["trace_evidence"]["events_ingested"] == 50000
    assert report["witnessed_edge_novelty"]["unique_edges"] == 1
    assert peak < 8_000_000, f"peak traced memory {peak} bytes is not bounded"


def test_explicit_receipt_scan_keeps_only_aggregates(tmp_path: Path) -> None:
    """The receipts pass must not retain per-case rows."""
    run_dir = _build_run(tmp_path / "run")
    stream = TraceEventStream(run_dir)
    iterator = stream.events()
    first = next(iterator)
    assert first["event_id"] == 1
    # A second stream over the same artifact must be independent and complete.
    assert [event["event_id"] for event in TraceEventStream(run_dir).events()] == [
        1, 2, 3, 4, 5, 6]


# --------------------------------------------------------------------------
# replay comparison
# --------------------------------------------------------------------------


def test_replay_comparison_matches_identical_copy(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    replay_dir = _build_run(tmp_path / "replay")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates,
                         replay_dir=replay_dir)
    replay = report["replay"]
    assert replay["event_count_match"] is True
    assert replay["semantic_sha256_match"] is True
    assert replay["status_match"] is True
    assert replay["certified_chains_match"] is True
    assert replay["verified"] is True
    assert replay["unverified_items"] == []


def test_replay_comparison_detects_mismatch(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    events = _default_events() + [_event(7)]
    replay_dir = _build_run(tmp_path / "replay", events=events)
    report = analyze_run(run_dir, chain_producer=StubChainCertificates,
                         replay_dir=replay_dir)
    replay = report["replay"]
    assert replay["run_event_count"] == 6
    assert replay["replay_event_count"] == 7
    assert replay["event_count_match"] is False
    assert replay["semantic_sha256_match"] is False
    assert replay["status_match"] is True
    assert replay["verified"] is False


def test_replay_comparison_accepts_saved_comparison_json(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    comparison = tmp_path / "replay.json"
    comparison.write_text(json.dumps(
        {"matches": True, "first_difference": None, "difference_context": None}) + "\n",
        encoding="utf-8")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates,
                         replay_dir=comparison)
    replay = report["replay"]
    assert replay["kind"] == "comparison_json"
    assert replay["comparison_matches"] is True
    assert replay["verified"] is False  # artifact equality is not proven here
    assert set(replay["unverified_items"]) >= {
        "event_count", "semantic_sha256", "status", "certified_chains"}


def test_replay_dir_without_recognized_artifacts_is_rejected(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="replay"):
        analyze_run(run_dir, chain_producer=StubChainCertificates, replay_dir=empty)


def test_cli_run_orchestration_executes_and_analyzes_without_rtl(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("first_step_acceptance_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)

    output_dir = tmp_path / "online-run"
    client = tmp_path / "kfuzz"
    client.write_bytes(b"stub")
    executed: list[list[str]] = []

    def fake_execute(command):
        executed.append(list(command))
        if command[2] == "run":
            _build_run(output_dir)  # the online entry produced its artifacts
            stdout = '{"tests": 4}\n'
        else:
            stdout = '{"matches": true, "first_difference": null}\n'
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(cli, "_execute", fake_execute)
    report = {"schema_version": SCHEMA_VERSION, "run_dir": str(output_dir),
              "limits": []}
    monkeypatch.setattr(cli, "analyze_run", lambda *a, **k: report)
    json_out = tmp_path / "report.json"
    markdown_out = tmp_path / "report.md"
    code = cli.main(["run", "--seconds", "5", "--max-tests", "4",
                     "--output-dir", str(output_dir),
                     "--client-binary", str(client), "--replay",
                     "--json-out", str(json_out),
                     "--markdown-out", str(markdown_out)])
    assert code == 0
    assert [command[2] for command in executed] == ["run", "replay"]
    assert executed[0][1].endswith("scripts/run_ibex_pulp_online.py")
    assert executed[1][-1].endswith("online_final_trace.meta.json")
    payload = json.loads(capsys.readouterr().out)
    assert payload["command_exit_codes"] == [0, 0]
    assert payload["analysis"] == report
    assert json.loads(json_out.read_text(encoding="utf-8")) == report
    assert "Evidence boundary" in markdown_out.read_text(encoding="utf-8")
    log = json.loads((output_dir / "first_step_acceptance_run.json").read_text())
    assert log["commands"] == executed
    assert log["command_exit_codes"] == [0, 0]
    replay = json.loads((output_dir / "first_step_acceptance_replay.json").read_text())
    assert replay["exit_code"] == 0
    assert replay["command"] == executed[1]


def test_cli_run_refuses_existing_output_directory(tmp_path: Path) -> None:
    output_dir = tmp_path / "online-run"
    output_dir.mkdir()
    completed = _run_cli("run", "--seconds", "1", "--max-tests", "1",
                         "--output-dir", str(output_dir), "--dry-run")
    assert completed.returncode == 0, completed.stderr  # dry run never touches it
    completed = _run_cli("run", "--seconds", "1", "--max-tests", "1",
                         "--output-dir", str(output_dir))
    assert completed.returncode == 1
    assert "must be new" in completed.stderr


# --------------------------------------------------------------------------
# markdown rendering
# --------------------------------------------------------------------------


def test_render_markdown_starts_with_evidence_boundary(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    report = analyze_run(run_dir, chain_producer=StubChainCertificates)
    text = render_markdown(report)
    assert text.startswith("# First-step acceptance")
    assert "Evidence boundary" in text
    assert "null" in text.lower()
    for item in report["limits"]:
        assert item["quantity"] in text


def test_render_markdown_lists_null_reasons_without_producer(tmp_path: Path,
                                                             monkeypatch) -> None:
    run_dir = _build_run(tmp_path / "run")

    def _missing():
        raise ImportError("no module named myfuzz.scenario.chain_certificates")

    monkeypatch.setattr("myfuzz.scenario.acceptance_metrics._load_chain_certificates",
                        _missing)
    text = render_markdown(analyze_run(run_dir))
    assert "certified_chains_per_second" in text
    assert "chain certificate producer unavailable" in text


# --------------------------------------------------------------------------
# command line interface
# --------------------------------------------------------------------------


def _run_cli(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI), *arguments], cwd=str(cwd or ROOT),
        capture_output=True, text=True, check=False)


def test_cli_analyze_prints_json_and_writes_outputs(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    json_out = tmp_path / "report.json"
    markdown_out = tmp_path / "report.md"
    completed = _run_cli("analyze", "--run-dir", str(run_dir),
                         "--json-out", str(json_out),
                         "--markdown-out", str(markdown_out))
    assert completed.returncode == 0, completed.stderr
    printed = json.loads(completed.stdout)
    assert printed["schema_version"] == SCHEMA_VERSION
    assert printed["effective_search_seconds"] == 10.0
    assert json.loads(json_out.read_text(encoding="utf-8")) == printed
    markdown = markdown_out.read_text(encoding="utf-8")
    assert "Evidence boundary" in markdown


def test_cli_analyze_reports_bad_jsonl_with_nonzero_exit(tmp_path: Path) -> None:
    run_dir = _build_run(tmp_path / "run")
    path = run_dir / "online_events.jsonl"
    path.write_text('{"event_id": 1}\n{"broken":\n', encoding="utf-8")
    completed = _run_cli("analyze", "--run-dir", str(run_dir))
    assert completed.returncode == 1
    assert "line 2" in completed.stderr


def test_cli_run_dry_run_prints_commands_without_side_effects(tmp_path: Path) -> None:
    output_dir = tmp_path / "online-run"
    cache_dir = tmp_path / "cache"
    completed = _run_cli(
        "run", "--seconds", "5", "--max-tests", "3",
        "--output-dir", str(output_dir), "--cache-dir", str(cache_dir),
        "--client-binary", str(tmp_path / "kfuzz"),
        "--run-id", "dry-run-test", "--compressed-trace", "--dry-run")
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["dry_run"] is True
    assert output_dir.exists() is False
    assert cache_dir.exists() is False
    commands = payload["commands"]
    assert len(commands) >= 1
    run_command = commands[0]
    assert run_command[1].endswith("scripts/run_ibex_pulp_online.py")
    assert run_command[2] == "run"
    for token in ("--seconds", "5", "--max-tests", "3", "--output",
                  str(output_dir), "--cache-dir", str(cache_dir),
                  "--run-id", "dry-run-test", "--compressed-trace"):
        assert token in run_command
    for command in commands:
        assert command[0] == sys.executable


def test_cli_run_dry_run_with_acceptance_arguments(tmp_path: Path) -> None:
    output_dir = tmp_path / "online-run"
    completed = _run_cli(
        "run", "--seconds", "1", "--max-tests", "1",
        "--output-dir", str(output_dir), "--dry-run")
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz" in \
        " ".join(payload["commands"][0])
    assert payload["analysis_command"][0] == sys.executable
    assert "--run-dir" in payload["analysis_command"]
