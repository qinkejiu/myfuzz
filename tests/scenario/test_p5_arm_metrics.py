"""Tests for the read-only P5 per-arm metric aggregator.

The fixtures are *synthetic but real-shaped*: ``receipts.jsonl``, ``report.json``,
``online_plan.json``, ``online_run_identity.json``, ``online_final_trace.meta.json``
+ ``online_events.jsonl`` and ``cold_start.json`` are written with the fields the
saved Ibex + dual-PULP runs actually carry, so the aggregation is exercised on the
same contract the saved run directories expose.

Two structural invariants are asserted for *every* arm, real or synthetic:

* the twelve declared P5 checklist groups are all present, and every group has
  exactly the same leaf paths in every arm (a missing input changes a leaf's
  ``value``/``reason``, never the document shape);
* every leaf is ``{"value", "source", "reason"}`` with a non-empty artifact key
  in ``source``, a non-empty ``reason`` whenever ``value`` is ``null``, and
  ``reason == null`` whenever a value was measured.

Nothing here starts RTL, Verilator, cargo or the RFuzz client.  The two tests
that touch real saved runs only read the artifacts; one of them streams the
saved zlib trace container of ``p5-format2-zlib-20261007-online`` (read-only)
because witness-edge and chain numbers cannot be derived without it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.acceptance_metrics import (
    CLASSIFIED_STATUSES,
    INVALID_STATUSES,
    TIMEOUT_STATUSES,
    _percentiles,
    analyze_run,
)
from myfuzz.scenario.paired_efficiency import compare_runs
from myfuzz.scenario.p5_arm_metrics import (
    CHECKLIST_METRIC_GROUPS,
    DEFAULT_MAX_CERTIFICATES,
    SCHEMA_VERSION,
    P5ArmMetricsInputError,
    aggregate_arms,
    analyze_arm,
    render_markdown,
)


ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = ROOT / "scripts" / "report_p5_arm_metrics.py"

REAL_ZLIB_ARM = ROOT / "runs" / "p5-format2-zlib-20261007-online"
REAL_FOREIGN_ARM = ROOT / "runs" / "p4-cpu-side-first-seen-20261008-online"


# ---------------------------------------------------------------------------
# fixture helpers: synthetic runs with the real artifact shape
# ---------------------------------------------------------------------------


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


PHASE_TIMING = {
    "selection_decode": 0.00013552900000490808,
    "rtl_submit": 1.019773401000009,
    "trace_digest": 0.03627435100000298,
    "interaction_ingest": 0.009301161999985652,
    "checker": 3.5270000182663352e-06,
    "feedback_credit": 0.0007310599999925671,
    "receipt_build": 2.4832999997670413e-05,
    "total": 1.0662448550000079,
}

RUNNER_TIMING = {
    "scheduler_batch": 0.7669696870000848,
    "runner_step": 0.7667967730000669,
    "router_enqueue": 0.0,
    "router_drain": 0.0,
    "router_transact": 0.0,
    "observed_output_route": 0.0016226030001291747,
}


def _receipt(index: int, *, status: str = "complete",
             coverage: str = "00000000",
             phase_timing: dict | None = None,
             runner_timing: dict | None = None,
             submit_timing: dict | None = None,
             local_ticks: dict | None = None,
             total_local_ticks: int | None = 96,
             disposition: str = "admitted",
             disposition_reason: str = "rtl_case_committed",
             interaction_new_features: list | None = None,
             interaction_feature_deltas: dict | None = None,
             interaction_source_gains: dict | None = None,
             interaction_deferred: bool = True,
             violations: list | None = None,
             raw: str | None = None,
             omit: tuple[str, ...] = ()) -> dict:
    """One receipt with the shape the online path persists."""
    if raw is None:
        raw = f"{index:064x}"
    row = {
        "run_id": "synthetic-arm",
        "slot": index,
        "case_id": f"online-{index}-{raw[:8]}",
        "status": status,
        "raw_sha256": raw,
        "online_raw_records_hex": [raw[:16]],
        "effective_genome_sha256": "genome-a",
        "genome_sha256": "genome-a",
        "path_id": "path-a",
        "applied_path": 1,
        "direction": "IP_TO_CPU_TO_IP",
        "applied_sources": ["gpio_b.external_pin8"],
        "applied_source_ids": ["gpio_b.external_pin8"],
        "source_id": "gpio_b.external_pin8",
        "violations": list(violations or ()),
        "rejection": None,
        "error": None,
        "coverage_hex": coverage,
        "local_ticks": {"cpu": 32, "gpio_a": 32, "gpio_b": 32}
        if local_ticks is None else dict(local_ticks),
        "total_local_ticks": total_local_ticks,
        "online_phase_timing_seconds": dict(phase_timing or PHASE_TIMING),
        "online_runner_timing_seconds": dict(runner_timing or RUNNER_TIMING),
        "online_submit_timing_seconds": dict(
            submit_timing or {"local_command_count": 96,
                              "local_command_roundtrip": 0.052,
                              "host_remainder": 0.967}),
        "candidate_disposition": disposition,
        "candidate_disposition_reason": disposition_reason,
        "interaction_deferred": interaction_deferred,
        "interaction_new_features": list(interaction_new_features or ()),
        "interaction_feature_deltas": dict(interaction_feature_deltas or {}),
        "interaction_source_gains": dict(interaction_source_gains or {}),
    }
    for name in omit:
        row.pop(name, None)
    return row


_UNSET = object()


def _report(*, execution_mode: str = "online_cases",
            effective: float = 10.0, elapsed: float = 12.0,
            statuses: dict | None = None, tests: int | None = None,
            finalization: object = _UNSET,
            **overrides) -> dict:
    if finalization is _UNSET:
        finalization = {"identity_write": 0.25, "plan_write": 0.002,
                        "session_finish": 6.25, "total_before_report": 11.55,
                        "trace_write": 5.0}
    document = {
        "client_returncode": 0,
        "clock_model": "independent_local_ticks_and_causal_order",
        "completed_feedback_exchanges": 2,
        "decoder_manifest_sha256": "manifest-sha",
        "effective_search_seconds": effective,
        "elapsed_seconds": elapsed,
        "execution_mode": execution_mode,
        "execution_status": "complete",
        "finalization_timing_seconds": finalization,
        "global_mutation_seed": 20261007,
        "global_mutation_seed_status": "supported",
        "mutation_hint_schema": "scenario_mutation_hint.v1",
        "mutation_hint_updates": 3,
        "online_run_identity_sha256": "identity-sha",
        "record_semantics": "mutation_decisions_not_dut_cycles",
        "run_identity_schema": "scenario_online_run_identity.v1",
        "runtime_path_status": "contract_preflight",
        "session_status": "complete",
        "statuses": dict(statuses or {}),
        "tests": tests,
        "total_local_ticks_semantics": "sum_of_independent_local_ticks_cost_only",
    }
    document.update(overrides)
    return document


def _plan(*, admissions: list[dict] | None = None) -> dict:
    return {
        "schema_version": "online_session_plan.v1",
        "cases": [],
        "source_admissions": {
            "schema_version": "source_admission_registry.v1",
            "admissions": list(admissions if admissions is not None else [
                {"admission_id": "admission-0", "role": "fuzz_source",
                 "source_id": "gpio_b.external_pin8"},
                {"admission_id": "admission-1", "role": "cpu_program",
                 "source_id": "cpu.online_instruction"},
            ]),
        },
    }


def _identity(run_id: str) -> dict:
    return {"identity": {"run_config": {"run_id": run_id}},
            "schema_version": "scenario_online_run_identity.v1"}


def _events(count: int, *, edges: int = 1) -> list[dict]:
    """Contiguous 1-based journal events, the shape the producer consumes."""
    events = []
    for index in range(count):
        candidates = []
        for candidate in range(edges):
            candidates.append({
                "graph_sha256": "graph-sha",
                "path_ids": ["path-a"],
                "relation": "PERSISTENT_STATE_RULE",
                "rule_index": candidate,
                "scope": "case",
            })
        events.append({
            "event_id": index + 1,
            "case_index": index % 3,
            "provenance": {"edge_candidates": candidates},
        })
    return events


def _write_trace_jsonl(directory: Path, events: list[dict]) -> None:
    with (directory / "online_events.jsonl").open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    local_ticks = {"cpu": 1, "gpio_a": 1, "gpio_b": 1}
    digest = hashlib.sha256(b'{"events":[')
    for index, event in enumerate(events):
        if index:
            digest.update(b",")
        digest.update(_canonical(event))
    digest.update(b'],"local_ticks":' + _canonical(local_ticks) +
                  b',"status":"complete"}')
    meta = {
        "event_count": len(events),
        "events_file": "online_events.jsonl",
        "genome_sha256": "genome-sha",
        "local_ticks": local_ticks,
        "manifest_sha256": "manifest-sha",
        "schema_version": "online_trace_jsonl.v1",
        "semantic_sha256": digest.hexdigest(),
        "status": "complete",
    }
    (directory / "online_final_trace.meta.json").write_text(
        json.dumps(meta, sort_keys=True), encoding="utf-8")


def _write_monolithic_trace(directory: Path, events: list[dict]) -> None:
    (directory / "online_final_trace.json").write_text(
        json.dumps({"events": events, "local_ticks": {"cpu": 1},
                    "status": "complete"}, sort_keys=True),
        encoding="utf-8")


def _write_cold_baseline(directory: Path, *, cases: int,
                         init_seconds: float = 12.0) -> None:
    document = {
        "schema_version": "ibex_pulp_cold_baseline.v1",
        "case_count": cases,
        "published_case_count": cases,
        "verified_case_count": cases,
        "elapsed_seconds": cases * init_seconds,
        "init_seconds_total": cases * init_seconds,
        "total_seconds_total": cases * (init_seconds + 1.0),
        "cases": [
            {"index": index, "init_seconds": init_seconds + index,
             "total_seconds": init_seconds + index + 1.0,
             "prefix_replay_seconds": 0.1, "raw_hex": f"{index:016x}"}
            for index in range(cases)
        ],
        "comparison_scope": "startup_cost_only_not_coverage_equivalence",
    }
    (directory / "cold_start.json").write_text(
        json.dumps(document, sort_keys=True), encoding="utf-8")


def _write_run(directory: Path, *, receipts: list[dict] | None = None,
               report: dict | None = None, plan: dict | None = None,
               run_id: str = "synthetic-arm",
               events: list[dict] | None = None,
               monolithic: bool = False,
               cold_cases: int | None = None,
               omit_receipts: bool = False,
               omit_report: bool = False,
               omit_plan: bool = False,
               omit_trace: bool = False,
               client_log: str = "Fuzzing myfuzz_scenario\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    rows = receipts if receipts is not None else [_receipt(0), _receipt(1)]
    if not omit_receipts:
        with (directory / "receipts.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    if not omit_report:
        document = report if report is not None else _report(
            statuses={"complete": len(rows)}, tests=len(rows))
        (directory / "report.json").write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8")
    if not omit_plan:
        (directory / "online_plan.json").write_text(
            json.dumps(plan if plan is not None else _plan(), sort_keys=True),
            encoding="utf-8")
    (directory / "online_run_identity.json").write_text(
        json.dumps(_identity(run_id), sort_keys=True), encoding="utf-8")
    (directory / "client.log").write_text(client_log, encoding="utf-8")
    if not omit_trace:
        trace_events = events if events is not None else _events(len(rows))
        if monolithic:
            _write_monolithic_trace(directory, trace_events)
        else:
            _write_trace_jsonl(directory, trace_events)
    if cold_cases is not None:
        _write_cold_baseline(directory, cases=cold_cases)
    return directory


# ---------------------------------------------------------------------------
# structural invariants
# ---------------------------------------------------------------------------


def _leaf_paths(arm: dict) -> set[str]:
    paths = set()
    for group, leaves in arm["metrics"].items():
        for name in leaves:
            paths.add(f"{group}.{name}")
    return paths


def _walk_leaves(arm: dict):
    for group, leaves in arm["metrics"].items():
        for name, leaf in leaves.items():
            yield f"{group}.{name}", leaf


def _leaf(arm: dict, path: str) -> dict:
    group, _, name = path.partition(".")
    return arm["metrics"][group][name]


def _value(arm: dict, path: str):
    return _leaf(arm, path)["value"]


def test_declared_checklist_groups_are_all_present():
    assert CHECKLIST_METRIC_GROUPS == (
        "one_time_compile_init", "per_case_admission", "real_rtl_transactions",
        "router_scheduler", "incremental_feedback", "log_evidence",
        "latency_percentiles", "effective_cases_per_second",
        "certified_chains_per_second", "coverage_novelty",
        "invalid_or_timeout_ratio", "status_counts",
    )
    document = aggregate_arms([])
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["checklist_metric_groups"] == list(CHECKLIST_METRIC_GROUPS)
    assert document["arms"] == []


def test_every_leaf_names_an_artifact_and_null_always_carries_a_reason(tmp_path):
    directory = _write_run(tmp_path / "arm", cold_cases=2)
    arm = analyze_arm(directory)
    seen = 0
    for path, leaf in _walk_leaves(arm):
        seen += 1
        assert set(leaf) == {"value", "source", "reason"}, path
        assert isinstance(leaf["source"], str) and leaf["source"], path
        if leaf["value"] is None:
            assert isinstance(leaf["reason"], str) and leaf["reason"], path
        else:
            assert leaf["reason"] is None, path
    assert seen >= 60
    assert set(arm["metrics"]) == set(CHECKLIST_METRIC_GROUPS)


def test_all_arms_expose_the_same_leaf_paths(tmp_path):
    rich = _write_run(tmp_path / "rich", cold_cases=2,
                      events=_events(3, edges=2))
    bare = _write_run(tmp_path / "bare", receipts=[], omit_trace=True,
                      report=_report(effective=1.0, statuses={}, tests=0))
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "report.json").write_text(
        json.dumps({"schema_version": "soc_result.v1"}), encoding="utf-8")
    paths = [_leaf_paths(analyze_arm(entry))
             for entry in (rich, bare, foreign)]
    assert paths[0] == paths[1] == paths[2]


def test_missing_inputs_are_null_with_reason_and_never_zero(tmp_path):
    directory = _write_run(tmp_path / "arm", receipts=[_receipt(0)],
                           omit_trace=True, omit_plan=True,
                           report=_report(effective=10.0,
                                          statuses={"complete": 1}, tests=1,
                                          finalization=None))
    arm = analyze_arm(directory)
    for path in ("certified_chains_per_second.certified_chains",
                 "certified_chains_per_second.certified_chains_per_second",
                 "certified_chains_per_second.first_missing_hop_histogram",
                 "coverage_novelty.unique_witnessed_edges",
                 "coverage_novelty.new_witnessed_edges_per_second",
                 "log_evidence.trace_bytes",
                 "log_evidence.trace_format",
                 "per_case_admission.admissions_total",
                 "one_time_compile_init.finalization_timing_seconds"):
        leaf = _leaf(arm, path)
        assert leaf["value"] is None, path
        assert isinstance(leaf["reason"], str) and leaf["reason"], path
    # the receipt-derived numbers are still measured, not zeroed
    assert _value(arm, "effective_cases_per_second.complete_status_count") == 1
    assert _value(arm, "effective_cases_per_second.effective_cases_per_second") == 0.1


# ---------------------------------------------------------------------------
# per-metric extraction
# ---------------------------------------------------------------------------


def test_effective_cases_per_second_and_exact_status_counts(tmp_path):
    receipts = [
        _receipt(0, status="complete"),
        _receipt(1, status="complete"),
        _receipt(2, status="complete"),
        _receipt(3, status="timeout"),
        _receipt(4, status="invalid_input"),
    ]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0, elapsed=12.0,
                       statuses={"complete": 3, "timeout": 1,
                                 "invalid_input": 1},
                       tests=5))
    arm = analyze_arm(directory)
    assert _value(arm, "status_counts.status_counts") == {
        "complete": 3, "invalid_input": 1, "timeout": 1}
    assert _value(arm, "status_counts.status_counts_total") == 5
    assert _value(arm, "status_counts.reports_agree") is True
    assert _value(arm, "effective_cases_per_second.complete_status_count") == 3
    assert _value(
        arm, "effective_cases_per_second.effective_cases_per_second") == 0.3
    assert _value(arm,
                  "effective_cases_per_second.denominator_seconds") == 10.0
    assert _value(
        arm, "effective_cases_per_second.all_receipt_cases_per_second") == 0.5
    assert _value(
        arm, "invalid_or_timeout_ratio.invalid_or_timeout_ratio") == 0.4
    assert _value(arm, "invalid_or_timeout_ratio.invalid_count") == 1
    assert _value(arm, "invalid_or_timeout_ratio.timeout_count") == 1
    assert _value(arm, "invalid_or_timeout_ratio.complete_count") == 3
    assert _value(arm, "invalid_or_timeout_ratio.unclassified_statuses") == []
    assert _leaf(
        arm,
        "invalid_or_timeout_ratio.invalid_or_timeout_ratio")["source"].startswith(
            "receipts.jsonl:status")


def test_unclassified_status_keeps_the_ratio_null_with_the_shipped_reason(tmp_path):
    # The status vocabulary is owned by the shipped analyzer and can grow; pick a
    # name that is provably outside it so the "unclassified" path stays exercised
    # whichever revision of acceptance_metrics is installed.
    unclassified_status = "probe_unclassified_status"
    assert unclassified_status not in CLASSIFIED_STATUSES
    receipts = [_receipt(0), _receipt(1, status=unclassified_status)]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0,
                       statuses={"complete": 1, unclassified_status: 1}, tests=2))
    arm = analyze_arm(directory)
    leaf = _leaf(arm, "invalid_or_timeout_ratio.invalid_or_timeout_ratio")
    assert leaf["value"] is None
    assert unclassified_status in leaf["reason"]
    assert _value(arm, "invalid_or_timeout_ratio.unclassified_statuses") == [
        unclassified_status]
    # the exact counts survive even though the ratio is undefined
    assert _value(arm, "status_counts.status_counts") == {
        "complete": 1, unclassified_status: 1}


def test_classified_input_invalid_status_follows_the_shipped_vocabulary(tmp_path):
    # ``input_invalid`` is a live writer status whose classification is owned by
    # acceptance_metrics.INVALID_STATUSES; the aggregator must relay whichever
    # revision is installed instead of pinning a classification of its own.
    receipts = [_receipt(0), _receipt(1, status="input_invalid")]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0,
                       statuses={"complete": 1, "input_invalid": 1}, tests=2))
    arm = analyze_arm(directory)
    leaf = _leaf(arm, "invalid_or_timeout_ratio.invalid_or_timeout_ratio")
    if "input_invalid" in INVALID_STATUSES:
        assert leaf["value"] == 0.5
        assert _value(arm, "invalid_or_timeout_ratio.invalid_count") == 1
        assert _value(arm, "invalid_or_timeout_ratio.unclassified_statuses") == []
    else:
        assert leaf["value"] is None and "input_invalid" in leaf["reason"]


def test_report_and_receipt_disagreement_is_reported_not_smoothed(tmp_path):
    directory = _write_run(tmp_path / "arm", receipts=[_receipt(0)],
                           report=_report(effective=10.0,
                                          statuses={"complete": 7}, tests=7))
    arm = analyze_arm(directory)
    assert _value(arm, "status_counts.status_counts") == {"complete": 1}
    assert _value(arm, "status_counts.reported_statuses") == {"complete": 7}
    assert _value(arm, "status_counts.reports_agree") is False


def test_latency_percentiles_cover_every_phase_the_receipts_carry(tmp_path):
    receipts = [
        _receipt(0, phase_timing=dict(PHASE_TIMING, extra_phase=0.5, total=1.0)),
        _receipt(1, phase_timing=dict(PHASE_TIMING, extra_phase=1.5, total=2.0)),
        _receipt(2, phase_timing=dict(PHASE_TIMING, extra_phase=2.5, total=3.0)),
    ]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0, statuses={"complete": 3}, tests=3))
    arm = analyze_arm(directory)
    mapping = _value(arm, "latency_percentiles.online_phase_timing_seconds")
    assert set(mapping) == set(PHASE_TIMING) | {"extra_phase"}
    expected_extra = _percentiles([0.5, 1.5, 2.5], (0.5, 0.95))
    assert mapping["extra_phase"] == {"count": 3,
                                      "p50": expected_extra["p50"],
                                      "p95": expected_extra["p95"]}
    expected_total = _percentiles([1.0, 2.0, 3.0], (0.5, 0.95))
    assert _value(arm, "latency_percentiles.per_case_total_seconds") == {
        "count": 3, "p50": expected_total["p50"], "p95": expected_total["p95"]}
    assert _value(
        arm, "latency_percentiles.cases_with_online_phase_timing_seconds") == 3


def test_single_sample_arm_reports_p50_only_and_a_null_p95(tmp_path):
    directory = _write_run(tmp_path / "arm", receipts=[_receipt(0)],
                           report=_report(effective=10.0,
                                          statuses={"complete": 1}, tests=1))
    arm = analyze_arm(directory)
    per_case = _value(arm, "latency_percentiles.per_case_total_seconds")
    assert per_case == {"count": 1, "p50": PHASE_TIMING["total"], "p95": None}
    mapping = _value(arm, "latency_percentiles.online_phase_timing_seconds")
    assert mapping["total"]["p50"] == PHASE_TIMING["total"]
    assert mapping["total"]["p95"] is None
    # a null p95 is reported as null, not as zero, and the leaf is measured
    assert _leaf(
        arm, "latency_percentiles.per_case_total_seconds")["reason"] is None


def test_phase_percentiles_are_bit_identical_to_acceptance_metrics(tmp_path):
    receipts = [
        _receipt(index,
                 phase_timing=dict(PHASE_TIMING,
                                   total=1.0 + index * 0.25,
                                   rtl_submit=0.1 * index),
                 runner_timing=dict(RUNNER_TIMING,
                                    scheduler_batch=0.5 + index,
                                    router_transact=0.0 if index < 2 else 0.25))
        for index in range(4)
    ]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0, statuses={"complete": 4}, tests=4))
    arm = analyze_arm(directory)
    shipped = analyze_run(directory)
    assert _value(arm, "latency_percentiles.online_phase_timing_seconds") == \
        {name: {"count": entry["count"], "p50": entry["p50"],
                "p95": entry["p95"]}
         for name, entry in
         shipped["phase_timing_seconds"]["online_phase_timing_seconds"].items()}
    ours = _value(arm, "router_scheduler.online_runner_timing_seconds")
    shipped_runner = {name: {"count": entry["count"], "p50": entry["p50"],
                             "p95": entry["p95"]}
                      for name, entry in
                      shipped["phase_timing_seconds"]
                      ["online_runner_timing_seconds"].items()}
    assert {name: {key: entry[key] for key in ("count", "p50", "p95")}
            for name, entry in ours.items()} == shipped_runner
    assert ours["scheduler_batch"]["sum_seconds"] == 8.0
    assert ours["router_transact"]["sum_seconds"] == 0.5
    assert _value(arm, "router_scheduler.cases_with_router_transact") == 2


def test_router_scheduler_and_real_rtl_transaction_statistics(tmp_path):
    receipts = [
        _receipt(0),
        _receipt(1, runner_timing=dict(RUNNER_TIMING, router_transact=0.25,
                                       router_enqueue=0.001,
                                       router_drain=0.002),
                 local_ticks={"cpu": 64}, total_local_ticks=64),
        _receipt(2, disposition="refused",
                 disposition_reason="rtl_case_rejected",
                 violations=["gpio_a_output_bit0"]),
    ]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0, statuses={"complete": 3}, tests=3))
    arm = analyze_arm(directory)
    assert _value(arm, "router_scheduler.cases_with_router_transact") == 1
    assert _value(arm, "router_scheduler.router_transact_seconds_sum") == 0.25
    assert _value(arm, "router_scheduler.cases_with_scheduler_batch") == 3
    mapping = _value(arm, "router_scheduler.online_runner_timing_seconds")
    assert mapping["router_transact"]["count"] == 3
    assert mapping["router_transact"]["p95"] is not None
    assert _value(arm, "real_rtl_transactions.cases_with_runner_timing") == 3
    assert _value(
        arm, "real_rtl_transactions.cases_with_rtl_case_committed") == 2
    assert _value(
        arm, "real_rtl_transactions.cases_with_total_local_ticks") == 3
    assert _value(
        arm, "real_rtl_transactions.record_semantics") == \
        "mutation_decisions_not_dut_cycles"
    assert _value(
        arm, "real_rtl_transactions.total_local_ticks_semantics") == \
        "sum_of_independent_local_ticks_cost_only"


def test_per_case_admission_statistics(tmp_path):
    receipts = [
        _receipt(0),
        _receipt(1, local_ticks={"cpu": 64}, total_local_ticks=64,
                 submit_timing={"local_command_count": 10,
                                "local_command_roundtrip": 0.5,
                                "host_remainder": 1.5}),
        _receipt(2, omit=("local_ticks", "online_submit_timing_seconds")),
    ]
    directory = _write_run(
        tmp_path / "arm", receipts=receipts,
        report=_report(effective=10.0, statuses={"complete": 3}, tests=3))
    arm = analyze_arm(directory)
    assert _value(arm, "per_case_admission.receipt_rows") == 3
    assert _value(arm, "per_case_admission.reported_tests") == 3
    assert _value(arm, "per_case_admission.admissions_total") == 2
    assert _value(arm, "per_case_admission.admissions_by_role") == {
        "cpu_program": 1, "fuzz_source": 1}
    assert _value(arm, "per_case_admission.candidate_dispositions") == {
        "admitted": 3}
    assert _value(
        arm, "per_case_admission.cases_with_online_submit_timing_seconds") == 2
    assert _value(arm, "per_case_admission.local_command_count_total") == 106
    assert _value(arm, "per_case_admission.local_command_count_p50") == \
        _percentiles([96.0, 10.0], (0.5,))["p50"]
    assert _value(arm, "per_case_admission.cases_with_local_ticks") == 2
    assert _value(arm, "per_case_admission.local_ticks_by_component_sum") == {
        "cpu": 96, "gpio_a": 32, "gpio_b": 32}
    assert _value(arm, "per_case_admission.total_local_ticks_sum") == 256
    assert _value(arm, "per_case_admission.cases_with_total_local_ticks") == 3
    assert _value(arm, "per_case_admission.coverage_records") == 3
    assert _value(arm, "per_case_admission.coverage_width_bytes") == 4
    assert _value(arm, "per_case_admission.raw_record_count") == 3
    assert _value(arm, "per_case_admission.cases_with_violations") == 0


def test_incremental_feedback_statistics(tmp_path):
    receipts = [
        _receipt(0, interaction_new_features=["f1"],
                 interaction_feature_deltas={"k": 1},
                 interaction_source_gains={"src": 2}),
        _receipt(1, interaction_deferred=False),
    ]
    report = _report(effective=10.0, statuses={"complete": 2}, tests=2,
                     source_action_gate={"status": "granted", "enforce": True,
                                         "action_ids": ["a", "b", "c"]},
                     path_switch={"status": "disabled", "attempts": 0},
                     closed_loop_energy={"enabled": False,
                                         "counts": {"certificate_count": 0}})
    directory = _write_run(tmp_path / "arm", receipts=receipts, report=report)
    arm = analyze_arm(directory)
    assert _value(
        arm, "incremental_feedback.completed_feedback_exchanges") == 2
    assert _value(arm, "incremental_feedback.mutation_hint_updates") == 3
    assert _value(
        arm, "incremental_feedback.cases_with_interaction_new_features") == 1
    assert _value(
        arm, "incremental_feedback.cases_with_interaction_feature_deltas") == 1
    assert _value(
        arm, "incremental_feedback.cases_with_interaction_source_gains") == 1
    assert _value(arm, "incremental_feedback.cases_deferred") == 1
    assert _value(
        arm, "incremental_feedback.source_action_gate_action_count") == 3
    assert _value(
        arm, "incremental_feedback.source_action_gate_enforce") is True
    assert _value(arm, "incremental_feedback.path_switch") == {
        "status": "disabled", "attempts": 0}
    assert _value(
        arm, "incremental_feedback.closed_loop_energy_enabled") is False
    assert _value(arm, "incremental_feedback.closed_loop_energy_counts") == {
        "certificate_count": 0}


def test_log_evidence_footprint_and_meta_container_split(tmp_path):
    split = _write_run(tmp_path / "split", receipts=[_receipt(0)])
    arm = analyze_arm(split)
    assert _value(arm, "log_evidence.trace_format") == "jsonl.v1"
    assert _value(arm, "log_evidence.trace_events_file") == "online_events.jsonl"
    assert _value(arm, "log_evidence.trace_meta_container_split") is True
    assert _value(arm, "log_evidence.trace_bytes") == \
        (split / "online_events.jsonl").stat().st_size
    assert _value(arm, "log_evidence.trace_events_ingested") == 1
    assert _value(arm, "log_evidence.trace_event_count_match") is True
    assert _value(arm, "log_evidence.trace_semantic_sha256_verified") is True
    assert _value(arm, "log_evidence.receipts_bytes") == \
        (split / "receipts.jsonl").stat().st_size
    assert _value(arm, "log_evidence.client_log_bytes") == \
        (split / "client.log").stat().st_size
    assert _value(arm, "log_evidence.evidence_footprint_bytes") == sum(
        (split / name).stat().st_size for name in
        ("online_events.jsonl", "online_final_trace.meta.json",
         "receipts.jsonl", "report.json", "online_plan.json",
         "online_run_identity.json", "client.log"))

    monolithic = _write_run(tmp_path / "monolithic", receipts=[_receipt(0)],
                            monolithic=True)
    other = analyze_arm(monolithic)
    assert _value(other, "log_evidence.trace_format") == "json.v1"
    assert _value(other, "log_evidence.trace_meta_container_split") is False


def test_certified_chains_incomplete_histogram_and_rates(tmp_path):
    directory = _write_run(tmp_path / "arm", receipts=[_receipt(0)],
                           events=_events(2, edges=2),
                           report=_report(effective=4.0,
                                          statuses={"complete": 1}, tests=1))
    arm = analyze_arm(directory, chain_producer=_FakeProducer())
    assert _value(
        arm, "certified_chains_per_second.certified_chains") == 2
    assert _value(
        arm, "certified_chains_per_second.certified_chains_per_second") == 0.5
    assert _value(
        arm, "certified_chains_per_second.certified_chains_by_direction") == {
        "CPU_TO_IP_TO_CPU": 1, "IP_TO_CPU_TO_IP": 1}
    assert _value(
        arm, "certified_chains_per_second.certified_chains_same_case") == 1
    assert _value(
        arm, "certified_chains_per_second.incomplete_certificates") == 1
    assert _value(
        arm, "certified_chains_per_second.first_missing_hop_histogram") == {
        "instruction_fetch": 1}
    assert _value(
        arm, "certified_chains_per_second.chain_producer_available") is True
    assert _value(
        arm, "certified_chains_per_second.certified_admissions") == 2


def test_coverage_novelty_rates(tmp_path):
    receipts = [_receipt(0, coverage="01000000"),
                _receipt(1, coverage="00010000"),
                _receipt(2, coverage="01000000")]
    directory = _write_run(tmp_path / "arm", receipts=receipts,
                           events=_events(2, edges=2),
                           report=_report(effective=2.0,
                                          statuses={"complete": 3}, tests=3))
    arm = analyze_arm(directory)
    assert _value(arm, "coverage_novelty.coverage_width_bytes") == 4
    assert _value(arm, "coverage_novelty.first_seen_target_bits") == 2
    assert _value(arm, "coverage_novelty.new_target_bits_per_second") == 1.0
    assert _value(arm, "coverage_novelty.unique_witnessed_edges") == 2
    assert _value(arm, "coverage_novelty.new_witnessed_edges_per_second") == 1.0
    assert _value(arm, "coverage_novelty.edge_candidate_observations") == 4
    assert "analyze_run" in _value(arm, "coverage_novelty.method")


def test_finalization_and_cold_start_initialization(tmp_path):
    continuous = _write_run(tmp_path / "continuous", receipts=[_receipt(0)],
                            report=_report(effective=10.0, elapsed=12.0,
                                           statuses={"complete": 1}, tests=1))
    arm = analyze_arm(continuous)
    assert _value(
        arm, "one_time_compile_init.finalization_timing_seconds") == {
        "identity_write": 0.25, "plan_write": 0.002, "session_finish": 6.25,
        "total_before_report": 11.55, "trace_write": 5.0}
    assert _value(
        arm,
        "one_time_compile_init.finalization_total_before_report_seconds") == 11.55
    assert _value(
        arm, "one_time_compile_init.elapsed_minus_effective_search_seconds") == 2.0
    init_leaf = _leaf(arm, "one_time_compile_init.compilation_seconds")
    assert init_leaf["value"] is None
    assert "compile" in init_leaf["reason"]
    per_case = _leaf(arm, "one_time_compile_init.per_case_initialization_seconds")
    assert per_case["value"] is None
    assert "continuous" in per_case["reason"]
    assert _leaf(
        arm, "one_time_compile_init.cold_start_init_seconds_p50")["value"] is None

    cold_receipts = [_receipt(index, raw=f"{index:064x}") for index in range(3)]
    cold = _write_run(
        tmp_path / "cold", receipts=cold_receipts, cold_cases=3,
        run_id="synthetic-cold",
        report=_report(execution_mode="online_cases_per_case_cold_start",
                       effective=0.09, elapsed=90.0,
                       statuses={"complete": 3}, tests=3))
    cold_arm = analyze_arm(cold)
    expected = _percentiles([12.0, 13.0, 14.0], (0.5, 0.95))
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_init_seconds_p50") == \
        expected["p50"]
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_init_seconds_p95") == \
        expected["p95"]
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_init_seconds_total") == 39.0
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_cases_with_init_seconds") == 3
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_share_of_elapsed") == \
        39.0 / 90.0
    assert cold_arm["arm_kind"] == "scenario_online_cases_per_case_cold_start"


def test_partial_cold_baseline_is_measured_with_an_explicit_limit(tmp_path):
    directory = _write_run(
        tmp_path / "cold", receipts=[_receipt(0), _receipt(1)],
        report=_report(execution_mode="online_cases_per_case_cold_start",
                       effective=0.09, elapsed=9.0,
                       statuses={"complete": 2}, tests=2))
    document = {
        "schema_version": "ibex_pulp_cold_baseline.v1",
        "case_count": 2,
        "cases": [{"index": 0, "init_seconds": 12.0, "total_seconds": 13.0},
                  {"index": 1, "total_seconds": 13.5}],
    }
    (directory / "cold_start.json").write_text(
        json.dumps(document, sort_keys=True), encoding="utf-8")
    arm = analyze_arm(directory)
    assert _value(
        arm, "one_time_compile_init.cold_start_cases_with_init_seconds") == 1
    assert _value(
        arm, "one_time_compile_init.cold_start_init_seconds_p50") == 12.0
    limit = next(entry for entry in arm["limits"]
                 if entry["quantity"].startswith(
                     "one_time_compile_init.cold_start_init_seconds"))
    assert "declares 2 cases" in limit["reason"]
    assert "only 1 carry" in limit["reason"]
    assert "paired_efficiency" in limit["reason"]


def test_wrong_cold_baseline_schema_is_refused(tmp_path):
    directory = _write_run(tmp_path / "cold", receipts=[_receipt(0)],
                           report=_report(
                               execution_mode="online_cases_per_case_cold_start",
                               effective=0.09, elapsed=9.0,
                               statuses={"complete": 1}, tests=1))
    (directory / "cold_start.json").write_text(
        json.dumps({"schema_version": "something_else.v1"}), encoding="utf-8")
    with pytest.raises(P5ArmMetricsInputError):
        analyze_arm(directory)


# ---------------------------------------------------------------------------
# cross-checks against the shipped modules
# ---------------------------------------------------------------------------


def _paired_fixture(tmp_path) -> tuple[Path, Path]:
    continuous_rows = []
    cold_rows = []
    for index in range(3):
        continuous_rows.append(_receipt(
            index, coverage="01000000" if index == 0 else "00000000",
            phase_timing=dict(PHASE_TIMING, total=0.5 + index * 0.5),
            runner_timing=dict(RUNNER_TIMING, scheduler_batch=0.4 + index,
                               router_transact=0.0 if index else 0.25),
            interaction_new_features=["f"] if index == 0 else []))
        cold_rows.append(_receipt(
            index, coverage="01000000" if index == 0 else "00000000",
            phase_timing=dict(PHASE_TIMING, total=12.0 + index,
                              rtl_submit=9.0 + index),
            runner_timing=dict(RUNNER_TIMING, scheduler_batch=11.0 + index,
                               router_transact=0.0),
            interaction_new_features=["f"] if index == 0 else []))
    continuous = _write_run(
        tmp_path / "continuous", receipts=continuous_rows,
        events=_events(3, edges=2), run_id="paired-continuous",
        report=_report(effective=10.0, elapsed=15.0,
                       statuses={"complete": 3}, tests=3))
    cold = _write_run(
        tmp_path / "cold", receipts=cold_rows, events=_events(3, edges=2),
        cold_cases=3, run_id="paired-cold",
        report=_report(execution_mode="online_cases_per_case_cold_start",
                       effective=0.25, elapsed=40.0,
                       statuses={"complete": 3}, tests=3))
    return continuous, cold


def test_coverage_and_efficiency_numbers_match_paired_efficiency(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    document = aggregate_arms([continuous, cold], labels=["continuous", "cold"])
    paired = compare_runs(continuous, cold)
    for arm in document["arms"]:
        label = arm["label"]
        group = paired["groups"][label]
        assert _value(arm, "coverage_novelty.new_target_bits_per_second") == \
            group["coverage_novelty"]["new_target_bits_per_second"]
        assert _value(arm, "coverage_novelty.new_witnessed_edges_per_second") == \
            group["witnessed_edge_novelty"]["new_edges_per_second"]
        assert _value(
            arm, "certified_chains_per_second.certified_chains") == \
            group["certified_chains"]["total"]
        assert _value(
            arm, "certified_chains_per_second.certified_chains_per_second") == \
            group["certified_chains_per_second"]
        assert _value(
            arm, "effective_cases_per_second.all_receipt_cases_per_second") == \
            group["cases_per_second"]
        assert _value(
            arm, "invalid_or_timeout_ratio.invalid_or_timeout_ratio") == \
            group["invalid_or_timeout_ratio"]
        assert _value(arm, "latency_percentiles.per_case_total_seconds") == {
            "count": group["per_case_total_seconds"]["count"],
            "p50": group["per_case_total_seconds"]["p50"],
            "p95": group["per_case_total_seconds"]["p95"],
        }
        assert _value(
            arm, "one_time_compile_init.finalization_timing_seconds") == \
            group["finalization_timing_seconds"]


def test_cold_start_init_matches_paired_efficiency_initialization(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    document = aggregate_arms([continuous, cold], labels=["continuous", "cold"])
    paired = compare_runs(continuous, cold)
    cold_arm = next(arm for arm in document["arms"] if arm["label"] == "cold")
    initialization = paired["initialization"]
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_init_seconds_p50") == \
        initialization["cold_init_seconds_p50"]
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_init_seconds_p95") == \
        initialization["cold_init_seconds_p95"]
    assert _value(
        cold_arm, "one_time_compile_init.cold_start_cases_with_init_seconds") == \
        initialization["cold_cases_with_init_seconds"]


# ---------------------------------------------------------------------------
# foreign / unavailable arms
# ---------------------------------------------------------------------------


def test_foreign_report_schema_yields_a_null_arm_with_a_reason(tmp_path):
    foreign = tmp_path / "p4-like"
    foreign.mkdir()
    (foreign / "report.json").write_text(
        json.dumps({"schema_version": "soc_result.v1",
                    "effective_fuzz_seconds": 300.0,
                    "client_result": {"actual_rtl_execution": {"tests": 54157}}},
                   sort_keys=True), encoding="utf-8")
    arm = analyze_arm(foreign)
    assert arm["arm_kind"] == "not_a_scenario_online_session"
    assert arm["analysis_performed"] is False
    assert "soc_result.v1" in arm["arm_kind_reason"]
    for path, leaf in _walk_leaves(arm):
        assert leaf["value"] is None, path
        assert leaf["reason"], path
        assert "soc_result.v1" in leaf["reason"], path


def test_real_foreign_arm_is_reported_as_not_a_dataflow_session():
    if not REAL_FOREIGN_ARM.is_dir():
        pytest.skip(f"saved run is absent: {REAL_FOREIGN_ARM}")
    arm = analyze_arm(REAL_FOREIGN_ARM)
    assert arm["arm_kind"] == "not_a_scenario_online_session"
    assert arm["analysis_performed"] is False
    assert _value(arm, "effective_cases_per_second.effective_cases_per_second") \
        is None
    assert "soc_result.v1" in _leaf(
        arm,
        "effective_cases_per_second.effective_cases_per_second")["reason"]


def test_missing_receipts_keeps_every_receipt_metric_null(tmp_path):
    directory = _write_run(tmp_path / "arm", omit_receipts=True,
                           events=_events(2, edges=1),
                           report=_report(effective=10.0))
    arm = analyze_arm(directory)
    for path in ("per_case_admission.receipt_rows",
                 "per_case_admission.coverage_records",
                 "per_case_admission.local_ticks_by_component_sum",
                 "status_counts.status_counts",
                 "effective_cases_per_second.effective_cases_per_second",
                 "coverage_novelty.first_seen_target_bits",
                 "latency_percentiles.online_phase_timing_seconds",
                 "invalid_or_timeout_ratio.invalid_or_timeout_ratio"):
        leaf = _leaf(arm, path)
        assert leaf["value"] is None, path
        assert leaf["reason"], path
    # the trace-derived edge count is still measured
    assert _value(arm, "coverage_novelty.unique_witnessed_edges") == 1


# ---------------------------------------------------------------------------
# document-level contract: determinism, markdown, CLI
# ---------------------------------------------------------------------------


def test_document_is_byte_identical_across_repeated_runs(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    first = aggregate_arms([continuous, cold])
    second = aggregate_arms([continuous, cold])
    assert json.dumps(first, sort_keys=True, allow_nan=False) == \
        json.dumps(second, sort_keys=True, allow_nan=False)
    assert json.dumps(first, sort_keys=True).encode("utf-8") == \
        json.dumps(second, sort_keys=True).encode("utf-8")


def test_labels_default_to_directory_names(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    document = aggregate_arms([continuous, cold])
    assert [arm["label"] for arm in document["arms"]] == ["continuous", "cold"]
    assert [arm["run_dir"] for arm in document["arms"]] == \
        [str(continuous), str(cold)]


def test_markdown_names_every_checklist_group(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    markdown = render_markdown(aggregate_arms([continuous, cold]))
    for group in CHECKLIST_METRIC_GROUPS:
        assert group in markdown
    assert "continuous" in markdown and "cold" in markdown


def test_cli_writes_deterministic_document_and_markdown(tmp_path):
    continuous, cold = _paired_fixture(tmp_path)
    json_out = tmp_path / "out" / "arm_metrics.json"
    markdown_out = tmp_path / "out" / "arm_metrics.md"
    command = [sys.executable, str(CLI_SCRIPT), str(continuous), str(cold),
               "--labels", "continuous", "cold",
               "--json-out", str(json_out), "--markdown-out", str(markdown_out),
               "--quiet"]
    completed = subprocess.run(command, capture_output=True, text=True,
                               cwd=ROOT, check=False)
    assert completed.returncode == 0, completed.stderr
    document = json.loads(json_out.read_text(encoding="utf-8"))
    assert document["schema_version"] == SCHEMA_VERSION
    assert json_out.read_text(encoding="utf-8") == json.dumps(
        document, sort_keys=True, indent=2, ensure_ascii=False,
        allow_nan=False) + "\n"
    assert "checklist" in markdown_out.read_text(encoding="utf-8").lower() or \
        "有效例/s" in markdown_out.read_text(encoding="utf-8")
    second = subprocess.run(command, capture_output=True, text=True, cwd=ROOT,
                            check=False)
    assert second.returncode == 0
    assert json_out.read_text(encoding="utf-8") == json.dumps(
        document, sort_keys=True, indent=2, ensure_ascii=False,
        allow_nan=False) + "\n"


def test_cli_usage_errors(tmp_path):
    missing = subprocess.run([sys.executable, str(CLI_SCRIPT)],
                             capture_output=True, text=True, cwd=ROOT,
                             check=False)
    assert missing.returncode == 3
    absent = subprocess.run(
        [sys.executable, str(CLI_SCRIPT), str(tmp_path / "nope")],
        capture_output=True, text=True, cwd=ROOT, check=False)
    assert absent.returncode == 1
    assert "does not exist" in absent.stderr


# ---------------------------------------------------------------------------
# real saved run, read-only
# ---------------------------------------------------------------------------


def test_real_saved_arm_is_aggregated_read_only():
    if not REAL_ZLIB_ARM.is_dir():
        pytest.skip(f"saved run is absent: {REAL_ZLIB_ARM}")
    arm = analyze_arm(REAL_ZLIB_ARM)
    assert arm["arm_kind"] == "scenario_online_cases"
    assert arm["analysis_performed"] is True
    assert _value(arm, "status_counts.status_counts_total") == 81
    assert _value(arm, "status_counts.status_counts") == {
        "complete": 79, "input_invalid": 2}
    # The invalid/timeout classification belongs to the shipped analyzer, whose
    # status vocabulary is a moving target: this pins the *rule* (counts from the
    # imported sets, ratio null only while some status is unclassified) instead
    # of one revision's answer.
    statuses = _value(arm, "status_counts.status_counts")
    invalid = sum(count for status, count in statuses.items()
                  if status in INVALID_STATUSES)
    timeout = sum(count for status, count in statuses.items()
                  if status in TIMEOUT_STATUSES)
    unclassified = _value(arm, "invalid_or_timeout_ratio.unclassified_statuses")
    assert _value(arm, "invalid_or_timeout_ratio.invalid_count") == invalid
    assert _value(arm, "invalid_or_timeout_ratio.timeout_count") == timeout
    assert unclassified == sorted(status for status in statuses
                                  if status not in CLASSIFIED_STATUSES)
    ratio_leaf = _leaf(arm,
                       "invalid_or_timeout_ratio.invalid_or_timeout_ratio")
    if unclassified:
        assert ratio_leaf["value"] is None
        assert unclassified[0] in ratio_leaf["reason"]
    else:
        assert ratio_leaf["value"] == (invalid + timeout) / 81
    assert _value(arm, "effective_cases_per_second.complete_status_count") == 79
    assert _value(arm, "coverage_novelty.first_seen_target_bits") == 4
    assert _value(arm, "coverage_novelty.unique_witnessed_edges") == 9
    assert _value(arm, "certified_chains_per_second.certified_chains") == 14
    assert _value(
        arm, "certified_chains_per_second.incomplete_certificates") == 65
    assert _value(
        arm, "certified_chains_per_second.first_missing_hop_histogram") == {
        "instruction_fetch": 23, "mmio_write_acceptance": 4,
        "pin8_injection": 38}
    assert _value(arm, "log_evidence.trace_format") == "zlib_chunks.v1"
    assert _value(arm, "log_evidence.trace_bytes") == 36903052
    assert _value(arm, "log_evidence.trace_events_ingested") == 114309
    assert _value(arm, "log_evidence.trace_meta_container_split") is True
    assert _value(arm, "log_evidence.trace_semantic_sha256_verified") is True
    assert _value(
        arm, "one_time_compile_init.finalization_total_before_report_seconds") \
        == pytest.approx(13.469330645006266)
    # long-run sanity: the aggregator did not byte the trace into memory
    assert _value(arm, "log_evidence.trace_bytes") < 40 * 1024 * 1024


class _FakeProducer:
    """Minimal chain-certificate producer used to exercise the aggregation.

    The real producer is exercised by the shipped analyzer's own tests and by
    the real-run test above; this stub only has to speak the frozen protocol
    (``ingest``/``flush``/``pending_count``) so the synthetic arm can carry a
    certified chain and an incomplete chain with a first missing hop.
    """

    def __init__(self, *, max_pending: int = 128, max_event_gap: int = 4096,
                 require_native_receipts: bool = True) -> None:
        self.max_pending = max_pending
        self.max_event_gap = max_event_gap
        self.require_native_receipts = require_native_receipts
        self.pending_count = 0
        self._emitted = False

    def ingest(self, events) -> tuple:
        self.pending_count += len(events)
        return ()

    def flush(self) -> tuple:
        if self._emitted:
            return ()
        self._emitted = True
        self.pending_count = 0
        return (
            {"schema_version": "runtime_chain_certificate.v1",
             "certificate_id": "cert-ip",
             "status": "certified",
             "direction": "IP_TO_CPU_TO_IP",
             "source_case_index": 0,
             "endpoint_case_index": 0,
             "source_admission_id": "admission-0",
             "hops": ["pin8_injection", "instruction_fetch",
                      "mmio_write_acceptance"]},
            {"schema_version": "runtime_chain_certificate.v1",
             "certificate_id": "cert-cpu",
             "status": "certified",
             "direction": "CPU_TO_IP_TO_CPU",
             "source_case_index": 0,
             "endpoint_case_index": 1,
             "source_admission_id": "admission-1",
             "hops": ["instruction_fetch", "mmio_write_acceptance"]},
            {"schema_version": "runtime_chain_certificate.v1",
             "certificate_id": "cert-incomplete",
             "status": "incomplete",
             "direction": "IP_TO_CPU_TO_IP",
             "source_admission_id": "admission-0",
             "missing_hops": ["instruction_fetch", "mmio_write_acceptance"]},
        )

    def close(self) -> None:
        return None


def test_fake_producer_certificates_are_relayed_verbatim(tmp_path):
    directory = _write_run(tmp_path / "arm", receipts=[_receipt(0)],
                           events=_events(2, edges=1),
                           report=_report(effective=4.0,
                                          statuses={"complete": 1}, tests=1))
    injected = analyze_arm(directory, chain_producer=_FakeProducer())
    shipped = analyze_run(directory, chain_producer=_FakeProducer)
    assert _value(injected, "certified_chains_per_second.certified_chains") == \
        shipped["certified_chains"]["total"]
    assert _value(
        injected, "certified_chains_per_second.first_missing_hop_histogram") == \
        shipped["chain_gap_evidence"]["first_missing_hop_counts"]
    assert _value(
        injected, "certified_chains_per_second.certified_chains_same_case") == \
        shipped["certified_chains"]["same_case"]
    assert _value(
        injected,
        "one_time_compile_init.compilation_seconds") is None
