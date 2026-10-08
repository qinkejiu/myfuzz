"""P5 stage acceptance suite: honest per-run judgement, union and exit codes.

``scripts/run_p5_acceptance_suite.py`` declares saved runs by role
(``--run ROLE=DIR[@COMPARE_DIR]``) and must answer, per declared run **and** as a
union, the six P5 critical items of the stage checklist.  The module under test
is :mod:`myfuzz.scenario.p5_acceptance`.

Every test below builds *synthetic but real-shaped* run directories (the same
file names and the same JSON key paths the saved ``runs/`` artifacts use), so the
suite's judgement is exercised without an RTL run and without depending on any
saved campaign.  The negative cases pin the two properties that matter most:

* an item that cannot be measured is ``measured=false`` with a precise reason --
  never a fabricated ``0`` and never a silent pass;
* ``met`` is never ``true`` unless ``measured`` is ``true`` and the exact
  artifact keys the criterion names are present and self-consistent.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from myfuzz.scenario.p5_acceptance import (
    ARTIFACT_ASSERTION_CLASSES,
    ARTIFACT_IDENTITY,
    ARTIFACT_PLAN,
    ARTIFACT_RECEIPTS,
    ARTIFACT_REPLAY,
    ARTIFACT_REPORT,
    CRITICAL_ITEMS,
    EXIT_NOT_READY,
    EXIT_READY,
    EXIT_USAGE,
    ITEM_ASSERTION_CLASSES,
    ITEM_COMPLETE_PREFIX,
    ITEM_CONTROLLED_FAULT,
    ITEM_LONG_SEARCH,
    ITEM_NORMAL_CONTROL,
    ITEM_PAIRED_BUDGET,
    p5_acceptance_report,
    p5_acceptance_suite,
    parse_artifact_declaration,
    parse_run_declaration,
    render_markdown,
)


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "run_p5_acceptance_suite.py"


# --------------------------------------------------------------- helpers


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, document) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=1, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    return _sha256_bytes(path.read_bytes())


def _write_jsonl(path: Path, rows) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")
    return _sha256_bytes(path.read_bytes())


def _item(report: dict, key: str) -> dict:
    rows = [row for row in report["items"] if row["key"] == key]
    assert len(rows) == 1, f"item {key} is not reported exactly once"
    return rows[0]


def _union_item(suite: dict, key: str) -> dict:
    rows = [row for row in suite["items"] if row["key"] == key]
    assert len(rows) == 1, f"union item {key} is not reported exactly once"
    return rows[0]


def build_run(root: Path, name: str, *, tests: int = 24,
              statuses=None, session_status: str = "complete",
              violations=(), effective_seconds: float = 31.273544,
              elapsed_seconds: float = 31.905327, trace_status: str = "complete",
              with_meta: bool = False, extra=None) -> Path:
    """One synthetic run directory with the real artifact names and key paths."""
    run = root / name
    (run / "failures").mkdir(parents=True, exist_ok=True)
    (run / "corpus").mkdir(parents=True, exist_ok=True)
    _write_json(run / "online_plan.json",
                {"schema_version": "online_session_plan.v1",
                 "cases": [{"index": index} for index in range(tests)]})
    rows = []
    for index in range(tests):
        row = {"case_id": f"online-{index}-{index:024x}",
               "status": "complete", "violations": [],
               "raw_sha256": f"{index:064x}"}
        rows.append(row)
    if violations:
        rows[-1]["status"] = "dut_violation"
        rows[-1]["violations"] = list(violations)
    _write_jsonl(run / "receipts.jsonl", rows)
    (run / "seed.bin").write_bytes(bytes(range(8)))
    _write_json(run / "corpus" / "entry_0000.json", {"seed": "00"})
    manifest_digest = "6d" * 32
    _write_json(run / "online_session_manifest.json",
                {"schema_version": "online_session_manifest.v1"})
    semantic = "c0" * 32
    if with_meta:
        (run / "online_events.zlib").write_bytes(b"MFZ1-not-a-real-trace")
    else:
        _write_json(run / "online_final_trace.json", {"events": []})
    artifacts = {}
    for relative in ("online_plan.json", "receipts.jsonl",
                     "online_session_manifest.json", "seed.bin",
                     "corpus/entry_0000.json",
                     "online_events.zlib" if with_meta else "online_final_trace.json"):
        artifacts[relative] = _sha256_bytes((run / relative).read_bytes())
    _write_json(run / "online_run_identity.json", {
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": "b3" * 32,
        "identity": {
            "schema_version": "scenario_online_run_identity.v1",
            "trace_file": "online_events.zlib" if with_meta
            else "online_final_trace.json",
            "run_config": {"run_id": name, "search_seed": 20261007,
                           "duration_seconds": 30.0},
            "artifacts": artifacts,
            "genome": {"plan_file": "online_plan.json",
                       "plan_sha256": artifacts["online_plan.json"]},
            "trace": {"semantic_sha256": semantic, "status": trace_status,
                      "manifest_sha256": manifest_digest,
                      "genome_sha256": artifacts["online_plan.json"]},
            "session": {"manifest_file": "online_session_manifest.json",
                        "manifest_sha256": manifest_digest},
            "components": {"identity_file": "online_session_manifest.json",
                           "identity_sha256": "58" * 32},
            "source_files": [],
        },
    })
    if with_meta:
        _write_json(run / "online_final_trace.meta.json", {
            "schema_version": "online_trace_zlib_chunks.v1",
            "events_file": "online_events.zlib", "event_count": 7,
            "semantic_sha256": semantic, "manifest_sha256": manifest_digest,
            "genome_sha256": artifacts["online_plan.json"],
            "status": trace_status})
    _write_json(run / "report.json", {
        "client_returncode": 0, "tests": tests,
        "statuses": statuses if statuses is not None else {"complete": tests},
        "session_status": session_status,
        "run_identity_schema": "scenario_online_run_identity.v1",
        "online_run_identity_sha256": "b3" * 32,
        "effective_search_seconds": effective_seconds,
        "elapsed_seconds": elapsed_seconds,
    })
    if violations:
        _write_json(run / "failures" / "online_dut_violation_ab.json", {
            "case_id": rows[-1]["case_id"], "violations": list(violations)})
    for relative, document in (extra or {}).items():
        _write_json(run / relative, document)
    return run


def build_assertion_classes(path: Path, *, gate_passed: bool = True,
                            unrepresented=(), engine_sha: str | None = None,
                            run_dir: str, trace_sha: str | None = None) -> Path:
    """A real-shaped ``p5_assertion_classes.v1`` document."""
    if engine_sha is None:
        engine_sha = _sha256_bytes(
            (ROOT / "src/myfuzz/scenario/assertion_classes.py").read_bytes())
    classes = {
        "protocol_checker": {"assertion_class": "protocol_checker",
                             "data_present": True, "finding_count": 0,
                             "finding_count_reason": None,
                             "observed_record_count": 24, "findings": []},
        "cross_component_provenance_and_order": {
            "assertion_class": "cross_component_provenance_and_order",
            "data_present": True, "finding_count": 22,
            "finding_count_reason": None, "observed_record_count": 39,
            "findings": []},
        "cpu_ip_behaviour": {"assertion_class": "cpu_ip_behaviour",
                             "data_present": True, "finding_count": 118,
                             "finding_count_reason": None,
                             "observed_record_count": 1308, "findings": []},
    }
    _write_json(path, {
        "schema_version": "p5_assertion_classes.v1",
        "run_dir": run_dir,
        "assertion_classes": classes,
        "not_silently_filtered": {
            "abnormal_record_count": 140,
            "represented_record_count": 140 if not unrepresented else 139,
            "unrepresented": list(unrepresented),
            "gate": {"passed": gate_passed, "exit_code": 0 if gate_passed else 2,
                     "reason": None if gate_passed else "one record is absent"},
        },
        "engine": {"module": {"module": "myfuzz.scenario.assertion_classes",
                              "path": str(ROOT / "src/myfuzz/scenario/assertion_classes.py"),
                              "sha256": engine_sha}},
        "trace": {"semantic_sha256_verified": True,
                  "semantic_sha256": trace_sha or ("c0" * 32)},
    })
    return path


def build_fault_run(root: Path, *, finding: str = "gpio_b_irq_source_mismatch",
                    calibration_only: bool = True,
                    boundary: str = "checker_input_copy") -> Path:
    run = build_run(root, "current-dataflow-p5-fault-20261008-online", tests=3,
                    statuses={"complete": 2, "dut_violation": 1},
                    session_status="finding", violations=(finding,),
                    effective_seconds=4.2426, elapsed_seconds=5.39)
    _write_json(run / "fault_document.json", {
        "schema_version": "p5_controlled_fault.v1",
        "faults": [{"kind": "wrong_irq", "variant": "observation_irq_level",
                    "expected_finding": finding,
                    "selector": {"case_id": "online-2-000000000000000000000002",
                                 "observation_event_id": 4609},
                    "mutation": {"field": "outputs.irq", "replacement": 0}}]})
    _write_json(run / "fault_run_summary.json", {
        "tests": 3, "statuses": {"complete": 2, "dut_violation": 1},
        "violations": [finding], "effective_search_seconds": 4.2426})
    _write_json(run / "minimal_replay.json", {
        "schema_version": "p5_controlled_fault_replay.v1",
        "calibration_only": calibration_only,
        "observation_boundary": boundary,
        "fault_document_sha256": "cd" * 32,
        "findings": [{"finding_id": "p5_controlled_fault_wrong_irq_811af21c",
                      "case_id": "online-2-000000000000000000000002",
                      "expected_finding": finding, "detected_by": finding,
                      "observation_event_id": 4609}]})
    return run


def build_reproduce(root: Path, *, finding: str = "gpio_b_irq_source_mismatch",
                    fault_document_sha256: str = "cd" * 32) -> Path:
    run = build_run(root, "current-dataflow-p5-fault-20261008-reproduce", tests=3,
                    statuses={"complete": 2, "dut_violation": 1},
                    session_status="finding", violations=(finding,))
    _write_json(run / "reproduction_summary.json", {
        "fault_document_sha256": fault_document_sha256,
        "tests": 3, "statuses": {"complete": 2, "dut_violation": 1},
        "violations": [finding]})
    return run


def build_long_search(root: Path, *, seconds: float = 600.362952,
                      chains: int = 27, per_second: float = 0.044972,
                      findings: int = 0) -> Path:
    run = build_run(root, "current-dataflow-p5-long-20261008-online",
                    tests=368, effective_seconds=seconds,
                    elapsed_seconds=seconds + 1.18,
                    with_meta=True)
    _write_json(run / "acceptance.json", {
        "schema_version": "first_step_acceptance_report.v1",
        "run_dir": str(run),
        "effective_search_seconds": seconds,
        "certified_chains": {"total": chains, "cap_reached": False,
                             "cross_case": 6, "same_case": 21,
                             "incomplete_total": 341,
                             "by_direction": {"CPU_TO_IP_TO_CPU": 20,
                                              "IP_TO_CPU_TO_IP": 7}},
        "certified_chains_per_second": per_second,
        "certified_chains_reason": None,
        "certified_chains_per_second_reason": None,
        "invalid_or_timeout_detail": {"complete": 368, "findings": findings,
                                      "invalid": 0, "timeout": 0},
        "reported_tests": 368, "reported_statuses": {"complete": 368},
        "trace_evidence": {"semantic_sha256_verified": True,
                           "event_count_match": True,
                           "declared_semantic_sha256": "c0" * 32,
                           "semantic_sha256_recomputed": "c0" * 32,
                           "events_ingested": 570196},
    })
    return run


def build_paired(root: Path) -> tuple[Path, Path]:
    continuous = build_run(root, "current-dataflow-p5-paired-20261008-online",
                           tests=24, effective_seconds=30.783371,
                           elapsed_seconds=31.905327)
    cold = root / "current-dataflow-p5-paired-20261008-cold-start"
    cold.mkdir(parents=True, exist_ok=True)
    (cold / "failures").mkdir(exist_ok=True)
    rows = [{"case_id": f"online-{index}-{index:024x}",
             "status": "complete", "violations": []} for index in range(24)]
    _write_jsonl(cold / "receipts.jsonl", rows)
    cases = [{"index": index, "case_id": f"online-{index}-{index:024x}",
              "init_seconds": 18.7, "total_seconds": 21.1,
              "verification_error": None, "error": None} for index in range(24)]
    _write_json(cold / "cold_start.json", {
        "schema_version": "ibex_pulp_cold_baseline.v1",
        "case_count": 24, "verified_case_count": 24, "cases": cases,
        "elapsed_seconds": 512.879228,
        "init_seconds_total": 449.695218,
        "total_seconds_total": 507.214933,
        "comparison_scope": "startup_cost_only_not_coverage_equivalence",
        "source_receipts": "runs/current-dataflow-p5-paired-20261008-online/receipts.jsonl",
        "raw_compatible_count": 24, "genome_compatible_count": 24,
        "path_compatible_count": 24, "source_compatible_count": 24,
        "status_compatible_count": 24,
    })
    _write_json(cold / "report.json", {
        "schema_version": "first_step_cold_start_run_report.v1",
        "execution_mode": "online_cases_per_case_cold_start",
        "execution_status": "complete", "tests": 24,
        "elapsed_seconds": 25.566133, "effective_search_seconds": 0.141097,
        "wall_clock_seconds": 512.881362, "case_count": 24,
        "published_case_count": 24, "verified_case_count": 24,
        "status_mismatch_count": 0, "verification_failure_count": 0,
        "case_failure_count": 0, "statuses": {"complete": 24},
        "continuous_run_dir": "runs/current-dataflow-p5-paired-20261008-online",
        "continuous_identity_sha256": "b3" * 32,
        "cold_start_document": "cold_start.json",
    })
    return continuous, cold


def build_paired_comparator(continuous: Path, cold: Path, *,
                            comparable: bool = True,
                            cold_rate: float | None = None) -> Path:
    """A real-shaped ``paired_efficiency_report.v1`` for the synthetic pair."""
    path = continuous / "paired_efficiency_report.json"
    _write_json(path, {
        "schema_version": "paired_efficiency_report.v1",
        "comparison_scope": "per-case artifact alignment plus per-group rates for "
                            "two run directories that must share source, seed and "
                            "budget; this is not a DUT equivalence, "
                            "coverage-equivalence, replay or speedup proof",
        "groups": {
            "continuous": {"run_dir": str(continuous), "case_count": 24,
                           "elapsed_seconds": 31.905327,
                           "effective_search_seconds": 30.783371,
                           "certified_chains": {"total": 8, "cap_reached": False},
                           "certified_chains_per_second": 0.259880,
                           "certified_chains_per_second_reason": None},
            "cold": {"run_dir": str(cold), "case_count": 24,
                     "elapsed_seconds": 25.566133,
                     "effective_search_seconds": 0.141097,
                     "certified_chains": {"total": None},
                     "certified_chains_per_second": cold_rate,
                     "certified_chains_per_second_reason": None if cold_rate
                     else "trace events are unavailable, so no certificate could "
                          "be derived"},
        },
        "paired": {
            "certified_chains_per_second_ratio_cold_over_continuous": {
                "value": None if cold_rate is None else cold_rate / 0.259880,
                "reason": None if cold_rate else
                "at least one of the two quantities is null or the denominator "
                "is zero"},
        },
        "comparison_validity": {
            "comparable": comparable,
            "status": "comparable" if comparable else "refused",
            "failed_prerequisites": [] if comparable else ["equal_case_count"],
            "unverified_prerequisites": [],
            "prerequisites": [
                {"name": name, "satisfied": comparable} for name in (
                    "equal_case_count", "source_identity_equal", "seed_equal",
                    "budget_equal", "input_sequence_alignment",
                    "raw_identity_agreement", "genome_agreement",
                    "path_agreement", "assertion_agreement")],
        },
    })
    return path


def build_identity_and_replay(run: Path, *, matches: bool = True) -> None:
    _write_json(run / "replay.log", {"difference_context": None,
                                     "first_difference": None if matches else 3,
                                     "matches": matches})


# ------------------------------------------------------- per-item judgement


def test_assertion_classes_separated_measured_and_met(tmp_path):
    run = build_run(tmp_path, "run-online")
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", run_dir=str(run))
    report = p5_acceptance_report(
        run, artifacts={ARTIFACT_ASSERTION_CLASSES: str(report_path)})
    item = _item(report, ITEM_ASSERTION_CLASSES)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["reason"] is None
    assert set(item["value"]["classes"]) == {
        "protocol_checker", "cross_component_provenance_and_order",
        "cpu_ip_behaviour"}
    assert item["value"]["census"]["gate_passed"] is True
    assert any(entry["key"] == ARTIFACT_ASSERTION_CLASSES
               for entry in item["evidence"])


def test_assertion_classes_separated_fails_closed_on_unrepresented_record(tmp_path):
    run = build_run(tmp_path, "run-online")
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", gate_passed=False,
        unrepresented=[{"reason": "record 7 is not represented"}],
        run_dir=str(run))
    report = p5_acceptance_report(
        run, artifacts={ARTIFACT_ASSERTION_CLASSES: str(report_path)})
    item = _item(report, ITEM_ASSERTION_CLASSES)
    assert item["measured"] is True
    assert item["met"] is False
    assert "gate" in item["reason"] or "unrepresented" in item["reason"]


def test_assertion_classes_separated_rejects_a_foreign_trace(tmp_path):
    run = build_run(tmp_path, "run-online")
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", run_dir=str(run),
        trace_sha="ff" * 32)
    item = _item(p5_acceptance_report(
        run, artifacts={ARTIFACT_ASSERTION_CLASSES: str(report_path)}),
        ITEM_ASSERTION_CLASSES)
    assert item["measured"] is True
    assert item["met"] is False
    assert "trace semantic_sha256" in item["reason"]


def test_assertion_classes_separated_rejects_a_foreign_engine(tmp_path):
    run = build_run(tmp_path, "run-online")
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", engine_sha="00" * 32,
        run_dir=str(run))
    report = p5_acceptance_report(
        run, artifacts={ARTIFACT_ASSERTION_CLASSES: str(report_path)})
    item = _item(report, ITEM_ASSERTION_CLASSES)
    assert item["measured"] is True
    assert item["met"] is False
    assert "sha256" in item["reason"] or "engine" in item["reason"]


def test_assertion_classes_separated_without_the_cli_report_is_unmeasured(tmp_path):
    run = build_run(tmp_path, "run-online")
    item = _item(p5_acceptance_report(run), ITEM_ASSERTION_CLASSES)
    assert item["measured"] is False
    assert item["met"] is None
    assert item["value"] is None
    assert item["reason"]


def test_an_artifact_with_a_foreign_schema_is_skipped_not_used(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    _write_json(run / "assertion_classes.json",
                {"schema_version": "first_step_acceptance_report.v1",
                 "run_dir": str(run)})
    item = _item(p5_acceptance_report(run), ITEM_ASSERTION_CLASSES)
    assert item["measured"] is False
    assert item["met"] is None
    assert "schema_version" in item["reason"]
    report = p5_acceptance_report(run)
    assert any("schema_version" in note for note in report["resolution_notes"])


def test_a_shared_store_never_serves_an_unbound_artifact(tmp_path):
    run = build_run(tmp_path, "run-online")
    store = tmp_path / "current-dataflow-p5-final-20261007-logs"
    store.mkdir(parents=True, exist_ok=True)
    _write_json(store / "replay.log",
                {"matches": True, "first_difference": None,
                 "difference_context": None})
    report = p5_acceptance_report(run)
    item = _item(report, ITEM_COMPLETE_PREFIX)
    assert item["measured"] is True
    assert item["met"] is False
    assert "replay" in item["reason"]
    assert report["resolved_artifacts"][ARTIFACT_REPLAY]["available"] is False


def test_identity_item_cites_the_shipped_replay_guard_and_saved_refusal(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    refusal = item["value"]["identity_refusal"]
    assert refusal["mechanism"].endswith("_verify_online_run_identity")
    assert "before the RTL factory" in refusal["stage"]
    saved = item["value"]["saved_refusal_artifact"]
    assert saved["available"] is True
    assert saved["declared_run_itself"] is False
    assert saved["matches"] == 0
    assert saved["cold_replay_failed"] == 24
    assert "identity mismatch" in saved["message"]
    assert any(entry["path"].endswith("cold-replay-0000.log")
               for entry in saved["artifacts"])


def test_a_compare_run_never_stands_in_for_the_declared_run(tmp_path):
    empty = tmp_path / "family-root"
    empty.mkdir(parents=True, exist_ok=True)
    (empty / "failures").mkdir(exist_ok=True)
    _write_json(empty / "fault_family_calibration.json", {
        "schema_version": "p5_fault_family_calibration.v1",
        "calibration_only": True, "observation_boundary": "checker_input_copy",
        "variants": []})
    _write_json(empty / "fault_family_calibration_verify.json", {
        "schema_version": "p5_fault_family_calibration_verify.v1",
        "ok": True, "failures": [], "variants": []})
    other = build_run(tmp_path, "other-online")
    build_identity_and_replay(other)
    report = p5_acceptance_report(empty, compare_run=other)
    for key in (ARTIFACT_IDENTITY, ARTIFACT_PLAN, ARTIFACT_RECEIPTS,
                ARTIFACT_REPORT):
        assert report["resolved_artifacts"][key]["available"] is False
    item = _item(report, ITEM_COMPLETE_PREFIX)
    assert item["measured"] is False
    assert item["met"] is None


def test_fault_family_root_proves_the_control_by_its_verifier(tmp_path):
    root = tmp_path / "family-root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "failures").mkdir(exist_ok=True)
    control = build_run(tmp_path, "control-online")
    _write_json(root / "fault_family_calibration.json", {
        "schema_version": "p5_fault_family_calibration.v1",
        "calibration_only": True, "observation_boundary": "checker_input_copy",
        "variants": [{"variant": "observation_irq_level",
                      "status": "calibrated",
                      "expected_finding": "gpio_b_irq_source_mismatch",
                      "observed_findings": ["gpio_b_irq_source_mismatch"],
                      "fault_document": {"sha256": "cd" * 32},
                      "source_run": {"path": str(control)}}]})
    _write_json(root / "fault_family_calibration_verify.json", {
        "schema_version": "p5_fault_family_calibration_verify.v1",
        "ok": True, "failures": [],
        "variants": [{"variant": "observation_irq_level", "ok": True,
                      "checks": [
                          {"name": "fault_document_canonical", "ok": True},
                          {"name": "fault_run_finding", "ok": True},
                          {"name": "control_run_clean", "ok": True},
                          {"name": "control_trace_unchanged", "ok": True}]}]})
    item = _item(p5_acceptance_report(root), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["control_checks"][0]["clean"] is True
    assert item["value"]["control_runs"][0]["state"] == "scanned"
    assert item["value"]["control_runs"][0]["carries_a_family_finding"] == []

    document = json.loads(
        (root / "fault_family_calibration_verify.json").read_text())
    document["variants"][0]["checks"][2]["ok"] = False
    _write_json(root / "fault_family_calibration_verify.json", document)
    unmet = _item(p5_acceptance_report(root), ITEM_NORMAL_CONTROL)
    assert unmet["measured"] is True
    assert unmet["met"] is False
    assert "control_run_clean" in unmet["reason"]


def test_fault_family_reproduce_must_name_a_family_fault_document(tmp_path):
    root = tmp_path / "family-root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "failures").mkdir(exist_ok=True)
    _write_json(root / "fault_family_calibration.json", {
        "schema_version": "p5_fault_family_calibration.v1",
        "calibration_only": True, "observation_boundary": "checker_input_copy",
        "variants": [{"variant": "observation_irq_level",
                      "status": "calibrated",
                      "expected_finding": "gpio_b_irq_source_mismatch",
                      "observed_findings": ["gpio_b_irq_source_mismatch"],
                      "fault_document": {"sha256": "cd" * 32}}]})
    _write_json(root / "fault_family_calibration_verify.json", {
        "schema_version": "p5_fault_family_calibration_verify.v1",
        "ok": True, "failures": [], "variants": []})
    reproduce = build_reproduce(tmp_path, fault_document_sha256="ff" * 32)
    item = _item(p5_acceptance_report(root, compare_run=reproduce),
                 ITEM_CONTROLLED_FAULT)
    assert item["measured"] is True
    assert item["met"] is False
    assert "fault document" in item["reason"]


def test_controlled_fault_caught_and_reproduced_with_reproduce_root(tmp_path):
    run = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path)
    report = p5_acceptance_report(run, compare_run=reproduce)
    item = _item(report, ITEM_CONTROLLED_FAULT)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["detected_by"] == ["gpio_b_irq_source_mismatch"]
    assert item["value"]["calibration_only"] is True
    assert item["value"]["observation_boundary"] == "checker_input_copy"
    assert item["value"]["reproduced_by"] is not None
    assert len(item["evidence"]) >= 2


def test_controlled_fault_without_a_reproduce_root_is_measured_but_unmet(tmp_path):
    run = build_fault_run(tmp_path)
    item = _item(p5_acceptance_report(run), ITEM_CONTROLLED_FAULT)
    assert item["measured"] is True
    assert item["met"] is False
    assert "reproduce" in item["reason"]


def test_controlled_fault_reproduce_identity_mismatch_is_unmet(tmp_path):
    run = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path, fault_document_sha256="ff" * 32)
    item = _item(p5_acceptance_report(run, compare_run=reproduce),
                 ITEM_CONTROLLED_FAULT)
    assert item["measured"] is True
    assert item["met"] is False
    assert "sha256" in item["reason"] or "reproduce" in item["reason"]


def test_controlled_fault_without_the_calibration_markers_is_unmet(tmp_path):
    run = build_fault_run(tmp_path, calibration_only=False, boundary="live_dut")
    reproduce = build_reproduce(tmp_path)
    item = _item(p5_acceptance_report(run, compare_run=reproduce),
                 ITEM_CONTROLLED_FAULT)
    assert item["measured"] is True
    assert item["met"] is False
    assert "calibration" in item["reason"] or "boundary" in item["reason"]


def test_normal_control_clean_run_is_measured_and_met(tmp_path):
    run = build_run(tmp_path, "control-online")
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["violations"] == []


def test_normal_control_run_carrying_the_finding_is_unmet(tmp_path):
    run = build_run(tmp_path, "control-online", tests=3,
                    statuses={"complete": 2, "dut_violation": 1},
                    session_status="finding",
                    violations=("gpio_b_irq_source_mismatch",))
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "gpio_b_irq_source_mismatch" in item["reason"]


def test_normal_control_run_with_an_uncertain_case_is_not_a_clean_control(tmp_path):
    run = build_run(tmp_path, "control-online", tests=7,
                    statuses={"complete": 6, "uncertain_effect": 1},
                    session_status="uncertain_effect")
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "uncertain_effect" in item["reason"]


def test_identity_and_replay_item_met_on_a_saved_prefix(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    identities = item["value"]["identities"]
    assert identities["raw"] is True
    assert identities["plan"] is True
    assert identities["trace"] is True
    assert identities["manifest"] is True
    assert item["value"]["replay"]["matches"] is True
    assert item["value"]["identity_refusal"]["mechanism"]


def test_identity_item_without_a_replay_log_is_measured_but_unmet(tmp_path):
    run = build_run(tmp_path, "run-online")
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    assert item["measured"] is True
    assert item["met"] is False
    assert "replay" in item["reason"]


def test_identity_item_with_a_diverged_replay_is_unmet(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run, matches=False)
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    assert item["measured"] is True
    assert item["met"] is False
    assert "matches" in item["reason"] or "replay" in item["reason"]


def test_identity_item_without_an_identity_document_is_unmeasured(tmp_path):
    run = build_run(tmp_path, "run-online")
    (run / "online_run_identity.json").unlink()
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    assert item["measured"] is False
    assert item["met"] is None
    assert "identity" in item["reason"]


def test_identity_item_with_a_broken_plan_binding_is_unmet(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    document = json.loads((run / "online_run_identity.json").read_text())
    document["identity"]["genome"]["plan_sha256"] = "ff" * 32
    _write_json(run / "online_run_identity.json", document)
    item = _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
    assert item["measured"] is True
    assert item["met"] is False
    assert "plan" in item["reason"]


def test_ten_minute_item_met_with_chains_and_a_fresh_replay(tmp_path):
    run = build_long_search(tmp_path)
    build_identity_and_replay(run)
    item = _item(p5_acceptance_report(run), ITEM_LONG_SEARCH)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["effective_search_seconds"] == 600.362952
    assert item["value"]["certified_chains"] == 27
    assert item["value"]["certified_chains_per_second"] == 0.044972
    assert item["value"]["natural_findings"] == 0
    assert item["value"]["replay"]["matches"] is True


def test_ten_minute_item_below_the_threshold_is_unmet(tmp_path):
    run = build_long_search(tmp_path, seconds=31.273544, chains=8,
                            per_second=0.255807)
    build_identity_and_replay(run)
    item = _item(p5_acceptance_report(run), ITEM_LONG_SEARCH)
    assert item["measured"] is True
    assert item["met"] is False
    assert "600" in item["reason"]


def test_ten_minute_item_without_a_replay_is_measured_but_unmet(tmp_path):
    run = build_long_search(tmp_path)
    item = _item(p5_acceptance_report(run), ITEM_LONG_SEARCH)
    assert item["measured"] is True
    assert item["met"] is False
    assert "replay" in item["reason"]


def test_ten_minute_item_without_the_acceptance_report_is_unmeasured(tmp_path):
    run = build_run(tmp_path, "run-online")
    item = _item(p5_acceptance_report(run), ITEM_LONG_SEARCH)
    assert item["measured"] is False
    assert item["met"] is None
    assert item["value"] is None
    assert item["reason"]


def test_paired_budget_item_met_with_wall_clock_comparison(tmp_path):
    continuous, cold = build_paired(tmp_path)
    report = p5_acceptance_report(continuous, compare_run=cold)
    item = _item(report, ITEM_PAIRED_BUDGET)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    value = item["value"]
    assert value["continuous"]["cases"] == 24
    assert value["cold_start"]["cases"] == 24
    assert value["cold_start"]["wall_clock_seconds"] == 512.881362
    assert value["speedup"] > 10.0
    assert value["case_identity_matched"] is True
    assert value["chain_per_second_equivalence"]["measurable"] is False
    assert value["chain_per_second_equivalence"]["reason"]


def test_paired_budget_item_cites_the_shipped_comparator(tmp_path):
    continuous, cold = build_paired(tmp_path)
    build_paired_comparator(continuous, cold)
    item = _item(p5_acceptance_report(continuous, compare_run=cold),
                 ITEM_PAIRED_BUDGET)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    value = item["value"]
    assert value["paired_report"]["comparable"] is True
    assert value["chain_per_second_equivalence"]["measured_from"] == \
        "paired_efficiency_report.v1"
    assert value["chain_per_second_equivalence"]["measurable"] is False
    assert "no certificate could be derived" in \
        value["chain_per_second_equivalence"]["reason"]
    build_paired_comparator(continuous, cold, comparable=False)
    refused = _item(p5_acceptance_report(continuous, compare_run=cold),
                    ITEM_PAIRED_BUDGET)
    assert refused["measured"] is True
    assert refused["met"] is False
    assert "comparable" in refused["reason"]


def test_paired_budget_item_without_the_cold_arm_is_unmeasured(tmp_path):
    continuous = build_run(tmp_path, "current-dataflow-p5-paired-20261008-online")
    item = _item(p5_acceptance_report(continuous), ITEM_PAIRED_BUDGET)
    assert item["measured"] is False
    assert item["met"] is None
    assert item["reason"]


def test_paired_budget_item_with_a_different_case_count_is_unmet(tmp_path):
    continuous, cold = build_paired(tmp_path)
    document = json.loads((cold / "cold_start.json").read_text())
    document["case_count"] = 15
    document["verified_case_count"] = 15
    document["cases"] = document["cases"][:15]
    _write_json(cold / "cold_start.json", document)
    report = json.loads((cold / "report.json").read_text())
    report["tests"] = 15
    report["verified_case_count"] = 15
    _write_json(cold / "report.json", report)
    item = _item(p5_acceptance_report(continuous, compare_run=cold),
                 ITEM_PAIRED_BUDGET)
    assert item["measured"] is True
    assert item["met"] is False
    assert "case" in item["reason"]


# ------------------------------------------------------- exits and the union


def test_an_empty_run_directory_measures_nothing_and_never_fabricates_a_zero(tmp_path):
    run = tmp_path / "empty-online"
    run.mkdir()
    report = p5_acceptance_report(run)
    assert report["schema_version"] == "p5_acceptance_report.v1"
    assert report["exit_code"] == EXIT_NOT_READY
    for item in report["items"]:
        assert item["measured"] is False
        assert item["met"] is None
        assert item["value"] is None
        assert item["reason"]


def test_per_run_exit_code_is_zero_only_when_every_critical_item_is_met(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    report = p5_acceptance_report(run)
    assert report["critical_total"] == len(CRITICAL_ITEMS)
    assert report["critical_met"] < len(CRITICAL_ITEMS)
    assert report["exit_code"] == EXIT_NOT_READY
    assert _item(report, ITEM_ASSERTION_CLASSES)["measured"] is False


def test_suite_union_two_runs_each_proving_part(tmp_path):
    first = build_run(tmp_path, "first-online")
    build_identity_and_replay(first)
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", run_dir=str(first))
    long_run = build_long_search(tmp_path)
    build_identity_and_replay(long_run)
    fault = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path)
    control = build_run(tmp_path, "control-online")
    continuous, cold = build_paired(tmp_path)

    suite = p5_acceptance_suite([
        {"role": "chain_acceptance", "run_dir": str(first),
         "artifacts": {ARTIFACT_ASSERTION_CLASSES: str(report_path)}},
        {"role": "long_search", "run_dir": str(long_run)},
        {"role": "fault_calibration", "run_dir": str(fault),
         "compare_run": str(reproduce)},
        {"role": "control", "run_dir": str(control)},
        {"role": "paired_continuous", "run_dir": str(continuous),
         "compare_run": str(cold)},
    ])
    assert suite["schema_version"] == "p5_acceptance_suite.v1"
    assert suite["critical_total"] == len(CRITICAL_ITEMS)
    assert suite["critical_met"] == len(CRITICAL_ITEMS), suite["critical_unmet"]
    assert suite["exit_code"] == EXIT_READY
    assert suite["no_proving_run"] == []
    for key in CRITICAL_ITEMS:
        item = _union_item(suite, key)
        assert item["measured"] is True
        assert item["met"] is True, (key, item["reason"])
        assert item["proving_runs"], key
    # neither run alone proves everything -- the union is the point
    assert max(row["critical_met"] for row in suite["runs"]) < len(CRITICAL_ITEMS)
    assert len(suite["runs"]) == 5


def test_suite_boundaries_name_the_heterogeneous_gap(tmp_path):
    run = build_run(tmp_path, "uart-online")
    build_identity_and_replay(run)
    suite = p5_acceptance_suite([
        {"role": "heterogeneous_uart", "run_dir": str(run)}])
    assert any("heterogeneous_uart" in entry and "600" in entry
               for entry in suite["boundaries"])
    assert any("p5_assertion_classes.v1 report exists for" in entry
               for entry in suite["boundaries"])


def test_suite_exits_two_and_names_the_item_without_a_proving_run(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    suite = p5_acceptance_suite([
        {"role": "chain_acceptance", "run_dir": str(run)}])
    assert suite["exit_code"] == EXIT_NOT_READY
    assert suite["no_proving_run"]
    assert ITEM_CONTROLLED_FAULT in suite["no_proving_run"]
    item = _union_item(suite, ITEM_CONTROLLED_FAULT)
    assert item["measured"] is False
    assert item["met"] is None
    assert item["reason"]


def test_suite_control_item_needs_the_fault_antecedent(tmp_path):
    control = build_run(tmp_path, "control-online")
    suffix = p5_acceptance_suite([{"role": "control", "run_dir": str(control)}])
    item = _union_item(suffix, ITEM_NORMAL_CONTROL)
    assert item["measured"] is False
    assert item["met"] is None
    assert "antecedent" in item["reason"] or "finding" in item["reason"]

    fault = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path)
    suite = p5_acceptance_suite([
        {"role": "control", "run_dir": str(control)},
        {"role": "fault_calibration", "run_dir": str(fault),
         "compare_run": str(reproduce)},
    ])
    item = _union_item(suite, ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["antecedent_findings"] == ["gpio_b_irq_source_mismatch"]
    assert item["value"]["controls_checked"]


def test_suite_control_item_is_unmet_when_the_control_carries_the_finding(tmp_path):
    fault = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path)
    dirty = build_run(tmp_path, "control-online", tests=3,
                      statuses={"complete": 2, "dut_violation": 1},
                      session_status="finding",
                      violations=("gpio_b_irq_source_mismatch",))
    suite = p5_acceptance_suite([
        {"role": "control", "run_dir": str(dirty)},
        {"role": "fault_calibration", "run_dir": str(fault),
         "compare_run": str(reproduce)},
    ])
    item = _union_item(suite, ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False


def test_role_mismatch_is_reported_not_silently_skipped(tmp_path):
    run = build_run(tmp_path, "run-online")
    suite = p5_acceptance_suite([
        {"role": "fault_calibration", "run_dir": str(run)}])
    assert len(suite["runs"]) == 1
    roles = {row["role"]: row for row in suite["role_evidence"]}
    assert roles["fault_calibration"]["matched"] is False
    assert roles["fault_calibration"]["missing"]
    assert roles["fault_calibration"]["reason"]
    assert suite["runs"][0]["role_evidence"]["matched"] is False


def test_suite_rejects_a_duplicate_role(tmp_path):
    run = build_run(tmp_path, "run-online")
    try:
        p5_acceptance_suite([{"role": "supporting", "run_dir": str(run)},
                             {"role": "supporting", "run_dir": str(run)}])
    except ValueError as error:
        assert "duplicate" in str(error)
    else:  # pragma: no cover - the suite must refuse
        raise AssertionError("a duplicate role was accepted")


def test_suite_is_byte_identical_across_runs(tmp_path):
    control = build_run(tmp_path, "control-online")
    fault = build_fault_run(tmp_path)
    reproduce = build_reproduce(tmp_path)
    declarations = [
        {"role": "control", "run_dir": str(control)},
        {"role": "fault_calibration", "run_dir": str(fault),
         "compare_run": str(reproduce)},
    ]
    first = p5_acceptance_suite(declarations)
    second = p5_acceptance_suite(list(reversed(declarations)))
    first_runs = {row["role"]: row for row in first["runs"]}
    second_runs = {row["role"]: row for row in second["runs"]}
    assert json.dumps(first_runs, sort_keys=True, allow_nan=False) == \
        json.dumps(second_runs, sort_keys=True, allow_nan=False)
    assert render_markdown(first) == render_markdown(second)
    again = p5_acceptance_suite(declarations)
    assert json.dumps(again, sort_keys=True) == json.dumps(first, sort_keys=True)


# ------------------------------------------------------------------ the CLI


def _run_cli(*arguments: str):
    environment = {"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"}
    return subprocess.run([sys.executable, str(CLI), *arguments],
                          capture_output=True, text=True, env=environment,
                          cwd=str(ROOT))


def test_parse_run_declaration_is_role_first_and_explicit():
    declaration = parse_run_declaration("long_search=runs/a-online@runs/b-cold")
    assert declaration == {"role": "long_search", "run_dir": "runs/a-online",
                           "compare_run": "runs/b-cold", "artifacts": {}}
    alone = parse_run_declaration("supporting=runs/a-online")
    assert alone["compare_run"] is None
    try:
        parse_run_declaration("runs/a-online")
    except ValueError as error:
        assert "ROLE=DIR" in str(error)
    else:  # pragma: no cover - declaration must be refused
        raise AssertionError("a declaration without a role was accepted")


def test_parse_artifact_declaration_names_role_key_and_path():
    assert parse_artifact_declaration(
        "long_search=first_step_acceptance=runs/x-logs/acceptance.json") == {
        "role": "long_search", "key": "first_step_acceptance",
        "path": "runs/x-logs/acceptance.json"}


def test_cli_exits_one_on_a_run_that_cannot_be_declared(tmp_path):
    result = _run_cli("--run", "long_search=runs/does-not-exist-online")
    assert result.returncode == EXIT_USAGE
    document = json.loads(result.stdout.strip().splitlines()[-1])
    assert document["schema_version"] == "p5_acceptance_suite_error.v1"
    assert document["error"]


def test_cli_exits_two_when_a_critical_item_has_no_proving_run(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    result = _run_cli("--run", f"chain_acceptance={run}")
    assert result.returncode == EXIT_NOT_READY
    document = json.loads(result.stdout.strip().splitlines()[-1])
    assert document["exit_code"] == EXIT_NOT_READY
    assert document["no_proving_run"]


def test_cli_accepts_an_explicit_artifact_declaration(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    report_path = build_assertion_classes(
        tmp_path / "assertion_classes.json", run_dir=str(run))
    result = _run_cli(
        "--run", f"chain_acceptance={run}",
        "--artifact", f"chain_acceptance=assertion_classes={report_path}")
    assert result.returncode == EXIT_NOT_READY
    document = json.loads(result.stdout.strip().splitlines()[-1])
    item = _union_item(document, ITEM_ASSERTION_CLASSES)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]


def test_cli_refuses_an_artifact_for_an_undeclared_role(tmp_path):
    run = build_run(tmp_path, "run-online")
    result = _run_cli("--run", f"chain_acceptance={run}",
                      "--artifact", "long_search=replay=runs/whatever.json")
    assert result.returncode == EXIT_USAGE
    document = json.loads(result.stdout.strip().splitlines()[-1])
    assert "long_search" in document["error"]


def test_cli_writes_byte_identical_documents(tmp_path):
    run = build_run(tmp_path, "run-online")
    build_identity_and_replay(run)
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    assert _run_cli("--run", f"chain_acceptance={run}",
                    "--json-out", str(first)).returncode == EXIT_NOT_READY
    assert _run_cli("--run", f"chain_acceptance={run}",
                    "--json-out", str(second)).returncode == EXIT_NOT_READY
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text())["schema_version"] == \
        "p5_acceptance_suite.v1"
