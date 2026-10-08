"""The P5 normal-control judge must read a run's *own* declared status field.

Two shipped report schemas coexist:

* the online live writer stores ``session_status`` (its session outcome), and
* ``first_step_cold_start_run_report.v1`` stores ``execution_status`` instead
  and never claims to carry ``session_status`` at all.

The judge used to read only ``report.get("session_status")``, so the saved
cold-start arm of the same-budget pair was reported as
``session_status is None, not 'complete'`` and could not be used as a clean
control even though every one of its per-case receipts is ``complete``.

The fix is deliberately fail-closed: a run is only accepted when the status it
declares agrees with the per-case receipts this judge streams itself, so a
declared "complete" over non-complete cases, a status that contradicts the
receipts, or a report that declares no status field at all are all refused.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from myfuzz.scenario.p5_acceptance import (
    ITEM_NORMAL_CONTROL,
    p5_acceptance_report,
)


def _write_json(path: Path, document) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")


def _write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n"
                            for row in rows), encoding="utf-8")


def _item(report: dict, key: str) -> dict:
    rows = [row for row in report["items"] if row["key"] == key]
    assert len(rows) == 1, f"item {key} is not reported exactly once"
    return rows[0]


def build_cold_start_run(root: Path, name: str = "cold-start", *,
                         cases: int = 4,
                         receipt_statuses=None,
                         report_statuses=None,
                         execution_status: str | None = "complete",
                         session_status=None,
                         schema_version: str = "first_step_cold_start_run_report.v1",
                         failures: int = 0) -> Path:
    """A real-shaped cold-start run directory: report.json + receipts.jsonl."""
    run = root / name
    (run / "failures").mkdir(parents=True, exist_ok=True)
    rows = []
    for index in range(cases):
        status = (receipt_statuses or ["complete"] * cases)[index]
        rows.append({"case_id": f"online-{index}-{index:024x}",
                     "status": status,
                     "violations": (["gpio_b_irq_source_mismatch"]
                                    if status == "dut_violation" else [])})
    _write_jsonl(run / "receipts.jsonl", rows)
    for index in range(failures):
        _write_json(run / "failures" / f"finding_{index}.json", {"index": index})
    report = {
        "schema_version": schema_version,
        "execution_mode": "online_cases_per_case_cold_start",
        "tests": cases,
        "case_count": cases,
        "statuses": dict(report_statuses or {"complete": cases}),
        "verification_failure_count": 0,
        "case_failure_count": 0,
    }
    if execution_status is not None:
        report["execution_status"] = execution_status
    if session_status is not None:
        report["session_status"] = session_status
    _write_json(run / "report.json", report)
    return run


# ------------------------------------------------------------- the gap itself


def test_cold_start_execution_status_is_used_as_the_session_status(tmp_path):
    run = build_cold_start_run(tmp_path)
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is True, item["reason"]
    assert item["value"]["session_status"] == "complete"
    assert item["value"]["session_status_source"] == (
        "report.json:execution_status (declared by schema "
        "first_step_cold_start_run_report.v1)")
    assert item["value"]["clean"] is True


def test_the_cold_start_arm_becomes_a_clean_control_of_a_declared_pair(tmp_path):
    """The exact saved shape: 24 complete cases, execution_status=complete."""
    run = build_cold_start_run(tmp_path, cases=24)
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["met"] is True, item["reason"]
    assert item["value"]["receipts"] == 24


# ------------------------------------------------------------- refusal paths


def test_declared_complete_over_a_non_complete_case_is_refused(tmp_path):
    """execution_status=complete is not enough: the receipts must agree."""
    run = build_cold_start_run(
        tmp_path, cases=3,
        receipt_statuses=["complete", "complete", "input_invalid"],
        report_statuses={"complete": 2, "input_invalid": 1})
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "input_invalid" in item["reason"]
    assert "receipt" in item["reason"]


def test_declared_complete_over_a_dut_violation_case_is_refused(tmp_path):
    run = build_cold_start_run(
        tmp_path, cases=2,
        receipt_statuses=["complete", "dut_violation"],
        report_statuses={"complete": 1, "dut_violation": 1})
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["met"] is False
    assert "dut_violation" in item["reason"]


def test_a_statuses_mapping_that_contradicts_the_receipts_is_refused(tmp_path):
    """The report's own statuses map must agree with the rows it published."""
    run = build_cold_start_run(tmp_path, cases=2,
                               report_statuses={"complete": 2})
    rows = [json.loads(line)
            for line in (run / "receipts.jsonl").read_text().splitlines()]
    rows[0]["status"] = "uncertain_effect"
    _write_jsonl(run / "receipts.jsonl", rows)
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "statuses" in item["reason"]


def test_a_non_complete_declared_execution_status_is_refused(tmp_path):
    run = build_cold_start_run(tmp_path, execution_status="failed")
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "execution_status" in item["reason"] or "session_status" in item["reason"]


def test_a_report_without_any_declared_status_field_is_refused(tmp_path):
    run = build_cold_start_run(tmp_path, execution_status=None,
                               schema_version="some_other_run_report.v9")
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "session_status" in item["reason"]


def test_an_explicit_null_session_status_keeps_its_reason(tmp_path):
    """A run that declares the field as null is honest, not clean."""
    run = build_cold_start_run(tmp_path, session_status=None)
    document = json.loads((run / "report.json").read_text())
    document["schema_version"] = "online_live_run_report.v9"
    document["session_status"] = None
    _write_json(run / "report.json", document)
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "None" in item["reason"] or "session_status" in item["reason"]


def test_a_non_string_declared_status_is_refused(tmp_path):
    run = build_cold_start_run(tmp_path, execution_status=3)
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False


def test_the_online_session_status_still_wins_when_both_are_present(tmp_path):
    """A live report keeps its own session_status, even beside execution_status."""
    run = build_cold_start_run(tmp_path, session_status="finding",
                               receipt_statuses=["complete", "complete",
                                                 "dut_violation", "complete"],
                               report_statuses={"complete": 3,
                                                "dut_violation": 1})
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["met"] is False
    assert item["value"]["session_status"] == "finding"
    assert item["value"]["session_status_source"] == "report.json:session_status"


def test_an_empty_receipts_file_cannot_prove_a_complete_session(tmp_path):
    run = build_cold_start_run(tmp_path, cases=1)
    (run / "receipts.jsonl").write_text("", encoding="utf-8")
    item = _item(p5_acceptance_report(run), ITEM_NORMAL_CONTROL)
    assert item["measured"] is True
    assert item["met"] is False
    assert "receipt" in item["reason"]
