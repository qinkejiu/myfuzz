"""P3 acceptance **suite**: an honest union of per-item evidence across runs.

The frozen consumer :func:`myfuzz.scenario.p3_acceptance.p3_acceptance_report`
judges **one** saved run.  No saved run in this repository satisfies all seven
critical P3 items at once, so this suite aggregates several *declared* runs and
must say exactly which run proves which item.

Two kinds of fixtures are used here:

* stub reports (``monkeypatch`` on the suite module's ``p3_acceptance_report``)
  for every aggregation rule, so each expectation is a value this file writes
  itself: one run proving one item, an item unmeasured everywhere, a controlled
  fault without ``compare_run``, per-run detail retention, illegal roles,
  duplicate roles, missing directories and a crashing producer;
* real synthetic run directories built by the *frozen* p3 test helpers
  (``tests.scenario.test_p3_acceptance._write_run``) so the union rule is also
  exercised against genuine ``p3_acceptance_report.v1`` documents: the default
  synthetic run proves six critical items and leaves
  ``finding_stops_and_replays`` unmeasured, while a finding run plus its
  reproduction run proves the seventh.

No test here starts RTL, renders a harness or touches a simulator.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

import myfuzz.scenario.p3_acceptance as frozen
import myfuzz.scenario.p3_acceptance_suite as suite_module
from myfuzz.scenario.p3_acceptance_suite import (
    CONTROLLED_FAULT_ROLE,
    CRITICAL_ITEMS,
    EVIDENCE_DIGEST_RECIPE,
    EXIT_NOT_READY,
    EXIT_READY,
    LEGAL_ROLES,
    NON_CRITICAL_ITEMS,
    RTL_EVENT_LEVEL_KEY,
    SCHEMA_VERSION,
    SuiteRun,
    item_evidence_digest,
    p3_acceptance_suite,
    render_markdown,
)
from tests.scenario.test_p3_acceptance import RUN_ID, _write_run

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "run_p3_acceptance_suite.py"
EXIT_USAGE = 1

#: The seven critical keys, in the frozen consumer's own order.
EXPECTED_CRITICAL_ITEMS = (
    "single_initialization", "store_then_load", "cross_case_chains",
    "feedback_changes_next_input", "finding_stops_and_replays",
    "chunk_split_invariance", "execution_identity")
FINDING = "finding_stops_and_replays"
STORE = "store_then_load"


# --------------------------------------------------------------- stub reports


def _unmeasured(key: str, reason: str | None = None) -> dict:
    return {"measured": False, "met": None, "evidence": None,
            "reason": reason or f"{key} is not observable in this stub run"}


def _met(key: str, evidence: dict | None = None) -> dict:
    return {"measured": True, "met": True,
            "evidence": evidence if evidence is not None
            else {"proof": f"{key}-evidence", "count": 3},
            "reason": None}


def _unmet(key: str, reason: str) -> dict:
    return {"measured": True, "met": False,
            "evidence": {"proof": f"{key}-partial", "count": 0},
            "reason": reason}


def _all_unmeasured() -> dict:
    return {key: _unmeasured(key) for key in CRITICAL_ITEMS}


@dataclass
class _Stub:
    """One stub ``p3_acceptance_report.v1`` document, per declared run."""

    items: dict
    run_id: str = "stub-run"
    run_identity_sha256: str = "a" * 64
    manifest_identity_sha256: str = "b" * 64
    engine_sha256: str = "c" * 64
    error: Exception | None = None
    with_gate: bool = True
    rtl_event_level: dict | None = None

    def document(self, run_dir, compare_run=None) -> dict:
        items: dict[str, dict] = {}
        for key, body in self.items.items():
            items[key] = {"criterion": frozen.CRITERIA[key],
                          "measured": body["measured"], "met": body["met"],
                          "evidence": body.get("evidence"),
                          "reason": body.get("reason")}
        if self.rtl_event_level is not None and "chunk_split_invariance" in items:
            chunk = items["chunk_split_invariance"]
            chunk["evidence"] = dict(chunk.get("evidence") or {})
            chunk["evidence"]["rtl_event_level"] = dict(self.rtl_event_level)
        rows = [{"key": key, "critical": True, "measured": body["measured"],
                 "met": body["met"], "value": None, "reason": body.get("reason")}
                for key, body in self.items.items()]
        rows.append({"key": RTL_EVENT_LEVEL_KEY, "critical": False,
                     "measured": False, "met": None, "value": None,
                     "reason": "the real-RTL half is not observable from a "
                               "saved run"})
        missing = [row["key"] for row in rows
                   if row["critical"] and not row["measured"]]
        unmet = [row["key"] for row in rows
                 if row["critical"] and row["measured"] and row["met"] is False]
        document = {
            "schema_version": frozen.SCHEMA_VERSION,
            "run_dir": str(run_dir), "run_id": self.run_id,
            "run_identity_sha256": self.run_identity_sha256,
            "compare_run_dir": (None if compare_run is None
                                else str(compare_run)),
            "manifest": {"identity_sha256": self.manifest_identity_sha256},
            "engine": {"p3_acceptance": {"module": frozen.__name__,
                                         "path": str(frozen.__file__),
                                         "sha256": self.engine_sha256}},
            "gate": ({"items": rows, "critical_missing": missing,
                      "critical_unmet": unmet,
                      "exit_code": 0 if not missing and not unmet else 2,
                      "summary": "stub gate"}
                     if self.with_gate else None),
            **items,
        }
        return document


def _install(monkeypatch, stubs: dict[str, _Stub], calls: list | None = None):
    """Replace the frozen producer inside the suite module with stub documents."""
    recorded = calls if calls is not None else []

    def fake(run_dir, *, compare_run=None):
        recorded.append((str(run_dir),
                         None if compare_run is None else str(compare_run)))
        stub = stubs[str(run_dir)]
        if stub.error is not None:
            raise stub.error
        return stub.document(run_dir, compare_run)

    monkeypatch.setattr(suite_module, "p3_acceptance_report", fake)
    return recorded


def _dirs(tmp_path: Path, *names: str) -> list[Path]:
    made = []
    for name in names:
        directory = tmp_path / name
        directory.mkdir(parents=True, exist_ok=True)
        made.append(directory)
    return made


# ---------------------------------------------------------------- single run


def test_one_run_proving_one_item_lists_that_run_and_its_digest(
        tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    items = _all_unmeasured()
    items[STORE] = _met(STORE)
    stub = _Stub(items)
    calls = _install(monkeypatch, {str(run): stub})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    assert suite["schema_version"] == SCHEMA_VERSION
    assert calls == [(str(run), None)]
    item = suite["items"][STORE]
    assert item["status"] == "met"
    assert item["met_by_at_least_one_run"] is True
    assert [entry["role"] for entry in item["met_by"]] == ["primary"]
    entry = item["met_by"][0]
    assert entry["run_dir"] == str(run)
    assert entry["resolved_run_dir"] == str(run)
    assert isinstance(entry["evidence_digest"], str)
    assert len(entry["evidence_digest"]) == 64
    assert entry["evidence_digest"] == item_evidence_digest(
        stub.document(run), STORE, run_dir=str(run))
    assert entry["evidence_fields"]
    assert "proof" in " ".join(entry["evidence_fields"])
    # The per-run detail survives next to the union verdict.
    detail = item["per_run"]["primary"]
    assert detail["status"] == "met"
    assert detail["measured"] is True
    assert detail["met"] is True
    assert detail["run_dir"] == str(run)
    assert detail["evidence_digest"] == entry["evidence_digest"]

    # Only one of seven critical items is proven, so the gate must not be ready.
    assert suite["items"]["single_initialization"]["status"] == "unmeasured"
    assert suite["gate"]["exit_code"] == EXIT_NOT_READY
    assert suite["gate"]["met_by_at_least_one_run"] == [STORE]
    assert set(suite["gate"]["unmeasured_across_all_runs"]) == (
        set(CRITICAL_ITEMS) - {STORE})


def test_two_runs_proving_the_same_item_are_both_listed(tmp_path, monkeypatch):
    first, second = _dirs(tmp_path, "primary", "cross_case")
    items = _all_unmeasured()
    items[STORE] = _met(STORE)
    _install(monkeypatch, {str(first): _Stub(dict(items)),
                           str(second): _Stub(dict(items))})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(first)},
        {"role": "cross_case", "run_dir": str(second)}])

    item = suite["items"][STORE]
    assert item["status"] == "met"
    assert [entry["role"] for entry in item["met_by"]] == ["primary", "cross_case"]
    assert set(item["per_run"]) == {"primary", "cross_case"}


def test_suite_run_declaration_objects_are_accepted(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    _install(monkeypatch, {str(run): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([SuiteRun(role="primary", run_dir=str(run))])

    assert [row["role"] for row in suite["runs"]] == ["primary"]


# -------------------------------------------------------- unmeasured / unmet


def test_item_unmeasured_by_every_run_is_named_and_forces_exit_two(
        tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    _install(monkeypatch, {str(run): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    assert suite["gate"]["unmeasured_across_all_runs"] == list(CRITICAL_ITEMS)
    assert suite["gate"]["met_by_at_least_one_run"] == []
    assert suite["gate"]["exit_code"] == EXIT_NOT_READY
    assert suite["gate"]["ready"] is False
    for key in CRITICAL_ITEMS:
        assert suite["items"][key]["status"] == "unmeasured"
        assert suite["items"][key]["met_by"] == []


def test_a_not_met_run_is_kept_in_the_per_run_detail(tmp_path, monkeypatch):
    proving, failing = _dirs(tmp_path, "primary", "cross_case")
    proven_items = _all_unmeasured()
    proven_items[STORE] = _met(STORE)
    failing_items = _all_unmeasured()
    failing_items[STORE] = _unmet(STORE, "the load returned another version")
    _install(monkeypatch, {str(proving): _Stub(proven_items),
                           str(failing): _Stub(failing_items)})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(proving)},
        {"role": "cross_case", "run_dir": str(failing)}])

    item = suite["items"][STORE]
    # One run proves it, so the union says met ...
    assert item["status"] == "met"
    assert [entry["role"] for entry in item["met_by"]] == ["primary"]
    # ... but the not-met run is never hidden.
    detail = item["per_run"]["cross_case"]
    assert detail["status"] == "unmet"
    assert detail["measured"] is True
    assert detail["met"] is False
    assert detail["reason"] == "the load returned another version"
    assert [row["role"] for row in item["not_met_by"]] == ["cross_case"]
    assert item["not_met_by"][0]["reason"] == "the load returned another version"


def test_measured_but_undecided_is_recorded_as_undecided(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    items = _all_unmeasured()
    items[STORE] = {"measured": True, "met": None, "evidence": {"count": 0},
                    "reason": "the evidence exists but the criterion is undecided"}
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    item = suite["items"][STORE]
    assert item["status"] == "unmet"
    assert item["measured_by"] == ["primary"]
    assert item["undecided_by"] == ["primary"]
    assert item["met_by"] == []


# ------------------------------------------------------- controlled fault run


def test_controlled_fault_without_compare_run_cannot_prove_the_replay_item(
        tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "fault")
    items = _all_unmeasured()
    # The stub claims met without a declared comparison run: the suite must
    # refuse to count it, whatever the producer document says.
    items[FINDING] = _met(FINDING)
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite(
        [{"role": CONTROLLED_FAULT_ROLE, "run_dir": str(run)}])

    item = suite["items"][FINDING]
    assert item["status"] != "met"
    assert item["met_by"] == []
    assert item["met_by_at_least_one_run"] is False
    assert [row["role"] for row in item["excluded_from_met_by"]] == [
        CONTROLLED_FAULT_ROLE]
    assert "compare_run" in item["excluded_from_met_by"][0]["reason"]
    assert item["evidence_kind"] is None
    assert suite["gate"]["exit_code"] == EXIT_NOT_READY


def test_controlled_fault_with_compare_run_proves_it_and_is_marked_injected(
        tmp_path, monkeypatch):
    fault, reproduce = _dirs(tmp_path, "fault", "reproduce")
    items = _all_unmeasured()
    items[FINDING] = _met(FINDING, evidence={
        "report_session_status": "finding",
        "finding_case_ids": ["case-3"],
        "fresh_replay": {"measured": True, "met": True,
                         "compare_run": {"different_run": True,
                                         "same_case_id": True}}})
    calls = _install(monkeypatch, {str(fault): _Stub(items)})

    suite = p3_acceptance_suite([
        {"role": CONTROLLED_FAULT_ROLE, "run_dir": str(fault),
         "compare_run": str(reproduce)}])

    assert calls == [(str(fault), str(reproduce))]
    item = suite["items"][FINDING]
    assert item["status"] == "met"
    assert [entry["role"] for entry in item["met_by"]] == [CONTROLLED_FAULT_ROLE]
    assert item["injected_calibration"] is True
    assert item["evidence_kind"] == "injected_fault_calibration"
    assert "injected" in item["caveat"]
    assert "natural" in item["caveat"]
    assert item["per_run"][CONTROLLED_FAULT_ROLE]["compare_run"] == str(reproduce)
    assert suite["gate"]["exit_code"] == EXIT_NOT_READY  # six items still missing


def test_a_natural_role_cannot_prove_the_replay_item(tmp_path, monkeypatch):
    run, reproduce = _dirs(tmp_path, "primary", "reproduce")
    items = _all_unmeasured()
    items[FINDING] = _met(FINDING)
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(run),
         "compare_run": str(reproduce)}])

    item = suite["items"][FINDING]
    assert item["status"] != "met"
    assert item["met_by"] == []
    assert item["per_run"]["primary"]["status"] == "met"  # the raw claim is kept
    assert "controlled_fault" in item["excluded_from_met_by"][0]["reason"]


# ------------------------------------------------------------- declaration API


def test_a_run_declaration_must_name_a_legal_role(tmp_path):
    run, = _dirs(tmp_path, "run")

    with pytest.raises(ValueError, match="role"):
        p3_acceptance_suite([{"run_dir": str(run)}])
    with pytest.raises(ValueError, match="not a legal role"):
        p3_acceptance_suite([{"role": "favourite", "run_dir": str(run)}])
    with pytest.raises(ValueError, match="role"):
        p3_acceptance_suite([{"role": "", "run_dir": str(run)}])
    with pytest.raises(ValueError, match="run declaration"):
        p3_acceptance_suite([["primary", str(run)]])
    with pytest.raises(ValueError, match="run_dir"):
        p3_acceptance_suite([{"role": "primary"}])


def test_a_duplicate_role_is_rejected(tmp_path):
    first, second = _dirs(tmp_path, "a", "b")
    with pytest.raises(ValueError, match="duplicate role"):
        p3_acceptance_suite([
            {"role": "primary", "run_dir": str(first)},
            {"role": "primary", "run_dir": str(second)}])


def test_a_run_declaration_must_not_carry_unknown_keys(tmp_path):
    run, = _dirs(tmp_path, "run")
    with pytest.raises(ValueError, match="unknown"):
        p3_acceptance_suite([{"role": "primary", "run_dir": str(run),
                              "cmpare_run": None}])


def test_an_empty_run_list_is_rejected():
    with pytest.raises(ValueError, match="at least one run"):
        p3_acceptance_suite([])
    with pytest.raises(ValueError, match="sequence"):
        p3_acceptance_suite(None)  # type: ignore[arg-type]


def test_a_missing_run_directory_is_a_hard_error(tmp_path, monkeypatch):
    missing = tmp_path / "absent"

    def explode(*args, **kwargs):  # pragma: no cover - must not be called
        raise AssertionError("the producer must not run for a missing directory")

    monkeypatch.setattr(suite_module, "p3_acceptance_report", explode)
    with pytest.raises(ValueError, match="run directory does not exist"):
        p3_acceptance_suite([{"role": "primary", "run_dir": str(missing)}])


def test_a_compare_run_must_exist_and_differ(tmp_path):
    run, = _dirs(tmp_path, "fault")
    with pytest.raises(ValueError, match="comparison run directory does not exist"):
        p3_acceptance_suite([{ 
            "role": CONTROLLED_FAULT_ROLE, "run_dir": str(run),
            "compare_run": str(tmp_path / "absent")}])
    with pytest.raises(ValueError, match="different"):
        p3_acceptance_suite([{
            "role": CONTROLLED_FAULT_ROLE, "run_dir": str(run),
            "compare_run": str(run)}])


def test_legal_roles_include_the_documented_ones():
    assert {"primary", "controlled_fault", "cross_case", "feedback",
            "supporting"} <= set(LEGAL_ROLES)
    assert CONTROLLED_FAULT_ROLE == "controlled_fault"


# ------------------------------------------------------------ producer errors


def test_a_crashing_producer_is_recorded_and_fails_closed(tmp_path, monkeypatch):
    broken, healthy = _dirs(tmp_path, "broken", "healthy")
    items = _all_unmeasured()
    items[STORE] = _met(STORE)
    _install(monkeypatch, {str(broken): _Stub(_all_unmeasured(),
                                              error=RuntimeError("corrupt trace")),
                           str(healthy): _Stub(items)})

    suite = p3_acceptance_suite([
        {"role": "cross_case", "run_dir": str(broken)},
        {"role": "primary", "run_dir": str(healthy)}])

    assert suite["runs_with_errors"] == ["cross_case"]
    row = next(row for row in suite["runs"] if row["role"] == "cross_case")
    assert row["error"]["type"] == "RuntimeError"
    assert "corrupt trace" in row["error"]["message"]
    # Nothing is fabricated for the broken run ...
    assert suite["items"][STORE]["per_run"]["cross_case"]["status"] == "unmeasured"
    assert suite["items"][STORE]["per_run"]["cross_case"]["measured"] is False
    # ... the healthy run's evidence is still reported ...
    assert [entry["role"] for entry in suite["items"][STORE]["met_by"]] == ["primary"]
    # ... and the gate never becomes ready while a declared run could not be read.
    assert suite["gate"]["exit_code"] == EXIT_NOT_READY
    assert any("could not be produced" in limit["reason"]
               for limit in suite["gate"]["limits"])


def test_a_report_without_a_gate_still_contributes_its_items(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    items = _all_unmeasured()
    items[STORE] = _met(STORE)
    _install(monkeypatch, {str(run): _Stub(items, with_gate=False)})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    row = suite["runs"][0]
    assert row["frozen_gate_exit_code"] is None
    assert suite["items"][STORE]["status"] == "met"


# ------------------------------------------------------------------- digests


def test_evidence_digest_is_recomputable_and_binds_the_run(tmp_path, monkeypatch):
    first, second = _dirs(tmp_path, "a", "b")
    items = _all_unmeasured()
    items[STORE] = _met(STORE)
    stub = _Stub(items)
    _install(monkeypatch, {str(first): stub, str(second): stub})

    document = stub.document(first)
    digest = item_evidence_digest(document, STORE, run_dir=str(first))
    assert digest == item_evidence_digest(document, STORE, run_dir=str(first))
    subject = _digest_subject(document, STORE, str(first))
    assert digest == hashlib.sha256(json.dumps(
        subject, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("utf-8")).hexdigest()
    # A different declared directory is a different evidence binding.
    assert digest != item_evidence_digest(document, STORE, run_dir=str(second))
    # Another item in the same report has another digest.
    assert digest != item_evidence_digest(document, "cross_case_chains",
                                          run_dir=str(first))
    # Different evidence content changes the digest.
    other = _Stub(dict(items))
    other.items[STORE] = _met(STORE, evidence={"proof": "other", "count": 9})
    assert digest != item_evidence_digest(other.document(first), STORE,
                                          run_dir=str(first))
    reported = p3_acceptance_suite([{"role": "primary", "run_dir": str(first)}])
    assert reported["evidence_digest_recipe"] == EVIDENCE_DIGEST_RECIPE
    assert reported["engine"]["digest_recipe"] == EVIDENCE_DIGEST_RECIPE
    assert reported["items"][STORE]["met_by"][0]["evidence_digest"] == (
        item_evidence_digest(stub.document(first), STORE, run_dir=str(first)))


def _digest_subject(report: Mapping, key: str, run_dir: str) -> dict:  # noqa: F821
    """The documented digest subject, rebuilt independently of the module."""
    item = report[key]
    return {
        "schema_version": "p3_acceptance_suite.evidence.v1",
        "suite_schema_version": SCHEMA_VERSION,
        "run_dir": run_dir,
        "report_schema_version": report.get("schema_version"),
        "run_identity_sha256": report.get("run_identity_sha256"),
        "manifest_identity_sha256": (report.get("manifest") or {}).get(
            "identity_sha256"),
        "engine": {
            "p3_acceptance": _module_sha256(frozen),
            "p3_acceptance_suite": _module_sha256(suite_module)},
        "item": {"key": key, "measured": item.get("measured"),
                 "met": item.get("met"), "reason": item.get("reason"),
                 "evidence": item.get("evidence")}}


def _module_sha256(module) -> str:
    return hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()


def test_decisive_scalar_paths_survive_a_long_array_in_the_same_evidence(
        tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    items = _all_unmeasured()
    items[STORE] = _met(STORE, evidence={
        "case_ids": [f"case-{index}" for index in range(200)],
        "decisive_scalar": True,
        "nested": {"decision": "met"}})
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    entry = suite["items"][STORE]["met_by"][0]
    assert "decisive_scalar" in entry["evidence_fields"]
    assert "nested.decision" in entry["evidence_fields"]
    assert entry["evidence_fields_truncated"] is True
    assert len(entry["evidence_fields"]) <= 96


def test_long_evidence_field_lists_are_flagged(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    items = _all_unmeasured()
    items[STORE] = _met(STORE, evidence={
        f"sample_{index}": {"value": index} for index in range(200)})
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    entry = suite["items"][STORE]["met_by"][0]
    assert entry["evidence_fields_truncated"] is True
    assert len(entry["evidence_fields"]) <= suite_module.MAX_EVIDENCE_FIELDS


# -------------------------------------------------------------------- engine


def test_engine_hashes_cover_the_frozen_producer_and_this_module(
        tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    _install(monkeypatch, {str(run): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    engine = suite["engine"]
    assert engine["p3_acceptance"]["sha256"] == _module_sha256(frozen)
    assert engine["p3_acceptance_suite"]["sha256"] == _module_sha256(suite_module)
    assert engine["p3_acceptance"]["path"] == str(frozen.__file__)
    assert engine["per_run"]["primary"]["p3_acceptance"]["sha256"] == "c" * 64


def test_engine_hashes_reject_a_mismatched_declared_producer(
        tmp_path, monkeypatch):
    run, reproduce = _dirs(tmp_path, "primary", "reproduce")
    items = _all_unmeasured()
    for key in CRITICAL_ITEMS:
        items[key] = _met(key)
    _install(monkeypatch, {str(run): _Stub(items)})
    declaration = {"role": CONTROLLED_FAULT_ROLE, "run_dir": str(run),
                   "compare_run": str(reproduce)}

    honest = p3_acceptance_suite(
        [declaration], engine_hashes={"p3_acceptance": _module_sha256(frozen)})
    assert honest["engine"]["verification"][frozen.__name__]["match"] is True
    # Every critical item is proven and the declared hash matches, so this is
    # ready -- the short engine key of the frozen report is accepted as well.
    assert honest["gate"]["exit_code"] == EXIT_READY

    mismatched = p3_acceptance_suite(
        [declaration], engine_hashes={frozen.__name__: "0" * 64})
    verification = mismatched["engine"]["verification"][frozen.__name__]
    assert verification["match"] is False
    assert verification["expected"] == "0" * 64
    assert verification["actual"] == _module_sha256(frozen)
    assert mismatched["gate"]["exit_code"] == EXIT_NOT_READY
    assert any("does not match" in limit["reason"]
               for limit in mismatched["gate"]["limits"])


def test_mixed_frozen_engine_versions_across_runs_force_exit_two(
        tmp_path, monkeypatch):
    first, second = _dirs(tmp_path, "a", "b")
    items = _all_unmeasured()
    for key in CRITICAL_ITEMS:
        items[key] = _met(key)
    _install(monkeypatch, {str(first): _Stub(dict(items), engine_sha256="1" * 64),
                           str(second): _Stub(dict(items), engine_sha256="2" * 64)})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(first)},
        {"role": "cross_case", "run_dir": str(second)}])

    assert suite["gate"]["exit_code"] == EXIT_NOT_READY
    assert any("engine" in limit["quantity"]
               for limit in suite["gate"]["limits"])


# --------------------------------------------------------------------- gate


def test_critical_items_follow_the_frozen_consumer(tmp_path):
    run = _write_run(tmp_path / "run")
    report = frozen.p3_acceptance_report(run)
    frozen_critical = [row["key"] for row in report["gate"]["items"]
                       if row["critical"]]

    assert tuple(CRITICAL_ITEMS) == EXPECTED_CRITICAL_ITEMS
    # Every suite criterion is a critical row of the frozen gate, and the only
    # frozen critical rows the suite does not union are the three per-run
    # artifact-availability rows (whose frozen met value is null by design).
    assert set(CRITICAL_ITEMS) <= set(frozen_critical)
    assert set(frozen_critical) - set(CRITICAL_ITEMS) == {
        "manifest", "receipts", "trace"}
    assert NON_CRITICAL_ITEMS == frozenset({RTL_EVENT_LEVEL_KEY})
    assert RTL_EVENT_LEVEL_KEY in frozen.CRITERIA
    assert RTL_EVENT_LEVEL_KEY not in CRITICAL_ITEMS
    assert RTL_EVENT_LEVEL_KEY not in frozen_critical

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])
    assert suite["gate"]["frozen_gate_critical_keys"] == frozen_critical
    assert any(limit["quantity"] == "frozen_gate_artifact_rows"
               and "manifest" in limit["reason"]
               for limit in suite["gate"]["limits"])


def test_gate_limits_record_the_single_run_limitation(tmp_path, monkeypatch):
    primary, cross = _dirs(tmp_path, "primary", "cross")
    primary_items = _all_unmeasured()
    primary_items[STORE] = _met(STORE)
    cross_items = _all_unmeasured()
    cross_items["cross_case_chains"] = _met("cross_case_chains")
    _install(monkeypatch, {str(primary): _Stub(primary_items),
                           str(cross): _Stub(cross_items)})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(primary)},
        {"role": "cross_case", "run_dir": str(cross)}])

    gate = suite["gate"]
    assert gate["critical_items"] == list(CRITICAL_ITEMS)
    assert set(gate["met_by_at_least_one_run"]) == {STORE, "cross_case_chains"}
    coverage = gate["single_run_coverage"]
    assert coverage["primary"]["critical_met"] == [STORE]
    assert set(coverage["primary"]["critical_missing"]) == (
        set(CRITICAL_ITEMS) - {STORE})
    assert gate["runs_satisfying_all_critical_items"] == []
    assert any("single" in limit["quantity"].lower()
               or "aggregat" in limit["reason"] for limit in gate["limits"])
    assert any("union" in limit["reason"] or "aggregat" in limit["reason"]
               for limit in gate["limits"])
    # The mirror keeps the same limits visible at the top level.
    assert suite["limits"] == gate["limits"]
    assert any(limit["quantity"] == "finding_stops_and_replays.calibration"
               for limit in gate["limits"])
    assert any(limit["quantity"] == "role_declaration"
               for limit in gate["limits"])
    assert any(limit["quantity"] == RTL_EVENT_LEVEL_KEY
               for limit in gate["limits"])


def test_single_run_coverage_names_a_run_that_proves_everything(
        tmp_path, monkeypatch):
    run, reproduce = _dirs(tmp_path, "primary", "reproduce")
    items = _all_unmeasured()
    for key in CRITICAL_ITEMS:
        items[key] = _met(key)
    _install(monkeypatch, {str(run): _Stub(items)})

    suite = p3_acceptance_suite([{
        "role": CONTROLLED_FAULT_ROLE, "run_dir": str(run),
        "compare_run": str(reproduce)}])

    assert suite["gate"]["runs_satisfying_all_critical_items"] == [
        CONTROLLED_FAULT_ROLE]
    assert suite["gate"]["exit_code"] == EXIT_READY
    assert suite["gate"]["ready"] is True
    assert any("single-session" in limit["reason"]
               for limit in suite["gate"]["limits"])


def test_the_suite_document_is_json_serialisable(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    _install(monkeypatch, {str(run): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    payload = json.dumps(suite, sort_keys=True, allow_nan=False)
    assert json.loads(payload)["schema_version"] == SCHEMA_VERSION


# ------------------------------------------------------------- real artifacts


def test_real_primary_run_alone_leaves_the_replay_item_unmeasured(tmp_path):
    run = _write_run(tmp_path / "primary")

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])

    assert suite["gate"]["exit_code"] == EXIT_NOT_READY
    assert FINDING in suite["gate"]["unmeasured_across_all_runs"]
    assert suite["items"][STORE]["status"] == "met"
    assert suite["items"]["single_initialization"]["status"] == "met"
    assert suite["items"][STORE]["met_by"][0]["role"] == "primary"
    # A run that never measured the replay item is no excluded claim: only a
    # claim the suite refuses is listed under excluded_from_met_by.
    finding = suite["items"][FINDING]
    assert finding["excluded_from_met_by"] == []
    assert finding["not_met_by"][0]["excluded_reason"] is None


def test_real_reports_union_two_declared_runs_into_all_seven_items(tmp_path):
    primary = _write_run(tmp_path / "primary")
    fault = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    reproduce = _write_run(tmp_path / "reproduce", finding=True,
                           finding_replay=False,
                           run_id=f"{RUN_ID}-reproduce")

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(primary)},
        {"role": CONTROLLED_FAULT_ROLE, "run_dir": str(fault),
         "compare_run": str(reproduce)}])

    for key in CRITICAL_ITEMS:
        assert suite["items"][key]["status"] == "met", key
        assert suite["items"][key]["met_by"], key
    assert suite["gate"]["exit_code"] == EXIT_READY
    # The finding pair happens to prove all seven items on its own, which the
    # gate names explicitly; the primary run still leaves the replay item
    # unmeasured and that stays visible next to it.
    assert suite["gate"]["runs_satisfying_all_critical_items"] == [
        CONTROLLED_FAULT_ROLE]
    assert [entry["role"] for entry in suite["items"][FINDING]["met_by"]] == [
        CONTROLLED_FAULT_ROLE]
    assert suite["items"][FINDING]["injected_calibration"] is True
    # Only the controlled fault run proves the replay item: the primary run
    # leaves it unmeasured, and that stays visible.
    assert suite["items"][FINDING]["per_run"]["primary"]["status"] == "unmeasured"
    assert suite["items"][FINDING]["per_run"]["primary"]["measured"] is False
    assert suite["items"][STORE]["per_run"][CONTROLLED_FAULT_ROLE]["status"] in (
        "met", "unmet")


def test_real_reports_keep_the_not_met_primary_detail(tmp_path):
    primary = _write_run(tmp_path / "primary", trace=False)
    healthy = _write_run(tmp_path / "healthy")

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(primary)},
        {"role": "supporting", "run_dir": str(healthy)}])

    item = suite["items"][STORE]
    assert item["status"] == "met"
    assert item["per_run"]["primary"]["status"] == "unmeasured"
    assert item["per_run"]["primary"]["reason"]
    assert [row["role"] for row in item["not_met_by"]] == ["primary"]


# ----------------------------------------------------------------- markdown


def test_markdown_puts_the_evidence_boundary_first(tmp_path, monkeypatch):
    primary, cross = _dirs(tmp_path, "primary", "cross")
    primary_items = _all_unmeasured()
    primary_items[STORE] = _met(STORE)
    _install(monkeypatch, {str(primary): _Stub(primary_items),
                           str(cross): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([
        {"role": "primary", "run_dir": str(primary)},
        {"role": "cross_case", "run_dir": str(cross)}])
    markdown = render_markdown(suite)

    assert markdown.startswith("# P3 acceptance suite report")
    boundary = markdown.index("## 证据边界")
    measured = markdown.index("### 实测")
    unproven = markdown.index("### 未证实与原因")
    limits = markdown.index("### 限制")
    detail = markdown.index("## 逐子项汇总")
    assert boundary < measured < unproven < limits < detail
    assert f"exit code {suite['gate']['exit_code']}" in markdown
    assert STORE in markdown
    assert "store_then_load-evidence" not in markdown  # paths, not full evidence
    assert "evidence_digest" in markdown or "digest" in markdown
    assert "controlled_fault" in markdown
    assert "注入校准" in markdown or "injected" in markdown


def test_markdown_binds_both_engine_hashes(tmp_path, monkeypatch):
    run, = _dirs(tmp_path, "primary")
    _install(monkeypatch, {str(run): _Stub(_all_unmeasured())})

    suite = p3_acceptance_suite([{"role": "primary", "run_dir": str(run)}])
    markdown = render_markdown(suite)

    assert suite["engine"]["p3_acceptance"]["sha256"] in markdown
    assert suite["engine"]["p3_acceptance_suite"]["sha256"] in markdown
    assert "sha256 `None`" not in markdown


# ---------------------------------------------------------------------- CLI


def test_cli_unions_real_runs_and_writes_both_documents(tmp_path):
    primary = _write_run(tmp_path / "cli-primary")
    fault = _write_run(tmp_path / "cli-fault", finding=True,
                       finding_replay=False)
    reproduce = _write_run(tmp_path / "cli-reproduce", finding=True,
                           finding_replay=False,
                           run_id=f"{RUN_ID}-cli-reproduce")
    json_out = tmp_path / "out" / "suite.json"
    markdown_out = tmp_path / "out" / "suite.md"
    reports_dir = tmp_path / "out" / "reports"

    result = subprocess.run(
        [sys.executable, str(CLI),
         "--run", f"primary={primary}",
         "--run", f"controlled_fault={fault}@{reproduce}",
         "--json-out", str(json_out), "--markdown-out", str(markdown_out),
         "--reports-dir", str(reports_dir)],
        capture_output=True, text=True)

    assert result.returncode == EXIT_READY, result.stdout + result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["gate"]["exit_code"] == EXIT_READY
    assert json.loads(json_out.read_text(encoding="utf-8")) == document
    markdown = markdown_out.read_text(encoding="utf-8")
    assert markdown.startswith("# P3 acceptance suite report")
    assert "## 证据边界" in markdown
    assert (reports_dir / "report-primary.json").is_file()
    assert (reports_dir / "report-controlled_fault.json").is_file()
    dumped = json.loads((reports_dir / "report-controlled_fault.json").read_text(
        encoding="utf-8"))
    assert dumped["schema_version"] == frozen.SCHEMA_VERSION
    assert dumped["compare_run_dir"] == str(reproduce)


def test_cli_exits_two_when_an_item_has_no_proving_run(tmp_path):
    primary = _write_run(tmp_path / "cli-primary")

    result = subprocess.run(
        [sys.executable, str(CLI), "--run", f"primary={primary}"],
        capture_output=True, text=True)

    assert result.returncode == EXIT_NOT_READY, result.stdout + result.stderr
    document = json.loads(result.stdout)
    assert document["gate"]["exit_code"] == EXIT_NOT_READY
    assert FINDING in document["gate"]["unmeasured_across_all_runs"]


def test_cli_rejects_a_malformed_run_declaration(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "--run", "primary"],
        capture_output=True, text=True)

    assert result.returncode == EXIT_USAGE
    error = json.loads(result.stdout)
    assert error["schema_version"] == "p3_acceptance_suite_error.v1"
    assert "ROLE=DIR" in error["error"]


def test_cli_engine_hash_declaration_is_verified(tmp_path):
    primary = _write_run(tmp_path / "cli-primary")
    fault = _write_run(tmp_path / "cli-fault", finding=True,
                       finding_replay=False)
    reproduce = _write_run(tmp_path / "cli-reproduce", finding=True,
                           finding_replay=False,
                           run_id=f"{RUN_ID}-cli-engine-reproduce")
    declarations = ["--run", f"primary={primary}",
                    "--run", f"controlled_fault={fault}@{reproduce}"]

    honest = subprocess.run(
        [sys.executable, str(CLI)] + declarations
        + ["--engine-hash", f"p3_acceptance={_module_sha256(frozen)}"],
        capture_output=True, text=True)
    assert honest.returncode == EXIT_READY, honest.stdout + honest.stderr
    verification = json.loads(honest.stdout)["engine"]["verification"]
    assert verification[frozen.__name__]["match"] is True

    mismatched = subprocess.run(
        [sys.executable, str(CLI)] + declarations
        + ["--engine-hash", f"{frozen.__name__}={'0' * 64}"],
        capture_output=True, text=True)
    assert mismatched.returncode == EXIT_NOT_READY
    assert json.loads(mismatched.stdout)["engine"]["verification"][
        frozen.__name__]["match"] is False

    malformed = subprocess.run(
        [sys.executable, str(CLI)] + declarations
        + ["--engine-hash", "p3_acceptance"],
        capture_output=True, text=True)
    assert malformed.returncode == EXIT_USAGE
    assert "MODULE=SHA256" in json.loads(malformed.stdout)["error"]


def test_cli_maps_an_illegal_role_and_a_missing_directory_to_exit_one(
        tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    illegal = subprocess.run(
        [sys.executable, str(CLI), "--run", f"favourite={run}"],
        capture_output=True, text=True)
    assert illegal.returncode == EXIT_USAGE
    assert "not a legal role" in json.loads(illegal.stdout)["error"]

    absent = subprocess.run(
        [sys.executable, str(CLI), "--run", f"primary={tmp_path / 'absent'}"],
        capture_output=True, text=True)
    assert absent.returncode == EXIT_USAGE
    assert "run directory does not exist" in json.loads(absent.stdout)["error"]
