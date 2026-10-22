"""Retrospective Runner reporting over archived Caliptra AHB target receipts.

These saved samples are from earlier real RTL runs. Replaying them here does not
execute RTL or establish native CPU origin, waits, errors, or cancellation.
"""

import copy
import gzip
import hashlib
import json
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

import pytest

from myfuzz.scenario.ip_base_coverage import IpBaseCoverageConsumer
from myfuzz.scenario.event_journal import EventJournal
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.protocol_trace_sets import ProtocolTraceSetObserver
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = (ROOT / "docs/reports/evidence/live-ahb-target-protocol-evidence-20261022"
           / "archived-inputs")
SHA256 = {
    "first": "4a21ad69a7400e3e8ad89945cc58c5b1e00b6f1f2f0ac5779b24bbd4c3c7f509",
    "fresh": "3b1d6842c06043653199b1318a920ce20a2971136c9469b95eaa91202583242a",
    "artifact": "fb62ee1da214866aa264405dc091657a1b6f47e25a269503fb3f6a6d78cfc959",
}
COMPONENT = "archived-ahb"
ENDPOINT = "sha256.bus"


def _archived(name):
    data = gzip.decompress((ARCHIVE / (name + ".json.gz")).read_bytes())
    assert hashlib.sha256(data).hexdigest() == SHA256[name]
    return json.loads(data)


@pytest.fixture(scope="module")
def archive_artifact():
    from tests.local_harness.test_ahb_register_target import artifact

    generated = artifact()
    archived = _archived("artifact")
    assert archived["kind"] == generated.runtime_document["kind"] == "ahb_lite_register_observe"
    # Reconstruct the current artifact and admit archived observations only
    # while the actual trace and physical pin mapping still match.
    for field in ("base_protocol_trace", "physical_exports", "backend_ports",
                  "runtime_ports", "raw_observation_schema_version",
                  "base_event_schema_version", "clock_schedule"):
        assert generated.runtime_document[field] == archived[field], field
    return generated


class SavedSampleSession:
    """Finite receipt source; no bus, peripheral, or CPU value computation."""

    _physical_tick_samples_enabled = True
    reset_epoch = 0
    max_local_ticks_per_step = 1
    max_transaction_events_per_step = 0

    def __init__(self, artifact, samples):
        self.artifact = artifact
        self.samples = copy.deepcopy(samples)
        self.local_ticks = 0
        self.queued = []

    def begin_case(self, case):
        pass

    def end_case(self):
        pass

    def step_local(self, inputs):
        assert not inputs
        sample = self.samples[self.local_ticks]
        self.local_ticks += 1
        assert sample["local_tick"] == self.local_ticks
        self.queued.append(copy.deepcopy(sample))
        return {}

    def drain_tick_samples(self):
        rows, self.queued = self.queued, []
        return rows


@contextmanager
def _replay(artifact, name):
    saved = _archived(name)
    archived_artifact = _archived("artifact")
    assert saved["identity"]["runtime_artifact"] == archived_artifact
    assert not saved["protocol_violations"]
    samples = [sample for access in saved["accesses"] for sample in access["samples"]]
    assert len(saved["accesses"]) == 91
    assert len(samples) == 364
    assert [sample["local_tick"] for sample in samples] == list(range(1, 365))
    session = SavedSampleSession(artifact, samples)
    runner = ScenarioRunner(sessions={COMPONENT: session},
                            ownership=compile_ownership((), ()), bindings=())
    runner.enable_event_journal(chunk_size=17)
    journal = runner._events._records
    assert isinstance(journal, EventJournal)
    try:
        runner.begin_test("archived-caliptra-ahb")
        for _ in samples:
            runner.step(COMPONENT)
        assert len(journal._offsets) > 1  # Exercise completed file-backed chunks.
        yield runner, saved, samples
    finally:
        try:
            if runner._status in ("running", "quiescing", "failed"):
                runner.finalize()
        finally:
            journal.close()


def _semantic_events(rows):
    return [(row["event_type"], row["endpoint_id"], row["tick"],
             row["phase"] if "phase" in row else None, row["payload"],
             row["identity_gap"], row["native_identity"])
            for row in rows if row.get("event_type") in
            ("transaction_request", "transaction_accept", "transaction_response")]


def _without_execution_identity(rows, execution_id):
    detached = copy.deepcopy(rows)
    for row in detached:
        if row.get("execution_id") == execution_id:
            row["execution_id"] = "<runner-execution>"
    return detached


def _assert_successful_replay(runner, saved, samples):
    rows = runner.events  # Complete, ordered EventJournal, including scheduler rows.
    assert [row["event_id"] for row in rows] == list(range(1, len(rows) + 1))
    raw = [row for row in rows if row.get("kind") == "local_tick_sample"]
    assert len(raw) == 2 * len(samples)
    assert [(row["local_tick"], row["phase"]) for row in raw] == [
        (sample["local_tick"], phase) for sample in samples for phase in ("pre", "post")]
    assert all(row["component"] == COMPONENT for row in raw)
    assert [row["outputs"] for row in raw] == [
        sample[phase] for sample in samples for phase in ("pre", "post")]
    projections = [row for row in rows if row.get("event_type") in
                   ("transaction_request", "transaction_accept", "transaction_response")]
    assert Counter(row["event_type"] for row in projections) == {
        "transaction_request": 91, "transaction_accept": 91,
        "transaction_response": 91}
    assert len({row["local_event_id"] for row in projections}) == 273
    assert {row["endpoint_id"] for row in projections} == {ENDPOINT}
    assert all(row["identity_gap"] == "protocol_has_no_transaction_id"
               and row["transaction_key"] is None for row in projections)
    raw_by_id = {row["event_id"]: row for row in raw}
    assert all(row["raw_event_refs"] and all(
        ref in raw_by_id and raw_by_id[ref]["phase"] == "pre"
        and raw_by_id[ref]["component"] == COMPONENT
        for ref in row["raw_event_refs"]) for row in projections)
    assert not any(row.get("event_type") == "protocol_violation" for row in rows)
    report = runner.protocol_trace_set_reports()[COMPONENT]
    assert report == runner.protocol_trace_set_reports()[COMPONENT]
    assert report["proof_scope"] == "protocol_boundary_only"
    assert report["cursor"] == len(rows)
    assert set(report["endpoints"]) == {ENDPOINT}
    endpoint = report["endpoints"][ENDPOINT]
    proof, coverage = endpoint["evidence"], endpoint["coverage"]
    assert proof["counts"] == {"verified": 91, "pending": 0}
    assert proof["diagnostics"] == {}
    assert proof["journal_integrity"] is True
    assert proof["last_event_id"] == len(rows)
    assert len(proof["certificates"]) == 91
    for kind in ("request", "accept", "response"):
        assert len({row[f"{kind}_event_id"] for row in proof["certificates"]}) == 91
    assert all(row["identity_gap"] == "protocol_has_no_transaction_id"
               for row in proof["certificates"])
    projections_by_id = {row["event_id"]: row for row in projections}
    for certificate in proof["certificates"]:
        assert certificate["outcome"] == "ok"
        for kind in ("request", "accept", "response"):
            event = projections_by_id[certificate[f"{kind}_event_id"]]
            raw_ref = certificate[f"{kind}_raw_event_id"]
            assert event["event_type"] == f"transaction_{kind}"
            assert raw_ref in event["raw_event_refs"]
            assert raw_ref in raw_by_id
    assert coverage["cursor"] == len(rows)
    assert coverage["pending_count"] == 0
    assert coverage["diagnostics"] == {}
    assert coverage["counts"][f"response:{ENDPOINT}:ok"] == 91
    assert coverage["counts"][f"transaction:{ENDPOINT}:read"] == 57
    assert coverage["counts"][f"transaction:{ENDPOINT}:write"] == 34
    assert Counter("write" if row["write"] else "read" for row in saved["accesses"]) == {
        "read": 57, "write": 34}
    return report


def test_archived_first_and_fresh_certify_same_singular_runner_path(archive_artifact):
    results = []
    for name in ("first", "fresh"):
        with _replay(archive_artifact, name) as (runner, saved, samples):
            report = _assert_successful_replay(runner, saved, samples)
            semantics = _semantic_events(runner.events)
            assert semantics == _semantic_events(saved["protocol_events"])
            journal_rows = _without_execution_identity(
                list(runner.events), runner.execution_id)
            results.append((saved, semantics, report, journal_rows))
    first, fresh = results
    assert first[0]["execution"] != fresh[0]["execution"]
    assert first[0]["accesses"] == fresh[0]["accesses"]
    assert first[0]["digests"] == fresh[0]["digests"]
    assert {key: value for key, value in first[0].items() if key != "execution"} == {
        key: value for key, value in fresh[0].items() if key != "execution"}
    assert first[1] == fresh[1]
    assert first[2] == fresh[2]
    assert first[3] == fresh[3]


@pytest.mark.parametrize("tamper", ("payload", "post_raw_ref"))
def test_tampered_projection_cannot_prove_archived_response(archive_artifact, tamper):
    with _replay(archive_artifact, "first") as (runner, _, _):
        # Snapshot detaches every row from the file-backed chunks. The altered
        # projection is then consumed by a fresh reporter over the full journal.
        tampered = list(runner.events)
    response = next(row for row in tampered
                    if row.get("event_type") == "transaction_response")
    if tamper == "payload":
        response["payload"]["value"] ^= 1
    else:
        pre = tampered[response["raw_event_refs"][0] - 1]
        assert pre["kind"] == "local_tick_sample" and pre["phase"] == "pre"
        post = next(row for row in tampered if row.get("kind") == "local_tick_sample"
                    and row["local_tick"] == pre["local_tick"] and row["phase"] == "post")
        response["raw_event_refs"] = [post["event_id"]]
    observer = ProtocolTraceSetObserver(COMPONENT, archive_artifact,
                                        runner_owns_projection=True)
    proof = observer.report(tampered)["endpoints"][ENDPOINT]["evidence"]
    assert proof["counts"]["verified"] == 0
    assert proof["diagnostics"]["projection_mismatch"] >= 1


def test_coverage_reset_barrier_clears_pending_and_keeps_counts(archive_artifact):
    with _replay(archive_artifact, "first") as (runner, _, _):
        rows = list(runner.events)
    coverage = IpBaseCoverageConsumer(component_id="caliptra_sha256", instance_id="sha",
                                      endpoint_protocols={ENDPOINT: "ahb-lite"})
    coverage.consume(rows, start_cursor=0)
    before = coverage.snapshot()
    assert before["counts"][f"response:{ENDPOINT}:ok"] == 91
    request = copy.deepcopy(next(row for row in rows
                                 if row.get("event_type") == "transaction_request"))
    request["event_id"] = len(rows) + 1
    request["raw_event_refs"] = [request["event_id"]]
    request["related_request_event_refs"] = [request["event_id"]]
    coverage.consume([request], start_cursor=len(rows))
    assert coverage.pending_count == 1
    barrier = {"event_id": len(rows) + 2, "kind": "reset_barrier",
               "component": COMPONENT}
    coverage.consume([barrier], start_cursor=len(rows) + 1)
    after = coverage.snapshot()
    assert after["pending_count"] == 0
    assert after["counts"][f"response:{ENDPOINT}:ok"] == 91
    coverage.consume([request, barrier], start_cursor=len(rows))
    assert coverage.snapshot() == after
