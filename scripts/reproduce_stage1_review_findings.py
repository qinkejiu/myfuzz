"""Small synthetic reproductions of the 2026-10-08 individual review findings.

Run with PYTHONPATH=src:. python3 scripts/reproduce_stage1_review_findings.py.
Uses existing test fixtures; starts no RTL process and changes no saved run.
The observations describe defects, rather than successful acceptance tests.
"""
import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.edge_provenance import EdgeProvenanceConsumer
from myfuzz.scenario.closed_loop_feedback import ClosedLoopFeedback, certificate_hit
from myfuzz.scenario.p5_acceptance import (
    ITEM_COMPLETE_PREFIX, ITEM_PAIRED_BUDGET, p5_acceptance_report,
)
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession, replay_online_session
from tests.scenario.test_edge_provenance import _binding_journal, _contract, _endpoints
from tests.scenario.test_closed_loop_feedback import _certified_ip_certificate
from tests.scenario.test_online_session_partial_replay import _factory, _template
from tests.scenario.test_p5_acceptance_suite import (
    _item, build_identity_and_replay, build_paired, build_run,
)
from tests.scenario.test_source_action_session_gate import case_for, session_with_gate


def main():
    observations = {}
    with TemporaryDirectory(prefix="myfuzz-review-") as directory:
        root = Path(directory)
        run = build_run(root, "prefix", with_meta=True)
        build_identity_and_replay(run)
        prefix = lambda: _item(p5_acceptance_report(run), ITEM_COMPLETE_PREFIX)
        baseline = prefix()["met"]
        (run / "corpus/entry_0000.json").unlink()
        missing = prefix()["met"]
        (run / "online_events.zlib").write_bytes(b"changed-after-recording")
        observations["prefix"] = {
            "baseline_met": baseline, "missing_corpus_met": missing,
            "changed_trace_met": prefix()["met"],
        }
        continuous, cold = build_paired(root)
        path = continuous / "report.json"
        report = json.loads(path.read_text())
        original_seconds = report["elapsed_seconds"]
        report["elapsed_seconds"] = 0
        path.write_text(json.dumps(report))
        paired = _item(p5_acceptance_report(continuous, compare_run=cold), ITEM_PAIRED_BUDGET)
        observations["zero_elapsed"] = {"met": paired["met"], "reason": paired["reason"]}
        report["elapsed_seconds"] = original_seconds
        path.write_text(json.dumps(report))
        for name in ("cold_start.json", "report.json"):
            path = cold / name
            document = json.loads(path.read_text())
            document.pop("verified_case_count", None)
            path.write_text(json.dumps(document))
        paired = _item(p5_acceptance_report(continuous, compare_run=cold), ITEM_PAIRED_BUDGET)
        observations["missing_verified_count"] = {"met": paired["met"], "reason": paired["reason"]}

    class FailingGate:
        calls = 0

        def require_case(self, case):
            pass

        def observe(self, receipt):
            self.calls += 1
            if self.calls == 1:
                raise ValueError("effect journal rejected")

    gate = FailingGate()
    session = session_with_gate(gate)
    session.begin()
    try:
        case = case_for(session, "one", "action-one")
        try:
            session.submit_case(case)
        except ValueError:
            pass
        halted = session._halted
        session.submit_case(case)
        retry_calls = gate.calls
        session.submit_case(case_for(session, "two", "action-two"))
        observations["gate_failure"] = {
            "halted": halted, "observe_calls_after_retry": retry_calls,
            "accepted_cases": len(session.cases),
        }
    finally:
        session.finish()

    session = ScenarioSession(_template(), _factory())
    session.begin()
    session.submit_case(OnlineCase("one", "CPU_TO_IP", "unit",
        BatchSourceEvent("action", "cpu", "source", 2), (BatchAdvance(("cpu",)),)))
    reference = session.finish()
    plan = session.encode_plan()
    runners, ended = [], []

    def bad_factory():
        runner = _factory()
        runners.append(runner)

        def fail(inputs):
            raise RuntimeError("unexpected replay transport failure")

        runner.sessions["cpu"].step_local = fail
        runner.sessions["cpu"].end_case = lambda: ended.append(True)
        return runner

    try:
        replay_online_session(plan, bad_factory, reference)
    except RuntimeError:
        observations["replay_cleanup"] = {"end_case_calls_before_manual_cleanup": len(ended)}
    finally:
        for runner in runners:
            runner.finalize()

    journal = _binding_journal()
    consumer = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    produced = consumer.ingest(journal.events)
    report = consumer.report()
    observations["certificate_report"] = {
        "ingested": len(produced), "reported": len(report["certificates"]),
        "certified_edges": report["counts"]["certified"],
    }
    consumer = EdgeProvenanceConsumer(_contract(pin8=True), endpoints=_endpoints(pin8=True))
    consumer.ingest(journal.events[:1])
    report = consumer.report()
    observations["certificate_flush"] = {
        "reported": len(report["certificates"]), "stored": len(consumer.certificates),
    }

    certificate = _certified_ip_certificate()
    certificate["hops"] = certificate["hops"][:1]
    hit = certificate_hit(certificate)
    observations["truncated_closed_loop"] = {
        "kind": hit["kind"], "reached_terminal_hop": hit["reached_terminal_hop"],
        "hop_count": hit["hop_count"], "missing_hops": hit["missing_hops"],
    }
    original = _certified_ip_certificate()
    changed = deepcopy(original)
    changed["hops"][0]["evidence"]["review_changed"] = "different evidence"
    feedback = ClosedLoopFeedback()
    feedback.ingest([original])
    observations["changed_certificate_evidence"] = {
        "new_hits": len(feedback.ingest([changed])), "conflict_refused": False,
    }
    feedback = ClosedLoopFeedback()
    changed = deepcopy(original)
    changed["source_action_id"] = "changed-action"
    try:
        feedback.ingest([original, changed])
    except ValueError as error:
        observations["partial_feedback_batch"] = {
            "error": str(error), "stored_after_failed_batch": feedback.certificate_count,
        }
    print(json.dumps(observations, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
