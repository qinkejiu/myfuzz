"""ScenarioSession consults an opt-in source-action gate before admission.

Software only: the lightweight ``_Pin`` harness emits no RTL events, so the
recorded effects here are synthetic journal evidence. The recording gate proves
the wiring order (query before any RTL command, ingest after a receipt); it does
not claim a real RTL dataflow chain.
"""

from dataclasses import replace
import unittest

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession
from myfuzz.scenario.source_actions import (
    CrossCaseEffectTracker, SourceAction, SourceActionGate,
    SourceActionInputMismatch, SourceActionPrerequisiteError,
    SourceActionUnknownAction,
    TerminationObservation, instruction_slot_unmaterialized_prerequisite,
    ram_commit_prerequisite,
)
from tests.scenario.test_session_runtime_paths import declaration, factory


def commit_event(event_id, byte_offset, *, commit_id):
    commit_id = (commit_id * 64)[:64]
    return {
        "event_id": event_id, "component": "cpu", "kind": "memory_write_commit",
        "schema_version": "memory_write_commit.v1", "commit_id": commit_id,
        "commit_document": {
            "schema_version": "memory_write_commit_receipt.v1",
            "commit_id": commit_id, "memory_id": "ram", "generation": 0,
            "byte_offset": byte_offset, "width_bytes": 1, "byte_enable": 1,
            "version": [0, 1], "commit_status": "complete",
            "enabled_byte_cells": [
                {"byte_offset": byte_offset, "value": 0x5A, "version": [0, 1],
                 "writer_kind": "STORE", "writer_event_id": "case"}]}}


class RecordingGate:
    """Records gate calls around a real SourceActionGate."""

    def __init__(self, inner):
        self.inner = inner
        self.required = []
        self.observed = []

    def require_case(self, case):
        self.required.append(case.case_id)
        return self.inner.require_case(case)

    def observe(self, receipt):
        self.observed.append(receipt.case_id)
        return self.inner.observe(receipt)


def action_for(action_id, *, prerequisites=(), value=1):
    return SourceAction(action_id=action_id, kind="external_event", component="a",
                        source_id="a.pin", ownership="fuzzable", flow_id="F4",
                        payload={"port": "pin", "bit_offset": 0, "width": 1,
                                 "value": value},
                        termination_observation=TerminationObservation(
                            "delivery", f"gpio:{action_id}"),
                        local_step_budget=8, prerequisites=tuple(prerequisites))


def session_with_gate(gate):
    session = ScenarioSession(
        ScenarioGenome('paths', 'IP_TO_IP', 'template', ('a', 'b'), 8, ()),
        factory(), prerequisite_gate=gate)
    graph, contract, paths = declaration()
    session.configure_runtime_paths(graph, contract, paths,
                                    source_ownership=factory().ownership)
    return session


def case_for(session, case_id, action_id):
    return OnlineCase(case_id, 'IP_TO_IP', session.runtime_path_ids[0],
                      BatchSourceEvent(action_id, 'a', 'pin', 1, 0, 1),
                      (BatchAdvance(('a', 'b')),))


class SessionSourceActionGateTests(unittest.TestCase):
    def test_gate_rejects_unsatisfied_action_before_any_rtl_command(self):
        tracker = CrossCaseEffectTracker()
        gate = SourceActionGate(tracker)
        prerequisite = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        action = action_for("case:s", prerequisites=(prerequisite,))
        gate.register(action)
        session = session_with_gate(gate)
        session.begin()
        before = (session.runner.event_count, dict(session.runner.local_ticks))
        with self.assertRaises(SourceActionPrerequisiteError) as caught:
            session.submit_case(case_for(session, "one", "case:s"))
        self.assertEqual((prerequisite,), caught.exception.evaluation.missing)
        self.assertEqual(before, (session.runner.event_count,
                                  dict(session.runner.local_ticks)))
        self.assertEqual((), session.cases)

    def test_gate_admits_after_real_evidence_and_ingests_the_receipt(self):
        tracker = CrossCaseEffectTracker()
        recording = RecordingGate(SourceActionGate(tracker))
        prerequisite = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        action = action_for("case:s", prerequisites=(prerequisite,))
        recording.inner.register(action)
        session = session_with_gate(recording)
        session.begin()
        tracker.ingest([commit_event(1, 0x10000, commit_id="a")])
        receipt = session.submit_case(case_for(session, "one", "case:s"))
        self.assertEqual("one", receipt.case_id)
        self.assertEqual(["one"], recording.required)
        self.assertEqual(["one"], recording.observed)
        self.assertEqual(["one"], [case.case_id for case in session.cases])

    def test_unregistered_case_action_is_refused_without_side_effects(self):
        gate = SourceActionGate(CrossCaseEffectTracker())
        session = session_with_gate(gate)
        session.begin()
        with self.assertRaises(SourceActionUnknownAction):
            session.submit_case(case_for(session, "one", "case:unregistered"))
        self.assertEqual((), session.cases)

    def test_case_input_must_match_the_registered_action(self):
        gate = SourceActionGate(CrossCaseEffectTracker())
        gate.register(action_for("case:s", value=1))
        session = session_with_gate(gate)
        session.begin()
        mismatched = OnlineCase("one", 'IP_TO_IP', session.runtime_path_ids[0],
                                BatchSourceEvent("case:s", 'a', 'pin', 0, 0, 1),
                                (BatchAdvance(('a', 'b')),))
        before = (session.runner.event_count, dict(session.runner.local_ticks))
        with self.assertRaises(SourceActionInputMismatch):
            session.submit_case(mismatched)
        self.assertEqual(before, (session.runner.event_count,
                                  dict(session.runner.local_ticks)))
        self.assertEqual((), session.cases)

    def test_unconfigured_session_keeps_the_original_behaviour(self):
        session = session_with_gate(None)
        self.assertIsNone(session.prerequisite_gate)
        session.begin()
        receipt = session.submit_case(case_for(session, "one", "any:action"))
        self.assertEqual("one", receipt.case_id)

    def test_online_manifest_pins_the_source_action_module(self):
        session = session_with_gate(None)
        session.begin()
        paths = {item["path"]
                 for item in session.manifest_document["online_source_files"]}
        self.assertIn("src/myfuzz/scenario/source_actions.py", paths)

    def test_bootstrap_advance_also_ingests_its_receipt(self):
        tracker = CrossCaseEffectTracker()
        recording = RecordingGate(SourceActionGate(tracker))
        session = session_with_gate(recording)
        session.begin()
        receipt = session.advance_initial(("a",))
        self.assertEqual([receipt.case_id], recording.observed)

    def test_slot_prerequisite_is_queried_by_the_session(self):
        tracker = CrossCaseEffectTracker()
        gate = SourceActionGate(tracker)
        prerequisite = instruction_slot_unmaterialized_prerequisite(
            "a", 0x11000, "reservation:one")
        action = action_for("case:s", prerequisites=(prerequisite,))
        gate.register(action)
        session = session_with_gate(gate)
        session.begin()
        with self.assertRaises(SourceActionPrerequisiteError):
            session.submit_case(case_for(session, "one", "case:s"))
        tracker.register_instruction_slot("a", 0x11000, "reservation:one",
                                          event_id=1)
        receipt = session.submit_case(case_for(session, "two", "case:s"))
        self.assertEqual("two", receipt.case_id)


if __name__ == "__main__":
    unittest.main()
