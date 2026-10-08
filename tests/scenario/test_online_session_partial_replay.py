"""Replay boundaries for failed online cases."""

import json
import unittest

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession, replay_online_session
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker


class _LocalSession:
    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        if inputs.get("source") == 7:
            raise RuntimeError("local step failed")
        return {"value": inputs.get("source", 0)}

    def end_case(self):
        pass


class _ConfiguredChecker:
    def __init__(self, finding):
        self.finding = finding
        self._seen = 0

    def __call__(self, receipt):
        self._seen += 1
        return ()


def _factory():
    ownership = compile_ownership(
        (InputField("cpu", "source", 8),),
        (InputOwner("cpu", "source", 0, 8, "source", "program"),))
    return ScenarioRunner(sessions={"cpu": _LocalSession()}, ownership=ownership,
                          bindings=())


def _template():
    return ScenarioGenome(testcase_id="partial", direction="CPU_TO_IP",
                          path_id="unit", schedule_order=("cpu",),
                          max_steps=4, actions=())


def _admission_factory(message="source admission failed"):
    runner = _factory()
    inject = runner.inject_source

    def fail_after_injection(*args, **kwargs):
        inject(*args, **kwargs)
        raise RuntimeError(message)

    runner.inject_source = fail_after_injection
    return runner


class OnlinePartialReplayTests(unittest.TestCase):
    def test_manifest_binds_live_rfuzz_transport_source(self):
        session = ScenarioSession(_template(), _factory())
        session.begin()
        source_paths = {item['path'] for item in
                        session.manifest_document['online_source_files']}
        self.assertIn('src/myfuzz/integration/rfuzz_fifo.py', source_paths)

    def test_failed_step_replays_terminal_boundary(self):
        session = ScenarioSession(_template(), _factory())
        session.begin()
        case = OnlineCase("failed", "CPU_TO_IP", "unit",
                          BatchSourceEvent("source", "cpu", "source", 7),
                          (BatchAdvance(("cpu",)),))
        with self.assertRaisesRegex(RuntimeError, "local step failed"):
            session.submit_case(case)
        reference = session.finish()
        plan = session.encode_plan()
        self.assertEqual(5, json.loads(plan)["schema_version"])
        result = replay_online_session(plan, _factory, reference)
        self.assertTrue(result.matches, result.difference_context)
        self.assertEqual(reference.events, result.actual_trace.events)

    def test_checker_identity_is_bound_to_manifest(self):
        def first(receipt):
            return ()

        def second(receipt):
            return ()

        session = ScenarioSession(_template(), _factory(), checker=first)
        session.begin()
        reference = session.finish()
        with self.assertRaisesRegex(ValueError, "manifest identity mismatch"):
            replay_online_session(session.encode_plan(), _factory, reference,
                                  checker=second)

        configured = ScenarioSession(
            _template(), _factory(), checker=_ConfiguredChecker("first"))
        configured.begin()
        configured_reference = configured.finish()
        with self.assertRaisesRegex(ValueError, "manifest identity mismatch"):
            replay_online_session(configured.encode_plan(), _factory,
                                  configured_reference,
                                  checker=_ConfiguredChecker("second"))

    def test_checker_identity_normalizes_deterministic_deques(self):
        checker = IbexUartOnlineChecker()
        session = ScenarioSession(_template(), _factory(), checker=checker)
        session.begin()
        self.assertEqual([], session.manifest_document['checker']['config']['_expected_rx'])

    def test_checker_closure_configuration_is_bound_to_manifest(self):
        def make_checker(finding):
            def checker(receipt):
                return (finding,)
            return checker

        checker = make_checker("first")
        session = ScenarioSession(_template(), _factory(), checker=checker)
        session.begin()
        reference = session.finish()
        with self.assertRaisesRegex(ValueError, "manifest identity mismatch"):
            replay_online_session(session.encode_plan(), _factory, reference,
                                  checker=make_checker("second"))

    def test_partial_admission_replays_and_wrong_error_does_not_match(self):
        session = ScenarioSession(_template(), _admission_factory())
        session.begin()
        case = OnlineCase("admission", "CPU_TO_IP", "unit",
                          BatchSourceEvent("source", "cpu", "source", 2),
                          (BatchAdvance(("cpu",)),))
        with self.assertRaisesRegex(RuntimeError, "source admission failed"):
            session.submit_case(case)
        reference = session.finish()
        plan = session.encode_plan()
        failure = json.loads(plan)["terminal_failure"]
        self.assertEqual("source_admission", failure["phase"])
        self.assertTrue(replay_online_session(
            plan, _admission_factory, reference).matches)
        mismatch = replay_online_session(
            plan, lambda: _admission_factory("different failure"), reference)
        self.assertFalse(mismatch.matches)
        self.assertEqual("different failure", mismatch.difference_context[
            "actual_terminal_failure"]["error_message"])

    def test_success_and_checker_finding_keep_schema_four(self):
        case = OnlineCase("normal", "CPU_TO_IP", "unit",
                          BatchSourceEvent("source", "cpu", "source", 2),
                          (BatchAdvance(("cpu",)),))
        for checker in (None, lambda receipt: ("finding",)):
            with self.subTest(checker=checker):
                session = ScenarioSession(_template(), _factory(), checker=checker)
                session.begin()
                session.submit_case(case)
                reference = session.finish()
                plan = session.encode_plan()
                self.assertEqual(4, json.loads(plan)["schema_version"])
                self.assertTrue(replay_online_session(
                    plan, _factory, reference, checker=checker).matches)

    def test_completed_case_retry_recovers_only_original_event_suffix(self):
        session = ScenarioSession(_template(), _factory())
        session.begin()
        first = OnlineCase("first", "CPU_TO_IP", "unit",
                           BatchSourceEvent("source-first", "cpu", "source", 1),
                           (BatchAdvance(("cpu",)),))
        second = OnlineCase("second", "CPU_TO_IP", "unit",
                            BatchSourceEvent("source-second", "cpu", "source", 2),
                            (BatchAdvance(("cpu",)),))
        first_receipt = session.submit_case(first)
        session.submit_case(second)
        count_before_retry = session.runner.event_count
        retried = session.submit_case(first)
        self.assertEqual(first_receipt, retried)
        self.assertEqual(count_before_retry, session.runner.event_count)
        self.assertEqual((), session._receipts["first"][1].events)
        self.assertEqual({}, session.runner._step_commands)
        with self.assertRaisesRegex(ValueError, "retired_command"):
            session.runner.execute_step(
                "cpu", execution_id=session.runner.execution_id,
                command_sequence=1, epoch=0, expected_inputs={})
        self.assertEqual(count_before_retry, session.runner.event_count)


if __name__ == "__main__":
    unittest.main()
