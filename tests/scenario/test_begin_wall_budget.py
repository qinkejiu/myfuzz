"""The testcase wall clock includes all local READY handshakes."""

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.protocol_io import LocalCommandDeadlineExceeded
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioBudgetExhausted, ScenarioRunner
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.scheduler import DependencyScheduler


def _runner(names):
    ownership = compile_ownership(
        tuple(InputField(name, "gpio_in", 32) for name in names),
        tuple(InputOwner(name, "gpio_in", 0, 32, "source", "external")
              for name in names))
    return ScenarioRunner(sessions={name: OpenTitanGpioSession() for name in names},
                          ownership=ownership, bindings=())


class BeginWallBudgetTests(unittest.TestCase):
    def _ready_script(self, directory, delay):
        executable = Path(directory) / "delayed-ready"
        executable.write_text(
            "#!/bin/sh\n"
            f"sleep {delay}\n"
            "printf 'READY\\n'\n"
            "IFS= read -r _\n")
        executable.chmod(0o755)
        return executable

    def test_two_ready_waits_share_one_testcase_wall_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self._ready_script(directory, 0.12)
            runner = _runner(("a", "b"))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=200))
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                started = time.monotonic()
                try:
                    with self.assertRaises(ScenarioBudgetExhausted):
                        runner.begin_test("two-ready")
                finally:
                    runner.finalize()
                self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual("budget_exhausted", runner.failure_status)
            marker = runner.events[-1]
            self.assertEqual("budget_exhausted", marker["kind"])
            self.assertEqual("inflight_begin", marker["phase"])
            self.assertEqual("b", marker["failed_component"])
            self.assertEqual(("a",), marker["started_components"])

    def test_first_ready_wait_uses_testcase_wall_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self._ready_script(directory, 0.15)
            runner = _runner(("gpio",))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                started = time.monotonic()
                try:
                    with self.assertRaises(ScenarioBudgetExhausted):
                        runner.begin_test("one-ready")
                finally:
                    runner.finalize()
                self.assertLess(time.monotonic() - started, 0.3)
            marker = runner.events[-1]
            self.assertEqual("inflight_begin", marker["phase"])
            self.assertEqual("gpio", marker["failed_component"])
            self.assertEqual((), marker["started_components"])

    def test_preparation_is_explicitly_outside_testcase_wall_budget(self):
        class PreparedSession:
            prepared = False

            def prepare_local(self):
                time.sleep(0.05)
                self.prepared = True

            def begin_case(self, testcase_id):
                if not self.prepared:
                    raise RuntimeError("begin happened before preparation")

            def end_case(self):
                pass

        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "environment"),))
        session = PreparedSession()
        runner = ScenarioRunner(sessions={"device": session},
                                ownership=ownership, bindings=())
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
        runner.begin_test("prepared")
        try:
            self.assertTrue(session.prepared)
            self.assertEqual("running", runner._status)
        finally:
            runner.finalize()

    def test_replay_cuts_inflight_begin_before_any_local_process_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self._ready_script(directory, 0)
            runner = _runner(("a", "b"))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=25))
            runner.set_replay_wall_cut(
                0, "inflight_begin", failed_component="b",
                started_components=("a",))
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                with self.assertRaises(ScenarioBudgetExhausted):
                    runner.begin_test("replay-begin")
            self.assertEqual("inflight_begin", runner.events[-1]["phase"])
            self.assertEqual("b", runner.events[-1]["failed_component"])
            self.assertEqual(("a",), runner.events[-1]["started_components"])
            self.assertTrue(all(session._process is None
                                for session in runner.sessions.values()))
            runner.finalize()

    def test_finalize_uses_remaining_testcase_wall_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "ignore-end"
            executable.write_text("#!/bin/sh\nprintf 'READY\\n'\nexec sleep 2\n")
            executable.chmod(0o755)
            runner = _runner(("gpio",))
            runner.set_resource_budget(ResourceBudget(max_wall_time_ms=40))
            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                runner.begin_test("slow-end")
                started = time.monotonic()
                runner.finalize()
                self.assertLess(time.monotonic() - started, 0.3)
            self.assertEqual("budget_exhausted", runner.failure_status)
            marker = runner.events[-1]
            self.assertEqual("inflight_finalize", marker["phase"])
            self.assertTrue(marker["effect_may_have_occurred"])

    def test_scheduler_reports_finalize_wall_cut(self):
        class SlowEndSession:
            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": 0}

            def end_case(self):
                time.sleep(0.03)

        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "environment"),))
        runner = ScenarioRunner(sessions={"device": SlowEndSession()},
                                ownership=ownership, bindings=())
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=10))
        genome = ScenarioGenome(testcase_id="slow-finalize", direction="IP_TO_IP",
                                path_id="finalize", schedule_order=("device",),
                                max_steps=1, actions=())
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("budget_exhausted", result.status)
        self.assertEqual("inflight_finalize", runner.events[-1]["phase"])

    def test_startup_wall_cut_bundle_replays_semantic_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = self._ready_script(directory, 0.15)
            output = Path(directory) / "bundle"
            genome = ScenarioGenome(testcase_id="startup-cut", direction="IP_TO_IP",
                                    path_id="startup", schedule_order=("gpio",),
                                    max_steps=1, actions=())

            def factory():
                return _runner(("gpio",))

            with patch("myfuzz.scenario.gpio_session._binary",
                       return_value=executable):
                trace = save_evidence_bundle(
                    genome, factory, output,
                    budget=ResourceBudget(max_wall_time_ms=25))
                self.assertEqual("budget_exhausted", trace.status)
                self.assertEqual("inflight_begin", trace.events[-1]["phase"])
                comparison = replay_evidence_bundle(output, factory)
                self.assertTrue(comparison.matches)
                self.assertEqual("semantic_prefix", comparison.verification_scope)

    def test_finalize_deadline_exception_still_cleans_later_session(self):
        closed = []

        class EndSession:
            def __init__(self, name):
                self.name = name

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": 0}

            def end_case(self):
                closed.append(self.name)
                if self.name == "a":
                    time.sleep(0.02)
                    raise LocalCommandDeadlineExceeded("END deadline")

        names = ("a", "b")
        ownership = compile_ownership(
            tuple(InputField(name, "pin", 1) for name in names),
            tuple(InputOwner(name, "pin", 0, 1, "source", "environment")
                  for name in names))
        runner = ScenarioRunner(sessions={name: EndSession(name) for name in names},
                                ownership=ownership, bindings=())
        runner.set_resource_budget(ResourceBudget(max_wall_time_ms=10))
        genome = ScenarioGenome(testcase_id="end-error", direction="IP_TO_IP",
                                path_id="finalize", schedule_order=names,
                                max_steps=1, actions=())
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("budget_exhausted", result.status)
        self.assertEqual(["a", "b"], closed)
        self.assertEqual("inflight_finalize", runner.events[-1]["phase"])
        self.assertEqual("LocalCommandDeadlineExceeded",
                         runner.events[-1]["cleanup_errors"][0]["error_type"])

    def test_slow_failed_prepare_is_setup_failure_not_testcase_wall_overrun(self):
        class FailedPrepareSession:
            max_final_state_growth_bytes_per_operation = 0
            max_evidence_record_bytes = 1024
            max_local_ticks_per_step = 1

            def identity_document(self):
                return {"kind": "failed_prepare_fixture"}

            def prepare_local(self):
                time.sleep(0.03)
                raise RuntimeError("bounded setup build failed")

            def begin_case(self, testcase_id):
                raise AssertionError("testcase must not begin after setup failure")

            def end_case(self):
                pass

        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "environment"),))

        def factory():
            return ScenarioRunner(sessions={"device": FailedPrepareSession()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="setup-failure", direction="IP_TO_IP",
                                path_id="setup", schedule_order=("device",),
                                max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, factory, output,
                budget=ResourceBudget(max_wall_time_ms=1))
            self.assertEqual("environment_error", trace.status)
            self.assertEqual("begin_failure", trace.events[-1]["kind"])
            self.assertEqual("RuntimeError", trace.events[-1]["error_type"])
            self.assertTrue((output / "bundle_index.json").is_file())
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(0, result["resource_usage"]["wall_time_ms"])
            self.assertTrue(replay_evidence_bundle(output, factory).matches)

    def test_prior_step_failure_survives_slow_cleanup_with_replayable_wall_cut(self):
        class FailedStepSlowEnd:
            max_final_state_growth_bytes_per_operation = 0
            max_evidence_record_bytes = 2048
            max_local_ticks_per_step = 1

            def identity_document(self):
                return {"kind": "failed_step_slow_end_fixture"}

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                raise RuntimeError("step failed before reply")

            def end_case(self):
                time.sleep(0.03)
                raise LocalCommandDeadlineExceeded("END deadline")

        ownership = compile_ownership(
            (InputField("device", "pin", 1),),
            (InputOwner("device", "pin", 0, 1, "source", "environment"),))

        def factory():
            return ScenarioRunner(sessions={"device": FailedStepSlowEnd()},
                                  ownership=ownership, bindings=())

        genome = ScenarioGenome(testcase_id="failed-step-slow-end",
                                direction="IP_TO_IP", path_id="slow-end",
                                schedule_order=("device",), max_steps=1, actions=())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bundle"
            trace = save_evidence_bundle(
                genome, factory, output,
                budget=ResourceBudget(max_wall_time_ms=10))
            self.assertEqual("uncertain_effect", trace.status)
            self.assertEqual("harness_failure", trace.events[-2]["kind"])
            marker = trace.events[-1]
            self.assertEqual("inflight_finalize", marker["phase"])
            self.assertEqual("uncertain_effect", marker["status_before_finalize"])
            self.assertEqual([{"component": "device",
                               "error_type": "LocalCommandDeadlineExceeded"}],
                             marker["cleanup_errors"])
            replay = replay_evidence_bundle(output, factory)
            self.assertTrue(replay.matches)
            self.assertEqual("semantic_prefix", replay.verification_scope)


if __name__ == "__main__":
    unittest.main()
