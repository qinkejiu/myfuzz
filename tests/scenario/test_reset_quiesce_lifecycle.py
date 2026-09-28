"""Whole testcase reset and bounded drain preserve observable state."""

import unittest

from myfuzz.scenario.genome import (Action, GenomeCodec, ResetAction,
                                    ScenarioGenome, Trigger)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


class LocalSession:
    def __init__(self, memory=None, *, stuck=False):
        self.memory = memory
        self.stuck = stuck
        self.local_ticks = 0
        self.epoch = 0
        self.pending_responses = 0
        self.quiescing = False
        self.accepts = 0
        self.closes = 0

    def begin_case(self, testcase_id):
        self.testcase_id = testcase_id

    def step_local(self, inputs):
        self.local_ticks += 1
        if self.pending_responses and not self.stuck:
            self.pending_responses -= 1
        if inputs.get("pin", 0) and not self.quiescing:
            self.accepts += 1
            self.pending_responses = 1
        return {"out": inputs.get("pin", 0)}

    def begin_quiesce(self):
        self.quiescing = True

    def reset_local(self):
        cancelled = self.pending_responses
        self.pending_responses = 0
        self.quiescing = False
        self.epoch += 1
        return {"cancelled_responses": cancelled}

    def end_case(self):
        self.closes += 1


def _runner(session):
    ownership = compile_ownership(
        (InputField("cpu", "pin", 1),),
        (InputOwner("cpu", "pin", 0, 1, "source", "external"),))
    return ScenarioRunner(sessions={"cpu": session},
                          ownership=ownership, bindings=())


class ResetQuiesceLifecycleTests(unittest.TestCase):
    def test_reset_cancels_late_bound_input_and_pending_local_event(self):
        class Source:
            def __init__(self):
                self.pending_events = 2

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"out": 1}

            def reset_local(self):
                self.pending_events = 0
                return {"cancelled_responses": 0}

            def end_case(self):
                pass

        class Target:
            def __init__(self):
                self.seen = []

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                self.seen.append(inputs.get("pin", 0))
                return {}

            def reset_local(self):
                return {"cancelled_responses": 0}

            def end_case(self):
                pass

        source, target = Source(), Target()
        ownership = compile_ownership(
            (InputField("b", "pin", 1),),
            (InputOwner("b", "pin", 0, 1, "bound", "a.out"),))
        runner = ScenarioRunner(sessions={"a": source, "b": target},
                                ownership=ownership,
                                bindings=(Binding("a", "out", "b", "pin", 1),))
        runner.begin_test("reset-pending")
        try:
            runner.step("a")
            self.assertEqual(("b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            runner.reset_all("warm_all")
            barrier = next(e for e in runner.events
                           if e.get("kind") == "reset_barrier")
            self.assertEqual("warm_all", barrier["policy"])
            self.assertEqual(("b",), barrier["cancelled_dataflow_targets"])
            self.assertEqual({"a": 2}, barrier["pending_events_before_reset"])
            self.assertEqual({}, barrier["pending_events_after_reset"])
            runner.step("b")
            self.assertEqual([0], target.seen)
        finally:
            runner.finalize()

    def test_quiesce_delivers_late_bound_event_to_other_component(self):
        class Source:
            def __init__(self):
                self.pending_events = 1

            def begin_case(self, testcase_id):
                pass

            def begin_quiesce(self):
                pass

            def step_local(self, inputs):
                self.pending_events -= 1
                return {"out": 1}

            def end_case(self):
                pass

        class Target:
            def __init__(self):
                self.seen = []

            def begin_case(self, testcase_id):
                pass

            def begin_quiesce(self):
                pass

            def step_local(self, inputs):
                self.seen.append(inputs["pin"])
                return {}

            def end_case(self):
                pass

        source, target = Source(), Target()
        ownership = compile_ownership(
            (InputField("b", "pin", 1),),
            (InputOwner("b", "pin", 0, 1, "bound", "a.out"),))
        runner = ScenarioRunner(sessions={"a": source, "b": target},
                                ownership=ownership,
                                bindings=(Binding("a", "out", "b", "pin", 1),))
        runner.begin_test("async-bound-drain")
        try:
            outcome = runner.quiesce(3)
            self.assertEqual("drained", outcome.status)
            self.assertEqual(2, outcome.steps)
            self.assertEqual([1], target.seen)
        finally:
            runner.finalize()

        source, target = Source(), Target()
        runner = ScenarioRunner(sessions={"a": source, "b": target},
                                ownership=ownership,
                                bindings=(Binding("a", "out", "b", "pin", 1),))
        runner.begin_test("async-bound-no-budget")
        try:
            runner.step("a")
            self.assertEqual(("b",), runner.final_state_document()[
                "pending_dataflow_targets"])
            outcome = runner.quiesce(0)
            self.assertEqual("incomplete", outcome.status)
            self.assertEqual(0, outcome.steps)
            self.assertEqual(("b",), runner.events[-1][
                "pending_dataflow_targets"])
            self.assertEqual([], target.seen)
        finally:
            runner.finalize()

    def test_quiesce_drains_accepted_response_without_new_accepts(self):
        session = LocalSession()
        runner = _runner(session)
        runner.begin_test("drain")
        runner.inject_source("cpu", "pin", 1, direction="CPU_TO_IP")
        runner.step("cpu")
        self.assertEqual(1, session.accepts)
        result = runner.quiesce(2)
        self.assertEqual("drained", result.status)
        self.assertEqual(1, result.steps)
        self.assertEqual(0, result.pending_responses["cpu"])
        self.assertEqual(1, session.accepts)
        with self.assertRaisesRegex(RuntimeError, "not running"):
            runner.inject_source("cpu", "pin", 0, direction="CPU_TO_IP")
        runner.finalize()
        runner.finalize()
        self.assertEqual(1, session.closes)

    def test_quiesce_budget_exhaustion_keeps_pending_visible(self):
        session = LocalSession(stuck=True)
        runner = _runner(session)
        runner.begin_test("stuck")
        runner.inject_source("cpu", "pin", 1, direction="CPU_TO_IP")
        runner.step("cpu")
        result = runner.quiesce(2)
        self.assertEqual("incomplete", result.status)
        self.assertEqual(2, result.steps)
        self.assertEqual(1, result.pending_responses["cpu"])
        self.assertEqual(1, session.accepts)
        runner.finalize()

    def test_genome_v3_causal_reset_and_quiesce_replay_canonically(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 256),),
            initialization_seed=19, max_initialized_bytes=256)
        session = LocalSession(memory)
        runner = _runner(session)
        genome = ScenarioGenome(
            testcase_id="reset-flow", direction="CPU_TO_IP", path_id="pin-reset",
            schedule_order=("cpu",), max_steps=4,
            actions=(Action("rise", "cpu", "pin", 1, "CPU_TO_IP",
                            Trigger("START")),),
            encoding_version=3,
            reset_actions=(ResetAction("reset", "warm_all",
                                       Trigger("AFTER_OUTPUT", "cpu", "out", 1, 1)),),
            quiesce_steps=2)
        self.assertEqual(genome, GenomeCodec.decode(GenomeCodec.encode(genome)))
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(("reset",), result.fired_resets)
        self.assertEqual("drained", result.quiesce.status)
        self.assertEqual(1, session.epoch)
        self.assertEqual(0, runner.events[-2]["pending_responses"]["cpu"])
        self.assertEqual(1, sum(event.get("kind") == "reset_barrier"
                                for event in runner.events))


if __name__ == "__main__":
    unittest.main()
