"""Batch transport boundaries preserve one continuous runner schedule."""

import unittest

from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class _Echo:
    def __init__(self):
        self.begins = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


class StepBatchEquivalenceTests(unittest.TestCase):
    def run_schedule(self, chunk_sizes):
        sessions = {"a": _Echo(), "b": _Echo()}
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out")))
        runner = ScenarioRunner(sessions=sessions, ownership=ownership,
                                bindings=(Binding("a", "out", "b", "pin", 1),))
        runner.begin_test("batch-equivalence")
        try:
            runner.inject_source("a", "pin", 1, direction="IP_TO_IP")
            schedule = ("a", "b", "b", "a", "b", "a", "b", "b")
            offset = 0
            index = 0
            while offset < len(schedule):
                size = chunk_sizes[index % len(chunk_sizes)]
                runner.step_batch(schedule[offset:offset + size])
                offset += size
                index += 1
            return (runner.events, dict(runner.local_ticks),
                    runner.final_state_document(),
                    tuple(session.begins for session in sessions.values()))
        finally:
            runner.finalize()

    def test_single_fixed_and_irregular_batches_have_same_semantics(self):
        baseline = self.run_schedule((1,))
        self.assertEqual((1, 1), baseline[3])
        self.assertEqual({"a": 3, "b": 5}, baseline[1])
        for sizes in ((8,), (2,), (3,), (1, 4, 2)):
            with self.subTest(sizes=sizes):
                self.assertEqual(baseline, self.run_schedule(sizes))

    def test_invalid_later_component_rejects_before_first_step(self):
        session = _Echo()
        ownership = compile_ownership(
            (InputField("a", "pin", 1),),
            (InputOwner("a", "pin", 0, 1, "source", "external"),))
        runner = ScenarioRunner(sessions={"a": session}, ownership=ownership,
                                bindings=())
        runner.begin_test("invalid-batch")
        try:
            with self.assertRaisesRegex(ValueError, "unknown local harness"):
                runner.step_batch(("a", "missing"))
            self.assertEqual(0, runner.local_ticks["a"])
            self.assertEqual((), runner.events)
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
