"""A batch callback must preserve per-step causal scheduler decisions."""

import unittest

from myfuzz.scenario.genome import Action, ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


class _Echo:
    def __init__(self, output):
        self.output = output
        self.values = []

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.values.append(dict(inputs))
        return {self.output: inputs.get("pin", 0)}

    def end_case(self):
        pass

    def reset_local(self):
        return {}


def _run(batch_sizes=None):
    sessions = {"a": _Echo("out"), "b": _Echo("irq"), "c": _Echo("out")}
    ownership = compile_ownership(
        (InputField("a", "pin", 1), InputField("b", "pin", 1),
         InputField("c", "pin", 1)),
        (InputOwner("a", "pin", 0, 1, "source", "external_a"),
         InputOwner("b", "pin", 0, 1, "bound", "a.out"),
         InputOwner("c", "pin", 0, 1, "source", "external_c")))
    runner = ScenarioRunner(sessions=sessions, ownership=ownership,
                            bindings=(Binding("a", "out", "b", "pin", 1),))
    genome = ScenarioGenome(
        testcase_id="causal-batch", direction="IP_TO_IP", path_id="a-b-c",
        schedule_order=("a", "b", "c"), max_steps=15,
        actions=(Action("rise-a", "a", "pin", 1, "IP_TO_IP",
                        Trigger("START")),
                 Action("rise-c", "c", "pin", 1, "IP_TO_IP",
                        Trigger("AFTER_OUTPUT", "b", "irq", 1, 1),
                        delay_component="c", delay_ticks=2)))
    result = DependencyScheduler().run(runner, genome, batch_sizes=batch_sizes)
    return (result, runner.events, dict(runner.local_ticks),
            runner.final_state_document(), sessions["c"].values)


def _run_mid_batch_reset(batch_sizes=None):
    sessions = {"a": _Echo("out"), "b": _Echo("irq"), "c": _Echo("out")}
    ownership = compile_ownership(
        (InputField("a", "pin", 1), InputField("b", "pin", 1)),
        (InputOwner("a", "pin", 0, 1, "source", "external_a"),
         InputOwner("b", "pin", 0, 1, "bound", "a.out")))
    runner = ScenarioRunner(sessions=sessions, ownership=ownership,
                            bindings=(Binding("a", "out", "b", "pin", 1),))
    genome = ScenarioGenome(
        testcase_id="mid-batch-reset", direction="IP_TO_IP", path_id="a-b-c",
        schedule_order=("a", "b", "c"), max_steps=15, encoding_version=3,
        actions=(Action("rise-a", "a", "pin", 1, "IP_TO_IP",
                        Trigger("START")),),
        reset_actions=(ResetAction(
            "warm-after-irq", "warm_all",
            Trigger("AFTER_OUTPUT", "b", "irq", 1, 1),
            delay_component="c", delay_ticks=2),))
    result = DependencyScheduler().run(runner, genome, batch_sizes=batch_sizes)
    return (result, runner.events, dict(runner.local_ticks),
            runner.final_state_document(), runner.command_epoch)


class SchedulerBatchTriggerTests(unittest.TestCase):
    def test_reset_trigger_and_delay_mid_batch_match_single_step(self):
        baseline = _run_mid_batch_reset()
        self.assertEqual("complete", baseline[0].status)
        self.assertEqual(("warm-after-irq",), baseline[0].fired_resets)
        self.assertEqual({"a": 5, "b": 5, "c": 5}, baseline[2])
        barriers = [index for index, event in enumerate(baseline[1])
                    if event.get("kind") == "reset_barrier"]
        self.assertEqual(1, len(barriers))
        barrier = barriers[0]
        self.assertTrue(any(event.get("component") == "a"
                            for event in baseline[1][:barrier]))
        self.assertTrue(any(event.get("component") == "a"
                            for event in baseline[1][barrier + 1:]))
        self.assertEqual(0, next(event["outputs"]["out"]
                                 for event in baseline[1][barrier + 1:]
                                 if event.get("component") == "a"))
        self.assertEqual(1, baseline[4])
        for sizes in ((15,), (2, 5, 1, 7)):
            with self.subTest(sizes=sizes):
                self.assertEqual(baseline, _run_mid_batch_reset(sizes))

    def test_trigger_and_delayed_release_inside_one_batch_match_single_step(self):
        baseline = _run()
        self.assertEqual("complete", baseline[0].status)
        self.assertEqual([0, 0, 1, 1, 1],
                         [value.get("pin", 0) for value in baseline[4]])
        for sizes in ((15,), (2, 5, 1, 7)):
            with self.subTest(sizes=sizes):
                self.assertEqual(baseline, _run(sizes))

    def test_batch_callback_can_change_next_step_input(self):
        session = _Echo("out")
        ownership = compile_ownership(
            (InputField("a", "pin", 1),),
            (InputOwner("a", "pin", 0, 1, "source", "external_a"),))
        runner = ScenarioRunner(sessions={"a": session}, ownership=ownership,
                                bindings=())
        runner.begin_test("callback")
        try:
            def after_step(component, outputs):
                if len(session.values) == 1:
                    runner.inject_source("a", "pin", 1,
                                         direction="IP_TO_IP")

            outputs = runner.step_batch(("a", "a"), on_step=after_step)
            self.assertEqual(({"out": 0}, {"out": 1}), outputs)
        finally:
            runner.finalize()

    def test_invalid_callback_is_rejected_before_any_step(self):
        session = _Echo("out")
        ownership = compile_ownership(
            (InputField("a", "pin", 1),),
            (InputOwner("a", "pin", 0, 1, "source", "external_a"),))
        runner = ScenarioRunner(sessions={"a": session}, ownership=ownership,
                                bindings=())
        runner.begin_test("invalid-batch-callback")
        try:
            with self.assertRaisesRegex(ValueError, "callback"):
                runner.step_batch(("a",), on_step=object())
            self.assertEqual([], session.values)
            self.assertEqual({"a": 0}, runner.local_ticks)
        finally:
            runner.finalize()


if __name__ == "__main__":
    unittest.main()
