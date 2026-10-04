"""Native tick phases are ordered observations for scheduler triggers."""

import unittest

from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from tests.scenario.test_irq_delivery import RecordingSession


class NativeLevels:
    def __init__(self, samples, summaries):
        self.samples = iter(samples)
        self.summaries = iter(summaries)
        self.pending = []
        self.local_ticks = 0

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        phases = next(self.samples)
        self.local_ticks += 1
        self.pending.append({"local_tick": self.local_ticks,
                             "pre": {"interrupt": phases[0]},
                             "post": {"interrupt": phases[1]}})
        return {"irq": next(self.summaries)}

    def drain_tick_samples(self):
        samples, self.pending = self.pending, []
        return samples

    def end_case(self):
        pass


def run_native(samples, summaries, occurrence, *, batch_sizes=None):
    gpio = NativeLevels(samples, summaries)
    sink = RecordingSession()
    ownership = compile_ownership(
        (InputField("sink", "pin", 1),),
        (InputOwner("sink", "pin", 0, 1, "source", "external"),))
    runner = ScenarioRunner(sessions={"gpio": gpio, "sink": sink},
                            ownership=ownership, bindings=())
    genome = ScenarioGenome(
        "native-trigger", "IP_TO_IP", "gpio-to-sink", ("gpio", "sink"),
        2 * len(samples),
        (Action("edge", "sink", "pin", 1, "IP_TO_IP",
                Trigger("AFTER_OUTPUT", "gpio", "interrupt", 1, 1,
                        occurrence)),))
    result = DependencyScheduler().run(runner, genome, batch_sizes=batch_sizes)
    return result, runner.events


class NativeTickTriggerTests(unittest.TestCase):
    def test_indirect_gpio_receipt_triggers_during_cpu_step(self):
        gpio = NativeLevels(((0, 1), (0, 1)), (0, 0))
        cpu = RecordingSession()
        sink = RecordingSession()

        def cpu_step(inputs):
            cpu.local_ticks += 1
            gpio.step_local({})
            gpio.step_local({})
            return {}

        cpu.step_local = cpu_step
        ownership = compile_ownership(
            (InputField("sink", "pin", 1),),
            (InputOwner("sink", "pin", 0, 1, "source", "external"),))
        runner = ScenarioRunner(sessions={"cpu": cpu, "gpio": gpio, "sink": sink},
                                ownership=ownership, bindings=())
        genome = ScenarioGenome(
            "indirect-native-trigger", "IP_TO_IP", "cpu-gpio-sink",
            ("cpu", "gpio", "sink"), 1,
            (Action("edge", "sink", "pin", 1, "IP_TO_IP",
                    Trigger("AFTER_OUTPUT", "gpio", "irq", 1, 1, 2)),))
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(1, result.steps)
        self.assertEqual(1, sum(event.get("kind") is None
                                for event in runner.events))
        posts = [event for event in runner.events
                 if event.get("kind") == "local_tick_sample"
                 and event["phase"] == "post"]
        self.assertEqual(posts[1]["event_id"],
                         result.consumption_cursors["edge"].event_id)

    def test_post_phase_selects_cursor_even_when_step_summary_is_low(self):
        result, events = run_native(((0, 1),), (0,), 1)
        self.assertEqual("complete", result.status)
        self.assertEqual(2, result.steps)
        sample = next(event for event in events
                      if event.get("kind") == "local_tick_sample"
                      and event["phase"] == "post")
        self.assertEqual(sample["event_id"],
                         result.consumption_cursors["edge"].event_id)
        self.assertEqual(("gpio", "interrupt"),
                         (result.consumption_cursors["edge"].source_component,
                          result.consumption_cursors["edge"].source_port))
        self.assertEqual(1, sum(event.get("kind") == "source_injection"
                                for event in events))

    def test_summary_cannot_create_false_second_edge_from_held_native_level(self):
        for sizes in (None, (4,)):
            with self.subTest(batch_sizes=sizes):
                result, events = run_native(((0, 1), (1, 1)), (0, 0), 2,
                                            batch_sizes=sizes)
                self.assertEqual("path_incomplete", result.status)
                self.assertEqual(4, result.steps)
                self.assertEqual({}, result.consumption_cursors)
                self.assertFalse(any(event.get("kind") == "source_injection"
                                     for event in events))

    def test_two_native_rises_select_second_post_event_once(self):
        result, events = run_native(((0, 1), (0, 1)), (0, 0), 2)
        self.assertEqual("complete", result.status)
        posts = [event for event in events
                 if event.get("kind") == "local_tick_sample"
                 and event["phase"] == "post"]
        self.assertEqual(posts[1]["event_id"],
                         result.consumption_cursors["edge"].event_id)
        self.assertEqual(1, sum(event.get("kind") == "source_injection"
                                for event in events))


if __name__ == "__main__":
    unittest.main()
