"""GEN-01: one Genome frame action persists across local RTL steps."""

import unittest

from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


class _FrameReceiver:
    def __init__(self):
        self.samples = []
        self.begins = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.samples.append(inputs["rx"])
        return {"frame_phase": int(len(self.samples) == 4)}

    def end_case(self):
        pass


class GenomeFramePersistenceTests(unittest.TestCase):
    def test_frame_level_holds_until_next_causal_action(self):
        receiver = _FrameReceiver()
        ownership = compile_ownership(
            (InputField("uart", "rx", 1),),
            (InputOwner("uart", "rx", 0, 1, "source", "external_rx"),))
        runner = ScenarioRunner(sessions={"uart": receiver},
                                ownership=ownership, bindings=())
        genome = ScenarioGenome(
            testcase_id="frame-hold", direction="IP_TO_CPU",
            path_id="uart-rx-frame", schedule_order=("uart",), max_steps=10,
            actions=(
                Action("start-bit", "uart", "rx", 0, "IP_TO_CPU",
                       Trigger("START")),
                Action("stop-bit", "uart", "rx", 1, "IP_TO_CPU",
                       Trigger("AFTER_OUTPUT", "uart", "frame_phase", 1, 1),
                       delay_component="uart", delay_ticks=2),
            ))
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(1, receiver.begins)
        self.assertEqual([0, 0, 0, 0, 0, 0, 1, 1, 1, 1], receiver.samples)
        injections = [event for event in runner.events
                      if event.get("kind") == "source_injection"]
        self.assertEqual(["start-bit", "stop-bit"],
                         [event["action_id"] for event in injections])


if __name__ == "__main__":
    unittest.main()
