"""Replay runs a fresh OpenTitan GPIO RTL process and compares all events."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.runner import ScenarioRunner


class _ConfiguredGpio(OpenTitanGpioSession):
    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.write_register(0x04, 1)
        self.write_register(0x2c, 1)


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealReplayTests(unittest.TestCase):
    def test_full_gpio_trace_replays_from_fresh_rtl(self):
        genome = ScenarioGenome(
            testcase_id="gpio-replay", direction="IP_TO_CPU", path_id="edge-irq",
            schedule_order=("gpio",), max_steps=20,
            actions=(Action("initial-low", "gpio", "gpio_in", 0,
                            "IP_TO_CPU", Trigger("START")),
                     Action("rising-edge", "gpio", "gpio_in", 1,
                            "IP_TO_CPU", Trigger("AFTER_OUTPUT", "gpio", "irq", 1, 0),
                            delay_component="gpio", delay_ticks=3)))
        ownership = compile_ownership(
            (InputField("gpio", "gpio_in", 32),),
            (InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins"),))

        def fresh():
            return ScenarioRunner(sessions={"gpio": _ConfiguredGpio()},
                                  ownership=ownership, bindings=())

        reference = record_scenario(genome, fresh)
        self.assertTrue(any(event.get("outputs", {}).get("irq") == 1
                            for event in reference.events))
        comparison = replay_scenario(genome, fresh, reference)
        self.assertTrue(comparison.matches)
        self.assertEqual(reference.semantic_sha256,
                         comparison.actual_trace.semantic_sha256)
        graph = DependencyGraph(
            sources=(FuzzableSource("gpio.external", "gpio", "gpio_in", 0, 1,
                                    ("IP_TO_CPU",)),),
            rules=(DependencyRule("gpio.irq", ("gpio.external",),
                                  "DATA_BINDING"),))
        plan = choose_mutation(graph, {"gpio.irq": 10}, direction="IP_TO_CPU")
        mutated = mutate_genome(genome, plan, graph, ownership, bit_index=0)
        changed = record_scenario(mutated, fresh)
        self.assertNotEqual(reference.semantic_sha256, changed.semantic_sha256)
        self.assertTrue(any(event.get("outputs", {}).get("irq") == 1
                            for event in changed.events))


if __name__ == "__main__":
    unittest.main()
