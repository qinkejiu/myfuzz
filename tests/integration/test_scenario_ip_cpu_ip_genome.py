"""External GPIO B data → Ibex ISR → GPIO A output in two persistent rounds."""

from __future__ import annotations

import os
import unittest
from dataclasses import replace

from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.campaign import ScenarioCampaign
from myfuzz.scenario.feedback import CoverageTarget

from tests.integration.test_scenario_three_component_genome import _image, _sw


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class IpCpuIpGenomeTests(unittest.TestCase):
    @staticmethod
    def _case():
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=53,
                                  max_initialized_bytes=0x20000)
        a, b = OpenTitanGpioSession(), OpenTitanGpioSession()
        router = DataflowRouter((
            DeviceWindow("gpio_a", 0x40001000, 0x1000, a),
            DeviceWindow("gpio_b", 0x40000000, 0x1000, b)))
        cpu = IbexCpuSession(memory=memory, router=router)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio_a", "gpio_in", 0, 32, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_b")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio_a": a, "gpio_b": b}, ownership=ownership,
            bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
        main = (
            0x400000b7,  # B base
            0x10000113,  # x2=pin 8 mask
            _sw(2, 1, 4), _sw(2, 1, 44),  # enable rising IRQ on pin 8
            0x000102b7, 0x10028293, 0x30529073,  # mtvec
            0x000012b7, 0x80028293, 0x3042a073,  # MEIE
            0x00800293, 0x3002a073,  # MIE
            0x0000006f)
        isr = (
            0x400000b7,  # B base
            0x0100a103,  # x2=B.DATA_IN, from real RTL
            0x40001237,  # A base
            _sw(2, 4, 20),  # A.DIRECT_OUT=x2
            _sw(2, 0, 0x200),  # persistent RAM record
            0x10000193,  # x3=pin 8 mask
            _sw(3, 1, 0),  # B W1C
            0x30200073)
        genome = ScenarioGenome(
            testcase_id="b-cpu-a-two-events", direction="IP_TO_CPU_TO_IP",
            path_id="external-b-irq-cpu-isr-a-output",
            schedule_order=("cpu", "gpio_b", "gpio_a"), max_steps=3600,
            initial_images=(
                MemoryImage("cpu.main", "cpu", 0x10080, _image(main)),
                MemoryImage("cpu.isr", "cpu", 0x10100, _image(isr)),
                MemoryImage("cpu.isr.vector", "cpu", 0x1012c, _image(isr))),
            actions=(
                Action("first-rise", "gpio_b", "gpio_in", 0x100,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 2),
                       delay_component="gpio_b", delay_ticks=4, width=9),
                Action("second-low", "gpio_b", "gpio_in", 0,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 6),
                       delay_component="gpio_b", delay_ticks=4, width=9),
                Action("second-rise", "gpio_b", "gpio_in", 0x300,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 6),
                       delay_component="gpio_b", delay_ticks=16, width=10)))
        return memory, cpu, a, runner, genome

    def test_two_external_gpio_events_change_cpu_and_other_real_gpio(self):
        memory, cpu, a, runner, genome = self._case()
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(3, len(result.fired_actions))
        self.assertGreaterEqual(cpu.memory_write_count, 2)
        self.assertGreaterEqual(cpu.mmio_write_count, 4)
        self.assertEqual(0x300, memory.read(0x200, 4,
                                            transaction_id="check").value)
        self.assertTrue(any(e.get("component") == "gpio_a"
                            and e.get("outputs", {}).get("gpio_out") == 0x300
                            for e in runner.events))
        self.assertTrue(any(e.get("kind") == "dataflow_delivery"
                            and e.get("source") == ("gpio_b", "irq")
                            and e.get("value") == 1 for e in runner.events))
        self.assertTrue(any(e.get("kind") == "state_dependency"
                            and e.get("edge_kind") == "WAW"
                            for e in runner.events))

    def test_second_external_event_mutation_changes_real_cpu_to_ip_result(self):
        _, _, _, runner, seed = self._case()
        graph = DependencyGraph(
            sources=(FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    ("IP_TO_CPU_TO_IP",)),),
            rules=(DependencyRule("a.output", ("b.pin9",),
                                  "DATA_BINDING"),))
        plan = choose_mutation(graph, {"a.output": 10},
                               direction="IP_TO_CPU_TO_IP")
        changed = mutate_genome(seed, plan, graph, runner.ownership,
                                bit_index=0, action_id="second-rise")
        self.assertEqual(0x100, changed.actions[2].value)
        first = record_scenario(seed, lambda: self._case()[3])
        second = record_scenario(changed, lambda: self._case()[3])
        def a_outputs(trace):
            return [e["outputs"]["gpio_out"] for e in trace.events
                    if e.get("component") == "gpio_a"
                    and "outputs" in e and "gpio_out" in e["outputs"]]
        self.assertIn(0x300, a_outputs(first))
        self.assertNotIn(0x300, a_outputs(second))
        self.assertIn(0x100, a_outputs(second))
        self.assertEqual(seed.actions[:2], changed.actions[:2])

    def test_feedback_campaign_reaches_real_downstream_gpio_target(self):
        _, _, _, runner, baseline = self._case()
        seed_actions = list(baseline.actions)
        seed_actions[2] = replace(seed_actions[2], value=0x100)
        seed = replace(baseline, actions=tuple(seed_actions),
                       testcase_id="b-cpu-a-seed")
        graph = DependencyGraph(
            sources=(FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    ("IP_TO_CPU_TO_IP",)),),
            rules=(DependencyRule("a.output.0x300", ("b.pin9",),
                                  "DATA_BINDING"),))
        campaign = ScenarioCampaign(
            graph=graph, ownership=runner.ownership,
            targets=(CoverageTarget("a.output.0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300),),
            factory=lambda: self._case()[3], random_seed=1)
        result = campaign.run(seed, mutations=1)
        self.assertEqual((), result.executions[0].new_targets)
        self.assertEqual(("a.output.0x300",), result.executions[1].new_targets)
        self.assertEqual(0x300, result.executions[1].genome.actions[2].value)

    def test_external_to_cpu_to_gpio_trace_replays_from_fresh_rtl(self):
        genome = self._case()[4]
        reference = record_scenario(genome, lambda: self._case()[3])
        compared = replay_scenario(genome, lambda: self._case()[3], reference)
        self.assertTrue(compared.matches, compared.first_difference)
        self.assertEqual("complete", reference.status)


if __name__ == "__main__":
    unittest.main()
