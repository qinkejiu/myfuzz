"""A genome supplies external edges after real CPU configuration transactions."""

from __future__ import annotations

import os
import unittest

from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.gpio_session import OpenTitanGpioSession
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.mutation import choose_mutation, mutate_genome


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class GenomeIbexIrqTests(unittest.TestCase):
    @staticmethod
    def _case():
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x20000),),
                                  initialization_seed=41,
                                  max_initialized_bytes=0x20000)
        main = (0x400000b7,  # GPIO B base
                0x00100113,  # li x2,1
                0x0020a223,  # sw x2, INTR_ENABLE
                0x0220a623,  # sw x2, INTR_CTRL_EN_RISING
                0x000102b7, 0x10028293, 0x30529073,  # mtvec=0x10100
                0x000012b7, 0x80028293, 0x3042a073,  # MEIE
                0x00800293, 0x3002a073,  # MIE
                0x0000006f)
        isr = (0x400000b7, 0x0100a103, 0x20202023,
               0x00100193, 0x0030a023, 0x30200073)
        main_image = b"".join(x.to_bytes(4, "little") for x in main)
        isr_image = b"".join(x.to_bytes(4, "little") for x in isr)
        gpio = OpenTitanGpioSession()
        router = DataflowRouter((DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio),))
        cpu = IbexCpuSession(memory=memory, router=router)
        ownership = compile_ownership(
            (InputField("cpu", "irq", 2), InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_pins")))
        runner = ScenarioRunner(
            sessions={"cpu": cpu, "gpio_b": gpio}, ownership=ownership,
            bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
        genome = ScenarioGenome(
            testcase_id="cpu-config-two-edges", direction="IP_TO_CPU_TO_IP",
            path_id="gpio-input-irq-cpu-gpio-ack",
            schedule_order=("cpu", "gpio_b"), max_steps=1200,
            initial_images=(MemoryImage("cpu.main", "cpu", 0x10080,
                                        main_image.hex()),
                            MemoryImage("cpu.isr", "cpu", 0x10100,
                                        isr_image.hex()),
                            MemoryImage("cpu.isr.second", "cpu", 0x1012c,
                                        isr_image.hex())),
            actions=(
                Action("initial-low", "gpio_b", "gpio_in", 0x5a,
                       "IP_TO_CPU_TO_IP", Trigger("START")),
                Action("first-rise", "gpio_b", "gpio_in", 0x5b,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 2),
                       delay_component="gpio_b", delay_ticks=4),
                Action("second-low", "gpio_b", "gpio_in", 0x58,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 4),
                       delay_component="gpio_b", delay_ticks=4),
                Action("second-rise", "gpio_b", "gpio_in", 0x59,
                       "IP_TO_CPU_TO_IP",
                       Trigger("AFTER_OUTPUT", "cpu", "data_req_valid", 1, 1, 4),
                       delay_component="gpio_b", delay_ticks=16)))
        return memory, cpu, runner, genome

    def test_cpu_configures_gpio_then_two_causal_external_edges(self):
        memory, cpu, runner, genome = self._case()
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(4, len(result.fired_actions))
        self.assertGreaterEqual(cpu.mmio_write_count, 4)  # config twice, W1C twice
        self.assertGreaterEqual(cpu.memory_write_count, 2)
        self.assertEqual(0x59, memory.read(0x200, 4,
                                           transaction_id="assert").value)
        injections = [event["action_id"] for event in runner.events
                      if event.get("kind") == "source_injection"]
        self.assertEqual(["initial-low", "first-rise", "second-low", "second-rise"],
                         injections)
        self.assertGreaterEqual(sum(event.get("kind") == "mmio_delivery"
                                    for event in runner.events), 6)
        self.assertGreaterEqual(sum(event.get("kind") == "memory_write"
                                    for event in runner.events), 2)
        self.assertTrue(any(event.get("kind") == "state_dependency"
                            and event.get("edge_kind") == "WAW"
                            for event in runner.events))

    def test_complete_cpu_gpio_trace_replays_from_fresh_rtl(self):
        genome = self._case()[3]
        trace = record_scenario(genome, lambda: self._case()[2])
        replay = replay_scenario(genome, lambda: self._case()[2], trace)
        self.assertTrue(replay.matches, replay.first_difference)
        self.assertGreaterEqual(sum(e.get("kind") == "mmio_delivery"
                                    for e in trace.events), 6)
        self.assertTrue(any(e.get("kind") == "state_dependency"
                            for e in trace.events))

    def test_mutating_cpu_program_changes_real_gpio_irq_chain(self):
        _, _, _, seed = self._case()
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.main", "cpu", "cpu.main", 32, 32,
                                    ("IP_TO_CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("gpio.irq", ("cpu.main",),
                                  "PERSISTENT_STATE_RULE"),))
        plan = choose_mutation(graph, {"gpio.irq": 10},
                               direction="IP_TO_CPU_TO_IP")
        _, _, runner, _ = self._case()
        changed = mutate_genome(seed, plan, graph, runner.ownership,
                                bit_index=20)
        seed_trace = record_scenario(seed, lambda: self._case()[2])
        changed_trace = record_scenario(changed, lambda: self._case()[2])
        self.assertEqual("complete", seed_trace.status)
        self.assertEqual("path_incomplete", changed_trace.status)
        self.assertNotEqual(seed_trace.semantic_sha256,
                            changed_trace.semantic_sha256)
        self.assertEqual(seed.initial_images[1:], changed.initial_images[1:])
        self.assertEqual(seed.actions, changed.actions)


if __name__ == "__main__":
    unittest.main()
