"""Continuous actions depend on observed outputs and local tick delays."""

import unittest

from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                         FuzzableSource)
from myfuzz.scenario.genome import (Action, GenomeCodec, MemoryImage,
                                    ScenarioGenome, Trigger)
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler


class Echo:
    def __init__(self, output_port):
        self.output_port = output_port
        self.begins = 0
        self.values = []

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.values.append(dict(inputs))
        return {self.output_port: inputs.get("pin", 0)}

    def end_case(self):
        pass


class GenomeSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = Echo("out"), Echo("irq"), Echo("out")
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1),
             InputField("c", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external_a"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out"),
             InputOwner("c", "pin", 0, 1, "source", "external_c")))
        self.runner = ScenarioRunner(
            sessions={"a": self.a, "b": self.b, "c": self.c},
            ownership=ownership,
            bindings=(Binding("a", "out", "b", "pin", 1),))

    def test_after_real_output_and_two_target_local_ticks(self):
        genome = ScenarioGenome(
            testcase_id="cause-1", direction="IP_TO_IP", path_id="a-b-c",
            schedule_order=("a", "b", "c"), max_steps=15,
            actions=(Action("rise-a", "a", "pin", 1, "IP_TO_IP",
                            Trigger("START")),
                     Action("rise-c", "c", "pin", 1, "IP_TO_IP",
                            Trigger("AFTER_OUTPUT", "b", "irq", 1, 1),
                            delay_component="c", delay_ticks=2)))
        result = DependencyScheduler().run(self.runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(1, self.a.begins)
        self.assertEqual(1, self.b.values[0]["pin"])
        self.assertEqual([0, 0, 1, 1, 1],
                         [value.get("pin", 0) for value in self.c.values])
        injections = [e for e in self.runner.events
                      if e.get("kind") == "source_injection"]
        self.assertEqual(["rise-a", "rise-c"],
                         [e["action_id"] for e in injections])
        self.assertEqual(2, len(injections))

    def test_missing_real_output_does_not_activate_action(self):
        genome = ScenarioGenome(
            testcase_id="missing", direction="IP_TO_IP", path_id="a-b-c",
            schedule_order=("a", "b", "c"), max_steps=6,
            actions=(Action("rise-c", "c", "pin", 1, "IP_TO_IP",
                            Trigger("AFTER_OUTPUT", "b", "irq", 1, 1)),))
        result = DependencyScheduler().run(self.runner, genome)
        self.assertEqual("path_incomplete", result.status)
        self.assertEqual(0, sum(value.get("pin", 0) for value in self.c.values))

    def test_static_cycle_does_not_fabricate_two_real_event_occurrences(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("external.pin", "b", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("b.irq", ("external.pin",), "DATA_BINDING"),
                   DependencyRule("b.irq", ("feedback",), "EVENT_ORDER"),
                   DependencyRule("feedback", ("b.irq",), "EVENT_ORDER")))
        self.assertEqual(("external.pin",), graph.paths_to(
            "feedback", direction="IP_TO_IP")[0].source_ids)

        class ObservedIrq:
            def __init__(self, levels):
                self.levels = iter(levels)

            def begin_case(self, testcase_id):
                pass

            def step_local(self, inputs):
                return {"irq": next(self.levels)}

            def end_case(self):
                pass

        def run(levels):
            target = Echo("out")
            ownership = compile_ownership(
                (InputField("c", "pin", 1),),
                (InputOwner("c", "pin", 0, 1, "source", "external_c"),))
            runner = ScenarioRunner(
                sessions={"b": ObservedIrq(levels), "c": target},
                ownership=ownership, bindings=())
            genome = ScenarioGenome(
                testcase_id="two-irqs", direction="IP_TO_IP",
                path_id="feedback", schedule_order=("b", "c"), max_steps=6,
                actions=(Action("on-second-irq", "c", "pin", 1, "IP_TO_IP",
                                Trigger("AFTER_OUTPUT", "b", "irq", 1, 1, 2)),))
            return DependencyScheduler().run(runner, genome), runner

        missing, missing_runner = run((1, 1, 1))
        self.assertEqual("path_incomplete", missing.status)
        self.assertFalse(any(event.get("kind") == "source_injection"
                             for event in missing_runner.events))
        observed, observed_runner = run((1, 0, 1))
        self.assertEqual("complete", observed.status)
        irq_events = [event for event in observed_runner.events
                      if event.get("component") == "b"
                      and "irq" in event.get("outputs", {})]
        self.assertEqual((1, 0, 1), tuple(
            event["outputs"]["irq"] for event in irq_events))
        self.assertEqual(1, sum(event.get("kind") == "source_injection"
                                for event in observed_runner.events))

    def test_codec_is_canonical_and_rejects_unknown_fields(self):
        genome = ScenarioGenome(
            testcase_id="codec", direction="IP_TO_IP", path_id="gpio-edge",
            schedule_order=("a",), max_steps=4,
            actions=(Action("edge", "a", "pin", 1, "IP_TO_IP", Trigger("START")),))
        raw = GenomeCodec.encode(genome)
        self.assertEqual(genome, GenomeCodec.decode(raw))
        self.assertEqual(raw, GenomeCodec.encode(GenomeCodec.decode(raw)))
        with self.assertRaisesRegex(ValueError, "unknown"):
            GenomeCodec.decode(raw[:-1] + b',"unowned":1}')

    def test_program_image_is_loaded_once_before_continuous_execution(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0, 0x1000),),
                                  initialization_seed=3, max_initialized_bytes=0x1000)
        self.a.memory = memory
        genome = ScenarioGenome(
            testcase_id="program", direction="CPU_TO_IP", path_id="cpu-program",
            schedule_order=("a", "b", "c"), max_steps=3, actions=(),
            initial_images=(MemoryImage("cpu.program", "a", 0x100, "13000000"),))
        self.assertEqual(genome, GenomeCodec.decode(GenomeCodec.encode(genome)))
        result = DependencyScheduler().run(self.runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(0x13, memory.read(0x100, 4, transaction_id="check").value)
        with self.assertRaisesRegex(ValueError, "overwrite"):
            memory.preload(0x100, b"\x00")


if __name__ == "__main__":
    unittest.main()
