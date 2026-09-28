"""Feedback selects upstream source bits from actual execution observations."""

import unittest

from myfuzz.scenario.campaign import ScenarioCampaign
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding, ScenarioRunner


class OutputSession:
    def __init__(self, port):
        self.port = port
        self.begins = 0

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {self.port: inputs.get("pin", 0)}

    def end_case(self):
        pass


class ImageReaderSession:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x100),),
            initialization_seed=3, max_initialized_bytes=0x100)
        self.begins = 0
        self.reads = []

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        value = self.memory.read(0x1000, 1,
                                 transaction_id=f"read-{len(self.reads)}").value
        self.reads.append(value)
        if len(self.reads) == 2:
            self.memory.write(0x1000, 0xFF, width_bytes=1, byte_enable=1,
                              writer_event_id="final-store")
        return {"rdata": value}

    def end_case(self):
        pass


class FeedbackCampaignTests(unittest.TestCase):
    def test_uncovered_downstream_output_mutates_only_upstream_source(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("a.pin", "a", "pin", 0, 1,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("b.irq", ("a.pin",), "DATA_BINDING"),))
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "bound", "a.out")))
        cases = []

        def factory():
            a, b = OutputSession("out"), OutputSession("irq")
            runner = ScenarioRunner(
                sessions={"a": a, "b": b}, ownership=ownership,
                bindings=(Binding("a", "out", "b", "pin", 1),))
            cases.append((a, b, runner))
            return runner

        seed = ScenarioGenome(
            testcase_id="seed", direction="IP_TO_IP", path_id="a-b",
            schedule_order=("a", "b"), max_steps=4,
            actions=(Action("pin", "a", "pin", 0, "IP_TO_IP",
                            Trigger("START"), width=1),))
        result = ScenarioCampaign(
            graph=graph, ownership=ownership,
            targets=(CoverageTarget("b.irq", "b", "irq", 1, 1),),
            factory=factory, random_seed=7).run(seed, mutations=1)
        self.assertEqual(2, len(result.executions))
        self.assertEqual(("b.irq",), result.executions[1].new_targets)
        self.assertEqual(1, result.executions[1].genome.actions[0].value)
        self.assertEqual(0, result.executions[0].genome.actions[0].value)
        self.assertEqual(1, result.executions[1].trace.events[2]["value"])
        self.assertTrue(all(a.begins == b.begins == 1 for a, b, _ in cases))

    def test_memory_image_source_mutates_fresh_initial_image_per_testcase(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("cpu.program", "cpu", "program", 0, 1,
                                    ("CPU_TO_IP",), kind="memory_image"),),
            rules=(DependencyRule("cpu.rdata", ("cpu.program",),
                                  "PERSISTENT_STATE_RULE"),))
        ownership = compile_ownership((), ())
        sessions = []

        def factory():
            session = ImageReaderSession()
            sessions.append(session)
            return ScenarioRunner(sessions={"cpu": session},
                                  ownership=ownership, bindings=())

        seed = ScenarioGenome(
            testcase_id="image-seed", direction="CPU_TO_IP",
            path_id="program-to-rdata", schedule_order=("cpu",),
            max_steps=2, actions=(),
            initial_images=(MemoryImage("program", "cpu", 0x1000, "00"),))
        result = ScenarioCampaign(
            graph=graph, ownership=ownership,
            targets=(CoverageTarget("cpu.rdata", "cpu", "rdata", 1, 1),),
            factory=factory, random_seed=7).run(seed, mutations=1)

        self.assertEqual(2, len(result.executions))
        self.assertEqual("00", seed.initial_images[0].data_hex)
        self.assertEqual("00", result.executions[0].genome.initial_images[0].data_hex)
        self.assertEqual("01", result.executions[1].genome.initial_images[0].data_hex)
        self.assertEqual("memory_image", graph.sources[
            result.executions[1].mutation_plan.focus_source].kind)
        self.assertEqual(("cpu.rdata",), result.executions[1].new_targets)
        self.assertEqual([[0, 0], [1, 1]], [session.reads for session in sessions])
        self.assertEqual([1, 1], [session.begins for session in sessions])
        self.assertEqual([0xFF, 0xFF], [
            session.memory.read(0x1000, 1, transaction_id="inspect").value
            for session in sessions])
        self.assertNotEqual(result.executions[0].trace.semantic_sha256,
                            result.executions[1].trace.semantic_sha256)


if __name__ == "__main__":
    unittest.main()
