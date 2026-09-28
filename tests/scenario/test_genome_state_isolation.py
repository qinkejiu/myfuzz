"""A changed genome starts with a fresh testcase memory generation."""

from dataclasses import replace
import unittest

from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


class _MemoryReader:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x1000, 0x1000),),
            initialization_seed=3, max_initialized_bytes=0x1000)
        self.begins = 0

    def identity_document(self):
        return {"fixture": "fresh-memory-reader-v1"}

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        value = self.memory.read(0x1000, 4, transaction_id="fixture-read").value
        return {"rdata": value}

    def end_case(self):
        pass


class GenomeStateIsolationTests(unittest.TestCase):
    def test_mutated_initial_image_never_inherits_previous_final_memory(self):
        sessions = []
        ownership = compile_ownership(
            (InputField("cpu", "environment", 1),),
            (InputOwner("cpu", "environment", 0, 1, "source", "external"),))

        def factory():
            session = _MemoryReader()
            sessions.append(session)
            return ScenarioRunner(sessions={"cpu": session},
                                  ownership=ownership, bindings=())

        first = ScenarioGenome(
            testcase_id="fresh-case", direction="CPU_TO_IP",
            path_id="initial-image", schedule_order=("cpu",),
            max_steps=2, actions=(), initial_images=(
                MemoryImage("cpu.initial", "cpu", 0x1000, "05000000"),))
        changed = replace(first, initial_images=(
            MemoryImage("cpu.initial", "cpu", 0x1000, "09000000"),))
        trace_first = record_scenario(first, factory)
        trace_changed = record_scenario(changed, factory)
        trace_first_again = record_scenario(first, factory)
        self.assertEqual(3, len(sessions))
        self.assertEqual([1, 1, 1], [session.begins for session in sessions])
        self.assertEqual([5, 9, 5], [
            session.memory.read(0x1000, 4, transaction_id="inspect").value
            for session in sessions])
        self.assertEqual(trace_first.semantic_sha256,
                         trace_first_again.semantic_sha256)
        self.assertNotEqual(trace_first.semantic_sha256,
                            trace_changed.semantic_sha256)
        self.assertEqual([0, 0, 0],
                         [session.memory.generation for session in sessions])


if __name__ == "__main__":
    unittest.main()
