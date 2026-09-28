"""Remaining G1 checks for multiple persistent keys and repeated events."""

import unittest

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.scheduler import DependencyScheduler
from myfuzz.scenario.state_dependency import StateDependencyTracker


class _PulseSession:
    def __init__(self):
        self.levels = iter((0, 1, 1, 0, 1, 0))

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"irq": next(self.levels)}

    def end_case(self):
        pass


class _StateSink:
    def __init__(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("state", 0x1000, 0x100),),
            initialization_seed=3, max_initialized_bytes=0x100)
        self.service = MemoryService(self.memory, TransactionLedger())
        self.previous = 0
        self.sequence = 0
        self.case_id = ""

    def begin_case(self, testcase_id):
        self.case_id = testcase_id

    def step_local(self, inputs):
        current = inputs.get("pin", 0)
        if current != self.previous and current:
            self.sequence += 1
            key = TransactionKey("fixture-execution", self.case_id, "sink",
                                 0, "state", self.sequence)
            self.service.write(key, 0x1000, current,
                               width_bytes=1, byte_enable=1)
        self.previous = current
        return {"seen": current}

    def end_case(self):
        pass


class G1DependencyRemainingTests(unittest.TestCase):
    def test_warm_and_cold_keep_each_address_and_memory_writer_separate(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram_a", 0x1000, 0x100),
                     MemoryRegion("ram_b", 0x2000, 0x100)),
            initialization_seed=19, max_initialized_bytes=0x200)
        service = MemoryService(memory, TransactionLedger())
        tracker = StateDependencyTracker()

        def key(epoch, sequence):
            return TransactionKey("execution", "case", "cpu", epoch,
                                  "data", sequence)

        locations = ((0x1000, "ram_a", 0x11),
                     (0x1004, "ram_a", 0x22),
                     (0x2000, "ram_b", 0x33))
        originals = {}
        for sequence, (address, memory_id, value) in enumerate(locations, 1):
            transaction = key(0, sequence)
            originals[(memory_id, address)] = str(transaction)
            service.write(transaction, address, value,
                          width_bytes=1, byte_enable=1)
        tracker.ingest(service.events)
        for _ in range(1024):
            memory.advance_step()
        memory.warm_reset()
        self.assertEqual(0, memory.generation)

        warm_reads = {}
        for sequence, (address, memory_id, value) in enumerate(locations, 1):
            transaction = key(1, sequence)
            snapshot = service.read(transaction, address, width_bytes=1)
            warm_reads[(memory_id, address)] = str(transaction)
            self.assertEqual((value, (originals[(memory_id, address)],)),
                             (snapshot.value, snapshot.writer_event_ids))
        tracker.ingest(service.events)
        for address, memory_id, _ in locations:
            offset = address - (0x1000 if memory_id == "ram_a" else 0x2000)
            self.assertEqual(1, sum(
                edge.kind == "PERSIST" and edge.memory_id == memory_id
                and edge.generation == 0 and edge.byte_offset == offset
                and edge.source == originals[(memory_id, address)]
                and edge.target == warm_reads[(memory_id, address)]
                for edge in tracker.edges))

        invalidated = tuple(tracker.invalidate_generation(memory_id, 0, "cold")
                            for memory_id in ("ram_a", "ram_b"))
        self.assertEqual((2, 1), tuple(len(edges) for edges in invalidated))
        memory.cold_reset()
        self.assertEqual(1, memory.generation)
        cold_reads = {}
        for sequence, (address, memory_id, _) in enumerate(locations, 1):
            transaction = key(2, sequence)
            snapshot = service.read(transaction, address, width_bytes=1)
            cold_reads[(memory_id, address)] = str(transaction)
            self.assertEqual(1, snapshot.generation)
            self.assertNotIn(originals[(memory_id, address)],
                             snapshot.writer_event_ids)
        tracker.ingest(service.events)
        self.assertFalse(any(
            edge.kind in ("RAW", "PERSIST") and edge.generation == 1
            and edge.source in originals.values()
            and edge.target in cold_reads.values()
            for edge in tracker.edges))

    def test_two_real_output_rises_create_two_actions_and_state_versions(self):
        graph = DependencyGraph(
            sources=(FuzzableSource("external.pin", "sink", "pin", 0, 2,
                                    ("IP_TO_IP",)),),
            rules=(DependencyRule("done", ("feedback",), "EVENT_ORDER"),
                   DependencyRule("feedback", ("done",), "EVENT_ORDER"),
                   DependencyRule("feedback", ("external.pin",),
                                  "DATA_BINDING")))
        self.assertEqual(("external.pin",),
                         graph.paths_to("done", direction="IP_TO_IP")[0].source_ids)
        ownership = compile_ownership(
            (InputField("sink", "pin", 2),),
            (InputOwner("sink", "pin", 0, 2, "source", "external"),))
        sink = _StateSink()
        runner = ScenarioRunner(
            sessions={"pulse": _PulseSession(), "sink": sink},
            ownership=ownership, bindings=())
        genome = ScenarioGenome(
            "two-occurrences", "IP_TO_IP", "done", ("pulse", "sink"), 12,
            (Action("round-1", "sink", "pin", 1, "IP_TO_IP",
                    Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1, 1),
                    width=2),
             Action("round-2", "sink", "pin", 2, "IP_TO_IP",
                    Trigger("AFTER_OUTPUT", "pulse", "irq", 1, 1, 2),
                    width=2)))
        result = DependencyScheduler().run(runner, genome)
        self.assertEqual("complete", result.status)
        self.assertEqual(("round-1", "round-2"), result.fired_actions)
        events = runner.events
        levels = [event for event in events if event.get("component") == "pulse"
                  and "irq" in event.get("outputs", {})]
        self.assertEqual([0, 1, 1, 0, 1, 0],
                         [event["outputs"]["irq"] for event in levels])
        injections = [event for event in events
                      if event.get("kind") == "source_injection"]
        self.assertEqual(["round-1", "round-2"],
                         [event["action_id"] for event in injections])
        self.assertLess(levels[1]["event_id"], injections[0]["event_id"])
        self.assertLess(levels[4]["event_id"], injections[1]["event_id"])
        self.assertGreater(injections[1]["event_id"], levels[2]["event_id"])
        writes = [event for event in events
                  if event.get("kind") == "memory_write"
                  and event.get("memory_id") == "state"]
        self.assertEqual([1, 2], [event["value"] for event in writes])
        self.assertEqual([(0, 1), (0, 2)],
                         [tuple(event["version"]) for event in writes])
        self.assertEqual(1, sum(event.get("kind") == "state_dependency"
                                and event.get("edge_kind") == "WAW"
                                for event in events))
        self.assertFalse(any("done" in event.get("outputs", {})
                             for event in events))


if __name__ == "__main__":
    unittest.main()
