"""Byte-level version edges survive unrelated steps and partial overwrites."""

import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.state_dependency import StateDependencyTracker


class StateDependencyTests(unittest.TestCase):
    def test_equal_value_new_writer_is_distinct_and_zero_enable_keeps_writer(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x100),),
                                  initialization_seed=9, max_initialized_bytes=64)
        service = MemoryService(memory, TransactionLedger())
        tracker = StateDependencyTracker()

        def key(sequence):
            return TransactionKey("exec", "case", "cpu", 0, "data", sequence)

        service.write(key(1), 0x1000, 0x5a, width_bytes=1, byte_enable=1)
        service.write(key(2), 0x1000, 0x5a, width_bytes=1, byte_enable=1)
        service.write(key(3), 0x1000, 0xff, width_bytes=1, byte_enable=0)
        self.assertEqual(0x5a, service.read(key(4), 0x1000, width_bytes=1).value)
        tracker.ingest(service.events)
        self.assertEqual({(str(key(1)), str(key(2)))}, {
            (edge.source, edge.target) for edge in tracker.edges
            if edge.kind == "WAW"})
        self.assertEqual({str(key(2))}, {
            edge.source for edge in tracker.edges
            if edge.kind == "RAW" and edge.target == str(key(4))})
        self.assertFalse(any(edge.source == str(key(3))
                             or edge.target == str(key(3))
                             for edge in tracker.edges))

    def test_warm_read_keeps_old_writer_and_cold_read_uses_new_generation(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x1000),),
                                  initialization_seed=1, max_initialized_bytes=64)
        service = MemoryService(memory, TransactionLedger())
        tracker = StateDependencyTracker()

        def key(epoch, sequence):
            return TransactionKey("exec", "case", "cpu", epoch, "data", sequence)

        original = key(0, 1)
        service.write(original, 0x1000, 0x12345678,
                      width_bytes=4, byte_enable=15)
        tracker.ingest(service.events)
        for _ in range(64):
            memory.advance_step()
        memory.warm_reset()
        warm = key(1, 1)
        self.assertEqual(0x12345678,
                         service.read(warm, 0x1000, width_bytes=4).value)
        tracker.ingest(service.events)
        self.assertEqual({str(original)}, {
            edge.source for edge in tracker.edges
            if edge.kind == "PERSIST" and edge.target == str(warm)})

        invalidated = tracker.invalidate_generation("ram", 0, "reset:cold")
        self.assertEqual(4, len(invalidated))
        memory.cold_reset()
        cold = key(2, 1)
        self.assertNotEqual(0x12345678,
                            service.read(cold, 0x1000, width_bytes=4).value)
        tracker.ingest(service.events)
        cold_edges = [edge for edge in tracker.edges
                      if edge.kind == "PERSIST" and edge.target == str(cold)]
        self.assertEqual(4, len(cold_edges))
        self.assertTrue(all(edge.generation == 1 for edge in cold_edges))
        self.assertTrue(all(edge.source != str(original) for edge in cold_edges))

    def test_partial_overwrite_keeps_other_writer_and_read_snapshot(self):
        memory = PersistentMemory(regions=(MemoryRegion("ram", 0x1000, 0x1000),),
                                  initialization_seed=1, max_initialized_bytes=64)
        service = MemoryService(memory, TransactionLedger())

        def key(sequence):
            return TransactionKey("exec", "case", "cpu", 0, "data", sequence)

        service.write(key(1), 0x1000, 0x11223344,
                      width_bytes=4, byte_enable=0b1111)
        for _ in range(20):
            memory.advance_step()
        first = service.read(key(2), 0x1000, width_bytes=4)
        service.write(key(3), 0x1000, 0x55667788,
                      width_bytes=4, byte_enable=0b0101)
        second = service.read(key(4), 0x1000, width_bytes=4)

        tracker = StateDependencyTracker()
        tracker.ingest(service.events)
        self.assertEqual(0x11223344, first.value)
        self.assertEqual(0x11663388, second.value)
        self.assertEqual({0, 2}, {edge.byte_offset for edge in tracker.edges
                                  if edge.kind == "WAW"})
        self.assertEqual({0, 2}, {edge.byte_offset for edge in tracker.edges
                                  if edge.kind == "WAR"})
        last_read = str(key(4))
        writer1, writer3 = str(key(1)), str(key(3))
        self.assertEqual({writer3}, {edge.source for edge in tracker.edges
                                     if edge.kind == "RAW"
                                     and edge.target == last_read
                                     and edge.byte_offset in (0, 2)})
        self.assertEqual({writer1}, {edge.source for edge in tracker.edges
                                     if edge.kind == "RAW"
                                     and edge.target == last_read
                                     and edge.byte_offset in (1, 3)})
        self.assertTrue(any(edge.kind == "PERSIST" and edge.source == writer1
                            and edge.target == last_read
                            and edge.byte_offset == 1 for edge in tracker.edges))


if __name__ == "__main__":
    unittest.main()
