"""Transport retries must never repeat a committed CPU memory operation."""

import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


class MemoryServiceTests(unittest.TestCase):
    def setUp(self):
        self.memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0x80000000, 0x1000),),
            initialization_seed=1,
            max_initialized_bytes=64,
        )
        self.service = MemoryService(self.memory, TransactionLedger())

    def key(self, sequence, *, execution="execution-1"):
        return TransactionKey(execution, "case-1", "cpu", 0, "data", sequence)

    def test_duplicate_write_returns_original_receipt_without_second_store(self):
        first = self.service.write(self.key(1), 0x80000040, 0x11223344,
                                   width_bytes=4, byte_enable=0b1111)
        retry = self.service.write(self.key(1), 0x80000040, 0x11223344,
                                   width_bytes=4, byte_enable=0b1111)
        self.assertIs(first, retry)
        self.assertEqual(first.version, self.memory.read(
            0x80000040, 4, transaction_id="probe").versions[0])
        second = self.service.write(self.key(2), 0x80000040, 0x11223344,
                                    width_bytes=4, byte_enable=0b1111)
        self.assertNotEqual(first.version, second.version)

    def test_duplicate_read_keeps_old_snapshot_after_later_write(self):
        self.service.write(self.key(1), 0x80000040, 0x11223344,
                           width_bytes=4, byte_enable=0b1111)
        first = self.service.read(self.key(2), 0x80000040, width_bytes=4)
        self.service.write(self.key(3), 0x80000040, 0x55667788,
                           width_bytes=4, byte_enable=0b1111)
        retry = self.service.read(self.key(2), 0x80000040, width_bytes=4)
        self.assertIs(first, retry)
        self.assertEqual(0x11223344, retry.value)
        self.assertEqual(0x55667788, self.service.read(
            self.key(4), 0x80000040, width_bytes=4).value)

    def test_new_instruction_read_observes_data_store_but_old_fetch_is_frozen(self):
        def fetch_key(sequence):
            return TransactionKey("execution-1", "case-1", "cpu", 0,
                                  "instruction", sequence)

        self.memory.preload(0x80000040, bytes.fromhex("13000000"))
        first_fetch = self.service.read(fetch_key(1), 0x80000040,
                                        width_bytes=4)
        self.service.write(self.key(1), 0x80000040, 0x00100073,
                           width_bytes=4, byte_enable=15)
        later_fetch = self.service.read(fetch_key(2), 0x80000040,
                                        width_bytes=4)
        self.assertEqual(0x00000013, first_fetch.value)
        self.assertEqual(0x00100073, later_fetch.value)
        self.assertEqual(0x00000013,
                         self.service.read(fetch_key(1), 0x80000040,
                                           width_bytes=4).value)
        self.assertEqual((str(self.key(1)),) * 4,
                         later_fetch.writer_event_ids)

    def test_conflicting_reuse_of_key_is_rejected(self):
        self.service.write(self.key(1), 0x80000040, 1,
                           width_bytes=4, byte_enable=0b1111)
        with self.assertRaisesRegex(ValueError, "identity_conflict"):
            self.service.write(self.key(1), 0x80000040, 2,
                               width_bytes=4, byte_enable=0b1111)
        self.assertEqual(1, self.service.read(self.key(2), 0x80000040,
                                              width_bytes=4).value)

    def test_invalid_mmio_access_does_not_materialize_ram(self):
        with self.assertRaisesRegex(ValueError, "unmapped"):
            self.service.read(self.key(1), 0x40000000, width_bytes=4)
        self.assertEqual(0, self.memory.initialized_bytes)
        self.assertEqual((), self.service.ledger.unresolved_keys)

    def test_invalid_write_is_rejected_before_transaction_acceptance(self):
        with self.assertRaisesRegex(ValueError, "byte_enable exceeds"):
            self.service.write(self.key(1), 0x80000040, 1,
                               width_bytes=4, byte_enable=0x10)
        self.assertEqual((), self.service.ledger.unresolved_keys)

    def test_commits_are_logged_once_with_frozen_read_sources(self):
        self.service.write(self.key(1), 0x80000040, 0x11223344,
                           width_bytes=4, byte_enable=0b1111)
        self.service.write(self.key(1), 0x80000040, 0x11223344,
                           width_bytes=4, byte_enable=0b1111)
        self.service.read(self.key(2), 0x80000040, width_bytes=4)
        self.service.read(self.key(2), 0x80000040, width_bytes=4)
        self.assertEqual(["memory_write", "memory_read"],
                         [event["kind"] for event in self.service.events])
        self.assertEqual(0x11223344, self.service.events[1]["value"])
        self.assertEqual(self.service.events[0]["version"],
                         self.service.events[1]["versions"][0])

    def test_first_read_materialization_has_one_event_per_new_byte(self):
        first = self.service.read(self.key(1), 0x80000040, width_bytes=4)
        self.service.read(self.key(1), 0x80000040, width_bytes=4)
        self.service.read(self.key(2), 0x80000040, width_bytes=4)
        initialized = [event for event in self.service.events
                       if event["kind"] == "memory_initialization"]
        self.assertEqual([0x40, 0x41, 0x42, 0x43],
                         [event["byte_offset"] for event in initialized])
        self.assertEqual(list(first.data), [event["value"] for event in initialized])
        self.assertEqual(list(first.versions), [event["version"]
                                                for event in initialized])
        self.assertEqual(list(first.writer_event_ids), [event["writer_event_id"]
                                                         for event in initialized])
        self.assertEqual(2, sum(event["kind"] == "memory_read"
                                for event in self.service.events))


if __name__ == "__main__":
    unittest.main()
