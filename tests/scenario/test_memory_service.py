"""Transport retries must never repeat a committed CPU memory operation."""

from dataclasses import FrozenInstanceError
import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory, ReadSnapshot
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

    def test_writer_kinds_snapshot_preserves_instruction_lanes_after_partial_store(self):
        self.memory.declare_instruction_slots(0x80000040, 1)
        self.service.accept_instructions(0x80000040, bytes.fromhex('13000000'),
                                         source_event_id=str(self.key(2)))
        original = self.service.read(self.key(1), 0x80000040, width_bytes=4)
        self.assertEqual(('INSTRUCTION_SOURCE',) * 4, original.writer_kinds)
        self.service.write(self.key(2), 0x80000040, 0xff0000aa,
                           width_bytes=4, byte_enable=0b1001)
        current = self.service.read(self.key(3), 0x80000040, width_bytes=4)
        self.assertEqual(('STORE', 'INSTRUCTION_SOURCE', 'INSTRUCTION_SOURCE', 'STORE'),
                         current.writer_kinds)
        # Identical writer-ID strings cannot erase the typed lane distinction.
        self.assertEqual((str(self.key(2)),) * 4, current.writer_event_ids)
        self.assertEqual(('INSTRUCTION_SOURCE',) * 4, original.writer_kinds)
        self.assertIs(original, self.service.read(self.key(1), 0x80000040, width_bytes=4))
        with self.assertRaises(FrozenInstanceError):
            original.writer_kinds = current.writer_kinds

    def test_preload_and_first_read_kinds_come_from_actual_cells(self):
        self.memory.preload(0x80000040, b'\x01\x02')
        snapshot = self.memory.read(0x80000040, 4, transaction_id='mixed-preload-read')
        self.assertEqual(('INITIAL_IMAGE', 'INITIAL_IMAGE', 'FIRST_READ', 'FIRST_READ'),
                         snapshot.writer_kinds)
        self.service.write(self.key(1), 0x80000040, 0x11223344,
                           width_bytes=4, byte_enable=15)
        self.assertEqual(('STORE',) * 4,
                         self.memory.read(0x80000040, 4, transaction_id='post-store').writer_kinds)
        self.assertEqual(('INITIAL_IMAGE', 'INITIAL_IMAGE', 'FIRST_READ', 'FIRST_READ'),
                         snapshot.writer_kinds)

    def test_opted_in_read_event_logs_writer_kinds_once_and_freezes_them(self):
        service = MemoryService(self.memory, TransactionLedger(), include_writer_kinds=True)
        original = service.read(self.key(1), 0x80000040, width_bytes=4)
        event = service.events[-1]
        self.assertEqual(('FIRST_READ',) * 4, event['writer_kinds'])
        service.write(self.key(2), 0x80000040, 0x11223344, width_bytes=4, byte_enable=15)
        before = len(service.events)
        self.assertIs(original, service.read(self.key(1), 0x80000040, width_bytes=4))
        self.assertEqual(before, len(service.events))
        self.assertEqual(('FIRST_READ',) * 4, event['writer_kinds'])
        self.assertEqual(original.writer_kinds, event['writer_kinds'])
        current = service.read(self.key(3), 0x80000040, width_bytes=4)
        self.assertEqual(('STORE',) * 4, current.writer_kinds)
        self.assertEqual(current.writer_kinds, service.events[-1]['writer_kinds'])
        self.assertTrue(all('writer_kinds' not in record for record in service.events
                            if record['kind'] != 'memory_read'))

    def test_legacy_service_shape_and_manually_constructed_snapshot_remain_compatible(self):
        snapshot = self.service.read(self.key(1), 0x80000040, width_bytes=4)
        self.assertEqual(('FIRST_READ',) * 4, snapshot.writer_kinds)
        self.assertTrue(all('writer_kinds' not in record for record in self.service.events))
        manual = ReadSnapshot('manual', 'ram', 0, 0, b'\x00', ((0, 1),), ('old-writer',))
        self.assertEqual((), manual.writer_kinds)

    def test_writer_kind_event_configuration_requires_boolean(self):
        for invalid in (1, None, 'true'):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                MemoryService(self.memory, TransactionLedger(), include_writer_kinds=invalid)


if __name__ == "__main__":
    unittest.main()
