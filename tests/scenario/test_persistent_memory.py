"""A CPU's environment memory must retain real effects across local steps."""

import unittest
from unittest.mock import patch

from myfuzz.scenario.memory import MemoryRegion, PersistentMemory


class PersistentMemoryTests(unittest.TestCase):
    def make_memory(self, *, seed=7, limit=64):
        return PersistentMemory(
            regions=(
                MemoryRegion("ram", 0x80000000, 0x1000, aliases=(0x90000000,)),
                MemoryRegion("rom", 0x10000, 0x1000, writable=False),
            ),
            initialization_seed=seed,
            max_initialized_bytes=limit,
        )

    def test_store_survives_steps_and_alias_load(self):
        memory = self.make_memory()
        memory.write(0x80000040, 0x11223344, width_bytes=4,
                     byte_enable=0b1111, writer_event_id="cpu-store-1")
        for _ in range(64):
            memory.advance_step()
        read = memory.read(0x90000040, 4, transaction_id="cpu-load-1")
        self.assertEqual(0x11223344, read.value)
        self.assertEqual(("cpu-store-1",) * 4, read.writer_event_ids)
        self.assertEqual(0, memory.generation)

    def test_byte_enable_preserves_other_lanes_and_frozen_read(self):
        memory = self.make_memory()
        memory.preload(0x80000040, bytes.fromhex("44332211"))
        memory.write(0x80000040, 0xAABBCCDD, width_bytes=4,
                     byte_enable=0b0101, writer_event_id="cpu-store-1")
        old = memory.read(0x80000040, 4, transaction_id="load-before-store")
        self.assertEqual(0x11BB33DD, old.value)
        memory.write(0x80000040, 0x00007700, width_bytes=4,
                     byte_enable=0b0010, writer_event_id="cpu-store-2")
        new = memory.read(0x80000040, 4, transaction_id="load-after-store")
        self.assertEqual(0x11BB33DD, old.value)
        self.assertEqual(0x11BB77DD, new.value)
        self.assertEqual("cpu-store-2", new.writer_event_ids[1])
        self.assertEqual("cpu-store-1", new.writer_event_ids[0])

    def test_unknown_byte_initialized_once_independent_of_access_order(self):
        first = self.make_memory()
        a = first.read(0x80000040, 4, transaction_id="a")
        b = first.read(0x80000044, 4, transaction_id="b")
        second = self.make_memory()
        second.read(0x80000044, 4, transaction_id="b")
        second.read(0x80000040, 1, transaction_id="byte")
        self.assertEqual(a.value, second.read(0x80000040, 4, transaction_id="a").value)
        self.assertEqual(b.value, second.read(0x80000044, 4, transaction_id="b2").value)
        self.assertEqual(8, first.initialized_bytes)
        self.assertEqual(8, second.initialized_bytes)

    def test_partial_unknown_write_materializes_only_unwritten_lanes_on_read(self):
        memory = self.make_memory()
        memory.write(0x80000040, 0xAABBCCDD, width_bytes=4,
                     byte_enable=0b0101, writer_event_id="partial-store")
        self.assertEqual(2, memory.initialized_bytes)
        first = memory.read(0x80000040, 4, transaction_id="first-word-read")
        self.assertEqual((65, 67), first.materialized_offsets)
        self.assertEqual(("partial-store", "init:ram:65",
                          "partial-store", "init:ram:67"),
                         first.writer_event_ids)
        self.assertEqual(0xDD, first.data[0])
        self.assertEqual(0xBB, first.data[2])
        self.assertEqual(4, memory.initialized_bytes)
        later = memory.read(0x90000040, 4, transaction_id="alias-word-read")
        self.assertEqual(first.data, later.data)
        self.assertEqual(first.writer_event_ids, later.writer_event_ids)
        self.assertEqual((), later.materialized_offsets)

    def test_old_written_byte_survives_4096_unrelated_steps(self):
        memory = self.make_memory()
        memory.write(0x80000040, 0x13579BDF, width_bytes=4,
                     byte_enable=15, writer_event_id="old-store")
        for _ in range(4096):
            memory.advance_step()
        result = memory.read(0x80000040, 4, transaction_id="late-load")
        self.assertEqual(0x13579BDF, result.value)
        self.assertEqual(("old-store",) * 4, result.writer_event_ids)
        self.assertEqual(4096, memory.step_count)

    def test_invalid_or_mmio_access_has_no_initializer_effect(self):
        memory = self.make_memory(limit=2)
        with self.assertRaisesRegex(ValueError, "unmapped"):
            memory.read(0x40000000, 4, transaction_id="mmio")
        with self.assertRaisesRegex(ValueError, "read-only"):
            memory.write(0x10000, 0x12345678, width_bytes=4,
                         byte_enable=0b1111, writer_event_id="bad")
        with self.assertRaisesRegex(ValueError, "budget"):
            memory.read(0x80000040, 4, transaction_id="large")
        self.assertEqual(0, memory.initialized_bytes)

    def test_warm_reset_keeps_bytes_and_cold_reset_restarts_generation(self):
        memory = self.make_memory()
        memory.preload(0x80000040, b"\x05\x00\x00\x00")
        memory.write(0x80000040, 17, width_bytes=4, byte_enable=0b1111,
                     writer_event_id="isr-store")
        memory.warm_reset()
        self.assertEqual(17, memory.read(0x80000040, 4, transaction_id="after-warm").value)
        memory.cold_reset()
        self.assertEqual(1, memory.generation)
        self.assertEqual(5, memory.read(0x80000040, 4, transaction_id="after-cold").value)

    def test_same_value_store_changes_writer_but_zero_lane_store_does_not(self):
        memory = self.make_memory()
        first_version = memory.write(
            0x80000040, 0x11223344, width_bytes=4, byte_enable=15,
            writer_event_id="store-one")
        self.assertIsNone(memory.write(
            0x80000040, 0xFFFFFFFF, width_bytes=4, byte_enable=0,
            writer_event_id="disabled-store"))
        unchanged = memory.read(0x80000040, 4, transaction_id="before-rewrite")
        self.assertEqual((first_version,) * 4, unchanged.versions)
        self.assertEqual(("store-one",) * 4, unchanged.writer_event_ids)
        second_version = memory.write(
            0x80000040, 0x11223344, width_bytes=4, byte_enable=15,
            writer_event_id="store-two")
        self.assertNotEqual(first_version, second_version)
        rewritten = memory.read(0x80000040, 4, transaction_id="after-rewrite")
        self.assertEqual(unchanged.value, rewritten.value)
        self.assertEqual((second_version,) * 4, rewritten.versions)
        self.assertEqual(("store-two",) * 4, rewritten.writer_event_ids)

    def test_invalid_write_preserves_full_state_digest(self):
        memory = self.make_memory(limit=4)
        memory.write(0x80000040, 0x11223344, width_bytes=4,
                     byte_enable=15, writer_event_id="first")
        before = memory.state_summary()
        with self.assertRaisesRegex(ValueError, "budget"):
            memory.write(0x80000044, 0x55667788, width_bytes=4,
                         byte_enable=15, writer_event_id="over-budget")
        with self.assertRaisesRegex(ValueError, "unaligned"):
            memory.write(0x80000041, 0x55667788, width_bytes=4,
                         byte_enable=15, writer_event_id="unaligned")
        with self.assertRaisesRegex(ValueError, "byte_enable"):
            memory.write(0x80000040, 0, width_bytes=4,
                         byte_enable=16, writer_event_id="bad-mask")
        self.assertEqual(before, memory.state_summary())

    def test_invalid_reads_and_writes_never_partially_materialize(self):
        memory = self.make_memory(limit=3)
        before = memory.state_summary()
        failures = (
            lambda: memory.read(0x80000040, 4, transaction_id="over-budget"),
            lambda: memory.read(0x80000FFE, 4, transaction_id="cross-boundary"),
            lambda: memory.read(0x10000, 4, transaction_id="uninitialized-rom"),
            lambda: memory.read(0x40000000, 4, transaction_id="unmapped-mmio"),
            lambda: memory.read(0x80000040, 3, transaction_id="bad-width"),
            lambda: memory.write(0x80000FFE, 0, width_bytes=4,
                                 byte_enable=15, writer_event_id="cross-boundary"),
            lambda: memory.write(0x10000, 0, width_bytes=4,
                                 byte_enable=15, writer_event_id="rom-write"),
            lambda: memory.write(0x80000040, 0, width_bytes=4,
                                 byte_enable=15, writer_event_id="over-budget"),
        )
        with patch.object(memory, "_initial_byte", wraps=memory._initial_byte) as initializer:
            for operation in failures:
                with self.subTest(operation=operation):
                    with self.assertRaises(ValueError):
                        operation()
                    self.assertEqual(before, memory.state_summary())
            self.assertEqual(0, initializer.call_count)


if __name__ == "__main__":
    unittest.main()
