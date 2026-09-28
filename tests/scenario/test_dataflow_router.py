"""CPU request routing uses a declared target and exact beat lane semantics."""

from __future__ import annotations

import unittest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.ibex_session import IbexCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow


class _Device:
    def __init__(self) -> None:
        self.writes: list[tuple[int, int, int]] = []
        self.reads: list[int] = []

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self.writes.append((offset, value, be))

    def read_register(self, offset: int) -> int:
        self.reads.append(offset)
        return 0xa5


class DataflowRouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.device = _Device()
        self.router = DataflowRouter((DeviceWindow("gpio", 0x40000000,
                                                   0x1000, self.device),))
        self.ledger = TransactionLedger()

    def key(self, sequence: int) -> TransactionKey:
        return TransactionKey("exec", "case", "cpu", 0, "data", sequence)

    def test_32bit_write_is_delivered_once_to_real_target(self):
        first = self.router.transact(self.ledger, self.key(1), address=0x40000014,
                                     write=True, wdata=0xa5, be=15, beat_bytes=4)
        second = self.router.transact(self.ledger, self.key(1), address=0x40000014,
                                      write=True, wdata=0xa5, be=15, beat_bytes=4)
        self.assertEqual((0, 0), first)
        self.assertEqual(first, second)
        self.assertEqual([(0x14, 0xa5, 15)], self.device.writes)
        self.assertEqual(15, self.router.deliveries[0]["byte_enable"])

    def test_64bit_high_lane_read_and_write(self):
        self.assertEqual((0, 0), self.router.transact(
            self.ledger, self.key(1), address=0x40000014, write=True,
            wdata=0x1234567800000000, be=0xf0, beat_bytes=8))
        self.assertEqual([(0x14, 0x12345678, 15)], self.device.writes)
        self.assertEqual((0xa500000000, 0), self.router.transact(
            self.ledger, self.key(2), address=0x40000014, write=False,
            wdata=0, be=0xf0, beat_bytes=8))

    def test_invalid_spanning_write_never_reaches_target(self):
        with self.assertRaisesRegex(ValueError, "byte lanes"):
            self.router.transact(self.ledger, self.key(1), address=0x40000010,
                                 write=True, wdata=1, be=0xff, beat_bytes=8)
        self.assertEqual([], self.device.writes)

    def test_reordered_transport_cannot_change_real_target_write_order(self):
        args = {"address": 0x40000014, "write": True,
                "be": 15, "beat_bytes": 4}
        with self.assertRaisesRegex(ValueError, "out_of_order_transaction"):
            self.router.transact(self.ledger, self.key(2), wdata=2, **args)
        self.assertEqual([], self.device.writes)
        self.router.transact(self.ledger, self.key(1), wdata=1, **args)
        self.router.transact(self.ledger, self.key(2), wdata=2, **args)
        self.assertEqual([(0x14, 1, 15), (0x14, 2, 15)], self.device.writes)
        self.assertEqual([1, 2], [delivery["source_transaction"].source_sequence
                                  for delivery in self.router.deliveries])
        self.assertEqual([1, 2], [delivery["delivery_order"]
                                  for delivery in self.router.deliveries])
        self.assertEqual([1, 2], [delivery["target_delivery_order"]
                                  for delivery in self.router.deliveries])
        self.assertEqual([1, 2], [delivery["source_sequence"]
                                  for delivery in self.router.deliveries])
        self.router.transact(self.ledger, self.key(1), wdata=1, **args)
        self.assertEqual(2, len(self.router.deliveries))

    def test_target_delivery_order_is_per_device_and_transport_order_is_global(self):
        other = _Device()
        router = DataflowRouter((DeviceWindow("a", 0x40000000, 0x1000, self.device),
                                 DeviceWindow("b", 0x40001000, 0x1000, other)))
        for sequence, address in enumerate(
                (0x40000014, 0x40001014, 0x40000014), start=1):
            router.transact(self.ledger, self.key(sequence), address=address,
                            write=True, wdata=sequence, be=15, beat_bytes=4)
        self.assertEqual([1, 2, 3], [item["delivery_order"]
                                    for item in router.deliveries])
        self.assertEqual([1, 1, 2], [item["target_delivery_order"]
                                    for item in router.deliveries])
        self.assertEqual([1, 2, 3], [item["source_sequence"]
                                    for item in router.deliveries])
        self.assertEqual(["a", "b", "a"], [item["device_id"]
                                            for item in router.deliveries])

    def test_interleaved_source_channels_have_distinct_sequences_at_one_target(self):
        keys = (TransactionKey("exec", "case", "cpu", 0, "data", 1),
                TransactionKey("exec", "case", "cpu", 0, "debug", 1),
                TransactionKey("exec", "case", "cpu", 0, "data", 2))
        for index, key in enumerate(keys, start=1):
            self.router.transact(self.ledger, key, address=0x40000014,
                                 write=True, wdata=index, be=15, beat_bytes=4)
        self.assertEqual([1, 1, 2], [item["source_sequence"]
                                    for item in self.router.deliveries])
        self.assertEqual([1, 2, 3], [item["target_delivery_order"]
                                    for item in self.router.deliveries])
        self.assertEqual(["data", "debug", "data"], [
            item["source_transaction"].channel_id for item in self.router.deliveries])

    def test_queued_mmio_waits_for_target_step_and_freezes_real_readback(self):
        receipts = []
        args = {"address": 0x40000014, "write": False,
                "wdata": 0, "be": 15, "beat_bytes": 4}
        self.assertTrue(self.router.enqueue(
            self.ledger, self.key(1), callback=receipts.append, **args))
        self.assertFalse(self.router.enqueue(
            self.ledger, self.key(1), callback=receipts.append, **args))
        self.assertEqual(("gpio",), self.router.pending_targets)
        self.assertEqual([], self.device.reads)
        self.assertEqual([], receipts)
        self.assertTrue(self.router.drain_one("gpio"))
        self.assertEqual([0x14], self.device.reads)
        self.assertEqual([(0xa5, 0)], receipts)
        self.assertEqual((), self.router.pending_targets)
        self.assertFalse(self.router.drain_one("gpio"))
        self.assertEqual(1, len(self.router.deliveries))

    def test_queued_target_keeps_acceptance_order_across_source_channels(self):
        receipts = []
        first = self.key(1)
        second = TransactionKey("exec", "case", "cpu", 0, "debug", 1)
        for key, value in ((first, 1), (second, 2)):
            self.router.enqueue(
                self.ledger, key, address=0x40000014, write=True,
                wdata=value, be=15, beat_bytes=4,
                callback=lambda receipt, key=key: receipts.append((key, receipt)))
        self.assertEqual([], self.device.writes)
        self.assertTrue(self.router.drain_one("gpio"))
        self.assertEqual([(0x14, 1, 15)], self.device.writes)
        self.assertEqual(("gpio",), self.router.pending_targets)
        self.assertTrue(self.router.drain_one("gpio"))
        self.assertEqual([(0x14, 1, 15), (0x14, 2, 15)], self.device.writes)
        self.assertEqual([first, second], [item["source_transaction"]
                                           for item in self.router.deliveries])
        self.assertEqual([(first, (0, 0)), (second, (0, 0))], receipts)

    def test_reset_cancels_only_undelivered_source_requests(self):
        key = self.key(1)
        self.router.enqueue(
            self.ledger, key, address=0x40000014, write=True,
            wdata=7, be=15, beat_bytes=4, callback=lambda _receipt: None)
        self.assertEqual((key,), self.router.cancel_for_ledger(self.ledger))
        self.assertEqual((), self.router.pending_targets)
        self.assertEqual([], self.device.writes)
        self.assertEqual((), self.ledger.unresolved_keys)
        self.assertFalse(self.router.drain_one("gpio"))

    def test_invalid_deferred_cpu_request_does_not_leave_phantom_pending(self):
        memory = PersistentMemory(
            regions=(MemoryRegion("ram", 0, 0x1000),),
            initialization_seed=1, max_initialized_bytes=0x1000)
        cpu = IbexCpuSession(memory=memory, router=self.router,
                             defer_mmio=True)
        cpu._testcase_id = "bad-mmio-shape"
        with self.assertRaisesRegex(ValueError, "byte lanes"):
            cpu._serve("data", 1, 0x40000014, 7, 0)
        self.assertEqual(0, cpu.pending_responses)
        self.assertEqual((), self.router.pending_targets)
        self.assertEqual((), cpu.service.ledger.pending_keys)

    def test_target_failure_moves_queued_request_to_uncertain_without_retry(self):
        class FailingDevice(_Device):
            def write_register(self, offset, value, *, be=15):
                super().write_register(offset, value, be=be)
                raise RuntimeError("reply_lost_after_effect")

        device = FailingDevice()
        router = DataflowRouter((DeviceWindow(
            "gpio", 0x40000000, 0x1000, device),))
        key = self.key(1)
        router.enqueue(self.ledger, key, address=0x40000014, write=True,
                       wdata=7, be=15, beat_bytes=4,
                       callback=lambda _receipt: None)
        with self.assertRaisesRegex(RuntimeError, "reply_lost_after_effect"):
            router.drain_one("gpio")
        self.assertEqual([(0x14, 7, 15)], device.writes)
        self.assertEqual((), router.pending_targets)
        self.assertEqual((key,), self.ledger.uncertain_keys)
        self.assertFalse(router.drain_one("gpio"))
        self.assertEqual([(0x14, 7, 15)], device.writes)


if __name__ == "__main__":
    unittest.main()
