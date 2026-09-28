"""G1 memory checks with explicit fault-injection calibration.

The injected branches are test-only mutants.  Each oracle is run against the
mutant first, then against the production memory/service implementation.
"""

import hashlib
import unittest

from myfuzz.scenario.genome import ChunkAssembler, GenomeCodec, ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ADDRESS = 0x80000040


def make_service():
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0x80000000, 0x1000,
                              aliases=(0x90000000,)),),
        initialization_seed=7, max_initialized_bytes=64)
    return memory, MemoryService(memory, TransactionLedger())


def key(sequence):
    return TransactionKey("run-1", "case-1", "cpu", 0, "data", sequence)


class _MemoryStepSession:
    def __init__(self, memory, service):
        self.memory = memory
        self.service = service
        self.begins = 0
        self.steps = 0
        self.response = None

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        self.steps += 1
        if self.steps == 1:
            self.service.write(key(1), ADDRESS, 0x11223344,
                               width_bytes=4, byte_enable=15)
        if self.steps == 66:
            self.response = self.service.read(key(2), 0x90000040,
                                              width_bytes=4)
        self.memory.advance_step()
        return {"load": self.response.value if self.response else 0}

    def end_case(self):
        pass


class MemoryCalibrationTests(unittest.TestCase):
    def _store_wait_load(self, *, reset_at_chunk_boundary):
        """Three host calls encompass 66 local steps and one testcase."""
        memory, service = make_service()
        genome = ScenarioGenome("case-1", "CPU_TO_IP", "memory-retention",
                                ("cpu",), 66, ())
        raw = GenomeCodec.encode(genome)
        chunks = [raw[:17], raw[17:49], raw[49:]]
        assembler = ChunkAssembler(len(raw), hashlib.sha256(raw).hexdigest())
        for offset, chunk in zip((0, 17, 49), chunks):
            assembler.accept(offset, chunk)
        self.assertEqual(genome, assembler.finish())
        session = _MemoryStepSession(memory, service)
        runner = ScenarioRunner(sessions={"cpu": session},
                                ownership=compile_ownership((), ()), bindings=())
        runner.begin_test("case-1")
        resets = []
        # Three real host API calls; none starts a new testcase.
        for host_call, steps in enumerate((21, 22, 23), start=1):
            if reset_at_chunk_boundary and host_call > 1:
                memory.cold_reset()  # injection: reconstruct storage per chunk
                resets.append(host_call)
            runner.step_batch(("cpu",) * steps)
        result = (memory, service, session.response, session.begins, resets,
                  runner.events, runner.local_ticks["cpu"])
        runner.finalize()
        return result

    def _assert_store_wait_load(self, result):
        memory, service, response, begins, resets, events, local_ticks = result
        self.assertEqual(1, begins)
        self.assertEqual(66, memory.step_count)
        self.assertEqual(66, local_ticks)
        self.assertEqual(0x11223344, response.value)
        self.assertEqual((str(key(1)),) * 4, response.writer_event_ids)
        self.assertEqual(0, memory.generation)
        self.assertEqual([], resets)
        self.assertEqual(["memory_write", "memory_read"],
                         [event["kind"] for event in service.events])
        self.assertEqual(response.versions,
                         tuple(service.events[-1]["versions"]))
        self.assertFalse(any(event.get("kind") == "reset_barrier" for event in events))

    def test_mem01_three_host_calls_and_chunk_reconstruction_fault(self):
        with self.assertRaises(AssertionError, msg="MEM-01 injection not detected"):
            self._assert_store_wait_load(
                self._store_wait_load(reset_at_chunk_boundary=True))
        self._assert_store_wait_load(
            self._store_wait_load(reset_at_chunk_boundary=False))

    def _first_read_then_overlaps(self, *, reinitialize_each_read):
        memory, service = make_service()
        original_read = memory.read
        original_initial_byte = memory._initial_byte
        rng_calls = 0

        def faulty_initial_byte(memory_id, offset):
            nonlocal rng_calls
            rng_calls += 1
            return original_initial_byte(memory_id, offset) ^ (rng_calls & 0xFF)

        def faulty_read(address, width_bytes, *, transaction_id):
            # injection: discard old materialization and draw new bytes on read
            region, offset = memory._resolve(address, width_bytes, write=False)
            for lane in range(width_bytes):
                memory._bytes.pop((region.memory_id, offset + lane), None)
            return original_read(address, width_bytes,
                                 transaction_id=transaction_id)

        if reinitialize_each_read:
            memory.read = faulty_read
            memory._initial_byte = faulty_initial_byte
        first = service.read(key(1), ADDRESS, width_bytes=4)
        for _ in range(64):
            memory.advance_step()
        repeated = service.read(key(2), ADDRESS, width_bytes=4)
        overlapping = service.read(key(3), ADDRESS + 2, width_bytes=2)
        return service, first, repeated, overlapping

    def _assert_materialized_once(self, result):
        service, first, repeated, overlapping = result
        initializations = [event for event in service.events
                           if event["kind"] == "memory_initialization"]
        self.assertEqual([0x40, 0x41, 0x42, 0x43],
                         [event["byte_offset"] for event in initializations])
        self.assertEqual(first.data, repeated.data)
        self.assertEqual(first.versions, repeated.versions)
        self.assertEqual(first.writer_event_ids, repeated.writer_event_ids)
        self.assertEqual(first.data[2:], overlapping.data)
        self.assertEqual(first.versions[2:], overlapping.versions)

    def test_mem02_repeated_and_overlapping_read_reinit_fault(self):
        with self.assertRaises(AssertionError, msg="MEM-02 injection not detected"):
            self._assert_materialized_once(
                self._first_read_then_overlaps(reinitialize_each_read=True))
        self._assert_materialized_once(
            self._first_read_then_overlaps(reinitialize_each_read=False))

    def _byte_enable_matrix(self, fault):
        for mask in range(16):
            memory, service = make_service()
            memory.preload(ADDRESS, bytes.fromhex("44332211"))
            original_write = memory.write

            def faulty_write(address, value, *, width_bytes,
                             byte_enable, writer_event_id):
                if fault == "endian":
                    value = int.from_bytes(value.to_bytes(4, "little"), "big")
                elif fault == "mask_shift":
                    byte_enable = (byte_enable << 1) & 15
                elif fault == "whole_word":
                    byte_enable = 15 if byte_enable else 0
                return original_write(address, value, width_bytes=width_bytes,
                                      byte_enable=byte_enable,
                                      writer_event_id=writer_event_id)

            if fault:
                memory.write = faulty_write
            before = memory.read(ADDRESS, 4, transaction_id="before")
            service.write(key(1), ADDRESS, 0xAABBCCDD,
                          width_bytes=4, byte_enable=mask)
            after = service.read(key(2), ADDRESS, width_bytes=4)
            original = bytes.fromhex("44332211")
            replacement = bytes.fromhex("ddccbbaa")
            expected = bytes(replacement[lane] if mask & (1 << lane)
                             else original[lane] for lane in range(4))
            self.assertEqual(expected, after.data, f"mask={mask:04b}")
            if mask == 0b0101:
                self.assertEqual(0x11BB33DD, after.value)
            for lane in range(4):
                if mask & (1 << lane):
                    self.assertEqual(str(key(1)), after.writer_event_ids[lane])
                    self.assertNotEqual(before.versions[lane],
                                        after.versions[lane])
                else:
                    self.assertEqual(before.writer_event_ids[lane],
                                     after.writer_event_ids[lane])
                    self.assertEqual(before.versions[lane],
                                     after.versions[lane])
            self.assertEqual((None if mask == 0 else after.versions[next(
                lane for lane in range(4) if mask & (1 << lane))]),
                service.events[0]["version"])

    def test_mem04_all_masks_detect_endian_shift_and_whole_word_faults(self):
        for injection_id in ("endian", "mask_shift", "whole_word"):
            with self.subTest(injection_id=injection_id):
                with self.assertRaises(AssertionError,
                                       msg=f"MEM-04 {injection_id} not detected"):
                    self._byte_enable_matrix(injection_id)
        self._byte_enable_matrix(None)

    def _delayed_delivery(self, *, reread_at_delivery):
        memory, service = make_service()
        service.write(key(1), ADDRESS, 0x11223344,
                      width_bytes=4, byte_enable=15)
        frozen = service.read(key(2), ADDRESS, width_bytes=4)
        service.write(key(3), ADDRESS, 0x55667788,
                      width_bytes=4, byte_enable=15)
        delivered = (service.read(key(4), ADDRESS, width_bytes=4)
                     if reread_at_delivery else frozen)
        later = service.read(key(5 if reread_at_delivery else 4),
                             ADDRESS, width_bytes=4)
        return frozen, delivered, later, service

    def _assert_frozen_delivery(self, result):
        frozen, delivered, later, service = result
        self.assertIs(frozen, delivered)
        self.assertEqual(0x11223344, delivered.value)
        self.assertEqual((str(key(1)),) * 4, delivered.writer_event_ids)
        self.assertEqual(0x55667788, later.value)
        self.assertEqual((str(key(3)),) * 4, later.writer_event_ids)
        self.assertEqual(["memory_write", "memory_read", "memory_write",
                          "memory_read"],
                         [event["kind"] for event in service.events])

    def test_mem09_delivery_reread_fault_is_detected(self):
        with self.assertRaises(AssertionError, msg="MEM-09 injection not detected"):
            self._assert_frozen_delivery(
                self._delayed_delivery(reread_at_delivery=True))
        self._assert_frozen_delivery(
            self._delayed_delivery(reread_at_delivery=False))


if __name__ == "__main__":
    unittest.main()
