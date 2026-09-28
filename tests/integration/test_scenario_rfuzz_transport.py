"""Scenario mode keeps RFuzz FIFO/shared-memory buffer framing unchanged."""

import ctypes
import os
import struct
import unittest

from myfuzz.integration.rfuzz_shmem import OwnedSegment
from myfuzz.integration.rfuzz_wire import INPUT_MAGIC, COVERAGE_MAGIC
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor


class TransportTests(unittest.TestCase):
    def test_owned_sysv_pair_transports_one_whole_genome_test(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        input_id = libc.shmget(0, 128, 0o600)
        output_id = libc.shmget(0, 128, 0o600)
        self.assertGreaterEqual(input_id, 0)
        self.assertGreaterEqual(output_id, 0)
        try:
            with OwnedSegment(input_id, creator_pid=os.getpid(),
                              writable=True) as segment:
                raw = struct.pack(">IIHHHHQ", INPUT_MAGIC, 19, 1, 0, 0, 0, 2)
                raw += bytes(8) + bytes((0, 0, 0, 0, 0, 1, 0, 0))
                segment.write(raw + bytes(128 - len(raw)))

            class Stub:
                counter_count = 1
                decoder = type("Decoder", (), {"max_records": 200})()
                observed = None

                def execute_batch(self, batch):
                    self.observed = batch
                    return (b"\x01",)

            stub = Stub()
            reply = ScenarioRfuzzExecutor.process_owned_pair(
                stub, input_id, output_id, creator_pid=os.getpid())
            self.assertEqual((output_id, input_id), reply)
            self.assertEqual(2, len(stub.observed.tests[0]))
            with OwnedSegment(output_id, creator_pid=os.getpid()) as segment:
                self.assertEqual(struct.pack(">IIHB", COVERAGE_MAGIC, 19, 2, 1),
                                 segment.read()[:11])
        finally:
            libc.shmctl(input_id, 0, None)
            libc.shmctl(output_id, 0, None)


if __name__ == "__main__":
    unittest.main()
