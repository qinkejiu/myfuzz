import ctypes
import os
import struct
import unittest
from myfuzz.integration.rfuzz_wire import INPUT_MAGIC, COVERAGE_MAGIC
from myfuzz.integration import rfuzz_shmem


class SharedMemoryTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(rfuzz_shmem, "owned shared-memory transport missing")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        self.ids = []

    def tearDown(self):
        for segment in getattr(self, "ids", ()):
            self.libc.shmctl(segment, 0, None)

    def allocate(self, size=128):
        result = self.libc.shmget(0, size, 0o600)
        self.assertGreaterEqual(result, 0)
        self.ids.append(result)
        return result

    def test_real_owned_segments_roundtrip_and_coverage_tail(self):
        input_id, output_id = self.allocate(), self.allocate()
        with rfuzz_shmem.OwnedSegment(input_id, creator_pid=os.getpid(), writable=True) as segment:
            raw = struct.pack(">IIHHHHQQ", INPUT_MAGIC, 7, 1, 0, 0, 0, 1, 42)
            segment.write(raw + bytes(128-len(raw)))
        seen = []
        def execute(records):
            seen.append(records)
            return b"\3\5"
        result = rfuzz_shmem.process_pair(input_id, output_id, creator_pid=os.getpid(),
            input_bytes=8, counter_count=2, execute=execute)
        self.assertEqual(result, (output_id, input_id))
        self.assertEqual(seen, [(struct.pack(">Q",42),)])
        with rfuzz_shmem.OwnedSegment(output_id, creator_pid=os.getpid()) as segment:
            output = segment.read()
            self.assertEqual(output[:12], struct.pack(">IIHBB", COVERAGE_MAGIC,7,1,3,5))
            self.assertEqual(output[-8:], bytes(8))
            with self.assertRaises(ValueError):
                segment.write(bytes(128))
        with self.assertRaises(ValueError):
            segment.read()

    def test_foreign_creator_bounds_and_alias_rejected_without_removal(self):
        segment_id = self.allocate()
        for identity in (-1, True, 1<<40):
            with self.assertRaises(ValueError):
                rfuzz_shmem.OwnedSegment(identity, creator_pid=os.getpid())
        with self.assertRaises(ValueError):
            rfuzz_shmem.OwnedSegment(segment_id, creator_pid=os.getpid()+100000)
        with rfuzz_shmem.OwnedSegment(segment_id, creator_pid=os.getpid(), writable=True) as segment:
            with self.assertRaises(ValueError):
                segment.write(bytes(129))
        with self.assertRaises(ValueError):
            rfuzz_shmem.process_pair(segment_id,segment_id,creator_pid=os.getpid(),
                input_bytes=8,counter_count=1,execute=lambda _: b"\0")
        with rfuzz_shmem.OwnedSegment(segment_id, creator_pid=os.getpid()) as segment:
            self.assertEqual(len(segment.read()), 128)

    def test_invalid_counter_type_is_rejected_before_execution(self):
        input_id, output_id = self.allocate(), self.allocate()
        with rfuzz_shmem.OwnedSegment(input_id, creator_pid=os.getpid(), writable=True) as segment:
            raw = struct.pack(">IIHHHHQQ", INPUT_MAGIC, 1, 1, 0, 0, 0, 1, 0)
            segment.write(raw + bytes(128-len(raw)))
        for count in (None, "1", True, 0, 4097):
            with self.subTest(count=count), self.assertRaises(ValueError):
                rfuzz_shmem.process_pair(input_id,output_id,creator_pid=os.getpid(),input_bytes=8,
                    counter_count=count,execute=lambda _: self.fail("invalid request executed"))
