"""Exact upstream RFuzz buffer headers and finite aligned records."""
import struct
import unittest

from myfuzz.integration import rfuzz_wire


class RfuzzWireTests(unittest.TestCase):
    def buffer(self, tests=(b"\x80" + b"\0" * 7,), *, width=8):
        return struct.pack(">IIHHHH", 0x19931993, 42, len(tests), 0, 0, 0) + b"".join(
            struct.pack(">Q", len(test) // width) + test for test in tests)

    def test_input_magic_big_endian_and_multiple_tests(self):
        first, second = bytes(range(16)), b"\xff" * 8
        batch = rfuzz_wire.parse_input_buffer(self.buffer((first, second)), input_bytes=8)
        self.assertEqual(batch.buffer_id, 42)
        self.assertEqual(batch.tests, ((first[:8], first[8:]), (second,)))
        # Shared memory capacity may exceed the used request length.
        padded = rfuzz_wire.parse_input_buffer(self.buffer((first, second)) + b"\xaa" * 128, input_bytes=8)
        self.assertEqual(padded, batch)

    def test_wrong_headers_and_truncated_records_rejected(self):
        good = self.buffer()
        invalid = [b"", good[:15], good[:-1], b"BAD!" + good[4:],
                   good[:8] + b"\0\0" + good[10:], good[:10] + b"\0\1" + good[12:],
                   good[:16] + struct.pack(">Q", 0), good[:16] + struct.pack(">Q", 201)]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                rfuzz_wire.parse_input_buffer(raw, input_bytes=8)

    def test_explicit_buffer_and_cycle_bounds(self):
        for width in (0, 7, True):
            with self.subTest(width=width), self.assertRaises(ValueError):
                rfuzz_wire.parse_input_buffer(self.buffer(), input_bytes=width)
        with self.assertRaises(ValueError):
            rfuzz_wire.parse_input_buffer(self.buffer(), input_bytes=8, max_buffer_bytes=16)
        with self.assertRaises(ValueError):
            rfuzz_wire.parse_input_buffer(self.buffer((b"\0" * 16,)), input_bytes=8, max_cycles=1)

    def test_coverage_header_cycle_prefix_stride_and_footer(self):
        batch = rfuzz_wire.parse_input_buffer(self.buffer((b"\0" * 16, b"\0" * 8)), input_bytes=8)
        result = rfuzz_wire.encode_coverage_buffer(batch, (b"\x01\x02\xff", b"\x03\x04\x05"), counter_count=3)
        expected = (struct.pack(">II", 0x73537353, 42) +
                    b"\0\2\1\2\xff\0\0\0" + b"\0\1\3\4\5\0\0\0" + b"\0" * 8)
        self.assertEqual(result, expected)
        capacity = rfuzz_wire.encode_coverage_buffer(batch, (b"\x01\x02\xff", b"\x03\x04\x05"), counter_count=3, capacity=64)
        self.assertEqual(len(capacity), 64)
        self.assertEqual(capacity[:24], expected[:24])
        self.assertEqual(capacity[24:], b"\0" * 40)

    def test_wrong_coverage_shape_or_capacity_rejected(self):
        batch = rfuzz_wire.parse_input_buffer(self.buffer(), input_bytes=8)
        for coverage, count, capacity in (((), 1, None), ((b"\0\0",), 1, None), ((b"\0",), 1, 16), ((b"\0",), 0, None)):
            with self.subTest(count=count, capacity=capacity), self.assertRaises(ValueError):
                rfuzz_wire.encode_coverage_buffer(batch, coverage, counter_count=count, capacity=capacity)
