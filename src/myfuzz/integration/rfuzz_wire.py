"""Bounded RFuzz shared-buffer framing, independent of any DUT or CPU.

Wire constants follow ekiwi/rfuzz@651f28f1583e14a4aa9d8dfc624b700e6da3a143
fuzzer/src/run/buffered.rs (the C++ header's input-magic comment is stale).
Buffer integer fields are big-endian; FIFO shared-memory IDs are a separate
little-endian protocol and are not parsed here.
"""
from dataclasses import dataclass
import struct

INPUT_MAGIC = 0x19931993
COVERAGE_MAGIC = 0x73537353
MAX_BUFFER_BYTES = 1024 * 1024


def _positive(value, label, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"invalid {label}")
    return value


@dataclass(frozen=True, slots=True)
class InputBatch:
    buffer_id: int
    input_bytes: int
    tests: tuple[tuple[bytes, ...], ...]

    def __post_init__(self):
        if type(self.buffer_id) is not int or not 0 <= self.buffer_id <= 0xFFFFFFFF:
            raise ValueError("invalid buffer ID")
        _positive(self.input_bytes, "input bytes", MAX_BUFFER_BYTES)
        if self.input_bytes % 8 or not isinstance(self.tests, tuple) or not 1 <= len(self.tests) <= 65535:
            raise ValueError("invalid input batch")
        for cycles in self.tests:
            if not isinstance(cycles, tuple) or not 1 <= len(cycles) <= 65535:
                raise ValueError("invalid cycle count")
            if any(not isinstance(record, bytes) or len(record) != self.input_bytes for record in cycles):
                raise ValueError("invalid input record")


def parse_input_buffer(data: bytes, *, input_bytes: int, max_cycles: int = 200,
                       max_buffer_bytes: int = MAX_BUFFER_BYTES) -> InputBatch:
    _positive(input_bytes, "input bytes", MAX_BUFFER_BYTES)
    _positive(max_cycles, "max cycles", 65535)
    _positive(max_buffer_bytes, "buffer bound", MAX_BUFFER_BYTES)
    if input_bytes % 8 or not isinstance(data, bytes) or not 16 <= len(data) <= max_buffer_bytes:
        raise ValueError("invalid input buffer size or alignment")
    magic, buffer_id, count, r0, r1, r2 = struct.unpack_from(">IIHHHH", data)
    if magic != INPUT_MAGIC or count == 0 or (r0, r1, r2) != (0, 0, 0):
        raise ValueError("invalid input buffer header")
    offset, tests = 16, []
    for _ in range(count):
        if offset + 8 > len(data):
            raise ValueError("truncated test length")
        cycles = struct.unpack_from(">Q", data, offset)[0]
        offset += 8
        if not 1 <= cycles <= max_cycles:
            raise ValueError("test cycle count outside bound")
        end = offset + cycles * input_bytes
        if end > len(data):
            raise ValueError("truncated test input")
        tests.append(tuple(data[i:i + input_bytes] for i in range(offset, end, input_bytes)))
        offset = end
    return InputBatch(buffer_id, input_bytes, tuple(tests))


def encode_coverage_buffer(batch: InputBatch, coverages: tuple[bytes, ...], *,
                           counter_count: int, capacity: int | None = None) -> bytes:
    if not isinstance(batch, InputBatch):
        raise ValueError("coverage requires a validated input batch")
    _positive(counter_count, "counter count", 4096)
    if not isinstance(coverages, tuple) or len(coverages) != len(batch.tests):
        raise ValueError("coverage test count mismatch")
    if any(not isinstance(record, bytes) or len(record) != counter_count for record in coverages):
        raise ValueError("coverage counter count mismatch")
    # Two-byte executed-cycle prefix is included in the aligned record stride.
    stride = ((counter_count + 2 + 7) // 8) * 8
    minimum = 16 + stride * len(coverages)  # header8 + footer8
    capacity = minimum if capacity is None else capacity
    _positive(capacity, "coverage capacity", MAX_BUFFER_BYTES)
    if capacity < minimum or capacity % 8:
        raise ValueError("coverage buffer too small or unaligned")
    output = bytearray(capacity)
    struct.pack_into(">II", output, 0, COVERAGE_MAGIC, batch.buffer_id)
    for index, (inputs, coverage) in enumerate(zip(batch.tests, coverages)):
        offset = 8 + index * stride
        struct.pack_into(">H", output, offset, len(inputs))
        output[offset + 2:offset + 2 + counter_count] = coverage
    return bytes(output)
