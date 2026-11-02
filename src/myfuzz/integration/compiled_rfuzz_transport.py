"""Bounded wire and owned shared-memory exchange shared by compiled routes."""
from .rfuzz_shmem import OwnedSegment
from .rfuzz_wire import InputBatch, parse_input_buffer, encode_coverage_buffer

WIRE_RECORD_BYTES = 8
WIRE_MAX_CYCLES = 200


def parse_compiled_input_buffer(data) -> InputBatch:
    return parse_input_buffer(data, input_bytes=WIRE_RECORD_BYTES,
                              max_cycles=WIRE_MAX_CYCLES)


def process_compiled_owned_pair(executor, input_id, coverage_id, *, creator_pid,
                                on_receipt=None) -> tuple[int, int]:
    if input_id == coverage_id:
        raise ValueError('input and coverage shared-memory IDs alias')
    with OwnedSegment(input_id, creator_pid=creator_pid) as inputs, \
            OwnedSegment(coverage_id, creator_pid=creator_pid, writable=True) as outputs:
        batch = parse_compiled_input_buffer(inputs.read())
        stride = ((executor.counter_count + 2 + 7) // 8) * 8
        if 16 + stride * len(batch.tests) > outputs.size:
            raise ValueError('RFuzz coverage capacity is insufficient')
        coverages = executor.execute_batch(batch, on_receipt=on_receipt)
        outputs.write(encode_coverage_buffer(batch, coverages,
            counter_count=executor.counter_count, capacity=outputs.size))
    return coverage_id, input_id
