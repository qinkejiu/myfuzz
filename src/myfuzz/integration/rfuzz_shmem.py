"""Linux RFuzz buffer attachment restricted to the launched client's segments.

This is an IPC correctness boundary, not a sandbox against a malicious process
running as the same user. Callers must supply their owned child PID, never an ID
obtained from untrusted FIFO contents. Attachments do not remove segments.
"""
import ctypes
import os
from pathlib import Path
from .rfuzz_wire import MAX_BUFFER_BYTES, parse_input_buffer, encode_coverage_buffer


def _metadata(segment_id, creator_pid):
    if type(segment_id) is not int or not 0 <= segment_id <= 0x7fffffff:
        raise ValueError("invalid shared-memory ID")
    if type(creator_pid) is not int or creator_pid <= 0:
        raise ValueError("invalid owned client PID")
    rows = Path("/proc/sysvipc/shm").read_text().splitlines()
    columns = rows[0].split()
    for row in rows[1:]:
        values = dict(zip(columns, row.split()))
        if int(values["shmid"]) == segment_id:
            if any(int(values[key]) != expected for key, expected in (
                    ("cpid", creator_pid), ("uid", os.getuid()), ("cuid", os.getuid()))):
                raise ValueError("shared-memory segment is not owned by client")
            size = int(values["size"])
            if not 16 <= size <= MAX_BUFFER_BYTES or size % 8:
                raise ValueError("shared-memory size outside wire bounds")
            return size
    raise ValueError("shared-memory segment does not exist")


class OwnedSegment:
    def __init__(self, segment_id, *, creator_pid, writable=False):
        self.size = _metadata(segment_id, creator_pid)
        self.writable = writable
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        self.libc.shmat.restype = ctypes.c_void_p
        self.libc.shmdt.argtypes = [ctypes.c_void_p]
        self.libc.shmdt.restype = ctypes.c_int
        self.address = self.libc.shmat(segment_id, None, 0 if writable else 0o10000)
        if self.address == ctypes.c_void_p(-1).value:
            self.address = None
            raise OSError(ctypes.get_errno(), "shmat failed")
        try:
            if _metadata(segment_id, creator_pid) != self.size:
                raise ValueError("shared-memory identity changed during attachment")
        except BaseException:
            self.close()
            raise

    def read(self):
        if self.address is None:
            raise ValueError("closed shared-memory attachment")
        return ctypes.string_at(self.address, self.size)

    def write(self, data):
        if self.address is None or not self.writable:
            raise ValueError("shared-memory attachment is not writable")
        if not isinstance(data, bytes) or len(data) != self.size:
            raise ValueError("shared-memory write must match capacity")
        ctypes.memmove(self.address, data, self.size)

    def close(self):
        if self.address is not None:
            address, self.address = self.address, None
            if self.libc.shmdt(address) != 0:
                raise OSError(ctypes.get_errno(), "shmdt failed")

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()


def process_pair(input_id, coverage_id, *, creator_pid, input_bytes,
                 counter_count, execute, max_cycles=200):
    if input_id == coverage_id:
        raise ValueError("input and coverage shared-memory IDs alias")
    if type(counter_count) is not int or not 1 <= counter_count <= 4096:
        raise ValueError("invalid counter count")
    with OwnedSegment(input_id, creator_pid=creator_pid) as inputs, \
            OwnedSegment(coverage_id, creator_pid=creator_pid, writable=True) as outputs:
        batch = parse_input_buffer(inputs.read(), input_bytes=input_bytes, max_cycles=max_cycles)
        # Validate output capacity before executing any DUT cycles.
        stride = ((counter_count + 9) // 8) * 8
        if 16 + stride * len(batch.tests) > outputs.size:
            raise ValueError("coverage capacity or counter count invalid")
        coverages = tuple(execute(test) for test in batch.tests)
        outputs.write(encode_coverage_buffer(batch, coverages,
            counter_count=counter_count, capacity=outputs.size))
    return coverage_id, input_id
