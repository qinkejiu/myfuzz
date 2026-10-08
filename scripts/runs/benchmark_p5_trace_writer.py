"""Controlled P5 saved-trace prefix comparator for the zlib writer."""

import gc
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import time
import zlib

from myfuzz.scenario.event_journal import EventJournal, write_zlib_chunk_events

source = Path("runs/p5-runner-zlib-600s-20261007/online/online_events.zlib")
header = struct.Struct("<IIII")
journal = EventJournal(chunk_size=2048)
original = bytearray(b"MFZ1")
with source.open("rb") as handle:
    assert handle.read(4) == b"MFZ1"
    for block in range(512):
        packed = handle.read(header.size)
        compressed_size, raw_size, event_count, crc = header.unpack(packed)
        compressed = handle.read(compressed_size)
        raw = zlib.decompress(compressed)
        assert len(raw) == raw_size and zlib.crc32(raw) == crc
        events = [json.loads(line) for line in raw.splitlines()]
        assert len(events) == event_count
        for event in events:
            journal.append(event)
        original.extend(packed)
        original.extend(compressed)
snapshot = journal.snapshot()
metadata = json.loads((source.parent / "online_final_trace.meta.json").read_bytes())
print("fixture_events", len(snapshot), "fixture_bytes", len(original),
      "original_sha256", hashlib.sha256(original).hexdigest(), flush=True)

with tempfile.TemporaryDirectory(prefix="p5-trace-writer-bench-") as directory:
    results = []
    for mode in ("copy", "borrow", "borrow", "copy", "copy", "borrow"):
        gc.collect()
        path = Path(directory) / f"{mode}.zlib"
        semantic = hashlib.sha256(b'{"events":[')
        started = time.perf_counter()
        count = write_zlib_chunk_events(path,
            iter(snapshot) if mode == "copy" else snapshot,
            chunk_events=256, semantic_digest=semantic)
        semantic.update(b'],"local_ticks":')
        semantic.update(json.dumps(metadata["local_ticks"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8"))
        semantic.update(b',"status":')
        semantic.update(json.dumps(metadata["status"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8"))
        semantic.update(b"}")
        seconds = time.perf_counter() - started
        output = path.read_bytes()
        assert count == len(snapshot) and output == original
        result = (mode, round(seconds, 6), hashlib.sha256(output).hexdigest(),
                  semantic.hexdigest())
        results.append(result)
        print(*result, flush=True)
    assert len({row[2:] for row in results}) == 1
journal.close()
