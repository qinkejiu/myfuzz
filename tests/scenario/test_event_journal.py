"""Indexed online event storage keeps the old ordered evidence semantics."""

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import struct
import zlib

from myfuzz.scenario.event_journal import (
    EventJournal, JsonlEventView, ZlibChunkEventView, canonical_json_chunks,
)
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.session_runtime import _trace_semantic_sha256, _canonical


class SerializableWithoutDeepcopy(dict):
    def __deepcopy__(self, memo):
        raise AssertionError("compressed writer copied an event")


class EventJournalTests(unittest.TestCase):
    def test_compressed_writer_uses_snapshot_prefix_without_detached_copies(self):
        from myfuzz.scenario.event_journal import write_zlib_chunk_events

        journal = EventJournal(chunk_size=2)
        try:
            journal.append(SerializableWithoutDeepcopy(event_id=1, value="雪"))
            journal.append(SerializableWithoutDeepcopy(event_id=2, value=[1, 2]))
            snapshot = journal.snapshot()
            journal.append({"event_id": 3})
            with TemporaryDirectory() as directory:
                path = Path(directory) / "events.zlib"
                count = write_zlib_chunk_events(path, snapshot, chunk_events=1)
                self.assertEqual(2, count)
                self.assertEqual([{"event_id": 1, "value": "雪"},
                                  {"event_id": 2, "value": [1, 2]}],
                                 list(ZlibChunkEventView(path, count)))
                reference = Path(directory) / "reference.zlib"
                write_zlib_chunk_events(reference,
                    [{"event_id": 1, "value": "雪"},
                     {"event_id": 2, "value": [1, 2]}], chunk_events=1)
                self.assertEqual(reference.read_bytes(), path.read_bytes())
        finally:
            journal.close()

    def test_compressed_reader_accepts_noncanonical_json_with_same_semantics(self):
        events = [{"event_id": 1, "value": "雪"}]
        raw = b'{ "value": "\\u96ea", "event_id": 1 }\n'
        compressed = zlib.compress(raw)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.zlib"
            path.write_bytes(b"MFZ1" + struct.pack("<IIII", len(compressed),
                len(raw), 1, zlib.crc32(raw)) + compressed)
            view = ZlibChunkEventView(path, 1)
            semantic = sha256(_canonical({"events": events, "local_ticks": {},
                                           "status": "complete"})).hexdigest()
            view.verify_trace_semantic(status="complete", local_ticks={},
                                       expected_sha256=semantic)
            self.assertEqual(events, list(view))
            with self.assertRaisesRegex(ValueError, "semantic SHA"):
                view.verify_trace_semantic(status="complete", local_ticks={},
                                           expected_sha256="0" * 64)

    def test_compressed_reader_rejects_raw_digest_forged_for_noncanonical_json(self):
        raw = b'{ "event_id": 1 }\n'
        compressed = zlib.compress(raw)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.zlib"
            path.write_bytes(b"MFZ1" + struct.pack("<IIII", len(compressed),
                len(raw), 1, zlib.crc32(raw)) + compressed)
            view = ZlibChunkEventView(path, 1)
            forged = sha256(b'{"events":[' + raw[:-1] +
                            b'],"local_ticks":{},"status":"complete"}').hexdigest()
            with self.assertRaisesRegex(ValueError, "semantic SHA"):
                view.verify_trace_semantic(status="complete", local_ticks={},
                                           expected_sha256=forged)

    def test_compressed_reader_supports_random_access_and_rejects_corruption(self):
        from myfuzz.scenario.event_journal import write_zlib_chunk_events
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.zlib"
            events = [{"event_id": index, "value": "雪" * 8}
                      for index in range(7)]
            write_zlib_chunk_events(path, events, chunk_events=2)
            view = ZlibChunkEventView(path, len(events))
            self.assertEqual(events, list(view))
            self.assertEqual(events[-1], view[-1])
            self.assertEqual(tuple(events[1:4]), view[1:4])
            with self.assertRaisesRegex(ValueError, "semantic SHA"):
                view.verify_trace_semantic(status="complete", local_ticks={},
                                           expected_sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "count mismatch"):
                ZlibChunkEventView(path, len(events) + 1)
            original = path.read_bytes()
            for damaged in (original[:-1], original + b"x",
                            original[:24] + bytes([original[24] ^ 1]) + original[25:]):
                path.write_bytes(damaged)
                with self.assertRaises(ValueError):
                    ZlibChunkEventView(path, len(events))
            path.write_bytes(original[:4] + (2**31).to_bytes(4, "little")
                             + original[8:])
            with self.assertRaisesRegex(ValueError, "block size"):
                ZlibChunkEventView(path, len(events))

    def test_spilled_chunks_keep_order_slices_and_detached_snapshot(self):
        journal = EventJournal(chunk_size=2)
        try:
            originals = [{"event_id": index + 1, "value": [index]}
                         for index in range(7)]
            for event in originals:
                journal.append(event)
            snapshot = journal.snapshot()
            self.assertEqual(originals, list(snapshot))
            self.assertEqual(originals[2:6], journal[2:6])
            self.assertEqual(originals[-1], journal[-1])
            self.assertEqual(tuple(originals), snapshot)
            detached = snapshot[0]
            detached["value"].append(99)
            self.assertEqual([0], snapshot[0]["value"])
            journal.append({"event_id": 8})
            self.assertEqual(7, len(snapshot))
            self.assertEqual(originals, list(snapshot))
        finally:
            journal.close()

    def test_streaming_trace_bytes_and_semantic_hash_match_legacy_json(self):
        journal = EventJournal(chunk_size=2)
        try:
            for index in range(5):
                journal.append({"event_id": index + 1,
                                "message": "数据", "tuple": (index, index + 1)})
            snapshot = journal.snapshot()
            trace = ScenarioTrace("genome", "complete", snapshot,
                                  {"cpu": 17}, "semantic", "manifest")
            expected = json.dumps(asdict(ScenarioTrace(
                "genome", "complete", tuple(snapshot), {"cpu": 17},
                "semantic", "manifest")), sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False)
            self.assertEqual(expected, "".join(canonical_json_chunks(trace)))
            semantic = _trace_semantic_sha256("complete", snapshot, {"cpu": 17})
            plain = _canonical({"events": tuple(snapshot),
                                "local_ticks": {"cpu": 17},
                                "status": "complete"})
            import hashlib
            self.assertEqual(hashlib.sha256(plain).hexdigest(), semantic)
        finally:
            journal.close()

    def test_jsonl_reader_indexes_and_rejects_truncated_count(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            events = [{"event_id": 1}, {"event_id": 2}, {"event_id": 3}]
            path.write_text("".join(json.dumps(event) + "\n" for event in events),
                            encoding="utf-8")
            view = JsonlEventView(path, 3)
            self.assertEqual(events, list(view))
            self.assertEqual(events[1], view[1])
            self.assertEqual(tuple(events[1:]), view[1:])
            with self.assertRaisesRegex(ValueError, "count mismatch"):
                JsonlEventView(path, 4)


if __name__ == "__main__":
    unittest.main()
