"""Large online traces preserve canonical semantics while writing JSONL."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.scenario_rfuzz_live import (_write_online_trace_jsonl,
                                                       _write_online_trace_zlib)
from myfuzz.scenario.event_journal import ZlibChunkEventView
from myfuzz.scenario.replay import ScenarioTrace


class JsonlSemanticStreamTests(unittest.TestCase):
    def test_compressed_stream_keeps_full_canonical_semantics(self):
        events = tuple({"event_id": index, "payload": "雪" * 10}
                       for index in range(9))
        ticks = {"uart": 9}
        trace = ScenarioTrace("genome", "complete", events, ticks, "", "manifest")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            completed = _write_online_trace_zlib(root, trace, chunk_events=2)
            metadata = json.loads((root / "online_final_trace.meta.json").read_bytes())
            saved = list(ZlibChunkEventView(root / "online_events.zlib", 9))
            (root / "plain").mkdir()
            plain = _write_online_trace_jsonl(root / "plain", trace)
        self.assertEqual(list(events), saved)
        self.assertEqual("online_trace_zlib_chunks.v1", metadata["schema_version"])
        self.assertEqual("online_events.zlib", metadata["events_file"])
        self.assertEqual(plain.semantic_sha256, completed.semantic_sha256)

    def test_streamed_sha_matches_exact_canonical_trace_payload(self):
        events = ({"event_id": 1, "value": "雪", "nested": {"z": 2, "a": 1}},
                  {"event_id": 2, "value": None, "list": [True, -3]})
        ticks = {"uart": 3, "gpio": 2}
        payload = {"status": "complete", "events": events, "local_ticks": ticks}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        expected = hashlib.sha256(canonical).hexdigest()
        trace = ScenarioTrace("genome", "complete", events, ticks, "", "manifest")
        with tempfile.TemporaryDirectory() as directory:
            completed = _write_online_trace_jsonl(Path(directory), trace)
            metadata = json.loads((Path(directory) / "online_final_trace.meta.json").read_bytes())
            saved = [json.loads(line) for line in
                     (Path(directory) / "online_events.jsonl").read_text().splitlines()]
        self.assertEqual(expected, completed.semantic_sha256)
        self.assertEqual(expected, metadata["semantic_sha256"])
        self.assertEqual(list(events), saved)
        self.assertEqual("", trace.semantic_sha256)

    def test_writer_rejects_mismatched_supplied_sha(self):
        trace = ScenarioTrace("genome", "complete", ({"event_id": 1},), {},
                              "0" * 64, "manifest")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "semantic SHA"):
                _write_online_trace_jsonl(Path(directory), trace)
            self.assertFalse((Path(directory) / "online_final_trace.meta.json").exists())


if __name__ == "__main__":
    unittest.main()
