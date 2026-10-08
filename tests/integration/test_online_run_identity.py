"""The live online run identity binds the complete saved run record."""

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration.scenario_rfuzz_live import (
    _write_online_run_identity, _verify_online_run_identity,
)
from myfuzz.integration.ibex_uart_online import _read_uart_online_trace
from myfuzz.scenario.replay import ScenarioTrace


class OnlineRunIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        (self.output / "decoder_manifest.json").write_text(
            '{"graph":{"rules":[]},"schema_version":"decoder.v1"}\n')
        (self.output / "targets.json").write_text('[{"target_id":"irq"}]\n')
        (self.output / "rfuzz.toml").write_text('[general]\nfilename = "plan"\n')
        (self.output / "seed.bin").write_bytes(b"seed")
        self.plan = b'{"schema_version":1,"cases":[]}\n'
        (self.output / "online_plan.json").write_bytes(self.plan)
        self.manifest = {
            "schema_version": "online_session_manifest.v1",
            "runner": {"sessions": {"cpu": {"identity": {
                "runtime_artifact": {"selected_template": {
                    "id": "cpu.test", "version": "1"}},
                "build_identity": {"toolchain": {"verilator": "5.x"}}}}}},
            "online_source_files": [],
            "checker": {"module": "checks", "qualname": "Check",
                        "source_sha256": "checker-source"},
        }
        self.manifest_hash = self._sha(self.manifest)
        self.trace = ScenarioTrace(
            self._sha_bytes(self.plan), "complete", [], {"cpu": 1},
            "semantic-hash", self.manifest_hash)
        (self.output / "online_final_trace.json").write_text(json.dumps({
            "genome_sha256": self.trace.genome_sha256,
            "status": self.trace.status,
            "events": list(self.trace.events),
            "local_ticks": self.trace.local_ticks,
            "semantic_sha256": self.trace.semantic_sha256,
            "manifest_sha256": self.trace.manifest_sha256,
        }, sort_keys=True, separators=(",", ":")) + "\n")
        self.binary = self.output / "kfuzz"
        self.binary.write_bytes(b"rfuzz-client")

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def _sha(value):
        return OnlineRunIdentityTests._sha_bytes(json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode())

    @staticmethod
    def _sha_bytes(value):
        import hashlib
        return hashlib.sha256(value).hexdigest()

    def write_identity(self):
        return _write_online_run_identity(
            self.output, session_manifest=self.manifest,
            plan_bytes=self.plan, trace=self.trace,
            client_binary=self.binary,
            run_config={"duration_seconds": 1, "max_tests": 2,
                        "search_seed": 3, "max_runs_per_batch": 1})

    def test_identity_binds_session_graph_feedback_genome_and_toolchain(self):
        identity_sha256 = self.write_identity()
        document = json.loads((self.output / "online_run_identity.json").read_text())
        identity = document["identity"]
        self.assertEqual("scenario_online_run_identity.v1", identity["schema_version"])
        self.assertEqual(identity_sha256, document["sha256"])
        self.assertEqual(self.trace.genome_sha256, identity["genome"]["plan_sha256"])
        self.assertEqual(self.trace.manifest_sha256,
                         identity["session"]["manifest_sha256"])
        self.assertEqual("cpu.test", identity["templates"][0]["id"])
        self.assertEqual("checker-source", identity["checker"]["source_sha256"])
        self.assertTrue(identity["dependency_graph"]["sha256"])
        self.assertTrue(identity["feedback"]["targets_sha256"])
        self.assertTrue(identity["toolchain"]["client"]["binary_sha256"])
        self.assertEqual(3, identity["run_config"]["search_seed"])

    def test_replay_verification_rejects_changed_identity_inputs(self):
        self.write_identity()
        verified = _verify_online_run_identity(
            self.output, plan_path=self.output / "online_plan.json",
            trace_path=self.output / "online_final_trace.json",
            trace=self.trace)
        self.assertEqual(self.trace.genome_sha256,
                         verified["genome"]["plan_sha256"])

        (self.output / "targets.json").write_text('[{"target_id":"changed"}]\n')
        with self.assertRaisesRegex(ValueError, "online run identity artifact mismatch"):
            _verify_online_run_identity(
                self.output, plan_path=self.output / "online_plan.json",
                trace_path=self.output / "online_final_trace.json",
                trace=self.trace)

    def test_replay_verification_rejects_a_different_trace_identity(self):
        self.write_identity()
        changed = ScenarioTrace(
            self.trace.genome_sha256, "complete", [], {"cpu": 1},
            "different-semantic-hash", self.manifest_hash)
        with self.assertRaisesRegex(ValueError, "online run identity trace mismatch"):
            _verify_online_run_identity(
                self.output, plan_path=self.output / "online_plan.json",
                trace_path=self.output / "online_final_trace.json",
                trace=changed)

    def test_replay_verification_rejects_changed_trace_body(self):
        self.write_identity()
        trace_path = self.output / "online_final_trace.json"
        changed = json.loads(trace_path.read_text())
        changed["events"].append({"kind": "extra-event"})
        trace_path.write_text(json.dumps(changed, sort_keys=True,
                                         separators=(",", ":")) + "\n")
        with self.assertRaisesRegex(ValueError,
                                    "online run identity artifact mismatch: online_final_trace.json"):
            _verify_online_run_identity(
                self.output, plan_path=self.output / "online_plan.json",
                trace_path=self.output / "online_final_trace.json",
                trace=self.trace)

    def test_replay_verification_rejects_an_alternate_trace_path(self):
        self.write_identity()
        alternate = self.output / "alternate.json"
        changed = json.loads((self.output / "online_final_trace.json").read_text())
        changed["events"].append({"event_id": 2, "kind": "alternate"})
        alternate.write_text(json.dumps(changed, sort_keys=True,
                                        separators=(",", ":")) + "\n")
        with self.assertRaisesRegex(ValueError, "online run identity trace path mismatch"):
            _verify_online_run_identity(
                self.output, plan_path=self.output / "online_plan.json",
                trace_path=alternate, trace=self.trace)

    def test_missing_sidecar_is_rejected_when_new_bundle_markers_remain(self):
        identity_sha = self.write_identity()
        (self.output / "report.json").write_text(json.dumps(
            {"online_run_identity_sha256": identity_sha}))
        (self.output / "online_run_identity.json").unlink()
        with self.assertRaisesRegex(ValueError, "identity is missing"):
            _verify_online_run_identity(
                self.output, plan_path=self.output / "online_plan.json",
                trace_path=self.output / "online_final_trace.json",
                trace=self.trace)

    def test_pre_identity_legacy_bundle_without_sidecar_remains_accepted(self):
        self.assertIsNone(_verify_online_run_identity(
            self.output, plan_path=self.output / "online_plan.json",
            trace_path=self.output / "online_final_trace.json",
            trace=self.trace))

    def test_uart_file_replay_reads_streamed_jsonl_trace(self):
        events = [{"event_id": 1, "kind": "case_started"}]
        (self.output / "online_events.jsonl").write_text(
            json.dumps(events[0], sort_keys=True, separators=(",", ":")) + "\n")
        metadata = {
            "schema_version": "online_trace_jsonl.v1",
            "events_file": "online_events.jsonl", "event_count": 1,
            "genome_sha256": self.trace.genome_sha256,
            "status": self.trace.status, "local_ticks": self.trace.local_ticks,
            "semantic_sha256": self.trace.semantic_sha256,
            "manifest_sha256": self.trace.manifest_sha256,
        }
        path = self.output / "online_final_trace.meta.json"
        path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")))
        trace = _read_uart_online_trace(path)
        self.assertEqual(events[0], trace.events[0])


if __name__ == "__main__":
    unittest.main()
