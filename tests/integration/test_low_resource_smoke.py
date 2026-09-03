from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration import run_low_resource_smoke


ROOT = Path(__file__).resolve().parents[2]


class LowResourceSmokeTests(unittest.TestCase):
    def test_smoke_uses_real_runtime_adapters_and_publishes_bounded_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            result = run_low_resource_smoke(ROOT, report_path=report_path)

            self.assertEqual("passed", result["status"])
            self.assertEqual("conservative", result["profile"])
            self.assertEqual(1, result["candidate_count"])
            self.assertEqual(1, result["build_jobs"])
            self.assertEqual(3, result["fuzz_jobs"])
            self.assertEqual(
                [{"protocol_id": "ready-valid-mmio", "version": "1"}],
                result["protocols"],
            )
            graph = result["dependency_graph"]
            self.assertGreater(graph["node_count"], 0)
            self.assertGreater(graph["edge_count"], 0)
            policy = result["runtime_policy"]
            self.assertEqual(1, policy["build_concurrency"])
            self.assertFalse(policy["waveforms"])
            self.assertEqual(32, policy["replay_queue_capacity"])
            self.assertEqual(512, policy["event_ring_capacity"])
            self.assertEqual(16, policy["field_groups_per_batch"])
            self.assertEqual(512 * 1024 * 1024, policy["soft_memory_bytes"])
            self.assertEqual(768 * 1024 * 1024, policy["hard_memory_bytes"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("experiment_report.v1", report["report"]["schema_version"])
            self.assertEqual([], report["execution"]["resource_terminated_job_ids"])


if __name__ == "__main__":
    unittest.main()
