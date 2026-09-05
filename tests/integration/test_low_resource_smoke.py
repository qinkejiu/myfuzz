from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from myfuzz.integration import campaign, run_low_resource_smoke
from myfuzz.integration.campaign import CampaignError, CampaignLimits, CampaignOptions


ROOT = Path(__file__).resolve().parents[2]


class LowResourceSmokeTests(unittest.TestCase):
    def _options(
        self,
        output_dir: Path,
        source: str,
        *arguments: str,
        duration_seconds: int = 2,
        checkpoint_seconds: int = 1,
        limits: CampaignLimits | None = None,
    ) -> CampaignOptions:
        return CampaignOptions(
            command=(sys.executable, "-u", "-c", textwrap.dedent(source), *arguments),
            output_dir=output_dir,
            duration_seconds=duration_seconds,
            checkpoint_seconds=checkpoint_seconds,
            limits=limits if limits is not None else CampaignLimits(),
        )

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

    def test_process_group_rss_sums_live_members_and_ignores_duplicate_or_exited_entries(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc_root = Path(temporary) / "proc"
            for pid, pgid, state, rss_kib in (
                (101, 77, "S", 4),
                (102, 77, "R", 7),
                (103, 78, "S", 100),
                (104, 77, "Z", 200),
            ):
                process_dir = proc_root / str(pid)
                process_dir.mkdir(parents=True)
                (process_dir / "stat").write_text(
                    f"{pid} (fixture with spaces) {state} 1 {pgid}\n",
                    encoding="ascii",
                )
                (process_dir / "status").write_text(
                    f"Name: fixture\nVmRSS: {rss_kib} kB\n",
                    encoding="ascii",
                )

            duplicate_entries = [
                proc_root / "101",
                proc_root / "101",
                proc_root / "102",
                proc_root / "103",
                proc_root / "104",
                proc_root / "105",
            ]
            with mock.patch.object(
                type(proc_root), "iterdir", return_value=iter(duplicate_entries)
            ), mock.patch.object(campaign, "_PROC_ROOT", proc_root):
                self.assertEqual(
                    (4 + 7) * 1024,
                    campaign.read_process_group_rss_bytes(77),
                )

    def test_process_group_hard_limit_uses_cumulative_rss_and_kills_descendant(self) -> None:
        source = """
            import subprocess
            import sys
            import time

            marker = sys.argv[1]
            grandchild = subprocess.Popen([
                sys.executable,
                "-c",
                (
                    "import time; "
                    "allocation = bytearray(16 * 1024 * 1024); "
                    "allocation[::4096] = b'x' * (len(allocation) // 4096); "
                    "time.sleep(30)"
                ),
            ])
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write(str(grandchild.pid))
            allocation = bytearray(4 * 1024 * 1024)
            allocation[::4096] = b'x' * (len(allocation) // 4096)
            time.sleep(30)
        """

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            marker = Path(temporary) / "grandchild.pid"
            limits = CampaignLimits(
                soft_memory_bytes=8 * 1024 * 1024,
                hard_memory_bytes=24 * 1024 * 1024,
                max_restarts=0,
            )
            result = campaign.run_supervised_command(
                self._options(output_dir, source, str(marker), limits=limits)
            )

            self.assertEqual("resource-terminated", result["status"])
            self.assertGreaterEqual(result["peak_rss_bytes"], limits.hard_memory_bytes)
            grandchild_pid = int(marker.read_text(encoding="utf-8"))
            self._assert_process_is_gone_or_zombie(grandchild_pid)

    def test_process_group_procfs_failure_fails_closed_after_child_start(self) -> None:
        source = """
            from pathlib import Path
            import os
            import sys
            import time

            Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(30)
        """

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            marker = Path(temporary) / "started"
            options = self._options(output_dir, source, str(marker))

            def fail_after_child_starts(_pgid: int) -> None:
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise CampaignError("procfs process-group scan is unavailable")

            with mock.patch.object(
                campaign,
                "read_process_group_rss_bytes",
                side_effect=fail_after_child_starts,
            ):
                result = campaign.run_supervised_command(options)

            self.assertEqual("startup-error", result["status"])
            self.assertEqual("rss-unavailable", result["error"]["type"])
            self.assertIn("process-group scan is unavailable", result["error"]["message"])
            self.assertTrue(marker.exists())
            self.assertIsNotNone(result["termination_signal"])
            self._assert_process_is_gone_or_zombie(
                int(marker.read_text(encoding="utf-8"))
            )

    def test_process_group_procfs_enumeration_failure_is_a_campaign_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unavailable_proc_root = Path(temporary) / "missing-proc"
            with mock.patch.object(campaign, "_PROC_ROOT", unavailable_proc_root):
                with self.assertRaisesRegex(CampaignError, "cannot scan procfs process group"):
                    campaign.read_process_group_rss_bytes(77)

    @staticmethod
    def _assert_process_is_gone_or_zombie(pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status_path = Path(f"/proc/{pid}/status")
            if not status_path.exists():
                return
            try:
                state_line = next(
                    line
                    for line in status_path.read_text(encoding="ascii").splitlines()
                    if line.startswith("State:")
                )
            except (OSError, StopIteration):
                return
            if state_line.split()[1].startswith("Z"):
                return
            time.sleep(0.05)
        raise AssertionError(f"process group descendant {pid} is still alive")


if __name__ == "__main__":
    unittest.main()
