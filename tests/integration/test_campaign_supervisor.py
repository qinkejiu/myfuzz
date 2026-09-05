from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from myfuzz.integration import campaign
from myfuzz.integration.campaign import CampaignError, CampaignLimits, CampaignOptions


class CampaignSupervisorTests(unittest.TestCase):
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

    def test_completed_child_records_rss_return_code_and_json_line_metrics(self) -> None:
        source = """
            import json
            import os
            import time

            print(json.dumps({
                "transactions": 3,
                "protocol": "tl-ul",
                "component": "ram",
                "coverage": ["load"],
                "group_id": os.getpgrp(),
            }), flush=True)
            print("diagnostic text that is not JSON", flush=True)
            print(json.dumps({"error": 0}), flush=True)
            time.sleep(0.2)
        """

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            result = campaign.run_supervised_command(
                self._options(output_dir, source, checkpoint_seconds=1)
            )

            self.assertEqual("completed", result["status"])
            self.assertEqual(0, result["return_code"])
            self.assertEqual(0, result["returncode"])
            self.assertGreater(result["duration_seconds"], 0)
            self.assertGreater(result["peak_rss_bytes"], 0)
            self.assertEqual(2, result["metric_count"])
            self.assertEqual(
                [
                    {
                        "transactions": 3,
                        "protocol": "tl-ul",
                        "component": "ram",
                        "coverage": ["load"],
                        "group_id": result["pid"],
                    },
                    {"error": 0},
                ],
                result["metrics"],
            )
            self.assertNotEqual(os.getpgrp(), result["metrics"][0]["group_id"])

    def test_unbounded_and_unrecognized_output_is_not_retained_as_a_metric(self) -> None:
        source = """
            import json
            print({"transactions": 1, "protocol": "apb"}.__class__.__name__)
            print("x" * (64 * 1024 + 1), flush=True)
            print(json.dumps({"transactions": 7, "component": "timer"}), flush=True)
        """

        with tempfile.TemporaryDirectory() as temporary:
            result = campaign.run_supervised_command(
                self._options(Path(temporary) / "campaign", source)
            )

            self.assertEqual("completed", result["status"])
            self.assertEqual(
                [{"transactions": 7, "component": "timer"}], result["metrics"]
            )
            self.assertEqual(1, result["metric_count"])

    def test_json_lines_with_unbounded_integer_values_are_ignored(self) -> None:
        source = """
            import json

            print('{"transactions":' + ('9' * 5000) + '}', flush=True)
            print(json.dumps({"transactions": 2, "protocol": "axi4-lite"}), flush=True)
        """

        with tempfile.TemporaryDirectory() as temporary:
            result = campaign.run_supervised_command(
                self._options(Path(temporary) / "campaign", source)
            )

            self.assertEqual("completed", result["status"])
            self.assertEqual(
                [{"transactions": 2, "protocol": "axi4-lite"}], result["metrics"]
            )
            self.assertGreaterEqual(result["invalid_metric_lines"], 1)

    def test_rss_monitoring_unavailable_fails_closed_before_starting_child(self) -> None:
        source = """
            from pathlib import Path
            Path(__import__("sys").argv[1]).write_text("started", encoding="utf-8")
        """

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            marker = Path(temporary) / "started"
            options = self._options(output_dir, source, str(marker))
            with mock.patch.object(
                campaign,
                "read_rss_bytes",
                side_effect=CampaignError("procfs RSS is unavailable"),
            ), mock.patch.object(campaign.subprocess, "Popen") as popen:
                result = campaign.run_supervised_command(options)

            self.assertEqual("startup-error", result["status"])
            self.assertEqual("rss-unavailable", result["error"]["type"])
            self.assertIn("procfs RSS is unavailable", result["error"]["message"])
            popen.assert_not_called()
            self.assertFalse(marker.exists())

    def test_hard_rss_limit_terminates_the_entire_process_group_and_persists_checkpoint(
        self,
    ) -> None:
        source = """
            import json
            import subprocess
            import sys
            import time

            marker = sys.argv[1]
            grandchild = subprocess.Popen([
                sys.executable, "-c", "import time; time.sleep(30)"
            ])
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write(str(grandchild.pid))
            allocation = bytearray(32 * 1024 * 1024)
            for offset in range(0, len(allocation), 4096):
                allocation[offset] = 1
            print(json.dumps({"transactions": 1, "component": "ram"}), flush=True)
            time.sleep(30)
        """

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            marker = Path(temporary) / "grandchild.pid"
            limits = CampaignLimits(
                soft_memory_bytes=4 * 1024 * 1024,
                hard_memory_bytes=16 * 1024 * 1024,
                max_restarts=0,
            )
            result = campaign.run_supervised_command(
                self._options(output_dir, source, str(marker), limits=limits)
            )

            self.assertEqual("resource-terminated", result["status"])
            self.assertIsNotNone(result["return_code"])
            self.assertNotEqual(0, result["return_code"])
            self.assertGreaterEqual(
                result["peak_rss_bytes"], limits.hard_memory_bytes
            )
            checkpoint_path = output_dir / "checkpoint.json"
            self.assertTrue(checkpoint_path.is_file())
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            self.assertEqual("resource-terminated", checkpoint["status"])
            self.assertEqual(result["peak_rss_bytes"], checkpoint["peak_rss_bytes"])

            grandchild_pid = int(marker.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status_path = Path(f"/proc/{grandchild_pid}/status")
                if not status_path.exists():
                    break
                try:
                    state_line = next(
                        line for line in status_path.read_text(encoding="ascii").splitlines()
                        if line.startswith("State:")
                    )
                except (OSError, StopIteration):
                    break
                if state_line.split()[1].startswith("Z"):
                    break
                time.sleep(0.05)
            self.assertFalse(
                status_path.exists() and not state_line.split()[1].startswith("Z")
            )

    def test_rss_parser_rejects_missing_and_malformed_proc_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            proc_root = Path(temporary) / "proc"
            status_path = proc_root / "123" / "status"
            status_path.parent.mkdir(parents=True)
            with mock.patch.object(campaign, "_PROC_ROOT", proc_root):
                with self.assertRaises(CampaignError):
                    campaign.read_rss_bytes(123)

                status_path.write_text("VmRSS: not-a-number kB\n", encoding="ascii")
                with self.assertRaises(CampaignError):
                    campaign.read_rss_bytes(123)

                status_path.write_text("VmRSS: 12 MB\n", encoding="ascii")
                with self.assertRaises(CampaignError):
                    campaign.read_rss_bytes(123)

                status_path.write_text("VmRSS: 12 kB\n", encoding="ascii")
                self.assertEqual(12 * 1024, campaign.read_rss_bytes(123))

    def test_pipe_setup_failure_terminates_a_started_child(self) -> None:
        source = """
            from pathlib import Path
            import os
            import sys
            import time

            Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(30)
        """

        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "started"
            options = self._options(Path(temporary) / "campaign", source, str(marker))

            def fail_after_child_starts(_descriptor: int, _blocking: bool) -> None:
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise OSError("nonblocking setup failed")

            with mock.patch.object(
                campaign.os,
                "set_blocking",
                side_effect=fail_after_child_starts,
            ):
                result = campaign.run_supervised_command(options)

            self.assertTrue(marker.exists())
            self.assertEqual("startup-error", result["status"])
            self.assertEqual("monitor-setup-failed", result["error"]["type"])
            child_pid = int(marker.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and Path(f"/proc/{child_pid}").exists():
                time.sleep(0.05)
            self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_selector_setup_failure_terminates_a_started_child(self) -> None:
        source = """
            from pathlib import Path
            import os
            import sys
            import time

            Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(30)
        """

        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "started"
            options = self._options(Path(temporary) / "campaign", source, str(marker))

            def fail_after_child_starts():
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise OSError("selector setup failed")

            with mock.patch.object(
                campaign.selectors,
                "DefaultSelector",
                side_effect=fail_after_child_starts,
            ):
                result = campaign.run_supervised_command(options)

            self.assertEqual("startup-error", result["status"])
            self.assertEqual("monitor-setup-failed", result["error"]["type"])
            child_pid = int(marker.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and Path(f"/proc/{child_pid}").exists():
                time.sleep(0.05)
            self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_process_group_support_is_verified_before_start(self) -> None:
        source = "import time; time.sleep(30)"
        with tempfile.TemporaryDirectory() as temporary:
            options = self._options(Path(temporary) / "campaign", source)
            with mock.patch.object(
                campaign.os,
                "getpgid",
                side_effect=OSError("process groups unavailable"),
            ), mock.patch.object(campaign.subprocess, "Popen") as popen:
                result = campaign.run_supervised_command(options)

            self.assertEqual("startup-error", result["status"])
            self.assertEqual("process-group-unavailable", result["error"]["type"])
            popen.assert_not_called()

    def test_crashed_child_cleans_up_its_process_group(self) -> None:
        source = """
            import subprocess
            import sys
            import time

            grandchild = subprocess.Popen([
                sys.executable, "-c", "import time; time.sleep(30)"
            ])
            with open(sys.argv[1], "w", encoding="utf-8") as handle:
                handle.write(str(grandchild.pid))
            raise SystemExit(3)
        """

        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "grandchild.pid"
            result = campaign.run_supervised_command(
                self._options(Path(temporary) / "campaign", source, str(marker))
            )

            self.assertEqual("crashed", result["status"])
            self.assertNotEqual(0, result["return_code"])
            grandchild_pid = int(marker.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                status_path = Path(f"/proc/{grandchild_pid}/status")
                if not status_path.exists():
                    break
                try:
                    state_line = next(
                        line for line in status_path.read_text(encoding="ascii").splitlines()
                        if line.startswith("State:")
                    )
                except (OSError, StopIteration):
                    break
                if state_line.split()[1].startswith("Z"):
                    break
                time.sleep(0.05)
            self.assertFalse(
                status_path.exists() and not state_line.split()[1].startswith("Z")
            )


if __name__ == "__main__":
    unittest.main()
