from __future__ import annotations

import json
import math
import os
from pathlib import Path
import signal
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from myfuzz.integration import campaign
from myfuzz.integration.campaign import CampaignLimits, CampaignOptions
from myfuzz.integration.campaign_report import (
    CampaignReportError,
    CampaignState,
    build_campaign_report,
    publish_campaign_report,
    write_checkpoint,
)


class CampaignReportTests(unittest.TestCase):
    def _options(self, output_dir: Path, *, duration_seconds: int = 10) -> CampaignOptions:
        return CampaignOptions(
            command=(sys.executable, "-c", "pass"),
            output_dir=output_dir,
            duration_seconds=duration_seconds,
            seed=41,
            checkpoint_seconds=1,
            limits=CampaignLimits(max_restarts=0),
            composition_hash="sha256:" + "a" * 64,
        )

    def test_checkpoint_is_atomically_parseable_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "checkpoint.json"
            path.write_text('{"old":true}\n', encoding="utf-8")
            state = CampaignState(
                seed=7,
                iterations=12,
                transactions=19,
                protocol_transactions={"tl-ul": 11, "apb": 8},
                component_transactions={"ram": 19},
                coverage={"cov.load", "cov.store"},
                errors=2,
                peak_rss_bytes=1234,
                last_output_line='{"transactions":1}',
            )

            write_checkpoint(path, state)

            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual("campaign_checkpoint.v1", document["schema_version"])
            self.assertEqual(1, document["checkpoint_count"])
            self.assertEqual(19, document["transactions"])
            self.assertEqual(["cov.load", "cov.store"], document["coverage"])
            self.assertFalse(list(path.parent.glob(".checkpoint.json.*.tmp")))

    def test_campaign_report_contains_evidence_and_derived_throughput(self) -> None:
        options = self._options(Path("/tmp/campaign-report-test"), duration_seconds=20)
        state = CampaignState(
            seed=41,
            iterations=50,
            transactions=75,
            protocol_transactions={"axi4-lite": 25, "tl-ul": 50},
            component_transactions={"gpio": 12, "ram": 63},
            coverage={"cov.0", "cov.1"},
            errors=3,
            peak_rss_bytes=4096,
            checkpoint_count=4,
            duration_seconds=2.5,
            last_output_line='{"transactions":1}',
        )

        report = build_campaign_report(options, state, "completed", None)

        self.assertEqual("campaign_report.v1", report["schema_version"])
        self.assertEqual("completed", report["status"])
        self.assertEqual(options.composition_hash, report["composition_hash"])
        self.assertEqual(41, report["seed"])
        self.assertEqual(2.5, report["duration_seconds"])
        self.assertEqual(50, report["iterations"])
        self.assertEqual(20.0, report["throughput_iterations_per_second"])
        self.assertEqual(4096, report["peak_rss_bytes"])
        self.assertEqual({"axi4-lite": 25, "tl-ul": 50}, report["protocol_transactions"])
        self.assertEqual({"gpio": 12, "ram": 63}, report["component_transactions"])
        self.assertEqual(["cov.0", "cov.1"], report["coverage"])

    def test_crash_report_contains_replay_command(self) -> None:
        options = self._options(Path("/tmp/campaign-report-test"))
        state = CampaignState(seed=41, duration_seconds=0.25)
        replay = (sys.executable, "-u", "campaign.py", "--seed", "41")

        report = build_campaign_report(options, state, "crashed", replay)

        self.assertEqual("crashed", report["status"])
        self.assertEqual(list(replay), report["replay_command"])

    def test_invalid_protocol_increments_errors_without_terminating_campaign(self) -> None:
        state = CampaignState(seed=41)

        state.record_metric(
            {"transactions": 4, "protocol": "unsupported-protocol", "component": "ram"},
            '{"transactions":4,"protocol":"unsupported-protocol","component":"ram"}',
        )

        self.assertEqual(4, state.transactions)
        self.assertEqual({"ram": 4}, state.component_transactions)
        self.assertEqual({}, state.protocol_transactions)
        self.assertEqual(1, state.errors)

    def test_error_only_metric_does_not_inflate_iteration_count(self) -> None:
        state = CampaignState(seed=41)

        state.record_metric({"error": 0}, '{"error":0}')

        self.assertEqual(0, state.iterations)
        self.assertEqual(0, state.transactions)
        self.assertEqual(0, state.errors)

    def test_publish_rejects_oversized_document_without_replacing_existing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text('{"status":"previous"}\n', encoding="utf-8")
            document = {"schema_version": "campaign_report.v1", "status": "completed", "output": "x" * (64 * 1024 * 1024)}

            with self.assertRaises(CampaignReportError):
                publish_campaign_report(path, document)

            self.assertEqual('{"status":"previous"}\n', path.read_text(encoding="utf-8"))
            self.assertFalse(list(path.parent.glob(".report.json.*.tmp")))

    def test_publish_rejects_interrupted_status_and_does_not_create_success_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            document = {"schema_version": "campaign_report.v1", "status": "running"}

            with self.assertRaises(CampaignReportError):
                publish_campaign_report(path, document)

            self.assertFalse(path.exists())

    def test_supervisor_checkpoints_at_interval_and_publishes_completed_report(self) -> None:
        source = """
            import json
            import time

            print(json.dumps({"iterations": 2, "transactions": 3, "protocol": "tl-ul", "component": "ram", "coverage": ["load"]}), flush=True)
            time.sleep(1.2)
        """
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            options = CampaignOptions(
                command=(sys.executable, "-u", "-c", textwrap.dedent(source)),
                output_dir=output_dir,
                duration_seconds=3,
                seed=9,
                checkpoint_seconds=1,
                limits=CampaignLimits(max_restarts=0),
                composition_hash="sha256:" + "b" * 64,
            )

            result = campaign.run_supervised_command(options)

            self.assertEqual("completed", result["status"])
            checkpoint = json.loads((output_dir / "checkpoint.json").read_text(encoding="utf-8"))
            report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(checkpoint["checkpoint_count"], 1)
            self.assertEqual("completed", report["status"])
            self.assertEqual(2, report["iterations"])
            self.assertEqual({"tl-ul": 3}, report["protocol_transactions"])
            self.assertEqual({"ram": 3}, report["component_transactions"])

    def test_parent_interrupt_terminates_child_before_propagating(self) -> None:
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
            marker = Path(temporary) / "child.pid"

            def interrupt_after_child_starts(*_args: object, **_kwargs: object) -> int:
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise KeyboardInterrupt

            with mock.patch.object(
                campaign,
                "_read_available_output",
                side_effect=interrupt_after_child_starts,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    campaign.run_supervised_command(
                        CampaignOptions(
                            command=(sys.executable, "-u", "-c", textwrap.dedent(source), str(marker)),
                            output_dir=output_dir,
                            duration_seconds=30,
                            checkpoint_seconds=1,
                            limits=CampaignLimits(max_restarts=0),
                        )
                    )

            child_pid = int(marker.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(Path(f"/proc/{child_pid}").exists())
            self.assertFalse((output_dir / "report.json").exists())

    def test_parent_interrupt_during_state_initialization_terminates_child_before_propagating(self) -> None:
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
            marker = Path(temporary) / "child.pid"
            child_pid: int | None = None

            def interrupt_during_state_initialization(*_args: object, **_kwargs: object) -> CampaignState:
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                raise KeyboardInterrupt

            try:
                with mock.patch.object(
                    campaign,
                    "CampaignState",
                    side_effect=interrupt_during_state_initialization,
                ):
                    with self.assertRaises(KeyboardInterrupt):
                        campaign.run_supervised_command(
                            CampaignOptions(
                                command=(
                                    sys.executable,
                                    "-u",
                                    "-c",
                                    textwrap.dedent(source),
                                    str(marker),
                                ),
                                output_dir=output_dir,
                                duration_seconds=30,
                                checkpoint_seconds=1,
                                limits=CampaignLimits(max_restarts=0),
                            )
                        )

                child_pid = int(marker.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 2
                while Path(f"/proc/{child_pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertFalse(Path(f"/proc/{child_pid}").exists())
            finally:
                if child_pid is None and marker.exists():
                    child_pid = int(marker.read_text(encoding="utf-8"))
                if child_pid is not None:
                    if Path(f"/proc/{child_pid}").exists():
                        try:
                            os.killpg(child_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    try:
                        os.waitpid(child_pid, 0)
                    except ChildProcessError:
                        pass

            self.assertFalse((output_dir / "report.json").exists())

    def test_reused_output_directory_removes_stale_success_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            completed = CampaignOptions(
                command=(sys.executable, "-u", "-c", "pass"),
                output_dir=output_dir,
                duration_seconds=1,
                checkpoint_seconds=1,
                limits=CampaignLimits(max_restarts=0),
            )
            self.assertEqual("completed", campaign.run_supervised_command(completed)["status"])
            self.assertTrue((output_dir / "report.json").is_file())

            timed_out = CampaignOptions(
                command=(sys.executable, "-u", "-c", "import time; time.sleep(30)"),
                output_dir=output_dir,
                duration_seconds=1,
                checkpoint_seconds=1,
                limits=CampaignLimits(max_restarts=0),
            )
            result = campaign.run_supervised_command(timed_out)

            self.assertEqual("timed-out", result["status"])
            self.assertIsNone(result["report_path"])
            self.assertFalse((output_dir / "report.json").exists())

    def test_campaign_state_rejects_non_finite_duration(self) -> None:
        for duration in (math.nan, math.inf, -math.inf):
            with self.subTest(duration=duration):
                with self.assertRaises(CampaignReportError):
                    CampaignState(seed=1, duration_seconds=duration)


if __name__ == "__main__":
    unittest.main()
