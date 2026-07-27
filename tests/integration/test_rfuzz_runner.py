from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.experiments.rfuzz_adapter import RfuzzAvailability
from myfuzz.integration import (
    BuildJobResult,
    FuzzJobResult,
    ResourceCheckpointEvent,
    RfuzzExperimentRunner,
)
from myfuzz.scripts import run_design_flow
from tests.experiments.test_rfuzz_adapter import build_job, job


class InstrumentationCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.first = {
            "module": "top",
            "signal": "branch_0",
            "kind": "branch",
            "subtype": "hit",
            "file": "top.sv",
            "line": 7,
            "column": 3,
        }
        self.second = {
            "module": "top",
            "signal": "branch_1",
            "kind": "branch",
            "subtype": "hit",
            "file": "top.sv",
            "line": 11,
            "column": 5,
        }

    def test_instrumentation_records_become_ordered_stable_coverage_points(self) -> None:
        points = run_design_flow.coverage_universe_from_instrumentation({
            "coverage_point_count": 2,
            "coverage": [self.first, self.second],
        })

        self.assertEqual([1, 2], [point["point_id"] for point in points])
        self.assertRegex(points[0]["stable_source_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual((1,), run_design_flow.covered_point_ids_from_bitmap(points, [254, 255]))

    def test_instrumentation_and_bitmap_shape_mismatches_fail_closed(self) -> None:
        invalid = (
            {"coverage_point_count": 1, "coverage": [self.first, self.second]},
            {"coverage_point_count": 1, "coverage": ["not-an-object"]},
            {"coverage_point_count": 2, "coverage": [self.first, self.first]},
        )
        for instrumentation in invalid:
            with self.subTest(instrumentation=instrumentation), self.assertRaises(ValueError):
                run_design_flow.coverage_universe_from_instrumentation(instrumentation)

        points = run_design_flow.coverage_universe_from_instrumentation({
            "coverage_point_count": 2,
            "coverage": [self.first, self.second],
        })
        with self.assertRaisesRegex(ValueError, "bitmap width"):
            run_design_flow.covered_point_ids_from_bitmap(points, [254])

    def test_queue_statistics_are_joined_to_instrumentation_measurements(self) -> None:
        points = run_design_flow.coverage_universe_from_instrumentation({
            "coverage_point_count": 2,
            "coverage": [self.first, self.second],
        })
        statistics = {
            "tests_per_second": {"global_numerator": 12.0},
            "cycles_per_second": {"global_numerator": 48.0},
            "bitmap": [254, 255],
            "runtime": {"secs": 2, "nanos": 500_000_000},
        }

        measured = run_design_flow.rfuzz_measurements(statistics, points)

        self.assertEqual(2.5, measured["elapsed_seconds"])
        self.assertEqual(12, measured["tests_executed"])
        self.assertEqual(48, measured["cycles_executed"])
        self.assertEqual([1], measured["covered_point_ids"])
        self.assertEqual(2, measured["coverage_point_count"])

    def test_result_path_must_resolve_beneath_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(
                root / "runs" / "result.json",
                run_design_flow.result_json_path(root, "runs/result.json"),
            )
            with self.assertRaisesRegex(ValueError, "beneath the repository"):
                run_design_flow.result_json_path(root, "../result.json")

    def test_statistics_evidence_must_be_fresh_regular_valid_and_width_matched(self) -> None:
        points = run_design_flow.coverage_universe_from_instrumentation({
            "coverage_point_count": 2,
            "coverage": [self.first, self.second],
        })
        valid = {
            "tests_per_second": {"global_numerator": 12.0},
            "cycles_per_second": {"global_numerator": 48.0},
            "bitmap": [254, 255],
            "runtime": {"secs": 2, "nanos": 0},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started_ns = time.time_ns()
            missing = root / "missing.json"
            with self.assertRaisesRegex(ValueError, "missing"):
                run_design_flow.load_rfuzz_measurements(missing, points, started_ns)

            stale = root / "stale.json"
            stale.write_text(json.dumps(valid), encoding="utf-8")
            os.utime(stale, ns=(1, 1))
            with self.assertRaisesRegex(ValueError, "stale"):
                run_design_flow.load_rfuzz_measurements(stale, points, started_ns)

            non_regular = root / "directory.json"
            non_regular.mkdir()
            with self.assertRaisesRegex(ValueError, "regular"):
                run_design_flow.load_rfuzz_measurements(non_regular, points, 0)

            malformed = root / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid JSON"):
                run_design_flow.load_rfuzz_measurements(malformed, points, 0)

            wrong_width = root / "wrong-width.json"
            wrong_width.write_text(json.dumps(dict(valid, bitmap=[255])), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bitmap width"):
                run_design_flow.load_rfuzz_measurements(wrong_width, points, 0)

    def test_handshake_requires_both_paths_to_be_real_fifos(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fpga = Path(directory)
            endpoint = fpga / "0"
            endpoint.mkdir()
            os.mkfifo(endpoint / "tx.fifo")
            self.assertFalse(run_design_flow.rfuzz_fifos_ready(fpga, ("0",)))
            (endpoint / "rx.fifo").write_text("not a fifo", encoding="utf-8")
            self.assertFalse(run_design_flow.rfuzz_fifos_ready(fpga, ("0",)))
            (endpoint / "rx.fifo").unlink()
            os.mkfifo(endpoint / "rx.fifo")
            self.assertTrue(run_design_flow.rfuzz_fifos_ready(fpga, ("0",)))

    def test_stage_fuzz_retains_observed_crash_restart_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "out_dir": root / "out",
                "queue": root / "out" / "queue",
            }
            paths["out_dir"].mkdir()
            crash = paths["out_dir"] / "crashes" / "crash_000001"
            crash.mkdir(parents=True)
            outcomes = [
                ("crash", 9, -15, crash, True, 1024, False),
                ("ok", -15, -15, None, True, 2048, False),
            ]
            with patch.object(run_design_flow, "build_fuzzer", return_value=root / "kfuzz"), patch.object(
                run_design_flow, "run_fuzz_attempt", side_effect=outcomes
            ):
                result = run_design_flow.stage_fuzz(
                    root,
                    {"fuzz": {"max_cycles": 1, "crash_restarts": 1}},
                    root / "config.json",
                    paths,
                    None,
                )

        self.assertEqual(1, result["crash_restart_count"])
        self.assertEqual(1, result["failure_reasons"]["dut_crash"])
        self.assertEqual(-15, result["fuzzer_returncode"])

    def test_resource_termination_retains_restarts_without_dut_misclassification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"out_dir": root / "out", "queue": root / "out" / "queue"}
            paths["out_dir"].mkdir()
            crash = paths["out_dir"] / "crashes" / "crash_000001"
            crash.mkdir(parents=True)
            outcomes = [
                ("crash", 9, -15, crash, True, 1024, False),
                ("resource", -9, -15, None, True, 8192, True),
            ]
            with patch.object(
                run_design_flow, "build_fuzzer", return_value=root / "kfuzz"
            ), patch.object(run_design_flow, "run_fuzz_attempt", side_effect=outcomes):
                result = run_design_flow.stage_fuzz(
                    root,
                    {"fuzz": {"max_cycles": 1, "crash_restarts": 1}},
                    root / "config.json",
                    paths,
                    None,
                )

        self.assertEqual(1, result["crash_restart_count"])
        self.assertEqual(0, result["failure_reasons"]["dut_crash"])
        self.assertEqual(1, result["failure_reasons"]["resource_terminated"])

    def test_monitored_command_terminates_at_hard_memory_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_design_flow.run_monitored_command(
                [sys.executable, "-c", "import time; payload=bytearray(1048576); time.sleep(30)"],
                cwd=Path(directory),
                hard_memory_bytes=1,
            )

        self.assertTrue(result["resource_terminated"])
        self.assertGreaterEqual(result["peak_rss_bytes"], 1)
        self.assertNotEqual(0, result["returncode"])

    def test_monitored_command_cleans_descendants_after_launcher_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_path = Path(directory) / "child.pid"
            child_code = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(child_path)!r}).write_text(str(__import__('os').getpid())); "
                "time.sleep(30)"
            )
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib,subprocess,sys,time\n"
                    f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
                    f"path=pathlib.Path({str(child_path)!r})\n"
                    "deadline=time.time()+5\n"
                    "while not path.exists() and time.time()<deadline:\n"
                    " time.sleep(.01)\n"
                ),
            ]
            run_design_flow.run_monitored_command(
                command, cwd=Path(directory), hard_memory_bytes=None
            )
            child_pid = int(child_path.read_text(encoding="utf-8"))

            deadline = time.time() + 2
            while time.time() < deadline:
                stat_path = Path(f"/proc/{child_pid}/stat")
                if not stat_path.exists() or stat_path.read_text().rpartition(")")[2].split()[0] == "Z":
                    break
                time.sleep(0.02)
            else:
                self.fail("monitored command left a surviving descendant")

    def test_cleanup_kills_surviving_process_group_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child_path = Path(directory) / "child.pid"
            ready_path = Path(directory) / "child.ready"
            child_code = (
                "import pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready_path)!r}).write_text('ready'); "
                "time.sleep(30)"
            )
            leader = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import pathlib,subprocess,sys,time\n"
                        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
                        f"ready=pathlib.Path({str(ready_path)!r})\n"
                        "deadline=time.time()+5\n"
                        "while not ready.exists() and time.time()<deadline:\n"
                        " time.sleep(.01)\n"
                        f"pathlib.Path({str(child_path)!r}).write_text(str(child.pid))\n"
                    ),
                ],
                start_new_session=True,
            )
            leader.wait(timeout=5)
            child_pid = int(child_path.read_text(encoding="utf-8"))
            self.assertTrue(Path(f"/proc/{child_pid}").exists())

            run_design_flow.terminate_process(leader, timeout=1)

            deadline = time.time() + 2
            while time.time() < deadline:
                stat_path = Path(f"/proc/{child_pid}/stat")
                if not stat_path.exists() or stat_path.read_text().rpartition(")")[2].split()[0] == "Z":
                    break
                time.sleep(0.02)
            else:
                self.fail("surviving process-group descendant was not terminated")

    def test_server_build_uses_descendant_monitor_with_forwarded_hard_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "instrumented": root / "instrumented",
                "harness": root / "harness",
                "server": root / "server",
            }
            observed = {
                "returncode": -15,
                "peak_rss_bytes": 4096,
                "resource_terminated": True,
            }
            with patch.object(
                run_design_flow, "run_monitored_command", return_value=observed
            ) as monitored, patch.object(run_design_flow, "run") as unmonitored:
                result = run_design_flow.stage_server(
                    root,
                    {"top": "top", "hard_memory_bytes": 2048},
                    paths,
                    "verilator",
                    "1",
                )

        self.assertEqual(observed, result)
        self.assertEqual(2048, monitored.call_args.kwargs["hard_memory_bytes"])
        unmonitored.assert_not_called()


class RfuzzExperimentRunnerTest(unittest.TestCase):
    def _install_fixture_paths(self, root: Path) -> None:
        driver = root / "src" / "myfuzz" / "scripts" / "run_design_flow.py"
        driver.parent.mkdir(parents=True, exist_ok=True)
        driver.touch()
        flow = root / "third_party" / "rfuzz" / "rfuzz_flow"
        fuzzer = flow / "fuzzer" / "target" / "release" / "kfuzz"
        fuzzer.parent.mkdir(parents=True, exist_ok=True)
        fuzzer.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fuzzer.chmod(0o755)

    def _fixture(
        self,
        root: Path,
        document: dict[str, object] | None,
        *,
        exit_code: int = 0,
        stale: bool = False,
    ) -> RfuzzExperimentRunner:
        script = root / "src" / "myfuzz" / "scripts" / "run_design_flow.py"
        script.parent.mkdir(parents=True)
        self._install_fixture_paths(root)
        payload = json.dumps(document)
        script.write_text(
            "import argparse, json, os, pathlib\n"
            "p=argparse.ArgumentParser(add_help=False)\n"
            "p.add_argument('--result-json')\n"
            "a,_=p.parse_known_args()\n"
            f"document=json.loads({payload!r})\n"
            "if document is not None:\n"
            " path=pathlib.Path(a.result_json); path.parent.mkdir(parents=True, exist_ok=True)\n"
            " path.write_text(json.dumps(document))\n"
            + (" os.utime(path, (1, 1))\n" if stale else "")
            + f"raise SystemExit({exit_code})\n",
            encoding="utf-8",
        )
        return RfuzzExperimentRunner(root, root / "runs" / "results")

    def test_build_result_is_strictly_mapped_from_the_result_document(self) -> None:
        planned = build_job(artifact_id="sha256:" + "a" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = root / "runs" / "server"
            server.parent.mkdir(parents=True)
            server.write_text("server")
            runner = self._fixture(root, {
                "kind": "build",
                "artifact_id": planned.artifact_id,
                "server_path": "runs/server",
                "server_exists": True,
                "peak_rss_bytes": 4096,
                "resource_terminated": False,
            })

            result = runner(planned)

        self.assertEqual(BuildJobResult(planned.job_id, 1, planned.artifact_id), result)

    def test_resource_documents_map_to_checkpoint_events(self) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned_build = build_job(artifact_id=artifact_id)
        planned_fuzz = job(
            budget_kind="seconds", budget_value=1,
            artifact_id=artifact_id, build_job_id=planned_build.job_id,
        )
        documents = (
            (
                planned_build,
                {
                    "kind": "build", "artifact_id": artifact_id,
                    "server_path": "runs/missing-server", "server_exists": False,
                    "peak_rss_bytes": 8192, "resource_terminated": True,
                },
            ),
            (
                planned_fuzz,
                {
                    "kind": "fuzz", "job_id": planned_fuzz.job_id,
                    "artifact_id": artifact_id, "elapsed_seconds": 1.0,
                    "tests_executed": 1, "cycles_executed": 1,
                    "coverage_point_count": 1, "covered_point_ids": [1],
                    "peak_rss_bytes": 8192, "server_returncode": -15,
                    "fuzzer_returncode": -15, "handshake_succeeded": True,
                    "fifo_cleanup_succeeded": True, "crash_restart_count": 0,
                    "failure_reasons": {"dut_crash": 0, "resource_terminated": 1},
                },
            ),
        )
        for planned, document in documents:
            with self.subTest(kind=document["kind"]), tempfile.TemporaryDirectory() as directory:
                runner = self._fixture(Path(directory), document)
                result = runner(planned)

                self.assertIsInstance(result, ResourceCheckpointEvent)
                self.assertEqual(planned.job_id, result.job_id)
                self.assertEqual(8192, result.observed_peak_rss_bytes)
                runner.persist_checkpoint(result)
                checkpoint = Path(directory) / "runs" / "results" / "checkpoints" / (
                    f"{planned.job_id}.1.checkpoint.json"
                )
                self.assertTrue(checkpoint.is_file())

    def test_fuzz_result_copies_job_identity_and_document_measurements(self) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned = job(
            budget_kind="seconds", budget_value=1,
            artifact_id=artifact_id, build_job_id="build-bound",
        )
        document = {
            "kind": "fuzz",
            "job_id": planned.job_id,
            "artifact_id": artifact_id,
            "elapsed_seconds": 1.25,
            "tests_executed": 20,
            "cycles_executed": 80,
            "coverage_point_count": 3,
            "covered_point_ids": [1, 3],
            "peak_rss_bytes": 4096,
            "server_returncode": -15,
            "fuzzer_returncode": -15,
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), document)
            result = runner(planned)

        self.assertIsInstance(result, FuzzJobResult)
        assert isinstance(result, FuzzJobResult)
        sample = result.samples[0]
        self.assertEqual(planned.job_id, sample["job_id"])
        self.assertEqual(planned.candidate_id, sample["candidate_id"])
        self.assertEqual(planned.harness, sample["harness"])
        self.assertEqual(planned.seed, sample["seed"])
        for field in (
            "elapsed_seconds", "tests_executed", "cycles_executed",
            "covered_point_ids", "peak_rss_bytes", "failure_reasons",
            "server_returncode", "fuzzer_returncode", "handshake_succeeded",
            "fifo_cleanup_succeeded", "crash_restart_count",
        ):
            self.assertEqual(document[field], sample[field])
        for field in (
            "projection_count", "protocol_event_count", "no_progress_cycles",
            "generation_count", "validation_passed",
        ):
            self.assertEqual(0, sample[field])
        self.assertEqual({}, sample["correction_counts"])

    def test_runner_requires_rfuzz_availability_before_subprocess_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = RfuzzExperimentRunner(root, root / "runs" / "results")

            with self.assertRaisesRegex(ValueError, "RFuzz unavailable"):
                runner(build_job())

    def test_fuzz_result_rejects_wrong_job_and_artifact_bindings_independently(self) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned = job(
            budget_kind="seconds", budget_value=1,
            artifact_id=artifact_id, build_job_id="build-bound",
        )
        valid = {
            "kind": "fuzz", "job_id": planned.job_id, "artifact_id": artifact_id,
            "elapsed_seconds": 1.0, "tests_executed": 1, "cycles_executed": 1,
            "coverage_point_count": 1, "covered_point_ids": [1],
            "peak_rss_bytes": 1, "server_returncode": -15,
            "fuzzer_returncode": -15, "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True, "crash_restart_count": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        for field, replacement in (
            ("job_id", "wrong-job"),
            ("artifact_id", "sha256:" + "b" * 64),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                runner = self._fixture(Path(directory), dict(valid, **{field: replacement}))
                with self.assertRaisesRegex(ValueError, field):
                    runner(planned)

    def test_prepare_manifest_preserves_flat_scope_and_refreshes_candidate_pair(self) -> None:
        from myfuzz.harness import StaticPolicyParameters
        from scripts.runs.run_static_projection_campaign import _runtime_manifest, load_campaign

        campaign = load_campaign(
            Path(__file__).resolve().parents[2]
            / "configs" / "experiments" / "static_projection_training.json"
        )
        runtime = _runtime_manifest(
            campaign.targets[0], StaticPolicyParameters(1, 2, 1, "none")
        )
        flat_identity = runtime["harnesses"]["flat-direct"]["coverage_universe"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._install_fixture_paths(root)
            config_path = root / "configs" / "design.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(json.dumps({"out_dir": "runs/design"}), encoding="utf-8")
            instrumentation = root / "runs" / "design" / "instrumented" / "instrumentation.json"
            instrumentation.parent.mkdir(parents=True)
            instrumentation.write_text(json.dumps({
                "coverage_point_count": 1,
                "coverage": [{
                    "module": "top", "kind": "branch", "file": "top.sv", "line": 1,
                }],
            }), encoding="utf-8")
            runner = RfuzzExperimentRunner(root, root / "runs" / "results")
            with patch("myfuzz.integration.rfuzz_runner.subprocess.run") as execute:
                execute.return_value.returncode = 0
                prepared = runner.prepare_manifest(runtime, Path("configs/design.json"))

        self.assertEqual(
            flat_identity,
            prepared["harnesses"]["flat-direct"]["coverage_universe"],
        )
        measured = prepared["coverage_metadata_hash"]
        self.assertEqual(
            measured,
            prepared["harnesses"]["candidate-direct"]["coverage_universe"],
        )
        self.assertEqual(
            measured,
            prepared["harnesses"]["candidate-static"]["coverage_universe"],
        )
        self.assertNotEqual(flat_identity, measured)

    def test_prepare_manifest_rejects_configured_output_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self._install_fixture_paths(root)
            config_path = root / "configs" / "design.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(json.dumps({"out_dir": outside}), encoding="utf-8")
            runner = RfuzzExperimentRunner(root, root / "runs" / "results")
            with patch("myfuzz.integration.rfuzz_runner.subprocess.run") as execute:
                with self.assertRaisesRegex(ValueError, "out_dir.*beneath"):
                    runner.prepare_manifest({}, Path("configs/design.json"))
                execute.assert_not_called()

    @staticmethod
    def _valid_fuzz_document(planned) -> dict[str, object]:
        return {
            "kind": "fuzz",
            "job_id": planned.job_id,
            "artifact_id": planned.execution.server_artifact_id,
            "elapsed_seconds": 1.0,
            "tests_executed": 1,
            "cycles_executed": 1,
            "coverage_point_count": 1,
            "covered_point_ids": [1],
            "peak_rss_bytes": 1,
            "server_returncode": -15,
            "fuzzer_returncode": -15,
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": 0,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }

    def _assert_fuzz_field_rejected(
        self, field: str, value: object, message: str
    ) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned = job(
            budget_kind="seconds",
            budget_value=1,
            artifact_id=artifact_id,
            build_job_id="build-bound",
        )
        document = self._valid_fuzz_document(planned)
        document[field] = value
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), document)
            with self.assertRaisesRegex(ValueError, message):
                runner(planned)

    def test_runner_rejects_driver_failure_before_loading_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), None, exit_code=7)
            with self.assertRaisesRegex(ValueError, "status 7"):
                runner(build_job())

    def test_runner_rejects_missing_result_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), None)
            with self.assertRaisesRegex(ValueError, "did not publish"):
                runner(build_job())

    def test_runner_rejects_stale_result_document(self) -> None:
        planned = job(
            budget_kind="seconds", budget_value=1,
            artifact_id="sha256:" + "a" * 64, build_job_id="build-bound",
        )
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(
                Path(directory), self._valid_fuzz_document(planned), stale=True
            )
            with self.assertRaisesRegex(ValueError, "stale"):
                runner(planned)

    def test_build_rejects_wrong_kind_with_otherwise_closed_schema(self) -> None:
        planned = build_job(artifact_id="sha256:" + "a" * 64)
        document = {
            "kind": "fuzz", "artifact_id": planned.artifact_id,
            "server_path": "runs/server", "server_exists": True,
            "peak_rss_bytes": 1, "resource_terminated": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), document)
            with self.assertRaisesRegex(ValueError, "kind must be build"):
                runner(planned)

    def test_build_rejects_wrong_artifact_with_existing_server(self) -> None:
        planned = build_job(artifact_id="sha256:" + "a" * 64)
        document = {
            "kind": "build", "artifact_id": "sha256:" + "b" * 64,
            "server_path": "runs/server", "server_exists": True,
            "peak_rss_bytes": 1, "resource_terminated": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = root / "runs" / "server"
            server.parent.mkdir(parents=True)
            server.write_text("server", encoding="utf-8")
            runner = self._fixture(root, document)
            with self.assertRaisesRegex(ValueError, "artifact_id"):
                runner(planned)

    def test_build_rejects_missing_declared_server_independently(self) -> None:
        planned = build_job(artifact_id="sha256:" + "a" * 64)
        document = {
            "kind": "build", "artifact_id": planned.artifact_id,
            "server_path": "runs/missing", "server_exists": True,
            "peak_rss_bytes": 1, "resource_terminated": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), document)
            with self.assertRaisesRegex(ValueError, "does not exist"):
                runner(planned)

    def test_fuzz_rejects_invalid_coverage_identifier(self) -> None:
        self._assert_fuzz_field_rejected("covered_point_ids", [2], "covered_point_ids")

    def test_fuzz_rejects_failed_handshake(self) -> None:
        self._assert_fuzz_field_rejected("handshake_succeeded", False, "handshake")

    def test_fuzz_rejects_failed_fifo_cleanup(self) -> None:
        self._assert_fuzz_field_rejected("fifo_cleanup_succeeded", False, "cleanup")

    def test_fuzz_rejects_abnormal_observed_return_code(self) -> None:
        self._assert_fuzz_field_rejected("fuzzer_returncode", 9, "return codes")


if __name__ == "__main__":
    unittest.main()
