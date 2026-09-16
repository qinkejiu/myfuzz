from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def test_selected_top_propagated_width_defines_the_logical_universe(self) -> None:
        instrumentation = {
            "coverage_port": "__vi_coverage",
            "coverage_point_count": 2,
            "coverage": [self.first, self.second],
            "module_coverage": [
                {
                    "module": "top",
                    "active": True,
                    "coverage_width": 4,
                    "local_points": 0,
                    "propagated_child_count": 2,
                }
            ],
        }

        points = run_design_flow.coverage_universe_from_instrumentation(
            instrumentation, "top"
        )

        self.assertEqual(4, len(points))
        self.assertEqual([1, 2, 3, 4], [point["point_id"] for point in points])
        self.assertEqual("top", points[2]["component_role"])
        self.assertNotEqual(points[2]["stable_source_id"], points[3]["stable_source_id"])

    def test_bitmap_accepts_only_logical_or_upstream_aligned_width(self) -> None:
        points = run_design_flow.coverage_universe_from_instrumentation({
            "coverage_point_count": 3,
            "coverage": [
                self.first,
                self.second,
                dict(self.second, signal="branch_2", line=13),
            ],
        })

        self.assertEqual(
            (1,),
            run_design_flow.covered_point_ids_from_bitmap(
                points, [254, 255, 255, 7, 8, 9]
            ),
        )
        with self.assertRaisesRegex(ValueError, "bitmap width"):
            run_design_flow.covered_point_ids_from_bitmap(points, [255] * 7)
        with self.assertRaisesRegex(ValueError, r"bitmap\[5\].*byte"):
            run_design_flow.covered_point_ids_from_bitmap(
                points, [255, 255, 255, 0, 0, "invalid"]
            )

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

    def test_original_rfuzz_endpoints_use_unique_fixed_parent_and_cleanup_exact_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"out_dir": root / "out", "server": root / "servers" / "artifact"}
            ids = run_design_flow.original_rfuzz_server_ids(paths, 2, attempt=3, pid=41)
            self.assertEqual(2, len(ids))
            self.assertRegex(ids[0], r"^myfuzz-[0-9a-f]{12}-41-3-0$")
            self.assertRegex(ids[1], r"^myfuzz-[0-9a-f]{12}-41-3-1$")
            fifo_root = root / "fpga"
            for server_id in ids:
                endpoint = fifo_root / server_id
                endpoint.mkdir(parents=True)
                os.mkfifo(endpoint / "tx.fifo")
                os.mkfifo(endpoint / "rx.fifo")
            self.assertTrue(run_design_flow.rfuzz_fifos_ready(fifo_root, ids))
            self.assertTrue(run_design_flow.cleanup_original_rfuzz_endpoints(fifo_root, ids))
            self.assertFalse(fifo_root.exists())

    def test_original_rfuzz_fuzzer_rejects_multiple_server_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "exactly one server"):
            run_design_flow.fuzz_server_count({"fuzz": {"server_count": 2}})

    def test_original_rfuzz_fuzzer_requires_a_strict_single_server_integer(self) -> None:
        for value in (True, 1.5, "1"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "exactly one server"):
                run_design_flow.fuzz_server_count({"fuzz": {"server_count": value}})

    def test_write_json_rejects_existing_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = root / "result.json"
            target.symlink_to(Path(outside) / "outside.json")
            with self.assertRaisesRegex(ValueError, "output file"):
                run_design_flow.write_json(target, {"safe": True})

    def test_max_runs_is_a_valid_fuzz_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"out_dir": root / "out", "queue": root / "out" / "queue"}
            paths["out_dir"].mkdir(parents=True)
            with patch.object(run_design_flow, "build_fuzzer", return_value=root / "kfuzz"), patch.object(
                run_design_flow,
                "run_fuzz_attempt",
                return_value=("ok", 0, -15, None, True, 1024, False),
            ):
                result = run_design_flow.stage_fuzz(
                    root,
                    {"fuzz": {"max_runs": 1}},
                    root / "config.json",
                    paths,
                    None,
                )
        self.assertEqual(0, result["crash_restart_count"])

    def test_queue_entry_sort_key_uses_numeric_entry_id(self) -> None:
        entries = [Path("entry_10000.json"), Path("entry_9999.json")]
        self.assertEqual(entries[0], max(entries, key=run_design_flow._queue_entry_sort_key))

    def test_reproduce_script_uses_artifact_server_and_supported_input_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crash = root / "crash"
            crash.mkdir()
            script_path = crash / "reproduce.sh"
            run_design_flow.write_reproduce_script(
                script_path,
                root,
                root / "config.json",
                crash / "crash_input.json",
                server_path=root / "out" / "server_artifacts" / ("a" * 64) / "server" / "server",
                fuzzer_path=root / "third_party" / "rfuzz" / "upstream" / "target" / "release" / "kfuzz",
                queue_snapshot=crash / "queue_snapshot",
                server_id="myfuzz-aaaaaaaaaaaa-1-1-0",
            )
            script = script_path.read_text(encoding="utf-8")
        self.assertIn("--input-directory", script)
        self.assertNotIn("--replay-input", script)
        self.assertNotIn("rm -rf", script)
        self.assertIn("server_artifacts", script)

    def test_vendor_latest_counts_accept_integral_json_floats_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            queue = Path(directory)
            (queue / "latest.json").write_text(
                json.dumps({
                    "tests_per_second": {"global_numerator": 100212.0},
                    "cycles_per_second": {"global_numerator": 352288.0},
                }),
                encoding="utf-8",
            )
            self.assertEqual((100212, 352288), run_design_flow._vendor_latest_counts(queue))
            (queue / "latest.json").write_text(
                json.dumps({
                    "tests_per_second": {"global_numerator": 100212.5},
                    "cycles_per_second": {"global_numerator": 352288.0},
                }),
                encoding="utf-8",
            )
            self.assertIsNone(run_design_flow._vendor_latest_counts(queue))

    def test_seeded_fuzzing_requires_the_explicit_campaign_seed_fuzzer(self) -> None:
        with self.assertRaisesRegex(ValueError, "campaign-seed"):
            run_design_flow._validate_vendored_fuzz_config({"seed": 19}, Path("kfuzz"))

        seeded = run_design_flow.seeded_fuzzer_path(Path("/repo"))
        run_design_flow._validate_vendored_fuzz_config(
            {"seed": 19, "fuzzer_path": seeded.relative_to(Path("/repo")).as_posix()},
            seeded,
        )

    def test_stage_fuzz_does_not_count_infrastructure_failure_as_dut_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"out_dir": root / "out", "queue": root / "out" / "queue"}
            paths["out_dir"].mkdir()
            with patch.object(run_design_flow, "build_fuzzer", return_value=root / "kfuzz"), patch.object(
                run_design_flow,
                "run_fuzz_attempt",
                return_value=("infra", 17, -15, None, False, 1024, False),
            ):
                with self.assertRaisesRegex(RuntimeError, "infrastructure"):
                    run_design_flow.stage_fuzz(
                        root,
                        {"fuzz": {"max_cycles": 1}},
                        root / "config.json",
                        paths,
                        None,
                    )

    def test_stage_fuzz_checks_endpoint_cleanup_under_runtime_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fpga_root = root / "fpga"
            fpga_root.mkdir()
            paths = {"out_dir": root / "out", "queue": root / "out" / "queue"}
            paths["out_dir"].mkdir()
            runtime = patch.object(run_design_flow, "_original_rfuzz_runtime")
            runtime_context = runtime.start()
            runtime_context.return_value.__enter__.return_value = fpga_root
            runtime_context.return_value.__exit__.return_value = False
            try:
                with patch.object(
                    run_design_flow,
                    "cleanup_original_rfuzz_endpoints",
                    side_effect=AssertionError("cleanup must remain inside the runtime lock"),
                ), patch.object(
                    run_design_flow,
                    "build_fuzzer",
                    return_value=root / "kfuzz",
                ), patch.object(
                    run_design_flow,
                    "run_fuzz_attempt",
                    return_value=("ok", 0, 0, None),
                ):
                    result = run_design_flow.stage_fuzz(
                        root,
                        {"fuzz": {"max_cycles": 1}},
                        root / "config.json",
                        paths,
                        None,
                    )
            finally:
                runtime.stop()

        self.assertTrue(result["fifo_cleanup_succeeded"])

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

    def test_resource_result_before_handshake_does_not_require_statistics(self) -> None:
        execution = {
            "peak_rss_bytes": 8192,
            "server_returncode": -9,
            "fuzzer_returncode": -15,
            "handshake_succeeded": False,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": 1,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            document = run_design_flow.fuzz_result_document(
                "job-bound", "sha256:" + "a" * 64, execution, missing, (), 0
            )

        self.assertEqual("fuzz-resource", document["kind"])
        self.assertEqual("job-bound", document["job_id"])
        self.assertNotIn("elapsed_seconds", document)
        self.assertNotIn("covered_point_ids", document)

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
            paths["instrumented"].mkdir()
            (paths["instrumented"] / "top.sv").write_text(
                "module top; output wire __vi_coverage; endmodule\n",
                encoding="utf-8",
            )
            (paths["instrumented"] / "sources.f").write_text("top.sv\n", encoding="utf-8")
            (paths["instrumented"] / "instrumentation.json").write_text("{}\n", encoding="utf-8")
            observed = {
                "returncode": -15,
                "peak_rss_bytes": 4096,
                "resource_terminated": True,
            }
            generated = SimpleNamespace(
                coverage=SimpleNamespace(top="top"),
                wrapper_module="wrapper",
                wrapper=root / "harness/wrapper.sv",
                header=root / "harness/dut.hpp",
                raw_abi=SimpleNamespace(source=root / "harness/candidate.sv"),
            )
            command = ["verilator", "--build-jobs", "1"]
            with patch.object(
                run_design_flow, "load_materialized_harness", return_value=generated
            ), patch.object(
                run_design_flow, "build_server_command", return_value=command
            ) as build_command, patch.object(
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
        self.assertEqual(command, monitored.call_args.args[0])
        self.assertEqual("1", command[command.index("--build-jobs") + 1])
        self.assertEqual(2048, monitored.call_args.kwargs["hard_memory_bytes"])
        build_command.assert_called_once()
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
        verilator = flow / "verilator"
        verilator.mkdir(parents=True)
        (verilator / "top.cpp").write_text("// fixture\n", encoding="utf-8")
        (verilator / "fpga_queue.cpp").write_text("// fixture\n", encoding="utf-8")
        (verilator / "fpga_queue.hpp").write_text("// fixture\n", encoding="utf-8")
        (verilator / "fuzzer.hpp").write_text("// fixture\n", encoding="utf-8")

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

    def test_pre_handshake_resource_document_maps_to_empty_checkpoint(self) -> None:
        artifact_id = "sha256:" + "a" * 64
        planned = job(
            budget_kind="seconds", budget_value=1,
            artifact_id=artifact_id, build_job_id="build-bound",
        )
        document = {
            "kind": "fuzz-resource",
            "job_id": planned.job_id,
            "artifact_id": artifact_id,
            "peak_rss_bytes": 8192,
            "server_returncode": -9,
            "fuzzer_returncode": -15,
            "handshake_succeeded": False,
            "fifo_cleanup_succeeded": True,
            "crash_restart_count": 1,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            runner = self._fixture(Path(directory), document)
            result = runner(planned)

        self.assertIsInstance(result, ResourceCheckpointEvent)
        assert isinstance(result, ResourceCheckpointEvent)
        self.assertEqual((), result.samples)
        self.assertEqual(1, result.checkpoint["crash_restart_count"])

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
            config_path.write_text(
                json.dumps({"out_dir": "runs/design", "top": "top"}),
                encoding="utf-8",
            )
            instrumentation = root / "runs" / "design" / "instrumented" / "instrumentation.json"
            instrumentation.parent.mkdir(parents=True)
            instrumentation.write_text(json.dumps({
                "coverage_port": "__vi_coverage",
                "coverage_point_count": 1,
                "coverage": [{
                    "module": "top", "kind": "branch", "file": "top.sv", "line": 1,
                }],
                "module_coverage": [{
                    "module": "top", "active": True, "coverage_width": 1,
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

    def test_prepare_manifest_rejects_symlinked_instrumentation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self._install_fixture_paths(root)
            config_path = root / "configs" / "design.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                json.dumps({"out_dir": "runs/design", "top": "top"}),
                encoding="utf-8",
            )
            instrumentation = Path(outside) / "instrumentation.json"
            instrumentation.write_text(
                json.dumps({"coverage_point_count": 0, "coverage": []}),
                encoding="utf-8",
            )
            linked = root / "runs" / "design" / "instrumented" / "instrumentation.json"
            linked.parent.mkdir(parents=True)
            linked.symlink_to(instrumentation)
            runner = RfuzzExperimentRunner(root, root / "runs" / "results")
            with patch("myfuzz.integration.rfuzz_runner.subprocess.run") as execute:
                execute.return_value.returncode = 0
                with self.assertRaisesRegex(ValueError, "instrumentation.*repository|regular"):
                    runner.prepare_manifest({}, Path("configs/design.json"))

    def test_instrumentation_read_is_pinned_against_parent_directory_swap(self) -> None:
        from myfuzz.harness import StaticPolicyParameters
        from scripts.runs.run_static_projection_campaign import _runtime_manifest, load_campaign

        campaign = load_campaign(
            Path(__file__).resolve().parents[2]
            / "configs" / "experiments" / "static_projection_training.json"
        )
        runtime = _runtime_manifest(
            campaign.targets[0], StaticPolicyParameters(1, 2, 1, "none")
        )
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            self._install_fixture_paths(root)
            config_path = root / "configs" / "design.json"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                json.dumps({"out_dir": "runs/design", "top": "top"}),
                encoding="utf-8",
            )
            instrumented = root / "runs" / "design" / "instrumented"
            instrumented.mkdir(parents=True)
            instrumentation_path = instrumented / "instrumentation.json"
            safe_document = {
                "coverage_port": "__vi_coverage",
                "coverage_point_count": 1,
                "coverage": [{
                    "module": "top", "signal": "safe", "kind": "branch",
                    "file": "top.sv", "line": 1,
                }],
                "module_coverage": [{
                    "module": "top", "active": True, "coverage_width": 1,
                }],
            }
            instrumentation_path.write_text(
                json.dumps(safe_document), encoding="utf-8"
            )
            outside_instrumented = Path(outside) / "instrumented"
            outside_instrumented.mkdir()
            (outside_instrumented / "instrumentation.json").write_text(json.dumps({
                "coverage_port": "__vi_coverage",
                "coverage_point_count": 1,
                "coverage": [{
                    "module": "top", "signal": "outside", "kind": "branch",
                    "file": "outside.sv", "line": 1,
                }],
                "module_coverage": [{
                    "module": "top", "active": True, "coverage_width": 1,
                }],
            }), encoding="utf-8")
            saved = instrumented.with_name("instrumented-saved")
            original_open = os.open
            swapped = False

            def swapping_open(path, *args, **kwargs):
                nonlocal swapped
                final_at = path == "instrumentation.json" and kwargs.get("dir_fd") is not None
                if not swapped and (Path(path) == instrumentation_path or final_at):
                    instrumented.rename(saved)
                    instrumented.symlink_to(outside_instrumented, target_is_directory=True)
                    swapped = True
                return original_open(path, *args, **kwargs)

            runner = RfuzzExperimentRunner(root, root / "runs" / "results")
            with patch("myfuzz.integration.rfuzz_runner.subprocess.run") as execute, patch(
                "myfuzz.integration.rfuzz_runner.os.open", side_effect=swapping_open
            ):
                execute.return_value.returncode = 0
                prepared = runner.prepare_manifest(runtime, Path("configs/design.json"))

        self.assertTrue(swapped)
        expected = run_design_flow.coverage_universe_from_instrumentation(
            safe_document
        )[0]["stable_source_id"]
        self.assertEqual(
            expected, prepared["coverage_universe"][0]["stable_source_id"]
        )

    def test_result_read_is_pinned_against_parent_directory_swap(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            results = root / "runs" / "results"
            results.mkdir(parents=True)
            result_path = results / "result.json"
            result_path.write_text(json.dumps({"source": "safe"}), encoding="utf-8")
            outside_results = Path(outside) / "results"
            outside_results.mkdir()
            (outside_results / "result.json").write_text(
                json.dumps({"source": "outside"}), encoding="utf-8"
            )
            saved = results.with_name("results-saved")
            original_open = os.open
            swapped = False

            def swapping_open(path, *args, **kwargs):
                nonlocal swapped
                final_at = path == "result.json" and kwargs.get("dir_fd") is not None
                if not swapped and (Path(path) == result_path or final_at):
                    results.rename(saved)
                    results.symlink_to(outside_results, target_is_directory=True)
                    swapped = True
                return original_open(path, *args, **kwargs)

            runner = RfuzzExperimentRunner(root, results)
            with patch(
                "myfuzz.integration.rfuzz_runner.os.open", side_effect=swapping_open
            ):
                document = runner._load_result(result_path, 0)

        self.assertTrue(swapped)
        self.assertEqual({"source": "safe"}, document)

    def test_checkpoint_sink_rejects_symlinked_destination_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            results = root / "runs" / "results"
            results.mkdir(parents=True)
            (results / "checkpoints").symlink_to(Path(outside), target_is_directory=True)
            runner = RfuzzExperimentRunner(root, results)
            event = ResourceCheckpointEvent(
                "job-bound", 1, 4096, "hard_memory_limit", {"bound": True}
            )

            with self.assertRaisesRegex(ValueError, "checkpoint"):
                runner.persist_checkpoint(event)

            self.assertEqual([], list(Path(outside).iterdir()))

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
