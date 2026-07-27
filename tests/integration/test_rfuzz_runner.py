from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from myfuzz.integration import BuildJobResult, FuzzJobResult, RfuzzExperimentRunner
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


class RfuzzExperimentRunnerTest(unittest.TestCase):
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
            })

            result = runner(planned)

        self.assertEqual(BuildJobResult(planned.job_id, 1, planned.artifact_id), result)

    def test_fuzz_result_copies_job_identity_and_document_measurements(self) -> None:
        planned = job(budget_kind="seconds", budget_value=1)
        document = {
            "kind": "fuzz",
            "elapsed_seconds": 1.25,
            "tests_executed": 20,
            "cycles_executed": 80,
            "coverage_point_count": 3,
            "covered_point_ids": [1, 3],
            "peak_rss_bytes": 4096,
            "server_returncode": -15,
            "fuzzer_returncode": 124,
            "handshake_succeeded": True,
            "fifo_cleanup_succeeded": True,
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
        ):
            self.assertEqual(document[field], sample[field])
        for field in (
            "projection_count", "protocol_event_count", "no_progress_cycles",
            "generation_count", "validation_passed",
        ):
            self.assertEqual(0, sample[field])
        self.assertEqual({}, sample["correction_counts"])

    def test_runner_rejects_failed_missing_stale_and_invalid_results(self) -> None:
        planned_build = build_job(artifact_id="sha256:" + "a" * 64)
        planned_fuzz = job(budget_kind="seconds", budget_value=1)
        valid_fuzz = {
            "kind": "fuzz", "elapsed_seconds": 1.0, "tests_executed": 1,
            "cycles_executed": 1, "coverage_point_count": 1,
            "covered_point_ids": [1], "peak_rss_bytes": 1,
            "server_returncode": -15, "fuzzer_returncode": 124,
            "handshake_succeeded": True, "fifo_cleanup_succeeded": True,
            "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
        }
        cases = (
            (planned_build, None, 7, False),
            (planned_build, None, 0, False),
            (planned_build, {"kind": "fuzz"}, 0, False),
            (planned_build, {"kind": "build", "artifact_id": "sha256:" + "b" * 64, "server_path": "missing", "server_exists": False}, 0, False),
            (planned_fuzz, dict(valid_fuzz, covered_point_ids=[2]), 0, False),
            (planned_fuzz, dict(valid_fuzz, handshake_succeeded=False), 0, False),
            (planned_fuzz, dict(valid_fuzz, fifo_cleanup_succeeded=False), 0, False),
            (planned_fuzz, dict(valid_fuzz, fuzzer_returncode=9), 0, False),
            (planned_fuzz, valid_fuzz, 0, True),
        )
        for index, (planned, document, exit_code, stale) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                runner = self._fixture(
                    Path(directory), document, exit_code=exit_code, stale=stale
                )
                with self.assertRaises(ValueError):
                    runner(planned)


if __name__ == "__main__":
    unittest.main()
