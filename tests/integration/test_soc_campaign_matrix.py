"""P15 matrix expansion and preflight CLI tests."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.run_soc_campaigns import (
    ROOT,
    load_matrix,
    plan_matrix_tasks,
    rebuild_replay_matrix,
    run_matrix,
)


MATRIX = ROOT / "configs/soc/matrix.json"


class SocCampaignMatrixTests(unittest.TestCase):
    def _write_matrix(self, directory: str, mutate) -> Path:
        document = json.loads(MATRIX.read_text(encoding="utf-8"))
        mutate(document)
        path = Path(directory) / "matrix.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_matrix_expands_to_24_main_and_8_bias_off_tasks(self):
        matrix = load_matrix(MATRIX)
        tasks = plan_matrix_tasks(matrix, seconds=300, seed=20260914)
        self.assertEqual(32, len(tasks))
        self.assertEqual(24, sum(not task["bias_off"] for task in tasks))
        self.assertEqual(8, sum(task["bias_off"] for task in tasks))
        self.assertEqual(32, len({task["task_id"] for task in tasks}))

    def test_preflight_creates_no_live_run_and_records_zero_unsupported(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "preflight"
            result = run_matrix(MATRIX, output, seconds=300, seed=20260914,
                                preflight_only=True, root=ROOT)
            self.assertEqual("preflight-only", result["status"])
            self.assertEqual(32, result["tasks_planned"])
            self.assertEqual([], result["unsupported"])
            self.assertEqual(32, len(result["tasks"]))
            self.assertFalse(any((output / str(row["task_id"]).replace("/", "__") / "live").exists()
                                 for row in result["tasks"]))
            self.assertEqual(result, json.loads((output / "manifest.json").read_text()))

    def test_non_preflight_budget_is_at_least_300_seconds_per_task(self):
        with self.assertRaisesRegex(ValueError, "at least 300"):
            run_matrix(MATRIX, Path(tempfile.mkdtemp()) / "out", seconds=299,
                       seed=1, preflight_only=False, root=ROOT)

    def test_loader_rejects_eight_rows_that_do_not_cover_the_required_grid(self):
        def mutate(document):
            source = deepcopy(document["cells"][1])
            document["cells"] = [
                {**source, "cell_id": f"ibex-pulp-copy-{index}"}
                for index in range(8)
            ]

        with tempfile.TemporaryDirectory() as temporary:
            path = self._write_matrix(temporary, mutate)
            with self.assertRaisesRegex(ValueError, "six CPU/family cells"):
                load_matrix(path)

    def test_loader_cross_checks_matrix_rows_against_cell_configs(self):
        def mutate(document):
            document["cells"][0]["config"] = "configs/soc/cva6-opentitan.json"

        with tempfile.TemporaryDirectory() as temporary:
            path = self._write_matrix(temporary, mutate)
            with self.assertRaisesRegex(ValueError, "config id mismatch"):
                load_matrix(path)

    def test_real_matrix_counts_only_completed_measured_and_replayed_time(self):
        short = {
            "status": "completed",
            "effective_fuzz_seconds": 1.0,
            "replay": {"status": "not-requested", "entries": 0},
        }
        with tempfile.TemporaryDirectory() as temporary, patch(
                "scripts.run_soc_campaigns.run_soc_campaign", return_value=short) as campaign:
            result = run_matrix(
                MATRIX, Path(temporary) / "out", seconds=300, seed=1,
                preflight_only=False, root=ROOT,
            )
        self.assertEqual("incomplete", result["status"])
        self.assertEqual(0, result["effective_budget_seconds"])
        self.assertTrue(callable(campaign.call_args.kwargs["rebuilder"]))

    def test_rebuild_replay_executes_every_retained_task(self):
        matrix = load_matrix(MATRIX)
        tasks = plan_matrix_tasks(matrix, seconds=300, seed=11)
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing"
            existing.mkdir()
            (existing / "manifest.json").write_text(json.dumps({
                "schema_version": "soc_campaign_matrix_result.v1",
                "tasks": tasks,
            }), encoding="utf-8")
            for task in tasks:
                corpus = existing / task["task_id"].replace("/", "__") / "live/corpus"
                corpus.mkdir(parents=True)
                (corpus / "entry_0000.json").write_text("{}", encoding="utf-8")

            def builder(config, build_dir):
                calls.append((config["config_id"], Path(build_dir)))
                return object()

            result = rebuild_replay_matrix(
                existing, root / "replayed", matrix_path=MATRIX, root=ROOT,
                builder=builder,
                replayer=lambda _artifact, _corpus: {"status": "passed", "entries": 1},
            )

        self.assertEqual("completed", result["status"])
        self.assertEqual(32, len(calls))
        self.assertTrue(all(row["status"] == "passed" for row in result["tasks"]))

    def test_rebuild_replay_records_unexpected_task_failures(self):
        tasks = plan_matrix_tasks(load_matrix(MATRIX), seconds=300, seed=11)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            existing = root / "existing"
            existing.mkdir()
            (existing / "manifest.json").write_text(json.dumps({
                "schema_version": "soc_campaign_matrix_result.v1",
                "tasks": tasks,
            }), encoding="utf-8")
            for task in tasks:
                corpus = existing / task["task_id"].replace("/", "__") / "live/corpus"
                corpus.mkdir(parents=True)
                (corpus / "entry_0000.json").write_text("{}", encoding="utf-8")

            result = rebuild_replay_matrix(
                existing, root / "replayed", matrix_path=MATRIX, root=ROOT,
                builder=lambda _config, _build_dir: object(),
                replayer=lambda _artifact, _corpus: (_ for _ in ()).throw(LookupError("boom")),
            )

        self.assertEqual("incomplete", result["status"])
        self.assertEqual(32, len(result["tasks"]))
        self.assertTrue(all(row["status"] == "failed" for row in result["tasks"]))

    def test_cli_reports_task_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "cli"
            process = subprocess.run([
                sys.executable, str(ROOT / "scripts/run_soc_campaigns.py"),
                "--matrix", str(MATRIX), "--output", str(output),
                "--seconds", "300", "--seed", "20260914", "--preflight-only",
            ], cwd=ROOT, capture_output=True, text=True, check=False, timeout=60)
            self.assertEqual(0, process.returncode, process.stdout + process.stderr)
            summary = json.loads(process.stdout.strip())
            self.assertEqual(32, summary["tasks_planned"])
            self.assertEqual(24, summary["main_tasks"])
            self.assertEqual(8, summary["bias_off_tasks"])


if __name__ == "__main__":
    unittest.main()
