"""P15 matrix expansion and preflight CLI tests."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.run_soc_campaigns import ROOT, load_matrix, plan_matrix_tasks, run_matrix


MATRIX = ROOT / "configs/soc/matrix.json"


class SocCampaignMatrixTests(unittest.TestCase):
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
