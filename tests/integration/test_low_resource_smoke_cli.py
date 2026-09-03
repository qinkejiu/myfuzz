from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_low_resource_smoke.py"


class LowResourceSmokeCliTests(unittest.TestCase):
    def test_cli_publishes_report_and_prints_effective_profile(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "cli-report.json"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--report", str(report)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("profile=conservative", completed.stdout)
            self.assertIn("build_jobs=1", completed.stdout)
            self.assertIn("fuzz_jobs=3", completed.stdout)
            document = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("experiment_report.v1", document["report"]["schema_version"])


if __name__ == "__main__":
    unittest.main()
