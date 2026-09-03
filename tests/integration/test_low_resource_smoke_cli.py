from __future__ import annotations

import argparse
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from scripts.run_low_resource_smoke import _override_profile


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_low_resource_smoke.py"


class LowResourceSmokeCliTests(unittest.TestCase):
    def _run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_cli_publishes_report_and_prints_effective_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "cli-report.json"
            completed = self._run_cli("--report", str(report))

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("profile=conservative", completed.stdout)
            self.assertIn("build_jobs=1", completed.stdout)
            self.assertIn("fuzz_jobs=3", completed.stdout)
            document = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("experiment_report.v1", document["report"]["schema_version"])

    def test_cli_preserves_lower_memory_overrides(self) -> None:
        completed = self._run_cli(
            "--soft-memory-mib",
            "128",
            "--hard-memory-mib",
            "256",
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("memory_policy=134217728/268435456 bytes, token=64000000", completed.stdout)

    def test_cli_reduces_token_to_a_lower_soft_memory_ceiling(self) -> None:
        profile = _override_profile(
            argparse.ArgumentParser(),
            argparse.Namespace(soft_memory_mib=1, hard_memory_mib=2),
        )

        self.assertEqual(1 * 1024 * 1024, profile.soft_memory_bytes)
        self.assertEqual(2 * 1024 * 1024, profile.hard_memory_bytes)
        self.assertEqual(1 * 1024 * 1024, profile.token_bytes)

    def test_cli_clamps_memory_overrides_to_conservative_ceilings(self) -> None:
        completed = self._run_cli(
            "--soft-memory-mib",
            "1024",
            "--hard-memory-mib",
            "2048",
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("profile=conservative", completed.stdout)
        self.assertIn("memory_policy=536870912/805306368 bytes, token=64000000", completed.stdout)

    def test_cli_rejects_invalid_memory_order_with_argparse_error(self) -> None:
        completed = self._run_cli(
            "--soft-memory-mib",
            "256",
            "--hard-memory-mib",
            "128",
        )

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("usage:", completed.stderr)
        self.assertIn("soft-memory-mib", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)

    def test_cli_rejects_malformed_memory_with_argparse_error(self) -> None:
        completed = self._run_cli("--soft-memory-mib", "not-a-number")

        self.assertNotEqual(0, completed.returncode)
        self.assertIn("usage:", completed.stderr)
        self.assertIn("memory size must be an integer", completed.stderr)
        self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
