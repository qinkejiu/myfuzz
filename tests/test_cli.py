"""Concise module CLI tests."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.__main__ import CHECK_MODULES, ROOT, main


class MyfuzzCliTests(unittest.TestCase):
    def test_check_includes_campaign_build_and_interrupt_policy(self):
        self.assertIn("tests.integration.test_soc_rfuzz_build", CHECK_MODULES)

    def test_check_never_inherits_real_campaign_opt_in(self):
        with patch.dict(os.environ, {"MYFUZZ_SOC_REAL": "1"}), patch(
                "myfuzz.__main__.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0)) as run:
            status = main(["check"])
        self.assertEqual(0, status)
        self.assertNotIn("MYFUZZ_SOC_REAL", run.call_args.kwargs["env"])

    def test_top_level_help_lists_three_commands(self):
        process = subprocess.run(
            [sys.executable, "-m", "myfuzz", "--help"],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertIn("{check,preflight,run}", process.stdout)

    def test_preflight_forwards_compact_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "preflight"
            with patch("myfuzz.__main__.run_matrix", return_value={
                "status": "preflight-only", "tasks_planned": 32,
                "effective_budget_seconds": 0,
            }) as run:
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    status = main(["preflight", "--output", str(output)])
        self.assertEqual(0, status)
        kwargs = run.call_args.kwargs
        self.assertTrue(kwargs["preflight_only"])
        self.assertEqual(300, kwargs["seconds"])
        self.assertEqual(output, run.call_args.args[1])

    def test_run_requires_opt_in_before_calling_matrix(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch(
                "myfuzz.__main__.run_matrix") as run, redirect_stderr(stderr):
            status = main(["run", "--output", "unused", "--client", "/bin/true"])
        self.assertEqual(2, status)
        self.assertFalse(run.called)
        self.assertIn("MYFUZZ_SOC_REAL=1", stderr.getvalue())

    def test_run_passes_explicit_client_without_changing_environment(self):
        before = os.environ.get("MYFUZZ_RFuzz_CLIENT")
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
                os.environ, {"MYFUZZ_SOC_REAL": "1"}, clear=False), patch(
                    "myfuzz.__main__.run_matrix", return_value={
                        "status": "completed", "tasks_planned": 32,
                        "effective_budget_seconds": 9600,
                    }) as run:
            with redirect_stdout(io.StringIO()):
                status = main([
                    "run", "--output", str(Path(temporary) / "run"),
                    "--client", "/bin/true",
                ])
        self.assertEqual(0, status)
        self.assertEqual("/bin/true", run.call_args.kwargs["client"])
        self.assertEqual(before, os.environ.get("MYFUZZ_RFuzz_CLIENT"))


if __name__ == "__main__":
    unittest.main()
