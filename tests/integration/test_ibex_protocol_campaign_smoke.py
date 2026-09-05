from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CAMPAIGN_CONFIG = ROOT / "configs/designs/ibex_protocol_composition/campaign.json"
SCRIPT = ROOT / "scripts/run_ibex_protocol_campaign.py"


class IbexProtocolCampaignSmokeTests(unittest.TestCase):
    def test_local_smoke_publishes_complete_atomic_evidence_without_rtl_claim(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT / "src")

        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "ibex-smoke"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--config",
                    str(CAMPAIGN_CONFIG),
                    "--local-smoke",
                    "--duration-seconds",
                    "1",
                    "--seed",
                    "41",
                    "--output-dir",
                    str(output_dir),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            summary = json.loads(result.stdout.strip())
            self.assertEqual("completed", summary["status"])
            report_path = output_dir / "report.json"
            checkpoint_path = output_dir / "checkpoint.json"
            self.assertTrue(report_path.is_file())
            self.assertTrue(checkpoint_path.is_file())

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("campaign_report.v1", report["schema_version"])
            self.assertEqual("completed", report["status"])
            self.assertGreater(report["iterations"], 0)
            self.assertGreater(report["transactions"], 0)
            self.assertEqual(
                {"tl-ul", "apb", "axi4-lite"},
                set(report["protocol_transactions"]),
            )
            self.assertTrue(
                {"ram", "timer", "gpio", "uart", "spi"}.issubset(
                    report["component_transactions"]
                )
            )
            self.assertTrue(report["coverage"])
            self.assertGreater(report["checkpoint_count"], 0)
            self.assertGreater(report["peak_rss_bytes"], 0)
            self.assertEqual(
                "dependency-unavailable",
                report["upstream_dependency"]["status"],
            )
            self.assertFalse(report["evidence"]["rtl_compilation_claimed"])
            self.assertFalse(list(output_dir.glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
