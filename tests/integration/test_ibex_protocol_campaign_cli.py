from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from myfuzz.integration import campaign
from myfuzz.integration.campaign import (
    build_ibex_campaign_command,
    run_ibex_campaign,
)


ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "configs" / "designs" / "ibex_protocol_composition"
CAMPAIGN_CONFIG = DESIGN / "campaign.json"
DESIGN_CONFIG = DESIGN / "config.json"
COMPOSITION_MANIFEST = DESIGN / "manifest.json"
SCRIPT = ROOT / "scripts" / "run_ibex_protocol_campaign.py"


class IbexProtocolCampaignCliTests(unittest.TestCase):
    def _config_copy(self, temporary: str, **updates: object) -> Path:
        document = json.loads(CAMPAIGN_CONFIG.read_text(encoding="utf-8"))
        document.update(updates)
        path = Path(temporary) / "campaign.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_default_config_is_single_worker_waveform_free_and_memory_bounded(self) -> None:
        document = json.loads(CAMPAIGN_CONFIG.read_text(encoding="utf-8"))

        self.assertEqual("ibex_campaign.v1", document["schema_version"])
        self.assertEqual(1, document["workers"])
        self.assertEqual(1, document["build_jobs"])
        self.assertFalse(document["waveforms"])
        self.assertEqual(512 * 1024 * 1024, document["soft_memory_bytes"])
        self.assertEqual(768 * 1024 * 1024, document["hard_memory_bytes"])
        self.assertEqual(64 * 1024 * 1024, document["token_bytes"])
        self.assertEqual(3600, document["duration_seconds"])
        self.assertEqual(30, document["checkpoint_seconds"])
        self.assertEqual(7, document["seed"])
        self.assertEqual(
            "configs/designs/ibex_protocol_composition/manifest.json",
            document["composition_manifest"],
        )

    def test_command_contains_single_worker_flow_flags_and_the_composition_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_dir = Path(temporary) / "campaign"
            command = build_ibex_campaign_command(
                ROOT,
                CAMPAIGN_CONFIG,
                output_dir,
                duration_seconds=10,
                seed=41,
            )

        self.assertEqual(sys.executable, command[0])
        self.assertIn(str(ROOT / "src/myfuzz/scripts/run_design_flow.py"), command)
        self.assertIn("--stage", command)
        self.assertEqual("all", command[command.index("--stage") + 1])
        self.assertIn("--jobs", command)
        self.assertEqual("1", command[command.index("--jobs") + 1])
        self.assertIn("--fuzz-seconds", command)
        self.assertEqual("10", command[command.index("--fuzz-seconds") + 1])
        self.assertIn("--seed", command)
        self.assertEqual("41", command[command.index("--seed") + 1])
        self.assertIn(str(DESIGN_CONFIG), command)
        self.assertNotIn("--parallel-verilator-build", command)

    def test_zero_duration_fails_closed_before_supervision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "duration_seconds"):
                run_ibex_campaign(
                    CAMPAIGN_CONFIG,
                    Path(temporary) / "campaign",
                    duration_seconds=0,
                    dry_run=True,
                )

    def test_invalid_memory_order_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            config_path = self._config_copy(
                temporary,
                soft_memory_bytes=256 * 1024 * 1024,
                hard_memory_bytes=128 * 1024 * 1024,
            )

            with self.assertRaisesRegex(ValueError, "soft_memory_bytes"):
                run_ibex_campaign(config_path, Path(temporary) / "campaign", dry_run=True)

    def test_non_one_worker_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            config_path = self._config_copy(temporary, workers=2)

            with self.assertRaisesRegex(ValueError, "workers"):
                run_ibex_campaign(config_path, Path(temporary) / "campaign", dry_run=True)

    def test_mixed_command_configuration_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            config_path = self._config_copy(
                temporary,
                command_mode="real",
                command=[sys.executable, "-c", "pass"],
            )

            with self.assertRaisesRegex(ValueError, "configuration-mixed"):
                run_ibex_campaign(config_path, Path(temporary) / "campaign", dry_run=True)

    def test_unknown_cli_command_mode_is_rejected_by_argparse(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--config", str(CAMPAIGN_CONFIG), "--command", "unknown"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("invalid choice", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_real_source_list_returns_dependency_unavailable_without_spawning(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            output_dir = Path(temporary) / "campaign"
            missing_source_list = Path(temporary) / "missing" / "sources.f"
            config_path = self._config_copy(temporary, source_list=str(missing_source_list.relative_to(ROOT)))

            with mock.patch.object(campaign.subprocess, "Popen") as popen:
                result = run_ibex_campaign(config_path, output_dir, dry_run=False)

            self.assertEqual("dependency-unavailable", result["status"])
            self.assertEqual("dependency-unavailable", result["upstream_dependency"]["status"])
            popen.assert_not_called()
            self.assertFalse(output_dir.exists())


if __name__ == "__main__":
    unittest.main()
