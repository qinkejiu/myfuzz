"""P14 SoC campaign evidence and fail-closed opt-in tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.soc_campaign import (
    SocCampaignSoftwareTrap,
    preflight_soc_campaign,
    run_soc_campaign,
)


ROOT = Path(__file__).resolve().parents[2]


def _config(**overrides):
    value = {
        "config_id": "ibex-pulp",
        "cell_id": "ibex-pulp",
        "cpu": "ibex",
        "families": ["pulp"],
        "peripherals": ["pulp_gpio", "pulp_spi"],
        "source_paths": ["configs/soc/sources.lock.json"],
        "simulator": "icarus",
        "client_binary": sys.executable,
        "duration_seconds": 1,
        "seed": 7,
        "seed_cycles": 3,
        "reset_contract": {
            "driver": True, "memory": True, "cpu": True,
            "peripherals": True, "irq": True, "coverage": True,
        },
    }
    value.update(overrides)
    return value


class _Transport:
    def document(self):
        return {"schema_version": "rfuzz_input_transport.v1", "byte_count": 8,
                "transport_hash": "sha256:test-transport"}


class SocRfuzzCampaignTests(unittest.TestCase):
    @staticmethod
    def _ready_probe(*args, **kwargs):
        return {"schema_version": "soc_dependency_probe.v1", "ready": True,
                "status": "ready", "missing": [], "simulator_path": "/tool"}

    def test_preflight_never_launches_without_real_opt_in(self):
        config = _config()
        with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                   side_effect=self._ready_probe):
            report = preflight_soc_campaign(config, root=ROOT, environment={})
        self.assertFalse(report["opt_in"])
        self.assertTrue(report["dependencies"]["ready"])
        self.assertEqual("preflight never launches a client; real run requires MYFUZZ_SOC_REAL=1",
                         report["policy"])
        with tempfile.TemporaryDirectory() as temporary:
            called = []
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe):
                result = run_soc_campaign(
                    config, Path(temporary) / "run", root=ROOT, environment={},
                    builder=lambda *_: called.append(True),
                )
            self.assertEqual("opt-in-required", result["status"])
            self.assertEqual([], called)
            self.assertTrue((Path(temporary) / "run/report.json").is_file())

    def test_success_records_fifo_rtl_transport_and_corpus_identity(self):
        artifact = SimpleNamespace(transport=_Transport())
        def runner(config, built, client, live_dir):
            self.assertIs(built, artifact)
            self.assertEqual(Path(sys.executable), client)
            return {
                "returncode": 0,
                "tests": 2,
                "duration_seconds": 1.0,
                "corpus_entries": 1,
                "corpus_manifest": {
                    "schema_version": "rfuzz_corpus_manifest.v1",
                    "entries": 1,
                },
                "fifo_reply_receipts": [{
                    "input_sha256": "sha256:input",
                    "coverage_sha256": "sha256:coverage",
                    "status": "fifo_reply_and_rtl_completed",
                    "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
                }],
                "actual_rtl_execution": {
                    "tests": 2, "coverage_records": 1,
                    "execution_totals": {"source_transactions": 2, "target_transactions": 2},
                },
                "source_target_transactions": {
                    "source": {"ibex": 2}, "target": {"pulp_gpio": 1},
                },
                "remaining_segments": [], "removed_owned_segments": [11],
            }
        with tempfile.TemporaryDirectory() as temporary:
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe), patch(
                           "myfuzz.integration.soc_campaign.replay_corpus",
                           return_value={"status": "passed", "entries": 1}):
                result = run_soc_campaign(
                    _config(), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=lambda *_: artifact, runner=runner,
                    rebuilder=lambda *_: artifact,
                )
            self.assertEqual("completed", result["status"])
            self.assertEqual("passed", result["final_status"])
            self.assertEqual(1, len(result["fifo_reply_receipts"]))
            self.assertEqual("observed", result["rtl_execution"]["status"])
            self.assertEqual("observed", result["source_target_transactions"]["status"])
            self.assertEqual("observed", result["input_transport"]["status"])
            self.assertEqual("passed", result["replay"]["status"])
            self.assertFalse((Path(temporary) / "run/.report.json.tmp").exists())

    def test_completion_rejects_each_missing_acceptance_evidence(self):
        artifact = SimpleNamespace(transport=_Transport())

        def complete_result():
            return {
                "returncode": 0,
                "tests": 2,
                "duration_seconds": 1.0,
                "corpus_entries": 1,
                "corpus_manifest": {
                    "schema_version": "rfuzz_corpus_manifest.v1",
                    "entries": 1,
                },
                "fifo_reply_receipts": [{
                    "input_sha256": "sha256:input",
                    "coverage_sha256": "sha256:coverage",
                    "status": "fifo_reply_and_rtl_completed",
                    "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
                }],
                "actual_rtl_execution": {
                    "tests": 2,
                    "coverage_records": 1,
                    "execution_totals": {
                        "source_transactions": 2,
                        "target_transactions": 2,
                    },
                },
                "source_target_transactions": {
                    "source": {"ibex": 2},
                    "target": {"pulp_gpio": 1},
                },
                "remaining_segments": [],
            }

        cases = {
            "requested_fuzz_duration": lambda row: row.update(duration_seconds=0.1),
            "rtl_coverage": lambda row: row["actual_rtl_execution"].update(
                coverage_records=0),
            "source_transactions": lambda row: row["source_target_transactions"].update(
                source={}),
            "target_transactions": lambda row: row["source_target_transactions"].update(
                target={}),
            "verified_corpus": lambda row: row.update(corpus_manifest=None),
            "completed_fifo_receipt": lambda row: row["fifo_reply_receipts"][0].update(
                status="failed"),
        }

        for expected_gap, mutate in cases.items():
            with self.subTest(expected_gap=expected_gap), tempfile.TemporaryDirectory() as temporary:
                row = complete_result()
                mutate(row)

                def runner(*_args):
                    return row

                with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                           side_effect=self._ready_probe), patch(
                               "myfuzz.integration.soc_campaign.replay_corpus",
                               return_value={"status": "passed", "entries": 1}):
                    result = run_soc_campaign(
                        _config(), Path(temporary) / "run", root=ROOT,
                        environment={"MYFUZZ_SOC_REAL": "1"},
                        builder=lambda *_: artifact, runner=runner,
                        rebuilder=lambda *_: artifact,
                    )
                self.assertEqual("incomplete-evidence", result["status"])
                self.assertIn(expected_gap, result["evidence_missing"])

        with tempfile.TemporaryDirectory() as temporary:
            row = complete_result()
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe):
                result = run_soc_campaign(
                    _config(), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=lambda *_: artifact, runner=lambda *_: row,
                )
            self.assertEqual("incomplete-evidence", result["status"])
            self.assertIn("rebuild_replay", result["evidence_missing"])

    def test_compile_failure_is_persisted_and_classified(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe):
                result = run_soc_campaign(
                    _config(), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=lambda *_: (_ for _ in ()).throw(RuntimeError("compiler failed")),
                )
            self.assertEqual("failed", result["status"])
            self.assertEqual("compile", result["errors"][0]["category"])
            self.assertEqual("failed", result["final_status"])
            self.assertTrue((Path(temporary) / "run/report.json").is_file())

    def test_legal_software_trap_is_not_protocol_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe):
                result = run_soc_campaign(
                    _config(), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=lambda *_: (_ for _ in ()).throw(SocCampaignSoftwareTrap("legal software trap")),
                )
            self.assertEqual("software_trap", result["errors"][0]["category"])
            self.assertNotEqual("protocol_or_model", result["errors"][0]["category"])

    def test_zero_probe_cannot_be_declared_as_campaign(self):
        with self.assertRaisesRegex(ValueError, "zero-input-probe"):
            preflight_soc_campaign(_config(zero_input_probe=True), root=ROOT, environment={})


if __name__ == "__main__":
    unittest.main()
