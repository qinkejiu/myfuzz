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


def _corpus_manifest():
    return {
        "schema_version": "rfuzz_corpus_manifest.v1",
        "coverage_transport": "sysv-shared-memory-rfuzz-coverage-buffer",
        "entries": 1,
        "replays": [{
            "file": "entry_0000.json",
            "input_sha256": "sha256:input",
            "coverage_sha256": "sha256:coverage",
            "coverage_verified": True,
        }],
    }


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
        artifact = SimpleNamespace(
            transport=_Transport(),
            build_document={
                "composition_hash": "sha256:composition",
                "layout_hash": "sha256:layout",
                "policy_hash": "sha256:policy",
                "constraint_hash": "sha256:constraint",
                "image_hash": "sha256:image",
                "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
                "mode": "cpu_only",
                "structure_audit": {"status": "pass", "summary": {"status": "pass"}},
                "unsupported_capabilities": [],
                "sources": {"source_count": 1, "source_files": [{"path": "dut.sv"}]},
            },
        )
        def runner(config, built, client, live_dir):
            self.assertIs(built, artifact)
            self.assertEqual(Path(sys.executable), client)
            return {
                "returncode": 0,
                "tests": 2,
                "duration_seconds": 1.0,
                "corpus_entries": 1,
                "corpus_manifest": _corpus_manifest(),
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
                "input_projection": {
                    "raw_samples": 2, "projected_samples": 2,
                    "projection_rejections": 0, "raw_unique": 2,
                    "projected_unique": 1,
                    "repair_counts": {"address_repair": 1},
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
            self.assertEqual("verified", result["artifact"]["status"])
            self.assertEqual("pass", result["artifact"]["structure_audit"]["status"])
            self.assertEqual("verified", result["artifact"]["bug_attribution"]["generator_boundary"])
            self.assertEqual(2, result["input_projection"]["raw_samples"])
            self.assertEqual(1, result["input_projection"]["repair_counts"]["address_repair"])
            self.assertEqual("passed", result["replay"]["status"])
            self.assertFalse((Path(temporary) / "run/.report.json.tmp").exists())

    def test_campaign_uses_environment_selected_client_for_runner(self):
        artifact = SimpleNamespace(
            transport=_Transport(),
            build_document={
                "composition_hash": "sha256:composition",
                "layout_hash": "sha256:layout",
                "policy_hash": "sha256:policy",
                "constraint_hash": "sha256:constraint",
                "structure_audit": {"status": "pass", "summary": {"status": "pass"}},
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            verilator = root / "verilator"
            verilator.write_text("#!/bin/sh\nprintf 'Verilator 5.020 test\\n'\n", encoding="utf-8")
            verilator.chmod(0o755)
            config = _config(verilator=str(verilator))
            config.pop("client_binary")
            seen = []

            def runner(_config, _artifact, client, _live_dir):
                seen.append(Path(client))
                return {
                    "returncode": 0, "tests": 1, "duration_seconds": 1.0,
                    "corpus_entries": 1, "corpus_manifest": _corpus_manifest(),
                    "fifo_reply_receipts": [{
                        "input_sha256": "sha256:input", "coverage_sha256": "sha256:coverage",
                        "status": "fifo_reply_and_rtl_completed",
                        "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
                    }],
                    "actual_rtl_execution": {"tests": 1, "coverage_records": 1,
                                              "execution_totals": {"source_transactions": 1,
                                                                    "target_transactions": 1}},
                    "source_target_transactions": {"source": {"cpu": 1}, "target": {"mmio": 1}},
                    "remaining_segments": [],
                }

            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe), patch(
                           "myfuzz.integration.soc_campaign.replay_corpus",
                           return_value={"status": "passed", "entries": 1}):
                result = run_soc_campaign(
                    config, root / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1",
                                 "MYFUZZ_RFuzz_CLIENT": str(Path(sys.executable).resolve())},
                    builder=lambda *_: artifact, runner=runner,
                    rebuilder=lambda *_: artifact,
                )
        self.assertEqual("completed", result["status"])
        self.assertEqual([Path(sys.executable).resolve()], seen)

    def test_production_campaign_rejects_unadmitted_toolchain_before_build(self):
        """A real campaign must not render a DUT with an unknown RFuzz tool."""
        with tempfile.TemporaryDirectory() as temporary, patch(
            "myfuzz.integration.soc_campaign.probe_soc_dependencies",
            side_effect=self._ready_probe,
        ), patch(
            "myfuzz.integration.soc_builder.build_soc_campaign_artifact",
            side_effect=AssertionError("builder must not run before tool admission"),
        ):
            result = run_soc_campaign(
                _config(client_binary=str(Path(sys.executable).resolve())),
                Path(temporary) / "run", root=ROOT,
                # The environment names the compiler explicitly, so the campaign
                # really is given an unadmitted tool now that a validated bundled
                # Verilator is installed: without the override this test would
                # resolve that tool and the builder would be reached.
                environment={"MYFUZZ_SOC_REAL": "1",
                             "MYFUZZ_SERVER_VERILATOR_BIN": str(Path(temporary) / "no-such-verilator")},
                rebuilder=lambda *_: None,
            )
        self.assertEqual("failed", result["status"])
        self.assertEqual("rfuzz-verilator-unavailable", result["final_status"])
        self.assertEqual("rfuzz-verilator-unavailable", result["errors"][0]["category"])

    def test_public_preflight_keeps_environment_values_out_of_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            verilator = root / "verilator"
            verilator.write_text("#!/bin/sh\nprintf 'Verilator 5.020 test\\n'\n",
                                 encoding="utf-8")
            verilator.chmod(0o755)
            config = _config(
                client_binary=str(Path(sys.executable).resolve()),
                verilator=str(verilator),
            )
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe):
                result = run_soc_campaign(
                    config, root / "run", root=root,
                    environment={"MYFUZZ_SOC_REAL": "1", "SECRET_TOKEN": "do-not-publish"},
                    preflight_only=True,
                )
        toolchain = result["preflight"]["toolchain"]
        self.assertTrue(toolchain["ready"])
        self.assertNotIn("verilator_environment", toolchain)
        self.assertNotIn("SECRET_TOKEN", repr(result))

    def test_completion_rejects_each_missing_acceptance_evidence(self):
        artifact = SimpleNamespace(transport=_Transport())

        def complete_result():
            return {
                "returncode": 0,
                "tests": 2,
                "duration_seconds": 1.0,
                "corpus_entries": 1,
                "corpus_manifest": _corpus_manifest(),
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

        cases = [
            ("requested_fuzz_duration", lambda row: row.update(duration_seconds=0.1)),
            ("rtl_coverage", lambda row: row["actual_rtl_execution"].update(
                coverage_records=0),
            ),
            ("source_transactions", lambda row: row["source_target_transactions"].update(
                source={}),
            ),
            ("target_transactions", lambda row: row["source_target_transactions"].update(
                target={}),
            ),
            ("verified_corpus", lambda row: row.update(corpus_manifest=None)),
            ("verified_corpus", lambda row: row.update(corpus_manifest={"entries": 1})),
            ("clean_cleanup", lambda row: row.pop("remaining_segments")),
            ("completed_fifo_receipt", lambda row: row["fifo_reply_receipts"][0].update(
                status="failed"),
            ),
        ]

        for expected_gap, mutate in cases:
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
            builds = []

            def builder(_config, build_dir):
                builds.append(Path(build_dir))
                return artifact

            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe), patch(
                           "myfuzz.integration.soc_campaign.replay_corpus",
                           return_value={"status": "passed", "entries": 1}):
                result = run_soc_campaign(
                    _config(), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=builder, runner=lambda *_: row,
                )
            self.assertEqual("completed", result["status"])
            self.assertEqual(2, len(builds))
            self.assertEqual("rebuild", builds[1].name)

        for missing in ("returncode",):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                row = complete_result()
                row.pop(missing)
                with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                           side_effect=self._ready_probe), patch(
                               "myfuzz.integration.soc_campaign.replay_corpus",
                               return_value={"status": "passed", "entries": 1}):
                    result = run_soc_campaign(
                        _config(), Path(temporary) / "run", root=ROOT,
                        environment={"MYFUZZ_SOC_REAL": "1"},
                        builder=lambda *_: artifact, runner=lambda *_: row,
                        rebuilder=lambda *_: artifact,
                    )
                self.assertEqual("incomplete-evidence", result["status"])

        with tempfile.TemporaryDirectory() as temporary:
            row = complete_result()
            row.pop("source_target_transactions")
            with patch("myfuzz.integration.soc_campaign.probe_soc_dependencies",
                       side_effect=self._ready_probe), patch(
                           "myfuzz.integration.soc_campaign.replay_corpus",
                           return_value={"status": "passed", "entries": 1}):
                result = run_soc_campaign(
                    _config(source_target_transactions={
                        "source": {"declared": 9}, "target": {"declared": 9},
                    }), Path(temporary) / "run", root=ROOT,
                    environment={"MYFUZZ_SOC_REAL": "1"},
                    builder=lambda *_: artifact, runner=lambda *_: row,
                    rebuilder=lambda *_: artifact,
                )
            self.assertEqual("declared-not-observed",
                             result["source_target_transactions"]["status"])
            self.assertEqual("incomplete-evidence", result["status"])

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
