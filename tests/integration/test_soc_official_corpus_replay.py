"""Strict replay of one official RFuzz corpus through three projectors."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.contracts import content_hash
from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.composition.rfuzz_transport import RfuzzInputTransport
from myfuzz.integration.rfuzz_live import replay_identity
from myfuzz.integration.soc_builder import SocCampaignArtifact
from myfuzz.integration.soc_comparison import (
    ARM_NAMES,
    SocComparisonError,
    replay_official_corpus_arms,
)


class _Projector:
    instruction_mode = "test"

    def __init__(self, name: str):
        self.name = name
        self.constraint_hash = f"sha256:{name}-constraints"
        self.repair_counts = {"address_repair": 1 if name == "dependency_repair" else 0}

    def project_records(self, records):
        return tuple(int(value) for value in records)


class OfficialCorpusReplayTests(unittest.TestCase):
    def _artifact(self, root: Path):
        layout = InputLayout(
            "input_layout.v1", 8,
            (LayoutField("cpu:input", "cpu", "data", 8, 0, 7,
                         "bits", {}, port="cpu_input"),),
            "sha256:layout",
        )
        executable = root / "Vmyfuzz_live_tb"
        executable.write_bytes(b"same-executable")
        transport = RfuzzInputTransport(8, layout.layout_hash)
        sources = {"source_files": [{"path": "dut.sv", "sha256": "sha256:source"}]}
        tool = {"path": "/opt/verilator", "version": "Verilator 5.020",
                "sha256": "sha256:verilator", "source": "controlled"}
        build = {
            "composition_hash": "sha256:composition",
            "layout_hash": layout.layout_hash,
            "policy_hash": "sha256:policy",
            "constraint_hash": "sha256:dependency_repair-constraints",
            "coverage_kind": "source-instrumented-rtl-branch-u8-saturating",
            "structure_audit": {"status": "pass"},
            "sources": sources,
            "tool_identity": tool,
        }
        arms = {name: _Projector(name) for name in ARM_NAMES}
        artifact = SocCampaignArtifact(
            layout=layout, transport=transport, executable=executable,
            coverage_ports=(("__vi_coverage", 0),),
            projector=arms["dependency_repair"],
            coverage_kind=build["coverage_kind"],
            simulator="verilator", isolate_tests=True,
            build_document=build, projection_arms=arms,
        )
        return artifact

    def _campaign_report(self, artifact):
        build = artifact.build_document
        return {
            "execution_kind": "official_rfuzz_source_backed_soc",
            "status": "completed", "final_status": "passed",
            "artifact": {
                "composition_hash": build["composition_hash"],
                "layout_hash": build["layout_hash"],
                "coverage_kind": build["coverage_kind"],
                "structure_audit": {"status": "pass"},
                "source_closure": build["sources"],
                "tool_identity": build["tool_identity"],
                "executable_sha256": "sha256:" + hashlib.sha256(
                    artifact.executable.read_bytes()).hexdigest(),
            },
            "corpus": {"status": "verified", "entries": 1},
            "rtl_execution": {"tests": 1, "coverage_records": 1},
            "fifo_reply_receipts": [{
                "input_sha256": "sha256:input",
                "coverage_sha256": "sha256:coverage",
                "status": "fifo_reply_and_rtl_completed",
                "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
            }],
        }

    def _write_official_corpus(self, artifact: SocCampaignArtifact, root: Path):
        corpus = root / "corpus"
        corpus.mkdir()
        payload = artifact.transport.pack(1)
        original = replay_identity(artifact, payload)
        document = {
            "entry": {"inputs": list(payload)},
            "trace_bits": [1, 0, 0, 0, 0, 0],
            "replay_identity": original,
        }
        (corpus / "entry_0000.json").write_text(json.dumps(document), encoding="utf-8")
        (root / "corpus_manifest.json").write_text(json.dumps({
            "schema_version": "rfuzz_corpus_manifest.v1",
            "coverage_transport": "sysv-shared-memory-rfuzz-coverage-buffer",
            "entries": 1,
            "layout_hash": artifact.layout.layout_hash,
            "binary_sha256": original["binary_sha256"],
            "replays": [{"file": "entry_0000.json",
                         "input_sha256": original["raw_sha256"],
                         "coverage_sha256": "sha256:coverage",
                         "trace_sha256": "sha256:" + hashlib.sha256(
                             bytes([1, 0, 0, 0, 0, 0])).hexdigest(),
                         "coverage_verified": True,
                         "shared_memory_exchange_verified": True,
                         "layout_hash": artifact.layout.layout_hash,
                         "constraint_hash": original["constraint_hash"],
                         "binary_sha256": original["binary_sha256"]}],
        }), encoding="utf-8")
        return corpus

    def test_one_official_corpus_is_replayed_by_all_three_arms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            corpus = self._write_official_corpus(artifact, root)

            class FakeSimulator:
                def __init__(self, view, *, timeout_seconds):
                    self.view = view
                    self.last_diagnostics = ()
                    self.last_peer_events = ()

                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

                def run_test(self, records):
                    return b"\1"

            with patch("myfuzz.integration.rfuzz_simulator.RtlSimulator", FakeSimulator):
                result = replay_official_corpus_arms(
                    artifact, corpus,
                    campaign_report=self._campaign_report(artifact),
                    output_dir=root / "replay",
                )
        self.assertEqual("official-rfuzz-corpus-replay-3arm", result["execution_mode"])
        self.assertEqual(ARM_NAMES, tuple(result["arms"]))
        self.assertEqual(1, result["shared"]["corpus_entries"])
        self.assertTrue(result["shared"]["identity_shared"])
        self.assertEqual(3, len(result["arm_reports"]))

    def test_tool_identity_drift_is_refused_before_rtl_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            corpus = self._write_official_corpus(artifact, root)
            report = self._campaign_report(artifact)
            report["artifact"]["tool_identity"] = {"version": "Verilator 5.051"}
            with self.assertRaisesRegex(SocComparisonError, "identity-mismatch:tool_identity"):
                replay_official_corpus_arms(
                    artifact, corpus, campaign_report=report,
                    output_dir=root / "replay",
                )

    def test_manifest_entry_identity_and_trace_drift_are_refused(self):
        for field, value, message in (
            ("layout_hash", "sha256:other-layout", "entry-identity-mismatch:layout"),
            ("binary_sha256", "sha256:other-binary", "entry-identity-mismatch:binary"),
            ("trace_sha256", "sha256:other-trace", "entry-trace-mismatch"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifact = self._artifact(root)
                corpus = self._write_official_corpus(artifact, root)
                manifest_path = root / "corpus_manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest["replays"][0][field] = value
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(SocComparisonError, message):
                    replay_official_corpus_arms(
                        artifact, corpus, campaign_report=self._campaign_report(artifact),
                        output_dir=root / "replay",
                    )

    def test_seeded_or_unverified_corpus_is_not_called_official(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = self._artifact(root)
            corpus = self._write_official_corpus(artifact, root)
            report = self._campaign_report(artifact)
            report["execution_kind"] = "seeded-corpus-real-rtl"
            with self.assertRaisesRegex(SocComparisonError, "official-execution-required"):
                replay_official_corpus_arms(
                    artifact, corpus, campaign_report=report,
                    output_dir=root / "replay",
                )


if __name__ == "__main__":
    unittest.main()
