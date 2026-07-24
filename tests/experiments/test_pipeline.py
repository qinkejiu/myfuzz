from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from myfuzz.experiments import PreparedCandidateRuntime, RfuzzAdapter, prepare_candidate_runtime
from myfuzz.harness import HarnessBundle
from myfuzz.protocols import ProtocolDefinitionError, load_builtin_protocol
from tests.runtime_fixtures import load_runtime_documents


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "experiments" / "ibex_opentitan.json"


def _load_config() -> dict[str, object]:
    document = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


class CandidateRuntimePipelineTest(unittest.TestCase):
    def test_builtin_protocol_selection_uses_exact_declared_id(self) -> None:
        plugin = load_builtin_protocol("ready-valid-mmio")

        self.assertEqual("ready-valid-mmio", plugin.protocol_id)
        with self.assertRaises(ProtocolDefinitionError):
            load_builtin_protocol("ready-valid")
        with self.assertRaises(ProtocolDefinitionError):
            load_builtin_protocol("apb")

    def test_declared_protocol_selection_preserves_apb_versions(self) -> None:
        from myfuzz.experiments.pipeline import _declared_protocols

        selected = _declared_protocols(
            (
                {"protocol_id": "apb", "version": "3"},
                {"protocol_id": "apb", "version": "4"},
            )
        )

        self.assertEqual(
            {("apb", "3"), ("apb", "4")},
            {(plugin.protocol_id, plugin.version) for plugin in selected.values()},
        )

    def test_frozen_runtime_fixture_produces_actual_three_mode_job_identities(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        config = _load_config()
        snapshots = tuple(
            json.dumps(document, sort_keys=True)
            for document in (facts, composition, manifest, config)
        )

        with tempfile.TemporaryDirectory() as directory:
            repo_root = Path(directory)
            runtime = prepare_candidate_runtime(facts, composition, manifest, config, repo_root)
            repeated = prepare_candidate_runtime(facts, composition, manifest, config, repo_root)

            self.assertIsInstance(runtime, PreparedCandidateRuntime)
            self.assertIsInstance(runtime.harness_bundle, HarnessBundle)
            self.assertEqual(runtime, repeated)
            self.assertEqual([], list(repo_root.iterdir()))
            self.assertNotIn(repo_root.as_posix(), json.dumps(runtime.manifest_fragment, sort_keys=True))

        self.assertEqual(
            snapshots,
            tuple(
                json.dumps(document, sort_keys=True)
                for document in (facts, composition, manifest, config)
            ),
        )
        bundle = runtime.harness_bundle
        artifacts = {
            "flat-direct": bundle.flat_direct,
            "candidate-direct": bundle.candidate_direct,
            "candidate-depaware": bundle.candidate_depaware,
        }
        self.assertEqual(("ready-valid-mmio",), bundle.protocol_ids)
        self.assertEqual(
            {"flat_direct", "candidate_direct", "candidate_depaware"},
            {artifact.mode for artifact in artifacts.values()},
        )
        self.assertTrue(all(artifact.source_text.endswith("\n") for artifact in artifacts.values()))
        self.assertTrue(all("module " in artifact.source_text for artifact in artifacts.values()))
        self.assertTrue(all("$dump" not in artifact.source_text for artifact in artifacts.values()))
        self.assertNotEqual(bundle.flat_direct.top_content_hash, bundle.candidate_direct.top_content_hash)
        self.assertEqual(
            bundle.candidate_direct.abi.destinations,
            bundle.candidate_depaware.abi.destinations,
        )
        self.assertEqual(
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in bundle.candidate_direct.abi.uses
            ],
            [
                (use.raw_lo, use.raw_hi, use.destination_id, use.destination_lo)
                for use in bundle.candidate_depaware.abi.uses
            ],
        )
        self.assertIsNone(bundle.candidate_direct.projection_plan)
        self.assertIsNotNone(bundle.candidate_depaware.projection_plan)
        self.assertNotEqual(bundle.candidate_direct.source_text, bundle.candidate_depaware.source_text)
        self.assertRegex(bundle.dependency_graph_hash, r"^sha256:[0-9a-f]{64}$")

        plan = runtime.experiment_plan
        self.assertEqual(27, len(plan.jobs))
        self.assertEqual({1, 7, 19}, {job.seed for job in plan.jobs})
        self.assertEqual(set(artifacts), {job.harness for job in plan.jobs})
        for job in plan.jobs:
            artifact = artifacts[job.harness]
            self.assertEqual(artifact.raw_width, job.raw_width)
            self.assertEqual(artifact.top_content_hash, job.instrumented_rtl_hash)
            self.assertEqual(artifact.coverage_universe_id, job.coverage_universe)
            self.assertEqual(bundle.coverage_metadata_hash, job.coverage_metadata_hash)
            command = RfuzzAdapter(ROOT).command(job)
            self.assertNotIn("--waveform", command)
            self.assertNotIn("--trace", command)

        audit = plan.fairness
        self.assertTrue(audit.shared_coverage_metadata)
        self.assertEqual(1, len(audit.candidate_pair_identities))
        identity = audit.candidate_pair_identities[0]
        self.assertEqual(manifest["candidate_id"], identity.candidate_id)
        self.assertEqual(bundle.candidate_direct.raw_width, identity.direct.raw_width)
        self.assertEqual(
            bundle.candidate_direct.top_content_hash,
            identity.direct.instrumented_rtl_hash,
        )
        self.assertEqual(
            bundle.candidate_direct.coverage_universe_id,
            identity.direct.coverage_universe,
        )
        self.assertEqual(bundle.coverage_metadata_hash, identity.direct.coverage_metadata_hash)
        self.assertEqual(identity.direct, identity.depaware)

        self.assertEqual(1, plan.runtime_policy.build_concurrency)
        self.assertIs(plan.runtime_policy.waveforms, False)
        self.assertEqual(128, plan.runtime_policy.replay_queue_capacity)
        self.assertEqual(4_096, plan.runtime_policy.event_ring_capacity)
        self.assertEqual(64, plan.runtime_policy.field_groups_per_batch)
        self.assertFalse(runtime.rfuzz_availability.available)
        self.assertIn("third_party/rfuzz/rfuzz_flow", runtime.rfuzz_availability.missing_paths)
        self.assertIn(
            "third_party/rfuzz/rfuzz_flow/fuzzer/target/release/kfuzz",
            runtime.rfuzz_availability.missing_paths,
        )
        self.assertEqual(bundle.manifest_fragment(), runtime.manifest_fragment)
        json.dumps(runtime.manifest_fragment, sort_keys=True)
        with self.assertRaises(FrozenInstanceError):
            runtime.rfuzz_availability = None

    def test_composition_hash_mismatch_is_rejected_before_planning(self) -> None:
        facts, composition, manifest = load_runtime_documents()
        invalid_manifest = copy.deepcopy(manifest)
        invalid_manifest["composition_ir_hash"] = "sha256:" + "0" * 64

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "composition_ir_hash"):
                prepare_candidate_runtime(
                    facts,
                    composition,
                    invalid_manifest,
                    _load_config(),
                    Path(directory),
                )


if __name__ == "__main__":
    unittest.main()
