"""Campaign inputs are immutable snapshots, linked to actual cell evidence."""

import hashlib
from itertools import count
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.integration.scenario_campaign import (
    CampaignConfig, IbexTwoGpioBoundProvider, run_scenario_campaign,
)
from myfuzz.integration.cva6_scenario_campaign import Cva6TwoGpioBoundProvider
from tests.integration.test_scenario_campaign import CompleteProvider


class DeclaredProvider(CompleteProvider):
    def campaign_input_files(self, role, manifest):
        return (manifest.name, "nested/reverse.json") if role == "bound" else (manifest.name,)


class CampaignRunIdentityTests(unittest.TestCase):
    def run_campaign(self, directory, provider):
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        (source / "bound.json").write_text('{"frozen": 1}')
        (source / "independent.json").write_text('{"baseline": true}')
        (source / "nested").mkdir()
        (source / "nested/reverse.json").write_text('{"reverse": 2}')
        config = CampaignConfig(source / "bound.json", source / "independent.json")
        provider.original = source / "bound.json"
        output = root / "campaign"
        with patch("myfuzz.integration.scenario_campaign.time.monotonic",
                   side_effect=count(0, 60)):
            report = run_scenario_campaign(config, output, provider=provider)
        return output, report

    def test_declared_closure_preserves_relative_paths_and_provider_uses_snapshots(self):
        provider = DeclaredProvider()
        with tempfile.TemporaryDirectory() as directory:
            output, report = self.run_campaign(directory, provider)
            inputs = report["campaign_inputs"]
            self.assertEqual("provider_declared", inputs["bound"]["closure_status"])
            self.assertEqual({"bound.json", "nested/reverse.json"},
                             {r["relative_path"] for r in inputs["bound"]["files"]})
            self.assertEqual('{"reverse": 2}',
                             (output / "inputs/bound/nested/reverse.json").read_text())
            self.assertTrue(all(path.is_relative_to(output / "inputs")
                                for cell, path in provider.searched))
            self.assertEqual("complete", report["gate_status"])
            self.assertTrue(report["campaign_input_stability"]["snapshots_stable"])

    def test_builtin_providers_declare_only_their_actual_reverse_seed_and_baseline_seeds(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "baseline.json"
            manifest.write_text(json.dumps({"cpu_seed": "cpu.json", "reverse_seed": "ip.json"}))
            ibex, cva6 = IbexTwoGpioBoundProvider(), Cva6TwoGpioBoundProvider()
            self.assertEqual(("baseline.json", "external_gpio_ibex_gpio_closed_two_rounds_variant.json"),
                             ibex.campaign_input_files("bound", manifest))
            self.assertEqual(("baseline.json", "cva6_external_two_gpio_campaign_seed.json"),
                             cva6.campaign_input_files("bound", manifest))
            self.assertEqual(("baseline.json", "cpu.json", "ip.json"),
                             cva6.campaign_input_files("independent", manifest))

    def test_original_mutation_does_not_change_active_inputs_and_invalidates_gate(self):
        class MutatingOriginal(DeclaredProvider):
            def search(self, cell, output, manifest):
                self.original.write_text('{"changed": true}')
                self.asserted_content = manifest.read_text() if cell.strategy != "independent_drive" else self.asserted_content
                return super().search(cell, output, manifest)

        provider = MutatingOriginal()
        with tempfile.TemporaryDirectory() as directory:
            output, report = self.run_campaign(directory, provider)
            self.assertEqual('{"frozen": 1}', provider.asserted_content)
            self.assertFalse(report["campaign_input_stability"]["originals_stable"])
            self.assertTrue(report["campaign_input_stability"]["snapshots_stable"])
            self.assertEqual("incomplete", report["gate_status"])
            self.assertIn("campaign_original_input_changed", report["cells"][0]["gate_failures"])

    def test_snapshot_mutation_invalidates_gate(self):
        class MutatingSnapshot(DeclaredProvider):
            def search(self, cell, output, manifest):
                if not self.searched:
                    manifest.write_text('{"changed_snapshot": true}')
                return super().search(cell, output, manifest)

        with tempfile.TemporaryDirectory() as directory:
            _, report = self.run_campaign(directory, MutatingSnapshot())
            self.assertTrue(report["campaign_input_stability"]["originals_stable"])
            self.assertFalse(report["campaign_input_stability"]["snapshots_stable"])
            self.assertEqual("incomplete", report["gate_status"])

    def test_snapshot_symlink_with_identical_content_invalidates_gate(self):
        class SymlinkSnapshot(DeclaredProvider):
            replace_parent = False

            def search(self, cell, output, manifest):
                if not self.searched:
                    if self.replace_parent:
                        manifest.parent.rename(manifest.parent.with_name("original_bound"))
                        manifest.parent.symlink_to(self.original.parent)
                    else:
                        manifest.unlink()
                        manifest.symlink_to(self.original)
                return super().search(cell, output, manifest)

        for replace_parent in (False, True):
            with self.subTest(replace_parent=replace_parent), tempfile.TemporaryDirectory() as directory:
                provider = SymlinkSnapshot()
                provider.replace_parent = replace_parent
                _, report = self.run_campaign(directory, provider)
                self.assertTrue(report["campaign_input_stability"]["originals_stable"])
                self.assertFalse(report["campaign_input_stability"]["snapshots_stable"])
                self.assertEqual("incomplete", report["gate_status"])

    def test_custom_provider_without_closure_or_execution_identity_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            output, report = self.run_campaign(directory, CompleteProvider())
            self.assertEqual("manifest_only", report["campaign_inputs"]["bound"]["closure_status"])
            self.assertEqual(["bound.json"], [r["relative_path"] for r in report["campaign_inputs"]["bound"]["files"]])
            envelope = json.loads((output / "campaign_run_identity.json").read_text())
            identity = envelope["identity"]
            self.assertEqual(report["campaign_run_identity_sha256"], envelope["sha256"])
            self.assertEqual(envelope["sha256"], hashlib.sha256(json.dumps(
                identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False).encode()).hexdigest())
            self.assertTrue(all(c["execution_identity_status"] == "unavailable" for c in identity["cells"]))
            self.assertNotIn("dependency_graph", identity)

    def test_required_execution_identity_cannot_be_omitted_by_completed_cells(self):
        class RequiredProvider(DeclaredProvider):
            requires_execution_identity = True

        with tempfile.TemporaryDirectory() as directory:
            _, report = self.run_campaign(directory, RequiredProvider())
            self.assertEqual('incomplete', report['gate_status'])
            self.assertTrue(all('cell_execution_identity_missing' in cell['gate_failures']
                                for cell in report['cells']))

    def test_report_version_marker_requires_sidecar_even_for_custom_provider(self):
        class MarkedProvider(DeclaredProvider):
            def search(self, cell, output, manifest):
                result = super().search(cell, output, manifest)
                (output / 'live').mkdir()
                (output / 'live/report.json').write_text(json.dumps({
                    'run_identity_schema': 'scenario_fresh_run_identity.v1',
                    'run_identity_sha256': '0' * 64}))
                return result

        with tempfile.TemporaryDirectory() as directory:
            _, report = self.run_campaign(directory, MarkedProvider())
            self.assertEqual('incomplete', report['gate_status'])
            self.assertTrue(all('cell_execution_identity_missing' in cell['gate_failures']
                                for cell in report['cells']))

    def test_builtin_providers_require_actual_execution_identity(self):
        for provider in (IbexTwoGpioBoundProvider(), Cva6TwoGpioBoundProvider()):
            self.assertIs(True, getattr(provider, 'requires_execution_identity', False))

    def test_incomplete_terminal_identity_is_linked_and_never_completes_cell(self):
        class IncompleteProvider(DeclaredProvider):
            def search(self, cell, output, manifest):
                result = super().search(cell, output, manifest)
                live = output / 'live'
                live.mkdir()
                (live / 'seed.bin').write_bytes(b'seed')
                body = {'schema_version': 'scenario_incomplete_run_identity.v1',
                        'execution_status': 'incomplete',
                        'run_config': {'run_id': cell.cell_id},
                        'artifacts': {'seed.bin': hashlib.sha256(b'seed').hexdigest()}}
                digest = hashlib.sha256(json.dumps(body, sort_keys=True,
                    separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
                (live / 'incomplete_run_identity.json').write_text(json.dumps({
                    'schema_version': 'scenario_incomplete_run_identity_envelope.v1',
                    'identity': body, 'sha256': digest}))
                (live / 'report.json').write_text(json.dumps({
                    'run_identity_schema': 'scenario_incomplete_run_identity.v1',
                    'incomplete_run_identity_sha256': digest}))
                return result

        with tempfile.TemporaryDirectory() as directory:
            output, report = self.run_campaign(directory, IncompleteProvider())
            body = json.loads((output / 'campaign_run_identity.json').read_bytes())['identity']
            self.assertEqual('incomplete', report['gate_status'])
            self.assertTrue(all(c['execution_identity_status'] == 'incomplete'
                                for c in body['cells']))
            self.assertTrue(all('cell_execution_incomplete' in c['gate_failures']
                                for c in report['cells']))

    def test_cell_envelopes_are_associated_with_correct_cell_and_auxiliary_files(self):
        class EnvelopeProvider(DeclaredProvider):
            wrong_run_id = False
            omit_artifact = False

            def search(self, cell, output, manifest):
                result = super().search(cell, output, manifest)
                live = output / "live"
                live.mkdir()
                (live / "seed.bin").write_bytes(bytes(8))
                for name in ("runner_manifest.json", "decoder_manifest.json", "targets.json", "receipts.jsonl", "rfuzz.toml"):
                    (live / name).write_bytes(b"{}")
                (live / "corpus").mkdir()
                (live / "corpus/entry_1.json").write_bytes(b"{}")
                artifacts = {path.relative_to(live).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in live.rglob("*") if path.is_file()}
                if self.omit_artifact:
                    del artifacts["corpus/entry_1.json"]
                body = {"schema_version": "scenario_fresh_run_identity.v1",
                        "run_config": {"run_id": "wrong" if self.wrong_run_id else cell.cell_id},
                        "artifacts": artifacts}
                digest = hashlib.sha256(json.dumps(body, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
                (live / "run_identity.json").write_text(json.dumps({
                    "schema_version": "scenario_fresh_run_identity_envelope.v1", "identity": body, "sha256": digest}))
                (live / "report.json").write_text(json.dumps({"run_identity_sha256": digest}))
                (output / "comparison_policy.json").write_text('{"strategy": "synthetic_test"}')
                return result

        for wrong_id, omit_artifact in ((False, False), (True, False), (False, True)):
            with self.subTest(wrong_id=wrong_id, omit_artifact=omit_artifact), tempfile.TemporaryDirectory() as directory:
                provider = EnvelopeProvider()
                provider.wrong_run_id = wrong_id
                provider.omit_artifact = omit_artifact
                output, report = self.run_campaign(directory, provider)
                identity = json.loads((output / "campaign_run_identity.json").read_text())["identity"]
                association = identity["cells"][0]
                envelope = association["execution_identities"][0]
                self.assertEqual(report["cells"][0]["cell_id"], association["cell_id"])
                self.assertIn("comparison_policy.json", next(iter(association["auxiliary_artifacts"])))
                invalid = wrong_id or omit_artifact
                self.assertEqual("invalid_envelope" if invalid else "validated_envelope", envelope["status"])
                self.assertEqual("invalid" if invalid else "available", association["execution_identity_status"])
                self.assertEqual("incomplete" if invalid else "complete", report["gate_status"])

    def test_missing_builtin_main_inputs_remain_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            config = CampaignConfig(Path(directory) / "bound.json", Path(directory) / "independent.json")
            report = run_scenario_campaign(config, Path(directory) / "campaign",
                provider=IbexTwoGpioBoundProvider(client_binary=Path("/bin/true")))
            self.assertEqual("incomplete", report["gate_status"])
            self.assertTrue(all(cell["status"] == "blocked" for cell in report["cells"]))
            self.assertTrue(all(record["status"] == "missing" for role in report["campaign_inputs"].values()
                                for record in role["files"]))


if __name__ == "__main__":
    unittest.main()
