"""A fixed-genome bundle binds its immutable run inputs before fresh RTL."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import (
    _evidence_base_bytes, _factory_identity, replay_evidence_bundle,
    save_evidence_bundle, _termination_reserve_floor,
    _final_state_growth_bound, _evidence_record_bound,
)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from tests.scenario.evidence_cli_fixture import make_runner


class EvidenceRunIdentityTests(unittest.TestCase):
    def setUp(self):
        self.runners = []
        self.genome = ScenarioGenome(
            testcase_id='run-identity', direction='IP_TO_IP', path_id='pin',
            schedule_order=('gpio',), max_steps=3,
            actions=(Action('edge', 'gpio', 'pin', 1, 'IP_TO_IP', Trigger('START')),))
        self.targets = (CoverageTarget('out', 'gpio', 'out', 1, 1),)

    def factory(self):
        runner = make_runner()
        self.runners.append(runner)
        return runner

    @staticmethod
    def reindex(bundle):
        index_path = bundle / 'bundle_index.json'
        index = json.loads(index_path.read_bytes())
        index['files'] = {path.relative_to(bundle).as_posix():
                          hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in bundle.rglob('*') if path.is_file()
                          and path.name not in ('bundle_index.json', 'replay_report.json')}
        index_path.write_text(json.dumps(index))

    def test_identity_references_real_inputs_without_inventing_decoder_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'bundle'
            trace = save_evidence_bundle(
                self.genome, self.factory, bundle, coverage_targets=self.targets)
            self.assertTrue((bundle / 'run_identity.json').is_file())
            envelope = json.loads((bundle / 'run_identity.json').read_bytes())
            identity = envelope['identity']
            self.assertEqual('scenario_run_identity.v1', identity['schema_version'])
            self.assertEqual(trace.manifest_sha256, identity['components']['sha256'])
            self.assertEqual(trace.genome_sha256, identity['genome']['sha256'])
            self.assertEqual('not_applicable', identity['dependency_graph']['status'])
            self.assertEqual('fixed_genome_execution', identity['execution_kind'])
            self.assertEqual('coverage.json', identity['feedback']['targets_file'])
            self.assertTrue(replay_evidence_bundle(bundle, self.factory).matches)

    def test_reindexed_identity_declaration_change_rejects_before_factory(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'bundle'
            save_evidence_bundle(self.genome, self.factory, bundle)
            self.assertTrue((bundle / 'run_identity.json').is_file())
            path = bundle / 'run_identity.json'
            envelope = json.loads(path.read_bytes())
            envelope['identity']['checker']['configuration_sha256'] = '0' * 64
            raw = json.dumps(envelope['identity'], sort_keys=True,
                             separators=(',', ':'), ensure_ascii=False).encode()
            envelope['sha256'] = hashlib.sha256(raw).hexdigest()
            path.write_text(json.dumps(envelope))
            self.reindex(bundle)
            before = len(self.runners)
            with self.assertRaisesRegex(ValueError, 'run identity'):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.runners))

    def test_new_bundle_cannot_drop_identity_even_after_reindex(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'bundle'
            save_evidence_bundle(self.genome, self.factory, bundle)
            self.assertTrue((bundle / 'run_identity.json').is_file())
            (bundle / 'run_identity.json').unlink()
            self.reindex(bundle)
            before = len(self.runners)
            with self.assertRaisesRegex(ValueError, 'run identity'):
                replay_evidence_bundle(bundle, self.factory)
            self.assertEqual(before, len(self.runners))

    def test_budget_accounts_for_identity_file_and_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'budgeted'
            save_evidence_bundle(self.genome, self.factory, bundle,
                                 budget=ResourceBudget())
            self.assertTrue((bundle / 'run_identity.json').is_file())
            result = json.loads((bundle / 'result.json').read_bytes())
            actual = sum(path.stat().st_size for path in bundle.rglob('*') if path.is_file())
            self.assertEqual(actual, result['resource_usage']['evidence_bytes'])
            self.assertTrue(replay_evidence_bundle(bundle, self.factory).matches)

    def test_initial_identity_bytes_exceeding_budget_reject_before_begin(self):
        runner = self.factory()
        base = _evidence_base_bytes(self.genome, runner.identity_document(),
                                    _factory_identity(self.factory))
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'too-small'
            with self.assertRaisesRegex(ValueError, 'initial material'):
                save_evidence_bundle(self.genome, self.factory, bundle,
                    budget=ResourceBudget(max_evidence_bytes=1024 * 1024 + base - 1,
                                          evidence_termination_reserve_bytes=1024 * 1024))
            self.assertEqual('created', self.runners[-1]._status)
            self.assertFalse(bundle.exists())

    def test_legacy_budget_replay_uses_its_original_index_reserve(self):
        runner = self.factory()
        budget = ResourceBudget()
        for _ in range(3):
            reserve = (_termination_reserve_floor(
                self.genome, runner, budget, (), include_run_identity=False)
                + 2 * _final_state_growth_bound(self.genome, runner, budget)
                + 3 * _evidence_record_bound(self.genome, runner, budget))
            budget = replace(budget, evidence_termination_reserve_bytes=reserve)
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / 'legacy'
            save_evidence_bundle(self.genome, self.factory, bundle,
                                 budget=ResourceBudget())
            (bundle / 'run_identity.json').unlink()
            result_path = bundle / 'result.json'
            result = json.loads(result_path.read_bytes())
            result['schema_version'] = 'scenario_evidence.v1'
            result.pop('run_identity_sha256')
            result['resource_budget'] = budget.to_document()
            for _ in range(12):
                result_path.write_text(json.dumps(result, sort_keys=True,
                    separators=(',', ':')) + '\n')
                self.reindex(bundle)
                actual = sum(path.stat().st_size for path in bundle.rglob('*')
                             if path.is_file())
                if actual == result['resource_usage']['evidence_bytes']:
                    break
                result['resource_usage']['evidence_bytes'] = actual
            self.assertTrue(replay_evidence_bundle(bundle, self.factory).matches)
