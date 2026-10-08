"""Explicit local gate exercises the existing real Git/closure verifier."""
import copy
import hashlib
import importlib
import json
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from myfuzz.composition.component_profile import load_component_profile, _source_locator
from myfuzz.local_harness.source_lock import verify_local_source_lock
from tests.integration import test_soc_source_locks as source_fixtures

ROOT = Path(__file__).resolve().parents[2]


class RvxSourceOnlyAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.profile = load_component_profile(
            ROOT / 'configs/cpus/rvx_core/component_profile.json')

    def test_default_gate_rejects_rvx_without_verified_closure(self):
        with self.assertRaisesRegex(ValueError, 'local-source-lock-unverified:rvx_core'):
            verify_local_source_lock(self.profile, base_dir=ROOT)

    def test_explicit_rvx_source_only_gate_returns_authenticated_identity(self):
        result = verify_local_source_lock(
            self.profile, base_dir=ROOT, allow_source_only=True)
        self.assertEqual(result['schema_version'], 'local_source_lock_verification.v1')
        self.assertEqual(result['source_status'], 'source_verified')
        self.assertEqual(result['elaboration_status'], 'elaboration_unverified')
        self.assertEqual(result['runtime_status'], 'runtime_unverified')
        self.assertEqual(result['selected_files'], 1)
        self.assertEqual(result['lock_sha256'], hashlib.sha256(
            (ROOT / 'configs/soc/sources.lock.json').read_bytes()).hexdigest())
        self.assertNotIn('closure_sha256', result)

    def test_source_only_gate_requires_literal_boolean(self):
        for value in (1, 'true', None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'local-source-lock-allow-source-only-bool-required'):
                    verify_local_source_lock(
                        self.profile, base_dir=ROOT, allow_source_only=value)

    def test_source_only_gate_is_limited_to_exact_rvx_source_selection(self):
        with self.assertRaisesRegex(ValueError, 'source-only-component-unsupported'):
            verify_local_source_lock(replace(self.profile, component_id='other'),
                                     base_dir=ROOT, allow_source_only=True)
        for field, value in (('root', 'external_designs/other'),
                             ('top_module', 'other_top'),
                             ('files', ['hardware/other.v'])):
            source = dict(self.profile.source_document)
            source[field] = value
            altered = replace(self.profile, source_document=source,
                              source=_source_locator(source))
            with self.subTest(field=field), self.assertRaisesRegex(
                    ValueError, 'source-only-scope-mismatch'):
                verify_local_source_lock(altered, base_dir=ROOT,
                                         allow_source_only=True)

    def test_source_only_gate_rejects_any_elaboration_evidence_block(self):
        original_loads = json.loads

        def with_evidence(raw, *args, **kwargs):
            document = original_loads(raw, *args, **kwargs)
            for record in document.get('components', []):
                if record.get('id') == 'rvx_core':
                    record['elaboration'] = None
            return document

        with patch('myfuzz.local_harness.source_lock.json.loads', side_effect=with_evidence):
            with self.assertRaisesRegex(ValueError, 'local-source-lock-unverified:rvx_core'):
                verify_local_source_lock(self.profile, base_dir=ROOT,
                                         allow_source_only=True)


class LocalSourceLockTests(unittest.TestCase):
    def setUp(self):
        fixture = source_fixtures.SourceLockTests(methodName='test_clean_selected_sources_and_untracked_manifest')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        self.fixture = fixture
        self.evidence = fixture.enable_elaboration()
        self.base = fixture.base
        self.lock = self.base / 'configs/soc/sources.lock.json'
        self.lock.parent.mkdir(parents=True)
        self.document = {'schema_version': 'soc_sources.v1', 'components': [fixture.record]}
        self.write_lock()
        document = json.loads((ROOT / 'configs/cpus/picorv32/component_profile.json').read_text())
        document['component_id'] = 'fixture'
        document['source'] = copy.deepcopy(fixture.record['source'])
        document['source']['top_port_selection'] = 'all'
        fixture.record['source']['top_port_selection'] = 'all'
        self.write_lock()
        self.profile = load_component_profile(document)

    def write_lock(self):
        self.lock.write_text(json.dumps(self.document))

    def verify(self, profile=None):
        self.assertIsNotNone(importlib.util.find_spec('myfuzz.local_harness.source_lock'), 'missing gate module')
        module = importlib.import_module('myfuzz.local_harness.source_lock')
        return module.verify_local_source_lock(profile or self.profile, base_dir=self.base)

    def test_clean_pin_and_closure_return_lock_identity(self):
        result = self.verify()
        self.assertEqual(result['source_status'], 'source_verified')
        self.assertEqual(result['elaboration_status'], 'elaboration_verified')
        self.assertEqual(result['lock_sha256'], hashlib.sha256(self.lock.read_bytes()).hexdigest())
        self.assertEqual(result['schema_version'], 'local_source_lock_verification.v1')
        self.assertNotIn('replay', result)

    def test_source_facts_mismatch_rejected(self):
        for key, value in [('revision', 'git:' + '0' * 40), ('files', ['other.sv']),
                           ('top_module', 'other'), ('include_roots', ['includes']),
                           ('elaboration', {'parameters': [{'name': 'WIDTH', 'value': '3'}]})]:
            with self.subTest(key=key):
                self.fixture.record['source'][key] = value
                self.write_lock()
                with self.assertRaisesRegex(ValueError, 'local-source-lock'):
                    self.verify()
                self.fixture.record['source'] = copy.deepcopy(dict(self.profile.source_document))

    def test_missing_and_duplicate_component_rejected(self):
        self.fixture.record['id'] = 'other'
        self.write_lock()
        with self.assertRaisesRegex(ValueError, 'local-source-lock-missing-component'):
            self.verify()
        self.fixture.record['id'] = 'fixture'
        self.document['components'].append(copy.deepcopy(self.fixture.record))
        self.write_lock()
        with self.assertRaisesRegex(ValueError, 'duplicate-source-id'):
            self.verify()

    def test_unverified_closure_rejected(self):
        self.fixture.record['elaboration_status'] = 'elaboration_unverified'
        self.write_lock()
        with self.assertRaisesRegex(ValueError, 'local-source-lock-unverified'):
            self.verify()

    def test_dirty_pinned_source_rejected(self):
        (self.fixture.repo / 'top.sv').write_text('module top(input logic reset); endmodule\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_closure_evidence_rejected(self):
        self.evidence.write_text(self.evidence.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'elaboration-evidence-hash-mismatch'):
            self.verify()

    def test_changed_source_even_with_updated_selected_hash_rejected(self):
        (self.fixture.repo / 'top.sv').write_text('module top(input logic reset); endmodule\n')
        self.fixture.refresh()
        self.write_lock()
        with self.assertRaises(ValueError):
            self.verify()

    def test_closure_cannot_borrow_unrelated_root(self):
        closure = json.loads(self.evidence.read_text())
        closure['closure_files'][0]['root'] = 'unrelated'
        self.fixture.rewrite_closure(self.evidence, closure)
        self.write_lock()
        with self.assertRaises(ValueError):
            self.verify()

    def test_closure_only_file_is_checked_against_pin(self):
        helper = self.fixture.repo / 'helper.svh'
        helper.write_text('// pinned elaboration dependency\n')
        self.fixture.git('add', 'helper.svh')
        self.fixture.git('commit', '-qm', 'closure helper')
        revision = 'git:' + self.fixture.git('rev-parse', 'HEAD')
        self.fixture.record['source']['revision'] = revision
        document = json.loads((ROOT / 'configs/cpus/picorv32/component_profile.json').read_text())
        document['component_id'] = 'fixture'
        document['source'] = copy.deepcopy(self.fixture.record['source'])
        self.profile = load_component_profile(document)
        closure = json.loads(self.evidence.read_text())
        closure['closure_files'].append({'root': 'repo', 'path': 'helper.svh',
                                        'sha256': hashlib.sha256(helper.read_bytes()).hexdigest()})
        self.fixture.record['elaboration']['closure_files'] = 2
        self.fixture.rewrite_closure(self.evidence, closure)
        self.write_lock()
        self.assertEqual(self.verify()['elaboration']['closure_files'], 2)
        helper.write_text('// modified dependency\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_normalized_sources_and_locked_elaboration_settings_pass(self):
        from dataclasses import replace
        self.fixture.record['source']['include_roots'] = []
        self.fixture.record['source']['repositories'] = []
        self.fixture.record['typed_parameters'] = []
        self.fixture.record['defines'] = []
        self.write_lock()
        source = dict(self.profile.source_document)
        source.pop('include_roots', None)
        source.pop('repositories', None)
        source['elaboration'] = {'frontend': 'verilator-json', 'parameters': []}
        self.assertEqual(self.verify(replace(self.profile, source_document=source, source=_source_locator(source)))['source_status'], 'source_verified')

    def test_unlocked_parameter_and_define_overrides_rejected(self):
        from dataclasses import replace
        for setting in [{'parameters': [{'name': 'WIDTH', 'value': '9'}]},
                        {'defines': [{'name': 'NEW', 'value': '1'}]},
                        {'frontend': 'other-frontend'}]:
            with self.subTest(setting=setting):
                source = dict(self.profile.source_document)
                source['elaboration'] = {'frontend': 'verilator-json', **setting}
                with self.assertRaisesRegex(ValueError, 'local-source-lock|unsupported-elaboration-frontend'):
                    self.verify(replace(self.profile, source_document=source, source=_source_locator(source)))

    def test_replaced_actual_source_locator_rejected(self):
        from dataclasses import replace
        for changes in ({'revision': 'git:' + '0' * 40},
                        {'source_root': 'different'}, {'files': ('different.sv',)},
                        {'top_module': 'different'}):
            with self.subTest(changes=changes):
                profile = replace(self.profile, source=replace(self.profile.source, **changes))
                with self.assertRaisesRegex(ValueError, 'local-source-lock-profile-source-inconsistent'):
                    self.verify(profile)

    def test_replaced_actual_elaboration_rejected(self):
        from dataclasses import replace
        from myfuzz.composition.component_profile import _source_locator
        document = dict(self.profile.source_document)
        document['elaboration'] = {'frontend': 'verilator-json',
                                   'parameters': [{'name': 'WIDTH', 'value': '9'}]}
        profile = replace(self.profile, source=_source_locator(document))
        with self.assertRaisesRegex(ValueError, 'local-source-lock-profile-source-inconsistent'):
            self.verify(profile)
