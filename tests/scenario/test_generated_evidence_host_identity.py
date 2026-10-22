"""Evidence replay verifies the generated per-harness host source closure."""
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import _verify_evidence_host_identity
from myfuzz.scenario.host_identity import (HARNESS_HOST_SOURCE_PATHS,
    HOST_SOURCE_PATHS, host_source_identity, verify_host_source_identity)


class GeneratedEvidenceHostIdentityTests(unittest.TestCase):
    def test_native_completion_is_added_only_to_the_explicit_harness_v2_closure(self):
        native_paths = {
            'src/myfuzz/scenario/native_instruction_bus_completion.py',
            'src/myfuzz/scenario/session_runtime.py',
        }
        self.assertEqual(len(HOST_SOURCE_PATHS), 34)
        self.assertTrue(native_paths.isdisjoint(HOST_SOURCE_PATHS))
        self.assertTrue(native_paths.issubset(HARNESS_HOST_SOURCE_PATHS))
        legacy = host_source_identity()
        self.assertEqual(legacy['schema_version'], 'scenario_host_sources.v1')
        self.assertEqual(tuple(row['path'] for row in legacy['files']), HOST_SOURCE_PATHS)

    def test_harness_v2_refuses_missing_native_completion_source_path(self):
        generated = {'schema_version': 'generated_local_session_identity.v1',
                     'build_identity': {'inputs': []}}
        saved = host_source_identity(harness_identities=(generated,))
        self.assertIn('src/myfuzz/scenario/native_instruction_bus_completion.py',
                      {row['path'] for row in saved['files']})
        saved['files'] = [row for row in saved['files'] if row['path'] !=
                          'src/myfuzz/scenario/native_instruction_bus_completion.py']
        with self.assertRaisesRegex(ValueError, 'host source identity mismatch'):
            verify_host_source_identity(saved, harness_identities=(generated,))

    def test_harness_host_identity_schema_tampering_is_refused(self):
        generated = {'schema_version': 'generated_local_session_identity.v1',
                     'build_identity': {'inputs': []}}
        saved = host_source_identity(harness_identities=(generated,))
        saved['schema_version'] = 'scenario_harness_host_sources.v3'
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            verify_host_source_identity(saved)

    def test_build_input_digest_must_agree_with_saved_host_source_digest(self):
        generated = {'schema_version': 'generated_local_session_identity.v1',
                     'build_identity': {'inputs': [{
                         'path': 'src/myfuzz/scenario/runner.py',
                         'sha256': '0' * 64}]}}
        saved = host_source_identity(harness_identities=(generated,))
        with self.assertRaisesRegex(ValueError, 'build input.*sha256'):
            verify_host_source_identity(saved, harness_identities=(generated,))

    def test_generated_sessions_pass_their_build_closures_to_verifier(self):
        generated = {'schema_version': 'generated_local_session_identity.v1',
                     'build_identity': {'inputs': []}}
        identity = {'host_sources': {'schema_version': 'scenario_harness_host_sources.v2',
                                     'files': []},
                    'sessions': {'cpu': {'identity': generated},
                                 'legacy': {'identity': {'revision': 'git:abc'}}}}
        with patch('myfuzz.scenario.evidence.verify_host_source_identity') as verify:
            _verify_evidence_host_identity(identity)
        verify.assert_called_once_with(identity['host_sources'],
                                       harness_identities=(generated,))

    def test_legacy_replay_keeps_empty_harness_closure(self):
        identity = {'host_sources': {'schema_version': 'scenario_host_sources.v1',
                                     'files': []},
                    'sessions': {'legacy': {'identity': {'revision': 'git:abc'}}}}
        with patch('myfuzz.scenario.evidence.verify_host_source_identity') as verify:
            _verify_evidence_host_identity(identity)
        verify.assert_called_once_with(identity['host_sources'], harness_identities=())


if __name__ == '__main__':
    unittest.main()
