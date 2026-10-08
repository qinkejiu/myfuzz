"""Evidence replay verifies the generated per-harness host source closure."""
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import _verify_evidence_host_identity
from myfuzz.scenario.host_identity import host_source_identity, verify_host_source_identity


class GeneratedEvidenceHostIdentityTests(unittest.TestCase):
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
