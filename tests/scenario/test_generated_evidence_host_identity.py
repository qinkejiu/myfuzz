"""Evidence replay verifies the generated per-harness host source closure."""
import unittest
from unittest.mock import patch

from myfuzz.scenario.evidence import _verify_evidence_host_identity


class GeneratedEvidenceHostIdentityTests(unittest.TestCase):
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
