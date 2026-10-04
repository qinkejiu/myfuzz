import copy
from unittest.mock import patch
from myfuzz.scenario.genome import ScenarioGenome, GenomeCodec
from myfuzz.scenario.replay import ScenarioTrace, replay_scenario, _canonical
import unittest
from tests.scenario import test_generated_local_contract as fixtures
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from tests.local_harness.test_renderer import ROOT
from pathlib import Path
import hashlib

class GeneratedReplayIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.GeneratedLocalContractTests.setUpClass()
        cls.artifact=fixtures.GeneratedLocalContractTests.artifact

    def identity(self):
        return fixtures.GeneratedLocalContractTests.identity(self)

    def test_replay_drift_rejected_before_rtl_start(self):
        genome=ScenarioGenome(testcase_id='identity-replay',direction='CPU_TO_IP',path_id='p',
            schedule_order=('gpio',),max_steps=1,actions=())
        identity=self.identity()
        reference=ScenarioTrace(hashlib.sha256(GenomeCodec.encode(genome)).hexdigest(),
            'completed',(),{'gpio':0},'0'*64,hashlib.sha256(_canonical(identity)).hexdigest())
        paths=[('plan','profile_sha256'),('structural_abi','abi_sha256'),('cpp_sha256',),('adapter_sources',)]
        for path in paths:
            changed=copy.deepcopy(identity)
            doc=changed['sessions']['gpio']['identity']['runtime_artifact']
            if len(path)==2:doc[path[0]][path[1]]='0'*64
            else:doc[path[0]]='changed'
            session=GeneratedPulpGpioSession(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/unused-replay'))
            runner=ScenarioRunner(sessions={'gpio':session},ownership=compile_ownership((),()),bindings=())
            with patch.object(runner,'identity_document',return_value=changed),patch.object(session,'begin_case') as begin:
                with self.subTest(path=path),self.assertRaisesRegex(ValueError,'replay manifest identity mismatch'):
                    replay_scenario(genome,lambda:runner,reference)
                begin.assert_not_called()

    def test_transport_execution_uuid_excluded_from_stable_identity(self):
        session=GeneratedPulpGpioSession(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/unused-replay'))
        before=session.identity_document();session._execution='different-wire-uuid'
        self.assertEqual(before,session.identity_document())
