"""P0-2 CPU-only route: one CPU model, RAM, real program and DUT assertions."""
from __future__ import annotations

import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))

from inprocess_cpu_only import (  # noqa: E402
    CpuOnlyError, build_cpu_only, load_cpu_only_config, run_cpu_only,
)

CONFIG = ROOT / 'configs/scenarios/p0-cpu-only-ibex.json'
SECOND_CONFIG = ROOT / 'configs/scenarios/p0-cpu-only-cv32e40p.json'
CACHE = ROOT / 'runs/p0-cpu-only/cache'
ARTIFACT_CACHE = ROOT / 'runs/stage2-stepD2-cache'
SECOND_ARTIFACT_CACHE = ROOT / 'runs/cv32e40p-pulp-online-20261007-cache'
PINNED_DIGEST = '007450f9afee9d36d42052b4da76d0f29715787c42ccbed9dcfcde988f2b8f0c'


class CpuOnlyRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ARTIFACT_CACHE / PINNED_DIGEST).is_dir():
            raise unittest.SkipTest('pinned Ibex CPU artifact cache is unavailable')
        cls.temporary = tempfile.TemporaryDirectory(prefix='p0-cpu-only-test-')
        cls.output = Path(cls.temporary.name)
        cls.baseline = build_cpu_only(CONFIG, CACHE, cls.output / 'build-baseline',
                                     assertions=False)
        cls.assertion = build_cpu_only(CONFIG, CACHE, cls.output / 'build-assertion',
                                      assertions=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_one_cpu_archive_and_no_target_model(self):
        self.assertEqual(1, len(self.baseline['archives']))
        archive = self.baseline['archives'][0]
        self.assertEqual('cpu', archive['kind'])
        self.assertEqual('local_cpu', archive['module'])
        self.assertTrue(Path(archive['path']).is_file())
        self.assertEqual(archive['path'], self.baseline['model_archive'])
        build = json.loads((Path(self.baseline['model']['model_dir']) / 'build.json').read_text())
        self.assertIn('--assert', build['command'])
        self.assertNotIn('-UVERILATOR', build['command'])
        self.assertIn('local_cpu', build['command'])
        self.assertNotIn('local_runtime_cpu', build['command'])

    def test_assertion_build_flags(self):
        self.assertIn('--assert', self.baseline['assertion_flags'])
        self.assertNotIn('-UVERILATOR', self.baseline['assertion_flags'])
        self.assertIn('--assert', self.assertion['assertion_flags'])
        self.assertIn('-UVERILATOR', self.assertion['assertion_flags'])
        build = json.loads((Path(self.assertion['model']['model_dir']) / 'build.json').read_text())
        self.assertIn('-UVERILATOR', build['command'])

    def test_normal_batch_executes_real_program(self):
        result = run_cpu_only(CONFIG, CACHE, self.output / 'normal',
                              records=[1, 2, 0x100, 0xffffffff], assertions=False)
        self.assertEqual('observations_passed', result['status'])
        self.assertEqual(0, result['returncode'])
        self.assertEqual(4, result['case_count'])
        self.assertEqual([], result['assertion_events'])
        self.assertEqual('observed', result['signal_status']['retirement'])
        self.assertEqual(1, result['signal_status']['clock']['clocks'])
        for case in result['cases']:
            self.assertEqual('observations_passed', case['status'])
            self.assertEqual((case['input'] + 1) & 0xffffffff, case['result'])
            self.assertGreater(case['ticks'], 0)
            self.assertGreater(case['retires'], 0)

    def test_light_fuzz_uses_the_same_record_shape(self):
        seed, cases = 7, 6
        result = run_cpu_only(CONFIG, CACHE, self.output / 'fuzz',
                              fuzz={'cases': cases, 'seed': seed}, assertions=False)
        self.assertEqual('observations_passed', result['status'])
        self.assertEqual('fuzz', result['input_mode'])
        generator = random.Random(seed)
        expected = ['0x%08x' % generator.getrandbits(32) for _ in range(cases)]
        self.assertEqual(expected, result['records'])
        self.assertEqual(cases, result['case_count'])
        for case in result['cases']:
            self.assertEqual((case['input'] + 1) & 0xffffffff, case['result'])

    def test_real_dut_assertion_is_captured_with_input_and_source(self):
        result = run_cpu_only(CONFIG, CACHE, self.output / 'assertion', fault=True)
        self.assertEqual('assertion_failed', result['status'])
        self.assertEqual(3, result['returncode'])
        self.assertTrue(result['assertions'])
        self.assertEqual('assertion', result['model_kind'])
        self.assertEqual([], result['missing_assertions'])
        scopes = ' '.join(event['scope'] for event in result['assertion_events'])
        self.assertIn('PendingAccessTrackingCorrect', scopes)
        self.assertIn('NoMemResponseWithoutPendingAccess', scopes)
        event = next(event for event in result['assertion_events']
                     if 'NoMemResponseWithoutPendingAccess' in event['scope'])
        self.assertEqual('ibex_core.sv', event['file'])
        self.assertEqual(1391, event['line'])
        self.assertEqual(30, event['tick'])
        self.assertEqual(0, event['case'])
        self.assertEqual('cpu', event['model'])
        self.assertEqual(1, len(result['archives']))
        self.assertEqual('fault', result['input_mode'])
        self.assertEqual(30, result['fault']['tick'])

    def test_bus_timeout_is_environment_not_an_assertion(self):
        result = run_cpu_only(CONFIG, CACHE, self.output / 'timeout',
                              records=[1], max_ticks=1, assertions=False)
        self.assertEqual('environment_failed', result['status'])
        self.assertEqual(4, result['returncode'])
        self.assertEqual([], result['assertion_events'])
        self.assertEqual(1, len(result['environment_events']))
        self.assertEqual('case_timeout', result['environment_events'][0]['reason'])

    @unittest.skipUnless((SECOND_ARTIFACT_CACHE / '7e5778575a767b36c1618191e6dbc7ff8a233cf9612f76618fc022990e54ec89').is_dir(),
                         'pinned CV32E40P CPU artifact cache is unavailable')
    def test_second_cpu_profile_runs_with_unknown_retirement(self):
        result = run_cpu_only(SECOND_CONFIG, CACHE, self.output / 'second-cpu',
                              records=[1, 2], assertions=False)
        self.assertEqual('observations_passed', result['status'])
        self.assertEqual('unknown', result['signal_status']['retirement'])
        self.assertEqual('unknown', result['signal_status']['trap'])
        self.assertEqual(1, result['signal_status']['clock']['clocks'])
        self.assertEqual(1, result['signal_status']['clock']['resets'])
        self.assertEqual(1, len(result['archives']))
        self.assertEqual('cpu', result['archives'][0]['kind'])
        for case in result['cases']:
            self.assertEqual((case['input'] + 1) & 0xffffffff, case['result'])
            self.assertEqual('unknown', case['retires'])
            self.assertEqual('unknown', case['pc'])
        self.assertEqual('unknown', result['summary']['retires'])

    def test_required_observation_is_refused_before_a_model_build(self):
        document = json.loads(SECOND_CONFIG.read_text(encoding='utf-8'))
        document['required_observations'] = ['rvfi_valid']
        path = self.output / 'requires-rvfi.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(CpuOnlyError) as caught:
            build_cpu_only(path, CACHE, None, assertions=False)
        self.assertIn('cpu-only-required-observation-missing', str(caught.exception))

    def test_fault_mode_refuses_a_scenario_without_a_declared_fault(self):
        with self.assertRaises(CpuOnlyError) as caught:
            run_cpu_only(SECOND_CONFIG, CACHE, self.output / 'no-fault',
                         records=[1], fault=True)
        self.assertIn('cpu-only-fault-not-declared', str(caught.exception))

    def test_config_freezes_boot_and_mailbox(self):
        config = load_cpu_only_config(CONFIG)
        self.assertEqual(0x10000, config['boot_address'])
        self.assertEqual(0x10080, config['program_address'])
        self.assertEqual(0x11000, config['mailbox_address'])
        self.assertEqual(0x11004, config['result_address'])
        self.assertEqual('cpu', config['instance_id'])


if __name__ == '__main__':
    unittest.main()
