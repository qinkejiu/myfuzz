"""Generated pinned OpenTitan I2C TL-UL, open-drain pads, and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanI2cSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanI2cRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-ot-i2c-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_i2c_local/component_profile.json',
            instance_id='i2c_ot', reset_assert_ticks=8, reset_release_ticks=8,
            max_wait_cycles=32))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 33
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        top = render_local_runtime(plan, render_local_harness(plan), verified,
                                   base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        device = GeneratedOpentitanI2cSession(self.artifact, base_dir=ROOT,
                                              cache_dir=self.cache)
        device.prepare_local()
        device.begin_case(name)
        self.addCleanup(device.end_case)
        return device

    def test_real_tlul_registers_bound_open_drain_pads_and_serial_byte(self):
        device = self.session('real-i2c')
        device.configure_peer_response(0x5a)
        with self.assertRaisesRegex(ValueError, 'one response byte'):
            device.configure_peer_response(0xa6)
        self.assertEqual(0x33c, device.read_register(0x14) & 0x33c)
        device.write_register(0x10, 1)
        self.assertEqual(1, device.read_register(0x10) & 1)
        observed = device.step_local({})
        self.assertEqual((1, 1, 0, 0),
                         (observed['scl_i'], observed['sda_i'],
                          observed['scl_o'], observed['sda_o']))
        with self.assertRaisesRegex(ValueError, 'bound'):
            device.step_local({'sda_i': 0})
        for offset, value in ((0x3c, 0x00100010), (0x40, 0x00020002),
                              (0x44, 0x00080008), (0x48, 0x00040004),
                              (0x4c, 0x00080008), (0x04, 0x202)):
            device.write_register(offset, value)
        device.write_register(0x1c, 0x1a1)
        device.write_register(0x1c, 0x601)
        scl_low = sda_low = False
        for _ in range(1600):
            observed = device.step_local({})
            scl_low |= observed['scl_en_o'] == 1
            sda_low |= observed['sda_en_o'] == 1
            if observed['irq_o'] & (1 << 9):
                break
        else:
            self.fail('native OpenTitan I2C command completion IRQ absent')
        self.assertTrue(scl_low and sda_low)
        self.assertEqual(0x5a, device.read_register(0x18) & 0xff)
        self.assertEqual(0, device.pending_events)

    def test_source_owned_pad_trace_has_fresh_replay(self):
        ownership = compile_ownership(
            (InputField('i2c', 'peer_response', 8),),
            (InputOwner('i2c', 'peer_response', 0, 8, 'source',
                        'external_i2c_peer'),))

        def factory():
            device = GeneratedOpentitanI2cSession(self.artifact, base_dir=ROOT,
                                                   cache_dir=self.cache)
            return ScenarioRunner(sessions={'i2c': device}, ownership=ownership,
                                  bindings=())

        genome = ScenarioGenome(testcase_id='ot-i2c-open-drain-idle',
            direction='IP_TO_IP', path_id='external-peer-real-i2c-pads',
            schedule_order=('i2c',), max_steps=8,
            actions=(Action('peer-byte', 'i2c', 'peer_response', 0x5a,
                            'IP_TO_IP', Trigger('START')),))
        bundle = Path(self.temp.name) / 'formal-ot-i2c-evidence'
        trace = save_evidence_bundle(genome, factory, bundle)
        self.assertEqual('complete', trace.status)
        self.assertEqual([(0x5a, 'external_i2c_peer')], [
            (event['value'], event['source_ref']) for event in trace.events
            if event.get('kind') == 'source_injection'
            and event.get('component') == 'i2c'])
        self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                            and event.get('component') == 'i2c'
                            and event.get('outputs', {}).get('scl_i') == 1
                            and event.get('outputs', {}).get('sda_i') == 1
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
