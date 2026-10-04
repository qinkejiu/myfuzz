"""Generated pinned OpenTitan SPI Device TL-UL and native serial acceptance."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedOpentitanSpiDeviceSession, load_local_harness_request,
    plan_local_harness, render_local_harness, render_local_runtime,
    render_local_driver, verify_local_source_lock,
)
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanSpiDeviceRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-ot-spi-device-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_spi_device_local/component_profile.json',
            instance_id='spi_device_ot', reset_assert_ticks=12, reset_release_ticks=12,
            max_wait_cycles=32))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 35
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        top = render_local_runtime(plan, render_local_harness(plan), verified,
                                   base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def session(self, name):
        device = GeneratedOpentitanSpiDeviceSession(self.artifact, base_dir=ROOT,
                                                    cache_dir=self.cache)
        device.prepare_local()
        device.begin_case(name)
        self.addCleanup(device.end_case)
        return device

    def test_native_jedec_response_and_persistent_register_state(self):
        device = self.session('spi-device-jedec')
        device.write_register(0x10, 1 << 4)
        device.write_register(0x30, 0x00A11234)
        device.write_register(0x88, 0x8012009F)
        self.assertEqual(0x00A11234, device.read_register(0x30))
        self.assertEqual(bytes((0xA1, 0x34, 0x12)),
                         device.transfer_bytes(bytes((0x9F,)), read_count=3))
        self.assertEqual(bytes((0xA1, 0x34, 0x12)),
                         device.transfer_bytes(bytes((0x9F,)), read_count=3))
        device.write_register(0x30, 0x00B25678)
        self.assertEqual(bytes((0xB2, 0x78, 0x56)),
                         device.transfer_bytes(bytes((0x9F,)), read_count=3))
        self.assertTrue(any(sample['post']['sd_en_o'] & 2
                            for sample in device.drain_tick_samples()))
        with self.assertRaisesRegex(ValueError, 'external input'):
            device.step_local({'sd_o': 1})

    def test_native_upload_irq_and_sram(self):
        device = self.session('spi-device-upload')
        device.write_register(0x10, 1 << 4)
        device.write_register(0xA8, 0x81010202)
        device.write_register(0x04, 1)
        device.transfer_bytes(bytes((0x02, 0x00, 0x12, 0x34, 0x5A)))
        for _ in range(100):
            if device.step_local({})['irq_o'] & 1:
                break
        else:
            self.fail('native SPI Device upload IRQ absent')
        self.assertEqual(0x02, device.read_register(0x44) & 0xff)
        self.assertEqual(0x001234, device.read_register(0x48) & 0xffffff)
        self.assertEqual(0x5A, device.read_register(0x1e00) & 0xff)

    def test_source_owned_pin_trace_has_fresh_replay(self):
        ownership = compile_ownership(
            (InputField('spi_device', 'sd_i', 4),),
            (InputOwner('spi_device', 'sd_i', 0, 4, 'source',
                        'external_spi_master'),))

        def factory():
            device = GeneratedOpentitanSpiDeviceSession(self.artifact, base_dir=ROOT,
                                                        cache_dir=self.cache)
            return ScenarioRunner(sessions={'spi_device': device}, ownership=ownership,
                                  bindings=())

        genome = ScenarioGenome(testcase_id='ot-spi-device-pin-source',
            direction='IP_TO_IP', path_id='external-spi-master-to-real-pad',
            schedule_order=('spi_device',), max_steps=8,
            actions=(Action('master-mosi', 'spi_device', 'sd_i', 1,
                            'IP_TO_IP', Trigger('START')),))
        bundle = Path(self.temp.name) / 'formal-ot-spi-device-evidence'
        trace = save_evidence_bundle(genome, factory, bundle)
        self.assertEqual('complete', trace.status)
        self.assertTrue(any(event.get('kind') == 'source_injection'
                            and event.get('value') == 1
                            and event.get('source_ref') == 'external_spi_master'
                            for event in trace.events))
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
