"""A reusable mode-0 external master over a profile-only TL-UL harness."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedTlulSpiMode0PeerSession, load_local_harness_request,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact


def spi_request(*, omit_clock=False, fixed_clock=False):
    environment = [dict(endpoint_id='spi_device.pins', role=role,
                        source_id='external_spi_master_frame')
                   for role in ('sck_i', 'csb_i', 'sd_i') if role != 'sck_i' or not omit_clock]
    fixed = [dict(endpoint_id='spi_device.pins', role='tpm_csb_i', value=1)]
    if fixed_clock:
        fixed.append(dict(endpoint_id='spi_device.pins', role='sck_i', value=0))
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/opentitan_spi_device_local/component_profile.json',
        instance_id='generic_spi_device', reset_assert_ticks=12,
        reset_release_ticks=12, max_wait_cycles=32,
        tuning={'endpoint_policies': [dict(
            endpoint_id='opentitan_spi_device.mmio', template_id='target.tl-ul',
            template_version='1', variant_id='user-integrity', max_outstanding=1)],
            'fixed_inputs': fixed, 'environment_bindings': environment}))


def peer(generated, cache, *, source_bytes=1, prefix=b'', read_count=3,
         setup_writes=((0x10, 1 << 4), (0x30, 0x00A11234),
                       (0x88, 0x8012009F))):
    return GeneratedTlulSpiMode0PeerSession(generated, base_dir=ROOT,
        cache_dir=cache,
        clock_input='spi_device.pins.sck_i',
        select_input='spi_device.pins.csb_i',
        data_input='spi_device.pins.sd_i',
        data_output='sd_o', enable_output='sd_en_o',
        source_id='external_spi_master_frame',
        source_port='spi_master_frame', source_bytes=source_bytes,
        prefix=prefix, read_count=read_count,
        mosi_lane=0, miso_lane=1, half_period=8,
        setup_writes=setup_writes)


class GenericTlulSpiMode0PeerContractTests(unittest.TestCase):
    def test_v2_artifact_pin_ownership_and_frame_source_identity(self):
        generated = artifact(spi_request())
        self.assertEqual('tlul_register_observe', generated.runtime_document['kind'])
        self.assertEqual({'sck_i', 'csb_i', 'sd_i'},
            {row['role'] for row in generated.runtime_document['dynamic_physical_inputs']})
        self.assertEqual({'tpm_csb_i'},
            {row['role'] for row in generated.runtime_document['fixed_physical_inputs']})
        with tempfile.TemporaryDirectory() as directory:
            session = peer(generated, Path(directory))
            ownership = compile_ownership((InputField('device', 'spi_master_frame', 8),),
                (InputOwner('device', 'spi_master_frame', 0, 8, 'source',
                            'external_spi_master_frame'),))
            session.validate_scenario_ownership('device', ownership)
            wrong = compile_ownership((InputField('device', 'spi_master_frame', 8),),
                (InputOwner('device', 'spi_master_frame', 0, 8, 'bound',
                            'other.output'),))
            with self.assertRaisesRegex(ValueError, 'master frame source ownership'):
                session.validate_scenario_ownership('device', wrong)
        with self.assertRaisesRegex(ValueError, 'unowned-input'):
            artifact(spi_request(omit_clock=True))
        with self.assertRaisesRegex(ValueError, 'overlapping-input-owners'):
            artifact(spi_request(fixed_clock=True))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulSpiMode0PeerRealTests(unittest.TestCase):
    def test_real_jedec_miso_and_fresh_replay(self):
        generated = artifact(spi_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-spi-mode0-') as directory:
            work = Path(directory)
            sessions = []
            ownership = compile_ownership((InputField('device', 'spi_master_frame', 8),),
                (InputOwner('device', 'spi_master_frame', 0, 8, 'source',
                            'external_spi_master_frame'),))

            def factory():
                session = peer(generated, work / 'cache')
                sessions.append(session)
                return ScenarioRunner(sessions={'device': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-spi-jedec',
                direction='IP_TO_CPU', path_id='external-master-real-miso',
                schedule_order=('device',), max_steps=8,
                actions=(Action('jedec-opcode', 'device', 'spi_master_frame', 0x9F,
                                'IP_TO_CPU', Trigger('START')),))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertEqual(bytes((0xA1, 0x34, 0x12)), sessions[0].last_response)
            self.assertGreater(sessions[0].miso_enabled_samples, 0)
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            self.assertIsNot(sessions[0], sessions[1])

    def test_real_upload_irq_sram_and_fresh_replay(self):
        generated = artifact(spi_request())
        writes = ((0x10, 1 << 4), (0xA8, 0x81010202), (0x04, 1))
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-spi-upload-') as directory:
            work = Path(directory)
            direct = peer(generated, work / 'cache', source_bytes=4,
                prefix=b'\x02', read_count=0, setup_writes=writes)
            direct.prepare_local()
            direct.begin_case('direct-upload')
            try:
                direct.step_local({'spi_master_frame': 0x0012345A})
                for _ in range(100):
                    if direct.step_local({})['irq_o'] & 1:
                        break
                else:
                    self.fail('real upload IRQ absent')
                self.assertEqual(0x02, direct.read_register(0x44) & 0xff)
                self.assertEqual(0x001234, direct.read_register(0x48) & 0xffffff)
                self.assertEqual(0x5A, direct.read_register(0x1e00) & 0xff)
                with self.assertRaisesRegex(ValueError, 'cannot change after transfer'):
                    direct.step_local({'spi_master_frame': 0x0012345B})
                before_repeat = direct.local_ticks
                direct.step_local({'spi_master_frame': 0x0012345A})
                self.assertEqual(before_repeat + 1, direct.local_ticks,
                                 'same frame must not execute the transfer twice')
            finally:
                direct.end_case()

            sessions = []
            ownership = compile_ownership((InputField('device', 'spi_master_frame', 32),),
                (InputOwner('device', 'spi_master_frame', 0, 32, 'source',
                            'external_spi_master_frame'),))

            def factory():
                session = peer(generated, work / 'cache', source_bytes=4,
                    prefix=b'\x02', read_count=0, setup_writes=writes)
                sessions.append(session)
                return ScenarioRunner(sessions={'device': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-spi-upload',
                direction='IP_TO_CPU', path_id='external-master-real-upload-irq',
                schedule_order=('device',), max_steps=100,
                actions=(Action('upload-frame', 'device', 'spi_master_frame',
                                0x0012345A, 'IP_TO_CPU', Trigger('START')),))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertTrue(any(event.get('outputs', {}).get('irq_o', 0) & 1
                                for event in trace.events))
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
