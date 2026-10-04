"""Declarative SPI mode-0 tuning and component-neutral session factory."""
from __future__ import annotations

import copy
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedTlulSpiMode0PeerSession, create_generated_tlul_session,
    load_local_harness_request,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact
from tests.local_harness.test_generic_tlul_spi_mode0_peer_real import spi_request


def tuned_request(*, half_period=8, read_count=3):
    document = spi_request().document()
    document['tuning']['spi_mode0_peers'] = [dict(
        endpoint_id='spi_device.pins', clock_role='sck_i',
        select_role='csb_i', data_input_role='sd_i',
        data_output_role='sd_o', enable_output_role='sd_en_o',
        source_id='external_spi_master_frame', source_port='spi_master_frame',
        format='mode0-single', source_bytes=1, prefix_value=0,
        prefix_bytes=0, read_count=read_count,
        mosi_lane=0, miso_lane=1, half_period=half_period)]
    document['tuning']['startup_writes'] = [
        dict(sequence=index, offset=offset, value=value)
        for index, (offset, value) in enumerate((
            (0x10, 1 << 4), (0x30, 0x00A11234), (0x88, 0x8012009F)), 1)]
    return load_local_harness_request(document)


class GenericTlulSpiMode0TuningContractTests(unittest.TestCase):
    def test_artifact_identity_and_factory_are_declarative(self):
        generated = artifact(tuned_request())
        alternate = artifact(tuned_request(half_period=9))
        self.assertEqual('tlul_register_observe', generated.runtime_document['kind'])
        self.assertEqual('tlul_register_spi_mode0_peer',
                         generated.runtime_document['functional_scope'])
        self.assertEqual('mode0-single', generated.runtime_document['serial_peer']['format'])
        self.assertEqual('sd_o', generated.runtime_document['serial_peer']['data_output'])
        self.assertNotEqual(generated.runtime_document['artifact_digest'],
                            alternate.runtime_document['artifact_digest'])
        with tempfile.TemporaryDirectory() as directory:
            session = create_generated_tlul_session(generated, base_dir=ROOT,
                cache_dir=Path(directory))
            self.assertIsInstance(session, GeneratedTlulSpiMode0PeerSession)
            self.assertEqual(((0x10, 1 << 4), (0x30, 0x00A11234),
                              (0x88, 0x8012009F)), session.setup_writes)
            self.assertEqual(8, session.half_period)
            forged = copy.deepcopy(generated.runtime_document)
            forged['serial_peer']['miso_lane'] = 0
            with self.assertRaisesRegex(ValueError, 'differs from artifact'):
                create_generated_tlul_session(replace(generated,
                    runtime_document=forged), base_dir=ROOT, cache_dir=Path(directory))

    def test_invalid_peer_shape_source_and_tuning_refuse(self):
        base = tuned_request().document()
        for edit, error in (
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(format='mode3'),
             'invalid-tuning-value'),
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(half_period=1),
             'invalid-tuning-value'),
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(source_bytes=5),
             'invalid-tuning-value'),
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(miso_lane=5),
             'spi-output-lane'),
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(clock_role='sd_o'),
             'spi-pin-shape'),
            (lambda d: d['tuning']['environment_bindings'][0].update(source_id='other'),
             'spi-source-required'),
            (lambda d: d['tuning']['spi_mode0_peers'][0].update(unknown=1),
             'unexpected-or-missing-tuning-fields')):
            invalid = copy.deepcopy(base)
            edit(invalid)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                artifact(load_local_harness_request(invalid))

        invalid = copy.deepcopy(base)
        invalid['tuning']['uart_8n1_peers'] = [dict(endpoint_id='spi_device.pins',
            rx_role='sck_i', tx_role='sd_o', source_id='external_spi_master_frame',
            format='8N1', clocks_per_bit=32, idle_bits=17)]
        with self.assertRaisesRegex(ValueError, 'one-serial-peer-required'):
            artifact(load_local_harness_request(invalid))

    def test_upload_frame_prefix_and_width_come_from_artifact(self):
        document = tuned_request().document()
        row = document['tuning']['spi_mode0_peers'][0]
        row.update(source_bytes=4, prefix_value=2, prefix_bytes=1,
                   read_count=0)
        generated = artifact(load_local_harness_request(document))
        with tempfile.TemporaryDirectory() as directory:
            session = create_generated_tlul_session(generated, base_dir=ROOT,
                cache_dir=Path(directory))
            self.assertEqual(4, session.source_bytes)
            self.assertEqual(b'\x02', session.prefix)
            self.assertEqual(0, session.read_count)
            self.assertEqual('02', generated.runtime_document['serial_peer']['prefix_hex'])


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulSpiMode0TuningRealTests(unittest.TestCase):
    def test_factory_real_jedec_miso_and_fresh_replay(self):
        generated = artifact(tuned_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-spi-declarative-') as directory:
            work = Path(directory)
            sessions = []
            ownership = compile_ownership((InputField('device', 'spi_master_frame', 8),),
                (InputOwner('device', 'spi_master_frame', 0, 8, 'source',
                            'external_spi_master_frame'),))

            def factory():
                session = create_generated_tlul_session(generated, base_dir=ROOT,
                    cache_dir=work / 'cache')
                sessions.append(session)
                return ScenarioRunner(sessions={'device': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='declarative-spi-jedec',
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

    def test_factory_real_upload_prefix_irq_sram_and_replay(self):
        document = tuned_request().document()
        document['tuning']['spi_mode0_peers'][0].update(
            source_bytes=4, prefix_value=2, prefix_bytes=1, read_count=0)
        document['tuning']['startup_writes'] = [
            dict(sequence=index, offset=offset, value=value)
            for index, (offset, value) in enumerate((
                (0x10, 1 << 4), (0xA8, 0x81010202), (0x04, 1)), 1)]
        generated = artifact(load_local_harness_request(document))
        with tempfile.TemporaryDirectory(prefix='myfuzz-spi-declarative-upload-') as directory:
            work = Path(directory)
            direct = create_generated_tlul_session(generated, base_dir=ROOT,
                cache_dir=work / 'cache')
            direct.prepare_local()
            direct.begin_case('declarative-upload-direct')
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
            finally:
                direct.end_case()

            ownership = compile_ownership((InputField('device', 'spi_master_frame', 32),),
                (InputOwner('device', 'spi_master_frame', 0, 32, 'source',
                            'external_spi_master_frame'),))
            sessions = []

            def factory():
                session = create_generated_tlul_session(generated, base_dir=ROOT,
                    cache_dir=work / 'cache')
                sessions.append(session)
                return ScenarioRunner(sessions={'device': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='declarative-spi-upload',
                direction='IP_TO_CPU', path_id='external-master-real-upload',
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
