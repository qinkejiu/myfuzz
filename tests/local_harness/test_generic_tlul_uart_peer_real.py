"""Profile-only TL-UL UART peer on pinned OpenTitan RTL."""
from __future__ import annotations

import os
import copy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedTlulRegisterSession, create_generated_tlul_session,
    load_local_harness_request,
)
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact, request


def uart_request(*, tx_byte=True):
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/opentitan_uart_local/component_profile.json',
        instance_id='generic_uart', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id='opentitan_uart.mmio', template_id='target.tl-ul',
            template_version='1', variant_id='user-integrity', max_outstanding=1)],
            'environment_bindings': [dict(endpoint_id='uart.pins', role='rx',
                                          source_id='serial_rx_frame')],
            'uart_8n1_peers': [dict(endpoint_id='uart.pins', rx_role='rx',
                                    tx_role='tx', source_id='serial_rx_frame',
                                    format='8N1', clocks_per_bit=32, idle_bits=17)],
            'startup_writes': [dict(sequence=i + 1, offset=offset, value=value)
                               for i, (offset, value) in enumerate((
                                   (0x10, 0x80000003), (0x04, 0x6)) +
                                   (((0x1c, 0x41),) if tx_byte else ()))]}))


def make_uart_session(generated, cache_dir):
    return create_generated_tlul_session(generated, base_dir=ROOT, cache_dir=cache_dir)


class GenericTlulUartPeerContractTests(unittest.TestCase):
    def test_generic_artifact_and_declarative_peer_identity(self):
        generated = artifact(uart_request())
        self.assertEqual('tlul_register_observe', generated.runtime_document['kind'])
        with tempfile.TemporaryDirectory() as directory:
            session = make_uart_session(generated, Path(directory))
            identity = session.identity_document()
            self.assertEqual('uart.pins.rx', identity['uart_peer']['rx_port'])
            self.assertEqual(32, identity['uart_peer']['clocks_per_bit'])
            ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),),
                (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'serial_rx_frame'),))
            session.validate_scenario_ownership('uart', ownership)
            wrong = compile_ownership((InputField('uart', 'uart.pins.rx', 1),),
                (InputOwner('uart', 'uart.pins.rx', 0, 1, 'source', 'serial_rx_frame'),))
            with self.assertRaisesRegex(ValueError, 'UART frame source ownership'):
                session.validate_scenario_ownership('uart', wrong)

    def test_peer_shape_and_unknown_tuning_fail_closed(self):
        document = uart_request().document()
        for edit, error in (
                (lambda d: d['tuning']['uart_8n1_peers'][0].update(format='7E1'),
                 'invalid-tuning-value'),
                (lambda d: d['tuning']['uart_8n1_peers'][0].update(clocks_per_bit=15),
                 'invalid-tuning-value'),
                (lambda d: d['tuning']['uart_8n1_peers'][0].update(idle_bits=65),
                 'invalid-tuning-value'),
                (lambda d: d['tuning']['uart_8n1_peers'][0].update(unknown=1),
                 'unexpected-or-missing-tuning-fields')):
            invalid = copy.deepcopy(document)
            edit(invalid)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                load_local_harness_request(invalid)

        invalid = copy.deepcopy(document)
        invalid['tuning']['environment_bindings'] = []
        with self.assertRaisesRegex(ValueError, 'uart-rx-source-required'):
            artifact(load_local_harness_request(invalid))
        invalid = copy.deepcopy(document)
        invalid['tuning']['uart_8n1_peers'][0]['tx_role'] = 'rx'
        with self.assertRaisesRegex(ValueError, 'uart-pin-shape'):
            artifact(load_local_harness_request(invalid))
        invalid = copy.deepcopy(document)
        invalid['tuning']['startup_writes'][0]['offset'] = 3
        with self.assertRaisesRegex(ValueError, 'startup-access'):
            artifact(load_local_harness_request(invalid))

    def test_artifact_identity_and_factory_registration(self):
        generated = artifact(uart_request())
        alternate_document = uart_request().document()
        alternate_document['tuning']['uart_8n1_peers'][0]['idle_bits'] = 18
        alternate = artifact(load_local_harness_request(alternate_document))
        self.assertNotEqual(generated.runtime_document['artifact_digest'],
                            alternate.runtime_document['artifact_digest'])
        self.assertEqual('tlul_register_uart_8n1_peer',
                         generated.runtime_document['functional_scope'])
        self.assertEqual('8N1', generated.runtime_document['serial_peer']['format'])
        with tempfile.TemporaryDirectory() as directory:
            session = make_uart_session(generated, Path(directory))
            self.assertEqual([[0x10, 0x80000003], [0x04, 0x6], [0x1c, 0x41]],
                             generated.runtime_document['serial_peer']['startup_writes'])
            self.assertEqual(((0x10, 0x80000003), (0x04, 0x6), (0x1c, 0x41)),
                             session.setup_writes)
            forged = copy.deepcopy(generated.runtime_document)
            forged['serial_peer']['source_id'] = 'wrong_source'
            with self.assertRaisesRegex(ValueError, 'differs from artifact'):
                make_uart_session(replace(generated, runtime_document=forged), Path(directory))
            plain = artifact(request('rv_timer'))
            self.assertNotIn('uart_8n1_peers', plain.plan.request.tuning.document())
            self.assertNotIn('startup_writes', plain.plan.request.tuning.document())
            self.assertIsInstance(make_uart_session(plain, Path(directory)),
                                  GeneratedTlulRegisterSession)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class GenericTlulUartPeerRealTests(unittest.TestCase):
    def test_real_serial_rx_tx_irq_and_fresh_replay(self):
        generated = artifact(uart_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-uart-') as directory:
            work = Path(directory)
            sessions = []
            ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),),
                (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'serial_rx_frame'),))

            def factory():
                session = make_uart_session(generated, work / 'cache')
                sessions.append(session)
                return ScenarioRunner(sessions={'uart': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-uart-peer',
                direction='IP_TO_CPU', path_id='uart-rx-real-fifo-irq',
                schedule_order=('uart',), max_steps=1300,
                actions=(Action('rx-byte', 'uart', 'uart_rx_byte', 0x5a,
                                'IP_TO_CPU', Trigger('START')),))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertTrue(any(e.get('outputs', {}).get('serial_tx_last') == 0x41
                                for e in trace.events))
            self.assertTrue(any(e.get('outputs', {}).get('intr_rx_watermark_o') == 1
                                for e in trace.events))
            self.assertEqual(0x5a, sessions[0].peer.source[0])
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            self.assertIsNot(sessions[0], sessions[1])

    def test_explicit_reset_restores_real_idle_pin_and_clears_frame(self):
        generated = artifact(uart_request(tx_byte=False))
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-uart-reset-') as directory:
            session = make_uart_session(generated, Path(directory))
            session.prepare_local()
            session.begin_case('uart-reset-physical')
            try:
                session.step_local({'uart_rx_byte': 0x5a})
                while session.local_ticks <= session.peer.source_start_tick + 6:
                    session.step_local({})
                self.assertEqual(0, session._dynamic_values['uart.pins.rx'])
                self.assertEqual(0x5a, session.peer.source[0])
                previous_epoch = session.reset_epoch
                session.reset_local()
                self.assertEqual(previous_epoch + 1, session.reset_epoch)
                self.assertEqual(1, session._dynamic_values['uart.pins.rx'])
                self.assertEqual(b'', session.peer.source)
                self.assertIsNone(session.peer.source_start_tick)
                self.assertIsNone(session._selected_byte)
                self.assertEqual(0, session.pending_events)
                self.assertFalse(session._started)
                self.assertEqual([], session.local_transactions)
                self.assertEqual(1, len(session.drain_tick_samples()),
                                 'reset retains only the new idle-high source tick')
                rx_runtime = generated.runtime_document['dynamic_physical_inputs'][0]['runtime_name']
                physical = session.command('STEP_TLUL_REG', ()).payload['observations']['physical']
                self.assertEqual(1, physical[rx_runtime],
                                 'the generated RTL driver must hold RX high after reset')
                self.assertEqual(0, session.step_local({})['serial_tx_count'])
            finally:
                session.end_case()

    def test_explicit_reset_mid_frame_has_fresh_replay(self):
        generated = artifact(uart_request(tx_byte=False))
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-uart-reset-replay-') as directory:
            work = Path(directory)
            ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),),
                (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'serial_rx_frame'),))
            sessions = []

            def factory():
                session = make_uart_session(generated, work / 'cache')
                sessions.append(session)
                return ScenarioRunner(sessions={'uart': session},
                    ownership=ownership, bindings=())

            genome = ScenarioGenome(testcase_id='generic-uart-reset-replay',
                direction='IP_TO_CPU', path_id='uart-rx-reset-idle',
                schedule_order=('uart',), max_steps=700, encoding_version=3,
                actions=(Action('rx-byte', 'uart', 'uart_rx_byte', 0x5a,
                                'IP_TO_CPU', Trigger('START')),),
                reset_actions=(ResetAction('mid-frame', 'warm_all', Trigger('START'),
                                           delay_component='uart', delay_ticks=620),))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=None)
            self.assertEqual('complete', trace.status, trace.events[-3:])
            barriers = [e for e in trace.events if e.get('kind') == 'reset_barrier']
            self.assertEqual(1, len(barriers))
            self.assertEqual(1, sessions[0].reset_epoch)
            self.assertTrue(replay_evidence_bundle(bundle, factory).matches)
            self.assertIsNot(sessions[0], sessions[1])


if __name__ == '__main__':
    unittest.main()
