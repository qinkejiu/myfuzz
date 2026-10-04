"""Profile-only TL-UL UART peer on pinned OpenTitan RTL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import GeneratedTlulUartPeerSession, load_local_harness_request
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ResetAction, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from tests.local_harness.test_generic_tlul_register_real import ROOT, artifact


def uart_request():
    return load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/opentitan_uart_local/component_profile.json',
        instance_id='generic_uart', reset_assert_ticks=2,
        reset_release_ticks=2, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id='opentitan_uart.mmio', template_id='target.tl-ul',
            template_version='1', variant_id='user-integrity', max_outstanding=1)],
            'environment_bindings': [dict(endpoint_id='uart.pins', role='rx',
                                          source_id='serial_rx_frame')]}))


class GenericTlulUartPeerContractTests(unittest.TestCase):
    def test_generic_artifact_and_declarative_peer_identity(self):
        generated = artifact(uart_request())
        self.assertEqual('tlul_register_observe', generated.runtime_document['kind'])
        with tempfile.TemporaryDirectory() as directory:
            session = GeneratedTlulUartPeerSession(generated, base_dir=ROOT,
                cache_dir=Path(directory), rx_port='uart.pins.rx', tx_port='cio_tx_o',
                source_id='serial_rx_frame', clocks_per_bit=32,
                setup_writes=((0x10, 0x80000003), (0x04, 0x6), (0x1c, 0x41)))
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
                session = GeneratedTlulUartPeerSession(generated, base_dir=ROOT,
                    cache_dir=work / 'cache', rx_port='uart.pins.rx',
                    tx_port='cio_tx_o', source_id='serial_rx_frame',
                    clocks_per_bit=32,
                    setup_writes=((0x10, 0x80000003), (0x04, 0x6), (0x1c, 0x41)))
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
        generated = artifact(uart_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-uart-reset-') as directory:
            session = GeneratedTlulUartPeerSession(generated, base_dir=ROOT,
                cache_dir=Path(directory), rx_port='uart.pins.rx',
                tx_port='cio_tx_o', source_id='serial_rx_frame',
                clocks_per_bit=32,
                setup_writes=((0x10, 0x80000003), (0x04, 0x6)))
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
        generated = artifact(uart_request())
        with tempfile.TemporaryDirectory(prefix='myfuzz-generic-uart-reset-replay-') as directory:
            work = Path(directory)
            ownership = compile_ownership((InputField('uart', 'uart_rx_byte', 8),),
                (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'serial_rx_frame'),))
            sessions = []

            def factory():
                session = GeneratedTlulUartPeerSession(generated, base_dir=ROOT,
                    cache_dir=work / 'cache', rx_port='uart.pins.rx',
                    tx_port='cio_tx_o', source_id='serial_rx_frame',
                    clocks_per_bit=32,
                    setup_writes=((0x10, 0x80000003), (0x04, 0x6)))
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
