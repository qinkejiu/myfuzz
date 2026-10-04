"""Pinned ZipCPU wbuart through generated Wishbone and real serial pins."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedWishboneUartSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
STARTUP = ((0, 25, 15), (12, 0x41, 1))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedWishboneUartRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-generated-wb-uart-')
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/zipcpu_uart/component_profile.json',
            instance_id='wb_uart', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        assert plan.facts.selection == 'all' and len(plan.facts.ports) == 19
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        cls.artifact = render_local_driver(top, base_dir=ROOT)
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_wishbone_registers_serial_tx_rx_and_irq(self):
        uart = GeneratedWishboneUartSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, source=b'\x5a', startup_writes=STARTUP,
            read_rx_after_source=True)
        uart.prepare_local()
        uart.begin_case('real-wb-uart')
        self.addCleanup(uart.end_case)
        observations = [uart.step_local({}) for _ in range(850)]
        self.assertEqual(25, uart.read_register(0) & 0xffffff)
        self.assertTrue(any(row['serial_tx_count'] >= 1 for row in observations))
        self.assertEqual(0x41, observations[-1]['serial_tx_last'])
        self.assertEqual(1, observations[-1]['serial_rx_read'])
        self.assertEqual(0x5a, observations[-1]['serial_rx_word'] & 0xff)
        self.assertTrue(any(row['uart_rx_int'] == 1 for row in observations))
        self.assertTrue(any(row['post']['uart_rx_int'] == 1
                            for row in uart.drain_tick_samples()))

    def test_genome_source_fresh_replay(self):
        ownership = compile_ownership(
            (InputField('uart', 'uart_rx_byte', 8),),
            (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'serial_peer'),))
        def factory():
            uart = GeneratedWishboneUartSession(self.artifact, base_dir=ROOT,
                cache_dir=self.cache, source=None, startup_writes=STARTUP,
                read_rx_after_source=True)
            return ScenarioRunner(sessions={'uart': uart}, ownership=ownership, bindings=())
        for byte in (0x5a, 0xa6):
            genome = ScenarioGenome(testcase_id=f'wb-uart-rx-{byte:02x}',
                direction='IP_TO_CPU', path_id='serial-peer-wbuart-rxfifo',
                schedule_order=('uart',), max_steps=850,
                actions=(Action('serial-byte', 'uart', 'uart_rx_byte',
                    byte, 'IP_TO_CPU', Trigger('START')),))
            bundle = Path(self.temp.name) / f'formal-wishbone-uart-{byte:02x}'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=120000, max_transactions=3))
            self.assertEqual('complete', trace.status, trace.events[-1:])
            transactions = [event for event in trace.events
                            if event.get('kind') == 'local_register_transaction']
            self.assertEqual([0, 12, 8], [event['offset'] for event in transactions])
            self.assertTrue(any(event.get('outputs', {}).get('serial_rx_word', 0) & 0xff == byte
                                for event in trace.events))
            self.assertTrue(any(event.get('outputs', {}).get('uart_rx_int') == 1
                                for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
