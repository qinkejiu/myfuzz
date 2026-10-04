"""Pinned AXI4-Lite axiluart closes real register and serial transactions."""

from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.axil_uart_session import GeneratedAxiLiteUartSession
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import ResourceBudget, _verify_generated_session
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'


def uart_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=PROFILE, instance_id='uart', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,
        render_local_harness(plan), verify_local_source_lock(plan.profile,
            base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)


class AxilUartRuntimeAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-uart-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.artifact = uart_artifact()
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def make_session(self):
        return GeneratedAxiLiteUartSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, source=b'Z', startup_writes=((12, 65, 1),),
            read_rx_after_source=True)

    def test_full_top_and_real_axi_channels_with_serial_peer(self):
        artifact = self.artifact
        self.assertEqual('axi4_lite_uart', artifact.runtime_document['kind'])
        self.assertEqual(29, len(artifact.plan.facts.ports))
        self.assertEqual('all', artifact.plan.facts.selection)
        self.assertEqual(19, len(artifact.runtime_document['backend_ports']))
        self.assertEqual(8, len(artifact.runtime_document['physical_exports']))
        session = self.make_session()
        self.assertEqual(artifact, _verify_generated_session(session.identity_document()))
        session.begin_case('axil-uart-real')
        try:
            self.assertEqual(25, session.read_register(0))
            outputs = [session.step_local({}) for _ in range(780)]
            self.assertEqual([65], session.peer.captured)
            self.assertEqual(90, outputs[-1]['serial_rx_word'])
            self.assertEqual(1, outputs[-1]['serial_rx_read'])
            self.assertTrue(any(row['uart_rx_int'] for row in outputs))
            self.assertEqual(65, outputs[-1]['serial_tx_last'])
            self.assertEqual(1, outputs[-1]['serial_tx_count'])
            self.assertEqual(0, session.pending_responses)
        finally:
            session.end_case()

    def test_budgeted_saved_evidence_replays_fresh_uart_rtl(self):
        sessions = []

        def factory():
            uart = self.make_session()
            sessions.append(uart)
            return ScenarioRunner(sessions={'uart': uart},
                ownership=compile_ownership((), ()), bindings=())

        genome = ScenarioGenome(testcase_id='axil-uart-serial-evidence',
            direction='IP_TO_CPU', path_id='axil-uart-8n1',
            schedule_order=('uart',), max_steps=780, actions=())
        bundle = Path(self.directory.name) / 'evidence'
        trace = save_evidence_bundle(genome, factory, bundle,
            budget=ResourceBudget(max_wall_time_ms=90000))
        self.assertEqual('complete', trace.status)
        self.assertEqual([65], sessions[0].peer.captured)
        self.assertEqual(90, sessions[0]._rx_word)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        identity = manifest['sessions']['uart']['identity']
        self.assertEqual('axi4_lite_uart', identity['runtime_artifact']['kind'])
        self.assertEqual('5a', identity['source_hex'])
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay)
        self.assertEqual([65], sessions[1].peer.captured)
        self.assertEqual(90, sessions[1]._rx_word)
        self.assertNotEqual(sessions[0]._execution, sessions[1]._execution)

    def test_genome_source_byte_changes_real_uart_rx_and_replays(self):
        ownership = compile_ownership(
            (InputField('uart', 'uart_rx_byte', 8),),
            (InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                        'external_uart_rx_byte'),))
        graph = DependencyGraph(
            sources=(FuzzableSource('external_uart_rx_byte', 'uart',
                'uart_rx_byte', 0, 8, ('IP_TO_CPU',)),),
            rules=(DependencyRule('uart.serial_rx_word',
                ('external_uart_rx_byte',), 'DATA_BINDING'),))
        seed = ScenarioGenome(testcase_id='axil-uart-genome-source',
            direction='IP_TO_CPU', path_id='external-rx-rtl-read',
            schedule_order=('uart',), max_steps=780,
            actions=(Action('serial-byte', 'uart', 'uart_rx_byte', 0x35,
                            'IP_TO_CPU', Trigger('START')),))
        plan = choose_mutation(graph, {'uart.serial_rx_word': 1},
                               direction='IP_TO_CPU')
        changed = seed
        for bit in (0, 1, 4, 7):
            changed = mutate_genome(changed, plan, graph, ownership,
                                    bit_index=bit)
        self.assertEqual(0xa6, changed.actions[0].value)
        observed = []
        for genome in (seed, changed):
            byte = genome.actions[0].value
            sessions = []

            def factory():
                uart = GeneratedAxiLiteUartSession(self.artifact, base_dir=ROOT,
                    cache_dir=self.cache, source=None, read_rx_after_source=True)
                sessions.append(uart)
                return ScenarioRunner(sessions={'uart': uart},
                    ownership=ownership, bindings=())
            bundle = Path(self.directory.name) / f'genome-{byte:02x}'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=90000))
            self.assertEqual('complete', trace.status)
            self.assertEqual(byte, sessions[0]._rx_word)
            injections = [event for event in trace.events
                          if event.get('kind') == 'source_injection']
            self.assertEqual([byte], [event['value'] for event in injections])
            self.assertEqual('genome', sessions[0].identity_document()['source_mode'])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(byte, sessions[1]._rx_word)
            observed.append(sessions[0]._rx_word)
        self.assertEqual([0x35, 0xa6], observed)

    def test_genome_source_cannot_change_after_frame_begins(self):
        uart = GeneratedAxiLiteUartSession(self.artifact, base_dir=ROOT,
            cache_dir=self.cache, source=None, read_rx_after_source=True)
        uart.begin_case('axil-uart-locked-source')
        try:
            uart.step_local({'uart_rx_byte': 0x35})
            tick = uart.local_ticks
            with self.assertRaisesRegex(ValueError, 'cannot change'):
                uart.step_local({'uart_rx_byte': 0xa6})
            self.assertEqual(tick, uart.local_ticks)
            self.assertEqual(b'5', uart.peer.source)
        finally:
            uart.end_case()
