"""Pinned generated OpenTitan SPI Host TL-UL register path and fresh replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSpiHostSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, ScenarioGenome, Trigger
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_spi_host_local/component_profile.json'


def _artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=PROFILE, instance_id='spi_host', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,
        render_local_harness(plan), verify_local_source_lock(plan.profile,
            base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedOpentitanSpiHostRealTests(unittest.TestCase):
    def test_real_tlul_registers_and_pad_observations_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-spi-host-generated-') as directory:
            work = Path(directory)
            artifact = _artifact()
            self.assertEqual('tlul_spi_host', artifact.runtime_document['kind'])
            self.assertEqual('all', artifact.plan.facts.selection)
            self.assertEqual(29, len(artifact.plan.facts.ports))
            self.assertEqual(7, len(artifact.runtime_document['physical_exports']))
            sessions = []

            def factory():
                session = GeneratedOpentitanSpiHostSession(artifact, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    setup_writes=((0x10, 0x80000001), (0x18, 8)),
                    probe_offsets=(0x10, 0x14, 0x18))
                sessions.append(session)
                return ScenarioRunner(sessions={'spi_host': session},
                    ownership=compile_ownership((), ()), bindings=())

            genome = ScenarioGenome(testcase_id='ot-spi-host-generated-registers',
                direction='IP_TO_CPU', path_id='tlul-registers-to-real-state',
                schedule_order=('spi_host',), max_steps=12, actions=())
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000, max_transactions=5))
            self.assertEqual('complete', trace.status, trace.events[-3:])
            self.assertEqual(0x80000001, next(event['outputs']['reg_10']
                for event in trace.events if event.get('component') == 'spi_host'
                and 'outputs' in event and 'reg_10' in event['outputs']))
            self.assertTrue(any(event.get('kind') == 'local_register_transaction'
                                and event.get('offset') == 0x14 and not event['write']
                                and event['read_value'] & (1 << 28)
                                for event in trace.events))
            self.assertEqual(5, sum(event.get('kind') == 'local_register_transaction'
                                    for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                and event.get('component') == 'spi_host'
                                and 'sck' in event.get('outputs', {})
                                for event in trace.events))
            self.assertEqual(0, sessions[0].peer.sample_count)
            self.assertGreater(sessions[0].local_ticks, 12)
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertEqual(0, sessions[1].peer.sample_count)

    def test_real_mode0_four_byte_receive_replays_and_changes_with_peer_source(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-spi-host-rx-generated-') as directory:
            work = Path(directory)
            artifact = _artifact()
            source = {'bytes': bytes.fromhex('12 34 56 78')}
            sessions = []

            def factory():
                session = GeneratedOpentitanSpiHostSession(artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', source=source['bytes'],
                    setup_writes=((0x10, 0xa0000001), (0x18, 8),
                                  (0x34, 4), (0x04, 2), (0x20, 0x68)),
                    read_rx_on_complete=True)
                sessions.append(session)
                return ScenarioRunner(sessions={'spi_host': session},
                    ownership=compile_ownership((), ()), bindings=())

            genome = ScenarioGenome(testcase_id='ot-spi-host-generated-rx',
                direction='IP_TO_CPU', path_id='spi-peer-real-rxfifo',
                schedule_order=('spi_host',), max_steps=700, actions=())
            results = []
            for payload in (bytes.fromhex('12 34 56 78'),
                            bytes.fromhex('a5 5a 0f f0')):
                source['bytes'] = payload
                trace = save_evidence_bundle(genome, factory,
                    work / f'evidence-{payload.hex()}',
                    budget=ResourceBudget(max_wall_time_ms=180000,
                                          max_transactions=6))
                self.assertEqual('complete', trace.status, trace.events[-3:])
                session = sessions[-1]
                expected = int.from_bytes(payload, 'little')
                self.assertEqual(expected, session.rx_word)
                self.assertEqual(32, session.peer.sample_count)
                self.assertEqual(4, session.peer.payload_index)
                self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                    and event.get('component') == 'spi_host'
                                    and event.get('outputs', {}).get('irq_event')
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'local_register_transaction'
                                    and event.get('offset') == 0x24
                                    and event.get('read_value') == expected
                                    for event in trace.events))
                replay = replay_evidence_bundle(work / f'evidence-{payload.hex()}', factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual(expected, sessions[-1].rx_word)
                results.append(trace.semantic_sha256)
            self.assertNotEqual(results[0], results[1])

    def test_genome_owned_spi_word_mutates_upstream_of_real_rxfifo(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-spi-host-genome-') as directory:
            work = Path(directory)
            artifact = _artifact()
            sessions = []
            ownership = compile_ownership(
                (InputField('spi_host', 'spi_source_word', 32),),
                (InputOwner('spi_host', 'spi_source_word', 0, 32, 'source',
                            'external_spi_source_word'),))

            def factory():
                session = GeneratedOpentitanSpiHostSession(artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', source=None,
                    setup_writes=((0x10, 0xa0000001), (0x18, 8),
                                  (0x20, 0x68)), read_rx_on_complete=True)
                sessions.append(session)
                return ScenarioRunner(sessions={'spi_host': session},
                    ownership=ownership, bindings=())

            seed = ScenarioGenome(testcase_id='ot-spi-host-genome-rx',
                direction='IP_TO_CPU', path_id='source-word-real-rxfifo',
                schedule_order=('spi_host',), max_steps=700,
                actions=(Action('external-word', 'spi_host', 'spi_source_word',
                                0x12345678, 'IP_TO_CPU', Trigger('START')),))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_spi_source_word', 'spi_host',
                    'spi_source_word', 0, 32, ('IP_TO_CPU',)),),
                rules=(DependencyRule('spi_host.rx_word',
                    ('external_spi_source_word',), 'DATA_BINDING'),))
            plan = choose_mutation(graph, {'spi_host.rx_word': 1},
                                   direction='IP_TO_CPU')
            changed = mutate_genome(seed, plan, graph, ownership, bit_index=0)
            self.assertEqual(0x12345679, changed.actions[0].value)
            for case in (seed, changed):
                word = case.actions[0].value
                bundle = work / f'evidence-{word:08x}'
                trace = save_evidence_bundle(case, factory, bundle,
                    budget=ResourceBudget(max_wall_time_ms=180000,
                                          max_transactions=4))
                self.assertEqual('complete', trace.status, trace.events[-3:])
                expected = int.from_bytes(word.to_bytes(4, 'big'), 'little')
                self.assertEqual(expected, sessions[-1].rx_word)
                self.assertEqual(32, sessions[-1].peer.sample_count)
                self.assertEqual([word], [event['value'] for event in trace.events
                    if event.get('kind') == 'source_injection'
                    and event.get('component') == 'spi_host'])
                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual(expected, sessions[-1].rx_word)

    def test_genome_source_is_locked_after_transfer_starts(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ot-spi-host-source-lock-') as directory:
            session = GeneratedOpentitanSpiHostSession(_artifact(), base_dir=ROOT,
                cache_dir=Path(directory) / 'cache', source=None,
                setup_writes=((0x10, 0xa0000001), (0x18, 8), (0x20, 0x68)),
                read_rx_on_complete=True)
            session.begin_case('ot-spi-source-lock')
            try:
                session.step_local({'spi_source_word': 0x12345678})
                tick = session.local_ticks
                with self.assertRaisesRegex(ValueError, 'cannot change'):
                    session.step_local({'spi_source_word': 0x12345679})
                self.assertEqual(tick, session.local_ticks)
                self.assertEqual(bytes.fromhex('12 34 56 78'),
                                 bytes(session.peer._payload))
            finally:
                session.end_case()


if __name__ == '__main__':
    unittest.main()
