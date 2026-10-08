"""Real SPI RX watermark MEI service by CV32E40P, with source mutation and replay."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSpiHostSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
SPI_BASE = 0x40000000
RESULT = 0x20000


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _csrrw(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 1 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _program_images():
    main = (
        # CV32E40P implements mtvec[31:8]; use aligned direct 0x10100.
        _lui(7, 0x10), _addi(7, 7, 0x100), _csrrw(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrw(0x304, 7),
        _addi(7, 0, 8), _csrrw(0x300, 7),
        _lui(1, 0x40000),
        _lui(2, 0xa0000), _addi(2, 2, 1), _sw(2, 1, 0x10),
        _addi(2, 0, 8), _sw(2, 1, 0x18),
        _addi(2, 0, 4), _sw(2, 1, 0x34),
        _addi(2, 0, 2), _sw(2, 1, 0x04),
        _addi(2, 0, 0x68), _sw(2, 1, 0x20),
        0x0000006f,
    )
    # JAL x0,+0x100 skips the vector table. Other slots loop forever,
    # including IRQ11's 0x1012c, so a vectored-mode mistake cannot pass.
    vectors = (0x1000006f,) + (0x0000006f,) * 63
    isr = (
        *vectors, *((0x00000013,) * 64),
        # RXDATA must be the first Host access after COMMAND.
        _lw(4, 1, 0x24),
        0x342022f3,  # CSRRS x5,mcause,x0 reads the actual trap cause.
        _lui(6, 0x20), _sw(4, 6, 0), _sw(5, 6, 4),
        _addi(7, 0, 0x55), _sw(7, 6, 8),
        0x30200073,  # MRET resumes the main loop.
    )
    return (MemoryImage('cpu.main', 'cpu', 0x10000, _image(main)),
            MemoryImage('cpu.isr', 'cpu', 0x10100, _image(isr)),
            MemoryImage('cpu.result', 'cpu', RESULT, '00' * 12))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P and OpenTitan RTL')
class GeneratedCv32e40pOpentitanSpiHostIrqTests(unittest.TestCase):
    def test_spi_source_mutation_mei_isr_ram_and_fresh_full_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cv32e40p-ot-spi-host-irq-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e40p/component_profile.json', 'cpu')
            spi_artifact = _artifact(
                'configs/peripherals/opentitan_spi_host_local/component_profile.json',
                'spi_host')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('spi_host', 'spi_source_word', 32)),
                (InputOwner('cpu', 'irq', 0, 1, 'bound', 'spi_host.irq_event'),
                 InputOwner('spi_host', 'spi_source_word', 0, 32, 'source',
                            'external_spi_source_word')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                spi = GeneratedOpentitanSpiHostSession(spi_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', source=None, cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('spi_host', SPI_BASE, 0x1000, spi),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router, defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'spi_host': spi},
                    ownership=ownership,
                    bindings=(Binding('spi_host', 'irq_event', 'cpu', 'irq', 1),))
                instances.append(runner)
                return runner

            seed = ScenarioGenome(testcase_id='cv32e40p-ot-spi-host-mei',
                direction='IP_TO_CPU', path_id='spi-source-rtl-mei-isr-cpu-ram',
                schedule_order=('spi_host', 'cpu'), max_steps=1800,
                actions=(Action('external-word', 'spi_host', 'spi_source_word',
                    0x12345678, 'IP_TO_CPU', Trigger('START')),),
                initial_images=_program_images())
            graph = DependencyGraph(
                sources=(FuzzableSource('external_spi_source_word', 'spi_host',
                    'spi_source_word', 0, 32, ('IP_TO_CPU',)),),
                rules=(DependencyRule('spi_host.rx_word',
                    ('external_spi_source_word',), 'DATA_BINDING'),
                    DependencyRule('cpu.result_ram', ('spi_host.rx_word',),
                                   'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1}, direction='IP_TO_CPU')
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=0)
            self.assertEqual(0x12345679, changed.actions[0].value)
            budget = ResourceBudget(max_transactions=512,
                max_local_cycles_per_component=2048, max_scheduler_steps=4096,
                max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x20000,
                max_evidence_bytes=64 * 1024 * 1024)
            ram_values, hashes = [], []
            for case in (seed, changed):
                word = case.actions[0].value
                expected = int.from_bytes(word.to_bytes(4, 'big'), 'little')
                bundle = work / f'evidence-{word:08x}'
                trace = save_evidence_bundle(case, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-8:])
                original = instances[-1]
                events = trace.events
                cpu, spi = original.sessions['cpu'], original.sessions['spi_host']
                deliveries = [event for event in events
                    if event.get('kind') == 'mmio_delivery'
                    and event.get('device_id') == 'spi_host']
                writes = [event for event in deliveries if event['write']]
                self.assertEqual([(0x10, 0xa0000001), (0x18, 8), (0x34, 4),
                                  (0x04, 2), (0x20, 0x68)],
                    [(event['offset'], event['write_value']) for event in writes])
                transactions = [tuple(event['source_transaction'][field] for field in
                    ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
                    for event in deliveries]
                self.assertEqual(len(transactions), len(set(transactions)))
                self.assertEqual({'cpu'}, {key[0] for key in transactions})
                self.assertEqual({0}, {key[1] for key in transactions})
                reads = [event for event in deliveries if not event['write']]
                self.assertEqual([(0x24, expected)],
                    [(event['offset'], event['read_value']) for event in reads],
                    'ISR must consume actual RXDATA first and exactly once; '
                    + repr(dict(local_ticks=trace.local_ticks, peer_samples=spi.peer.sample_count,
                        cpu_tail=[(event.get('local_tick'),
                            event.get('inputs', {}).get('irq'),
                            event.get('outputs', {}).get('instr_addr'),
                            event.get('outputs', {}).get('irq_ack_o'))
                            for event in events if event.get('component') == 'cpu'
                            and 'outputs' in event][-8:])))
                self.assertEqual(32, spi.peer.sample_count)
                self.assertEqual(4, spi.peer.payload_index)
                self.assertEqual([word], [event['value'] for event in events
                    if event.get('kind') == 'source_injection'
                    and event.get('component') == 'spi_host'])

                irq_deliveries = [event for event in events
                    if event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ())) == ('spi_host', 'irq_event')
                    and tuple(event.get('target', ())) == ('cpu', 'irq')]
                irq = next((event for event in irq_deliveries if event['value'] == 1), None)
                self.assertIsNotNone(irq, 'native Host IRQ never reached CV32E40P')
                producer = next(event for event in events
                    if event['event_id'] == irq['producer_event_id'])
                self.assertEqual(1, producer['outputs']['irq_event'])
                cpu_steps = [event for event in events
                    if event.get('component') == 'cpu' and 'outputs' in event]
                ack = next((event for event in cpu_steps
                    if event.get('inputs', {}).get('irq') == 1
                    and event['outputs'].get('irq_ack_o') == 1
                    and event['outputs'].get('irq_id_o') == 11), None)
                self.assertIsNotNone(ack, 'CV32E40P did not acknowledge IRQ 11 while high')
                self.assertLess(producer['event_id'], irq['event_id'])
                self.assertLess(irq['event_id'], ack['event_id'])
                fetch = next((event for event in cpu_steps
                    if event['event_id'] > ack['event_id']
                    and event['outputs'].get('instr_req_accepted') == 1), None)
                self.assertIsNotNone(fetch)
                self.assertEqual(0x10100, fetch['outputs']['instr_addr'])
                self.assertLess(ack['event_id'], reads[0]['event_id'])
                low = next((event for event in irq_deliveries
                    if event['value'] == 0 and event['event_id'] > reads[0]['event_id']), None)
                self.assertIsNotNone(low, 'RXDATA consumption did not lower the real Host IRQ')
                low_producer = next(event for event in events
                    if event['event_id'] == low['producer_event_id'])
                self.assertEqual(0, low_producer['outputs']['irq_event'])

                expected_ram = [(RESULT, expected), (RESULT + 4, 0x8000000b),
                                (RESULT + 8, 0x55)]
                ram_writes = [event for event in events
                    if event.get('kind') == 'memory_write'
                    and event.get('component') == 'cpu'
                    and event.get('address') in (RESULT, RESULT + 4, RESULT + 8)]
                self.assertEqual(expected_ram,
                    [(event['address'], event['value']) for event in ram_writes])
                self.assertTrue(any(event['event_id'] > ram_writes[-1]['event_id']
                    and event['outputs'].get('instr_req_accepted') == 1
                    and event['outputs'].get('instr_addr') == 0x10050
                    for event in cpu_steps), 'MRET did not resume the main loop')
                for address, value in expected_ram:
                    self.assertEqual(value, cpu.memory.read(address, 4,
                        transaction_id=f'acceptance-{word:08x}-{address:x}').value)
                self.assertFalse(any(event.get('kind') in ('reset_barrier', 'reset_failure')
                                     for event in events))
                self.assertEqual({0}, {session.reset_epoch for session in original.sessions.values()})
                result = json.loads((bundle / 'result.json').read_text())
                usage = result['resource_usage']
                self.assertLessEqual(usage['transactions'], 512)
                self.assertLessEqual(usage['scheduler_steps'], 4096)
                self.assertLessEqual(sum('inputs' in event and 'outputs' in event
                                         for event in events), 1800)
                self.assertLessEqual(usage['evidence_bytes'], budget.max_evidence_bytes)

                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual('full', replay.verification_scope)
                replay_runner = instances[-1]
                for component in ('cpu', 'spi_host'):
                    self.assertIsNot(original.sessions[component], replay_runner.sessions[component])
                self.assertEqual({0}, {session.reset_epoch for session in replay_runner.sessions.values()})
                for address, value in expected_ram:
                    self.assertEqual(value, replay_runner.sessions['cpu'].memory.read(address, 4,
                        transaction_id=f'replay-{word:08x}-{address:x}').value)
                ram_values.append(expected)
                hashes.append(trace.semantic_sha256)
            self.assertEqual([0x78563412, 0x79563412], ram_values)
            self.assertNotEqual(hashes[0], hashes[1])
            self.assertEqual(4, len(instances))


if __name__ == '__main__':
    unittest.main()
