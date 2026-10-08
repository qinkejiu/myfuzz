"""Real SPI Device upload-payload IRQ reaches a CV32E40P MEI handler."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedOpentitanSpiDeviceSession, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
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
BASE = 0x40000000
VECTOR = 0x10100
ISR = 0x10200
RESULT = 0x20000


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile,
        instance_id=instance, reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
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


def _jal(rd: int, offset: int) -> int:
    immediate = offset & 0x1fffff
    return (((immediate >> 20) & 1) << 31
            | ((immediate >> 1) & 0x3ff) << 21
            | ((immediate >> 11) & 1) << 20
            | ((immediate >> 12) & 0xff) << 12
            | rd << 7 | 0x6f)


def _csrrs(rd: int, csr: int, rs1: int = 0) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _genome() -> ScenarioGenome:
    main = (
        _lui(7, 0x10), _addi(7, 7, 0x100),
        0x30539073,  # csrrw x0, mtvec, x7
        _lui(7, 1), _addi(7, 7, -0x800),
        0x30439073,  # csrrw x0, mie, x7: MEIE
        _addi(7, 0, 8), 0x30039073,  # mstatus.MIE
        _lui(1, 0x40000),
        _addi(2, 0, 0x10), _sw(2, 1, 0x10),
        _lui(2, 0x81010), _addi(2, 2, 0x202), _sw(2, 1, 0xa8),
        _addi(2, 0, 2), _sw(2, 1, 0x04),
        0x0000006f,
    )
    vectors = [_jal(0, 0)] * 64
    vectors[0] = _jal(0, ISR - VECTOR)
    # A vectored IRQ 11 enters 0x1012c and stays in its own loop.
    assert vectors[11] == 0x0000006f
    isr = (
        _lui(1, BASE >> 12),
        _lui(20, RESULT >> 12),
        _lui(9, 0x40002), _addi(9, 9, -0x200),
        _lw(3, 1, 0x00),          # actual INTR_STATE
        _lw(4, 1, 0x44),          # actual command FIFO
        _lw(5, 1, 0x48),          # actual address FIFO
        _lw(6, 9, 0),             # actual ingress SRAM
        _csrrs(8, 0x342),        # actual mcause
        _sw(3, 20, 0), _sw(4, 20, 4), _sw(5, 20, 8),
        _sw(6, 20, 12), _sw(8, 20, 16),
        _addi(7, 0, 2), _sw(7, 1, 0x00),  # upload payload W1C
        _lw(10, 1, 0x00), _sw(10, 20, 20),
        _addi(7, 0, 0x55), _sw(7, 20, 24),
        0x30200073,              # MRET
    )
    return ScenarioGenome(
        testcase_id='cv32e40p-spi-device-upload-mei',
        direction='CPU_TO_IP_TO_CPU',
        path_id='external-master-frame-upload-irq-cv32e40p-isr',
        schedule_order=('cpu', 'spi_device'), max_steps=1800,
        actions=(Action('external-upload', 'spi_device', 'master_frame',
            0x0012345a, 'CPU_TO_IP_TO_CPU',
            Trigger('AFTER_OUTPUT', 'cpu', 'data_addr', 0xffffffff, BASE + 4),
            delay_component='cpu', delay_ticks=30),),
        initial_images=(
            MemoryImage('cpu.main', 'cpu', 0x10000, _image(main)),
            MemoryImage('cpu.vector', 'cpu', VECTOR, _image(tuple(vectors))),
            MemoryImage('cpu.isr', 'cpu', ISR, _image(isr)),
            MemoryImage('cpu.result', 'cpu', RESULT, '00' * 28),
        ))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCv32e40pOpentitanSpiDeviceIrqTests(unittest.TestCase):
    def test_upload_payload_irq_is_serviced_and_freshly_replayed(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cv32-spi-device-mei-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e40p/component_profile.json', 'cpu')
            spi_artifact = _artifact(
                'configs/peripherals/opentitan_spi_device_local/component_profile.json',
                'spi_device')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1),
                 InputField('spi_device', 'master_frame', 32)),
                (InputOwner('cpu', 'irq', 0, 1, 'bound', 'spi_device.irq_o'),
                 InputOwner('spi_device', 'master_frame', 0, 32, 'source',
                            'external_spi_master_frame')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                spi = GeneratedOpentitanSpiDeviceSession(spi_artifact,
                    base_dir=ROOT, cache_dir=work / 'cache', cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('spi_device', BASE, 0x2000, spi),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'spi_device': spi},
                    ownership=ownership,
                    bindings=(Binding('spi_device', 'irq_o', 'cpu', 'irq', 1,
                                      source_bit_offset=1),))
                instances.append(runner)
                return runner

            graph = DependencyGraph(
                sources=(FuzzableSource('external_spi_master_frame', 'spi_device',
                    'master_frame', 0, 32, ('CPU_TO_IP_TO_CPU',)),),
                rules=(DependencyRule('spi_device.upload_payload',
                    ('external_spi_master_frame',), 'DATA_BINDING'),
                    DependencyRule('cpu.result_ram', ('spi_device.upload_payload',),
                                   'PERSISTENT_STATE_RULE')))
            seed = _genome()
            mutation = choose_mutation(graph, {'cpu.result_ram': 1},
                                       direction='CPU_TO_IP_TO_CPU')
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=0)
            self.assertEqual(0x0012345b, changed.actions[0].value)
            budget = ResourceBudget(
                max_transactions=512, max_local_cycles_per_component=4096,
                max_scheduler_steps=4096, max_wall_time_ms=300000,
                max_materialized_bytes_per_memory=0x20000,
                max_semantic_records=30000, max_evidence_bytes=64 * 1024 * 1024)
            payloads = []
            hashes = []
            for genome in (seed, changed):
                frame = genome.actions[0].value
                bundle = work / f'evidence-{frame:08x}'
                trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-8:])
                original = instances[-1]
                cpu = original.sessions['cpu']
                events = trace.events
                deliveries = [event for event in events
                    if event.get('kind') == 'mmio_delivery'
                    and event.get('device_id') == 'spi_device']
                writes = [event for event in deliveries if event.get('write')]
                self.assertEqual([(0x10, 0x10), (0xa8, 0x81010202),
                                  (0x04, 2), (0x00, 2)],
                    [(event['offset'], event['write_value']) for event in writes])
                source = [event for event in events
                    if event.get('kind') == 'source_injection'
                    and event.get('component') == 'spi_device']
                self.assertEqual([frame], [event['value'] for event in source])
                self.assertLess(writes[2]['event_id'], source[0]['event_id'])
                transactions = [tuple(event['source_transaction'][key] for key in
                    ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
                    for event in deliveries]
                self.assertEqual(len(transactions), len(set(transactions)))
                self.assertEqual({'cpu'}, {key[0] for key in transactions})
                self.assertEqual({0}, {key[1] for key in transactions})

                irq_events = [event for event in events
                    if event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ())) == ('spi_device', 'irq_o')
                    and tuple(event.get('target', ())) == ('cpu', 'irq')]
                high = next((event for event in irq_events if event['value'] == 1), None)
                self.assertIsNotNone(high, 'native upload-payload IRQ never reached MEI')
                producer = next(event for event in events
                    if event['event_id'] == high['producer_event_id'])
                self.assertEqual('spi_device', producer.get('component'))
                self.assertEqual(2, producer['outputs']['irq_o'] & 2)
                self.assertLess(source[0]['event_id'], producer['event_id'])
                cpu_steps = [event for event in events
                    if event.get('component') == 'cpu' and 'outputs' in event]
                ack = next((event for event in cpu_steps
                    if event.get('inputs', {}).get('irq') == 1
                    and event['outputs'].get('irq_ack_o') == 1
                    and event['outputs'].get('irq_id_o') == 11), None)
                self.assertIsNotNone(ack, 'CV32E40P did not ack physical irq_i[11]')
                fetch = next((event for event in cpu_steps
                    if event['event_id'] > ack['event_id']
                    and event['outputs'].get('instr_req_accepted') == 1), None)
                self.assertIsNotNone(fetch)
                self.assertEqual(VECTOR, fetch['outputs']['instr_addr'])
                self.assertLess(producer['event_id'], high['event_id'])
                self.assertLess(high['event_id'], ack['event_id'])

                reads = [event for event in deliveries if not event.get('write')]
                self.assertEqual([0x00, 0x44, 0x48, 0x1e00, 0x00],
                                 [event['offset'] for event in reads])
                self.assertLess(fetch['event_id'], reads[0]['event_id'])
                self.assertEqual(2, reads[0]['read_value'] & 2)
                self.assertEqual(2, reads[1]['read_value'] & 255)
                self.assertEqual((frame >> 8) & 0xffffff,
                                 reads[2]['read_value'] & 0xffffff)
                payload = reads[3]['read_value'] & 255
                self.assertEqual(frame & 255, payload)
                self.assertEqual(0, reads[4]['read_value'] & 2)
                self.assertLess(reads[3]['event_id'], writes[3]['event_id'])
                self.assertLess(writes[3]['event_id'], reads[4]['event_id'])
                low = next((event for event in irq_events
                    if event['value'] == 0
                    and event['event_id'] > writes[3]['event_id']), None)
                self.assertIsNotNone(low, 'W1C did not lower real upload IRQ')
                low_producer = next(event for event in events
                    if event['event_id'] == low['producer_event_id'])
                self.assertEqual(0, low_producer['outputs']['irq_o'] & 2)

                expected_ram = [reads[0]['read_value'], reads[1]['read_value'],
                    reads[2]['read_value'], reads[3]['read_value'],
                    0x8000000b, reads[4]['read_value'], 0x55]
                ram_writes = [event for event in events
                    if event.get('kind') == 'memory_write'
                    and event.get('component') == 'cpu'
                    and RESULT <= event.get('address', -1) < RESULT + 28]
                self.assertEqual([(RESULT + 4 * i, value)
                                  for i, value in enumerate(expected_ram)],
                    [(event['address'], event['value']) for event in ram_writes])
                self.assertTrue(any(event['event_id'] > ram_writes[-1]['event_id']
                    and event['outputs'].get('instr_req_accepted') == 1
                    and event['outputs'].get('instr_addr') == 0x10040
                    for event in cpu_steps), 'MRET did not resume the CPU wait loop')
                for i, value in enumerate(expected_ram):
                    self.assertEqual(value, cpu.memory.read(RESULT + 4 * i, 4,
                        transaction_id=f'accept-{frame:08x}-{i}').value)
                self.assertFalse(any(event.get('kind') in
                    ('reset_barrier', 'reset_failure') for event in events))
                self.assertEqual({0}, {s.reset_epoch for s in original.sessions.values()})
                result = json.loads((bundle / 'result.json').read_text())
                usage = result['resource_usage']
                self.assertLessEqual(usage['transactions'], budget.max_transactions)
                self.assertLessEqual(usage['scheduler_steps'], budget.max_scheduler_steps)
                self.assertLessEqual(usage['evidence_bytes'], budget.max_evidence_bytes)
                self.assertLessEqual(max(trace.local_ticks.values()),
                                     budget.max_local_cycles_per_component)

                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual('full', replay.verification_scope)
                replay_runner = instances[-1]
                for component in ('cpu', 'spi_device'):
                    self.assertIsNot(original.sessions[component],
                                     replay_runner.sessions[component])
                self.assertEqual({0}, {s.reset_epoch
                                       for s in replay_runner.sessions.values()})
                for i, value in enumerate(expected_ram):
                    self.assertEqual(value,
                        replay_runner.sessions['cpu'].memory.read(RESULT + 4 * i, 4,
                            transaction_id=f'replay-{frame:08x}-{i}').value)
                payloads.append(payload)
                hashes.append(trace.semantic_sha256)
            self.assertEqual([0x5a, 0x5b], payloads)
            self.assertNotEqual(hashes[0], hashes[1])
            self.assertEqual(4, len(instances))
