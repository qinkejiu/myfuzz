"""Real OpenTitan I2C command-complete MEI service by CV32E40P."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanI2cSession,
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
BASE, VECTOR, ISR, RESULT = 0x40000000, 0x10100, 0x10300, 0x20000
IRQ_BIT = 0x200


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _lui(rd, upper):
    return upper << 12 | rd << 7 | 0x37


def _addi(rd, rs1, immediate):
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _csrrw(csr, rs1):
    return csr << 20 | rs1 << 15 | 1 << 12 | 0x73


def _jal(rd, offset):
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 |
            ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 |
            rd << 7 | 0x6f)


def _image(words):
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _program_images():
    main = (
        # CV32E40P implements mtvec[31:8]: aligned direct vector.
        _lui(7, 0x10), _addi(7, 7, 0x100), _csrrw(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrw(0x304, 7),  # MEIE
        _addi(7, 0, 8), _csrrw(0x300, 7),  # MIE
        _lui(1, BASE >> 12),
        _lui(2, 0x100), _addi(2, 2, 0x10), _sw(2, 1, 0x3c),
        _lui(2, 0x20), _addi(2, 2, 2), _sw(2, 1, 0x40),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x44),
        _lui(2, 0x40), _addi(2, 2, 4), _sw(2, 1, 0x48),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x4c),
        _addi(2, 0, IRQ_BIT), _sw(2, 1, 0x04),
        _addi(2, 0, 1), _sw(2, 1, 0x10),
        _addi(2, 0, 0x1a1), _sw(2, 1, 0x1c),  # START + address
        _addi(2, 0, 0x601), _sw(2, 1, 0x1c),  # READ + STOP
        0x10500073, _jal(0, -4),  # WFI avoids fetch traffic while I2C shifts.
    )
    wait_pc = 0x10000 + 4 * (len(main) - 2)
    vectors = [0x0000006f] * 64
    vectors[0] = _jal(0, ISR - VECTOR)
    assert vectors[11] == 0x0000006f  # Vectored MEI slot must hang.
    isr = (
        _lui(1, BASE >> 12), _lui(20, RESULT >> 12),
        _lw(3, 1, 0x00), _lw(4, 1, 0x18),
        0x342022f3,  # CSRRS x5, mcause, x0: CPU CSR, no MMIO.
        _sw(3, 20, 0), _sw(4, 20, 4), _sw(5, 20, 8),
        _addi(7, 0, IRQ_BIT), _sw(7, 1, 0x00),
        _lw(6, 1, 0x00), _sw(6, 20, 12),
        _addi(7, 0, 0x55), _sw(7, 20, 16),
        0x30200073,
    )
    return wait_pc, (
        MemoryImage('cpu.main', 'cpu', 0x10000, _image(main)),
        MemoryImage('cpu.vector', 'cpu', VECTOR, _image(vectors)),
        MemoryImage('cpu.isr', 'cpu', ISR, _image(isr)),
        MemoryImage('cpu.result', 'cpu', RESULT, '00' * 20),
    )


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCv32e40pOpentitanI2cIrqTests(unittest.TestCase):
    def test_peer_byte_reaches_native_command_complete_irq_and_cpu_isr(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cv32-i2c-mei-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e40p/component_profile.json', 'cpu')
            i2c_artifact = _artifact(
                'configs/peripherals/opentitan_i2c_local/component_profile.json', 'i2c')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('i2c', 'peer_response', 8)),
                (InputOwner('cpu', 'irq', 0, 1, 'bound', 'i2c.irq_o'),
                 InputOwner('i2c', 'peer_response', 0, 8, 'source', 'external_i2c_peer')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                i2c = GeneratedOpentitanI2cSession(i2c_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache')
                router = DataflowRouter((DeviceWindow('i2c', BASE, 0x1000, i2c),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'i2c': i2c},
                    ownership=ownership,
                    bindings=(Binding('i2c', 'irq_o', 'cpu', 'irq', 1,
                                      source_bit_offset=9),))
                instances.append(runner)
                return runner

            wait_pc, images = _program_images()
            seed = ScenarioGenome(testcase_id='cv32e40p-ot-i2c-command-complete-mei',
                direction='IP_TO_CPU', path_id='peer-serial-rdata-mei-isr-ram',
                schedule_order=('i2c', 'cpu'), max_steps=6000,
                actions=(Action('peer-byte', 'i2c', 'peer_response', 0x5a,
                                'IP_TO_CPU', Trigger('START')),),
                initial_images=images)
            graph = DependencyGraph(
                sources=(FuzzableSource('external_i2c_peer', 'i2c',
                    'peer_response', 0, 8, ('IP_TO_CPU',)),),
                rules=(DependencyRule('i2c.rdata', ('external_i2c_peer',),
                                      'DATA_BINDING'),
                       DependencyRule('cpu.result_ram', ('i2c.rdata',),
                                      'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1},
                                       direction='IP_TO_CPU')
            self.assertEqual('external_i2c_peer', mutation.focus_source)
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=0)
            self.assertEqual(0x5b, changed.actions[0].value)
            budget = ResourceBudget(max_transactions=512,
                max_local_cycles_per_component=8192, max_scheduler_steps=12000,
                max_wall_time_ms=300000,
                max_materialized_bytes_per_memory=0x20000,
                max_evidence_bytes=64 * 1024 * 1024)
            rdata_values, ram_values, hashes = [], [], []
            for genome in (seed, changed):
                byte = genome.actions[0].value
                bundle = work / f'evidence-{byte:02x}'
                trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-8:])
                original = instances[-1]
                cpu = original.sessions['cpu']
                events = trace.events
                sources = [event for event in events
                    if event.get('kind') == 'source_injection']
                self.assertEqual([('i2c', 'peer_response', byte, 'external_i2c_peer')],
                    [(e['component'], e['port'], e['value'], e['source_ref'])
                     for e in sources])
                self.assertIn({'component_id': 'cpu', 'port': 'irq',
                    'bit_offset': 0, 'width': 1, 'kind': 'bound',
                    'producer_ref': 'i2c.irq_o'},
                    original.ownership.document()['owners'])

                deliveries = [event for event in events
                    if event.get('kind') == 'mmio_delivery'
                    and event.get('device_id') == 'i2c']
                writes = [event for event in deliveries if event['write']]
                self.assertEqual([
                    (0x3c, 0x00100010), (0x40, 0x00020002),
                    (0x44, 0x00080008), (0x48, 0x00040004),
                    (0x4c, 0x00080008), (0x04, 0x200), (0x10, 1),
                    (0x1c, 0x1a1), (0x1c, 0x601), (0x00, 0x200)],
                    [(e['offset'], e['write_value']) for e in writes])
                self.assertLess(sources[0]['event_id'], writes[7]['event_id'],
                    'START only configures the environment peer before FDATA')
                keys = [tuple(e['source_transaction'][field] for field in
                    ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
                    for e in deliveries]
                self.assertEqual(len(keys), len(set(keys)))
                self.assertEqual({'cpu'}, {key[0] for key in keys})
                self.assertEqual({0}, {key[1] for key in keys})

                samples = [e for e in events if e.get('kind') == 'local_tick_sample'
                           and e.get('component') == 'i2c']
                # The first accepted FDATA is the CPU START/address command.
                accepted = [e for e in events if e.get('kind') == 'mmio_acceptance'
                    and e.get('device_id') == 'i2c' and e.get('write')
                    and e.get('offset') == 0x1c]
                self.assertEqual([0x1a1, 0x601], [e['write_value'] for e in accepted])
                starts = [e for previous, e in zip(samples, samples[1:])
                    if e['event_id'] > accepted[0]['event_id']
                    and previous['outputs']['scl_i'] == e['outputs']['scl_i'] == 1
                    and previous['outputs']['sda_i'] == 1
                    and e['outputs']['sda_i'] == 0
                    and e['outputs']['sda_en_o'] == 1]
                self.assertTrue(starts, 'first FDATA did not cause a real serial START')
                start = starts[0]
                self.assertFalse(any(e['event_id'] < accepted[0]['event_id']
                    and e['outputs']['sda_en_o'] == 1 for e in samples))
                self.assertTrue(any(e['event_id'] > start['event_id']
                    and e['outputs']['scl_en_o'] == 1 for e in samples))
                read_clock_edges = [e for previous, e in zip(samples, samples[1:])
                    if e['event_id'] > accepted[1]['event_id']
                    and previous['outputs']['scl_i'] == 0
                    and e['outputs']['scl_i'] == 1]
                self.assertGreaterEqual(len(read_clock_edges), 16,
                    'second FDATA must precede address and one-byte READ clocks')
                edge_bits = tuple(e['outputs']['sda_i'] for e in read_clock_edges)
                expected_bits = tuple((byte >> bit) & 1 for bit in range(7, -1, -1))
                self.assertTrue(any(edge_bits[index:index + 8] == expected_bits
                    for index in range(len(edge_bits) - 7)),
                    f'peer byte {byte:#04x} absent from SCL rising-edge SDA samples: '
                    f'{edge_bits}')
                self.assertTrue(all(e['outputs']['scl_o'] == 0
                                    and e['outputs']['sda_o'] == 0 for e in samples))

                irq_deliveries = [e for e in events
                    if e.get('kind') == 'dataflow_delivery'
                    and tuple(e.get('source', ())) == ('i2c', 'irq_o')
                    and tuple(e.get('target', ())) == ('cpu', 'irq')]
                high = next((e for e in irq_deliveries if e['value'] == 1), None)
                self.assertIsNotNone(high, 'native irq_o[9] never reached CPU MEI')
                high_sample = next(e for e in samples
                    if e['event_id'] == high['producer_event_id'])
                self.assertEqual(IRQ_BIT, high_sample['outputs']['irq_o'] & IRQ_BIT)
                self.assertLess(writes[8]['event_id'], high_sample['event_id'])
                self.assertLess(high_sample['event_id'], writes[9]['event_id'])
                cpu_steps = [e for e in events
                    if e.get('component') == 'cpu' and 'outputs' in e]
                ack = next((e for e in cpu_steps
                    if e.get('inputs', {}).get('irq') == 1
                    and e['outputs'].get('irq_ack_o') == 1
                    and e['outputs'].get('irq_id_o') == 11), None)
                self.assertIsNotNone(ack, 'CV32E40P did not acknowledge physical IRQ11')
                self.assertTrue(any(e['event_id'] < high['event_id']
                    and e['outputs'].get('core_sleep_o') == 1 for e in cpu_steps),
                    'WFI did not park CPU instruction traffic during serial transfer')
                self.assertEqual(0, ack['outputs'].get('core_sleep_o'))
                fetch = next((e for e in cpu_steps
                    if e['event_id'] > ack['event_id']
                    and e['outputs'].get('instr_req_accepted') == 1), None)
                self.assertIsNotNone(fetch)
                self.assertEqual(VECTOR, fetch['outputs']['instr_addr'])
                self.assertLess(high['event_id'], ack['event_id'])

                reads = [e for e in deliveries if not e['write']]
                self.assertEqual([0x00, 0x18, 0x00], [e['offset'] for e in reads])
                self.assertLess(fetch['event_id'], reads[0]['event_id'])
                self.assertEqual(IRQ_BIT, reads[0]['read_value'] & IRQ_BIT)
                self.assertEqual(byte, reads[1]['read_value'] & 0xff)
                self.assertLess(accepted[1]['event_id'], reads[1]['event_id'])
                self.assertLess(reads[1]['event_id'], writes[9]['event_id'])
                self.assertLess(writes[9]['event_id'], reads[2]['event_id'])
                self.assertEqual(0, reads[2]['read_value'] & IRQ_BIT)
                low_sample = next((e for e in samples
                    if e['event_id'] > writes[9]['event_id']
                    and e['local_tick'] > high_sample['local_tick']
                    and e['outputs']['irq_o'] & IRQ_BIT == 0), None)
                self.assertIsNotNone(low_sample,
                    'real irq_o[9] did not fall on a later local tick after W1C')

                expected_ram = [reads[0]['read_value'], reads[1]['read_value'],
                                0x8000000b, reads[2]['read_value'], 0x55]
                ram_writes = [e for e in events if e.get('kind') == 'memory_write'
                    and e.get('component') == 'cpu'
                    and RESULT <= e.get('address', -1) < RESULT + 20]
                self.assertEqual([(RESULT + 4 * i, value)
                                  for i, value in enumerate(expected_ram)],
                    [(e['address'], e['value']) for e in ram_writes])
                self.assertTrue(any(e['event_id'] > ram_writes[-1]['event_id']
                    and e['outputs'].get('instr_req_accepted') == 1
                    and e['outputs'].get('instr_addr') in (wait_pc, wait_pc + 4)
                    for e in cpu_steps),
                    'MRET did not resume the main wait loop')
                for i, value in enumerate(expected_ram):
                    self.assertEqual(value, cpu.memory.read(RESULT + 4 * i, 4,
                        transaction_id=f'accept-{byte:02x}-{i}').value)
                self.assertFalse(any(e.get('kind') in ('reset_barrier', 'reset_failure')
                                     for e in events))
                self.assertEqual({0}, {s.reset_epoch for s in original.sessions.values()})
                usage = json.loads((bundle / 'result.json').read_text())['resource_usage']
                self.assertLessEqual(usage['transactions'], budget.max_transactions)
                self.assertLessEqual(usage['scheduler_steps'], budget.max_scheduler_steps)
                self.assertLessEqual(usage['evidence_bytes'], budget.max_evidence_bytes)
                self.assertLessEqual(max(trace.local_ticks.values()),
                                     budget.max_local_cycles_per_component)

                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual('full', replay.verification_scope)
                replay_runner = instances[-1]
                for component in ('cpu', 'i2c'):
                    self.assertIsNot(original.sessions[component],
                                     replay_runner.sessions[component])
                self.assertEqual({0},
                    {s.reset_epoch for s in replay_runner.sessions.values()})
                for i, value in enumerate(expected_ram):
                    self.assertEqual(value,
                        replay_runner.sessions['cpu'].memory.read(RESULT + 4 * i, 4,
                            transaction_id=f'replay-{byte:02x}-{i}').value)
                rdata_values.append(reads[1]['read_value'] & 0xff)
                ram_values.append(expected_ram[1] & 0xff)
                hashes.append(trace.semantic_sha256)
            self.assertEqual([0x5a, 0x5b], rdata_values)
            self.assertEqual([0x5a, 0x5b], ram_values)
            self.assertNotEqual(hashes[0], hashes[1])
            self.assertEqual(4, len(instances))


if __name__ == '__main__':
    unittest.main()
