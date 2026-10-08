"""Two native PULP I2C completion IRQs enter real CVA6 M_EXT handlers."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.i2c_session import GeneratedPulpI2cSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner

from tests.integration.test_scenario_cva6_generated_opentitan_gpio_mext_irq_real import (
    ROOT, BOOT, _artifact, _lui, _addi, _lw, _sw, _sd, _bne, _csr)


I2C_BASE = 0x40000000
RESULT = 0x20000
MTVEC = 0x10100
CAUSE_MEXT = 0x800000000000000b
PEER_SEED = 0x5a
PEER_MUTANT = 0xa6
SECOND_ISR_ENTRY_WORD = 13


def _beq(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def _program() -> tuple[bytes, bytes]:
    # Fixed CPU firmware. Only the external I2C peer response is fuzzable.
    main = [
        _lui(1, MTVEC >> 12), _addi(1, 1, MTVEC & 0xfff),
        _csr(1, 0, 0x305, 1),                  # mtvec = 0x10100, direct mode
        _lui(1, 1), _addi(1, 1, -0x800),
        _csr(1, 0, 0x304, 1),                  # mie.MEIE = 1 << 11
        _addi(19, 0, 0),                      # ISR round counter
        _lui(8, RESULT >> 12),
        _lui(1, I2C_BASE >> 12),
        _addi(2, 0, 2), _sw(2, 1, 0),         # PRESCALER = 2
        _addi(2, 0, 0xc0), _sw(2, 1, 4),      # CTRL: enable + IRQ
        _addi(2, 0, 0x85), _sw(2, 1, 16),     # TX: 7-bit address 0x42 + read bit
        _addi(2, 0, 0x90), _sw(2, 1, 20),     # START + WRITE
        _addi(2, 0, 8), _csr(1, 0, 0x300, 2), # mstatus.MIE = 1
    ]
    first_poll = len(main)
    main += [
        _lw(3, 8, 4),
        _beq(3, 0, -4),                       # await first ISR marker
        _addi(2, 0, 0x68), _sw(2, 1, 20),     # second transaction: READ/NACK/STOP
    ]
    second_poll = len(main)
    main += [
        _lw(3, 8, 32),
        _beq(3, 0, -4),                       # await second ISR marker
        _addi(4, 0, 0x66), _sw(4, 8, 36),     # proves MRET returned to main
        0x0000006f,                            # stable terminal loop
    ]
    assert main[first_poll + 1] == _beq(3, 0, -4)
    assert main[second_poll + 1] == _beq(3, 0, -4)

    # Both entries use the same real direct-mode M_EXT vector. x19 is private
    # to the handler and distinguishes address-complete from read-complete IRQ.
    isr = [
        _lui(1, I2C_BASE >> 12), _lui(20, RESULT >> 12),
        _bne(19, 0, (SECOND_ISR_ENTRY_WORD - 2) * 4),
        _lw(2, 1, 12),                        # first: actual STATUS
        _csr(2, 4, 0x342, 0),                  # first: actual 64-bit mcause
        _sw(2, 20, 0), _sd(4, 20, 8),        # first status + mcause
        _addi(3, 0, 1), _sw(3, 1, 20),       # first real CMD IACK
        _addi(19, 19, 1),
        _addi(3, 0, 0x51), _sw(3, 20, 4),    # first completion marker
        0x30200073,                            # MRET
        _lw(5, 1, 8),                         # second: actual RX byte
        _lw(3, 1, 12),                        # second: STATUS after master NACK
        _csr(2, 4, 0x342, 0),                  # second: actual 64-bit mcause
        _sw(5, 20, 16), _sw(3, 20, 20), _sd(4, 20, 24),
        _addi(6, 0, 1), _sw(6, 1, 20),        # second real CMD IACK
        _addi(3, 0, 0x52), _sw(3, 20, 32),   # second completion marker
        0x30200073,                            # MRET
    ]
    assert isr[SECOND_ISR_ENTRY_WORD] == _lw(5, 1, 8)
    assert isr[2] == _bne(19, 0, (SECOND_ISR_ENTRY_WORD - 2) * 4)
    prefix = BOOT.read_bytes()[:16]
    pack = lambda words: b''.join(word.to_bytes(4, 'little') for word in words)
    return prefix + pack(main), pack(isr)


def _make_factory(cpu_artifact, i2c_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1), InputField('cpu', 'irq_timer', 1),
         InputField('i2c', 'peer_response', 8)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'bound', 'i2c.interrupt_o'),
         InputOwner('cpu', 'irq_timer', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('i2c', 'peer_response', 0, 8, 'source', 'external_i2c_peer')))
    irq = Binding('i2c', 'interrupt_o', 'cpu', 'irq_external', 1)
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        i2c = GeneratedPulpI2cSession(i2c_artifact, base_dir=ROOT,
                                      cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('i2c', I2C_BASE, 0x1000, i2c),))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'i2c': i2c},
                                ownership=ownership, bindings=(irq,))
        instances.append(runner)
        return runner

    return factory, instances, ownership


def _read_result(cpu, offset: int, width: int = 4) -> int:
    return cpu.memory.read(RESULT + offset, width,
        transaction_id=f'cva6-pulp-i2c-two-mext-{offset:x}-{width}').value


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCva6PulpI2cTwoMextIrqRealTests(unittest.TestCase):
    def test_peer_byte_mutation_reaches_two_real_mext_isrs_and_replays(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(
                prefix='myfuzz-cva6-pulp-i2c-two-mext-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json', 'cpu')
            i2c_artifact = _artifact('configs/peripherals/pulp_i2c/component_profile.json',
                                     'i2c')
            cache = Path(os.environ.get('MYFUZZ_CVA6_PULP_I2C_CACHE', work / 'cache'))
            factory, instances, ownership = _make_factory(cpu_artifact,
                                                            i2c_artifact, cache)
            program, isr = _program()
            seed = ScenarioGenome(
                testcase_id='cva6-generated-pulp-i2c-two-mext-5a',
                direction='IP_TO_CPU',
                path_id='i2c-peer-byte-native-irq-two-mext-isr-result-ram',
                schedule_order=('cpu', 'i2c'), max_steps=7000,
                actions=(Action('peer-response', 'i2c', 'peer_response', PEER_SEED,
                    'IP_TO_CPU', Trigger('START'), bit_offset=0, width=8),),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, program.hex()),
                    MemoryImage('cpu.mext_isr', 'cpu', MTVEC, isr.hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, bytes(40).hex()),))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_i2c_peer', 'i2c',
                    'peer_response', 0, 8, ('IP_TO_CPU',)),),
                rules=(DependencyRule('i2c.rxdata', ('external_i2c_peer',),
                                      'DATA_BINDING'),
                       DependencyRule('cpu.mmio_rdata', ('i2c.rxdata',),
                                      'DATA_BINDING'),
                       DependencyRule('cpu.peer_result_ram', ('cpu.mmio_rdata',),
                                      'PERSISTENT_STATE_RULE'),
                       # The native completion IRQ is caused by these fixed CPU
                       # commands, not by the independently mutable peer byte.
                       DependencyRule('i2c.address_completion', ('cpu.cmd_0x90',),
                                      'EVENT_ORDER'),
                       DependencyRule('i2c.read_completion', ('cpu.cmd_0x68',),
                                      'EVENT_ORDER'),
                       DependencyRule('cpu.address_mext_isr',
                                      ('i2c.address_completion',), 'EVENT_ORDER'),
                       DependencyRule('cpu.read_mext_isr',
                                      ('i2c.read_completion',), 'EVENT_ORDER'),
                       DependencyRule('cpu.irq_history_ram',
                                      ('cpu.address_mext_isr', 'cpu.read_mext_isr'),
                                      'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.peer_result_ram': 1},
                                       direction='IP_TO_CPU')
            self.assertEqual(('external_i2c_peer',), mutation.path.source_ids)
            self.assertEqual('external_i2c_peer', mutation.focus_source)
            changed = seed
            for bit in range(8):
                if (PEER_SEED ^ PEER_MUTANT) & (1 << bit):
                    changed = mutate_genome(changed, mutation, graph, ownership,
                        bit_index=bit,
                        action_id='peer-response')
            self.assertEqual(PEER_MUTANT, changed.actions[0].value)
            self.assertEqual(seed.initial_images, changed.initial_images)
            self.assertEqual(seed.actions[0].trigger, changed.actions[0].trigger)
            self.assertEqual(0x30200073, int.from_bytes(isr[-4:], 'little'))

            budget = ResourceBudget(max_transactions=2048,
                max_local_cycles_per_component=8192, max_scheduler_steps=12000,
                max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x40000,
                max_evidence_bytes=64 * 1024 * 1024)
            for genome in (seed, changed):
                peer_byte = genome.actions[0].value
                with self.subTest(peer_response=f'{peer_byte:#04x}'):
                    bundle = work / f'evidence-peer-{peer_byte:02x}'
                    trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                    self.assertEqual('complete', trace.status, trace.events[-12:])
                    original = instances[-1]
                    cpu, i2c = original.sessions['cpu'], original.sessions['i2c']
                    events = trace.events
                    injections = [event for event in events
                                  if event.get('kind') == 'source_injection']
                    self.assertEqual([(peer_byte, 'external_i2c_peer')],
                        [(event['value'], event['source_ref']) for event in injections])
                    self.assertEqual(('i2c', 'peer_response'),
                        (injections[0]['component'], injections[0]['port']))
                    owners = original.ownership.document()['owners']
                    self.assertIn({'component_id': 'cpu', 'port': 'irq_external',
                        'bit_offset': 0, 'width': 1, 'kind': 'bound',
                        'producer_ref': 'i2c.interrupt_o'}, owners)
                    self.assertIn({'component_id': 'cpu', 'port': 'irq_timer',
                        'bit_offset': 0, 'width': 1, 'kind': 'fixed',
                        'producer_ref': 'constant_zero'}, owners)
                    self.assertIn({'component_id': 'i2c', 'port': 'peer_response',
                        'bit_offset': 0, 'width': 8, 'kind': 'source',
                        'producer_ref': 'external_i2c_peer'}, owners)

                    deliveries = [event for event in events
                        if event.get('kind') == 'mmio_delivery'
                        and event.get('device_id') == 'i2c']
                    writes = [event for event in deliveries if event.get('write')]
                    reads = [event for event in deliveries if not event.get('write')]
                    self.assertEqual([(0, 2), (4, 0xc0), (16, 0x85),
                                      (20, 0x90), (20, 1), (20, 0x68), (20, 1)],
                        [(event['offset'], event['write_value']) for event in writes])
                    commands = [event['write_value'] for event in writes
                                if event['offset'] == 20 and event['write_value'] in (0x90, 0x68)]
                    self.assertEqual([0x90, 0x68], commands,
                        'CPU must complete address write before its later read command')
                    self.assertTrue(all(event['byte_enable'] == 15
                                        and event['beat_bytes'] == 8 for event in writes),
                        'APB3 accepts only full 32-bit writes')
                    self.assertEqual([12, 8, 12], [event['offset'] for event in reads])
                    self.assertEqual([peer_byte], [event['read_value'] & 0xff
                        for event in reads if event['offset'] == 8])
                    self.assertLess(writes[3]['event_id'], writes[4]['event_id'])
                    self.assertLess(writes[4]['event_id'], writes[5]['event_id'])
                    self.assertLess(writes[5]['event_id'], writes[6]['event_id'])

                    irq_samples = [event for event in events
                        if event.get('kind') == 'local_tick_sample'
                        and event.get('component') == 'i2c'
                        and event.get('outputs', {}).get('interrupt_o') in (0, 1)]
                    observed_edges = []
                    last = 0
                    for sample in irq_samples:
                        level = sample['outputs']['interrupt_o']
                        if level != last:
                            observed_edges.append((level, sample['local_tick'],
                                                   sample['event_id']))
                            last = level
                    self.assertEqual([1, 0, 1, 0], [edge[0] for edge in observed_edges],
                        'two native completions must each hold IRQ high until IACK')

                    wire_samples = [event for event in events
                        if event.get('kind') == 'local_tick_sample'
                        and event.get('component') == 'i2c'
                        and event.get('outputs', {}).get('scl_pad_i') in (0, 1)
                        and event.get('outputs', {}).get('sda_pad_i') in (0, 1)]
                    read_clock_edges = [event for previous, event in
                        zip(wire_samples, wire_samples[1:])
                        if event['event_id'] > writes[5]['event_id']
                        and event['event_id'] < observed_edges[2][2]
                        and previous['outputs']['scl_pad_i'] == 0
                        and event['outputs']['scl_pad_i'] == 1]
                    expected_bits = tuple((peer_byte >> bit) & 1
                                          for bit in range(7, -1, -1))
                    edge_bits = tuple(event['outputs']['sda_pad_i']
                                      for event in read_clock_edges)
                    self.assertTrue(any(edge_bits[index:index + 8] == expected_bits
                        for index in range(max(0, len(edge_bits) - 7))),
                        f'{peer_byte:#04x} absent from real SCL-rising SDA samples: '
                        f'{edge_bits}')
                    self.assertTrue(all(event['outputs']['scl_pad_o'] == 0
                                        and event['outputs']['sda_pad_o'] == 0
                                        for event in wire_samples),
                        'pinned open-drain output data must remain zero')

                    bound_irq = [event for event in events
                        if event.get('kind') == 'dataflow_delivery'
                        and tuple(event.get('source', ())) == ('i2c', 'interrupt_o')
                        and tuple(event.get('target', ())) == ('cpu', 'irq_external')]
                    self.assertTrue(any(event['value'] == 1 for event in bound_irq),
                        'native I2C output must bind to CVA6 irq_external')
                    self.assertTrue(any(event['value'] == 0 for event in bound_irq),
                        'native I2C output must deassert CVA6 irq_external after IACK')
                    # The address command completes first; ISR observes STATUS,
                    # IACK drops IRQ, then only afterward may main launch READ.
                    self.assertLess(writes[3]['event_id'], observed_edges[0][2])
                    self.assertLess(observed_edges[0][2], reads[0]['event_id'])
                    self.assertLess(reads[0]['event_id'], writes[4]['event_id'])
                    self.assertLess(writes[4]['event_id'], observed_edges[1][2])
                    self.assertLess(observed_edges[1][2], writes[5]['event_id'])
                    # The read command's native completion drives the second
                    # real M_EXT entry; ISR reads RX/STATUS before its IACK.
                    self.assertLess(writes[5]['event_id'], observed_edges[2][2])
                    self.assertLess(observed_edges[2][2], reads[1]['event_id'])
                    self.assertLess(reads[1]['event_id'], reads[2]['event_id'])
                    self.assertLess(reads[2]['event_id'], writes[6]['event_id'])
                    self.assertLess(writes[6]['event_id'], observed_edges[3][2])

                    cpu_steps = [event for event in events
                        if event.get('component') == 'cpu' and event.get('inputs')]
                    self.assertTrue(any(event['inputs'].get('irq_external') == 1
                                        for event in cpu_steps),
                        'CVA6 must sample the native bound IRQ input')
                    self.assertTrue(all(event['inputs'].get('irq_timer', 0) == 0
                                        for event in cpu_steps))
                    self.assertEqual((1, 1),
                        (_read_result(cpu, 0) & 1, _read_result(cpu, 20) & 1),
                        'both ISR status snapshots must report command completion')
                    self.assertEqual(0, _read_result(cpu, 0) & 0x80,
                        'I2C slave must ACK the address phase')
                    self.assertEqual((peer_byte, CAUSE_MEXT, CAUSE_MEXT, 0x51, 0x52, 0x66),
                        (_read_result(cpu, 16), _read_result(cpu, 8, 8),
                         _read_result(cpu, 24, 8), _read_result(cpu, 4),
                         _read_result(cpu, 32), _read_result(cpu, 36)))
                    self.assertEqual(0x80, _read_result(cpu, 20) & 0x80,
                        'second I2C status must reflect master NACK')

                    ram_writes = [event for event in events
                        if event.get('kind') == 'memory_write'
                        and event.get('component') == 'cpu']
                    first_isr_marker = [event for event in ram_writes
                        if event.get('address') == RESULT and event.get('byte_enable') == 0xf0
                        and (event.get('value', 0) >> 32) & 0xffffffff == 0x51]
                    second_isr_marker = [event for event in ram_writes
                        if event.get('address') == RESULT + 32
                        and event.get('byte_enable') == 0x0f
                        and event.get('value', 0) & 0xffffffff == 0x52]
                    resumed_marker = [event for event in ram_writes
                        if event.get('address') == RESULT + 32
                        and event.get('byte_enable') == 0xf0
                        and (event.get('value', 0) >> 32) & 0xffffffff == 0x66]
                    self.assertEqual((1, 1, 1), (len(first_isr_marker),
                        len(second_isr_marker), len(resumed_marker)), ram_writes)
                    markers = [first_isr_marker[0], second_isr_marker[0],
                               resumed_marker[0]]
                    self.assertLess(markers[0]['event_id'], markers[1]['event_id'])
                    self.assertLess(markers[1]['event_id'], markers[2]['event_id'])
                    transaction_key = lambda event: tuple(event['source_transaction'][key]
                        for key in ('source_component', 'source_epoch', 'channel_id',
                                    'source_sequence'))
                    delivered = [transaction_key(event) for event in deliveries]
                    accepted = [transaction_key(event) for event in events
                        if event.get('kind') == 'mmio_acceptance']
                    self.assertEqual(accepted, delivered)
                    self.assertEqual(len(delivered), len(set(delivered)))
                    self.assertTrue(all(key[0] == 'cpu' and key[1] == 0
                                        for key in delivered))
                    self.assertEqual((0, 0), (cpu.reset_epoch, i2c.reset_epoch))
                    self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                         for event in events))

                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    fresh = instances[-1]
                    self.assertIsNot(original.sessions['cpu'], fresh.sessions['cpu'])
                    self.assertIsNot(original.sessions['i2c'], fresh.sessions['i2c'])
                    self.assertEqual(peer_byte, _read_result(fresh.sessions['cpu'], 16))
                    self.assertEqual(CAUSE_MEXT,
                                     _read_result(fresh.sessions['cpu'], 24, 8))
                    self.assertEqual(0x66, _read_result(fresh.sessions['cpu'], 36))
                    self.assertEqual((0, 0), (fresh.sessions['cpu'].reset_epoch,
                                               fresh.sessions['i2c'].reset_epoch))


if __name__ == '__main__':
    unittest.main()
