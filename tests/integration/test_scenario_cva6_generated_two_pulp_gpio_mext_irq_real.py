"""CPU image mutation through three independent generated RTL sessions and MEI."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.integration.test_scenario_cva6_generated_opentitan_gpio_mext_irq_real import (
    ROOT, BOOT, RESULT, MTVEC, _artifact, _lui, _addi, _lw, _sw, _sd,
    _bne, _jal, _csr)

GPIO_B = 0x40000000
GPIO_A = 0x40001000
IRQ_CPU_TICKS = 4


def _program():
    main = [
        _lui(1, MTVEC >> 12), _addi(1, 1, MTVEC & 0xfff),
        _csr(1, 0, 0x305, 1),
        _lui(1, 1), _addi(1, 1, -0x800), _csr(1, 0, 0x304, 1),
        _addi(1, 0, 8), _csr(1, 0, 0x300, 1),
        _lui(1, GPIO_B >> 12), _lui(9, GPIO_A >> 12),
        _addi(2, 0, 0xff), _sw(2, 1, 0x04),  # B GPIOEN: sync pins 0..7
        _addi(2, 0, 1), _sw(2, 1, 0x18),     # B INTEN pin 0
        _sw(2, 1, 0x1c),                      # B INTTYPE_LOW rising pin 0
        _addi(2, 0, 0xff), _sw(2, 9, 0),     # A PADDIR output byte
        _lui(8, RESULT >> 12),
    ]
    immediate_bit_offset = (16 + len(main) * 4) * 8 + 20
    main += [
        _addi(2, 0, 1),                       # sole mutable CPU immediate
        _sw(2, 9, 0x0c),                      # CPU AXI4 -> real A APB3 PADOUT
        _lw(2, 8, 20), _bne(2, 0, 8), _jal(0, -8),
        _addi(3, 0, 0x66), _sw(3, 8, 24), 0x0000006f,
    ]
    isr = [
        _lui(1, GPIO_B >> 12), _lui(20, RESULT >> 12),
        _lw(2, 1, 0x24),                      # INTSTATUS read clears real status
        _lw(3, 1, 0x08),                      # PADIN is r_gpio_in, not sync1
        _csr(2, 4, 0x342, 0),
        _sw(2, 20, 0), _sw(3, 20, 4), _sd(4, 20, 8),
        _lw(6, 1, 0x24), _sw(6, 20, 16),     # actual read-to-clear readback
        _addi(7, 0, 0x55), _sw(7, 20, 20), 0x30200073,
    ]
    pack = lambda words: b''.join(word.to_bytes(4, 'little') for word in words)
    program = BOOT.read_bytes()[:16] + pack(main)
    assert 0x10000 + len(program) <= MTVEC
    return program, pack(isr), immediate_bit_offset


def _make_factory(cache_dir):
    cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json', 'cpu')
    a_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
    b_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_b')
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1), InputField('cpu', 'irq_timer', 1),
         InputField('gpio_a', 'gpio_in', 32), InputField('gpio_b', 'gpio_in', 32)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'bound', 'gpio_b.irq'),
         InputOwner('cpu', 'irq_timer', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
         InputOwner('gpio_b', 'gpio_in', 0, 8, 'bound', 'gpio_a.gpio_out'),
         InputOwner('gpio_b', 'gpio_in', 8, 24, 'fixed', 'constant_zero')))
    pin = Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 8)
    irq = Binding('gpio_b', 'irq', 'cpu', 'irq_external', 1)
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        a = GeneratedPulpGpioSession(a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        b = GeneratedPulpGpioSession(b_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio_a', GPIO_A, 0x1000, a),
                                 DeviceWindow('gpio_b', GPIO_B, 0x1000, b)))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio_a': a, 'gpio_b': b},
            ownership=ownership, bindings=(pin, irq), irq_pulses={irq: IRQ_CPU_TICKS})
        instances.append(runner)
        return runner

    return factory, instances, ownership


def _read_result(cpu, offset, width=4):
    return cpu.memory.read(RESULT + offset, width,
        transaction_id=f'cva6-two-pulp-result-{offset}-{width}').value


def _read_word(event):
    return event['read_value'] >> (32 if event['address'] & 4 else 0) & 0xffffffff


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCva6TwoPulpGpioMextIrqRealTests(unittest.TestCase):
    def _assert_chain(self, trace, runner, expected):
        self.assertEqual('complete', trace.status, trace.events[-8:])
        events = trace.events
        deliveries = [e for e in events if e.get('kind') == 'mmio_delivery']
        writes = [e for e in deliveries if e['write']]
        reads = [e for e in deliveries if not e['write']]
        output = [e for e in writes if e['device_id'] == 'gpio_a'
                  and e['offset'] == 0x0c and e['write_value'] == expected]
        self.assertEqual(1, len(output), 'CPU did not commit the real A PADOUT store')
        output = output[0]
        self.assertEqual(5, len(writes), writes)
        self.assertTrue(all(e['byte_enable'] == 15 and e['beat_bytes'] == 8
                            for e in writes), 'APB3 only admits full 32-bit writes')
        for component, offset, value in (('gpio_b', 4, 0xff),
                ('gpio_b', 0x18, 1), ('gpio_b', 0x1c, 1), ('gpio_a', 0, 0xff)):
            setup = [e for e in writes if (e['device_id'], e['offset'], e['write_value'])
                     == (component, offset, value)]
            self.assertEqual(1, len(setup), writes)
            self.assertLess(setup[0]['event_id'], output['event_id'])
        samples = [e for e in events if e.get('kind') == 'local_tick_sample']
        a_output = next(e for e in samples if e['component'] == 'gpio_a'
                        and e['outputs'].get('gpio_out') == expected)
        self.assertLess(output['event_id'], a_output['event_id'])
        bound = next(e for e in events if e.get('kind') == 'dataflow_delivery'
                     and tuple(e.get('source', ())) == ('gpio_a', 'gpio_out')
                     and tuple(e.get('target', ())) == ('gpio_b', 'gpio_in')
                     and e.get('value') == expected)
        producer = next(e for e in samples if e['event_id'] == bound['producer_event_id'])
        self.assertEqual(expected, producer['outputs']['gpio_out'])
        b_sync = next(e for e in samples if e['component'] == 'gpio_b'
                      and e['outputs'].get('gpio_in_sync') == expected)
        self.assertLess(bound['event_id'], b_sync['event_id'])
        self.assertTrue(any(e.get('component') == 'gpio_b'
                            and e.get('inputs', {}).get('gpio_in') == expected
                            for e in events))
        padin = [e for e in reads if e['device_id'] == 'gpio_b' and e['offset'] == 8]
        self.assertEqual([expected], [_read_word(e) for e in padin])
        status = [e for e in reads if e['device_id'] == 'gpio_b' and e['offset'] == 0x24]
        self.assertEqual([1, 0], [_read_word(e) for e in status],
                         'INTSTATUS must return accumulated status then read-cleared zero')
        self.assertLess(status[0]['event_id'], status[1]['event_id'])

        irq_events = [e for e in events if tuple(e.get('source', ())) == ('gpio_b', 'irq')
                      and tuple(e.get('target', ())) == ('cpu', 'irq_external')]
        starts = [e for e in irq_events if e.get('kind') == 'source_start']
        ends = [e for e in irq_events if e.get('kind') == 'source_end']
        pulses = [e for e in irq_events if e.get('kind') == 'pulse_start']
        expired = [e for e in irq_events if e.get('kind') == 'pulse_expired']
        self.assertEqual((1, 1, 1, 1), tuple(map(len, (starts, ends, pulses, expired))))
        self.assertEqual(1, ends[0]['source_tick'] - starts[0]['source_tick'],
                         'native GPIO interrupt lasts one GPIO tick')
        native_high = next(e for e in samples if e['component'] == 'gpio_b'
                           and e['local_tick'] == starts[0]['source_tick']
                           and e['outputs'].get('interrupt') == 1)
        self.assertLess(native_high['event_id'], starts[0]['event_id'])
        self.assertLess(bound['event_id'], native_high['event_id'])
        self.assertLess(starts[0]['event_id'], status[0]['event_id'])
        pulse = pulses[0]
        self.assertEqual(starts[0]['source_event_id'], pulse['source_event_id'])
        self.assertEqual(starts[0]['cpu_tick'] + 1, pulse['start_cpu_tick'])
        self.assertEqual(IRQ_CPU_TICKS,
                         pulse['end_cpu_tick_exclusive'] - pulse['start_cpu_tick'])
        cpu_steps = [e for e in events if e.get('component') == 'cpu' and 'inputs' in e]
        self.assertTrue(any(e['outputs'].get('ar_accepted') == 1
                            and e['outputs'].get('araddr') == MTVEC for e in cpu_steps),
                        'CVA6 must fetch the actual ISR instruction line')
        high_ticks = [e['local_tick'] for e in cpu_steps
                      if e['inputs'].get('irq_external') == 1]
        self.assertEqual(list(range(pulse['start_cpu_tick'], pulse['end_cpu_tick_exclusive'])),
                         high_ticks, 'runner presents exactly four CPU-local ticks on irq_external')
        self.assertTrue(all(e['inputs'].get('irq_timer', 0) == 0 for e in cpu_steps))
        self.assertTrue(any(e['local_tick'] >= pulse['end_cpu_tick_exclusive']
                            and e['inputs'].get('irq_external') == 0 for e in cpu_steps))

        cpu = runner.sessions['cpu']
        self.assertEqual((1, expected, 0x800000000000000b, 0, 0x55, 0x66),
            tuple(_read_result(cpu, offset, width) for offset, width in
                  ((0, 4), (4, 4), (8, 8), (16, 4), (20, 4), (24, 4))))
        ram_writes = [e for e in events if e.get('kind') == 'memory_write'
                      and e.get('component') == 'cpu']
        marker = [e for e in ram_writes if e.get('address') == RESULT + 16
                  and e.get('byte_enable') == 0xf0
                  and (e.get('value', 0) >> 32) & 0xffffffff == 0x55]
        resumed = [e for e in ram_writes if e.get('address') == RESULT + 24
                   and e.get('byte_enable') == 0x0f
                   and e.get('value', 0) & 0xffffffff == 0x66]
        self.assertEqual((1, 1), (len(marker), len(resumed)))
        self.assertLess(marker[0]['event_id'], resumed[0]['event_id'])
        self.assertFalse(any(e.get('kind') == 'source_injection' for e in events),
                         'only the initial CPU image is mutable')
        transactions = [tuple(e['source_transaction'][k] for k in
            ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
            for e in deliveries]
        acceptances = [e for e in events if e.get('kind') == 'mmio_acceptance']
        accepted = [tuple(e['source_transaction'][k] for k in
            ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
            for e in acceptances]
        self.assertEqual(len(transactions), len(set(transactions)))
        self.assertEqual(accepted, transactions)
        self.assertTrue(all(t[0] == 'cpu' and t[1] == 0 for t in transactions))
        self.assertTrue(all(s.reset_epoch == 0 for s in runner.sessions.values()))
        self.assertFalse(any(e.get('kind') == 'reset_barrier' for e in events))

    def test_cpu_image_mutation_closes_gpio_chain_mext_isr_and_fresh_replay(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-two-pulp-mext-') as directory:
            work = Path(directory)
            factory, instances, ownership = _make_factory(Path(os.environ.get(
                'MYFUZZ_CVA6_PULP_GPIO_CACHE', work / 'cache')))
            program, isr, offset = _program()
            seed = ScenarioGenome(testcase_id='cva6-generated-two-pulp-gpio-mext',
                direction='CPU_TO_IP_TO_CPU', path_id='cpu-image-a-padout-b-padin-irq-mext-ram',
                schedule_order=('cpu', 'gpio_a', 'gpio_b'), max_steps=3000,
                actions=(), initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, program.hex()),
                    MemoryImage('cpu.mext_isr', 'cpu', MTVEC, isr.hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, bytes(28).hex())))
            graph = DependencyGraph(sources=(FuzzableSource('cpu.program.output', 'cpu',
                'cpu.program', offset, 8, ('CPU_TO_IP_TO_CPU',), kind='memory_image'),),
                rules=(DependencyRule('cpu.mmio_payload', ('cpu.program.output',), 'EVENT_ORDER'),
                       DependencyRule('gpio_a.padout_state', ('cpu.mmio_payload',),
                                      'PERSISTENT_STATE_RULE'),
                       DependencyRule('gpio_a.gpio_out', ('gpio_a.padout_state',), 'DATA_BINDING'),
                       DependencyRule('gpio_b.input', ('gpio_a.gpio_out',), 'DATA_BINDING'),
                       DependencyRule('gpio_b.irq', ('gpio_b.input',), 'EVENT_ORDER'),
                       DependencyRule('cpu.result_ram', ('gpio_b.irq',), 'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1}, direction=seed.direction)
            self.assertEqual('cpu.program.output', mutation.focus_source)
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=7)
            changed_program = changed.initial_images[0].data
            immediate = int.from_bytes(changed_program[offset // 8 - 2:offset // 8 + 2],
                                       'little') >> 20 & 0xfff
            self.assertEqual(0x81, immediate)
            changed_bits = [i for i in range(len(program) * 8)
                            if (program[i // 8] ^ changed_program[i // 8]) >> (i % 8) & 1]
            self.assertEqual([offset + 7], changed_bits)
            self.assertEqual(seed.initial_images[1:], changed.initial_images[1:])
            self.assertEqual((), changed.actions)
            self.assertEqual(0x30200073, int.from_bytes(isr[-4:], 'little'))
            budget = ResourceBudget(max_transactions=2048,
                max_local_cycles_per_component=8192, max_scheduler_steps=12000,
                max_wall_time_ms=300000, max_materialized_bytes_per_memory=0x40000,
                max_evidence_bytes=64 * 1024 * 1024)
            for genome, expected in ((seed, 1), (changed, 0x81)):
                with self.subTest(payload=expected):
                    bundle = work / f'evidence-{expected:02x}'
                    trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                    original = instances[-1]
                    self._assert_chain(trace, original, expected)
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    fresh = instances[-1]
                    self.assertIsNot(original, fresh)
                    for name in ('cpu', 'gpio_a', 'gpio_b'):
                        self.assertIsNot(original.sessions[name], fresh.sessions[name])
                        self.assertEqual(0, fresh.sessions[name].reset_epoch)
                    fresh_cpu = fresh.sessions['cpu']
                    self.assertEqual((1, expected, 0x800000000000000b, 0, 0x55, 0x66),
                        tuple(_read_result(fresh_cpu, off, width) for off, width in
                              ((0, 4), (4, 4), (8, 8), (16, 4), (20, 4), (24, 4))))


if __name__ == '__main__':
    unittest.main()
