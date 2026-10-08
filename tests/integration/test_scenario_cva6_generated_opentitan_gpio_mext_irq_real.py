"""Real OpenTitan GPIO M_EXT delivery into generated CVA6 RTL and replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
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
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'
GPIO_BASE = 0x40000000
RESULT = 0x20000
MTVEC = 0x10100
SOURCE_DELAY = 32


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=16,
        reset_release_ticks=20, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _sd(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            3 << 12 | (offset & 31) << 7 | 0x23)


def _bne(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | 1 << 12 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _jal(rd: int, offset: int) -> int:
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 |
            ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 |
            rd << 7 | 0x6f)


def _csr(funct3: int, rd: int, csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73


def _program() -> bytes:
    # Preserve the pinned boot stub. CVA6 starts at 0x10000 and begins this
    # program immediately after its four-instruction prefix.
    main = (
        _lui(1, MTVEC >> 12),
        _addi(1, 1, MTVEC & 0xfff),
        _csr(1, 0, 0x305, 1),              # mtvec = 0x10100, direct mode
        _lui(1, 1),
        _addi(1, 1, -0x800),
        _csr(1, 0, 0x304, 1),              # mie.MEIE = 1 << 11
        _addi(1, 0, 1 << 3),
        _csr(1, 0, 0x300, 1),              # mstatus.MIE = 1
        _lui(1, GPIO_BASE >> 12),
        _addi(2, 0, 1),
        _sw(2, 1, 0x04),                   # INTR_ENABLE pin 0
        _sw(2, 1, 0x2c),                   # INTR_CTRL_EN_RISING pin 0
        _lui(8, RESULT >> 12),
        # Wait for the ISR marker. The post-marker store proves MRET returned
        # to this loop and CVA6 continued executing the original program.
        _lw(2, 8, 20),
        _bne(2, 0, 8),
        _jal(0, -8),                       # jal x0, wait_loop
        _addi(3, 0, 0x66),
        _sw(3, 8, 24),                    # observed only after MRET
        0x0000006f,                        # stable terminal loop
    )
    isr = (
        _lui(1, GPIO_BASE >> 12),
        _lui(20, RESULT >> 12),        # keep main's x8 poll base intact
        _lw(2, 1, 0x00),                  # actual INTR_STATE
        _lw(3, 1, 0x10),                  # actual DATA_IN
        _csr(2, 4, 0x342, 0),              # actual 64-bit mcause
        _sw(2, 20, 0),
        _sw(3, 20, 4),
        _sd(4, 20, 8),
        _addi(5, 0, 1),
        _sw(5, 1, 0x00),                  # W1C INTR_STATE bit 0
        _lw(6, 1, 0x00),
        _sw(6, 20, 16),                   # record real clear readback
        _addi(7, 0, 0x55),
        _sw(7, 20, 20),                   # ISR completion marker
        0x30200073,                        # mret
    )
    boot_prefix = BOOT.read_bytes()[:16]
    return (boot_prefix + b''.join(word.to_bytes(4, 'little') for word in main),
            b''.join(word.to_bytes(4, 'little') for word in isr))


def _make_factory(cpu_artifact, gpio_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1),
         InputField('cpu', 'irq_timer', 1),
         InputField('gpio', 'gpio_in', 32),
         InputField('gpio', 'strap_en', 1)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'bound', 'gpio.irq'),
         InputOwner('cpu', 'irq_timer', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('gpio', 'gpio_in', 0, 8, 'source', 'external_gpio_pins'),
         InputOwner('gpio', 'gpio_in', 8, 24, 'fixed', 'constant_zero'),
         InputOwner('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero')))
    binding = Binding('gpio', 'irq', 'cpu', 'irq_external', 1)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        gpio = GeneratedOpentitanGpioSession(gpio_artifact, base_dir=ROOT,
                                              cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances, ownership


def _read_result(cpu, offset: int, width: int = 4) -> int:
    return cpu.memory.read(RESULT + offset, width,
        transaction_id=f'cva6-gpio-mext-result-{offset:x}-{width}').value


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCva6OpentitanGpioMextIrqRealTests(unittest.TestCase):
    def test_gpio_edge_reaches_generated_cva6_mext_isr_and_replays(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(
                prefix='myfuzz-cva6-generated-ot-gpio-mext-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json', 'cpu')
            gpio_artifact = _artifact(
                'configs/peripherals/opentitan_gpio_local/component_profile.json',
                'gpio')
            factory, instances, ownership = _make_factory(
                cpu_artifact, gpio_artifact, work / 'cache')
            program, isr = _program()
            seed = ScenarioGenome(
                testcase_id='cva6-generated-opentitan-gpio-mext-01',
                direction='IP_TO_CPU', path_id='gpio-pin-data-irq-cva6-mext-ram',
                schedule_order=('cpu', 'gpio'), max_steps=3000,
                actions=(Action('external-pin-vector', 'gpio', 'gpio_in', 0x01,
                    'IP_TO_CPU', Trigger('AFTER_OUTPUT', 'cpu', 'awaddr',
                        (1 << 64) - 1, GPIO_BASE + 0x2c),
                    delay_component='cpu', delay_ticks=SOURCE_DELAY,
                    bit_offset=0, width=8),),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, program.hex()),
                    MemoryImage('cpu.gpio_mext_isr', 'cpu', MTVEC, isr.hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, bytes(28).hex()),
                ))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_gpio_pins', 'gpio', 'gpio_in',
                    0, 8, ('IP_TO_CPU',)),),
                rules=(DependencyRule('gpio.data_in', ('external_gpio_pins',),
                                      'DATA_BINDING'),
                       DependencyRule('gpio.irq', ('gpio.data_in',), 'EVENT_ORDER'),
                       DependencyRule('cpu.result_ram', ('gpio.irq',),
                                      'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1},
                                       direction='IP_TO_CPU')
            self.assertEqual('external_gpio_pins', mutation.focus_source)
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=7)
            self.assertEqual(0x81, changed.actions[0].value)

            budget = ResourceBudget(max_transactions=2048,
                max_local_cycles_per_component=8192, max_scheduler_steps=12000,
                max_wall_time_ms=300000,
                max_materialized_bytes_per_memory=0x40000,
                max_evidence_bytes=64 * 1024 * 1024)
            for genome in (seed, changed):
                source_value = genome.actions[0].value
                bundle = work / f'evidence-gpio-{source_value:02x}'
                trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-8:])
                original = instances[-1]
                cpu, gpio = original.sessions['cpu'], original.sessions['gpio']
                events = trace.events

                injections = [event for event in events
                    if event.get('kind') == 'source_injection']
                self.assertEqual(1, len(injections))
                self.assertEqual(('gpio', 'gpio_in', source_value,
                                  'external_gpio_pins', 0, 8),
                    (injections[0]['component'], injections[0]['port'],
                     injections[0]['value'], injections[0]['source_ref'],
                     injections[0]['bit_offset'], injections[0]['width']))
                owners = original.ownership.document()['owners']
                self.assertIn({'component_id': 'cpu', 'port': 'irq_external',
                    'bit_offset': 0, 'width': 1, 'kind': 'bound',
                    'producer_ref': 'gpio.irq'}, owners)
                self.assertIn({'component_id': 'cpu', 'port': 'irq_timer',
                    'bit_offset': 0, 'width': 1, 'kind': 'fixed',
                    'producer_ref': 'constant_zero'}, owners)
                self.assertIn({'component_id': 'gpio', 'port': 'gpio_in',
                    'bit_offset': 0, 'width': 8, 'kind': 'source',
                    'producer_ref': 'external_gpio_pins'}, owners)
                self.assertIn({'component_id': 'gpio', 'port': 'gpio_in',
                    'bit_offset': 8, 'width': 24, 'kind': 'fixed',
                    'producer_ref': 'constant_zero'}, owners)
                self.assertIn({'component_id': 'gpio', 'port': 'strap_en',
                    'bit_offset': 0, 'width': 1, 'kind': 'fixed',
                    'producer_ref': 'constant_zero'}, owners)

                deliveries = [event for event in events
                    if event.get('kind') == 'mmio_delivery'
                    and event.get('device_id') == 'gpio']
                writes = [event for event in deliveries if event.get('write')]
                reads = [event for event in deliveries if not event.get('write')]
                rising_enable = [event for event in writes
                    if event.get('offset') == 0x2c
                    and event.get('write_value') == 1]
                self.assertEqual(1, len(rising_enable), writes)
                interrupt_enable = [event for event in writes
                    if event.get('offset') == 0x04
                    and event.get('write_value') == 1]
                self.assertEqual(1, len(interrupt_enable), writes)
                self.assertLess(interrupt_enable[0]['event_id'], injections[0]['event_id'],
                    'committed INTR_ENABLE setup must precede external source injection')
                self.assertLess(rising_enable[0]['event_id'], injections[0]['event_id'],
                    'AW trigger is only an address handshake; the committed GPIO write '
                    'must precede external source injection')
                self.assertTrue(any(event.get('offset') == 0x00
                                    and event.get('write_value') == 1
                                    for event in writes), 'ISR did not perform W1C')
                self.assertTrue(any(event.get('offset') == 0x00
                    and event.get('read_value') == 1 for event in reads),
                    'ISR did not read the asserted real INTR_STATE')
                self.assertTrue(any(event.get('offset') == 0x10
                    and event.get('read_value') == source_value for event in reads),
                    'ISR DATA_IN did not reflect the selected external pin vector')

                irq_events = [event for event in events
                    if event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ())) == ('gpio', 'irq')
                    and tuple(event.get('target', ())) == ('cpu', 'irq_external')]
                irq_high = next((event for event in irq_events
                                 if event.get('value') == 1), None)
                self.assertIsNotNone(irq_high, 'real GPIO IRQ never reached CVA6 M_EXT')
                assert irq_high is not None
                producer = next(event for event in events
                    if event.get('event_id') == irq_high['producer_event_id'])
                self.assertEqual('gpio', producer.get('component'))
                self.assertTrue((producer.get('outputs', {}).get('interrupt', 0) & 1)
                                or (producer.get('outputs', {}).get('irq', 0) & 1),
                    'IRQ delivery was not produced by the real GPIO interrupt output')
                self.assertLess(injections[0]['event_id'], irq_high['event_id'])
                cpu_steps = [event for event in events
                    if event.get('component') == 'cpu' and event.get('outputs') is not None]
                self.assertTrue(any(event.get('inputs', {}).get('irq_external') == 1
                                    for event in cpu_steps),
                    'CVA6 did not sample its bound machine-external IRQ input')
                self.assertTrue(all(event.get('inputs', {}).get('irq_timer', 0) == 0
                                    for event in cpu_steps),
                    'the independent M_TIMER input must remain fixed inactive')

                clear_write = next(event for event in writes
                    if event.get('offset') == 0x00 and event.get('write_value') == 1)
                self.assertTrue(any(event.get('value') == 0
                    and event.get('event_id', 0) > clear_write['event_id']
                    for event in irq_events), 'GPIO IRQ did not fall after W1C')
                self.assertEqual(1, _read_result(cpu, 0))
                self.assertEqual(source_value, _read_result(cpu, 4))
                self.assertEqual(0x800000000000000b, _read_result(cpu, 8, 8),
                    'CVA6 must take native machine-external cause 11')
                self.assertEqual(0, _read_result(cpu, 16),
                    'GPIO W1C must clear the actual INTR_STATE')
                self.assertEqual(0x55, _read_result(cpu, 20),
                    'ISR must write its completion marker')
                self.assertEqual(0x66, _read_result(cpu, 24),
                    'post-MRET marker proves execution returned to the wait loop')
                ram_writes = [event for event in events
                    if event.get('kind') == 'memory_write'
                    and event.get('component') == 'cpu']
                isr_marker = next((event for event in ram_writes
                    if event.get('address') == RESULT + 16
                    and event.get('byte_enable') == 0xf0
                    and (event.get('value', 0) >> 32) & 0xffffffff == 0x55), None)
                resumed_marker = next((event for event in ram_writes
                    if event.get('address') == RESULT + 24
                    and event.get('byte_enable') == 0x0f
                    and event.get('value', 0) & 0xffffffff == 0x66), None)
                self.assertIsNotNone(isr_marker,
                    ('ISR completion store is absent from the expected upper 32-bit lane',
                     ram_writes))
                self.assertIsNotNone(resumed_marker,
                    ('post-MRET main store is absent', ram_writes))
                assert isr_marker is not None and resumed_marker is not None
                self.assertLess(isr_marker['event_id'], resumed_marker['event_id'],
                    'main must observe the ISR flag after MRET before storing 0x66')
                isr_words = [int.from_bytes(isr[index:index + 4], 'little')
                    for index in range(0, len(isr), 4)]
                self.assertEqual(0x30200073, isr_words[-1])

                transactions = [tuple(event['source_transaction'][field]
                    for field in ('source_component', 'source_epoch', 'channel_id',
                                  'source_sequence')) for event in deliveries]
                self.assertEqual(len(transactions), len(set(transactions)),
                    'routed CPU MMIO transactions must execute exactly once')
                self.assertTrue(all(key[0] == 'cpu' and key[1] == 0
                                    for key in transactions), transactions)
                self.assertEqual(0, cpu.reset_epoch)
                self.assertEqual(0, gpio.reset_epoch)
                self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                     for event in events))

                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                fresh = instances[-1]
                fresh_cpu, fresh_gpio = fresh.sessions['cpu'], fresh.sessions['gpio']
                self.assertIsNot(cpu, fresh_cpu)
                self.assertIsNot(gpio, fresh_gpio)
                self.assertEqual(source_value, _read_result(fresh_cpu, 4))
                self.assertEqual(0x800000000000000b,
                                 _read_result(fresh_cpu, 8, 8))
                self.assertEqual(0x66, _read_result(fresh_cpu, 24))
                self.assertEqual(0, fresh_cpu.reset_epoch)
                self.assertEqual(0, fresh_gpio.reset_epoch)


if __name__ == '__main__':
    unittest.main()
