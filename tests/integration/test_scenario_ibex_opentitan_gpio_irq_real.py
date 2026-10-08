"""A real OpenTitan GPIO edge interrupts real Ibex and is replayable."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
GPIO_BASE = 0x40000000
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


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return (((offset >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 0x1f) << 7 | 0x23)


def _csrrs(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _genome() -> ScenarioGenome:
    main = (
        _lui(1, GPIO_BASE >> 12),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _addi(2, 0, 1),
        _sw(2, 1, 0x04),       # INTR_ENABLE[0]
        _sw(2, 1, 0x2c),       # INTR_CTRL_EN_RISING[0]
        _sw(2, 1, 0x14),       # DOUT[0], trigger for external edge admission
        _sw(2, 1, 0x20),       # DIRECT_OE[0]
        0x0000006f,             # wait in a real CPU loop for the bound IRQ
    )
    isr = (
        _lw(4, 1, 0x00),       # real INTR_STATE
        _lw(3, 1, 0x10),       # real DATA_IN pin sample
        _lui(5, RESULT >> 12),
        _sw(4, 5, 0), _sw(3, 5, 4),
        _addi(6, 0, 1), _sw(6, 1, 0x00),  # real W1C
        0x30200073,             # MRET
    )
    return ScenarioGenome(
        testcase_id='ibex-opentitan-gpio-rising-edge-irq',
        direction='IP_TO_CPU',
        path_id='gpio-pin-real-rtl-irq-ibex-status-data-ram',
        schedule_order=('gpio', 'cpu'), max_steps=1800,
        actions=(Action('gpio-pin0-rising', 'gpio', 'gpio_in', 1,
                        'IP_TO_CPU',
                        Trigger('AFTER_OUTPUT', 'gpio', 'gpio_out', 1, 1),
                        width=1),),
        initial_images=(
            MemoryImage('cpu.main', 'cpu', 0x10080, _image(main)),
            MemoryImage('cpu.isr', 'cpu', 0x1012c, _image(isr)),
            MemoryImage('cpu.result', 'cpu', RESULT, '0000000000000000'),
        ))


def _make_factory(cpu_artifact, gpio_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq', 1), InputField('gpio', 'gpio_in', 32),
         InputField('gpio', 'strap_en', 1)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio.irq'),
         InputOwner('gpio', 'gpio_in', 0, 32, 'source', 'external_gpio_pin'),
         InputOwner('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero')))
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x30000),),
            initialization_seed=71, max_initialized_bytes=0x30000)
        gpio = GeneratedOpentitanGpioSession(gpio_artifact, base_dir=ROOT,
            cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        binding = Binding('gpio', 'irq', 'cpu', 'irq', 1)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned OpenTitan and Ibex RTL')
class GeneratedIbexOpentitanGpioIrqTests(unittest.TestCase):
    def test_gpio_edge_irq_reaches_ibex_isr_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-opentitan-gpio-irq-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json',
                                     'cpu')
            gpio_artifact = _artifact(
                'configs/peripherals/opentitan_gpio_local/component_profile.json',
                'gpio')
            factory, instances = _make_factory(cpu_artifact, gpio_artifact,
                                               work / 'cache')
            genome = _genome()
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual('complete', trace.status, trace.events[-8:])

            events = trace.events
            injection = next(event for event in events
                if event.get('kind') == 'source_injection'
                and event.get('action_id') == 'gpio-pin0-rising')
            self.assertEqual(('gpio', 'gpio_in'),
                             (injection['component'], injection['port']))
            self.assertEqual(1, injection['value'] & 1)
            self.assertEqual('source', next(owner['kind'] for owner in
                instances[0].ownership.document()['owners']
                if owner['component_id'] == 'gpio' and owner['port'] == 'gpio_in'))
            self.assertEqual('bound', next(owner['kind'] for owner in
                instances[0].ownership.document()['owners']
                if owner['component_id'] == 'cpu' and owner['port'] == 'irq'))

            writes = [event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'gpio' and event.get('write')]
            self.assertIn((0x04, 1), [(event['offset'], event['write_value'])
                                     for event in writes])
            self.assertIn((0x2c, 1), [(event['offset'], event['write_value'])
                                     for event in writes])
            self.assertIn((0x00, 1), [(event['offset'], event['write_value'])
                                     for event in writes],
                          'Ibex ISR did not W1C the GPIO interrupt state')

            reads = [event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'gpio' and not event.get('write')]
            intr_state = next((event for event in reads
                               if event['offset'] == 0x00 and event['read_value'] & 1), None)
            data_in = next((event for event in reads
                            if event['offset'] == 0x10 and event['read_value'] & 1), None)
            self.assertIsNotNone(intr_state, 'ISR did not read the real asserted INTR_STATE')
            self.assertIsNotNone(data_in, 'ISR did not read the real DATA_IN pin value')

            irq_high = next((event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio', 'irq')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 1), None)
            self.assertIsNotNone(irq_high, 'GPIO RTL IRQ was not delivered to Ibex')
            producer = next(event for event in events
                if event.get('event_id') == irq_high['producer_event_id'])
            self.assertTrue(producer.get('outputs', {}).get('interrupt', 0) & 1,
                            'IRQ delivery did not originate from real GPIO output')
            isr_reads = [event for event in events
                if event.get('kind') == 'mmio_acceptance'
                and event.get('device_id') == 'gpio'
                and event.get('offset') in (0x00, 0x10)
                and event.get('event_id', 0) > irq_high['event_id']]
            self.assertEqual({0x00, 0x10}, {event['offset'] for event in isr_reads},
                             'Ibex did not execute the GPIO-specific ISR')

            irq_low_after_w1c = any(event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio', 'irq')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 0
                and event.get('event_id', 0) > next(event['event_id'] for event in writes
                    if event['offset'] == 0x00 and event['write_value'] == 1)
                for event in events)
            self.assertTrue(irq_low_after_w1c, 'GPIO IRQ did not fall after real W1C')

            ram_writes = [event for event in events
                if event.get('kind') == 'memory_write'
                and event.get('component') == 'cpu'
                and event.get('address') in (RESULT, RESULT + 4)]
            self.assertEqual([(RESULT, intr_state['read_value']),
                              (RESULT + 4, data_in['read_value'])],
                             [(event['address'], event['value']) for event in ram_writes])
            memory = instances[0].sessions['cpu'].memory
            self.assertEqual(intr_state['read_value'], memory.read(RESULT, 4,
                transaction_id='gpio-isr-intr-state').value)
            self.assertEqual(data_in['read_value'], memory.read(RESULT + 4, 4,
                transaction_id='gpio-isr-data-in').value)
            self.assertFalse(any(event.get('kind') == 'reset_barrier' for event in events))

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['gpio'], instances[1].sessions['gpio'])


if __name__ == '__main__':
    unittest.main()
