"""External PULP GPIO B pins drive generated Ibex ISR and GPIO A RTL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario import checker
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.local_harness.test_renderer import ROOT
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import (
    _artifact, _lui, _addi, _sw, _lw, _csrrs, _image)


def _srli(rd, rs1, shamt):
    return shamt << 20 | rs1 << 15 | 5 << 12 | rd << 7 | 0x13


def reverse_genome(external_byte: int = 0x49) -> ScenarioGenome:
    if type(external_byte) is not int or not 1 <= external_byte <= 0xff or not external_byte & 1:
        raise ValueError('external byte must be odd to raise PULP GPIO pin 8')
    main = (
        _lui(1, 0x40000), _lui(3, 0x40001),
        _lui(2, 0x10), _addi(2, 2, -256), _sw(2, 1, 4),       # B.GPIOEN[15:8]
        _addi(2, 0, 0x100), _sw(2, 1, 0x18),                # B.INTEN pin 8
        _lui(2, 0x10), _sw(2, 1, 0x1c),                    # B.INTTYPE pin 8 rising
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _addi(2, 0, 0xff), _sw(2, 3, 0),                  # A.PADDIR[7:0]
        0x0000006f,
    )
    isr = (
        _lw(4, 1, 8), _srli(4, 4, 8), _lui(5, 0x20),
        _sw(4, 5, 0), _sw(4, 3, 0x0c),
        _lw(6, 1, 0x24), _sw(6, 5, 4), 0x30200073,
    )
    return ScenarioGenome(
        testcase_id=f'ibex-pulp-b-external-to-a-{external_byte:02x}',
        direction='IP_TO_CPU_TO_IP', path_id='b-external-irq-ibex-isr-a-padout',
        schedule_order=('cpu', 'gpio_b', 'gpio_a'), max_steps=270,
        actions=(Action('b-external-rise', 'gpio_b', 'gpio_in', external_byte,
                        'IP_TO_CPU_TO_IP',
                        Trigger('AFTER_OUTPUT', 'cpu', 'data_req_accepted', 1, 1, 4),
                        delay_component='cpu', delay_ticks=8,
                        bit_offset=8, width=8),),
        initial_images=(MemoryImage('boot', 'cpu', 0x10080, _image(main)),
                        MemoryImage('isr', 'cpu', 0x1012c, _image(isr)),
                        MemoryImage('results', 'cpu', 0x20000, '00' * 8)))


def reverse_batch_genome() -> ScenarioGenome:
    """Three external values enter one continuous generated RTL testcase."""
    base = reverse_genome()
    direction = 'IP_TO_CPU_TO_IP'
    source = ('gpio_b', 'gpio_in')
    def action(action_id, value, trigger, *, clock='gpio_b', delay=0):
        return Action(action_id, source[0], source[1], value, direction, trigger,
                      delay_component=clock, delay_ticks=delay,
                      bit_offset=8, width=8)
    return ScenarioGenome(
        testcase_id='ibex-pulp-batch-three-external-events',
        direction=direction, path_id='b-external-irq-ibex-isr-a-padout-three-rounds',
        schedule_order=base.schedule_order, max_steps=900,
        initial_images=base.initial_images,
        actions=(
            Action('first-rise', 'gpio_b', 'gpio_in', 0x49, direction,
                   Trigger('AFTER_OUTPUT', 'cpu', 'data_req_accepted', 1, 1, 4),
                   delay_component='cpu', delay_ticks=8,
                   bit_offset=8, width=8),
            action('first-fall', 0,
                   Trigger('AFTER_OUTPUT', 'cpu', 'data_rsp_consumed', 1, 1, 5)),
            action('second-rise', 0x81,
                   Trigger('AFTER_OUTPUT', 'cpu', 'data_rsp_consumed', 1, 1, 5),
                   clock='cpu', delay=64),
            action('second-fall', 0,
                   Trigger('AFTER_OUTPUT', 'cpu', 'data_rsp_consumed', 1, 1, 10)),
            action('third-rise', 0xff,
                   Trigger('AFTER_OUTPUT', 'cpu', 'data_rsp_consumed', 1, 1, 10),
                   clock='cpu', delay=64)))


def reverse_ownership():
    return compile_ownership(
        (InputField('cpu', 'irq', 1), InputField('gpio_a', 'gpio_in', 32),
         InputField('gpio_b', 'gpio_in', 32)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio_b.irq'),
         InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
         InputOwner('gpio_b', 'gpio_in', 0, 8, 'fixed', 'constant_zero'),
         InputOwner('gpio_b', 'gpio_in', 8, 8, 'source', 'external_b'),
         InputOwner('gpio_b', 'gpio_in', 16, 16, 'fixed', 'constant_zero')))


def make_reverse_factory(cache_dir: Path):
    cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json', 'cpu')
    a_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
    b_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_b')
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                                  initialization_seed=37, max_initialized_bytes=0x20000)
        a = GeneratedPulpGpioSession(a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        b = GeneratedPulpGpioSession(b_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio_a', 0x40001000, 0x1000, a),
                                 DeviceWindow('gpio_b', 0x40000000, 0x1000, b)))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT, cache_dir=cache_dir,
                                   memory=memory, router=router, defer_mmio=True)
        irq = Binding('gpio_b', 'irq', 'cpu', 'irq', 1)
        ownership = reverse_ownership()
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio_a': a, 'gpio_b': b},
                                ownership=ownership, bindings=(irq,),
                                irq_pulses={irq: 4})
        instances.append(runner)
        return runner

    return factory, instances


class ReverseOwnershipTests(unittest.TestCase):
    def test_only_external_b_byte_is_mutable(self):
        ownership = reverse_ownership()
        direction = 'IP_TO_CPU_TO_IP'
        self.assertEqual('external_b', ownership.mutation_source(
            'gpio_b', 'gpio_in', 8, 8, direction=direction))
        with self.assertRaisesRegex(ValueError, 'bound'):
            ownership.mutation_source('cpu', 'irq', 0, 1, direction=direction)
        with self.assertRaisesRegex(ValueError, 'fixed'):
            ownership.mutation_source('gpio_b', 'gpio_in', 0, 8, direction=direction)
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            ownership.mutation_source('cpu', 'rdata', 0, 32, direction=direction)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class ReverseGeneratedIbexPulpGpioTests(unittest.TestCase):
    def test_external_pin_reaches_real_ibex_isr_and_other_real_gpio(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pulp-reverse-') as directory:
            factory, instances = make_reverse_factory(Path(os.environ.get(
                'MYFUZZ_IBEX_GPIO_CACHE', Path(directory) / 'cache')))
            case = reverse_genome()
            trace = record_scenario(case, factory)
            self.assertEqual('complete', trace.status)
            report = checker.check_pulp_gpio_reverse_irq_chain(
                trace.events, external_byte=0x49)
            self.assertTrue(report['complete'], report)
            self.assertEqual(0x49, instances[0].sessions['cpu'].memory.read(
                0x20000, 4, transaction_id='reverse-result').value)
            replay = replay_scenario(case, factory, trace)
            self.assertTrue(replay.matches, replay)

    def test_two_mutated_external_bytes_propagate_and_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pulp-reverse-variants-') as directory:
            factory, instances = make_reverse_factory(Path(os.environ.get(
                'MYFUZZ_IBEX_GPIO_CACHE', Path(directory) / 'cache')))
            for value in (0x81, 0xff):
                with self.subTest(value=value):
                    case = reverse_genome(value)
                    trace = record_scenario(case, factory)
                    self.assertEqual('complete', trace.status)
                    report = checker.check_pulp_gpio_reverse_irq_chain(
                        trace.events, external_byte=value)
                    self.assertTrue(report['complete'], report)
                    self.assertEqual(value, instances[-1].sessions['cpu'].memory.read(
                        0x20000, 4, transaction_id=f'reverse-{value}').value)
                    replay = replay_scenario(case, factory, trace)
                    self.assertTrue(replay.matches, replay)
                    self.assertIsNot(instances[-2].sessions['cpu'], instances[-1].sessions['cpu'])
                    self.assertNotEqual(instances[-2].sessions['cpu']._execution,
                                        instances[-1].sessions['cpu']._execution)

    def test_three_external_phases_share_one_rtl_lifetime_and_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pulp-reverse-batch-') as directory:
            factory, instances = make_reverse_factory(Path(os.environ.get(
                'MYFUZZ_IBEX_GPIO_CACHE', Path(directory) / 'cache')))
            case = reverse_batch_genome()
            trace = record_scenario(case, factory)
            self.assertEqual('complete', trace.status)
            injections = [event['action_id'] for event in trace.events
                          if event.get('kind') == 'source_injection']
            self.assertEqual(['first-rise', 'first-fall', 'second-rise',
                              'second-fall', 'third-rise'], injections)
            ram_writes = [event for event in trace.events
                          if event.get('kind') == 'memory_write'
                          and event.get('component') == 'cpu'
                          and event.get('address') == 0x20000]
            self.assertEqual([0x49, 0x81, 0xff],
                             [event['value'] & 0xff for event in ram_writes])
            memory = instances[0].sessions['cpu'].memory
            self.assertEqual(0, memory.generation)
            self.assertEqual(0xff, memory.read(
                0x20000, 4, transaction_id='reverse-batch-final').value)
            padin_reads = [event['read_value'] & 0xffffffff
                           for event in trace.events
                           if event.get('kind') == 'mmio_delivery'
                           and event.get('device_id') == 'gpio_b'
                           and event.get('offset') == 0x08
                           and not event.get('write')]
            self.assertEqual([0x4900, 0x8100, 0xff00], padin_reads)
            gpio_a_writes = [event['write_value'] & 0xff
                             for event in trace.events
                             if event.get('kind') == 'mmio_delivery'
                             and event.get('device_id') == 'gpio_a'
                             and event.get('offset') == 0x0c
                             and event.get('write')]
            self.assertEqual([0x49, 0x81, 0xff], gpio_a_writes)
            a_outputs = []
            for event in trace.events:
                if event.get('component') != 'gpio_a':
                    continue
                value = event.get('outputs', {}).get('gpio_out', 0) & 0xff
                if value in (0x49, 0x81, 0xff) and (
                        not a_outputs or a_outputs[-1] != value):
                    a_outputs.append(value)
            self.assertEqual([0x49, 0x81, 0xff], a_outputs)
            self.assertEqual(3, sum(event.get('kind') == 'source_start'
                                    and event.get('source') == ('gpio_b', 'irq')
                                    for event in trace.events))
            self.assertEqual(3, sum(event.get('kind') == 'pulse_start'
                                    for event in trace.events))
            self.assertEqual(3, sum(event.get('kind') == 'initial_image'
                                    for event in trace.events))
            self.assertFalse(any(event.get('kind') in
                                 ('irq_overrun', 'reset', 'reset_barrier', 'reset_failure')
                                 for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'state_dependency'
                                and event.get('edge_kind') == 'WAW'
                                for event in trace.events))
            self.assertEqual(1, len(instances))
            replay = replay_scenario(case, factory, trace)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(2, len(instances))


if __name__ == '__main__':
    unittest.main()
