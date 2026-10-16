"""External GPIO pins reach real Pico custom IRQ/RAM through Wishbone/TL-UL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.picorv32_wb_cpu_example import (
    GPIO_BASE, RESULT, make_picorv32_wb_gpio_irq_genome,
    make_picorv32_wb_gpio_irq_runner, picorv32_wb_gpio_irq_ownership,
)


def _make_factory(cache_dir: Path):
    instances = []

    def factory():
        runner = make_picorv32_wb_gpio_irq_runner(cache_dir=cache_dir)
        instances.append(runner)
        return runner

    return factory, instances, picorv32_wb_gpio_irq_ownership()


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned Pico and GPIO RTL')
class GeneratedPicoWishboneOpentitanGpioIrqRealTests(unittest.TestCase):
    def _assert_chain(self, trace, runner, source_value):
        self.assertEqual('complete', trace.status, trace.events[-8:])
        events = trace.events
        cpu, gpio = runner.sessions['cpu'], runner.sessions['gpio']
        self.assertEqual('wishbone_cpu', cpu.artifact.runtime_document['kind'])
        self.assertEqual('tlul_gpio', gpio.artifact.runtime_document['kind'])
        self.assertEqual({}, runner._irq_pulses)
        owners = runner.ownership.document()['owners']
        self.assertEqual([('gpio', 'gpio_in', 0, 8)],
            [(row['component_id'], row['port'], row['bit_offset'], row['width'])
             for row in owners if row['kind'] == 'source'])
        self.assertEqual([('cpu', 'irq', 3, 1, 'gpio.irq')],
            [(row['component_id'], row['port'], row['bit_offset'], row['width'],
              row['producer_ref']) for row in owners if row['kind'] == 'bound'])
        for component, port, offset, width in (
                ('cpu', 'irq', 0, 3), ('cpu', 'irq', 4, 28),
                ('gpio', 'gpio_in', 8, 24), ('gpio', 'strap_en', 0, 1)):
            self.assertIn(dict(component_id=component, port=port, bit_offset=offset,
                width=width, kind='fixed', producer_ref='constant_zero'), owners)
        injections = [event for event in events
                      if event.get('kind') == 'source_injection']
        self.assertEqual(1, len(injections))
        injection = injections[0]
        self.assertEqual(('gpio', 'gpio_in', source_value, 0, 8, 'external_gpio_pins'),
            tuple(injection[key] for key in
                  ('component', 'port', 'value', 'bit_offset', 'width', 'source_ref')))
        gpio_steps = [event for event in events if event.get('component') == 'gpio'
                      and 'inputs' in event and 'outputs' in event]
        self.assertTrue(all(event['inputs'].get('gpio_in', 0) >> 8 == 0
                            and event['inputs'].get('strap_en', 0) == 0
                            for event in gpio_steps))
        before = [event for event in gpio_steps
                  if event['event_id'] < injection['event_id']]
        after = [event for event in gpio_steps
                 if event['event_id'] > injection['event_id']]
        self.assertTrue(before and after, 'real GPIO input steps are absent')
        self.assertEqual(0, before[-1]['inputs'].get('gpio_in', 0) & 1)
        self.assertEqual(source_value, after[0]['inputs']['gpio_in'],
                         'real lower pin 0 rising edge/payload was not applied')
        # Validate the native physical input receipt as well as runner intent.
        pin_name = next(row['runtime_name'] for row in
                        gpio.artifact.runtime_document['physical_exports']
                        if row['physical_port'] == 'cio_gpio_i')
        pin_samples = [event for event in events
                       if event.get('kind') == 'local_tick_sample'
                       and event.get('component') == 'gpio']
        self.assertTrue(any(event['event_id'] < injection['event_id']
                            and event['outputs']['physical'][pin_name] == 0
                            for event in pin_samples))
        self.assertTrue(any(event['event_id'] > injection['event_id']
                            and event['outputs']['physical'][pin_name] == source_value
                            for event in pin_samples),
                        'actual GPIO RTL pin receipt must preserve pin0 and pin7 payload')
        physical_pins = [event['outputs']['physical'][pin_name] for event in pin_samples]
        self.assertTrue(all(value in (0, source_value) for value in physical_pins))
        self.assertEqual(1, sum((previous & 1) == 0 and (current & 1) == 1
            for previous, current in zip(physical_pins, physical_pins[1:])),
            'acceptance requires exactly one actual lower pin 0 rising edge')
        deliveries = [event for event in events if event.get('kind') == 'mmio_delivery']
        writes = [event for event in deliveries if event['write']]
        reads = [event for event in deliveries if not event['write']]
        # IRQ assertion comes before ISR checks: RED without rising setup
        # fails on causality instead of a consequence such as absent RAM data.
        irq = [event for event in events if event.get('kind') == 'dataflow_delivery'
               and tuple(event.get('source', ())) == ('gpio', 'irq')
               and tuple(event.get('target', ())) == ('cpu', 'irq')]
        high = next((event for event in irq if event['value'] == 1), None)
        self.assertIsNotNone(high, 'real GPIO IRQ never reached Pico irq[3]')
        self.assertLess(injection['event_id'], high['event_id'])
        producer = next(event for event in events
                        if event['event_id'] == high['producer_event_id'])
        self.assertEqual(('local_tick_sample', 'gpio'),
                         (producer['kind'], producer['component']))
        self.assertEqual(1, producer['outputs']['interrupt'])
        for offset in (0x04, 0x2c, 0x20, 0x14):
            setup = [event for event in writes
                     if event['offset'] == offset and event['write_value'] == 1]
            self.assertEqual(1, len(setup), f'actual GPIO setup {offset:#x} missing')
            self.assertLess(setup[0]['event_id'], injection['event_id'],
                            'all actual setup deliveries must precede pin action')
        output = next(event for event in pin_samples
                      if event['event_id'] < injection['event_id']
                      and event['outputs']['gpio_out'] == 1)
        self.assertEqual(1, output['outputs']['gpio_dir'] & 1)
        self.assertEqual([(0x00, 1), (0x10, source_value), (0x00, 0)],
                         [(event['offset'], event['read_value']) for event in reads])
        self.assertTrue(all(event['event_id'] > high['event_id'] for event in reads))
        clear = next(event for event in writes if event['offset'] == 0x00)
        self.assertEqual(1, clear['write_value'])
        low = next((event for event in irq if event['value'] == 0
                    and event['event_id'] > clear['event_id']), None)
        self.assertIsNotNone(low, 'real GPIO IRQ must fall after W1C')
        self.assertTrue(all(event['value'] == 1 for event in irq
                           if high['event_id'] <= event['event_id'] < clear['event_id']),
                        'native sticky IRQ must stay high until W1C')
        self.assertEqual(0, next(event for event in events
            if event['event_id'] == low['producer_event_id'])['outputs']['interrupt'])
        cpu_steps = [event for event in events if event.get('component') == 'cpu'
                     and 'inputs' in event and 'outputs' in event]
        self.assertTrue(all(event['inputs'].get('irq', 0) in (0, 8)
                            for event in cpu_steps))
        self.assertTrue(any(event['inputs'].get('irq') == 8 for event in cpu_steps))
        self.assertTrue(all(event['outputs']['trap'] == 0 for event in cpu_steps))
        consumed = [event for event in cpu_steps
                    if event['outputs']['data_rsp_consumed']
                    and event['outputs']['data_addr'] in (GPIO_BASE, GPIO_BASE + 0x10)
                    and not event['outputs']['data_write']]
        self.assertEqual([1, source_value, 0],
                         [event['outputs']['data_rsp_rdata'] for event in consumed],
                         'real Pico Wishbone must consume the TL-UL return values')
        self.assertTrue(all(delivery['event_id'] < response['event_id']
                            for delivery, response in zip(reads, consumed)))
        eoi = [event for event in cpu_steps if event['outputs']['eoi'] == 8]
        self.assertTrue(eoi, 'Pico did not enter its real custom IRQ handler')
        self.assertLess(high['event_id'], eoi[0]['event_id'])
        self.assertEqual(0, cpu_steps[-1]['outputs']['eoi'])
        self.assertTrue(any(event['outputs']['instr_req_accepted']
                            and event['outputs']['instr_addr'] == 0x10
                            for event in cpu_steps), 'handler entry fetch absent')
        self.assertTrue(any(event['outputs']['instr_req_accepted']
                            and event['outputs']['instr_addr'] == 0x48
                            for event in cpu_steps), 'custom retirq fetch absent')
        expected = [1, source_value, 8, 0, 0x55, 0x66]
        self.assertEqual(expected, [cpu.memory.read(RESULT + offset * 4, 4,
            transaction_id=f'pico-gpio-result-{offset}').value for offset in range(6)])
        ram = [event for event in events if event.get('kind') == 'memory_write'
               and event.get('component') == 'cpu'
               and RESULT <= event['address'] < RESULT + 24]
        self.assertEqual([(RESULT + offset * 4, value)
                          for offset, value in enumerate(expected)],
                         [(event['address'], event['value']) for event in ram])
        self.assertLess(low['event_id'], ram[-2]['event_id'])
        self.assertLess(eoi[-1]['event_id'], ram[-1]['event_id'],
                        'main must resume only after real retirq/eoi clear')
        self.assertTrue(any(event['outputs']['data_req_accepted']
                            and event['outputs']['data_write']
                            and event['outputs']['data_addr'] == RESULT + 20
                            for event in cpu_steps if event['event_id'] > eoi[-1]['event_id']))
        fields = ('source_component', 'source_epoch', 'channel_id', 'source_sequence')
        keys = [tuple(event['source_transaction'][field] for field in fields)
                for event in deliveries]
        accepted = [tuple(event['source_transaction'][field] for field in fields)
                    for event in events if event.get('kind') == 'mmio_acceptance']
        self.assertEqual(8, len(keys))
        self.assertEqual(len(keys), len(set(keys)), 'duplicate MMIO delivery')
        self.assertEqual(keys, accepted, 'each MMIO acceptance needs exactly one delivery')
        self.assertTrue(all(key[:2] == ('cpu', 0) for key in keys))
        self.assertTrue(all(event['device_id'] == 'gpio' and event['beat_bytes'] == 4
                            for event in deliveries))
        self.assertEqual((5, 3), (cpu.mmio_write_count, cpu.mmio_read_count))
        self.assertEqual((0, 0), (cpu.reset_epoch, gpio.reset_epoch))
        self.assertFalse(any(event.get('kind') == 'reset_barrier' for event in events))

    def test_external_gpio_irq_custom_handler_mutation_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-pico-wb-ot-gpio-irq-') as directory:
            work = Path(directory)
            factory, instances, ownership = _make_factory(work / 'cache')
            seed = make_picorv32_wb_gpio_irq_genome()
            graph = DependencyGraph(
                sources=(FuzzableSource('external_gpio_pins', 'gpio', 'gpio_in',
                    0, 8, ('IP_TO_CPU',)),),
                rules=(DependencyRule('gpio.data_in', ('external_gpio_pins',), 'DATA_BINDING'),
                       DependencyRule('gpio.irq', ('gpio.data_in',), 'EVENT_ORDER'),
                       DependencyRule('cpu.result_ram', ('gpio.irq',), 'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1}, direction='IP_TO_CPU')
            self.assertEqual('external_gpio_pins', mutation.focus_source)
            changed = mutate_genome(seed, mutation, graph, ownership, bit_index=7)
            self.assertEqual((0x01, 0x81), (seed.actions[0].value, changed.actions[0].value))
            self.assertEqual(seed.initial_images, changed.initial_images)
            self.assertEqual(seed.actions[0].trigger, changed.actions[0].trigger)
            with self.assertRaisesRegex(ValueError, 'bound input cannot be mutated'):
                ownership.mutation_source('cpu', 'irq', 3, 1, direction='IP_TO_CPU')
            budget = ResourceBudget(max_wall_time_ms=120000,
                max_materialized_bytes_per_memory=4096, max_evidence_bytes=32 * 1024 * 1024)
            for genome in (seed, changed):
                value = genome.actions[0].value
                with self.subTest(payload=f'{value:#04x}'):
                    bundle = work / f'evidence-{value:02x}'
                    trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                    original = instances[-1]
                    self._assert_chain(trace, original, value)
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    fresh = instances[-1]
                    self.assertIsNot(original, fresh)
                    for component in ('cpu', 'gpio'):
                        self.assertIsNot(original.sessions[component], fresh.sessions[component])
                        self.assertNotEqual(original.sessions[component]._execution,
                                            fresh.sessions[component]._execution)
                    self._assert_chain(replay.actual_trace, fresh, value)


if __name__ == '__main__':
    unittest.main()
