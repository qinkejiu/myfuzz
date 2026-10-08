"""One real 8N1 byte reaches Pico custom IRQ3, RXREG and persistent RAM."""
from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.local_harness.wishbone_uart_session import GeneratedWishboneUartSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.uart_peer import Uart8N1Peer
from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE, ROOT
from tests.integration.test_scenario_ibex_opentitan_gpio_irq_real import (
    _addi, _lui, _lw, _sw, _image)
from tests.integration.test_scenario_cve2_opentitan_gpio_generated_real import _beq
from tests.integration.test_scenario_cve2_zip_wb_uart_real import _andi


UART_BASE = 0x40000000
RESULT = 0x200
RETIRQ_PC = 0x34


class _PicoRxPeer(Uart8N1Peer):
    """Fixed external idle cell for Pico's slower boot SETUP transaction."""

    def start_source(self, tick):
        # The existing UART session supplies 17 idle cells. SETUP resets RX
        # synchronization after the slower Pico boot, so add one fixed cell.
        # Timing is testcase plumbing; only the selected byte is fuzzable.
        super().start_source(tick + self.clocks_per_bit)


def _genome():
    # Pinned custom0 ABI: q0=return PC, q1=pending vector; PROGADDR_IRQ=0x10.
    # Configure at reset entry; the peer adds one fixed 25-tick idle cell to
    # the session's 17 cells so SETUP's derived RX reset can synchronize.
    words = [_lui(1, UART_BASE >> 12), _addi(2, 0, 25), _sw(2, 1, 0),
             0x0740006f]                    # jal x0,0x80 from PC 0x0c
    words += [
        0x0000c28b,                         # getq x5,q1
        _lw(3, 1, 8), _andi(3, 3, 255),    # CPU pops the real RX FIFO once
        _sw(3, 8, 0), _sw(5, 8, 4),
        _addi(6, 0, 0x55), _sw(6, 8, 8),
        _addi(6, 0, -1), 0x0603600b,        # maskirq x0,x6 (one-shot)
        0x0400000b,                         # retirq through q0
    ]
    words += [0x00000013] * (32 - len(words))
    words += [
        _addi(6, 0, -9), 0x0603600b,        # enable only custom IRQ bit 3
        _addi(8, 0, RESULT),
        _lw(2, 8, 8), _beq(2, 0, -4),     # wait for ISR completion marker
        _addi(2, 0, 0x66), _sw(2, 8, 12),  # main after custom retirq
        0x0000006f,
    ]
    return ScenarioGenome(
        testcase_id='pico-wb-zipcpu-uart-rx-custom-irq', direction='IP_TO_CPU',
        path_id='external-8n1-uart-rx-irq-pico-custom-handler-ram',
        schedule_order=('cpu', 'uart'), max_steps=1800,
        actions=(Action('external-serial-byte', 'uart', 'uart_rx_byte', 0x35,
                        'IP_TO_CPU', Trigger('START'), width=8),),
        initial_images=(MemoryImage('cpu.program', 'cpu', 0, _image(tuple(words))),
                        MemoryImage('cpu.results', 'cpu', RESULT, bytes(16).hex())))


def _make_factory(cache_dir: Path):
    cpu_art = artifact(PROFILE, 'cpu')
    uart_art = artifact('configs/peripherals/zipcpu_uart/component_profile.json', 'uart')
    ownership = compile_ownership(
        (InputField('cpu', 'irq', 32), InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 3, 'fixed', 'constant_zero'),
         InputOwner('cpu', 'irq', 3, 1, 'bound', 'uart.uart_rx_int'),
         InputOwner('cpu', 'irq', 4, 28, 'fixed', 'constant_zero'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source', 'external_uart_rx_byte')))
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
            initialization_seed=37, max_initialized_bytes=4096)
        uart = GeneratedWishboneUartSession(uart_art, base_dir=ROOT,
            cache_dir=cache_dir, source=None, cpu_routed_mode=True)
        uart.peer = _PicoRxPeer(b'')
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, 16, uart),))
        cpu = GeneratedWishboneCpuSession(cpu_art, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'uart': uart},
            ownership=ownership, bindings=(Binding('uart', 'uart_rx_int',
                'cpu', 'irq', 1, target_bit_offset=3),))
        instances.append(runner)
        return runner

    return factory, instances, ownership


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned Pico and wbuart RTL')
class GeneratedPicoWishboneZipcpuUartIrqRealTests(unittest.TestCase):
    def _assert_chain(self, trace, runner, byte):
        events = trace.events
        cpu, uart = runner.sessions['cpu'], runner.sessions['uart']
        cpu_steps = [e for e in events if e.get('component') == 'cpu'
                     and 'inputs' in e and 'outputs' in e]
        self.assertTrue(any(e.get('kind') == 'local_tick_sample'
            and e.get('component') == 'uart'
            and e['outputs']['uart_rx_int'] == 1 for e in events),
            'real UART never accepted the RX frame into its FIFO')
        eoi = [e for e in cpu_steps if e['outputs']['eoi'] == 8]
        self.assertTrue(eoi, 'real Pico never entered custom IRQ3 handler')
        self.assertEqual('complete', trace.status, events[-8:])
        self.assertEqual('wishbone_cpu', cpu.artifact.runtime_document['kind'])
        self.assertEqual('wishbone_uart', uart.artifact.runtime_document['kind'])
        self.assertNotEqual(cpu._execution, uart._execution)
        self.assertEqual({}, runner._irq_pulses)
        owners = runner.ownership.document()['owners']
        self.assertEqual(4, len(owners))
        self.assertEqual([('uart', 'uart_rx_byte', 0, 8)],
            [(r['component_id'], r['port'], r['bit_offset'], r['width'])
             for r in owners if r['kind'] == 'source'])
        self.assertEqual([('cpu', 'irq', 3, 1, 'uart.uart_rx_int')],
            [(r['component_id'], r['port'], r['bit_offset'], r['width'],
              r['producer_ref']) for r in owners if r['kind'] == 'bound'])
        self.assertEqual([(0, 3), (4, 28)],
            [(r['bit_offset'], r['width']) for r in owners if r['kind'] == 'fixed'])
        self.assertTrue(all(r['producer_ref'] == 'constant_zero'
                            for r in owners if r['kind'] == 'fixed'))
        self.assertEqual([], uart.local_transactions)
        self.assertEqual((), uart.startup_writes)
        self.assertFalse(uart.read_rx_after_source)
        self.assertTrue(uart.cpu_routed_mode)
        self.assertEqual(bytes((byte,)), uart.peer.source)
        self.assertEqual(25, uart.peer.clocks_per_bit)
        self.assertEqual([], uart.peer.captured)
        injections = [e for e in events if e.get('kind') == 'source_injection']
        self.assertEqual(1, len(injections))
        self.assertEqual(('uart', 'uart_rx_byte', byte, 0, 8, 'external_uart_rx_byte'),
            tuple(injections[0][k] for k in
                  ('component', 'port', 'value', 'bit_offset', 'width', 'source_ref')))
        self.assertFalse(any(e.get('kind') in ('local_register_transaction',
                            'pulse_start', 'reset_barrier') for e in events))

        deliveries = [e for e in events if e.get('kind') == 'mmio_delivery']
        writes = [e for e in deliveries if e['write']]
        reads = [e for e in deliveries if not e['write']]
        self.assertEqual([(0, 25)], [(e['offset'], e['write_value']) for e in writes])
        self.assertEqual([(8, byte)], [(e['offset'], e['read_value']) for e in reads])
        setup, read = writes[0], reads[0]
        fields = ('source_component', 'source_epoch', 'channel_id', 'source_sequence')
        keys = [tuple(e['source_transaction'][k] for k in fields) for e in deliveries]
        accepted = [tuple(e['source_transaction'][k] for k in fields)
                    for e in events if e.get('kind') == 'mmio_acceptance']
        self.assertEqual(2, len(keys))
        self.assertEqual(2, len(set(keys)), 'duplicate MMIO delivery')
        self.assertEqual(keys, accepted)
        self.assertTrue(all(k[:2] == ('cpu', 0) for k in keys))
        self.assertTrue(all(e['device_id'] == 'uart' and e['beat_bytes'] == 4
                            and e['byte_enable'] == 15 for e in deliveries))
        self.assertEqual((1, 1), (cpu.mmio_write_count, cpu.mmio_read_count))
        setup_consumed = [e for e in cpu_steps if e['outputs']['data_rsp_consumed']
            and e['outputs']['data_write'] and e['outputs']['data_addr'] == UART_BASE]
        self.assertEqual(1, len(setup_consumed))
        self.assertLess(setup['event_id'], setup_consumed[0]['event_id'])

        samples = [e for e in events if e.get('kind') == 'local_tick_sample'
                   and e.get('component') == 'uart']
        rx_name = next(r['runtime_name'] for r in
            uart.artifact.runtime_document['physical_exports']
            if r['physical_port'] == 'i_uart_rx')
        irq_name = next(r['runtime_name'] for r in
            uart.artifact.runtime_document['physical_exports']
            if r['physical_port'] == 'o_uart_rx_int')
        self.assertTrue(all(e['outputs']['uart_rx_int'] ==
                            e['outputs']['physical'][irq_name] for e in samples))
        pre_strobes = [e for e in samples if e['phase'] == 'pre'
                       and e['outputs']['backend']['uart_target_stb']]
        self.assertEqual(2, len(pre_strobes), 'expected two actual target STB pulses')
        # Target STB in the pre sample acts at this clock's rising edge; its
        # paired post receipt and eventual real response prove ACCESS completed.
        setup_strobe, read_strobe = pre_strobes
        for delivery, strobe in zip(deliveries, pre_strobes):
            backend = strobe['outputs']['backend']
            self.assertEqual(int(delivery['write']), backend['uart_req_write'])
            self.assertEqual(delivery['offset'], backend['uart_req_addr'])
            self.assertEqual(15, backend['uart_req_be'])
            self.assertTrue(any(e['phase'] == 'post'
                and e['local_tick'] >= strobe['local_tick']
                and e['producer_event_id'] == strobe['producer_event_id']
                and e['outputs']['backend']['uart_rsp_valid'] for e in samples),
                'real target response receipt absent')
        self.assertEqual(25, setup_strobe['outputs']['backend']['uart_req_wdata'])
        setup_post = next(e for e in samples if e['phase'] == 'post'
                          and e['local_tick'] == setup_strobe['local_tick'])
        first_start = next(e for e in samples if e['phase'] == 'pre'
                          and e['outputs']['physical'][rx_name] == 0)
        self.assertEqual(uart.peer.source_start_tick, first_start['local_tick'])
        self.assertLess(setup_post['local_tick'], first_start['local_tick'],
                        'real SETUP write commit must precede RX start bit')
        self.assertGreaterEqual(first_start['local_tick'] - setup_post['local_tick'], 425,
                        'RX frame must allow 16 idle cells plus a fixed synchronization margin')
        self.assertLess(setup['event_id'], first_start['event_id'],
                        'completed real SETUP MMIO must precede physical RX frame')
        self.assertTrue(all(e['outputs']['physical'][rx_name] == 1 for e in samples
                           if e['local_tick'] < uart.peer.source_start_tick))
        frame = [e for e in samples if e['phase'] == 'pre' and
                 uart.peer.source_start_tick <= e['local_tick'] < uart.peer.source_end_tick]
        expected_bits = [0] + [(byte >> bit) & 1 for bit in range(8)] + [1]
        self.assertEqual([bit for bit in expected_bits for _ in range(25)],
                         [e['outputs']['physical'][rx_name] for e in frame],
                         'actual RTL RX pin receipt must be one complete 8N1 frame')
        self.assertGreaterEqual(read_strobe['local_tick'], uart.peer.source_end_tick)

        irq = [e for e in events if e.get('kind') == 'dataflow_delivery'
               and tuple(e.get('source', ())) == ('uart', 'uart_rx_int')
               and tuple(e.get('target', ())) == ('cpu', 'irq')]
        high = next((e for e in irq if e['value'] == 1), None)
        self.assertIsNotNone(high, 'native UART level IRQ did not reach CPU binding')
        high_sample = next(e for e in samples if e['event_id'] == high['producer_event_id'])
        self.assertEqual(1, high_sample['outputs']['uart_rx_int'])
        self.assertLess(high_sample['local_tick'], read_strobe['local_tick'])
        self.assertEqual(1, read_strobe['outputs']['uart_rx_int'])
        low_sample = next((e for e in samples if e['phase'] == 'post'
            and e['local_tick'] >= read_strobe['local_tick']
            and e['producer_event_id'] == read_strobe['producer_event_id']
            and e['outputs']['uart_rx_int'] == 0), None)
        self.assertIsNotNone(low_sample, 'actual RXREG FIFO pop did not clear level IRQ')
        self.assertTrue(all(e['outputs']['uart_rx_int'] == 1 for e in samples
            if high_sample['local_tick'] < e['local_tick'] < read_strobe['local_tick']))
        self.assertTrue(any(e['value'] == 0 and
            e['producer_event_id'] == low_sample['event_id'] for e in irq))
        self.assertTrue(all(e['outputs']['uart_rx_int'] == 0 for e in samples
            if e['local_tick'] > low_sample['local_tick']))

        self.assertTrue(all(e['inputs'].get('irq', 0) in (0, 8) for e in cpu_steps))
        self.assertTrue(any(e['inputs'].get('irq') == 8 for e in cpu_steps))
        self.assertTrue(all(e['outputs']['trap'] == 0 for e in cpu_steps))
        self.assertTrue(all(e['outputs']['eoi'] in (0, 8) for e in cpu_steps))
        self.assertEqual(0, cpu_steps[-1]['outputs']['eoi'])
        self.assertEqual(1, sum(previous['outputs']['eoi'] == 0
            and current['outputs']['eoi'] == 8
            for previous, current in zip(cpu_steps, cpu_steps[1:])),
            'one-shot handler must enter exactly once')
        self.assertLess(high['event_id'], eoi[0]['event_id'])
        for pc in (0x10, RETIRQ_PC):
            self.assertTrue(any(e['outputs']['instr_req_accepted']
                and e['outputs']['instr_addr'] == pc for e in eoi),
                f'custom handler fetch {pc:#x} absent while EOI high')
        consumed = [e for e in cpu_steps if e['outputs']['data_rsp_consumed']
            and not e['outputs']['data_write']
            and e['outputs']['data_addr'] == UART_BASE + 8]
        self.assertEqual([byte], [e['outputs']['data_rsp_rdata'] for e in consumed])
        self.assertLess(read['event_id'], consumed[0]['event_id'])
        self.assertLess(low_sample['event_id'], consumed[0]['event_id'])
        self.assertTrue(eoi[0]['event_id'] < consumed[0]['event_id'] < eoi[-1]['event_id'])

        expected = [byte, 8, 0x55, 0x66]
        self.assertEqual(expected, [cpu.memory.read(RESULT + 4 * i, 4,
            transaction_id=f'pico-uart-result-{i}').value for i in range(4)])
        ram = [e for e in events if e.get('kind') == 'memory_write'
               and e.get('component') == 'cpu' and RESULT <= e['address'] < RESULT + 16]
        self.assertEqual([(RESULT + 4 * i, v) for i, v in enumerate(expected)],
                         [(e['address'], e['value']) for e in ram])
        stores = [e for e in cpu_steps if e['outputs']['data_rsp_consumed']
                  and e['outputs']['data_write']
                  and RESULT <= e['outputs']['data_addr'] < RESULT + 16]
        self.assertEqual([RESULT + 4 * i for i in range(4)],
                         [e['outputs']['data_addr'] for e in stores])
        self.assertLess(consumed[0]['event_id'], ram[0]['event_id'])
        self.assertLess(stores[-2]['event_id'], ram[-1]['event_id'])
        self.assertLess(eoi[-1]['event_id'], ram[-1]['event_id'],
                        'mainline marker must occur after real retirq/EOI clear')
        self.assertEqual((0, 0), (cpu.reset_epoch, uart.reset_epoch))
        return (trace.semantic_sha256, expected[0])

    def test_external_uart_irq_custom_handler_mutation_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-pico-wb-zip-uart-irq-') as directory:
            work = Path(directory)
            factory, instances, ownership = _make_factory(work / 'cache')
            seed = _genome()
            graph = DependencyGraph(sources=(FuzzableSource('external_uart_rx_byte',
                'uart', 'uart_rx_byte', 0, 8, ('IP_TO_CPU',)),), rules=(
                DependencyRule('uart.rxfifo_data', ('external_uart_rx_byte',), 'DATA_BINDING'),
                DependencyRule('uart.uart_rx_int', ('uart.rxfifo_data',), 'EVENT_ORDER'),
                DependencyRule('cpu.result_ram', ('uart.uart_rx_int',), 'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.result_ram': 1}, direction='IP_TO_CPU')
            self.assertEqual('external_uart_rx_byte', mutation.focus_source)
            changed = seed
            for bit in (0, 1, 4, 7):
                changed = mutate_genome(changed, mutation, graph, ownership, bit_index=bit)
            self.assertEqual((0x35, 0xa6), (seed.actions[0].value, changed.actions[0].value))
            self.assertEqual(seed.initial_images, changed.initial_images)
            self.assertEqual(seed.actions[0].trigger, changed.actions[0].trigger)
            self.assertEqual(seed, replace(changed, actions=(
                replace(changed.actions[0], value=seed.actions[0].value),)))
            with self.assertRaisesRegex(ValueError, 'bound input cannot be mutated'):
                ownership.mutation_source('cpu', 'irq', 3, 1, direction='IP_TO_CPU')
            budget = ResourceBudget(max_wall_time_ms=180000,
                max_materialized_bytes_per_memory=4096, max_evidence_bytes=32 * 1024 * 1024)
            observed = []
            for genome in (seed, changed):
                byte = genome.actions[0].value
                with self.subTest(payload=f'{byte:#04x}'):
                    bundle = work / f'evidence-{byte:02x}'
                    trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                    original = instances[-1]
                    observed.append(self._assert_chain(trace, original, byte))
                    replay = replay_evidence_bundle(bundle, factory)
                    self.assertTrue(replay.matches, replay.difference_context)
                    fresh = instances[-1]
                    self.assertIsNot(original, fresh)
                    for component in ('cpu', 'uart'):
                        self.assertIsNot(original.sessions[component], fresh.sessions[component])
                        self.assertNotEqual(original.sessions[component]._execution,
                                            fresh.sessions[component]._execution)
                    self.assertEqual(observed[-1], self._assert_chain(replay.actual_trace, fresh, byte))
            self.assertEqual([0x35, 0xa6], [row[1] for row in observed])
            self.assertNotEqual(observed[0][0], observed[1][0])


if __name__ == '__main__':
    unittest.main()
