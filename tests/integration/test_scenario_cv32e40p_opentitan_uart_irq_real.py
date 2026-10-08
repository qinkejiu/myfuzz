"""OpenTitan UART RX watermark IRQ reaches CV32E40P through separate harnesses."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
UART_BASE = 0x40000000
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


def _jal(rd: int, offset: int) -> int:
    immediate = offset & 0x1fffff
    return (((immediate >> 20) & 1) << 31
            | ((immediate >> 1) & 0x3ff) << 21
            | ((immediate >> 11) & 1) << 20
            | ((immediate >> 12) & 0xff) << 12
            | rd << 7 | 0x6f)


def _csrrw(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 1 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),
        _lui(2, 0x80000), _addi(2, 2, 3), _sw(2, 1, 0x10),
        _addi(2, 0, 2), _sw(2, 1, 0x04),
        # CV32E40P stores mtvec[31:8], so the direct-mode base must be
        # 256-byte aligned. 0x1012c would be rounded down to 0x10100.
        _lui(7, 0x10), _addi(7, 7, 0x100), _csrrw(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrw(0x304, 7),
        _addi(7, 0, 8), _csrrw(0x300, 7),
        0x0000006f,
    )
    # Require direct-mode entry at 0x10100. A jump skips the vector table to
    # the delay block at 0x10200; ISR instructions start at 0x10300. Every
    # other slot, including IRQ 11's vectored slot at 0x1012c, loops forever
    # so a vector-mode/offset error cannot fall through the timing delay.
    vector_table = [0x0000006f] * 64
    vector_table[0] = _jal(0, 0x100)
    isr = (
        *vector_table,
        *((0x00000013,) * 64),
        _lw(4, 1, 0x00),
        _lw(3, 1, 0x18),
        _lui(5, 0x20),
        _sw(3, 5, 0), _sw(4, 5, 4),
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id='cv32e40p-opentitan-uart-rx-watermark-irq',
        direction='IP_TO_CPU',
        path_id='uart-rx-pin-real-rtl-irq-cv32e40p-rdata-status-ram',
        schedule_order=('uart', 'cpu'), max_steps=4500,
        actions=(
            Action('external-rx-byte', 'uart', 'uart_rx_byte', 0x5a,
                   'IP_TO_CPU', Trigger('START')),
        ),
        initial_images=(
            # CV32E40P's pinned local boot address is 0x10000 (unlike Ibex).
            MemoryImage('cpu.main', 'cpu', 0x10000, _image(main)),
            MemoryImage('cpu.isr', 'cpu', 0x10100, _image(isr)),
            MemoryImage('cpu.result', 'cpu', RESULT, '0000000000000000'),
        ))


def _make_factory(cpu_artifact, uart_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_watermark'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                    'external_uart_rx_byte')))
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x30000),),
            initialization_seed=47, max_initialized_bytes=0x30000)
        uart = GeneratedOpentitanUartSession(uart_artifact, base_dir=ROOT,
            cache_dir=cache_dir, source=None, cpu_routed_mode=True)
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, 0x1000, uart),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        binding = Binding('uart', 'uart_rx_watermark', 'cpu', 'irq', 1)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'uart': uart},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P and OpenTitan RTL')
class GeneratedCv32e40pOpentitanUartIrqTests(unittest.TestCase):
    def test_uart_rx_watermark_irq_is_serviced_by_cv32e40p_and_replayed(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cv32e40p-opentitan-uart-irq-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e40p/component_profile.json',
                                     'cpu')
            uart_artifact = _artifact(
                'configs/peripherals/opentitan_uart_local/component_profile.json',
                'uart')
            factory, instances = _make_factory(cpu_artifact, uart_artifact,
                                               work / 'cache')
            genome = _genome()
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual('complete', trace.status, trace.events[-8:])

            events = trace.events
            owners = instances[0].ownership.document()['owners']
            self.assertIn({
                'component_id': 'cpu', 'port': 'irq', 'bit_offset': 0,
                'width': 1, 'kind': 'bound',
                'producer_ref': 'uart.uart_rx_watermark'}, owners)
            self.assertIn({
                'component_id': 'uart', 'port': 'uart_rx_byte', 'bit_offset': 0,
                'width': 8, 'kind': 'source',
                'producer_ref': 'external_uart_rx_byte'}, owners)
            injection = next(event for event in events
                if event.get('kind') == 'source_injection'
                and event.get('action_id') == 'external-rx-byte')
            self.assertEqual(0x5a, injection['value'])
            writes = [event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'uart' and event.get('write')]
            self.assertIn((0x10, 0x80000003),
                          [(event['offset'], event['write_value']) for event in writes])
            self.assertIn((0x04, 0x2),
                          [(event['offset'], event['write_value']) for event in writes])
            self.assertEqual([(0x10, 0x80000003), (0x04, 0x2)],
                [(event['offset'], event['write_value']) for event in writes],
                'CPU must configure UART exactly once before the RX interrupt')
            self.assertFalse(any(event['offset'] == 0x00 for event in writes),
                'RX watermark INTR_STATE is a read-only status field')

            reads = [event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'uart' and not event.get('write')]
            if not any(event['offset'] == 0x18
                       and event['read_value'] & 0xff == 0x5a for event in reads):
                uart_samples = [event for event in events
                    if event.get('kind') == 'local_tick_sample'
                    and event.get('component') == 'uart']
                cpu_samples = [event for event in events
                    if event.get('component') == 'cpu'
                    and isinstance(event.get('outputs'), dict)]
                irq_deliveries = [event for event in events
                    if event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ())) == ('uart', 'uart_rx_watermark')
                    and tuple(event.get('target', ())) == ('cpu', 'irq')]
                irq_transitions = [(event.get('event_id'), event.get('value'),
                                    event.get('producer_event_id'))
                    for index, event in enumerate(irq_deliveries)
                    if index == 0 or irq_deliveries[index - 1].get('value') != event.get('value')]
                uart_last = uart_samples[-1] if uart_samples else None
                first_irq = next((event for event in irq_deliveries
                                  if event.get('value') == 1), None)
                cpu_irq_window = ([] if first_irq is None else [
                    (event.get('event_id'), event.get('inputs', {}).get('irq'),
                     event.get('outputs', {}).get('instr_addr'),
                     event.get('outputs', {}).get('instr_req_accepted'),
                     event.get('outputs', {}).get('irq_ack_o'),
                     event.get('outputs', {}).get('irq_id_o'))
                    for event in cpu_samples
                    if event.get('event_id', 0) > first_irq.get('event_id', 0)][:16])
                self.fail('CV32E40P ISR did not read UART RXDATA; '
                    + repr({
                        'reads': [(hex(event['offset']), hex(event['read_value']))
                                  for event in reads],
                        'irq_transition_deliveries': irq_transitions,
                        'uart_sample_count': len(uart_samples),
                        'uart_last_tick': None if uart_last is None else uart_last.get('local_tick'),
                        'uart_last_outputs': None if uart_last is None else {
                            key: uart_last.get('outputs', {}).get(key)
                            for key in ('uart_rx_watermark', 'uart_rx_frame_err',
                                         'uart_rx_parity_err', 'uart_rx_overflow')},
                        'cpu_sample_count': len(cpu_samples),
                        'cpu_tail': [(event.get('event_id'),
                                      event.get('inputs', {}).get('irq'),
                                      event.get('outputs', {}).get('instr_addr'),
                                      event.get('outputs', {}).get('instr_req_accepted'),
                                      event.get('outputs', {}).get('irq_ack_o'),
                                      event.get('outputs', {}).get('irq_id_o'))
                                     for event in cpu_samples[-12:]],
                        'cpu_irq_window': cpu_irq_window,
                    }))
            self.assertTrue(any(event['offset'] == 0x00
                                and event['read_value'] & 0x2 == 0x2
                                for event in reads),
                            'CV32E40P ISR did not read the asserted UART INTR_STATE')
            self.assertEqual([0x00, 0x18], [event['offset'] for event in reads],
                'ISR must read the status once, then pop RXDATA exactly once')
            rdata_read = next(event for event in reads if event['offset'] == 0x18)
            irq_low = next((event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('uart', 'uart_rx_watermark')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 0
                and event.get('event_id', 0) > rdata_read['event_id']), None)
            self.assertIsNotNone(irq_low, 'RDATA pop did not lower the real UART IRQ')
            irq_low_source = next(event for event in events
                if event.get('event_id') == irq_low['producer_event_id'])
            self.assertEqual(0, irq_low_source['outputs']['uart_rx_watermark'])
            self.assertLess(rdata_read['event_id'], irq_low['event_id'])

            irq_events = [event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('uart', 'uart_rx_watermark')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 1]
            self.assertTrue(irq_events, 'UART native IRQ never reached CV32E40P')
            irq = irq_events[0]
            producer = next(event for event in events
                if event.get('event_id') == irq['producer_event_id'])
            self.assertEqual(1, producer['outputs']['uart_rx_watermark'])
            irq_reads = [event for event in events
                if event.get('kind') == 'mmio_acceptance'
                and event.get('device_id') == 'uart'
                and event.get('offset') in (0x00, 0x18)
                and event.get('event_id', 0) > irq['event_id']]
            self.assertEqual({0x00, 0x18}, {event['offset'] for event in irq_reads},
                'CV32E40P did not execute the installed ISR after receiving UART IRQ')

            cpu_steps = [event for event in events
                         if event.get('component') == 'cpu' and 'outputs' in event]
            irq_ack = next((event for event in cpu_steps
                if event.get('inputs', {}).get('irq') == 1
                and event['outputs'].get('irq_ack_o') == 1
                and event['outputs'].get('irq_id_o') == 11), None)
            self.assertIsNotNone(irq_ack,
                'one CV32E40P step must see bound irq high and acknowledge irq_i[11]')
            self.assertLess(producer['event_id'], irq['event_id'])
            self.assertLess(irq['event_id'], irq_ack['event_id'])
            self.assertLess(irq_ack['event_id'], min(e['event_id'] for e in irq_reads))
            post_ack_fetch = next((event for event in cpu_steps
                if event.get('event_id', 0) > irq_ack['event_id']
                and event.get('outputs', {}).get('instr_req_accepted') == 1), None)
            self.assertIsNotNone(post_ack_fetch,
                'CV32E40P did not issue a fetch after acknowledging the IRQ')
            self.assertEqual(0x10100,
                post_ack_fetch['outputs'].get('instr_addr'),
                'direct-mode IRQ entry must fetch from the aligned mtvec base')

            writes_to_ram = [event for event in events
                if event.get('kind') == 'memory_write'
                and event.get('component') == 'cpu'
                and event.get('address') in (RESULT, RESULT + 4)]
            intr_state = next(event for event in reads
                if event['offset'] == 0x00)
            self.assertEqual([(RESULT, 0x5a),
                              (RESULT + 4, intr_state['read_value'])],
                [(event['address'], event['value']) for event in writes_to_ram])
            memory = instances[0].sessions['cpu'].memory
            self.assertEqual(0x5a, memory.read(RESULT, 4,
                transaction_id='uart-rdata').value)
            self.assertEqual(intr_state['read_value'], memory.read(RESULT + 4, 4,
                transaction_id='uart-intr-state').value)
            self.assertFalse(any(event.get('kind') in ('reset_barrier', 'reset_failure')
                                 for event in events))
            self.assertEqual({0}, {session.reset_epoch for session in
                                   instances[0].sessions.values()})

            mmio_transactions = [event for event in events
                if event.get('kind') == 'mmio_delivery']
            transaction_keys = [tuple(event['source_transaction'][field] for field in
                ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
                for event in mmio_transactions]
            self.assertEqual(len(transaction_keys), len(set(transaction_keys)),
                             'CPU MMIO transaction was executed more than once')
            self.assertEqual({'cpu'}, {key[0] for key in transaction_keys})
            self.assertEqual({0}, {key[1] for key in transaction_keys})

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['uart'], instances[1].sessions['uart'])
            replay_memory = instances[1].sessions['cpu'].memory
            self.assertEqual(0x5a, replay_memory.read(RESULT, 4,
                transaction_id='cv32-uart-replay-rdata').value)
            self.assertEqual(intr_state['read_value'], replay_memory.read(RESULT + 4, 4,
                transaction_id='cv32-uart-replay-intr-state').value)


if __name__ == '__main__':
    unittest.main()
