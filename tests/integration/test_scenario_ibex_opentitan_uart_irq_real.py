"""OpenTitan UART RX watermark IRQ reaches Ibex ISR through separate harnesses."""
from __future__ import annotations

import os
from dataclasses import replace
import json
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
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.session_runtime import OnlineCase, ScenarioSession, replay_online_session


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


def _csrrs(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _genome() -> ScenarioGenome:
    main = (
        _lui(1, 0x40000),
        _lui(2, 0x80000), _addi(2, 2, 3), _sw(2, 1, 0x10),
        _addi(2, 0, 2), _sw(2, 1, 0x04),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -0x800), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        0x0000006f,
    )
    isr = (
        *((0x00000013,) * 64),
        _lw(4, 1, 0x00),
        _lw(3, 1, 0x18),
        _lui(5, 0x20),
        _sw(3, 5, 0), _sw(4, 5, 4),
        0x30200073,
    )
    return ScenarioGenome(
        testcase_id='ibex-opentitan-uart-rx-watermark-irq',
        direction='IP_TO_CPU',
        path_id='uart-rx-pin-real-rtl-irq-ibex-rdata-status-ram',
        schedule_order=('uart', 'cpu'), max_steps=4500,
        actions=(Action('external-rx-byte', 'uart', 'uart_rx_byte', 0x5a,
                        'IP_TO_CPU', Trigger('START')) ,),
        initial_images=(
            MemoryImage('cpu.main', 'cpu', 0x10080, _image(main)),
            MemoryImage('cpu.isr', 'cpu', 0x1012c, _image(isr)),
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
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned OpenTitan and Ibex RTL')
class GeneratedIbexOpentitanUartIrqTests(unittest.TestCase):
    def test_online_two_uart_rx_cases_reuse_one_ibex_and_uart(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-uart-online-two-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json',
                                     'cpu')
            uart_artifact = _artifact(
                'configs/peripherals/opentitan_uart_local/component_profile.json',
                'uart')
            factory, instances = _make_factory(cpu_artifact, uart_artifact,
                                               work / 'cache')
            template = replace(_genome(), actions=(), max_steps=2400)
            session = ScenarioSession(template, factory())
            session.begin()
            self.addCleanup(lambda: session.finish() if not session._finished else None)
            for index, byte in enumerate((0x5a, 0xa6)):
                case = OnlineCase(f'frame-{index}', 'IP_TO_CPU', template.path_id,
                    BatchSourceEvent(f'rx-{index}', 'uart', 'uart_rx_byte', byte),
                    (BatchAdvance(('uart', 'cpu')),)*1100)
                receipt = session.submit_case(case)
                uart = instances[-1].sessions['uart']
                self.assertGreaterEqual(uart.local_ticks, uart.peer.source_end_tick)
                self.assertTrue(any(event.get('outputs', {}).get('uart_rx_watermark') == 1
                                    for event in receipt.events))
            reference = session.finish()
            plan = session.encode_plan()
            self.assertEqual(6, json.loads(plan)['schema_version'])
            self.assertTrue(replay_online_session(plan, factory, reference).matches)

    def test_uart_rx_watermark_irq_is_serviced_by_ibex_and_replayed(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-opentitan-uart-irq-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json',
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
            self.assertFalse(any(event['offset'] == 0x00 for event in writes),
                'RX watermark INTR_STATE is a read-only status field')

            reads = [event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'uart' and not event.get('write')]
            self.assertTrue(any(event['offset'] == 0x18
                                and event['read_value'] & 0xff == 0x5a
                                for event in reads),
                            'Ibex ISR did not read the UART RTL RXDATA')
            self.assertTrue(any(event['offset'] == 0x00
                                and event['read_value'] & 0x2 == 0x2
                                for event in reads),
                            'Ibex ISR did not read the asserted UART INTR_STATE')
            rdata_read = next(event for event in reads if event['offset'] == 0x18)
            self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('uart', 'uart_rx_watermark')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 0
                and event.get('event_id', 0) > rdata_read['event_id']
                for event in events), 'RDATA pop did not lower the real UART IRQ')

            irq_events = [event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('uart', 'uart_rx_watermark')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 1]
            self.assertTrue(irq_events, 'UART native IRQ never reached Ibex')
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
                'Ibex did not execute the installed ISR after receiving UART IRQ')

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
            self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                 for event in events))

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['uart'], instances[1].sessions['uart'])


if __name__ == '__main__':
    unittest.main()
