"""CV32E40P drives two real OpenTitan GPIOs through a bound RTL chain."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_driver, render_local_harness, render_local_runtime,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/cv32e40p/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/opentitan_gpio_local/component_profile.json'
GPIO_A_BASE = 0x40000000
GPIO_B_BASE = 0x40001000
RAM_BASE = 0x10000
RESULT_BASE = 0x20000
ISR_BASE = 0x10100


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    value = offset & 0xfff
    return (((value >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (value & 0x1f) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _csrrw(rd: int, csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 1 << 12 | rd << 7 | 0x73


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _firmware() -> tuple[str, str]:
    main = (
        _lui(1, GPIO_A_BASE >> 12),
        _lui(2, GPIO_B_BASE >> 12),
        _lui(7, ISR_BASE >> 12), _addi(7, 7, ISR_BASE & 0xfff),
        _csrrw(0, 0x305, 7),                 # mtvec = ISR_BASE, direct mode
        _lui(7, 1), _addi(7, 7, -2048),
        _csrrw(0, 0x304, 7),                 # mie = MEIE = 1 << 11
        _addi(7, 0, 8), _csrrw(0, 0x300, 7), # mstatus = MIE
        _addi(3, 0, 0), _sw(3, 1, 0x14),     # GPIO A DIRECT_OUT[0] = 0
        _addi(3, 0, 1), _sw(3, 1, 0x20),     # GPIO A DIRECT_OE[0] = 1
        _sw(3, 2, 0x04),                     # GPIO B INTR_ENABLE[0] = 1
        _sw(3, 2, 0x2c),                     # GPIO B rising-edge enable
        _sw(3, 1, 0x14),                     # GPIO A drives pin 0 high
        0x0000006f,                           # wait in a real CPU loop
    )
    isr = (
        _lui(1, GPIO_B_BASE >> 12),
        _lui(8, RESULT_BASE >> 12),
        _lw(3, 1, 0x00),                     # real GPIO B INTR_STATE
        _lw(4, 1, 0x10),                     # real GPIO B DATA_IN
        _sw(3, 8, 0), _sw(4, 8, 4),          # preserve observations in RAM
        _addi(5, 0, 1), _sw(5, 1, 0x00),     # real INTR_STATE W1C
        0x30200073,                           # MRET
    )
    return _image(main), _image(isr)


def _artifact(profile_path: str, instance_id: str):
    request = load_local_harness_request({
        'schema_version': 'local_harness.v1', 'profile_path': profile_path,
        'instance_id': instance_id, 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16})
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _ownership():
    fields = (
        InputField('cpu', 'irq', 1),
        InputField('gpio_a', 'gpio_in', 32),
        InputField('gpio_a', 'strap_en', 1),
        InputField('gpio_b', 'gpio_in', 32),
        InputField('gpio_b', 'strap_en', 1),
    )
    owners = (
        InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio_b.irq'),
        InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
        InputOwner('gpio_a', 'strap_en', 0, 1, 'fixed', 'constant_zero'),
        InputOwner('gpio_b', 'gpio_in', 0, 1, 'bound', 'gpio_a.gpio_out'),
        InputOwner('gpio_b', 'gpio_in', 1, 31, 'fixed', 'constant_zero'),
        InputOwner('gpio_b', 'strap_en', 0, 1, 'fixed', 'constant_zero'),
    )
    return compile_ownership(fields, owners)


def _genome() -> ScenarioGenome:
    main, isr = _firmware()
    return ScenarioGenome(
        testcase_id='cv32e40p-two-opentitan-gpio-external-irq',
        direction='CPU_TO_IP_TO_CPU',
        path_id='cv32e40p-gpio-a-pin-b-irq-isr-ram',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'),
        max_steps=1200, actions=(),
        initial_images=(
            MemoryImage('cpu.main', 'cpu', RAM_BASE, main),
            MemoryImage('cpu.isr', 'cpu', ISR_BASE, isr),
            MemoryImage('cpu.results', 'cpu', RESULT_BASE, '00' * 8),
        ))


def _make_factory(cpu_artifact, gpio_a_artifact, gpio_b_artifact,
                  cache_dir: Path):
    ownership = _ownership()
    a_to_b = Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 1)
    b_to_cpu = Binding('gpio_b', 'irq', 'cpu', 'irq', 1)
    instances = []

    def factory() -> ScenarioRunner:
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', RAM_BASE, 0x30000),),
            initialization_seed=73, max_initialized_bytes=0x30000)
        gpio_a = GeneratedOpentitanGpioSession(
            gpio_a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        gpio_b = GeneratedOpentitanGpioSession(
            gpio_b_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((
            DeviceWindow('gpio_a', GPIO_A_BASE, 0x80, gpio_a),
            DeviceWindow('gpio_b', GPIO_B_BASE, 0x80, gpio_b),
        ))
        cpu = GeneratedCve2Session(
            cpu_artifact, base_dir=ROOT, cache_dir=cache_dir,
            memory=memory, router=router, defer_mmio=True)
        runner = ScenarioRunner(
            sessions={'cpu': cpu, 'gpio_a': gpio_a, 'gpio_b': gpio_b},
            ownership=ownership, bindings=(a_to_b, b_to_cpu))
        instances.append(runner)
        return runner

    return factory, instances, ownership


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P/OpenTitan RTL')
class GeneratedCv32e40pTwoOpenTitanGpioTests(unittest.TestCase):
    def test_gpio_a_output_causes_gpio_b_irq_and_cv32_isr_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cv32e40p-two-ot-gpio-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact(CPU_PROFILE, 'cpu')
            gpio_a_artifact = _artifact(GPIO_PROFILE, 'gpio_a')
            gpio_b_artifact = _artifact(GPIO_PROFILE, 'gpio_b')
            cache_dir = (Path(tempfile.gettempdir()) /
                         'myfuzz-cv32e40p-two-opentitan-gpio-cache')
            factory, instances, ownership = _make_factory(
                cpu_artifact, gpio_a_artifact, gpio_b_artifact, cache_dir)
            genome = _genome()
            bundle = work / 'evidence'
            budget = ResourceBudget(
                max_wall_time_ms=180000,
                max_materialized_bytes_per_memory=0x30000)
            trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status, trace.events[-12:])

            first = instances[0]
            cpu = first.sessions['cpu']
            memory = cpu.memory
            events = trace.events
            self.assertEqual(1, memory.read(
                RESULT_BASE, 4, transaction_id='cv32-isr-intr-state').value)
            self.assertEqual(1, memory.read(
                RESULT_BASE + 4, 4, transaction_id='cv32-isr-data-in').value & 1)
            self.assertEqual({0}, {session.reset_epoch for session in first.sessions.values()})
            self.assertFalse(any(event.get('kind') in ('reset_barrier', 'reset_failure')
                                 for event in events))

            owners = ownership.document()['owners']
            self.assertIn({
                'component_id': 'gpio_b', 'port': 'gpio_in', 'bit_offset': 0,
                'width': 1, 'kind': 'bound', 'producer_ref': 'gpio_a.gpio_out'}, owners)
            self.assertIn({
                'component_id': 'cpu', 'port': 'irq', 'bit_offset': 0,
                'width': 1, 'kind': 'bound', 'producer_ref': 'gpio_b.irq'}, owners)

            delivered = [event for event in events
                         if event.get('kind') == 'mmio_delivery']
            writes = [event for event in delivered if event.get('write')]
            self.assertIn(('gpio_a', 0x14, 0), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes])
            self.assertIn(('gpio_a', 0x20, 1), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes])
            self.assertIn(('gpio_b', 0x04, 1), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes])
            self.assertIn(('gpio_b', 0x2c, 1), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes])
            self.assertIn(('gpio_a', 0x14, 1), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes])
            self.assertIn(('gpio_b', 0x00, 1), [
                (event['device_id'], event['offset'], event['write_value'])
                for event in writes], 'CV32 ISR did not W1C GPIO B INTR_STATE')

            a_to_b_events = [event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio_a', 'gpio_out')
                and tuple(event.get('target', ())) == ('gpio_b', 'gpio_in')
                and event.get('value') == 1]
            self.assertTrue(a_to_b_events, 'GPIO A real output did not reach GPIO B input')
            a_source = next(event for event in events
                if event.get('event_id') == a_to_b_events[0]['producer_event_id'])
            self.assertEqual('local_tick_sample', a_source.get('kind'))
            self.assertEqual('gpio_a', a_source.get('component'))
            self.assertEqual(1, a_source.get('outputs', {}).get('gpio_out', 0) & 1)
            self.assertEqual(1, a_source.get('outputs', {}).get('gpio_dir', 0) & 1,
                             'GPIO A pin 0 was not enabled as an output at the bound sample')

            irq_delivery = next((event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio_b', 'irq')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 1), None)
            self.assertIsNotNone(irq_delivery, 'GPIO B did not deliver its asserted RTL IRQ')
            irq_source = next(event for event in events
                if event.get('event_id') == irq_delivery['producer_event_id'])
            self.assertEqual('local_tick_sample', irq_source.get('kind'))
            self.assertEqual('gpio_b', irq_source.get('component'))
            self.assertEqual(1, irq_source.get('outputs', {}).get('interrupt', 0) & 1)

            cpu_steps = [event for event in events
                         if event.get('component') == 'cpu' and 'outputs' in event]
            irq_accept = next((event for event in cpu_steps
                if event.get('inputs', {}).get('irq') == 1
                and event['outputs'].get('irq_ack_o') == 1
                and event['outputs'].get('irq_id_o') == 11), None)
            self.assertIsNotNone(irq_accept,
                'one real CV32E40P step must see bound IRQ high and acknowledge irq_i[11]')

            reads = [event for event in delivered
                if event.get('device_id') == 'gpio_b' and not event.get('write')]
            intr_state_read = next((event for event in reads
                if event.get('offset') == 0x00 and event.get('read_value') == 1), None)
            data_in_read = next((event for event in reads
                if event.get('offset') == 0x10 and event.get('read_value', 0) & 1), None)
            self.assertIsNotNone(intr_state_read,
                'ISR did not read asserted GPIO B INTR_STATE')
            self.assertIsNotNone(data_in_read,
                'ISR did not read GPIO B DATA_IN from GPIO A pin')
            w1c = next(event for event in writes
                if event.get('device_id') == 'gpio_b'
                and event.get('offset') == 0x00 and event.get('write_value') == 1)
            irq_low = next((event for event in events
                if event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('gpio_b', 'irq')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 0
                and event.get('event_id', 0) > w1c['event_id']), None)
            self.assertIsNotNone(irq_low,
                'GPIO B IRQ did not deassert after ISR W1C')
            self.assertLess(irq_source['event_id'], irq_delivery['event_id'])
            self.assertLess(irq_delivery['event_id'], irq_accept['event_id'])
            self.assertLess(irq_accept['event_id'], intr_state_read['event_id'])
            self.assertLess(intr_state_read['event_id'], data_in_read['event_id'])
            self.assertLess(data_in_read['event_id'], w1c['event_id'])
            self.assertLess(w1c['event_id'], irq_low['event_id'])

            mmio_transactions = [event for event in events
                if event.get('kind') == 'mmio_delivery']
            keys = [tuple(event['source_transaction'][field] for field in
                           ('source_component', 'source_epoch', 'channel_id', 'source_sequence'))
                    for event in mmio_transactions]
            self.assertEqual(len(keys), len(set(keys)), 'MMIO transaction was repeated')
            self.assertEqual({'cpu'}, {key[0] for key in keys})
            self.assertEqual({0}, {key[1] for key in keys})

            manifest = json.loads((bundle / 'manifest.json').read_text())
            self.assertEqual('cv32e40p', manifest['sessions']['cpu']['identity']
                             ['runtime_artifact']['plan']['component_id'])
            self.assertEqual('opentitan_gpio_local', manifest['sessions']['gpio_a']['identity']
                             ['runtime_artifact']['plan']['component_id'])
            self.assertEqual('opentitan_gpio_local', manifest['sessions']['gpio_b']['identity']
                             ['runtime_artifact']['plan']['component_id'])

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            replay_runner = instances[1]
            replay_memory = replay_runner.sessions['cpu'].memory
            self.assertEqual(1, replay_memory.read(
                RESULT_BASE, 4, transaction_id='cv32-replay-intr-state').value)
            self.assertEqual(1, replay_memory.read(
                RESULT_BASE + 4, 4, transaction_id='cv32-replay-data-in').value & 1)
            self.assertNotEqual(cpu._execution,
                                replay_runner.sessions['cpu']._execution)


if __name__ == '__main__':
    unittest.main()
