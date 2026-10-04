"""Real Ibex receives OpenTitan sysrst_ctrl key0 IRQ and services its CSRs."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSysrstCtrlSession,
    compile_generated_register_ownership, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
KEY0 = 'opentitan_sysrst_ctrl.pins.key0'
SYSRST_BASE = 0x40000000
RESULT = 0x20000


def _artifact(profile: str, instance: str, *, reset_assert_ticks: int,
              reset_release_ticks: int):
    schema_version = ('local_harness.v2' if 'sysrst_ctrl_local' in profile
                      else 'local_harness.v1')
    document = dict(schema_version=schema_version,
        profile_path=profile, instance_id=instance,
        reset_assert_ticks=reset_assert_ticks,
        reset_release_ticks=reset_release_ticks, max_wait_cycles=16)
    if schema_version == 'local_harness.v2':
        fixed = [('ac_present', 0), ('ec_rst_l', 1), ('key1', 0), ('key2', 0),
                 ('pwrb', 0), ('lid_open', 0), ('flash_wp_l', 1)]
        document['tuning'] = {
            'endpoint_policies': [dict(endpoint_id='opentitan_sysrst_ctrl.mmio',
                template_id='target.tl-ul', template_version='1',
                variant_id='user-integrity', max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role=role, value=value) for role, value in fixed],
            'environment_bindings': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role='key0', source_id='sysrst_key0_environment')],
        }
    request = load_local_harness_request(document)
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


def _csrw(csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | 1 << 12 | 0x73


def _word_image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _main_program() -> tuple[int, ...]:
    # Install the trap handler at 0x1012c, enable machine external
    # interrupts, then wait for the real sysrst_ctrl level interrupt.
    return (_lui(5, 0x10), _addi(5, 5, 0x12c), _csrw(0x305, 5),
            _lui(5, 1), _addi(5, 5, -0x800), _csrw(0x304, 5),
            _addi(5, 0, 8), _csrw(0x300, 5), 0x0000006f)


def _isr_program() -> tuple[int, ...]:
    # Read status and pin value from real TL-UL RTL, save both in RAM, then
    # clear the source status followed by the aggregate interrupt state.
    return (_lui(5, 0x40000), _lw(6, 5, 0xa8), _lw(7, 5, 0x40),
            _lui(28, 0x20), _sw(6, 28, 0), _sw(7, 28, 4),
            _addi(29, 0, 2), _sw(29, 5, 0xa8),
            _addi(29, 0, 1), _sw(29, 5, 0x00), 0x30200073)


def _genome() -> ScenarioGenome:
    return ScenarioGenome(testcase_id='ibex-sysrst-key0-irq',
        direction='IP_TO_CPU', path_id='key0-pin-sysrst-irq-ibex-csr-ram',
        schedule_order=('sysrst', 'cpu'), max_steps=3200,
        actions=(
            Action('key0_start_high', 'sysrst', KEY0, 1, 'IP_TO_CPU',
                   Trigger('AFTER_OUTPUT', 'sysrst', 'intr_event_detected_o', 1, 0)),
            Action('key0_h2l', 'sysrst', KEY0, 0, 'IP_TO_CPU',
                   Trigger('AFTER_OUTPUT', 'sysrst', 'intr_event_detected_o', 1, 0),
                   delay_component='sysrst', delay_ticks=360),
        ),
        initial_images=(
            MemoryImage('cpu.boot', 'cpu', 0x10080, _word_image(_main_program())),
            MemoryImage('cpu.isr', 'cpu', 0x1012c, _word_image(_isr_program())),
            MemoryImage('cpu.result', 'cpu', RESULT, '0000000000000000'),
        ))


def _make_factory(cpu_artifact, sysrst_artifact, cache_dir: Path):
    register_ownership = compile_generated_register_ownership(
        {'sysrst': sysrst_artifact}).document()
    fields = tuple(InputField(row['component_id'], row['port'], row['width'])
                   for row in register_ownership['fields']) + (
        InputField('cpu', 'irq', 1),)
    owners = tuple(InputOwner(**row) for row in register_ownership['owners']) + (
        InputOwner('cpu', 'irq', 0, 1, 'bound', 'sysrst.intr_event_detected_o'),)
    ownership = compile_ownership(fields, owners)
    binding = Binding('sysrst', 'intr_event_detected_o', 'cpu', 'irq', 1)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=89, max_initialized_bytes=0x20000)
        sysrst = GeneratedOpentitanSysrstCtrlSession(sysrst_artifact,
            base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('sysrst', SYSRST_BASE, 0x100,
                                              sysrst),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'sysrst': sysrst},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned OpenTitan and Ibex RTL')
class GeneratedIbexOpentitanSysrstCtrlRealTests(unittest.TestCase):
    def test_key0_irq_reaches_ibex_real_csr_reads_ram_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-sysrst-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json',
                                     'cpu', reset_assert_ticks=8,
                                     reset_release_ticks=8)
            sysrst_artifact = _artifact(
                'configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json',
                'sysrst', reset_assert_ticks=120, reset_release_ticks=1)
            factory, instances = _make_factory(cpu_artifact, sysrst_artifact,
                                               work / 'cache')
            genome = _genome()
            trace = record_scenario(genome, factory)
            self.assertEqual('complete', trace.status, trace.events[-8:])
            events = trace.events

            low_injection = next(event for event in events
                if event.get('kind') == 'source_injection'
                and event.get('action_id') == 'key0_h2l')
            high_injection = next(event for event in events
                if event.get('kind') == 'source_injection'
                and event.get('action_id') == 'key0_start_high')
            initial_transactions = [event for event in events
                if event.get('kind') == 'local_register_transaction'
                and event.get('reason') is None and not event.get('write')]
            self.assertIn((0xa8, 0), {(event['offset'], event['read_value'])
                for event in initial_transactions})
            self.assertIn((0x00, 0), {(event['offset'], event['read_value'])
                for event in initial_transactions})
            self.assertTrue(initial_transactions)
            self.assertLess(max(event['event_id'] for event in initial_transactions),
                            high_injection['event_id'])
            high_pin = next(event for event in events
                if event.get('kind') == 'local_register_transaction'
                and event.get('reason') == 'key0_high_pin_readback')
            low_pin = next(event for event in events
                if event.get('kind') == 'local_register_transaction'
                and event.get('reason') == 'key0_low_pin_readback')
            self.assertEqual(0xc2, high_pin['read_value'])
            self.assertEqual(0xc0, low_pin['read_value'])
            irq_samples = [event for event in events
                if event.get('kind') == 'local_tick_sample'
                and event.get('component') == 'sysrst'
                and event.get('outputs', {}).get('intr_event_detected_o') == 1]
            self.assertTrue(irq_samples, 'sysrst native IRQ was not observed')
            self.assertLess(high_injection['event_id'], low_injection['event_id'])
            self.assertLess(high_pin['event_id'], low_injection['event_id'])
            self.assertLess(low_injection['event_id'], low_pin['event_id'])
            self.assertEqual(0, low_pin['read_value'] & 2)
            self.assertGreater(irq_samples[0]['event_id'], low_injection['event_id'])
            irq_before_pin_edge = [event for event in events
                if event.get('kind') == 'local_tick_sample'
                and event.get('component') == 'sysrst'
                and event['event_id'] < low_injection['event_id']]
            self.assertTrue(irq_before_pin_edge)
            self.assertTrue(all(event.get('outputs', {}).get('intr_event_detected_o') == 0
                                for event in irq_before_pin_edge))

            deliveries = [event for event in events
                          if event.get('kind') == 'mmio_delivery'
                          and event.get('device_id') == 'sysrst']
            self.assertTrue(any(not row['write'] and row['offset'] == 0xa8
                                and row['read_value'] == 2 for row in deliveries),
                            'Ibex did not read key0 H2L status from sysrst_ctrl RTL')
            self.assertTrue(any(not row['write'] and row['offset'] == 0x40
                                and row['read_value'] & 2 == 0 for row in deliveries),
                            'Ibex did not read the real key0 pin state')
            self.assertTrue(any(row['write'] and row['offset'] == 0xa8
                                and row['write_value'] == 2 for row in deliveries))
            self.assertTrue(any(row['write'] and row['offset'] == 0x00
                                and row['write_value'] == 1 for row in deliveries))

            cpu_irq_inputs = [event for event in events
                if event.get('component') == 'cpu' and event.get('kind') is None
                and event.get('inputs', {}).get('irq') == 1]
            self.assertTrue(cpu_irq_inputs, 'native sysrst IRQ never reached Ibex irq input')
            self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                and tuple(event.get('source', ())) == ('sysrst', 'intr_event_detected_o')
                and tuple(event.get('target', ())) == ('cpu', 'irq')
                and event.get('value') == 1 for event in events))
            writes = [event for event in events if event.get('kind') == 'memory_write'
                      and event.get('address') in (RESULT, RESULT + 4)]
            self.assertEqual({RESULT, RESULT + 4},
                             {event['address'] for event in writes})
            memory = instances[0].sessions['cpu'].memory
            self.assertEqual(2, memory.read(RESULT, 4,
                transaction_id='sysrst-status').value)
            self.assertEqual(0xc0, memory.read(RESULT + 4, 4,
                transaction_id='sysrst-pin').value)
            self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                 for event in events))

            replay = replay_scenario(genome, factory, trace)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['sysrst'],
                             instances[1].sessions['sysrst'])


if __name__ == '__main__':
    unittest.main()
