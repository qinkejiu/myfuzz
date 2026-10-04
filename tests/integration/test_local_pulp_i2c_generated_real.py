"""Pinned PULP APB3 I2C open-drain peer and CPU→I2C→RAM replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.i2c_session import GeneratedPulpI2cSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
BASE = 0x40000000
RESULT = 0x20000


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _lui(rd, upper):
    return upper << 12 | rd << 7 | 0x37


def _addi(rd, rs1, value):
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _andi(rd, rs1, value):
    return (value & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _beq(rs1, rs2, offset):
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def _program():
    words = [
        _lui(1, 0x40000), _addi(2, 0, 2), _sw(2, 1, 0),
        _addi(2, 0, 0xc0), _sw(2, 1, 4),
        _addi(2, 0, 0x85), _sw(2, 1, 16),
        _addi(2, 0, 0x90), _sw(2, 1, 20),
        _lw(3, 1, 12), _andi(3, 3, 1), _beq(3, 0, -8),
        _addi(2, 0, 1), _sw(2, 1, 20),
        _addi(2, 0, 0x68), _sw(2, 1, 20),
        _lw(3, 1, 12), _andi(3, 3, 1), _beq(3, 0, -8),
        _lw(4, 1, 8), _lui(5, 0x20), _sw(4, 5, 0), 0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedPulpI2cRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='myfuzz-pulp-i2c-')
        cls.artifact = _artifact('configs/peripherals/pulp_i2c/component_profile.json', 'i2c')
        cls.cache = Path(cls.temp.name) / 'cache'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_local_real_ack_data_irq_and_unsupported_modes(self):
        device = GeneratedPulpI2cSession(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        device.prepare_local()
        device.begin_case('local-i2c')
        self.addCleanup(device.end_case)
        device.configure_peer_response(0x5a)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            device.write_register(0, 1)
        device.write_register(0, 2)
        device.write_register(4, 0xc0)
        device.write_register(16, 0x85)
        device.write_register(20, 0x90)
        for _ in range(600):
            device.step_local({})
            if device.irq_edges:
                break
        else:
            self.fail('address command produced no native IRQ')
        self.assertEqual(0, device.read_register(12) & 0x80)  # Slave ACK.
        self.assertEqual(1, device.read_register(12) & 1)
        device.write_register(20, 1)
        for _ in range(8):
            if any(edge['level'] == 0 for edge in device.irq_edges):
                break
            device.step_local({})
        self.assertTrue(any(edge['level'] == 0 for edge in device.irq_edges))
        device.write_register(20, 0x68)
        for _ in range(600):
            device.step_local({})
            if sum(edge['level'] == 1 for edge in device.irq_edges) >= 2:
                break
        else:
            self.fail('read command produced no native IRQ')
        self.assertEqual(0x5a, device.read_register(8))
        self.assertEqual(0x80, device.read_register(12) & 0x80)  # Master NACK.
        samples = device.drain_tick_samples()
        self.assertTrue(any(row['post']['sda_padoen_o'] == 1
                            and row['post']['sda_pad_i'] == 0 for row in samples),
                        'peer never pulled released SDA low')
        self.assertTrue(all(row[phase]['scl_pad_o'] == row[phase]['sda_pad_o'] == 0
                            for row in samples for phase in ('pre', 'post')))
        with self.assertRaisesRegex(ValueError, 'full-word'):
            device.write_register(20, 0x68, be=1)
        with self.assertRaisesRegex(ValueError, 'owns both'):
            device.step_local({'sda_pad_i': 0})

    def test_cpu_mmio_serial_data_ram_and_budgeted_fresh_replay(self):
        cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
        runners = []

        def factory():
            memory = PersistentMemory(
                regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                initialization_seed=37, max_initialized_bytes=0x20000)
            i2c = GeneratedPulpI2cSession(self.artifact, base_dir=ROOT,
                cache_dir=self.cache)
            router = DataflowRouter((DeviceWindow('i2c', BASE, 0x1000, i2c),))
            cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                cache_dir=self.cache, memory=memory, router=router, defer_mmio=True)
            owner = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('i2c', 'peer_response', 8)),
                (InputOwner('cpu', 'irq', 0, 1, 'bound', 'i2c.interrupt_o'),
                 InputOwner('i2c', 'peer_response', 0, 8, 'source', 'external_i2c_peer')))
            runner = ScenarioRunner(sessions={'cpu': cpu, 'i2c': i2c},
                ownership=owner,
                bindings=(Binding('i2c', 'interrupt_o', 'cpu', 'irq', 1),))
            runners.append(runner)
            return runner

        for byte in (0x5a, 0xa6):
            with self.subTest(peer_response=byte):
                genome = ScenarioGenome(testcase_id=f'generated-cve2-i2c-read-{byte:02x}',
                    direction='IP_TO_CPU', path_id='peer-i2c-controller-irq-cpu-ram',
                    schedule_order=('cpu', 'i2c'), max_steps=1300,
                    actions=(Action(f'peer-{byte:02x}', 'i2c', 'peer_response', byte,
                                    'IP_TO_CPU', Trigger('START')),),
                    initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                                    MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))
                bundle = Path(self.temp.name) / f'formal-i2c-evidence-{byte:02x}'
                trace = save_evidence_bundle(genome, factory, bundle,
                    budget=ResourceBudget(max_wall_time_ms=180000,
                        max_materialized_bytes_per_memory=0x20000))
                self.assertEqual('complete', trace.status)
                self.assertEqual(byte, runners[-1].sessions['cpu'].memory.read(
                    RESULT, 4, transaction_id='acceptance-read').value)
                self.assertTrue(any(event.get('kind') == 'source_injection'
                                    and event.get('component') == 'i2c'
                                    and event.get('port') == 'peer_response'
                                    and event.get('source_ref') == 'external_i2c_peer'
                                    and event.get('value') == byte
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'mmio_delivery'
                                    and event.get('device_id') == 'i2c'
                                    and event.get('offset') == 8
                                    and event.get('read_value') == byte
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                    and event.get('component') == 'i2c'
                                    and event.get('outputs', {}).get('interrupt_o') == 1
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                    and event.get('source') == ('i2c', 'interrupt_o')
                                    and event.get('target') == ('cpu', 'irq')
                                    and event.get('value') == 1
                                    for event in trace.events))
                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
