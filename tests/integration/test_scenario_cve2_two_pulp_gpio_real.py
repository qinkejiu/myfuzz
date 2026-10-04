"""Initial generated CPU -> GPIO A -> GPIO B -> CPU persistent path."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.local_harness.test_renderer import ROOT, real_plan


def _lui(rd, upper):
    return upper << 12 | rd << 7 | 0x37


def _addi(rd, rs1, immediate):
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _andi(rd, rs1, immediate):
    return (immediate & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _beq(rs1, rs2, offset):
    if offset % 2 or not -4096 <= offset <= 4094:
        raise ValueError('branch offset out of range')
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def initial_program():
    # B.GPIOEN; A.PADDIR/PADOUT; poll real B.PADIN; store observed bit to RAM.
    words = [
        _lui(1, 0x40001), _lui(3, 0x40000), _addi(2, 0, 1),
        _sw(2, 3, 4), _sw(2, 1, 0), _sw(2, 1, 12),
        _lw(4, 3, 8), _andi(4, 4, 1), _beq(4, 0, -8),
        _lui(5, 0x20), _sw(4, 5, 0), 0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(path, instance):
    plan = real_plan(path, instance)
    structure = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    top = render_local_runtime(plan, structure, verified, base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def make_factory(cache_dir):
    cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
    gpio_a_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
    gpio_b_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_b')
    instances = []

    def factory():
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=37, max_initialized_bytes=0x20000)
        gpio_a = GeneratedPulpGpioSession(gpio_a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        gpio_b = GeneratedPulpGpioSession(gpio_b_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((
            DeviceWindow('gpio_a', 0x40001000, 0x1000, gpio_a),
            DeviceWindow('gpio_b', 0x40000000, 0x1000, gpio_b),
        ))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT, cache_dir=cache_dir,
                                   memory=memory, router=router, defer_mmio=True)
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('gpio_a', 'gpio_in', 32),
             InputField('gpio_b', 'gpio_in', 32)),
            (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),
             InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
             InputOwner('gpio_b', 'gpio_in', 0, 1, 'bound', 'gpio_a.gpio_out'),
             InputOwner('gpio_b', 'gpio_in', 1, 31, 'fixed', 'constant_zero')))
        runner = ScenarioRunner(
            sessions={'cpu': cpu, 'gpio_a': gpio_a, 'gpio_b': gpio_b},
            ownership=ownership,
            bindings=(Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 1),))
        instances.append(runner)
        return runner

    return factory, instances


def genome():
    return ScenarioGenome(
        testcase_id='generated-cve2-two-pulp-gpio-forward',
        direction='CPU_TO_IP_TO_CPU', path_id='program-a-out-b-in-cpu-read',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'), max_steps=1200, actions=(),
        initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, initial_program()),
                        MemoryImage('cpu.result', 'cpu', 0x20000, '00000000')))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCve2TwoPulpGpioRealTests(unittest.TestCase):
    def test_program_propagates_through_two_real_gpio_instances_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-generated-chain-') as directory:
            factory, instances = make_factory(Path(directory) / 'cache')
            trace = record_scenario(genome(), factory)
            self.assertEqual('complete', trace.status)
            runner = instances[0]
            events = trace.events
            self.assertTrue(any(event.get('kind') == 'mmio_delivery'
                                and event.get('device_id') == 'gpio_a'
                                and event.get('write') and event.get('offset') == 0x0c
                                for event in events))
            self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                and event.get('source') == ('gpio_a', 'gpio_out')
                                and event.get('target') == ('gpio_b', 'gpio_in')
                                and event.get('value') == 1 for event in events))
            self.assertTrue(any(event.get('kind') == 'mmio_delivery'
                                and event.get('device_id') == 'gpio_b'
                                and not event.get('write')
                                and event.get('offset') == 8
                                and event.get('read_value', 0) & 1 for event in events))
            self.assertEqual(1, runner.sessions['cpu'].memory.read(
                0x20000, 4, transaction_id='acceptance-read').value)
            self.assertGreater(runner.local_ticks['cpu'], 1)
            self.assertGreater(runner.local_ticks['gpio_a'], 1)
            self.assertGreater(runner.local_ticks['gpio_b'], 1)
            replay = replay_scenario(genome(), factory, trace)
            self.assertTrue(replay.matches)


if __name__ == '__main__':
    unittest.main()
