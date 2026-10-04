"""PicoRV32 Wishbone drives two independent PULP GPIO RTL harnesses."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.local_harness.test_renderer import ROOT
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import (
    _artifact, _lui, _addi, _sw, _lw, _image)


def pico_genome(output_value: int = 0x49) -> ScenarioGenome:
    if type(output_value) is not int or not 0 <= output_value <= 0xff:
        raise ValueError('GPIO output must be a byte')
    program = (
        _lui(1, 0x40001), _lui(3, 0x40000), _addi(2, 0, 0xff),
        _sw(2, 1, 0), _sw(2, 3, 4),
        _addi(2, 0, output_value), _sw(2, 1, 0x0c),
        _lw(4, 3, 8), _lui(5, 0x20), _sw(4, 5, 0),
        _lw(6, 1, 0x0c), _sw(6, 5, 4), 0x0000006f,
    )
    return ScenarioGenome(
        testcase_id=f'pico-wb-two-pulp-gpio-{output_value:02x}',
        direction='CPU_TO_IP_TO_CPU', path_id='pico-wb-a-out-b-in-cpu-read',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'), max_steps=390, actions=(),
        initial_images=(MemoryImage('program', 'cpu', 0, _image(program)),
                        MemoryImage('result', 'cpu', 0x20000, '00' * 8)))


def make_pico_factory(cache_dir: Path):
    cpu_artifact = _artifact('configs/cpus/picorv32_wb/component_profile.json', 'cpu')
    a_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
    b_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_b')
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                                  initialization_seed=37, max_initialized_bytes=0x30000)
        a = GeneratedPulpGpioSession(a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        b = GeneratedPulpGpioSession(b_artifact, base_dir=ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio_a', 0x40001000, 0x1000, a),
                                 DeviceWindow('gpio_b', 0x40000000, 0x1000, b)))
        cpu = GeneratedWishboneCpuSession(cpu_artifact, base_dir=ROOT, cache_dir=cache_dir,
                                          memory=memory, router=router, defer_mmio=True)
        ownership = compile_ownership(
            (InputField('gpio_a', 'gpio_in', 32), InputField('gpio_b', 'gpio_in', 32)),
            (InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
             InputOwner('gpio_b', 'gpio_in', 0, 8, 'bound', 'gpio_a.gpio_out'),
             InputOwner('gpio_b', 'gpio_in', 8, 24, 'fixed', 'constant_zero')))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio_a': a, 'gpio_b': b},
                                ownership=ownership,
                                bindings=(Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 8),))
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class PicoWishboneOwnershipTests(unittest.TestCase):
    def test_bound_gpio_input_cannot_be_mutated(self):
        factory, instances = make_pico_factory(Path('/tmp/myfuzz-pico-ownership-unused'))
        runner = factory()
        self.assertEqual('wishbone_cpu', runner.sessions['cpu'].artifact.runtime_document['kind'])
        with self.assertRaisesRegex(ValueError, 'bound'):
            runner.ownership.mutation_source(
                'gpio_b', 'gpio_in', 0, 8, direction='CPU_TO_IP_TO_CPU')


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedPicoWishboneTwoPulpGpioRealTests(unittest.TestCase):
    def test_real_wishbone_mmio_dataflow_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-pico-wb-two-gpio-') as directory:
            factory, instances = make_pico_factory(Path(directory) / 'cache')
            for value in (0x49, 0xff):
                with self.subTest(value=value):
                    case = pico_genome(value)
                    trace = record_scenario(case, factory)
                    self.assertEqual('complete', trace.status)
                    events = trace.events
                    write = next(event for event in events
                                 if event.get('kind') == 'mmio_delivery'
                                 and event.get('device_id') == 'gpio_a'
                                 and event.get('write') is True
                                 and event.get('offset') == 0x0c)
                    self.assertEqual(value, write['write_value'])
                    self.assertTrue(any(event.get('component') == 'gpio_a'
                                        and event.get('outputs', {}).get('gpio_out') == value
                                        and event['event_id'] > write['event_id']
                                        for event in events))
                    self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                        and event.get('source') == ('gpio_a', 'gpio_out')
                                        and event.get('target') == ('gpio_b', 'gpio_in')
                                        and event.get('value') == value
                                        and event['event_id'] > write['event_id']
                                        for event in events))
                    self.assertTrue(any(event.get('component') == 'gpio_b'
                                        and event.get('inputs', {}).get('gpio_in') == value
                                        and event['event_id'] > write['event_id']
                                        for event in events))
                    read = next(event for event in events
                                if event.get('kind') == 'mmio_delivery'
                                and event.get('device_id') == 'gpio_b'
                                and event.get('offset') == 8
                                and event.get('write') is False)
                    self.assertEqual(value, read['read_value'])
                    self.assertTrue(any(event.get('component') == 'cpu'
                                        and event.get('outputs', {}).get('data_rsp_consumed') == 1
                                        and event.get('outputs', {}).get('data_rsp_rdata') == value
                                        and event['event_id'] > read['event_id']
                                        for event in events))
                    memory = instances[-1].sessions['cpu'].memory
                    self.assertEqual(value, memory.read(
                        0x20000, 4, transaction_id=f'padin-{value}').value)
                    self.assertEqual(value, memory.read(
                        0x20004, 4, transaction_id=f'padout-{value}').value)
                    self.assertTrue(replay_scenario(case, factory, trace).matches)


if __name__ == '__main__':
    unittest.main()
