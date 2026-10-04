"""RV32E parameter variant closes a real CPU→GPIO A→GPIO B→CPU IRQ path."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.checker import check_pulp_gpio_irq_chain
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner
from tests.local_harness.test_renderer import ROOT
from tests.integration.test_scenario_ibex_two_pulp_gpio_generated_real import (
    _artifact, _lui, _addi, _sw, _lw, _csrrs, _image)


def rv32e_genome(output_value: int = 0x49) -> ScenarioGenome:
    if type(output_value) is not int or not 1 <= output_value <= 0xff or not output_value & 1:
        raise ValueError('GPIO output must be an odd byte to create the IRQ edge')
    main = (
        _lui(1, 0x40000), _lui(3, 0x40001), _addi(2, 0, 0xff),
        _sw(2, 1, 4), _addi(2, 0, 1), _sw(2, 1, 0x18), _sw(2, 1, 0x1c),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _addi(2, 0, 0xff), _sw(2, 3, 0),
        _addi(2, 0, output_value), _sw(2, 3, 0x0c), 0x0000006f,
    )
    isr = (
        _lw(4, 1, 8), _lui(5, 0x20), _sw(4, 5, 0),
        _lw(6, 1, 0x24), _sw(6, 5, 4), 0x30200073,
    )
    return ScenarioGenome(
        testcase_id=f'cve2-rv32e-two-pulp-gpio-irq-{output_value:02x}',
        direction='CPU_TO_IP_TO_CPU', path_id='rv32e-mmio-a-pin-b-irq-isr',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'), max_steps=330, actions=(),
        initial_images=(MemoryImage('boot', 'cpu', 0x10000, _image(main)),
                        MemoryImage('isr', 'cpu', 0x1012c, _image(isr)),
                        MemoryImage('result', 'cpu', 0x20000, '00' * 8)))


def make_rv32e_factory(cache_dir: Path):
    cpu_artifact = _artifact('configs/cpus/cv32e20_rv32e/component_profile.json', 'cpu')
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
        ownership = compile_ownership(
            (InputField('cpu', 'irq', 1), InputField('gpio_a', 'gpio_in', 32),
             InputField('gpio_b', 'gpio_in', 32)),
            (InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio_b.irq'),
             InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
             InputOwner('gpio_b', 'gpio_in', 0, 8, 'bound', 'gpio_a.gpio_out'),
             InputOwner('gpio_b', 'gpio_in', 8, 24, 'fixed', 'constant_zero')))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio_a': a, 'gpio_b': b},
                                ownership=ownership,
                                bindings=(Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 8), irq),
                                irq_pulses={irq: 4})
        instances.append(runner)
        return runner

    return factory, instances


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedRv32eTwoPulpGpioRealTests(unittest.TestCase):
    def test_rv32e_program_reaches_real_irq_isr_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-rv32e-two-gpio-') as directory:
            factory, instances = make_rv32e_factory(Path(directory) / 'cache')
            for value in (0x49, 0xff):
                with self.subTest(value=value):
                    case = rv32e_genome(value)
                    trace = record_scenario(case, factory)
                    self.assertEqual('complete', trace.status)
                    report = check_pulp_gpio_irq_chain(trace.events, expected_value=value)
                    self.assertTrue(report['complete'], report)
                    self.assertEqual(value, instances[-1].sessions['cpu'].memory.read(
                        0x20000, 4, transaction_id=f'check-{value}').value)
                    self.assertTrue(replay_scenario(case, factory, trace).matches)


if __name__ == '__main__':
    unittest.main()
