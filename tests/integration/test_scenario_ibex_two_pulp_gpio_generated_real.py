"""Generated Ibex OBI and two independent PULP GPIO RTL instances."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.checker import check_pulp_gpio_irq_chain
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


def _csrrs(csr, rs1):
    return csr << 20 | rs1 << 15 | 2 << 12 | 0x73


def _image(words):
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def genome(output_value: int = 1):
    if type(output_value) is not int or not 1 <= output_value <= 0xff or not output_value & 1:
        raise ValueError('GPIO output must be an odd byte to create the IRQ edge')
    # Ibex reset PC is 0x10080. The handler is the machine external vector.
    main = (
        _lui(1, 0x40000), _lui(3, 0x40001), _addi(2, 0, 1),
        _sw(2, 1, 4), _sw(2, 1, 0x18), _sw(2, 1, 0x1c),
        _lui(7, 0x10), _addi(7, 7, 0x12c), _csrrs(0x305, 7),
        _lui(7, 1), _addi(7, 7, -2048), _csrrs(0x304, 7),
        _addi(7, 0, 8), _csrrs(0x300, 7),
        _sw(2, 3, 0), _addi(2, 0, output_value), _sw(2, 3, 0x0c), 0x0000006f,
    )
    isr = (
        _lw(4, 1, 8), _lui(5, 0x20), _sw(4, 5, 0),
        _lw(6, 1, 0x24), _sw(6, 5, 4), 0x30200073,
    )
    return ScenarioGenome(
        testcase_id=f'ibex-generated-two-pulp-gpio-irq-{output_value:02x}',
        direction='CPU_TO_IP_TO_CPU', path_id='ibex-mmio-a-pin-b-irq-isr',
        schedule_order=('cpu', 'gpio_a', 'gpio_b'), max_steps=210, actions=(),
        initial_images=(MemoryImage('boot', 'cpu', 0x10080, _image(main)),
                        MemoryImage('isr', 'cpu', 0x1012c, _image(isr)),
                        MemoryImage('result', 'cpu', 0x20000, '00' * 8)))


def _artifact(path, instance):
    plan = real_plan(path, instance)
    structure = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, structure, verified,
                                                     base_dir=ROOT), base_dir=ROOT)


def make_factory(cache_dir):
    cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json', 'cpu')
    gpio_a_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
    gpio_b_artifact = _artifact('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_b')
    instances = []

    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                                  initialization_seed=37, max_initialized_bytes=0x20000)
        a = GeneratedPulpGpioSession(gpio_a_artifact, base_dir=ROOT, cache_dir=cache_dir)
        b = GeneratedPulpGpioSession(gpio_b_artifact, base_dir=ROOT, cache_dir=cache_dir)
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
class GeneratedIbexTwoPulpGpioRealTests(unittest.TestCase):
    def test_ibex_program_closes_real_gpio_irq_chain_and_replays(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-two-gpio-') as directory:
            factory, instances = make_factory(Path(os.environ.get(
                'MYFUZZ_IBEX_GPIO_CACHE', Path(directory) / 'cache')))
            case = genome()
            trace = record_scenario(case, factory)
            self.assertEqual('complete', trace.status)
            events = trace.events
            self.assertTrue(any(e.get('kind') == 'mmio_delivery' and
                                e.get('device_id') == 'gpio_a' and e.get('offset') == 0x0c
                                and e.get('write_value') == 1 for e in events))
            self.assertTrue(any(e.get('kind') == 'dataflow_delivery' and
                                e.get('source') == ('gpio_a', 'gpio_out') and
                                e.get('target') == ('gpio_b', 'gpio_in') and
                                e.get('value') == 1 for e in events))
            self.assertTrue(any(e.get('kind') == 'source_start' and
                                e.get('source') == ('gpio_b', 'irq') and
                                e.get('target') == ('cpu', 'irq') for e in events))
            self.assertTrue(any(e.get('kind') == 'pulse_start' and
                                e.get('source') == ('gpio_b', 'irq') and
                                e.get('target') == ('cpu', 'irq') for e in events))
            self.assertTrue(any(e.get('component') == 'cpu' and
                                e.get('inputs', {}).get('irq') == 1 for e in events))
            self.assertTrue(any(e.get('component') == 'cpu' and
                                e.get('outputs', {}).get('instr_req_accepted') == 1 and
                                e.get('outputs', {}).get('instr_addr') == 0x1012c
                                for e in events))
            self.assertEqual(1, instances[0].sessions['cpu'].memory.read(
                0x20000, 4, transaction_id='acceptance').value)
            self.assertEqual(1, instances[0].sessions['cpu'].memory.read(
                0x20004, 4, transaction_id='acceptance-status').value)
            self.assertFalse(any(e.get('kind') == 'reset_barrier' for e in events))
            report = check_pulp_gpio_irq_chain(events, expected_value=1)
            self.assertTrue(report['complete'], report)
            replay = replay_scenario(case, factory, trace)
            self.assertTrue(replay.matches, replay)


if __name__ == '__main__':
    unittest.main()
