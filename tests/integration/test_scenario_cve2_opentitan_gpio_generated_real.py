"""Generated CVE2 and OpenTitan GPIO exchange real MMIO and external pin data."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
GPIO_BASE = 0x40000000
RESULT = 0x20000


def _lui(rd, upper):
    return upper << 12 | rd << 7 | 0x37


def _addi(rd, rs1, value):
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2, rs1, offset):
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _beq(rs1, rs2, offset):
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _program():
    words = [
        _lui(1, 0x40000), _addi(2, 0, 1),
        _sw(2, 1, 0x04), _sw(2, 1, 0x2c),
        _addi(2, 0, 0xa5), _sw(2, 1, 0x14),
        _addi(2, 0, 0xff), _sw(2, 1, 0x20),
        _lw(3, 1, 0x14), _lui(4, 0x20), _sw(3, 4, 0),
        _lw(3, 1, 0), _beq(3, 0, -4), _sw(3, 4, 4),
        0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCve2OpentitanGpioRealTests(unittest.TestCase):
    def test_cpu_mmio_and_external_pin_reach_cpu_ram_with_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-ot-gpio-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
            gpio_artifact = _artifact('configs/peripherals/opentitan_gpio_local/component_profile.json', 'gpio_ot')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('gpio', 'gpio_in', 32),
                 InputField('gpio', 'strap_en', 1)),
                (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),
                 InputOwner('gpio', 'gpio_in', 0, 32, 'source', 'external_pin'),
                 InputOwner('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                gpio = GeneratedOpentitanGpioSession(gpio_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache')
                router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                    ownership=ownership, bindings=())
                instances.append(runner)
                return runner

            case = ScenarioGenome(testcase_id='generated-cve2-ot-gpio',
                direction='CPU_TO_IP_TO_CPU', path_id='cpu-gpio-pin-cpu',
                schedule_order=('cpu', 'gpio'), max_steps=800,
                actions=(Action('external-edge', 'gpio', 'gpio_in', 1,
                    'CPU_TO_IP_TO_CPU', Trigger('AFTER_OUTPUT', 'gpio', 'gpio_out', 0xff, 0xa5)),),
                initial_images=(MemoryImage('boot', 'cpu', 0x10000, _program()),
                                MemoryImage('result', 'cpu', RESULT, '0000000000000000')))
            budget = ResourceBudget(max_wall_time_ms=180000,
                                    max_materialized_bytes_per_memory=0x20000)
            bundle = work / 'evidence'
            trace = save_evidence_bundle(case, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status, trace.events[-1:])
            memory = instances[0].sessions['cpu'].memory
            self.assertEqual(0xa5, memory.read(RESULT, 4, transaction_id='out').value)
            self.assertEqual(1, memory.read(RESULT + 4, 4, transaction_id='irq').value & 1)
            self.assertTrue(any(e.get('kind') == 'mmio_delivery' and
                e.get('device_id') == 'gpio' and not e.get('write') and
                e.get('offset') == 0 and e.get('read_value', 0) & 1
                for e in trace.events))
            self.assertTrue(any(e.get('kind') == 'source_injection' and
                e.get('component') == 'gpio' for e in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
