"""Generated CVA6 packed AXI4 routes real MMIO to independent GPIO RTL."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'
GPIO_BASE = 0x40000000
RESULT = 0x20000


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=16,
        reset_release_ticks=20, max_wait_cycles=32))
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


def _program() -> bytes:
    # Keep the pinned four-instruction CVA6 boot prefix, then configure GPIO,
    # read DOUT back through real TL-UL, and store that result in persistent RAM.
    words = (
        _lui(1, 0x40000),
        _addi(2, 0, 0xa5), _sw(2, 1, 0x14),
        _addi(2, 0, 0xff), _sw(2, 1, 0x20),
        _lw(3, 1, 0x14),
        _lui(4, 0x20), _sw(3, 4, 0),
        0x0000006f,
    )
    return BOOT.read_bytes()[:16] + b''.join(
        word.to_bytes(4, 'little') for word in words)


def _make_factory(cpu_artifact, gpio_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1),
         InputField('gpio', 'gpio_in', 32), InputField('gpio', 'strap_en', 1)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('gpio', 'gpio_in', 0, 32, 'source', 'external_gpio_pins'),
         InputOwner('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero')))
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        gpio = GeneratedOpentitanGpioSession(gpio_artifact, base_dir=ROOT,
                                              cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
            ownership=ownership, bindings=())
        instances.append(runner)
        return runner

    return factory, instances


class GeneratedCva6OpentitanGpioRealTests(unittest.TestCase):
    def test_axi4_mmio_gpio_readback_and_ram_replay(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-generated-ot-gpio-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json', 'cpu')
            gpio_artifact = _artifact(
                'configs/peripherals/opentitan_gpio_local/component_profile.json',
                'gpio')
            factory, instances = _make_factory(cpu_artifact, gpio_artifact,
                                               work / 'cache')
            genome = ScenarioGenome(testcase_id='cva6-generated-opentitan-gpio',
                direction='CPU_TO_IP_TO_CPU', path_id='cva6-axi4-gpio-tlul-ram',
                schedule_order=('cpu', 'gpio'), max_steps=1800, actions=(),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, _program().hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, '0000000000000000'),
                ))
            budget = ResourceBudget(max_wall_time_ms=300000,
                                    max_materialized_bytes_per_memory=0x40000)
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status, trace.events[-8:])

            cpu, gpio = instances[0].sessions['cpu'], instances[0].sessions['gpio']
            deliveries = [event for event in trace.events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'gpio']
            writes = [event for event in deliveries if event.get('write')]
            reads = [event for event in deliveries if not event.get('write')]
            self.assertEqual([(0x14, 0xa5), (0x20, 0xff)],
                [(event['offset'], event['write_value']) for event in writes])
            self.assertEqual([(0x14, 0xa5 << 32)],
                [(event['offset'], event['read_value']) for event in reads])
            self.assertTrue(all(event['source_transaction']['source_component'] == 'cpu'
                                for event in deliveries))
            self.assertGreaterEqual(cpu.mmio_write_count, 2)
            self.assertGreaterEqual(cpu.mmio_read_count, 1)
            self.assertEqual(0xa5, cpu.memory.read(RESULT, 4,
                transaction_id='gpio-dout-result').value)
            self.assertTrue(any(event.get('component') == 'gpio'
                and event.get('outputs', {}).get('gpio_out') == 0xa5
                and event.get('outputs', {}).get('gpio_dir') == 0xff
                for event in trace.events))
            self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                 for event in trace.events))

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['gpio'], instances[1].sessions['gpio'])


if __name__ == '__main__':
    unittest.main()
