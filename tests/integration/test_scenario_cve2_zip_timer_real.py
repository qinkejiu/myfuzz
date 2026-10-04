"""Generated CVE2 MMIO reaches generated ZipCPU Wishbone timer RTL."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.zip_timer_session import GeneratedZipTimerSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
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


def _program():
    words = [_lui(1, 0x40000), _addi(2, 0, 20), _sw(2, 1, 0),
             _lw(3, 1, 0), _lui(4, 0x20), _sw(3, 4, 0), 0x0000006f]
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
class GeneratedCve2ZipTimerRealTests(unittest.TestCase):
    def test_cpu_write_read_timer_and_store_ram_with_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-zip-timer-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            timer_artifact = _artifact('configs/peripherals/zipcpu_timer/component_profile.json', 'timer')
            runners = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                timer = GeneratedZipTimerSession(timer_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache')
                router = DataflowRouter((DeviceWindow('timer', 0x40000000, 4, timer),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                ownership = compile_ownership(
                    (InputField('cpu', 'irq', 1),),
                    (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),))
                runner = ScenarioRunner(sessions={'cpu': cpu, 'timer': timer},
                    ownership=ownership, bindings=())
                runners.append(runner)
                return runner

            genome = ScenarioGenome(testcase_id='generated-cve2-zip-timer',
                direction='CPU_TO_IP_TO_CPU', path_id='cpu-wishbone-timer-ram',
                schedule_order=('cpu', 'timer'), max_steps=160, actions=(),
                initial_images=(MemoryImage('boot', 'cpu', 0x10000, _program()),
                                MemoryImage('result', 'cpu', RESULT, '00000000')))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000,
                    max_materialized_bytes_per_memory=0x20000))
            self.assertEqual('complete', trace.status, trace.events[-1:])
            deliveries = [event for event in trace.events
                          if event.get('kind') == 'mmio_delivery'
                          and event.get('device_id') == 'timer']
            self.assertEqual([(0, 20)], [(event['offset'], event['write_value'])
                                           for event in deliveries if event['write']])
            self.assertFalse(any(event.get('kind') == 'local_register_transaction'
                                 for event in trace.events))
            reads = [event['read_value'] for event in deliveries if not event['write']]
            self.assertTrue(reads)
            self.assertGreater(reads[0], 0)
            stored = runners[0].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='acceptance-read').value
            self.assertEqual(reads[0], stored)
            self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                and event.get('component') == 'timer'
                and event.get('outputs', {}).get('interrupt') == 1
                for event in trace.events))
            self.assertFalse(any(event.get('kind') == 'pulse_start'
                                 for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
