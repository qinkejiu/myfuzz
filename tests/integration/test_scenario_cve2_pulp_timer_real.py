"""Generated CVE2 programs PULP timer, reads RTL count, and stores it in RAM."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.timer_session import GeneratedPulpTimerSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
TIMER_BASE = 0x40000000
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
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def _program():
    words = [
        _lui(1, 0x40000), _addi(2, 0, 5), _sw(2, 1, 8),
        _addi(2, 0, 1), _sw(2, 1, 4),
        _lw(3, 1, 0), _beq(3, 0, -4),
        _lui(4, 0x20), _sw(3, 4, 0), 0x0000006f,
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
class GeneratedCve2PulpTimerRealTests(unittest.TestCase):
    def test_cpu_programs_timer_and_stores_live_count_with_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-timer-chain-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            timer_artifact = _artifact('configs/peripherals/pulp_timer/component_profile.json', 'timer')
            runners = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                timer = GeneratedPulpTimerSession(timer_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache')
                router = DataflowRouter((DeviceWindow('timer', TIMER_BASE, 0x1000, timer),))
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

            genome = ScenarioGenome(testcase_id='generated-cve2-timer-count',
                direction='CPU_TO_IP_TO_CPU', path_id='cpu-timer-counter-ram',
                schedule_order=('cpu', 'timer'), max_steps=400, actions=(),
                initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                                MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000,
                    max_materialized_bytes_per_memory=0x20000))
            self.assertEqual('complete', trace.status)
            deliveries = [event for event in trace.events
                          if event.get('kind') == 'mmio_delivery'
                          and event.get('device_id') == 'timer']
            self.assertEqual([(8, 5), (4, 1)],
                [(event['offset'], event['write_value']) for event in deliveries
                 if event['write']])
            count_reads = [event['read_value'] for event in deliveries
                           if not event['write'] and event['offset'] == 0]
            self.assertTrue(any(0 < value <= 5 for value in count_reads))
            stored = runners[0].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='acceptance-read').value
            self.assertIn(stored, count_reads)
            self.assertGreater(stored, 0)
            self.assertTrue(any(event.get('kind') == 'memory_write'
                                and event.get('address') == RESULT
                                and event.get('value') == stored for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                and event.get('component') == 'timer'
                                and event.get('outputs', {}).get('irq_o', 0) & 2
                                for event in trace.events))
            self.assertFalse(any(event.get('kind') == 'pulse_start'
                                 for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
