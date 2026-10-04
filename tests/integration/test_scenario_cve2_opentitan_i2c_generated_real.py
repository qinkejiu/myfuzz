"""Generated CVE2 starts real OpenTitan I2C read; peer byte reaches CPU RAM."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanI2cSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
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


def _andi(rd, rs1, value):
    return (value & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _beq(rs1, rs2, offset):
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def _program():
    words = [
        _lui(1, 0x40000),
        _lui(2, 0x100), _addi(2, 2, 0x10), _sw(2, 1, 0x3c),
        _lui(2, 0x20), _addi(2, 2, 2), _sw(2, 1, 0x40),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x44),
        _lui(2, 0x40), _addi(2, 2, 4), _sw(2, 1, 0x48),
        _lui(2, 0x80), _addi(2, 2, 8), _sw(2, 1, 0x4c),
        _addi(2, 0, 0x202), _sw(2, 1, 0x04),
        _addi(2, 0, 1), _sw(2, 1, 0x10),
        _addi(2, 0, 0x1a1), _sw(2, 1, 0x1c),
        _addi(2, 0, 0x601), _sw(2, 1, 0x1c),
        _lw(3, 1, 0), _andi(3, 3, 0x200), _beq(3, 0, -8),
        _lw(4, 1, 0x18), _lui(5, 0x20), _sw(4, 5, 0),
        0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCve2OpenTitanI2cRealTests(unittest.TestCase):
    def test_real_serial_rx_irq_mmio_ram_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-ot-i2c-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            i2c_artifact = _artifact('configs/peripherals/opentitan_i2c_local/component_profile.json', 'i2c')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('i2c', 'peer_response', 8)),
                (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),
                 InputOwner('i2c', 'peer_response', 0, 8, 'source', 'external_i2c_peer')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                i2c = GeneratedOpentitanI2cSession(i2c_artifact, base_dir=ROOT,
                                                     cache_dir=work / 'cache')
                router = DataflowRouter((DeviceWindow('i2c', 0x40000000, 0x1000, i2c),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'i2c': i2c},
                    ownership=ownership, bindings=())
                instances.append(runner)
                return runner

            genome = ScenarioGenome(testcase_id='cve2-ot-i2c-serial-rx',
                direction='IP_TO_CPU', path_id='peer-real-i2c-rx-cpu-ram',
                schedule_order=('cpu', 'i2c'), max_steps=4000,
                actions=(Action('peer-byte', 'i2c', 'peer_response', 0x5a,
                                'IP_TO_CPU', Trigger('START')),),
                initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                                MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000,
                                      max_materialized_bytes_per_memory=0x20000))
            self.assertEqual('complete', trace.status, trace.events[-1:])
            self.assertEqual([('peer-byte', 0x5a, 'external_i2c_peer')], [
                (event['action_id'], event['value'], event['source_ref'])
                for event in trace.events
                if event.get('kind') == 'source_injection'
                and event.get('component') == 'i2c'])
            self.assertEqual([0x1a1, 0x601], [event['write_value']
                for event in trace.events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'i2c'
                and event.get('offset') == 0x1c and event.get('write')])
            self.assertEqual(0x5a, instances[0].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='verify-rx').value)
            self.assertTrue(any(event.get('kind') == 'mmio_delivery'
                                and event.get('device_id') == 'i2c'
                                and event.get('offset') == 0x18
                                and event.get('read_value', 0) & 0xff == 0x5a
                                for event in trace.events))
            self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                and event.get('component') == 'i2c'
                                and event.get('outputs', {}).get('irq_o', 0) & 0x200
                                for event in trace.events))
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)


if __name__ == '__main__':
    unittest.main()
