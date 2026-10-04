"""CVE2 configures generated SPI Device; external upload reaches CPU RAM."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSpiDeviceSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
BASE = 0x40000000
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
        _addi(2, 0, 0x10), _sw(2, 1, 0x10),
        _lui(2, 0x81010), _addi(2, 2, 0x202), _sw(2, 1, 0xa8),
        _addi(2, 0, 1), _sw(2, 1, 0x04),
        _lw(3, 1, 0x00), _andi(3, 3, 1), _beq(3, 0, -8),
        _lw(4, 1, 0x44), _lw(6, 1, 0x48),
        _lui(9, 0x40002), _addi(9, 9, -512), _lw(8, 9, 0),
        _lui(5, 0x20), _sw(4, 5, 0), _sw(6, 5, 4), _sw(8, 5, 8),
        0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=12,
        reset_release_ticks=12, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class Cve2GeneratedOpentitanSpiDeviceRealTests(unittest.TestCase):
    def test_cpu_config_external_upload_real_fifo_ram_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-ot-spi-device-chain-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            device_artifact = _artifact(
                'configs/peripherals/opentitan_spi_device_local/component_profile.json',
                'spi_device')
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('spi_device', 'master_frame', 32)),
                (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),
                 InputOwner('spi_device', 'master_frame', 0, 32, 'source',
                            'external_spi_master_frame')))
            runners = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                device = GeneratedOpentitanSpiDeviceSession(device_artifact,
                    base_dir=ROOT, cache_dir=work / 'cache', cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('spi_device', BASE, 0x2000, device),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'spi_device': device},
                    ownership=ownership, bindings=())
                runners.append(runner)
                return runner

            seed = ScenarioGenome(testcase_id='cve2-spi-device-upload',
                direction='CPU_TO_IP_TO_CPU', path_id='cpu-config-spi-upload-cpu-ram',
                schedule_order=('cpu', 'spi_device'), max_steps=1600,
                actions=(Action('external-upload', 'spi_device', 'master_frame',
                                0x0012345a, 'CPU_TO_IP_TO_CPU',
                                Trigger('AFTER_OUTPUT', 'cpu', 'data_addr',
                                        0xffffffff, BASE + 0x04),
                                delay_component='cpu', delay_ticks=30),),
                initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                                MemoryImage('cpu.result', 'cpu', RESULT,
                                            '000000000000000000000000')))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_spi_master_frame', 'spi_device',
                    'master_frame', 0, 32, ('CPU_TO_IP_TO_CPU',)),),
                rules=(DependencyRule('spi_device.upload_fifo',
                    ('external_spi_master_frame',), 'DATA_BINDING'),
                    DependencyRule('cpu.result_ram', ('spi_device.upload_fifo',),
                                   'PERSISTENT_STATE_RULE')))
            plan = choose_mutation(graph, {'cpu.result_ram': 1},
                                   direction='CPU_TO_IP_TO_CPU')
            changed = mutate_genome(seed, plan, graph, ownership, bit_index=0)
            self.assertEqual(0x0012345b, changed.actions[0].value)
            hashes = []
            for genome in (seed, changed):
                frame = genome.actions[0].value
                bundle = work / f'evidence-{frame:08x}'
                trace = save_evidence_bundle(genome, factory, bundle,
                    budget=ResourceBudget(max_wall_time_ms=180000,
                        max_materialized_bytes_per_memory=0x20000))
                self.assertEqual('complete', trace.status, trace.events[-5:])
                deliveries = [event for event in trace.events
                              if event.get('kind') == 'mmio_delivery'
                              and event.get('device_id') == 'spi_device']
                self.assertEqual([(0x10, 0x10), (0xa8, 0x81010202), (0x04, 1)],
                    [(event['offset'], event['write_value']) for event in deliveries
                     if event['write']])
                source_events = [event for event in trace.events
                                 if event.get('kind') == 'source_injection'
                                 and event.get('component') == 'spi_device']
                self.assertEqual([frame], [event['value'] for event in source_events])
                self.assertLess(deliveries[2]['event_id'], source_events[0]['event_id'])
                reads = {event['offset']: event['read_value'] for event in deliveries
                         if not event['write'] and event['offset'] in (0x44, 0x48, 0x1e00)}
                self.assertEqual(2, reads[0x44] & 255)
                self.assertEqual((frame >> 8) & 0xffffff, reads[0x48] & 0xffffff)
                self.assertEqual(frame & 255, reads[0x1e00] & 255)
                memory = runners[-1].sessions['cpu'].memory
                self.assertEqual([reads[offset] for offset in (0x44, 0x48, 0x1e00)],
                    [memory.read(RESULT + offset, 4,
                        transaction_id=f'accept-{frame:08x}-{offset}').value
                     for offset in (0, 4, 8)])
                self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                    and event.get('component') == 'spi_device'
                                    and event.get('outputs', {}).get('irq_o', 0) & 1
                                    for event in trace.events))
                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                hashes.append(trace.semantic_sha256)
            self.assertNotEqual(hashes[0], hashes[1])


if __name__ == '__main__':
    unittest.main()
