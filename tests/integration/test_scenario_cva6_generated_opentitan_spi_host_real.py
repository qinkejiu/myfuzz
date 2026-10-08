"""CVA6 routes AXI4 MMIO through real OpenTitan SPI Host RTL and back to RAM."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedOpentitanSpiHostSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
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
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'
SPI_BASE = 0x40000000
RESULT = 0x20000


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, value: int) -> int:
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _bne(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | 1 << 12 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _program() -> bytes:
    # CVA6 configures and starts SPI Host through real AXI MMIO. The local
    # scheduler then gives the serial peer enough of its own ticks to finish.
    words = (
        _lui(1, 0x40000),
        _lui(2, 0xa0000), _addi(2, 2, 1), _sw(2, 1, 0x10),
        _addi(2, 0, 8), _sw(2, 1, 0x18),
        _addi(2, 0, 0x68), _sw(2, 1, 0x20),
        _addi(3, 0, 64), _addi(3, 3, -1), _bne(3, 0, -4),
        _lw(4, 1, 0x24), _lui(5, 0x20), _sw(4, 5, 0),
        0x0000006f,
    )
    return BOOT.read_bytes()[:16] + b''.join(
        word.to_bytes(4, 'little') for word in words)


def _artifact(profile: str, instance: str, *, reset_ticks: tuple[int, int],
              max_wait_cycles: int):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance,
        reset_assert_ticks=reset_ticks[0], reset_release_ticks=reset_ticks[1],
        max_wait_cycles=max_wait_cycles))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class GeneratedCva6OpentitanSpiHostRealTests(unittest.TestCase):
    def test_axi4_spi_source_cpu_readback_and_fresh_replay(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-ot-spi-host-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cva6/component_profile.json',
                'cpu', reset_ticks=(16, 20), max_wait_cycles=32)
            spi_artifact = _artifact(
                'configs/peripherals/opentitan_spi_host_local/component_profile.json',
                'spi_host', reset_ticks=(8, 8), max_wait_cycles=16)
            ownership = compile_ownership(
                (InputField('cpu', 'irq_external', 1),
                 InputField('spi_host', 'spi_source_word', 32)),
                (InputOwner('cpu', 'irq_external', 0, 1, 'fixed', 'constant_zero'),
                 InputOwner('spi_host', 'spi_source_word', 0, 32, 'source',
                            'external_spi_source_word')))
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0, 0x40000),),
                    initialization_seed=0, max_initialized_bytes=0x40000)
                spi = GeneratedOpentitanSpiHostSession(spi_artifact,
                    base_dir=ROOT, cache_dir=work / 'cache', source=None,
                    cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('spi_host', SPI_BASE,
                    0x1000, spi),))
                cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True, command_timeout_seconds=60)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'spi_host': spi},
                    ownership=ownership, bindings=())
                instances.append(runner)
                return runner

            seed = ScenarioGenome(testcase_id='cva6-ot-spi-host-rx',
                direction='IP_TO_CPU', path_id='spi-source-rtl-cva6-axi4-ram',
                schedule_order=('spi_host', 'cpu'), max_steps=2500,
                actions=(Action('external-word', 'spi_host', 'spi_source_word',
                    0x12345678, 'IP_TO_CPU', Trigger('START')),),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, _program().hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, '00000000'),))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_spi_source_word', 'spi_host',
                    'spi_source_word', 0, 32, ('IP_TO_CPU',)),),
                rules=(DependencyRule('spi_host.rx_word',
                    ('external_spi_source_word',), 'DATA_BINDING'),
                    DependencyRule('cpu.result_ram', ('spi_host.rx_word',),
                    'PERSISTENT_STATE_RULE')))
            plan = choose_mutation(graph, {'cpu.result_ram': 1},
                                   direction='IP_TO_CPU')
            genome = mutate_genome(seed, plan, graph, ownership, bit_index=0)
            word = genome.actions[0].value
            expected = int.from_bytes(word.to_bytes(4, 'big'), 'little')
            bundle = work / 'evidence'
            trace = save_evidence_bundle(genome, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=300000,
                    max_materialized_bytes_per_memory=0x40000))
            self.assertEqual('complete', trace.status, trace.events[-8:])

            cpu, spi = instances[0].sessions['cpu'], instances[0].sessions['spi_host']
            deliveries = [event for event in trace.events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == 'spi_host']
            writes = [event for event in deliveries if event['write']]
            self.assertEqual([(0x10, 0xa0000001), (0x18, 8), (0x20, 0x68)],
                [(event['offset'], event['write_value']) for event in writes])
            rx_reads = [event for event in deliveries
                         if not event['write'] and event['offset'] == 0x24]
            self.assertTrue(any(event['address'] == SPI_BASE + 0x24
                and event['beat_bytes'] == 8
                and event['read_value'] == expected << 32 for event in rx_reads),
                {'deliveries': deliveries, 'peer_samples': spi.peer.sample_count,
                 'local_ticks': trace.local_ticks})
            self.assertEqual(32, spi.peer.sample_count)
            self.assertEqual(4, spi.peer.payload_index)
            self.assertEqual(expected, cpu.memory.read(RESULT, 4,
                transaction_id='spi-rx-result').value)
            self.assertEqual([word], [event['value'] for event in trace.events
                if event.get('kind') == 'source_injection'
                and event.get('component') == 'spi_host'])
            self.assertTrue(any(event.get('kind') == 'memory_write'
                and event.get('address') == RESULT
                and event.get('byte_enable') == 0x0f
                and event.get('value', 0) & 0xffffffff == expected
                for event in trace.events))

            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertIsNot(instances[0].sessions['cpu'], instances[1].sessions['cpu'])
            self.assertIsNot(instances[0].sessions['spi_host'],
                             instances[1].sessions['spi_host'])


if __name__ == '__main__':
    unittest.main()
