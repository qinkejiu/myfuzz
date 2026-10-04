"""Generated CVE2 starts a real PULP SPI read and stores its RXFIFO word."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.spi_session import GeneratedPulpSpiSession
from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
SPI_BASE = 0x40000000
RESULT = 0x20000
EXPECTED = 0xa5c396f0


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, value: int) -> int:
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _srli(rd: int, rs1: int, count: int) -> int:
    return count << 20 | rs1 << 15 | 5 << 12 | rd << 7 | 0x13


def _andi(rd: int, rs1: int, value: int) -> int:
    return (value & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _beq(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | ((value >> 1) & 0xf) << 8 |
            ((value >> 11) & 1) << 7 | 0x63)


def _program() -> str:
    # CPU writes CLKDIV=1, SPILEN=32 bits, STATUS=CS0+read. STATUS[19:16]
    # is the RTL RX FIFO fill count. Poll it, pop RXFIFO and store to RAM.
    words = [
        _lui(1, 0x40000), _addi(2, 0, 1), _sw(2, 1, 4),
        _lui(2, 0x00200), _sw(2, 1, 0x10),
        _addi(2, 0, 0x101), _sw(2, 1, 0),
        _lw(3, 1, 0), _srli(3, 3, 16), _andi(3, 3, 15), _beq(3, 0, -12),
        _lw(4, 1, 0x20), _lui(5, 0x20), _sw(4, 5, 0), 0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _genome() -> ScenarioGenome:
    return ScenarioGenome(testcase_id='generated-cve2-pulp-spi-rx',
        direction='CPU_TO_IP_TO_CPU', path_id='cpu-spi-rxfifo-ram',
        schedule_order=('cpu', 'spi'), max_steps=1200, actions=(),
        initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                        MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCve2PulpSpiRealTests(unittest.TestCase):
    def test_cpu_spi_cpu_ram_budgeted_bundle_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-spi-chain-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
            spi_artifact = _artifact('configs/peripherals/pulp_spi/local_component_profile.json', 'spi_a')
            instances = []
            source_word = {'value': EXPECTED}

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                spi = GeneratedPulpSpiSession(spi_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache',
                    source=source_word['value'].to_bytes(4, 'big'))
                router = DataflowRouter((DeviceWindow('spi', SPI_BASE, 0x1000, spi),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                ownership = compile_ownership(
                    (InputField('cpu', 'irq', 1),),
                    (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),))
                runner = ScenarioRunner(sessions={'cpu': cpu, 'spi': spi},
                    ownership=ownership, bindings=())
                instances.append(runner)
                return runner

            budget = ResourceBudget(max_wall_time_ms=180000,
                max_materialized_bytes_per_memory=0x20000)
            case = _genome()
            bundle = work / 'evidence'
            trace = save_evidence_bundle(case, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status)
            runner = instances[0]
            cpu = runner.sessions['cpu']
            spi = runner.sessions['spi']
            writes = [e for e in trace.events if e.get('kind') == 'mmio_delivery'
                      and e.get('device_id') == 'spi' and e.get('write')]
            self.assertEqual([(4, 1), (0x10, 0x00200000), (0, 0x101)],
                [(e['offset'], e['write_value']) for e in writes])
            reads = [e for e in trace.events if e.get('kind') == 'mmio_delivery'
                     and e.get('device_id') == 'spi' and not e.get('write')]
            self.assertTrue(any(e['offset'] == 0x20 and e['read_value'] == EXPECTED
                                for e in reads))
            self.assertEqual(32, spi.peer.sample_count)
            self.assertEqual(4, spi.peer.payload_index)
            self.assertTrue(any(e['bit'] == 1 and e['level'] == 1
                                for e in spi.peer.events))
            self.assertTrue(any(e.get('kind') == 'local_tick_sample'
                                and e.get('component') == 'spi'
                                and e.get('outputs', {}).get('events_o', 0) & 2
                                for e in trace.events))
            self.assertEqual(EXPECTED, cpu.memory.read(RESULT, 4,
                transaction_id='acceptance-read').value)
            self.assertTrue(any(e.get('kind') == 'memory_write'
                                and e.get('address') == RESULT
                                and e.get('value') == EXPECTED for e in trace.events))
            self.assertGreater(runner.local_ticks['cpu'], 1)
            self.assertGreater(runner.local_ticks['spi'], 32)
            self.assertFalse(any(e.get('kind') == 'pulse_start' for e in trace.events))

            saved = json.loads((bundle / 'manifest.json').read_text())
            timings = {}
            for component, record in saved['sessions'].items():
                doc = record['identity']['runtime_artifact']
                timings[component] = dict(schema_version='generated_local_reset.v1',
                    artifact_digest=doc['artifact_digest'],
                    driver_sha256=doc['cpp_sha256'],
                    hold_cycles=doc['driver_reset']['reset_assert_ticks'],
                    release_cycles=doc['driver_reset']['reset_release_ticks'])
            manifest = ScenarioManifest.from_runner_identity(saved,
                scenario_id=case.testcase_id, schedule_order=case.schedule_order,
                scheduler_policy_id='stable-local-v1', budget=budget,
                reset_timings=timings)
            self.assertEqual('scenario_manifest_identity.v2',
                manifest.to_document()['runner_identity']['schema_version'])
            self.assertEqual(EXPECTED.to_bytes(4, 'big').hex(),
                saved['sessions']['spi']['identity']['source_hex'])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay.difference_context)
            self.assertEqual(EXPECTED, instances[1].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='replay-read').value)
            source_word['value'] ^= 1
            changed = save_evidence_bundle(case, factory, work / 'mutated',
                budget=budget)
            self.assertEqual('complete', changed.status)
            self.assertNotEqual(trace.semantic_sha256, changed.semantic_sha256)
            self.assertEqual(EXPECTED ^ 1, instances[2].sessions['cpu'].memory.read(
                RESULT, 4, transaction_id='mutated-read').value)
