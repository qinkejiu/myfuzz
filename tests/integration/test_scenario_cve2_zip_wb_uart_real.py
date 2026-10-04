"""Generated CVE2 and ZipCPU Wishbone UART exchange real MMIO and serial data."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.wishbone_uart_session import GeneratedWishboneUartSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import Action, MemoryImage, ScenarioGenome, Trigger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.mutation import choose_mutation, mutate_genome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import Binding, ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
UART_BASE = 0x40000000
RESULT = 0x20000


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, value: int) -> int:
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _sb(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            (offset & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _bne(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return ((value >> 12) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | 1 << 12 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _andi(rd: int, rs1: int, value: int) -> int:
    return (value & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _program() -> str:
    # The loop lets one external 8N1 frame traverse real rxuart before MMIO RX.
    words = [
        _lui(1, 0x40000), _addi(2, 0, 25), _sw(2, 1, 0),
        _addi(2, 0, 0x41), _sb(2, 1, 12),
        _addi(3, 0, 250), _addi(3, 3, -1), _bne(3, 0, -4),
        _lw(4, 1, 8), _andi(4, 4, 255), _lui(5, 0x20),
        _sw(4, 5, 0), 0x0000006f,
    ]
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCve2ZipWishboneUartRealTests(unittest.TestCase):
    def test_cpu_tx_uart_rx_cpu_ram_and_mutated_source_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-wb-uart-chain-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            uart_artifact = _artifact('configs/peripherals/zipcpu_uart/component_profile.json', 'uart')
            runners = []
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
                (InputOwner('cpu', 'irq', 0, 1, 'bound', 'uart.uart_rx_int'),
                 InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                            'external_uart_rx_byte')))

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                uart = GeneratedWishboneUartSession(uart_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', source=None, cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('uart', UART_BASE, 0x1000, uart),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'uart': uart},
                    ownership=ownership, bindings=(Binding('uart', 'uart_rx_int',
                                                          'cpu', 'irq', 1),))
                runners.append(runner)
                return runner

            seed = ScenarioGenome(testcase_id='cve2-zip-wb-uart-chain',
                    direction='MULTI_COMPONENT_CHAIN', path_id='cpu-tx-uart-rx-cpu-ram',
                    schedule_order=('cpu', 'uart'), max_steps=6500,
                    actions=(Action('external-serial-byte', 'uart', 'uart_rx_byte',
                                    0x35, 'MULTI_COMPONENT_CHAIN', Trigger('START')),),
                    initial_images=(MemoryImage('cpu.boot', 'cpu', 0x10000, _program()),
                                    MemoryImage('cpu.result', 'cpu', RESULT, '00000000')))
            graph = DependencyGraph(sources=(FuzzableSource(
                'external_uart_rx_byte', 'uart', 'uart_rx_byte', 0, 8,
                ('MULTI_COMPONENT_CHAIN',)),), rules=(
                DependencyRule('uart.rxfifo_data', ('external_uart_rx_byte',),
                               'DATA_BINDING'),
                DependencyRule('cpu.result_ram', ('uart.rxfifo_data',),
                               'PERSISTENT_STATE_RULE')))
            plan = choose_mutation(graph, {'cpu.result_ram': 1},
                                   direction='MULTI_COMPONENT_CHAIN')
            changed = seed
            for bit in (0, 1, 4, 7):
                changed = mutate_genome(changed, plan, graph, ownership,
                                        bit_index=bit)
            self.assertEqual(0xa6, changed.actions[0].value)

            budget = ResourceBudget(max_wall_time_ms=180000,
                max_materialized_bytes_per_memory=0x20000)
            observed = []
            for case in (seed, changed):
                byte = case.actions[0].value
                bundle = work / f'evidence-{byte:02x}'
                trace = save_evidence_bundle(case, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-5:])
                cpu = runners[-1].sessions['cpu']
                uart = runners[-1].sessions['uart']
                self.assertEqual([], uart.local_transactions)
                self.assertEqual([0x41], uart.peer.captured)
                self.assertEqual(byte, cpu.memory.read(RESULT, 4,
                    transaction_id=f'acceptance-{byte:02x}').value,
                    (runners[-1].local_ticks,
                     [event for event in trace.events if event.get('kind') == 'mmio_delivery'],
                     [event for event in trace.events if event.get('kind') == 'memory_write'][-5:]))
                deliveries = [event for event in trace.events
                              if event.get('kind') == 'mmio_delivery'
                              and event.get('device_id') == 'uart']
                self.assertEqual([(0, 25), (12, 0x41)],
                    [(event['offset'], event['write_value']) for event in deliveries
                     if event['write']])
                self.assertEqual([(8, byte)],
                    [(event['offset'], event['read_value'] & 255)
                     for event in deliveries if not event['write']])
                self.assertTrue(any(event.get('kind') == 'local_tick_sample'
                                    and event.get('component') == 'uart'
                                    and event.get('outputs', {}).get('uart_rx_int')
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'dataflow_delivery'
                                    and event.get('target') == ('cpu', 'irq')
                                    and event.get('value') == 1
                                    for event in trace.events))
                self.assertTrue(any(event.get('kind') == 'memory_write'
                                    and event.get('address') == RESULT
                                    and event.get('value') == byte
                                    for event in trace.events))
                self.assertEqual([byte], [event['value'] for event in trace.events
                    if event.get('kind') == 'source_injection'
                    and event.get('component') == 'uart'])
                self.assertFalse(any(event.get('kind') == 'pulse_start'
                                     for event in trace.events))
                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                self.assertEqual(byte, runners[-1].sessions['cpu'].memory.read(
                    RESULT, 4, transaction_id=f'replay-{byte:02x}').value)
                observed.append(trace.semantic_sha256)
            self.assertNotEqual(observed[0], observed[1])


if __name__ == '__main__':
    unittest.main()
