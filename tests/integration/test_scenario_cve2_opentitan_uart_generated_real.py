"""CVE2 drives generated OpenTitan UART TX and stores real RXDATA in RAM."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
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
from myfuzz.scenario.runner import ScenarioRunner


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
    # CPU configures UART, transmits, then waits for one genuine RX frame.
    words = [
        _lui(1, 0x40000), _lui(2, 0x80000), _addi(2, 2, 3), _sw(2, 1, 0x10),
        _addi(2, 0, 0x41), _sw(2, 1, 0x1c),
        _addi(3, 0, 250), _addi(3, 3, -1), _bne(3, 0, -4),
        _lw(4, 1, 0x18), _andi(4, 4, 255), _lui(5, 0x20),
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
class GeneratedCve2OpentitanUartRealTests(unittest.TestCase):
    def test_cpu_tlul_tx_serial_rx_rdata_ram_and_fresh_replay(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-cve2-opentitan-uart-chain-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact('configs/cpus/cv32e20/component_profile.json', 'cpu')
            uart_artifact = _artifact('configs/peripherals/opentitan_uart_local/component_profile.json', 'uart')
            runners = []
            ownership = compile_ownership(
                (InputField('cpu', 'irq', 1), InputField('uart', 'uart_rx_byte', 8)),
                (InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero'),
                 InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                            'external_uart_rx_byte')))

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                    initialization_seed=37, max_initialized_bytes=0x20000)
                uart = GeneratedOpentitanUartSession(uart_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', source=None, cpu_routed_mode=True)
                router = DataflowRouter((DeviceWindow('uart', UART_BASE, 0x1000, uart),))
                cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                    cache_dir=work / 'cache', memory=memory, router=router,
                    defer_mmio=True)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'uart': uart},
                    ownership=ownership, bindings=())
                runners.append(runner)
                return runner

            seed = ScenarioGenome(testcase_id='cve2-opentitan-uart-chain',
                    direction='MULTI_COMPONENT_CHAIN', path_id='cpu-tx-uart-rx-cpu-ram',
                    schedule_order=('uart', 'cpu'), max_steps=6500,
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
                self.assertEqual([0x41], uart.peer.captured)
                self.assertEqual(byte, cpu.memory.read(RESULT, 4,
                    transaction_id=f'acceptance-{byte:02x}').value,
                    (runners[-1].local_ticks,
                     [event for event in trace.events if event.get('kind') == 'mmio_delivery'],
                     [event for event in trace.events if event.get('kind') == 'memory_write'][-5:]))
                deliveries = [event for event in trace.events
                              if event.get('kind') == 'mmio_delivery'
                              and event.get('device_id') == 'uart']
                self.assertEqual([(0x10, 0x80000003), (0x1c, 0x41)],
                    [(event['offset'], event['write_value']) for event in deliveries
                     if event['write']])
                self.assertTrue(any(event['offset'] == 0x18
                                    and event['read_value'] & 255 == byte
                                    for event in deliveries if not event['write']))
                self.assertTrue(any(event.get('component') == 'uart'
                                    and event.get('outputs', {}).get('serial_rx_read') == 1
                                    and event.get('outputs', {}).get('serial_rx_word') & 255 == byte
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
