"""Real ZipCPU AXI4-Lite UART RX level IRQ into CVA6 M_EXT and replay."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.axil_uart_session import GeneratedAxiLiteUartSession
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
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
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'
UART_BASE = 0x40000000
RESULT = 0x20000
MTVEC = 0x10100
UART_CLKS_PER_BIT = 25
UART_POST_SETUP_IDLE_EXTENSION_TICKS = 14 * UART_CLKS_PER_BIT


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


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _andi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 31) << 7 | 0x23)


def _sd(rs2: int, rs1: int, offset: int) -> int:
    return ((offset >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            3 << 12 | (offset & 31) << 7 | 0x23)


def _bne(rs1: int, rs2: int, offset: int) -> int:
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | 1 << 12 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def _jal(rd: int, offset: int) -> int:
    value = offset & 0x1fffff
    return (((value >> 20) & 1) << 31 | ((value >> 1) & 0x3ff) << 21 |
            ((value >> 11) & 1) << 20 | ((value >> 12) & 0xff) << 12 |
            rd << 7 | 0x6f)


def _csr(funct3: int, rd: int, csr: int, rs1: int) -> int:
    return csr << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73


def _program() -> tuple[bytes, bytes]:
    # Preserve the pinned boot stub; CVA6 starts at 0x10000 and continues at
    # 0x10010. UART setup is a real CPU store before the RX waveform starts.
    main = (
        _lui(1, MTVEC >> 12),
        _addi(1, 1, MTVEC & 0xfff),
        _csr(1, 0, 0x305, 1),              # mtvec = 0x10100, direct mode
        _lui(1, 1),
        _addi(1, 1, -0x800),
        _csr(1, 0, 0x304, 1),              # mie.MEIE = 1 << 11
        _addi(1, 0, 1 << 3),
        _csr(1, 0, 0x300, 1),              # mstatus.MIE = 1
        _lui(1, UART_BASE >> 12),
        _addi(2, 0, 25),
        _sw(2, 1, 0),                      # actual AXI4 -> UART SETUP
        _lui(8, RESULT >> 12),
        _lw(2, 8, 16),                     # wait for the ISR marker
        _bne(2, 0, 8),
        _jal(0, -8),
        _addi(3, 0, 0x66),
        _sw(3, 8, 24),                     # proves MRET returned to main
        0x0000006f,                        # terminal loop
    )
    isr = (
        _lui(1, UART_BASE >> 12),
        _lui(20, RESULT >> 12),            # preserve main's x8 poll base
        _lw(2, 1, 8),                      # actual RXREG read pops FIFO
        _andi(2, 2, 0xff),
        _csr(2, 4, 0x342, 0),              # actual 64-bit mcause
        _sw(2, 20, 0),                     # received byte
        _sd(4, 20, 8),                     # native M_EXT cause
        _addi(5, 0, 0x55),
        _sw(5, 20, 16),                    # ISR completion marker
        0x30200073,                        # mret
    )
    boot_prefix = BOOT.read_bytes()[:16]
    return (boot_prefix + b''.join(word.to_bytes(4, 'little') for word in main),
            b''.join(word.to_bytes(4, 'little') for word in isr))


def _make_factory(cpu_artifact, uart_artifact, cache_dir: Path):
    ownership = compile_ownership(
        (InputField('cpu', 'irq_external', 1),
         InputField('cpu', 'irq_timer', 1),
         InputField('uart', 'uart_rx_byte', 8)),
        (InputOwner('cpu', 'irq_external', 0, 1, 'bound', 'uart.uart_rx_int'),
         InputOwner('cpu', 'irq_timer', 0, 1, 'fixed', 'constant_zero'),
         InputOwner('uart', 'uart_rx_byte', 0, 8, 'source',
                    'external_uart_rx_byte')))
    binding = Binding('uart', 'uart_rx_int', 'cpu', 'irq_external', 1)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x40000),),
            initialization_seed=0, max_initialized_bytes=0x40000)
        uart = GeneratedAxiLiteUartSession(uart_artifact, base_dir=ROOT,
            cache_dir=cache_dir, source=None, cpu_routed_mode=True)
        # The CPU's full-strobe SETUP write resets rxuart. Its ordinary
        # 17-cell idle interval starts before that write commits, so add a
        # fixed test-local mark interval after the peer's scheduled start.
        start_source = uart.peer.start_source
        uart.peer.start_source = lambda tick: start_source(
            tick + UART_POST_SETUP_IDLE_EXTENSION_TICKS)
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, 0x1000, uart),))
        cpu = GeneratedCva6Axi4Session(cpu_artifact, base_dir=ROOT,
            cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True,
            command_timeout_seconds=60)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'uart': uart},
            ownership=ownership, bindings=(binding,))
        instances.append(runner)
        return runner

    return factory, instances, ownership


def _read_result(cpu, offset: int, width: int = 4) -> int:
    return cpu.memory.read(RESULT + offset, width,
        transaction_id=f'cva6-axiluart-mext-result-{offset:x}-{width}').value


def _backend_handshakes(events, component: str, producer_event_id: int,
                        valid: str, ready: str):
    return [event for event in events
        if event.get('kind') == 'local_tick_sample'
        and event.get('component') == component
        and event.get('producer_event_id') == producer_event_id
        and event.get('phase') == 'pre'
        and event.get('outputs', {}).get('backend', {}).get(valid) == 1
        and event.get('outputs', {}).get('backend', {}).get(ready) == 1]


def _cpu_step_backend(event):
    outputs = event.get('outputs') or {}
    samples = outputs.get('driver_samples', ())
    return (samples[0].get('pre', {}).get('backend', {})
            if samples else {})


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedCva6ZipcpuAxilUartRxMextIrqRealTests(unittest.TestCase):
    def test_uart_rx_level_irq_reaches_cva6_mext_isr_and_replays(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        if not (ROOT / 'third_party/soc-zipcpu-wbuart/rtl/axiluart.v').is_file():
            self.skipTest('pinned ZipCPU UART source is not initialized locally')
        with tempfile.TemporaryDirectory(
                prefix='myfuzz-cva6-generated-zip-axiluart-mext-') as directory:
            work = Path(directory)
            cpu_artifact = _artifact(
                'configs/cpus/cva6/component_profile.json', 'cpu')
            uart_artifact = _artifact(
                'configs/peripherals/zipcpu_axiluart/component_profile.json',
                'uart')
            factory, instances, ownership = _make_factory(
                cpu_artifact, uart_artifact, work / 'cache')
            program, isr = _program()
            seed = ScenarioGenome(
                testcase_id='cva6-generated-zip-axiluart-rx-mext-01',
                direction='IP_TO_CPU',
                path_id='uart-rx-fifo-level-irq-cva6-mext-ram',
                schedule_order=('cpu', 'uart'), max_steps=3000,
                actions=(Action('external-uart-rx-byte', 'uart', 'uart_rx_byte',
                    0x35, 'IP_TO_CPU', Trigger('START')),),
                initial_images=(
                    MemoryImage('cpu.program', 'cpu', 0x10000, program.hex()),
                    MemoryImage('cpu.uart_mext_isr', 'cpu', MTVEC, isr.hex()),
                    MemoryImage('cpu.result', 'cpu', RESULT, bytes(32).hex()),
                ))
            graph = DependencyGraph(
                sources=(FuzzableSource('external_uart_rx_byte', 'uart',
                    'uart_rx_byte', 0, 8, ('IP_TO_CPU',)),),
                rules=(DependencyRule('uart.rx_fifo_data',
                                      ('external_uart_rx_byte',), 'DATA_BINDING'),
                       DependencyRule('uart.rx_level_irq', ('uart.rx_fifo_data',),
                                      'EVENT_ORDER'),
                       DependencyRule('cpu.mext_isr_ram', ('uart.rx_level_irq',),
                                      'PERSISTENT_STATE_RULE')))
            mutation = choose_mutation(graph, {'cpu.mext_isr_ram': 1},
                                       direction='IP_TO_CPU')
            self.assertEqual('external_uart_rx_byte', mutation.focus_source)
            changed = seed
            for bit in (0, 1, 4, 7):
                changed = mutate_genome(changed, mutation, graph, ownership,
                                        bit_index=bit)
            self.assertEqual(0xa6, changed.actions[0].value)
            self.assertEqual(seed.initial_images, changed.initial_images)
            self.assertEqual(seed.actions[0].trigger, changed.actions[0].trigger)

            budget = ResourceBudget(max_transactions=2048,
                max_local_cycles_per_component=8192, max_scheduler_steps=12000,
                max_wall_time_ms=300000,
                max_materialized_bytes_per_memory=0x40000,
                max_evidence_bytes=96 * 1024 * 1024)
            semantic_hashes = []
            for genome in (seed, changed):
                source_value = genome.actions[0].value
                bundle = work / f'evidence-uart-{source_value:02x}'
                trace = save_evidence_bundle(genome, factory, bundle, budget=budget)
                self.assertEqual('complete', trace.status, trace.events[-10:])
                original = instances[-1]
                cpu, uart = original.sessions['cpu'], original.sessions['uart']
                events = trace.events
                cpu_steps = [event for event in events
                    if event.get('component') == 'cpu'
                    and event.get('outputs') is not None]

                injections = [event for event in events
                    if event.get('kind') == 'source_injection']
                self.assertEqual(1, len(injections))
                self.assertEqual(('uart', 'uart_rx_byte', source_value,
                                  'external_uart_rx_byte', 0, 8),
                    (injections[0]['component'], injections[0]['port'],
                     injections[0]['value'], injections[0]['source_ref'],
                     injections[0]['bit_offset'], injections[0]['width']))
                self.assertEqual([], [event for event in events
                    if event.get('kind') == 'pulse_start'])
                owners = original.ownership.document()['owners']
                self.assertIn({'component_id': 'cpu', 'port': 'irq_external',
                    'bit_offset': 0, 'width': 1, 'kind': 'bound',
                    'producer_ref': 'uart.uart_rx_int'}, owners)
                self.assertIn({'component_id': 'cpu', 'port': 'irq_timer',
                    'bit_offset': 0, 'width': 1, 'kind': 'fixed',
                    'producer_ref': 'constant_zero'}, owners)
                self.assertIn({'component_id': 'uart', 'port': 'uart_rx_byte',
                    'bit_offset': 0, 'width': 8, 'kind': 'source',
                    'producer_ref': 'external_uart_rx_byte'}, owners)
                identity = uart.identity_document()
                self.assertTrue(identity['cpu_routed_mode'])
                self.assertEqual((), uart.startup_writes)
                self.assertFalse(uart.read_rx_after_source)

                deliveries = [event for event in events
                    if event.get('kind') == 'mmio_delivery'
                    and event.get('device_id') == 'uart']
                acceptances = [event for event in events
                    if event.get('kind') == 'mmio_acceptance'
                    and event.get('device_id') == 'uart']
                setup = [event for event in deliveries
                    if event.get('write') and event.get('offset') == 0]
                reads = [event for event in deliveries if not event.get('write')]
                rx_reads = [event for event in reads if event.get('offset') == 8]
                setup_acceptance = [event for event in acceptances
                    if event.get('write') and event.get('offset') == 0]
                rx_acceptance = [event for event in acceptances
                    if not event.get('write') and event.get('offset') == 8]
                self.assertEqual(2, len(deliveries), deliveries)
                self.assertEqual(2, len(acceptances), acceptances)
                transaction_keys = lambda rows: [tuple(sorted(
                    row['source_transaction'].items())) for row in rows]
                self.assertEqual(sorted(transaction_keys(acceptances)),
                                 sorted(transaction_keys(deliveries)))
                self.assertEqual(2, len(set(transaction_keys(acceptances))))
                self.assertEqual(1, len(setup), deliveries)
                self.assertEqual(1, len(setup_acceptance), acceptances)
                self.assertEqual((25, 15, 8),
                    (setup[0]['write_value'], setup[0]['byte_enable'],
                     setup[0]['beat_bytes']))
                self.assertEqual(setup_acceptance[0]['source_transaction'],
                                 setup[0]['source_transaction'])
                if len(rx_reads) != 1:
                    pin = next(row['runtime_name'] for row in
                        uart.artifact.runtime_document['physical_exports']
                        if row['endpoint_id'] == 'uart.pins' and row['role'] == 'rx')
                    uart_samples = [event for event in events
                        if event.get('kind') == 'local_tick_sample'
                        and event.get('component') == 'uart']
                    cpu_steps = [event for event in events
                        if event.get('component') == 'cpu'
                        and event.get('outputs') is not None]
                    setup_step = next((event for event in events
                        if event.get('event_id') == setup[0]['producer_event_id']), {})
                    setup_b = _backend_handshakes(events, 'uart',
                        setup[0]['producer_event_id'], 'axil_bvalid', 'axil_bready')
                    rx_pin_pre = [event for event in uart_samples
                        if event.get('phase') == 'pre'
                        and isinstance(event.get('outputs', {}).get('physical'), dict)
                        and pin in event['outputs']['physical']]
                    uart_irq_values = [event.get('outputs', {}).get('uart_rx_int')
                        for event in uart_samples
                        if event.get('phase') == 'post'
                        and event.get('outputs', {}).get('uart_rx_int') in (0, 1)]
                    uart_irq_high_ticks = [event['local_tick'] for event in uart_samples
                        if event.get('phase') == 'post'
                        and event.get('outputs', {}).get('uart_rx_int') == 1]
                    irq_inputs = [event.get('local_tick') for event in cpu_steps
                        if event.get('inputs', {}).get('irq_external') == 1]
                    irq_deliveries = [event.get('value') for event in events
                        if event.get('kind') == 'dataflow_delivery'
                        and tuple(event.get('source', ())) == ('uart', 'uart_rx_int')]
                    self.fail({
                        'setup_delivery': {key: setup[0].get(key) for key in
                            ('event_id', 'producer_event_id', 'offset', 'write_value')},
                        'setup_step_tick': setup_step.get('local_tick'),
                        'setup_b_handshake_ticks': [event['local_tick']
                                                     for event in setup_b],
                        'rx_source_start_end_final_ticks':
                            (uart.peer.source_start_tick, uart.peer.source_end_tick,
                             uart.local_ticks),
                        'physical_rx_first_low_tick': next((event['local_tick']
                            for event in rx_pin_pre
                            if event['outputs']['physical'][pin] == 0), None),
                        'physical_rx_final_level': (rx_pin_pre[-1]['outputs']['physical'][pin]
                            if rx_pin_pre else None),
                        'native_irq_high_tick_range': ((min(uart_irq_high_ticks),
                            max(uart_irq_high_ticks)) if uart_irq_high_ticks else None),
                        'native_irq_final_and_max': (uart_irq_values[-1] if uart_irq_values
                            else None, max(uart_irq_values, default=None)),
                        'bound_irq_value_counts': {value: irq_deliveries.count(value)
                            for value in set(irq_deliveries)},
                        'cpu_external_irq_ticks': irq_inputs[:8],
                        'cpu_result_ram': tuple(_read_result(cpu, offset, width)
                            for offset, width in ((0, 4), (8, 8), (16, 4), (24, 4))),
                        'last_cpu_axi': [{key: event['outputs'].get(key)
                            for key in ('ar_accepted', 'r_consumed', 'aw_accepted',
                                        'b_consumed', 'irq_external')}
                            for event in cpu_steps[-3:]],
                    })
                self.assertEqual((source_value, 15, 8),
                    (rx_reads[0]['read_value'] & 0xff,
                     rx_reads[0]['byte_enable'], rx_reads[0]['beat_bytes']))
                self.assertEqual(1, len(rx_acceptance), acceptances)
                self.assertEqual(rx_acceptance[0]['source_transaction'],
                                 rx_reads[0]['source_transaction'])
                cpu_rx_ar = [event for event in cpu_steps
                    if event['outputs'].get('ar_accepted') == 1
                    and event['outputs'].get('araddr') == UART_BASE + 8]
                self.assertEqual(1, len(cpu_rx_ar), cpu_rx_ar)
                cpu_rx_ar_id = _cpu_step_backend(cpu_rx_ar[0]).get('axi_arid')
                self.assertIsInstance(cpu_rx_ar_id, int)
                self.assertEqual(rx_acceptance[0]['producer_event_id'],
                                 cpu_rx_ar[0]['event_id'])
                rx_ar = _backend_handshakes(events, 'uart',
                    rx_reads[0]['producer_event_id'], 'axil_arvalid', 'axil_arready')
                rx_r = _backend_handshakes(events, 'uart',
                    rx_reads[0]['producer_event_id'], 'axil_rvalid', 'axil_rready')
                self.assertEqual(1, len(rx_ar), rx_ar)
                self.assertEqual(1, len(rx_r), rx_r)
                self.assertGreater(rx_r[0]['local_tick'], uart.peer.source_end_tick,
                    'CPU RXREG access must follow the physical frame')

                # A router delivery exists only after the target AXI-Lite
                # response completed. Verify that its real B handshake is
                # recorded in this UART-local tick group before RX begins.
                setup_b = _backend_handshakes(events, 'uart',
                    setup[0]['producer_event_id'], 'axil_bvalid', 'axil_bready')
                self.assertEqual(1, len(setup_b), setup_b)
                rx_export = next(row for row in uart.artifact.runtime_document[
                    'physical_exports'] if row['endpoint_id'] == 'uart.pins'
                    and row['role'] == 'rx')
                rx_pin = rx_export['runtime_name']
                rx_pin_samples = [event for event in events
                    if event.get('kind') == 'local_tick_sample'
                    and event.get('component') == 'uart'
                    and event.get('phase') == 'pre'
                    and isinstance(event.get('outputs', {}).get('physical'), dict)
                    and rx_pin in event['outputs']['physical']]
                low_samples = [event for event in rx_pin_samples
                    if event['outputs']['physical'][rx_pin] == 0]
                self.assertTrue(low_samples, 'real i_uart_rx never began a start bit')
                rx_start = min(low_samples, key=lambda event: event['local_tick'])
                self.assertEqual(uart.peer.source_start_tick, rx_start['local_tick'])
                self.assertLess(setup_b[0]['local_tick'], rx_start['local_tick'],
                    'SETUP B response must complete before the physical RX start bit')
                self.assertGreaterEqual(rx_start['local_tick'] - setup_b[0]['local_tick'],
                    17 * UART_CLKS_PER_BIT,
                    'rxuart needs 17 idle bit cells after the SETUP reset')
                self.assertLess(setup[0]['event_id'], rx_start['event_id'])
                rx_pin_by_tick = {}
                for event in rx_pin_samples:
                    level = event['outputs']['physical'][rx_pin]
                    prior = rx_pin_by_tick.setdefault(event['local_tick'], level)
                    self.assertEqual(prior, level,
                        'pre-samples disagree on the physical UART RX pin')
                self.assertEqual(1, rx_pin_by_tick[rx_start['local_tick'] - 1])
                for offset in range(10 * UART_CLKS_PER_BIT):
                    slot = offset // UART_CLKS_PER_BIT
                    expected_bit = (0 if slot == 0 else 1 if slot == 9
                                    else source_value >> (slot - 1) & 1)
                    self.assertEqual(expected_bit,
                        rx_pin_by_tick.get(rx_start['local_tick'] + offset),
                        f'physical RX 8N1 bit {slot} did not hold for 25 ticks')

                cpu_setup_aw = [event for event in cpu_steps
                    if event['outputs'].get('aw_accepted') == 1
                    and event['outputs'].get('awaddr') == UART_BASE]
                self.assertEqual(1, len(cpu_setup_aw), cpu_setup_aw)
                cpu_setup_aw_id = _cpu_step_backend(cpu_setup_aw[0]).get('axi_awid')
                self.assertIsInstance(cpu_setup_aw_id, int)
                cpu_setup_b = [event for event in cpu_steps
                    if event['event_id'] > setup[0]['event_id']
                    and event['event_id'] < rx_reads[0]['event_id']
                    and event['outputs'].get('b_consumed') == 1
                    and _cpu_step_backend(event).get('axi_bvalid') == 1
                    and _cpu_step_backend(event).get('axi_bready') == 1
                    and _cpu_step_backend(event).get('axi_bid') == cpu_setup_aw_id]
                self.assertEqual(1, len(cpu_setup_b),
                    'SETUP B response must match the AWID captured for UART_BASE: '
                    f'{cpu_setup_b!r}')

                uart_irq = [event for event in events
                    if event.get('kind') == 'local_tick_sample'
                    and event.get('component') == 'uart'
                    and event.get('phase') == 'post'
                    and event.get('outputs', {}).get('uart_rx_int') in (0, 1)]
                high_samples = [event for event in uart_irq
                                if event['outputs']['uart_rx_int'] == 1]
                self.assertTrue(high_samples,
                    'ZipCPU RX-not-empty level never asserted after the frame')
                bound_irq = [event for event in events
                    if event.get('kind') == 'dataflow_delivery'
                    and tuple(event.get('source', ())) == ('uart', 'uart_rx_int')
                    and tuple(event.get('target', ())) == ('cpu', 'irq_external')]
                irq_high = next((event for event in bound_irq
                                 if event.get('value') == 1), None)
                self.assertIsNotNone(irq_high, 'native UART level IRQ missed CVA6 M_EXT')
                assert irq_high is not None
                irq_producer = next(event for event in events
                    if event.get('event_id') == irq_high['producer_event_id'])
                self.assertEqual(1, irq_producer.get('outputs', {}).get('uart_rx_int'))
                self.assertLess(irq_high['event_id'], rx_reads[0]['event_id'])
                self.assertTrue(any(event.get('inputs', {}).get('irq_external') == 1
                    for event in events if event.get('component') == 'cpu'
                    and event.get('outputs') is not None),
                    'CVA6 never sampled its bound M_EXT input')
                self.assertTrue(all(event.get('inputs', {}).get('irq_timer', 0) == 0
                                    for event in cpu_steps))

                irq_low = next((event for event in bound_irq
                    if event.get('value') == 0
                    and event.get('event_id', 0) > rx_reads[0]['event_id']), None)
                self.assertIsNotNone(irq_low,
                    'RXREG FIFO pop did not lower the native level IRQ')
                native_low_in_pop = [event for event in events
                    if event.get('kind') == 'local_tick_sample'
                    and event.get('component') == 'uart'
                    and event.get('phase') == 'post'
                    and event.get('producer_event_id')
                        == rx_reads[0]['producer_event_id']
                    and rx_ar[0]['local_tick'] <= event.get('local_tick', 0)
                        <= rx_r[0]['local_tick']
                    and event.get('outputs', {}).get('uart_rx_int') == 0]
                self.assertTrue(native_low_in_pop,
                    'native RX level did not fall in the RXREG AXIL read interval')
                rx_response_value = rx_reads[0]['read_value']
                next_cpu_ar = [event for event in cpu_steps
                    if event['event_id'] > rx_reads[0]['event_id']
                    and event['outputs'].get('ar_accepted') == 1]
                self.assertTrue(next_cpu_ar,
                    'no later CPU AR acceptance bounded the RX response window')
                rx_response_window_end = min(event['event_id']
                                             for event in next_cpu_ar)
                cpu_rx_response = [event for event in cpu_steps
                    if rx_reads[0]['event_id'] < event['event_id']
                    <= rx_response_window_end
                    if event['outputs'].get('r_consumed') == 1
                    and _cpu_step_backend(event).get('axi_rvalid') == 1
                    and _cpu_step_backend(event).get('axi_rready') == 1
                    and _cpu_step_backend(event).get('axi_rid') == cpu_rx_ar_id
                    and _cpu_step_backend(event).get('axi_rdata') == rx_response_value]
                self.assertEqual(1, len(cpu_rx_response), cpu_rx_response)
                self.assertEqual(1,
                    _cpu_step_backend(cpu_rx_response[0]).get('axi_rlast'),
                    'RXREG response must be a single-beat AXI read')
                self.assertGreater(cpu_rx_response[0]['event_id'],
                                   rx_reads[0]['event_id'])
                payload_write = next(event for event in events
                    if event.get('kind') == 'memory_write'
                    and event.get('component') == 'cpu'
                    and event.get('address') == RESULT
                    and event.get('byte_enable') == 0x0f
                    and (event.get('value', 0) & 0xff) == source_value)
                self.assertLess(cpu_rx_response[0]['event_id'],
                                payload_write['event_id'],
                    'CVA6 must consume RXREG data before committing the byte to RAM')
                self.assertEqual(source_value, _read_result(cpu, 0) & 0xff)
                self.assertEqual(0x800000000000000b, _read_result(cpu, 8, 8),
                    'CVA6 must take native machine-external cause 11')
                self.assertEqual(0x55, _read_result(cpu, 16),
                    'ISR completion store must persist in RAM')
                self.assertEqual(0x66, _read_result(cpu, 24),
                    'post-MRET marker proves execution returned to main')
                ram_writes = [event for event in events
                    if event.get('kind') == 'memory_write'
                    and event.get('component') == 'cpu']
                isr_marker = next((event for event in ram_writes
                    if event.get('address') == RESULT + 16
                    and event.get('byte_enable') == 0x0f
                    and (event.get('value', 0) & 0xffffffff) == 0x55), None)
                resumed_marker = next((event for event in ram_writes
                    if event.get('address') == RESULT + 24
                    and (event.get('value', 0) & 0xffffffff) == 0x66), None)
                self.assertIsNotNone(isr_marker, ram_writes)
                self.assertIsNotNone(resumed_marker, ram_writes)
                assert isr_marker is not None and resumed_marker is not None
                self.assertLess(isr_marker['event_id'], resumed_marker['event_id'])

                transactions = [tuple(event['source_transaction'][field]
                    for field in ('source_component', 'source_epoch', 'channel_id',
                                  'source_sequence')) for event in deliveries]
                self.assertEqual(len(transactions), len(set(transactions)),
                    'each CPU-routed MMIO request must execute exactly once')
                self.assertTrue(all(key[0] == 'cpu' and key[1] == 0
                                    for key in transactions), transactions)
                self.assertEqual(0, cpu.reset_epoch)
                self.assertEqual(0, uart.reset_epoch)
                self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                     for event in events))

                replay = replay_evidence_bundle(bundle, factory)
                self.assertTrue(replay.matches, replay.difference_context)
                fresh = instances[-1]
                fresh_cpu, fresh_uart = fresh.sessions['cpu'], fresh.sessions['uart']
                self.assertIsNot(cpu, fresh_cpu)
                self.assertIsNot(uart, fresh_uart)
                self.assertNotEqual(original.execution_id, fresh.execution_id)
                self.assertNotEqual(cpu._execution, fresh_cpu._execution)
                self.assertNotEqual(uart._execution, fresh_uart._execution)
                replay_trace = replay.actual_trace
                self.assertEqual('complete', replay_trace.status)
                self.assertEqual(trace.events, replay_trace.events)
                self.assertEqual(trace.local_ticks, replay_trace.local_ticks)
                self.assertEqual(source_value, _read_result(fresh_cpu, 0) & 0xff)
                self.assertEqual(0x800000000000000b,
                                 _read_result(fresh_cpu, 8, 8))
                self.assertEqual(0x66, _read_result(fresh_cpu, 24))
                self.assertEqual(0, fresh_cpu.reset_epoch)
                self.assertEqual(0, fresh_uart.reset_epoch)
                semantic_hashes.append(trace.semantic_sha256)
            self.assertNotEqual(semantic_hashes[0], semantic_hashes[1])


if __name__ == '__main__':
    unittest.main()
