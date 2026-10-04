"""Ibex programs drive real OpenTitan pattgen RTL and consume its completion."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (GeneratedTlulRegisterSession,
    compile_generated_register_ownership, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario, replay_scenario
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', ROOT)).resolve()
PATTGEN_BASE = 0x40000000
RESULT_ADDRESS = 0x20000
PATTGEN_SIZE = 7 | (1 << 6) | (4 << 16)
CPU_PATTERNS = (0xA5, 0x5A)


def expected_writes(pattern: int) -> tuple[tuple[int, int], ...]:
    return ((0x10, 0), (0x04, 3), (0x14, 1), (0x18, 2),
            (0x1c, pattern), (0x20, 0), (0x24, 0x16), (0x28, 0),
            (0x2c, PATTGEN_SIZE), (0x10, 3))


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _andi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | 7 << 12 | rd << 7 | 0x13


def _sw(rs2: int, rs1: int, offset: int) -> int:
    immediate = offset & 0xfff
    return ((immediate >> 5) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (immediate & 31) << 7 | 0x23)


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _bne(rs1: int, rs2: int, offset: int) -> int:
    immediate = offset & 0x1fff
    return (((immediate >> 12) & 1) << 31 |
            ((immediate >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 | 1 << 12 |
            ((immediate >> 1) & 0xf) << 8 |
            ((immediate >> 11) & 1) << 7 | 0x63)


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _program(pattern: int) -> tuple[int, ...]:
    if type(pattern) is not int or not 0 <= pattern <= 0xff:
        raise ValueError('CPU pattgen source must be one byte')
    # Program-controlled MMIO is the only route to pattgen configuration.
    setup = (
        _lui(1, PATTGEN_BASE >> 12), _lui(2, RESULT_ADDRESS >> 12),
        _addi(3, 0, 0), _sw(3, 1, 0x10),
        _addi(3, 0, 3), _sw(3, 1, 0x04),
        _addi(3, 0, 1), _sw(3, 1, 0x14),
        _addi(3, 0, 2), _sw(3, 1, 0x18),
        _addi(3, 0, pattern), _sw(3, 1, 0x1c),
        _addi(3, 0, 0), _sw(3, 1, 0x20),
        _addi(3, 0, 0x16), _sw(3, 1, 0x24),
        _addi(3, 0, 0), _sw(3, 1, 0x28),
        _lui(3, PATTGEN_SIZE >> 12),
        _addi(3, 3, PATTGEN_SIZE & 0xfff), _sw(3, 1, 0x2c),
        _addi(3, 0, 3), _sw(3, 1, 0x10),
    )
    poll = (_lw(4, 1, 0), _andi(5, 4, 3), _addi(6, 0, 3),
            _bne(5, 6, -12), _sw(5, 2, 0), 0x0000006f)
    return setup + poll


def genome(pattern: int) -> ScenarioGenome:
    return ScenarioGenome(
        testcase_id=f'ibex-opentitan-pattgen-{pattern:02x}',
        direction='CPU_TO_IP_TO_CPU', path_id='ibex-mmio-pattgen-poll-status-ram',
        schedule_order=('cpu', 'pattgen'), max_steps=220, actions=(),
        initial_images=(MemoryImage('boot', 'cpu', 0x10080, _image(_program(pattern))),
                        MemoryImage('result', 'cpu', RESULT_ADDRESS, '00000000')))


def _request(profile_path: str, instance_id: str, *, generic_tlul: bool = False):
    if generic_tlul:
        return load_local_harness_request(dict(
            schema_version='local_harness.v2', profile_path=profile_path,
            instance_id=instance_id, reset_assert_ticks=2,
            reset_release_ticks=2, max_wait_cycles=16,
            tuning={'endpoint_policies': [dict(
                endpoint_id='opentitan_pattgen.mmio', template_id='target.tl-ul',
                template_version='1', variant_id='user-integrity', max_outstanding=1)],
                'fixed_inputs': []}))
    return load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile_path,
        instance_id=instance_id, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))


def _artifact(profile_path: str, instance_id: str, *, generic_tlul: bool = False):
    plan = plan_local_harness(_request(profile_path, instance_id,
                                       generic_tlul=generic_tlul),
                              base_dir=SOURCE_ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=SOURCE_ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=SOURCE_ROOT)
    return render_local_driver(runtime, base_dir=SOURCE_ROOT)


def make_factory(cache_dir: Path):
    cpu_artifact = _artifact('configs/cpus/ibex_obi_local/component_profile.json', 'cpu')
    pattgen_artifact = _artifact(
        'configs/peripherals/opentitan_pattgen_local/component_profile.json',
        'pattgen', generic_tlul=True)
    instances = []

    def factory():
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=101, max_initialized_bytes=0x20000)
        pattgen = GeneratedTlulRegisterSession(
            pattgen_artifact, base_dir=SOURCE_ROOT, cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow('pattgen', PATTGEN_BASE, 0x1000,
                                              pattgen),))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=SOURCE_ROOT,
                                   cache_dir=cache_dir, memory=memory,
                                   router=router, defer_mmio=True)
        register_ownership = compile_generated_register_ownership(
            {'pattgen': pattgen_artifact}).document()
        fields = [InputField('cpu', 'irq', 1)]
        owners = [InputOwner('cpu', 'irq', 0, 1, 'fixed', 'constant_zero')]
        for row in register_ownership['fields']:
            fields.append(InputField(row['component_id'], row['port'], row['width']))
        for row in register_ownership['owners']:
            owners.append(InputOwner(**row))
        ownership = compile_ownership(tuple(fields), tuple(owners))
        runner = ScenarioRunner(sessions={'cpu': cpu, 'pattgen': pattgen},
                                ownership=ownership, bindings=())
        instances.append(runner)
        return runner

    return factory, instances


def _mmio(events: tuple[dict, ...], *, write: bool):
    return [event for event in events
            if event.get('kind') == 'mmio_delivery'
            and event.get('component') == 'cpu'
            and event.get('device_id') == 'pattgen'
            and event.get('write') is write]


def _serial_edges(samples: list[dict], channel: int):
    clock = f'cio_pcl{channel}_tx_o'
    data = f'cio_pda{channel}_tx_o'
    previous = 0
    edges = []
    for sample in samples:
        outputs = sample['outputs']
        if outputs[clock] and not previous:
            edges.append((sample['local_tick'], outputs[data]))
        previous = outputs[clock]
    return edges


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class GeneratedIbexOpenTitanPattgenRealTests(unittest.TestCase):
    def test_ibex_configures_real_pattgen_reads_both_done_bits_and_replays_variants(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-ibex-pattgen-') as directory:
            cache_dir = Path(os.environ.get('MYFUZZ_IBEX_PATTGEN_CACHE',
                                            Path(directory) / 'cache'))
            factory, instances = make_factory(cache_dir)
            semantic_hashes = []
            observed_patterns = []

            for pattern in CPU_PATTERNS:
                with self.subTest(cpu_pattern=pattern):
                    case = genome(pattern)
                    trace = record_scenario(case, factory)
                    self.assertEqual('complete', trace.status, trace.events[-8:])
                    events = trace.events
                    writes = _mmio(events, write=True)
                    self.assertEqual(expected_writes(pattern),
                        tuple((event['offset'], event['write_value']) for event in writes))
                    self.assertTrue(all(event['byte_enable'] == 15 for event in writes))
                    self.assertTrue(all(
                        event['source_transaction']['source_component'] == 'cpu'
                        and event['source_transaction']['channel_id'] == 'data'
                        and type(event['source_transaction']['source_sequence']) is int
                        for event in writes))

                    samples = [event for event in events
                               if event.get('kind') == 'local_tick_sample'
                               and event.get('component') == 'pattgen'
                               and event.get('phase') == 'post']
                    for channel, value, length, repeats, period in (
                            (0, pattern, 8, 2, 4), (1, 0x16, 5, 1, 6)):
                        edges = _serial_edges(samples, channel)
                        expected_bits = [(value >> bit) & 1
                                         for _ in range(repeats) for bit in range(length)]
                        self.assertEqual(expected_bits, [bit for _, bit in edges])
                        self.assertEqual({period}, {b[0] - a[0]
                                                   for a, b in zip(edges, edges[1:])})
                        self.assertEqual(1, samples[-1]['outputs'][
                            f'intr_done_ch{channel}_o'])
                        self.assertEqual(0, samples[-1]['outputs'][
                            f'cio_pcl{channel}_tx_o'])
                        self.assertEqual(0, samples[-1]['outputs'][
                            f'cio_pda{channel}_tx_o'])
                    self.assertTrue(all(sample['outputs'][f'cio_p{pin}{channel}_tx_en_o'] == 1
                        for sample in samples for channel in (0, 1) for pin in ('da', 'cl')))

                    status_reads = [event for event in _mmio(events, write=False)
                                    if event['offset'] == 0]
                    self.assertTrue(status_reads)
                    completed_read = next((event for event in status_reads
                                           if event['read_value'] & 3 == 3), None)
                    self.assertIsNotNone(completed_read, status_reads[-3:])
                    transaction = completed_read['source_transaction']
                    consumed = next((event for event in events
                        if event.get('component') == 'cpu'
                        and event.get('outputs', {}).get('data_rsp_consumed') == 1
                        and event['outputs'].get('data_rsp_source_epoch') ==
                            transaction['source_epoch']
                        and event['outputs'].get('data_rsp_source_sequence') ==
                            transaction['source_sequence']), None)
                    self.assertIsNotNone(consumed, completed_read)
                    self.assertEqual(completed_read['read_value'],
                                     consumed['outputs']['data_rsp_rdata'])
                    stored = next((event for event in events
                        if event.get('kind') == 'memory_write'
                        and event.get('component') == 'cpu'
                        and event.get('event_id', 0) > consumed['event_id']
                        and event.get('address') == RESULT_ADDRESS), None)
                    self.assertIsNotNone(stored, consumed)
                    self.assertEqual(3, stored['value'])
                    self.assertEqual(3, instances[-1].sessions['cpu'].memory.read(
                        RESULT_ADDRESS, 4,
                        transaction_id=f'acceptance-{pattern:02x}').value)
                    self.assertFalse(any(event.get('kind') == 'reset_barrier'
                                         for event in events))
                    self.assertEqual(0, instances[-1].sessions['cpu'].reset_epoch)
                    self.assertEqual(0, instances[-1].sessions['pattgen'].reset_epoch)
                    self.assertEqual(0, instances[-1].sessions['pattgen'].pending_events)
                    self.assertEqual(0, instances[-1].sessions['cpu'].pending_responses)

                    semantic_hashes.append(trace.semantic_sha256)
                    observed_patterns.append(tuple(bit for _, bit in
                                                   _serial_edges(samples, 0)))
                    replay = replay_scenario(case, factory, trace)
                    self.assertTrue(replay.matches, replay.difference_context)
                    self.assertIsNot(instances[-2].sessions['cpu'],
                                     instances[-1].sessions['cpu'])
                    self.assertIsNot(instances[-2].sessions['pattgen'],
                                     instances[-1].sessions['pattgen'])
                    self.assertEqual(3, instances[-1].sessions['cpu'].memory.read(
                        RESULT_ADDRESS, 4,
                        transaction_id=f'replay-{pattern:02x}').value)

            self.assertNotEqual(observed_patterns[0], observed_patterns[1])
            self.assertNotEqual(semantic_hashes[0], semantic_hashes[1])


if __name__ == '__main__':
    unittest.main()
