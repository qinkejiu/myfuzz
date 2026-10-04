"""Measured OBI handshakes service persistent host memory and deferred targets."""
from pathlib import Path
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('i_req_valid', 'i_req_ready', 'i_req_write', 'i_req_addr', 'i_req_wdata',
         'i_req_be', 'i_rsp_valid', 'i_rsp_ready', 'i_rsp_rdata', 'i_rsp_error',
         'd_req_valid', 'd_req_ready', 'd_req_write', 'd_req_addr', 'd_req_wdata',
         'd_req_be', 'd_rsp_valid', 'd_rsp_ready', 'd_rsp_rdata', 'd_rsp_error')


class Target:
    def __init__(self):
        self.writes = []
    def write_register(self, offset, value, *, be=15):
        self.writes.append((offset, value, be))
    def read_register(self, offset):
        return 0x55


def make_receipt(cpu, fields, observed):
    pre = dict.fromkeys(NAMES, 0)
    pre.update(zip(('i_req_ready', 'i_rsp_valid', 'i_rsp_rdata', 'i_rsp_error',
                    'd_req_ready', 'd_rsp_valid', 'd_rsp_rdata', 'd_rsp_error'), fields[1:]))
    pre.update(observed)
    snapshot = {'backend': pre, 'physical': {}}
    tick = cpu.local_ticks + 1
    payload = dict(schema_version='local_driver_result.v1', kind='obi_cpu',
        samples=[dict(local_tick=tick, pre=snapshot, post=snapshot)],
        observations=snapshot, pre_backend=pre, rdata=0, error=0)
    reply = DriverReceipt('result', '0'*32, 1, cpu.local_ticks, tick, 1, payload)
    cpu.local_ticks = tick  # GeneratedLocalSession owns actual receipt tick accounting.
    return reply


class GeneratedCpuSessionTests(unittest.TestCase):
    def setUp(self):
        self.memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                                       initialization_seed=9, max_initialized_bytes=0x30000)
        self.memory.preload(0x10000, b'\x13\x00\x00\x00')
        self.target = Target()
        self.router = DataflowRouter((DeviceWindow('gpio_a', 0x40000000, 0x1000, self.target),))
        artifact = SimpleNamespace(plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu_7')),
                                   runtime_document={'kind': 'obi_cpu', 'backend_ports': [], 'physical_exports': []})
        self.cpu = GeneratedCve2Session(artifact, base_dir=ROOT, cache_dir=ROOT/'unused',
                                       memory=self.memory, router=self.router)
        self.cpu._case_id = 'persistent-case'
        self.cpu._process = SimpleNamespace(poll=lambda: None)

    def step(self, observed):
        with patch.object(GeneratedLocalSession, 'command',
                          side_effect=lambda op, fields: make_receipt(self.cpu, fields, observed)):
            return self.cpu.step_local({'irq': 0})

    def test_only_accepted_requests_service_memory_and_held_response_is_not_repeated(self):
        first = self.step(dict(i_req_valid=1, i_req_addr=0x10000, i_req_be=15))
        self.assertEqual(1, first['instr_req_accepted'])
        self.assertEqual(1, len(self.cpu.service.events))
        held = self.step(dict(i_req_valid=1, i_req_addr=0x10000, i_req_be=15))
        self.assertEqual(0, held['instr_req_accepted'])
        self.assertEqual(1, len(self.cpu.service.events))
        consumed = self.step(dict(i_rsp_ready=1))
        self.assertEqual(1, consumed['instr_rsp_consumed'])
        self.assertEqual(0, self.cpu.pending_responses)
        self.step(dict(i_req_valid=1, i_req_addr=0x10000, i_req_be=15))
        transactions = [event['transaction'] for event in self.cpu.service.events]
        self.assertEqual(['cpu_7', 'cpu_7'], [key['source_component'] for key in transactions])
        self.assertEqual([1, 2], [key['source_sequence'] for key in transactions])

    def test_ram_byte_enables_freeze_readback_and_response_identity(self):
        self.memory.preload(0x20000, b'\x11\x22\x33\x44')
        self.step(dict(d_req_valid=1, d_req_write=1, d_req_addr=0x20000,
                       d_req_wdata=0xaabbccdd, d_req_be=5))
        self.assertEqual(0x44bb22dd, self.memory.read(0x20000, 4, transaction_id='acceptance-check').value)
        completed = self.step(dict(d_rsp_ready=1))
        self.assertEqual(1, completed['data_rsp_source_sequence'])
        self.assertEqual(0, completed['data_rsp_source_epoch'])
        self.step(dict(d_req_valid=1, d_req_addr=0x20000, d_req_be=15))
        self.memory.write(0x20000, 0, width_bytes=4, byte_enable=15, writer_event_id='later')
        loaded = self.step(dict(d_rsp_ready=1))
        self.assertEqual(0x44bb22dd, loaded['data_rsp_rdata'])
        self.assertEqual(2, loaded['data_rsp_source_sequence'])

    def test_deferred_mmio_waits_for_target_and_same_value_requests_have_distinct_keys(self):
        for expected in (1, 2):
            self.step(dict(d_req_valid=1, d_req_write=1, d_req_addr=0x4000000c,
                           d_req_wdata=0xa5, d_req_be=15))
            self.assertEqual(expected - 1, len(self.target.writes))
            self.assertEqual(1, self.cpu.pending_responses)
            self.step(dict(d_req_valid=1, d_req_write=1, d_req_addr=0x4000000c,
                           d_req_wdata=0xa5, d_req_be=15))
            self.assertEqual(expected, len(self.router.acceptances))
            self.router.drain_one('gpio_a')
            self.step(dict(d_rsp_ready=1))
        self.assertEqual([(12, 0xa5, 15)] * 2, self.target.writes)
        keys = [record['source_transaction'] for record in self.router.acceptances]
        self.assertNotEqual(keys[0], keys[1])
        self.assertEqual(['cpu_7', 'cpu_7'], [key.source_component for key in keys])

    def test_quiesce_stops_new_grants_but_delivers_pending_responses(self):
        self.step(dict(i_req_valid=1, i_req_addr=0x10000, i_req_be=15))
        self.cpu.begin_quiesce()
        result = self.step(dict(i_rsp_ready=1, d_req_valid=1, d_req_write=1,
                                d_req_addr=0x20000, d_req_wdata=1, d_req_be=15))
        self.assertEqual(1, result['instr_rsp_consumed'])
        self.assertEqual(0, result['data_req_accepted'])
        self.assertEqual(0, self.cpu.memory_write_count)

    def test_reset_cancels_queued_target_preserves_memory_and_advances_epoch(self):
        self.memory.write(0x20000, 42, width_bytes=4, byte_enable=15, writer_event_id='saved')
        self.step(dict(d_req_valid=1, d_req_write=1, d_req_addr=0x4000000c,
                       d_req_wdata=0xa5, d_req_be=15))
        ticks = self.cpu.local_ticks
        def reset_transport():
            self.cpu.reset_epoch += 1
            self.cpu._tick_base = self.cpu.local_ticks
            return {'cancelled_responses': 0}
        with patch.object(GeneratedLocalSession, 'reset_local', side_effect=reset_transport):
            receipt = self.cpu.reset_local()
        self.assertEqual(1, receipt['cancelled_responses'])
        self.assertEqual(1, len(receipt['cancelled_target_requests']))
        self.assertEqual((), self.router.pending_targets)
        self.assertEqual(0, self.cpu.pending_responses)
        self.assertEqual(ticks, self.cpu.local_ticks)
        self.assertEqual(42, self.memory.read(0x20000, 4, transaction_id='acceptance-check').value)
        self.assertEqual(1, self.cpu.reset_epoch)

    def test_physical_output_aliases_come_from_artifact_port_map(self):
        self.cpu._artifact_document['physical_exports'] = [
            dict(runtime_name='observed_intr', physical_port='rvfi_intr', width=1,
                 direction='output', bit_lo=0, hex_digits=1),
            dict(runtime_name='observed_pc', physical_port='rvfi_pc_rdata', width=32,
                 direction='output', bit_lo=0, hex_digits=8),
            dict(runtime_name='observed_wide', physical_port='wide_status', width=65,
                 direction='output', bit_lo=0, hex_digits=17)]
        def observed(op, fields):
            reply = make_receipt(self.cpu, fields, {})
            reply.payload['observations']['physical'] = {
                'observed_intr': 1, 'observed_pc': 0x10014,
                'observed_wide': '10000000000000000'}
            return reply
        with patch.object(GeneratedLocalSession, 'command', side_effect=observed):
            output = self.cpu.step_local({})
        self.assertEqual(1, output['rvfi_intr'])
        self.assertEqual(0x10014, output['rvfi_pc_rdata'])
        self.assertEqual(1 << 64, output['wide_status'])
        self.assertNotIn('irq_masked_pre', output)
        self.assertNotIn('irq_taken_pre', output)

    def test_invalid_receipt_or_command_inputs_cannot_service_memory(self):
        for value in (True, -1, 2):
            with self.assertRaises(ValueError):
                self.cpu.step_local({'irq': value})
        with self.assertRaises(ValueError):
            self.cpu.step_local({'unknown': 1})
        with patch.object(GeneratedLocalSession, 'command', return_value=DriverReceipt(
                'error', '0'*32, 1, 0, 0, 0, error_code='protocol_environment', error_detail='bad_response')):
            with self.assertRaises(ProtocolEnvironmentError):
                self.cpu.step_local({})
        self.assertEqual([], self.cpu.service.events)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1', 'set MYFUZZ_SCENARIO_REAL=1')
class GeneratedCpuSessionRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.local_harness.test_driver_renderer import make_top
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.build import build_local_harness
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-cpu-session-real-')
        cls.addClassCleanup(cls.directory.cleanup)
        top = make_top('configs/cpus/cv32e20/component_profile.json', 'cpu_real')
        source_root = Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', ROOT))
        cls.artifact = render_local_driver(top, base_dir=source_root)
        cls.binary = build_local_harness(cls.artifact, base_dir=source_root,
            cache_dir=Path(cls.directory.name)/'cache')

    def test_real_store_load_partial_write_and_quiesce_persist(self):
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                                  initialization_seed=9, max_initialized_bytes=0x30000)
        # s1=RAM; store42, load, increment, store43, partial store low byte44, loop.
        program = (0x000204b7, 0x02a00113, 0x0024a023, 0x0004a183,
                   0x00118193, 0x0034a023, 0x02c00213, 0x00448023, 0x0000006f)
        memory.preload(0x10000, b''.join(word.to_bytes(4, 'little') for word in program))
        router = DataflowRouter((DeviceWindow('dummy', 0x40000000, 0x1000, Target()),))
        cpu = GeneratedCve2Session(self.artifact, base_dir=Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', ROOT)),
            cache_dir=Path(self.directory.name)/'cache', memory=memory, router=router)
        cpu._binary = self.binary
        cpu.begin_case('actual-obi-memory')
        try:
            observed = []
            for _ in range(1000):
                observed.append(cpu.step_local({'irq': 0}))
                if cpu.memory_write_count == 3:
                    break
            self.assertEqual(3, cpu.memory_write_count)
            self.assertEqual(44, memory.read(0x20000, 4, transaction_id='acceptance-check').value)
            writes = [item for item in cpu.service.events if item['kind'] == 'memory_write']
            self.assertEqual([15, 15, 1], [item['byte_enable'] for item in writes])
            self.assertTrue(any(item['data_rsp_rdata'] == 42 for item in observed))
            mapping = {row['physical_port']: row['runtime_name'] for row in
                       self.artifact.runtime_document['physical_exports']}
            for output in observed:
                for alias in ('rvfi_intr', 'rvfi_pc_rdata'):
                    self.assertEqual(output['physical_observations'][mapping[alias]], output[alias])
                self.assertNotIn('irq_masked_pre', output)
                self.assertNotIn('irq_taken_pre', output)
            self.assertTrue(all(item['transaction']['source_component'] == 'cpu_real' for item in writes))
            before = cpu.local_ticks
            cpu.begin_quiesce()
            for _ in range(8):
                cpu.step_local({})
            self.assertEqual(0, cpu.pending_responses)
            self.assertEqual(44, memory.read(0x20000, 4, transaction_id='acceptance-check').value)
            self.assertEqual(before + 8, cpu.local_ticks)
            lifetime = cpu.local_ticks
            cpu.reset_local()
            self.assertEqual(lifetime, cpu.local_ticks)
            self.assertEqual(44, memory.read(0x20000, 4, transaction_id='reset-check').value)
            first = cpu.step_local({})
            self.assertEqual(0x10000, first['instr_addr'])
            self.assertEqual(1, cpu.reset_epoch)
            self.assertEqual(1, cpu.service.events[-1]['transaction']['source_epoch'])
            self.assertEqual(lifetime + 1, cpu.local_ticks)
        finally:
            cpu.end_case()


if __name__ == '__main__':
    unittest.main()
