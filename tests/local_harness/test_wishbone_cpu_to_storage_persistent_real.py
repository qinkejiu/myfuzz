"""Real PicoRV32 -> WBUART SETUP persistent writes and fresh reproduction."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedWishboneRegisterSession, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.rv32i_sources import Rv32iInstruction, fragment_bytes

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32_wb/component_profile.json'
TARGET_PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
VALUES = (0x55, 0xAA, 0x12345678)


def _artifact(profile, instance_id):
    if profile == TARGET_PROFILE:
        request = load_local_harness_request(dict(
            schema_version='local_harness.v2', profile_path=profile,
            instance_id=instance_id, reset_assert_ticks=2,
            reset_release_ticks=2, max_wait_cycles=16,
            tuning={'endpoint_policies': [dict(
                endpoint_id='uart.bus', template_id='target.wishbone',
                template_version='1', variant_id='word-addressed-registered-ack',
                max_outstanding=1)],
                'fixed_inputs': [
                    dict(endpoint_id='uart.pins', role='rx', value=1),
                    dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))
    else:
        request = load_local_harness_request(dict(
            schema_version='local_harness.v1', profile_path=profile,
            instance_id=instance_id, reset_assert_ticks=2,
            reset_release_ticks=2, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _program(values):
    instructions = []
    for index, value in enumerate(values):
        result = 0x100 + index * 4
        high = (value + 0x800) >> 12
        low = ((value & 0xfff) + 0x800) % 0x1000 - 0x800
        instructions.extend((
            Rv32iInstruction('LUI', rd=2, immediate=0x60000),
            Rv32iInstruction('ADDI', rd=2, rs1=2, immediate=0),
            Rv32iInstruction('LUI', rd=3, immediate=high),
            Rv32iInstruction('ADDI', rd=3, rs1=3, immediate=low),
            Rv32iInstruction('SW', rs1=2, rs2=3),
            Rv32iInstruction('LW', rd=4, rs1=2),
            Rv32iInstruction('LUI', rd=5, immediate=0),
            Rv32iInstruction('ADDI', rd=5, rs1=5, immediate=result),
            Rv32iInstruction('SW', rs1=5, rs2=4),
        ))
    instructions.extend(Rv32iInstruction('NOP') for _ in range(8))
    return fragment_bytes(tuple(instructions))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class WishbonePersistentSetupRealTests(unittest.TestCase):
    def _run(self, cache):
        target_artifact = _artifact(TARGET_PROFILE, 'peripheral')
        cpu_artifact = _artifact(CPU_PROFILE, 'processor')
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', 0, 0x1000),),
            initialization_seed=1, max_initialized_bytes=0x1000)
        memory.preload(0, _program(VALUES))
        target = GeneratedWishboneRegisterSession(
            target_artifact, base_dir=ROOT, cache_dir=cache / 'target',
            setup_writes=(), probe_offsets=())
        target.begin_case('wishbone-persistent')
        calls = []

        class RecordingTarget:
            def write_register(self, offset, value, *, be=15):
                calls.append(('write', offset, value, be))
                return target.write_register(offset, value, be=be)

            def read_register(self, offset):
                value = target.read_register(offset)
                calls.append(('read', offset, value & 0x7fffffff, 15))
                return value

        router = DataflowRouter((DeviceWindow(
            'peripheral', 0x60000000, 16, RecordingTarget()),))
        cpu = GeneratedWishboneCpuSession(
            cpu_artifact, base_dir=ROOT, cache_dir=cache / 'cpu',
            memory=memory, router=router, defer_mmio=True)
        cpu.begin_case('wishbone-persistent')
        pids = (cpu.process.pid, target.process.pid)
        try:
            for _ in range(1200):
                cpu.step_local({})
                if router.pending_targets:
                    router.drain_one('peripheral')
                values = [memory.read(0x100 + index * 4, 4,
                                      transaction_id=f'check-{index}').value
                          for index in range(len(VALUES))]
                if values == list(VALUES):
                    break
            for _ in range(8):
                cpu.step_local({})
                if router.pending_targets:
                    router.drain_one('peripheral')
        finally:
            cpu.end_case()
            target.end_case()
        results = [memory.read(0x100 + index * 4, 4,
                               transaction_id=f'result-{index}').value
                   for index in range(len(VALUES))]
        return calls, results, pids, cpu

    def test_three_persistent_writes_then_fresh_reproduction(self):
        with tempfile.TemporaryDirectory(prefix='wishbone-persistent-') as directory:
            cache = Path(directory)
            first = self._run(cache)
            second = self._run(cache)
        for calls, results, pids, cpu in (first, second):
            writes = [row for row in calls if row[0] == 'write']
            reads = [row for row in calls if row[0] == 'read']
            self.assertEqual(3, len(writes), calls)
            self.assertEqual(3, len(reads), calls)
            self.assertEqual(list(VALUES), [row[2] for row in writes])
            self.assertEqual(list(VALUES), [row[2] for row in reads])
            self.assertEqual(list(VALUES), results)
            self.assertEqual(3, cpu.mmio_write_count)
            self.assertEqual(3, cpu.mmio_read_count)
            self.assertEqual(0, cpu.pending_responses)
            self.assertIsNotNone(pids[0])
            self.assertIsNotNone(pids[1])
        self.assertNotEqual(first[2], second[2])
        self.assertEqual(list(VALUES), first[1])
        self.assertEqual(list(VALUES), second[1])


if __name__ == '__main__':
    unittest.main()
