"""Real PicoRV32 Wishbone master -> WBUART SETUP target, one case."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedWishboneRegisterSession,
    compile_generated_register_ownership, load_local_harness_request,
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


def _cpu_program(value):
    address_high = 0x60000
    result_high = 0
    return fragment_bytes((
        Rv32iInstruction('LUI', rd=2, immediate=address_high),
        Rv32iInstruction('ADDI', rd=2, rs1=2, immediate=0),
        Rv32iInstruction('LUI', rd=3, immediate=0),
        Rv32iInstruction('ADDI', rd=3, rs1=3, immediate=value),
        Rv32iInstruction('SW', rs1=2, rs2=3),
        Rv32iInstruction('LW', rd=4, rs1=2),
        Rv32iInstruction('LUI', rd=5, immediate=result_high),
        Rv32iInstruction('ADDI', rd=5, rs1=5, immediate=0x100),
        Rv32iInstruction('SW', rs1=5, rs2=4),
        *(Rv32iInstruction('NOP') for _ in range(4))))


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class WishboneCpuToSetupRealTests(unittest.TestCase):
    def test_cpu_writes_and_reads_setup_through_router(self):
        target_artifact = _artifact(TARGET_PROFILE, 'peripheral')
        cpu_artifact = _artifact(CPU_PROFILE, 'processor')
        self.assertEqual('wishbone_register_observe',
                         target_artifact.runtime_document['kind'])
        self.assertEqual('wishbone_cpu', cpu_artifact.runtime_document['kind'])
        with tempfile.TemporaryDirectory(prefix='wishbone-cpu-setup-') as directory:
            cache = Path(directory)
            memory = PersistentMemory(
                regions=(MemoryRegion('ram', 0, 0x1000),),
                initialization_seed=1, max_initialized_bytes=0x1000)
            memory.preload(0, _cpu_program(0x55))
            target = GeneratedWishboneRegisterSession(
                target_artifact, base_dir=ROOT, cache_dir=cache / 'target',
                setup_writes=(), probe_offsets=())
            target.begin_case('wishbone-cpu-setup')
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
            cpu.begin_case('wishbone-cpu-setup')
            try:
                for _ in range(400):
                    cpu.step_local({})
                    if router.pending_targets:
                        router.drain_one('peripheral')
                    if memory.read(0x100, 4,
                                   transaction_id='probe').value == 0x55:
                        break
                for _ in range(8):
                    cpu.step_local({})
                    if router.pending_targets:
                        router.drain_one('peripheral')
            finally:
                cpu.end_case()
                target.end_case()
            self.assertEqual(1, cpu.mmio_write_count)
            self.assertEqual(1, cpu.mmio_read_count)
            self.assertEqual(0, cpu.pending_responses)
            writes = [row for row in calls if row[0] == 'write']
            reads = [row for row in calls if row[0] == 'read']
            self.assertEqual(1, len(writes), calls)
            self.assertEqual(1, len(reads), calls)
            self.assertEqual((0, 0x55, 15), writes[0][1:])
            self.assertEqual((0, 0x55, 15), reads[0][1:])
            self.assertEqual(0x55,
                memory.read(0x100, 4, transaction_id='result').value)


if __name__ == '__main__':
    unittest.main()
