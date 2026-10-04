"""The five generated CPU protocol paths follow pinned facts and instance IDs."""
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
VARIANTS = (
    ('obi_cpu', 'cv32e20', 'reuse_obi', 8, 8, 16),
    ('native_memory_cpu', 'picorv32', 'reuse_native', 8, 8, 16),
    ('wishbone_cpu', 'picorv32_wb', 'reuse_wishbone', 8, 8, 16),
    ('axi4_lite_cpu', 'picorv32_axi', 'reuse_axi_lite', 8, 8, 16),
    ('axi4_cpu', 'zipaxi', 'reuse_axi4', 16, 20, 32),
)


def artifact(row):
    kind, profile, instance, asserted, released, waited = row
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=f'configs/cpus/{profile}/component_profile.json',
        instance_id=instance, reset_assert_ticks=asserted,
        reset_release_ticks=released, max_wait_cycles=waited))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class CpuProtocolReuse(unittest.TestCase):
    def test_each_protocol_generates_from_renamed_instance(self):
        for row in VARIANTS:
            with self.subTest(kind=row[0]):
                generated = artifact(row)
                self.assertEqual(row[0], generated.runtime_document['kind'])
                self.assertEqual('local_runtime_' + row[2],
                                 generated.runtime_document['module_name'])
                self.assertEqual(row[2], generated.plan.request.instance_id)
                self.assertEqual('driver_generated', generated.runtime_document['status'])
                self.assertEqual('source_verified',
                    generated.runtime_document['source_verification']['source_status'])
                self.assertEqual('elaboration_verified',
                    generated.runtime_document['source_verification']['elaboration_status'])

    def test_renamed_wishbone_cpu_executes_with_profile_selected_instruction_pin(self):
        generated = artifact(VARIANTS[2])
        marker = generated.runtime_document['instruction_identity_observation']
        row = next(item for item in generated.runtime_document['physical_exports']
                   if item['runtime_name'] == marker)
        self.assertEqual('mem_instr', row['physical_port'])
        self.assertEqual('observe', row['disposition'])
        with tempfile.TemporaryDirectory(prefix='myfuzz-wb-reuse-') as directory:
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                initialization_seed=1, max_initialized_bytes=4096)
            # lw x1,0x20(x0); sw x1,0x24(x0); jal x0,0
            memory.preload(0, bytes.fromhex('83200002232210026f000000'))
            memory.preload(0x20, bytes.fromhex('78563412'))
            class UnusedTarget:
                def read_register(self, offset):
                    raise AssertionError('unexpected MMIO read')
                def write_register(self, offset, value, *, be):
                    raise AssertionError('unexpected MMIO write')
            router = DataflowRouter((DeviceWindow('unused', 0x40000000,
                4096, UnusedTarget()),))
            cpu = GeneratedWishboneCpuSession(generated, base_dir=ROOT,
                cache_dir=Path(directory), memory=memory, router=router)
            cpu.begin_case('renamed-wishbone-program')
            try:
                outputs = [cpu.step_local({}) for _ in range(100)]
            finally:
                cpu.end_case()
            self.assertTrue(any(row['instr_req_accepted'] for row in outputs))
            self.assertTrue(any(row['data_req_accepted'] and row['data_write']
                                for row in outputs))
            self.assertEqual(0x12345678,
                memory.read(0x24, 4, transaction_id='verify').value)
            self.assertEqual('reuse_wishbone', cpu.source_component)


if __name__ == '__main__':
    unittest.main()
