"""Real pinned CVA6 through a generated 64-bit AXI4 memory service."""
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.cva6_axi4_session import GeneratedCva6Axi4Session
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / 'third_party/docs/task-13/cva6-fixed/run/boot/boot.bin'


def store_load_program():
    # Pinned four-instruction boot prefix: t0=0x400, t1=0x600dcafe, sw t1,0(t0).
    # lw t2,0(t0); sw t2,4(t0); jal x0,0. The two stores must agree.
    return BOOT.read_bytes()[:16] + bytes.fromhex(
        '83a30200' '23a27200' '6f000000')


def artifact():
    request = load_local_harness_request({
        'schema_version': 'local_harness.v1',
        'profile_path': 'configs/cpus/cva6/component_profile.json',
        'instance_id': 'cva6',
        'reset_assert_ticks': 16,
        'reset_release_ticks': 20,
        'max_wait_cycles': 32,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class Cva6Axi4ServiceRealAcceptance(unittest.TestCase):
    def test_real_fetch_then_store_through_persistent_memory(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        driver = artifact()
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x20000),),
                                  initialization_seed=0, max_initialized_bytes=0x20000)
        memory.preload(0x10000, BOOT.read_bytes())
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-service-') as directory:
            cpu = GeneratedCva6Axi4Session(driver, base_dir=ROOT,
                cache_dir=Path(directory) / 'cache', memory=memory,
                command_timeout_seconds=60)
            cpu.begin_case('cva6-generated-store')
            try:
                for _ in range(800):
                    cpu.step_local({'irq_external': 0})
                    if cpu.write_beats:
                        break
                self.assertGreaterEqual(cpu.read_beats, 1)
                self.assertEqual(1, cpu.write_beats)
                self.assertEqual(0x600dcafe,
                    memory.read(0x400, 4, transaction_id='verify').value)
            finally:
                cpu.end_case()

    def test_store_load_store_and_fresh_evidence_replay(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        driver = artifact()
        with tempfile.TemporaryDirectory(prefix='myfuzz-cva6-replay-') as directory:
            path = Path(directory)
            instances = []

            def factory():
                memory = PersistentMemory(
                    regions=(MemoryRegion('ram', 0, 0x20000),),
                    initialization_seed=0, max_initialized_bytes=0x20000)
                cpu = GeneratedCva6Axi4Session(driver, base_dir=ROOT,
                    cache_dir=path / 'cache', memory=memory,
                    command_timeout_seconds=60)
                runner = ScenarioRunner(sessions={'cva6': cpu},
                    ownership=compile_ownership((), ()), bindings=())
                instances.append((cpu, memory))
                return runner

            case = ScenarioGenome(testcase_id='cva6-store-load-replay',
                direction='CPU_TO_IP', path_id='cva6-memory',
                schedule_order=('cva6',), max_steps=650, actions=(),
                initial_images=(MemoryImage('program', 'cva6', 0x10000,
                                            store_load_program().hex()),))
            bundle = path / 'evidence'
            trace = save_evidence_bundle(case, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=300000,
                    max_materialized_bytes_per_memory=0x20000))
            self.assertEqual('complete', trace.status)
            cpu, memory = instances[0]
            self.assertGreaterEqual(cpu.read_beats, 2)
            self.assertEqual(2, cpu.write_beats)
            self.assertEqual(0x600dcafe,
                memory.read(0x400, 4, transaction_id='saved-first').value)
            self.assertEqual(0x600dcafe,
                memory.read(0x404, 4, transaction_id='saved-readback').value)
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(0x600dcafe,
                instances[1][1].read(0x404, 4,
                                    transaction_id='replayed-readback').value)
            self.assertNotEqual(instances[0][0]._execution,
                                instances[1][0]._execution)


if __name__ == '__main__':
    unittest.main()
