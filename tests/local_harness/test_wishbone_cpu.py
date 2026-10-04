"""Pinned PicoRV32 Wishbone CPU completes measured memory transactions."""
from pathlib import Path
import copy
import json
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.build import build_local_harness
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/cpus/picorv32_wb/component_profile.json'


def cpu_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=PROFILE, instance_id='cpu_wb', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def gpio_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/pulp_gpio/component_profile.json',
        instance_id='gpio', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


class WishboneCpuAcceptance(unittest.TestCase):
    def test_generated_wishbone_evidence_has_driver_derived_bounds(self):
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.scenario.contracts import ResourceBudget
        from myfuzz.scenario.evidence import _evidence_record_bound, _final_state_growth_bound
        from myfuzz.scenario.genome import ScenarioGenome
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        artifact = cpu_artifact()
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                                  initialization_seed=3, max_initialized_bytes=4096)
        gpio = GeneratedPulpGpioSession(gpio_artifact(), base_dir=ROOT,
            cache_dir=ROOT/'unused')
        cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT,
            cache_dir=ROOT/'unused', memory=memory,
            router=DataflowRouter((DeviceWindow('gpio',0x40000000,4096,gpio),)))
        runner = ScenarioRunner(sessions={'cpu': cpu,'gpio':gpio},
            ownership=compile_ownership((),()), bindings=())
        genome = ScenarioGenome(testcase_id='wishbone-budget',direction='CPU_TO_IP',
            path_id='memory',schedule_order=('cpu','gpio'),max_steps=1,actions=())
        self.assertGreater(_final_state_growth_bound(genome, runner, ResourceBudget()), 0)
        self.assertGreater(_evidence_record_bound(genome, runner, ResourceBudget()),
            4 * artifact.runtime_document['driver_limits']['reply_reservation_bytes'])

    def test_formal_identity_and_published_manifest_schema(self):
        import jsonschema
        from myfuzz.scenario.contracts import ScenarioManifest, ResourceBudget, _verify_generated_session
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        artifact = cpu_artifact()
        gpio_art = gpio_artifact()
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                                  initialization_seed=3, max_initialized_bytes=4096)
        gpio = GeneratedPulpGpioSession(gpio_art, base_dir=ROOT, cache_dir=ROOT/'unused')
        router = DataflowRouter((DeviceWindow('gpio', 0x40000000, 4096, gpio),))
        cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT, cache_dir=ROOT/'unused',
                                          memory=memory, router=router)
        sid = cpu.identity_document()
        self.assertEqual(artifact, _verify_generated_session(sid))
        for field, value in [('cpu_service_schema_version', 'forged'),
                             ('source_component', 'other'), ('defer_mmio', 'yes')]:
            changed = copy.deepcopy(sid)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                _verify_generated_session(changed)
        runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                                ownership=compile_ownership((),()), bindings=())
        identity = runner.identity_document()
        reset = artifact.runtime_document['driver_reset']
        timing = dict(schema_version='generated_local_reset.v1',
                      artifact_digest=artifact.runtime_document['artifact_digest'],
                      driver_sha256=artifact.runtime_document['cpp_sha256'],
                      hold_cycles=reset['reset_assert_ticks'],
                      release_cycles=reset['reset_release_ticks'])
        gpio_reset = gpio_art.runtime_document['driver_reset']
        gpio_timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=gpio_art.runtime_document['artifact_digest'],
            driver_sha256=gpio_art.runtime_document['cpp_sha256'],
            hold_cycles=gpio_reset['reset_assert_ticks'],
            release_cycles=gpio_reset['reset_release_ticks'])
        def manifest(value):
            return ScenarioManifest.from_runner_identity(value, scenario_id='wishbone-identity',
                schedule_order=('cpu','gpio'), scheduler_policy_id='stable-local-v1',
                budget=ResourceBudget(), reset_timings={'cpu': timing,'gpio':gpio_timing})
        accepted = manifest(identity)
        schema = json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema = json.loads((ROOT/'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget'] = budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs', {}))
        jsonschema.Draft202012Validator(schema).validate(accepted.to_document())
        bad = copy.deepcopy(identity)
        bad['sessions']['cpu']['type'] = 'myfuzz.local_harness.native_session.GeneratedNativeMemorySession'
        with self.assertRaisesRegex(ValueError, 'type disagrees'):
            manifest(bad)

    def test_source_facts_drive_single_classic_wishbone_boundary(self):
        artifact = cpu_artifact()
        self.assertEqual('wishbone_cpu', artifact.runtime_document['kind'])
        self.assertEqual([], artifact.runtime_document['adapter_sources'])
        backend = {row['name']: row for row in artifact.runtime_document['backend_ports']}
        self.assertEqual({'wb_cyc', 'wb_stb', 'wb_we', 'wb_adr', 'wb_dat_w',
                          'wb_sel', 'wb_ack', 'wb_dat_r'}, set(backend))
        self.assertEqual({'wb_ack', 'wb_dat_r'},
                         {name for name, row in backend.items() if row['direction'] == 'input'})
        self.assertEqual(1, artifact.runtime_sv.count(' u_component ('))
        self.assertEqual(1, artifact.structural.wrapper_sv.count(' u_dut ('))
        self.assertIn('third_party/picorv32_upstream_reference/picorv32.v',
                      artifact.structural.build_document['source_files'])

    def test_real_cpu_fetch_and_data_write_complete_through_persistent_memory(self):
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        artifact = cpu_artifact()
        with tempfile.TemporaryDirectory(prefix='myfuzz-wb-') as directory:
            cache = Path(directory)
            build_local_harness(artifact, base_dir=ROOT, cache_dir=cache)
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                initialization_seed=1, max_initialized_bytes=0x1000)
            # lw x1, 0x20(x0); sw x1, 0x24(x0); jal x0, 0
            memory.preload(0, bytes.fromhex('83200002 23221002 6f000000'.replace(' ', '')))
            memory.preload(0x20, bytes.fromhex('78563412'))
            class UnusedTarget:
                def read_register(self, offset):
                    raise AssertionError('unexpected MMIO read')
                def write_register(self, offset, value, *, be):
                    raise AssertionError('unexpected MMIO write')
            router = DataflowRouter((DeviceWindow('unused', 0x40000000, 0x1000, UnusedTarget()),))
            cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT, cache_dir=cache,
                memory=memory, router=router)
            cpu.begin_case('wishbone-program')
            try:
                outputs = [cpu.step_local({}) for _ in range(100)]
            finally:
                cpu.end_case()
            self.assertTrue(any(row['instr_req_accepted'] for row in outputs))
            self.assertTrue(any(row['data_req_accepted'] and row['data_write'] for row in outputs))
            self.assertEqual(0x12345678,
                memory.read(0x24, 4, transaction_id='acceptance').value)
            self.assertEqual(0, cpu.pending_responses)
            self.assertEqual(1, cpu.memory_write_count)

    def test_real_cpu_deferred_mmio_ack_waits_for_target(self):
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        artifact = cpu_artifact()
        with tempfile.TemporaryDirectory(prefix='myfuzz-wb-mmio-') as directory:
            cache = Path(directory)
            build_local_harness(artifact, base_dir=ROOT, cache_dir=cache)
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                initialization_seed=2, max_initialized_bytes=0x1000)
            # lw x1,0x20(x0); lui x2,0x40000; sw x1,0(x2); jal x0,0
            memory.preload(0, bytes.fromhex('83200002 37010040 23201100 6f000000'.replace(' ', '')))
            memory.preload(0x20, bytes.fromhex('efbeadde'))
            class Target:
                def __init__(self):
                    self.writes = []
                def write_register(self, offset, value, *, be):
                    self.writes.append((offset, value, be))
                def read_register(self, offset):
                    raise AssertionError('unexpected MMIO read')
            target = Target()
            router = DataflowRouter((DeviceWindow('target', 0x40000000, 0x1000, target),))
            cpu = GeneratedWishboneCpuSession(artifact, base_dir=ROOT, cache_dir=cache,
                memory=memory, router=router)
            cpu.begin_case('wishbone-mmio')
            try:
                reset_queued = False
                for _ in range(140):
                    cpu.step_local({})
                    if router.pending_targets:
                        self.assertEqual([], target.writes)
                        self.assertEqual(1, cpu.pending_responses)
                        if not reset_queued:
                            cancelled = cpu.reset_local()
                            self.assertEqual(1, cancelled['cancelled_responses'])
                            self.assertEqual((), router.pending_targets)
                            self.assertEqual(0xdeadbeef,
                                memory.read(0x20, 4, transaction_id='reset-check').value)
                            reset_queued = True
                        else:
                            router.drain_one('target')
            finally:
                cpu.end_case()
            self.assertTrue(reset_queued)
            self.assertEqual(1, cpu.reset_epoch)
            self.assertEqual([(0, 0xdeadbeef, 15)], target.writes)
            self.assertEqual(1, cpu.mmio_write_count)

    def test_formal_saved_bundle_replays_fresh_wishbone_rtl(self):
        from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
        from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        cpu_art = cpu_artifact()
        gpio_art = gpio_artifact()
        with tempfile.TemporaryDirectory(prefix='myfuzz-wb-evidence-') as directory:
            root = Path(directory)
            instances = []
            def factory():
                memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                    initialization_seed=4, max_initialized_bytes=4096)
                gpio = GeneratedPulpGpioSession(gpio_art, base_dir=ROOT, cache_dir=root/'cache')
                router = DataflowRouter((DeviceWindow('gpio', 0x40000000, 4096, gpio),))
                cpu = GeneratedWishboneCpuSession(cpu_art, base_dir=ROOT, cache_dir=root/'cache',
                    memory=memory, router=router)
                runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                    ownership=compile_ownership((),()), bindings=())
                instances.append((runner, cpu, memory))
                return runner
            # lw x1,0x20(x0); sw x1,0x24(x0); jal x0,0
            program = '83200002232210026f000000'
            case = ScenarioGenome(testcase_id='wishbone-saved-evidence', direction='CPU_TO_IP',
                path_id='wishbone-memory', schedule_order=('cpu','gpio'), max_steps=100, actions=(),
                initial_images=(MemoryImage('program','cpu',0,program),
                                MemoryImage('data','cpu',0x20,'78563412')))
            bundle = root/'evidence'
            trace = save_evidence_bundle(case, factory, bundle)
            self.assertEqual('complete', trace.status)
            self.assertEqual(0x12345678,
                instances[0][2].read(0x24, 4, transaction_id='saved-check').value)
            self.assertEqual('wishbone_cpu', json.loads((bundle/'manifest.json').read_text())
                             ['sessions']['cpu']['identity']['runtime_artifact']['kind'])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(0x12345678,
                instances[1][2].read(0x24, 4, transaction_id='replay-check').value)
            self.assertNotEqual(instances[0][1]._execution, instances[1][1]._execution)


if __name__ == '__main__':
    unittest.main()
