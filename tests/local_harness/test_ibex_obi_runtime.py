"""A second pinned CPU RTL reuses the generated OBI protocol path."""

from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[2]
IBEX_PROFILE = 'configs/cpus/ibex_obi_local/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'
PROGRAM = (0x000204b7, 0x02a00113, 0x0024a023, 0x0004a183,
           0x00118193, 0x0034a023, 0x02c00213, 0x00448023,
           0x0000006f)
PROGRAM_HEX = ''.join(word.to_bytes(4, 'little').hex() for word in PROGRAM)


def artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    source = verify_local_source_lock(plan.profile, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan, structural, source,
        base_dir=ROOT), base_dir=ROOT)


class IbexObiRuntimeAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-ibex-obi-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.cpu_artifact = artifact(IBEX_PROFILE, 'cpu')
        cls.gpio_artifact = artifact(GPIO_PROFILE, 'gpio')
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)

    def test_full_top_source_facts_and_real_program(self):
        runtime = self.cpu_artifact.runtime_document
        self.assertEqual('obi_cpu', runtime['kind'])
        self.assertEqual(66, len(self.cpu_artifact.plan.facts.ports))
        self.assertEqual(23, len(runtime['physical_exports']))
        self.assertEqual(20, len(runtime['backend_ports']))
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
            initialization_seed=9, max_initialized_bytes=0x30000)
        memory.preload(0x10080, bytes.fromhex(PROGRAM_HEX))

        class UnusedTarget:
            def read_register(self, offset):
                raise AssertionError('unexpected MMIO read')
            def write_register(self, offset, value, *, be=15):
                raise AssertionError('unexpected MMIO write')

        router = DataflowRouter((DeviceWindow('unused', 0x40000000, 0x1000,
                                              UnusedTarget()),))
        cpu = GeneratedCve2Session(self.cpu_artifact, base_dir=ROOT,
            cache_dir=self.cache, memory=memory, router=router)
        cpu.begin_case('ibex-real-obi-program')
        try:
            outputs = []
            for _ in range(100):
                outputs.append(cpu.step_local({'irq': 0}))
                if cpu.memory_write_count == 3:
                    break
        finally:
            cpu.end_case()
        self.assertEqual(3, cpu.memory_write_count)
        self.assertEqual(0x10080, next(row['instr_addr'] for row in outputs
                         if row['instr_req_accepted']))
        self.assertTrue(any(row['data_req_accepted'] and not row['data_write']
                            for row in outputs))
        self.assertTrue(any(row['data_rsp_rdata'] == 42 for row in outputs))
        self.assertEqual(44, memory.read(0x20000, 4,
                         transaction_id='ibex-acceptance').value)
        writes = [row for row in cpu.service.events if row['kind'] == 'memory_write']
        self.assertEqual([15, 15, 1], [row['byte_enable'] for row in writes])
        self.assertEqual({'cpu'}, {row['transaction']['source_component']
                         for row in writes})

    def test_budgeted_bundle_replays_fresh_ibex_rtl(self):
        instances = []

        def factory():
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                initialization_seed=9, max_initialized_bytes=0x30000)
            gpio = GeneratedPulpGpioSession(self.gpio_artifact, base_dir=ROOT,
                cache_dir=self.cache)
            router = DataflowRouter((DeviceWindow('gpio', 0x40000000,
                                                  0x1000, gpio),))
            cpu = GeneratedCve2Session(self.cpu_artifact, base_dir=ROOT,
                cache_dir=self.cache, memory=memory, router=router)
            runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                ownership=compile_ownership((), ()), bindings=())
            instances.append((runner, cpu, memory))
            return runner

        case = ScenarioGenome(testcase_id='ibex-obi-saved-evidence',
            direction='CPU_TO_IP', path_id='obi-memory',
            schedule_order=('cpu', 'gpio'), max_steps=50, actions=(),
            initial_images=(MemoryImage('program', 'cpu', 0x10080, PROGRAM_HEX),))
        bundle = Path(self.directory.name) / 'evidence'
        trace = save_evidence_bundle(case, factory, bundle,
            budget=ResourceBudget(max_wall_time_ms=90000,
                                  max_materialized_bytes_per_memory=0x30000))
        self.assertEqual('complete', trace.status)
        self.assertEqual(44, instances[0][2].read(0x20000, 4,
                         transaction_id='saved-check').value)
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertEqual('obi_cpu', manifest['sessions']['cpu']['identity']
                         ['runtime_artifact']['kind'])
        self.assertEqual('ibex_obi_local', manifest['sessions']['cpu']['identity']
                         ['runtime_artifact']['plan']['component_id'])
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay)
        self.assertEqual(44, instances[1][2].read(0x20000, 4,
                         transaction_id='replay-check').value)
        self.assertNotEqual(instances[0][1]._execution, instances[1][1]._execution)
