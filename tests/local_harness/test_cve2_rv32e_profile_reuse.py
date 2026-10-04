"""A CVE2 parameter variant executes through the unchanged generated OBI path."""

from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, verify_local_source_lock,
)
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
PROFILE = 'configs/cpus/cv32e20_rv32e/component_profile.json'
PROGRAM = (0x000204b7, 0x02a00113, 0x0024a023, 0x0004a183,
           0x00118193, 0x0034a023, 0x02c00213, 0x00448023,
           0x0000006f)
PROGRAM_HEX = ''.join(word.to_bytes(4, 'little').hex() for word in PROGRAM)


class Cve2Rv32eProfileReuse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        request = load_local_harness_request(dict(
            schema_version='local_harness.v1', profile_path=PROFILE,
            instance_id='rv32e_cpu', reset_assert_ticks=8,
            reset_release_ticks=8, max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        cls.artifact = render_local_driver(render_local_runtime(
            plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT),
            base_dir=ROOT), base_dir=ROOT)
        gpio_request = load_local_harness_request(dict(
            schema_version='local_harness.v1',
            profile_path='configs/peripherals/pulp_gpio/component_profile.json',
            instance_id='gpio', reset_assert_ticks=8,
            reset_release_ticks=8, max_wait_cycles=16))
        gpio_plan = plan_local_harness(gpio_request, base_dir=ROOT)
        cls.gpio_artifact = render_local_driver(render_local_runtime(
            gpio_plan, render_local_harness(gpio_plan),
            verify_local_source_lock(gpio_plan.profile, base_dir=ROOT),
            base_dir=ROOT), base_dir=ROOT)
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-cve2-rv32e-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        build_local_harness(cls.artifact, base_dir=ROOT, cache_dir=cls.cache)

    def test_parameter_profile_executes_and_replays_real_rtl(self):
        self.assertEqual('obi_cpu', self.artifact.runtime_document['kind'])
        self.assertEqual('cv32e20_rv32e', self.artifact.plan.profile.component_id)
        parameters = self.artifact.plan.profile.source.elaboration.parameters
        self.assertTrue(any(name == 'RV32E' and value == '1'
                            for name, value in parameters))
        instances = []

        def factory():
            memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x30000),),
                initialization_seed=9, max_initialized_bytes=0x30000)

            gpio = GeneratedPulpGpioSession(self.gpio_artifact, base_dir=ROOT,
                cache_dir=self.cache)
            router = DataflowRouter((DeviceWindow('gpio', 0x40000000,
                                                  0x1000, gpio),))
            cpu = GeneratedCve2Session(self.artifact, base_dir=ROOT,
                cache_dir=self.cache, memory=memory, router=router)
            runner = ScenarioRunner(sessions={'rv32e_cpu': cpu, 'gpio': gpio},
                ownership=compile_ownership((), ()), bindings=())
            instances.append((cpu, memory))
            return runner

        case = ScenarioGenome(testcase_id='cve2-rv32e-profile-only',
            direction='CPU_TO_IP', path_id='obi-memory',
            schedule_order=('rv32e_cpu', 'gpio'), max_steps=50, actions=(),
            initial_images=(MemoryImage('program', 'rv32e_cpu', 0x10000,
                                        PROGRAM_HEX),))
        bundle = Path(self.directory.name) / 'evidence'
        trace = save_evidence_bundle(case, factory, bundle,
            budget=ResourceBudget(max_wall_time_ms=90000,
                                  max_materialized_bytes_per_memory=0x30000))
        self.assertEqual('complete', trace.status, trace.events[-5:])
        self.assertEqual(44, instances[0][1].read(0x20000, 4,
                         transaction_id='saved-check').value)
        writes = [row for row in instances[0][0].service.events
                  if row['kind'] == 'memory_write']
        self.assertEqual([15, 15, 1], [row['byte_enable'] for row in writes])
        manifest = json.loads((bundle / 'manifest.json').read_text())
        self.assertEqual('cv32e20_rv32e', manifest['sessions']['rv32e_cpu']
                         ['identity']['runtime_artifact']['plan']['component_id'])
        replay = replay_evidence_bundle(bundle, factory)
        self.assertTrue(replay.matches, replay)
        self.assertEqual(44, instances[1][1].read(0x20000, 4,
                         transaction_id='replay-check').value)
        self.assertIsNot(instances[0][0]._execution, instances[1][0]._execution)


if __name__ == '__main__':
    unittest.main()
