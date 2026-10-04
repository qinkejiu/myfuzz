"""Generated PicoRV32 AXI4-Lite program with persistent RAM and fresh replay."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.contracts import ProtocolEnvironmentError
from tests.local_harness.test_renderer import ROOT, real_plan
from tests.integration.test_local_native_memory_generated_real import program


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1', 'actual RTL opt-in')
class AxiLiteProgramRealTests(unittest.TestCase):
    def test_actual_lite_program_persists_memory_and_replays_fresh(self):
        plan = real_plan('configs/cpus/picorv32_axi/component_profile.json', 'cpu')
        artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
        instances = []
        with TemporaryDirectory() as cache:
            def factory():
                memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                    initialization_seed=7, max_initialized_bytes=4096)
                cpu = GeneratedAxiLiteMemorySession(artifact, base_dir=ROOT,
                    cache_dir=Path(cache), memory=memory)
                runner = ScenarioRunner(sessions={'cpu': cpu}, ownership=compile_ownership((),()), bindings=())
                instances.append((cpu, memory))
                return runner
            genome = ScenarioGenome(testcase_id='axi-lite-two-rounds', direction='CPU_TO_IP',
                path_id='axi-lite-memory', schedule_order=('cpu',), max_steps=340, actions=(),
                initial_images=(MemoryImage('program','cpu',0,program()),
                    MemoryImage('state','cpu',256,'0500000000000000')))
            bundle = Path(cache) / 'axi-lite-evidence'
            trace = save_evidence_bundle(genome, factory, bundle)
            self.assertEqual(trace.status, 'complete', trace.status)
            self.assertTrue((bundle/'manifest.json').is_file())
            self.assertTrue((bundle/'observations.jsonl').is_file())
            cpu, memory = instances[0]
            self.assertEqual(memory.read(256,4,transaction_id='check').value, 7)
            self.assertEqual(memory.read(260,4,transaction_id='check').value, 7)
            self.assertEqual(cpu.memory_write_count, 4)
            self.assertIn(256, cpu.accepted_addresses)
            comparison = replay_evidence_bundle(bundle, factory)
            self.assertTrue(comparison.matches, comparison.difference_context)
            self.assertEqual(comparison.verification_scope, 'full')
            self.assertNotEqual(instances[0][0]._execution, instances[1][0]._execution)

    def test_unmapped_memory_terminates_without_axi_success(self):
        plan = real_plan('configs/cpus/picorv32_axi/component_profile.json', 'cpu')
        artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
        memory = PersistentMemory(regions=(MemoryRegion('ram',0,64),),
            initialization_seed=7,max_initialized_bytes=64)
        memory.preload(0, bytes.fromhex(program()))
        with TemporaryDirectory() as cache:
            cpu = GeneratedAxiLiteMemorySession(artifact, base_dir=ROOT,
                cache_dir=Path(cache), memory=memory)
            cpu.begin_case('axi-lite-unmapped')
            with self.assertRaisesRegex(ProtocolEnvironmentError, 'backend error without completion'):
                for _ in range(180):
                    cpu.step_local({})
            self.assertIsNone(cpu.process)
            self.assertEqual(cpu.memory_write_count, 0)
