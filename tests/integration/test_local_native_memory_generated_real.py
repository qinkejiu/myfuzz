"""Actual native completion CPU program, persistence and fresh replay."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from myfuzz.local_harness import render_local_harness,render_local_runtime,verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
from myfuzz.scenario.genome import MemoryImage,ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.evidence import save_evidence_bundle,replay_evidence_bundle
from myfuzz.scenario.contracts import ResourceBudget
from tests.local_harness.test_renderer import ROOT,real_plan

def program():
    words=[0x10000093]
    # Two load/increment/store/readback rounds, without restarting RTL.
    for _ in range(2): words += [0x0000a103,0x00110113,0x0020a023,0x0000a183,0x0030a223]
    words += [0x0000006f]
    return b''.join(x.to_bytes(4,'little') for x in words).hex()

def artifact():
    p=real_plan('configs/cpus/picorv32/component_profile.json','cpu')
    return render_local_driver(render_local_runtime(p,render_local_harness(p),verify_local_source_lock(p.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)

@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL')=='1','actual RTL opt-in')
class NativeProgramRealTests(unittest.TestCase):
    def test_actual_program_persistent_store_load_and_fresh_replay(self):
        a=artifact();instances=[]
        with TemporaryDirectory() as cache:
            def factory():
                memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),initialization_seed=7,max_initialized_bytes=4096)
                cpu=GeneratedNativeMemorySession(a,base_dir=ROOT,cache_dir=Path(cache),memory=memory)
                runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
                instances.append((runner,cpu,memory));return runner
            genome=ScenarioGenome(testcase_id='native-two-rounds',direction='CPU_TO_IP',path_id='native-memory',
                schedule_order=('cpu',),max_steps=240,actions=(),
                initial_images=(MemoryImage('program','cpu',0,program()),MemoryImage('state','cpu',256,'0500000000000000')))
            bundle=Path(cache)/'evidence'
            trace=save_evidence_bundle(genome,factory,bundle,
                budget=ResourceBudget(max_wall_time_ms=90000,
                                      max_materialized_bytes_per_memory=4096))
            self.assertEqual(trace.status,'complete',trace.status)
            memory=instances[0][2];cpu=instances[0][1]
            self.assertEqual(memory.read(256,4,transaction_id='check').value,7)
            self.assertEqual(memory.read(260,4,transaction_id='check').value,7)
            self.assertEqual(cpu.memory_write_count,4)
            self.assertEqual([(event['address'],event['value']) for event in cpu.service.events if event['kind']=='memory_write'],
                             [(256,6),(260,6),(256,7),(260,7)])
            self.assertEqual([event['value'] for event in cpu.service.events if event['kind']=='memory_read' and event['address']==256],
                             [5,6,6,7])
            self.assertIn(0,cpu.accepted_addresses)
            self.assertIn(256,cpu.accepted_addresses)
            self.assertGreater(cpu.native_instruction_fetch_count,0)
            comparison=replay_evidence_bundle(bundle,factory)
            self.assertTrue(comparison.matches,comparison.difference_context)
            self.assertEqual(instances[1][2].read(256,4,transaction_id='check').value,7)
            self.assertNotEqual(instances[0][1]._execution,instances[1][1]._execution)

    def test_unmapped_backend_error_terminates_without_fake_completion(self):
        from myfuzz.scenario.contracts import ProtocolEnvironmentError
        a=artifact()
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,64),),initialization_seed=7,max_initialized_bytes=64)
        memory.preload(0,bytes.fromhex(program()))
        with TemporaryDirectory() as cache:
            cpu=GeneratedNativeMemorySession(a,base_dir=ROOT,cache_dir=Path(cache),memory=memory)
            cpu.begin_case('native-unmapped')
            with self.assertRaisesRegex(ProtocolEnvironmentError,'backend error without completion'):
                for _ in range(100):cpu.step_local({})
            self.assertIsNone(cpu.process)
            self.assertEqual(cpu.memory_write_count,0)
