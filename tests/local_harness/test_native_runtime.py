from dataclasses import replace
import unittest
from myfuzz.local_harness import render_local_harness,render_local_runtime,verify_local_source_lock
from tests.local_harness.test_renderer import real_plan,ROOT

class NativeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan=real_plan('configs/cpus/picorv32/component_profile.json','native_cpu')

    def test_real_native_runtime_top_retains_completion_identity(self):
        plan=self.plan
        artifact=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        self.assertEqual(artifact.runtime_document['kind'],'native_memory_cpu')
        self.assertEqual(artifact.runtime_document['selected_template']['contract']['template_id'],'cpu.native-memory')
        self.assertIn('native_completion_memory_adapter',artifact.runtime_sv)
        self.assertNotIn('ready_valid_processor_memory_adapter',artifact.runtime_sv)

    def test_native_driver_contains_bounded_memory_operation(self):
        from myfuzz.local_harness.driver_renderer import render_local_driver
        plan=self.plan
        top=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        artifact=render_local_driver(top,base_dir=ROOT)
        self.assertIn('STEP_MEMORY',artifact.cpp_text)
        self.assertEqual(artifact.runtime_document['driver_limits']['max_samples_per_command'],1)

    def test_formal_manifest_requires_native_service_identity(self):
        from pathlib import Path
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
        from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        from myfuzz.scenario.contracts import ScenarioManifest,ResourceBudget
        plan=self.plan
        a=render_local_driver(render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),initialization_seed=7,max_initialized_bytes=4096)
        session=GeneratedNativeMemorySession(a,base_dir=ROOT,cache_dir=Path('/tmp/unused-native'),memory=memory)
        identity=ScenarioRunner(sessions={'native_cpu':session},ownership=compile_ownership((),()),bindings=()).identity_document()
        sid=identity['sessions']['native_cpu']['identity']
        self.assertEqual(sid['native_service_schema_version'],'generated_native_memory_service.v1')
        self.assertEqual(sid['memory_policy'],'ram-rom-only')
        timing=dict(schema_version='generated_local_reset.v1',artifact_digest=a.runtime_document['artifact_digest'],
                    driver_sha256=a.runtime_document['cpp_sha256'],hold_cycles=8,release_cycles=8)
        def manifest(doc):return ScenarioManifest.from_runner_identity(doc,scenario_id='native',schedule_order=('native_cpu',),
            scheduler_policy_id='stable-local-v1',budget=ResourceBudget(),reset_timings={'native_cpu':timing})
        manifest(identity)
        import copy
        for key in ('native_service_schema_version','source_component','memory_policy'):
            changed=copy.deepcopy(identity);changed['sessions']['native_cpu']['identity'][key]='changed'
            with self.subTest(key=key),self.assertRaises(ValueError):manifest(changed)

    def test_generated_native_evidence_has_audited_budget_bounds(self):
        from pathlib import Path
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.native_session import GeneratedNativeMemorySession
        from myfuzz.scenario.evidence import _evidence_record_bound, _final_state_growth_bound
        from myfuzz.scenario.genome import ScenarioGenome
        from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        from myfuzz.scenario.contracts import ResourceBudget
        plan=self.plan
        a=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
            verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),
            initialization_seed=7,max_initialized_bytes=4096)
        session=GeneratedNativeMemorySession(a,base_dir=ROOT,cache_dir=Path('/tmp/unused-native'),memory=memory)
        runner=ScenarioRunner(sessions={'native_cpu':session},ownership=compile_ownership((),()),bindings=())
        genome=ScenarioGenome(testcase_id='native-budget',direction='CPU_TO_IP',
            path_id='native-memory',schedule_order=('native_cpu',),max_steps=1,actions=())
        self.assertGreater(_final_state_growth_bound(genome,runner,ResourceBudget()),0)
        self.assertGreater(_evidence_record_bound(genome,runner,ResourceBudget()),
                           4*a.runtime_document['driver_limits']['reply_reservation_bytes'])

    def test_missing_or_contradictory_typed_native_facts_refused(self):
        from myfuzz.local_harness.native_contract import native_completion_contract
        caps=dict(self.plan.profile.capabilities)
        endpoint=next(e for e in self.plan.binding.endpoints if e.protocol is not None)
        for key in ('completion_semantics','address_units','error_response','address_width','data_width','byte_enable','max_outstanding'):
            altered=dict(caps);altered.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):native_completion_contract(endpoint,altered)
        for key,value in [('completion_semantics','acceptance'),('address_units','word'),('error_response',True),('address_width',64)]:
            altered=dict(caps);altered[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):native_completion_contract(endpoint,altered)

    def test_reset_release_cannot_exhaust_native_wait_before_ready(self):
        plan=replace(self.plan,request=replace(self.plan.request,reset_release_ticks=17))
        with self.assertRaisesRegex(ValueError,'reset-release'):
            render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
