import copy
import unittest
from pathlib import Path
from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import ScenarioManifest, ResourceBudget
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from myfuzz.scenario.router import DataflowRouter, DeviceWindow
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership
from tests.local_harness.test_renderer import real_plan, ROOT

class GeneratedLocalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        plan=real_plan('configs/peripherals/pulp_gpio/component_profile.json','gpio')
        top=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        cls.artifact=render_local_driver(top,base_dir=ROOT)
        cpu_plan=real_plan('configs/cpus/cv32e20/component_profile.json','cpu_0')
        cpu_top=render_local_runtime(cpu_plan,render_local_harness(cpu_plan),
            verify_local_source_lock(cpu_plan.profile,base_dir=ROOT),base_dir=ROOT)
        cls.cpu_artifact=render_local_driver(cpu_top,base_dir=ROOT)

    def test_generated_cpu_service_identity_is_verified(self):
        from myfuzz.scenario.contracts import _verify_generated_session
        gpio=GeneratedPulpGpioSession(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/contract-unused-cache'))
        router=DataflowRouter((DeviceWindow('gpio',0x40000000,0x1000,gpio),))
        memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),
                                initialization_seed=1,max_initialized_bytes=0x20000)
        cpu=GeneratedCve2Session(self.cpu_artifact,base_dir=ROOT,
            cache_dir=Path('/tmp/contract-unused-cache'),memory=memory,router=router)
        identity=cpu.identity_document()
        self.assertEqual(self.cpu_artifact,_verify_generated_session(identity))
        runner=ScenarioRunner(sessions={'cpu':cpu,'gpio':gpio},
            ownership=compile_ownership((),()),bindings=())
        manifest_identity=runner.identity_document()
        self.assertEqual('scenario_manifest_identity.v2',manifest_identity['schema_version'])
        cpu_doc=self.cpu_artifact.runtime_document
        cpu_timing=dict(schema_version='generated_local_reset.v1',
            artifact_digest=cpu_doc['artifact_digest'],driver_sha256=cpu_doc['cpp_sha256'],
            hold_cycles=cpu_doc['driver_reset']['reset_assert_ticks'],
            release_cycles=cpu_doc['driver_reset']['reset_release_ticks'])
        manifest=ScenarioManifest.from_runner_identity(manifest_identity,scenario_id='generated-cpu-contract',
            schedule_order=('cpu','gpio'),scheduler_policy_id='stable-local-v1',
            budget=ResourceBudget(),reset_timings={'cpu':cpu_timing,'gpio':self.timing()})
        import json
        import jsonschema
        schema=json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema=json.loads((ROOT/'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget']=budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs',{}))
        jsonschema.Draft202012Validator(schema).validate(manifest.to_document())
        for field,value in [('source_component','other'),('defer_mmio','yes'),
                            ('cpu_service_schema_version','other')]:
            changed=copy.deepcopy(identity);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                _verify_generated_session(changed)

    def test_generated_evidence_bounds_are_derived_from_driver_limits(self):
        from myfuzz.scenario.evidence import (_final_state_growth_bound,
                                              _evidence_record_bound)
        from myfuzz.scenario.genome import ScenarioGenome
        gpio=GeneratedPulpGpioSession(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/contract-unused-cache'))
        router=DataflowRouter((DeviceWindow('gpio',0x40000000,0x1000,gpio),))
        memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),
                                initialization_seed=1,max_initialized_bytes=0x20000)
        cpu=GeneratedCve2Session(self.cpu_artifact,base_dir=ROOT,
            cache_dir=Path('/tmp/contract-unused-cache'),memory=memory,router=router)
        runner=ScenarioRunner(sessions={'cpu':cpu,'gpio':gpio},
            ownership=compile_ownership((),()),bindings=())
        genome=ScenarioGenome(testcase_id='generated-budget',direction='CPU_TO_IP',
            path_id='p',schedule_order=('cpu','gpio'),max_steps=1,actions=())
        budget=ResourceBudget()
        self.assertGreater(_final_state_growth_bound(genome,runner,budget),0)
        self.assertGreater(_evidence_record_bound(genome,runner,budget),
                           4*self.artifact.runtime_document['driver_limits']['reply_reservation_bytes'])

    def identity(self):
        session=GeneratedPulpGpioSession(self.artifact,base_dir=ROOT,cache_dir=Path('/tmp/contract-unused-cache'))
        return ScenarioRunner(sessions={'gpio':session},ownership=compile_ownership((),()),bindings=()).identity_document()

    def timing(self):
        doc=self.artifact.runtime_document
        return dict(schema_version='generated_local_reset.v1',artifact_digest=doc['artifact_digest'],
                    driver_sha256=doc['cpp_sha256'],hold_cycles=8,release_cycles=8)

    def manifest(self,identity,timing):
        return ScenarioManifest.from_runner_identity(identity,scenario_id='generated-contract',
            schedule_order=('gpio',),scheduler_policy_id='stable-local-v1',budget=ResourceBudget(),
            reset_timings={'gpio':timing})

    def test_generated_identity_and_reset_are_accepted(self):
        identity=self.identity()
        self.assertEqual(identity['schema_version'],'scenario_manifest_identity.v2')
        self.assertEqual(identity['host_sources']['schema_version'],'scenario_harness_host_sources.v2')
        result=self.manifest(identity,self.timing())
        self.assertEqual(result.to_document()['runner_identity'],identity)

    def test_generated_reset_and_nested_identity_tampering_refused_before_start(self):
        identity=self.identity()
        for key,value in [('hold_cycles',9),('release_cycles',7),('driver_sha256','0'*64),('artifact_digest','0'*64)]:
            timing=self.timing();timing[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.manifest(identity,timing)
        for section,key in [('runtime_artifact','cpp_sha256'),('build_identity','build_digest')]:
            bad=copy.deepcopy(identity);bad['sessions']['gpio']['identity'][section][key]='0'*64
            with self.subTest(section=section),self.assertRaises(ValueError):self.manifest(bad,self.timing())

    def test_generated_manifest_requires_host_v2_even_if_host_record_deleted(self):
        identity=self.identity();identity.pop('host_sources')
        with self.assertRaises(ValueError):self.manifest(identity,self.timing())

    def test_v2_generator_drift_preserves_legacy_34_file_identity(self):
        from unittest.mock import patch
        from myfuzz.scenario import host_identity
        legacy=host_identity.host_source_identity()
        identity=self.identity()
        generated=tuple(row['identity'] for row in identity['sessions'].values())
        original=host_identity._hash_file
        def changed(path):
            return '0'*64 if path.name=='driver_renderer.py' else original(path)
        with patch.object(host_identity,'_hash_file',side_effect=changed):
            self.assertEqual(legacy,host_identity.host_source_identity())
            self.assertEqual(len(legacy['files']),34)
            with self.assertRaises(ValueError):
                host_identity.verify_host_source_identity(identity['host_sources'],harness_identities=generated)

    def test_ready_counts_are_measurements_not_stable_identity(self):
        from myfuzz.local_harness.wire import parse_driver_ready
        digest=self.artifact.runtime_document['artifact_digest']
        parse_driver_ready(f'READY local_driver.v1 {digest} 8 8',digest=digest,assert_ticks=8,release_ticks=8)
        for counts in ('9 8','8 7'):
            with self.assertRaises(ValueError):
                parse_driver_ready(f'READY local_driver.v1 {digest} {counts}',digest=digest,assert_ticks=8,release_ticks=8)

    def test_published_runtime_schema_accepts_generated_manifest(self):
        import json
        import jsonschema
        schema=json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema=json.loads((ROOT/'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget']=budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs',{}))
        jsonschema.Draft202012Validator(schema).validate(self.manifest(self.identity(),self.timing()).to_document())
