"""Independent strict CPU observation identity review without RTL processes."""
import copy
from pathlib import Path
import unittest
from myfuzz.local_harness import render_local_harness,render_local_runtime,verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.contracts import _verify_generated_session
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from tests.local_harness.test_renderer import ROOT,real_plan
from tests.local_harness.test_cpu_session import Target

class CpuObservationIdentityReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identities={}
        for kind in ('ibex_obi_local','ibex_rvfi_local'):
            plan=real_plan('configs/cpus/'+kind+'/component_profile.json','cpu_review')
            top=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
            artifact=render_local_driver(top,base_dir=ROOT)
            memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=9,max_initialized_bytes=0x30000)
            router=DataflowRouter((DeviceWindow('dummy',0x40000000,0x1000,Target()),))
            cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=Path('/tmp/identity-review-unused'),memory=memory,router=router)
            cls.identities[kind]=cpu.identity_document()
    def test_valid_new_profile_observation_identity_is_accepted(self):
        identity=self.identities['ibex_rvfi_local']
        artifact=_verify_generated_session(identity)
        self.assertEqual('ibex_rvfi_local',artifact.plan.profile.component_id)
    def test_missing_or_changed_observation_fields_are_rejected(self):
        fields=('cpu_observation_schema_version','cpu_retirement_sampling_edge')
        variants=[]
        for field in fields:
            changed=copy.deepcopy(self.identities['ibex_rvfi_local']);changed.pop(field);variants.append(changed)
            changed=copy.deepcopy(self.identities['ibex_rvfi_local']);changed[field]='forged';variants.append(changed)
        changed=copy.deepcopy(self.identities['ibex_rvfi_local'])
        for field in fields:changed.pop(field)
        variants.append(changed)
        for index,identity in enumerate(variants):
            with self.subTest(index=index),self.assertRaises(ValueError):_verify_generated_session(identity)
    def test_legacy_profile_cannot_claim_new_observation_identity(self):
        changed=copy.deepcopy(self.identities['ibex_obi_local'])
        changed.update(cpu_observation_schema_version='ibex_rvfi_observation.v1',cpu_retirement_sampling_edge='post_rising')
        with self.assertRaises(ValueError):_verify_generated_session(changed)
