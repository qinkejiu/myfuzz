"""Generated PicoRV32 AXI4-Lite boundary uses only physical source pins."""
from pathlib import Path
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from tests.local_harness.test_renderer import ROOT, real_plan


class AxiLiteRuntimeTests(unittest.TestCase):
    def test_pico_axi_lite_no_error_pin_top_and_driver(self):
        plan = real_plan('configs/cpus/picorv32_axi/component_profile.json', 'cpu')
        top = render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        self.assertEqual(top.runtime_document['kind'], 'axi4_lite_cpu')
        self.assertEqual(top.runtime_document['selected_template']['contract']['variant_id'], 'no-response-code')
        self.assertIn('axi4_lite_processor_memory_adapter', top.runtime_sv)
        self.assertIn('.bresp_o(unused_bresp)', top.runtime_sv)
        self.assertIn('.rresp_o(unused_rresp)', top.runtime_sv)
        self.assertNotIn('link_cpu_mem_axi_bresp', top.runtime_sv)
        driver = render_local_driver(top, base_dir=ROOT)
        self.assertIn('STEP_MEMORY', driver.cpp_text)

    def test_manifest_admits_only_matching_axi_lite_service_identity(self):
        import copy
        import json
        from jsonschema import Draft202012Validator
        from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
        from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
        from myfuzz.scenario.ownership import compile_ownership
        from myfuzz.scenario.runner import ScenarioRunner
        from myfuzz.scenario.contracts import ScenarioManifest, ResourceBudget
        plan = real_plan('configs/cpus/picorv32_axi/component_profile.json', 'cpu')
        artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
        memory = PersistentMemory(regions=(MemoryRegion('ram',0,4096),),
            initialization_seed=7,max_initialized_bytes=4096)
        session = GeneratedAxiLiteMemorySession(artifact, base_dir=ROOT,
            cache_dir=Path('/tmp/unused-axi-lite'), memory=memory)
        identity = ScenarioRunner(sessions={'cpu':session},ownership=compile_ownership((),()),bindings=()).identity_document()
        timing = dict(schema_version='generated_local_reset.v1',
            artifact_digest=artifact.runtime_document['artifact_digest'],
            driver_sha256=artifact.runtime_document['cpp_sha256'],hold_cycles=8,release_cycles=8)
        manifest = ScenarioManifest.from_runner_identity(identity,scenario_id='axi-lite',
            schedule_order=('cpu',),scheduler_policy_id='stable-local-v1',
            budget=ResourceBudget(),reset_timings={'cpu':timing})
        schema = json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema = json.loads((ROOT/'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget'] = budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs',{}))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(manifest.to_document())
        changed = copy.deepcopy(identity)
        changed['sessions']['cpu']['identity']['axi_lite_service_schema_version'] = 'changed'
        with self.assertRaises(ValueError):
            ScenarioManifest.from_runner_identity(changed,scenario_id='axi-lite',
                schedule_order=('cpu',),scheduler_policy_id='stable-local-v1',
                budget=ResourceBudget(),reset_timings={'cpu':timing})
