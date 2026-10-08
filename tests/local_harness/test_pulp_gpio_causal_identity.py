"""Authenticated observation identity is required only for the GPIO variant."""
from copy import deepcopy
from pathlib import Path
import unittest
from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.contracts import _verify_generated_session
from tests.local_harness.test_renderer import real_plan

ROOT = Path(__file__).resolve().parents[2]


class PulpGpioCausalIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        plan = real_plan('configs/peripherals/pulp_gpio_causal_local/component_profile.json', 'gpio')
        cls.artifact = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
            verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)

    def test_variant_identity_and_tampered_schema_or_probe_rejected(self):
        session = GeneratedPulpGpioSession(self.artifact, base_dir=ROOT,
                                          cache_dir=Path('/tmp/gpio-identity-only'))
        identity = session.identity_document()
        self.assertEqual(self.artifact, _verify_generated_session(identity))
        for key in ('gpio_target_context_schema_version', 'gpio_observation_contract'):
            wrong = deepcopy(identity)
            del wrong[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                _verify_generated_session(wrong)
        wrong = deepcopy(identity)
        wrong['gpio_observation_contract']['sampling'] = 'post_only'
        with self.assertRaises(ValueError):
            _verify_generated_session(wrong)


    def identity(self, artifact=None):
        return GeneratedPulpGpioSession(artifact or self.artifact, base_dir=ROOT,
            cache_dir=Path('/tmp/gpio-identity-only')).identity_document()

    def test_all_contract_fields_are_exact_and_extra_fields_rejected(self):
        identity=self.identity()
        contract=identity['gpio_observation_contract']
        for key,value in contract.items():
            wrong=deepcopy(identity)
            wrong['gpio_observation_contract'][key]=('changed' if isinstance(value,str) else None)
            with self.subTest(field=key),self.assertRaises(ValueError):
                _verify_generated_session(wrong)
        for location in ('identity','contract'):
            wrong=deepcopy(identity)
            target=wrong if location=='identity' else wrong['gpio_observation_contract']
            target['unknown_field']=True
            with self.subTest(location=location),self.assertRaises(ValueError):
                _verify_generated_session(wrong)
        wrong=deepcopy(identity);wrong['gpio_target_context_schema_version']='pulp_gpio_routed_access.v2'
        with self.assertRaises(ValueError):_verify_generated_session(wrong)

    def test_causal_identity_requires_both_fields_even_when_artifact_matches(self):
        wrong=self.identity()
        wrong.pop('gpio_target_context_schema_version')
        wrong.pop('gpio_observation_contract')
        with self.assertRaises(ValueError):_verify_generated_session(wrong)

    def test_legacy_identity_preserved_and_causal_claim_cannot_be_grafted(self):
        plan=real_plan('configs/peripherals/pulp_gpio/component_profile.json','legacy_gpio')
        artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
            verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
        legacy=self.identity(artifact)
        self.assertEqual(set(legacy), {'schema_version','runtime_artifact','build_identity','command_timeout_seconds'})
        self.assertEqual(artifact,_verify_generated_session(legacy))
        causal=self.identity()
        for key in ('gpio_target_context_schema_version','gpio_observation_contract'):
            legacy[key]=deepcopy(causal[key])
        with self.assertRaises(ValueError):_verify_generated_session(legacy)

    def test_matching_top_level_claim_cannot_hide_changed_probe_artifact(self):
        original=self.identity()
        for mutation in ('width','expression','executor_version','parameters','build_identity'):
            wrong=deepcopy(original);document=wrong['runtime_artifact']
            if mutation=='width':
                next(r for r in document['physical_exports'] if r['physical_port']=='gpio_probe_sync0')['width']=31
            elif mutation=='expression':
                document['selected_template']['executor']['binding']['gpio_probe_contract']['probes']['padin_latch']['expression']='u_component.u_dut.r_gpio_sync1'
            elif mutation=='executor_version':
                document['selected_template']['executor']['contract']['template_version']='2'
            elif mutation=='parameters':
                document['structural_build']['parameter_overrides']['PAD_NUM']='64'
            else: wrong['build_identity']={}
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                _verify_generated_session(wrong)


if __name__ == '__main__':
    unittest.main()
