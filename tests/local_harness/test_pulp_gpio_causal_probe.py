"""Authentication and passive wiring for the fixed upstream GPIO variant."""
import copy
import json
import unittest
from dataclasses import replace
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from tests.local_harness.test_renderer import ROOT, real_plan

PROFILE = 'configs/peripherals/pulp_gpio_causal_local/component_profile.json'

class PulpGpioProbeTests(unittest.TestCase):
    def test_named_profile_and_contract_are_registered(self):
        self.assertTrue((ROOT / PROFILE).is_file(), 'authenticated variant profile is missing')
        from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
        identity = pulp_gpio_observation_contract()
        self.assertEqual(('pulp.gpio.causal', '1', 'pulp_gpio_causal_v1'),
                         tuple(identity[k] for k in ('template_id','template_version','variant_id')))

    def test_complete_passive_map_and_original_ports(self):
        from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES, pulp_gpio_observation_contract
        plan = real_plan(PROFILE, 'gpio_a')
        old = real_plan('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
        self.assertEqual(plan.facts.ports, old.facts.ports)
        structure = render_local_harness(plan)
        runtime = render_local_runtime(plan, structure, verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
        self.assertEqual(runtime.runtime_document['gpio_observation_contract'], pulp_gpio_observation_contract())
        exports = {r['physical_port']:r for r in runtime.runtime_document['physical_exports']}
        self.assertEqual(len(PULP_GPIO_PROBES), 28)
        for name, (width, signal) in PULP_GPIO_PROBES.items():
            self.assertEqual(exports['gpio_probe_' + name]['width'], width)
            self.assertIn(f'assign probe_gpio_{name} = u_component.u_dut.{signal};', runtime.runtime_sv)
        self.assertEqual(PULP_GPIO_PROBES['inttype'], (64, 'r_gpio_inttype'))
        self.assertEqual(PULP_GPIO_PROBES['write_out'][0], 64)
        for port in plan.facts.ports:
            self.assertEqual(structure.wrapper_sv.count('.'+port.name+'('), 1)
        old_runtime = render_local_runtime(old, render_local_harness(old), verify_local_source_lock(old.profile,base_dir=ROOT),base_dir=ROOT)
        self.assertNotIn('gpio_observation_contract', old_runtime.runtime_document)
        self.assertEqual(old_runtime.runtime_document['selected_template']['executor']['contract']['variant_id'], 'apb_gpio')
        self.assertEqual(runtime.runtime_sv[runtime.runtime_sv.index('beat_to_apb #'):], old_runtime.runtime_sv[old_runtime.runtime_sv.index('beat_to_apb #'):])

    def test_profile_mutations_refused(self):
        document = json.loads((ROOT / PROFILE).read_text())
        mutations = [('revision','git:'+'0'*40), ('top_module','bad'), ('files', []), ('top_port_selection','declared')]
        for key,value in mutations:
            changed=copy.deepcopy(document); changed['source'][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_local_source_lock(load_component_profile(changed),base_dir=ROOT)
        for key,value in [('PAD_NUM','64'),('APB_ADDR_WIDTH','16'),('NBIT_PADCFG','8')]:
            changed=copy.deepcopy(document)
            next(r for r in changed['source']['elaboration']['parameters'] if r['name']==key)['value']=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_local_source_lock(load_component_profile(changed),base_dir=ROOT)

    def test_changed_identity_expression_width_and_selection_refused(self):
        from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract, validate_pulp_gpio_observation_contract, pulp_gpio_probe_document, validate_pulp_gpio_probe_document
        for key,value in [('template_id','unknown'),('template_version','2'),('variant_id','apb_gpio'),('probes_sha256','0'*64)]:
            changed=pulp_gpio_observation_contract();changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_pulp_gpio_observation_contract(changed)
        with self.assertRaises(ValueError): validate_pulp_gpio_observation_contract(None)
        for key,value in [('width',31),('expression','u_component.u_dut.r_gpio_sync1')]:
            changed=pulp_gpio_probe_document();changed['probes']['padin_latch'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_pulp_gpio_probe_document(changed)

    def test_source_pin_closure_and_profile_bytes_are_authenticated(self):
        from pathlib import Path
        from unittest.mock import patch
        plan=real_plan(PROFILE,'gpio_a')
        original=Path.read_bytes
        for relative in (PROFILE, 'configs/soc/closures/pulp_gpio_causal_local.json',
                         'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'):
            target=ROOT/relative
            def changed(path, target=target):
                raw=original(path)
                return raw+b'\n' if path==target else raw
            with self.subTest(relative=relative),patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
                verify_local_source_lock(plan.profile,base_dir=ROOT)
        lock_path=ROOT/'configs/soc/sources.lock.json'
        for mutation in ('missing','unknown_revision'):
            document=json.loads(original(lock_path))
            row=next(r for r in document['components'] if r['id']=='pulp_gpio_causal_local')
            if mutation=='missing': document['components'].remove(row)
            else: row['source']['revision']='git:'+'0'*40
            changed_raw=json.dumps(document).encode()
            def changed(path): return changed_raw if path==lock_path else original(path)
            with self.subTest(mutation=mutation),patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
                verify_local_source_lock(plan.profile,base_dir=ROOT)

    def test_executor_requires_exact_observation_selection(self):
        from myfuzz.local_harness.template_contracts import generated_executor_selection
        from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract
        plan=real_plan(PROFILE,'gpio_a')
        runtime=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        document=copy.deepcopy(runtime.runtime_document)
        endpoint=tuple(e for e in plan.binding.endpoints if e.protocol is not None)
        selection=generated_executor_selection(document,endpoint,plan.profile.capabilities)
        self.assertEqual(selection['contract']['variant_id'],'pulp_gpio_causal_v1')
        self.assertIn('gpio_probe_contract',selection['binding'])
        for variant in (None,'unknown','apb_gpio'):
            caps=dict(plan.profile.capabilities)
            if variant is None: caps.pop('gpio_observation_variant')
            else: caps['gpio_observation_variant']=variant
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                generated_executor_selection(document,endpoint,caps)
        document.pop('gpio_observation_contract')
        with self.assertRaises(ValueError): generated_executor_selection(document,endpoint,plan.profile.capabilities)

    def test_named_variant_driver_observes_original_interrupt_and_all_probes(self):
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.pulp_gpio_probe_contract import PULP_GPIO_PROBES
        plan=real_plan(PROFILE,'gpio_a')
        top=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        artifact=render_local_driver(top,base_dir=ROOT)
        self.assertEqual(artifact.runtime_document['kind'],'apb_gpio')
        for name in PULP_GPIO_PROBES:
            self.assertIn('\"probe_gpio_'+name+'\"',artifact.cpp_text)
            self.assertIn('dut.probe_gpio_'+name,artifact.cpp_text)
        self.assertEqual(top.runtime_document['physical_exports'],artifact.runtime_document['physical_exports'])
        interrupt=next(r for r in top.runtime_document['physical_exports'] if r['physical_port']=='interrupt')
        self.assertIn(interrupt['runtime_name'],artifact.cpp_text)

    def test_raw_offset_alias_and_packed_type_order(self):
        from myfuzz.local_harness.pulp_gpio_probe_contract import decoded_gpio_word, unpack_gpio_inttype
        for raw in (12,15,140,4095): self.assertEqual(decoded_gpio_word(raw), (raw >> 2) & 31)
        self.assertEqual(unpack_gpio_inttype(1 | (2 << 2) | (3 << 62))[0:2], (1,2))
        self.assertEqual(unpack_gpio_inttype(3 << 62)[31], 3)

if __name__ == '__main__': unittest.main()
