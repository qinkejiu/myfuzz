"""Generated executor identity describes admitted implementations before RTL build."""
from dataclasses import replace
import hashlib
import json
import unittest

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from tests.local_harness.test_renderer import ROOT, real_plan


def artifact(profile, instance='identity_fixture', max_wait=None):
    plan = real_plan(profile, instance)
    if max_wait is not None:
        plan = replace(plan, request=replace(plan.request, max_wait_cycles=max_wait))
    return render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT,
            allow_source_only=plan.profile.component_id == 'rvx_core'), base_dir=ROOT)


class RuntimeTemplateIdentityTests(unittest.TestCase):
    def test_obi_and_apb_bind_real_protocol_contracts_and_executor_limits(self):
        for profile, ids in (
            ('configs/cpus/cv32e20/component_profile.json', ['cpu.obi', 'cpu.obi']),
            ('configs/peripherals/pulp_gpio/component_profile.json', ['target.apb3']),
        ):
            with self.subTest(profile=profile):
                runtime = artifact(profile).runtime_document
                selected = runtime['selected_template']
                self.assertEqual(ids, [row['contract']['template_id']
                    for row in selected['executor']['protocol_templates']])
                self.assertEqual(runtime['kind'], selected['executor']['contract']['variant_id'])
                self.assertEqual(runtime['effective_max_wait_cycles'],
                    selected['executor']['binding']['effective_max_wait_cycles'])
                self.assertEqual(runtime['adapter_sources'],
                    selected['executor']['binding']['adapter_sources'])
                self.assertEqual(runtime['plan']['profile_sha256'],
                    selected['executor']['binding']['profile_sha256'])

    def test_each_other_admitted_executor_declares_exact_kind_without_generic_axi_claim(self):
        profiles = [
            'configs/cpus/picorv32/component_profile.json',
            'configs/cpus/picorv32_axi/component_profile.json',
            'configs/cpus/rvx_core/component_profile.json',
            'configs/cpus/ibex_obi_local/component_profile.json',
            'configs/cpus/picorv32_wb/component_profile.json',
            'configs/cpus/zipaxi/component_profile.json',
            'configs/cpus/cva6/component_profile.json',
            'configs/peripherals/zipcpu_axiluart/component_profile.json',
            'configs/peripherals/zipcpu_timer/component_profile.json',
            'configs/peripherals/zipcpu_uart/component_profile.json',
            'configs/peripherals/opentitan_uart_local/component_profile.json',
            'configs/peripherals/opentitan_gpio_local/component_profile.json',
            'configs/peripherals/opentitan_rv_timer_local/component_profile.json',
            'configs/peripherals/opentitan_i2c_local/component_profile.json',
            'configs/peripherals/opentitan_spi_host_local/component_profile.json',
            'configs/peripherals/opentitan_spi_device_local/component_profile.json',
            'configs/peripherals/pulp_spi/local_component_profile.json',
            'configs/peripherals/pulp_timer/component_profile.json',
            'configs/peripherals/pulp_i2c/component_profile.json',
        ]
        for profile in profiles:
            with self.subTest(profile=profile):
                runtime = artifact(profile).runtime_document
                selected = runtime['selected_template']
                executor = selected['executor']
                self.assertEqual(runtime['kind'], executor['contract']['variant_id'])
                self.assertEqual('1', executor['contract']['template_version'])
                self.assertEqual(sorted(runtime['adapted_endpoint_ids']),
                    [row['endpoint_id'] for row in executor['binding']['endpoints']])
                if runtime['kind'] in ('axi4_cpu', 'cva6_packed_axi4_cpu'):
                    self.assertEqual([], executor['protocol_templates'])
                    self.assertEqual('generated_executor_only', executor['contract']['scope'])

    def test_effective_wait_changes_template_identity_while_contract_stays_versioned(self):
        a = artifact('configs/peripherals/pulp_gpio/component_profile.json', max_wait=5)
        b = artifact('configs/peripherals/pulp_gpio/component_profile.json', max_wait=7)
        sa, sb = (x.runtime_document['selected_template'] for x in (a, b))
        self.assertEqual(sa['executor']['contract'], sb['executor']['contract'])
        self.assertNotEqual(sa['executor']['identity_sha256'], sb['executor']['identity_sha256'])
        for value in (sa, sb):
            executor = dict(value['executor'])
            digest = executor.pop('identity_sha256')
            self.assertEqual(digest, hashlib.sha256(json.dumps(executor,
                sort_keys=True, separators=(',', ':')).encode()).hexdigest())
