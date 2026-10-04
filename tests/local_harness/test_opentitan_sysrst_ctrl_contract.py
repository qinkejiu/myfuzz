"""Source, port, clock and reset contract for generated OpenTitan sysrst_ctrl."""
from __future__ import annotations

import json
import re
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    verify_local_source_lock)
from myfuzz.local_harness.clock_schedule import build_local_clock_schedule


ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_sysrst_ctrl_local/component_profile.json'
RTL = ROOT / 'third_party/soc-opentitan/hw/ip/sysrst_ctrl/rtl'


def request():
    fixed = [
        ('ac_present', 0), ('ec_rst_l', 1), ('key1', 0), ('key2', 0),
        ('pwrb', 0), ('lid_open', 0), ('flash_wp_l', 1),
    ]
    return load_local_harness_request({
        'schema_version': 'local_harness.v2',
        'profile_path': PROFILE,
        'instance_id': 'sysrst_ctrl_contract',
        'reset_assert_ticks': 120,
        'reset_release_ticks': 1,
        'max_wait_cycles': 16,
        'tuning': {
            'endpoint_policies': [dict(endpoint_id='opentitan_sysrst_ctrl.mmio',
                template_id='target.tl-ul', template_version='1',
                variant_id='user-integrity', max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role=role, value=value) for role, value in fixed],
            'environment_bindings': [dict(endpoint_id='opentitan_sysrst_ctrl.pins',
                role='key0', source_id='sysrst_key0_environment')],
        },
    })


@unittest.skipUnless((RTL / 'sysrst_ctrl.sv').is_file(),
                     'pinned OpenTitan source checkout unavailable')
class OpenTitanSysrstCtrlContractTests(unittest.TestCase):
    def test_upstream_source_declares_pin_register_and_irq_causality(self):
        top = (RTL / 'sysrst_ctrl.sv').read_text()
        hjson = (ROOT / 'third_party/soc-opentitan/hw/ip/sysrst_ctrl/data/sysrst_ctrl.hjson').read_text()
        interrupt = (RTL / 'sysrst_ctrl_intr.sv').read_text()
        reg_pkg = (RTL / 'sysrst_ctrl_reg_pkg.sv').read_text()
        self.assertIn('clk_i,  // Always-on 24MHz clock(config)', top)
        self.assertIn('clk_aon_i,  // Always-on 200KHz clock(logic)', top)
        self.assertIn('input cio_key0_in_i', top)
        self.assertIn('KEY_INTR_CTL_OFFSET = 8\'h 44', reg_pkg)
        self.assertIn('KEY_INTR_STATUS_OFFSET = 8\'h a8', reg_pkg)
        self.assertIn('PIN_IN_VALUE_OFFSET = 8\'h 40', reg_pkg)
        self.assertGreaterEqual(len(re.findall(r'bits:\s+"1",[\s\S]{0,100}name:\s+"key0_in_H2L"', hjson)), 2)
        self.assertGreaterEqual(len(re.findall(r'bits:\s+"1",[\s\S]{0,100}name:\s+"key0_in_H2L"', hjson)), 2)
        self.assertIn('prim_sync_reqack u_match_sync', interrupt)
        self.assertIn('.clk_src_i(clk_aon_i)', interrupt)
        self.assertIn('.clk_dst_i(clk_i)', interrupt)
        self.assertIn('assign intr_event_status', interrupt)

    def test_profile_authenticates_two_real_domains_and_full_local_boundary(self):
        plan = plan_local_harness(request(), base_dir=ROOT)
        self.assertEqual('all', plan.facts.selection)
        self.assertEqual(24_000_000, max(clock.frequency_hz for clock in plan.profile.clocks))
        clocks = {clock.port: (clock.domain, clock.frequency_hz)
                  for clock in plan.profile.clocks}
        self.assertEqual(('core', 24_000_000), clocks['clk_i'])
        self.assertEqual(('aon', 200_000), clocks['clk_aon_i'])
        resets = {reset.port: (reset.domain, reset.polarity, reset.synchronous)
                  for reset in plan.profile.resets}
        self.assertEqual(('core', 'active_low', False), resets['rst_ni'])
        self.assertEqual(('aon', 'active_low', False), resets['rst_aon_ni'])
        self.assertEqual(120, plan.profile.clocks[0].frequency_hz //
                         min(clock.frequency_hz for clock in plan.profile.clocks))
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        self.assertEqual('source_verified', verified['source_status'])
        self.assertEqual('elaboration_verified', verified['elaboration_status'])
        self.assertEqual('opentitan_sysrst_ctrl', verified['upstream_record']['id'])
        schedule = build_local_clock_schedule(plan.profile.clocks, plan.profile.resets,
            reset_assert_ticks=request().reset_assert_ticks,
            reset_release_ticks=request().reset_release_ticks)
        self.assertEqual(120, schedule['clocks'][0]['ratio'])
        self.assertEqual(60, schedule['clocks'][0]['first_rising_fast_tick'])

    def test_mutated_local_profile_is_not_admitted(self):
        profile_path = ROOT / PROFILE
        document = json.loads(profile_path.read_text())
        document['clocks'][1]['frequency_hz'] = 100_000
        mutated = load_component_profile(document)
        with self.assertRaisesRegex(ValueError, 'profile-changed|profile-object-mismatch|union-source-mismatch'):
            verify_local_source_lock(mutated, base_dir=ROOT)


if __name__ == '__main__':
    unittest.main()
