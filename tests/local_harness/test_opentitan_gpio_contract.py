"""Full-top and immutable owner checks for the generated TL-UL GPIO target."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness import (load_local_harness_request,
    plan_local_harness, verify_local_source_lock)


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio.sv'


@unittest.skipUnless(SOURCE.is_file(), 'pinned OpenTitan source checkout unavailable')
class OpenTitanGpioContractTests(unittest.TestCase):
    def test_exact_two_owner_gate_and_full_wrapper_boundary(self):
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_gpio_local/component_profile.json',
            instance_id='gpio_ot', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        plan = plan_local_harness(request, base_dir=ROOT)
        self.assertEqual('all', plan.facts.selection)
        self.assertEqual(30, len(plan.facts.ports))
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        self.assertEqual('source_verified', verified['source_status'])
        self.assertEqual('elaboration_verified', verified['elaboration_status'])
        self.assertEqual('opentitan_gpio', verified['upstream_record']['id'])

    def test_mutated_profile_object_rejected_before_runtime(self):
        doc = json.loads((ROOT / 'configs/peripherals/opentitan_gpio_local/component_profile.json').read_text())
        doc['capabilities']['max_wait_cycles'] = 17
        mutated = load_component_profile(doc)
        with self.assertRaisesRegex(ValueError, 'profile-object-mismatch'):
            verify_local_source_lock(mutated, base_dir=ROOT)

    def test_unwrapped_source_is_not_a_generated_full_top(self):
        request = load_local_harness_request(dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/opentitan_gpio/component_profile.json',
            instance_id='gpio_raw', reset_assert_ticks=2, reset_release_ticks=2,
            max_wait_cycles=16))
        with self.assertRaisesRegex(ValueError, 'full-top-required'):
            plan_local_harness(request, base_dir=ROOT)


if __name__ == '__main__':
    unittest.main()
