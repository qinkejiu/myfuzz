"""Artifact source identity must not depend on elaboration execution mode."""

from dataclasses import replace
from pathlib import Path
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_harness, verify_local_source_lock)


ROOT = Path(__file__).resolve().parents[2]


class PinnedSourceIdentityTests(unittest.TestCase):
    def test_uart_plan_and_render_keep_same_pin_across_elaboration_hashes(self):
        request = load_local_harness_request({
            "schema_version": "local_harness.v1",
            "profile_path": "configs/peripherals/opentitan_uart_local/component_profile.json",
            "instance_id": "uart", "reset_assert_ticks": 8,
            "reset_release_ticks": 8, "max_wait_cycles": 16})
        plan = plan_local_harness(request, base_dir=ROOT)
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        pin = verified["profile_union_revision"]
        direct = replace(plan, facts=replace(plan.facts, content_hash=pin))
        supervised = replace(plan, facts=replace(
            plan.facts, content_hash="sha256:" + "5" * 64))
        self.assertEqual(pin, direct.source_content_hash)
        self.assertEqual(pin, supervised.source_content_hash)
        self.assertNotEqual(direct.elaboration_content_hash,
                            supervised.elaboration_content_hash)
        self.assertEqual(direct.document(), supervised.document())
        rendered_direct = render_local_harness(direct)
        rendered_supervised = render_local_harness(supervised)
        self.assertEqual(rendered_direct.abi_document,
                         rendered_supervised.abi_document)
        self.assertEqual(rendered_direct.build_document,
                         rendered_supervised.build_document)


if __name__ == "__main__":
    unittest.main()
