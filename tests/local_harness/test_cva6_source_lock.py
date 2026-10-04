"""Pinned CVA6 source and physical boundary, without a generated runtime claim."""
from pathlib import Path
import unittest

from myfuzz.local_harness import (
    load_local_harness_request, plan_local_harness, verify_local_source_lock,
)


ROOT = Path(__file__).resolve().parents[2]


class Cva6SourceLockAcceptance(unittest.TestCase):
    def test_pinned_full_top_and_nested_elaboration_closure(self):
        if not (ROOT / 'third_party/cva6_upstream_reference/core/cva6.sv').is_file():
            self.skipTest('pinned CVA6 submodule is not initialized locally')
        request = load_local_harness_request({
            'schema_version': 'local_harness.v1',
            'profile_path': 'configs/cpus/cva6/component_profile.json',
            'instance_id': 'cva6',
            'reset_assert_ticks': 16,
            'reset_release_ticks': 20,
            'max_wait_cycles': 32,
        })
        plan = plan_local_harness(request, base_dir=ROOT)
        self.assertEqual('all', plan.facts.selection)
        self.assertEqual(13, len(plan.facts.ports))
        self.assertEqual(('output', 470),
                         (plan.facts.port('noc_req_o').direction,
                          plan.facts.port('noc_req_o').width))
        self.assertEqual(('input', 210),
                         (plan.facts.port('noc_resp_i').direction,
                          plan.facts.port('noc_resp_i').width))
        self.assertEqual(45, len(plan.binding.endpoint('processor.memory.unified').fields))
        self.assertEqual(57, len(plan.dispositions))
        verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
        self.assertEqual('source_verified', verified['source_status'])
        self.assertEqual('elaboration_verified', verified['elaboration_status'])
        self.assertEqual(232, verified['elaboration']['closure_files'])


if __name__ == '__main__':
    unittest.main()
