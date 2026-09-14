"""Coverage-universe and instance attribution tests for P13."""
from __future__ import annotations

import unittest

from myfuzz.integration.soc_coverage import (
    SocCoverageError,
    build_coverage_universe,
    coverage_delta,
    coverage_feedback_document,
    observe_rtl_coverage,
)


class SocCoverageTests(unittest.TestCase):
    def setUp(self):
        self.universe = build_coverage_universe([
            {"point_id": "gpio_a:b0:t", "instance_id": "gpio_a", "module": "apb_gpio",
             "category": "ip", "kind": "branch", "source": "gpio.sv", "line": 12, "branch": "true"},
            {"point_id": "gpio_a:b0:f", "instance_id": "gpio_a", "module": "apb_gpio",
             "category": "ip", "kind": "branch", "source": "gpio.sv", "line": 12, "branch": "false"},
            {"point_id": "gpio_b:b0:t", "instance_id": "gpio_b", "module": "apb_gpio",
             "category": "ip", "kind": "branch", "source": "gpio.sv", "line": 12, "branch": "true"},
            {"point_id": "cpu:fetch", "instance_id": "cpu0", "module": "ibex_top",
             "category": "cpu", "kind": "branch", "source": "ibex.sv", "line": 7, "branch": "true"},
            {"point_id": "event:gpio", "instance_id": "gpio_a", "module": "apb_gpio",
             "category": "interaction", "kind": "interaction", "source": "trace", "line": 1},
        ])

    def test_same_module_instances_are_distinct_universe_points(self):
        ids = {item["point_id"] for item in self.universe["points"]}
        self.assertIn("gpio_a:b0:t", ids)
        self.assertIn("gpio_b:b0:t", ids)
        self.assertNotEqual(self.universe["universe_hash"], "")

    def test_input_variation_without_rtl_hit_does_not_increase_branch_coverage(self):
        before = ["cpu:fetch"]
        after = ["cpu:fetch"]  # raw RFuzz bits changed, observed RTL did not
        delta = coverage_delta(self.universe, before, after)
        self.assertFalse(delta["changed"])
        self.assertEqual(delta["new_hits"], [])

    def test_branch_change_maps_to_the_declared_instance(self):
        delta = coverage_delta(self.universe, ["gpio_a:b0:f"], ["gpio_a:b0:t"])
        self.assertEqual(delta["new_hits"], ["gpio_a:b0:t"])
        self.assertNotIn("gpio_b:b0:t", delta["new_hits"])

    def test_input_samples_cannot_be_labeled_as_branch_feedback(self):
        with self.assertRaisesRegex(SocCoverageError, "sampled-input"):
            build_coverage_universe([{
                "point_id": "raw:0", "instance_id": "harness", "module": "harness",
                "category": "harness", "kind": "sampled_input", "source": "raw", "line": 1,
            }])

    def test_feedback_keeps_interaction_points_separate_by_default(self):
        evidence = coverage_feedback_document(self.universe, ["cpu:fetch", "event:gpio"])
        self.assertEqual(evidence["feedback_hits"], ["cpu:fetch"])
        self.assertEqual(evidence["interaction_hits"], ["event:gpio"])
        self.assertFalse(evidence["include_interactions"])

    def test_unknown_backend_point_is_rejected(self):
        with self.assertRaisesRegex(SocCoverageError, "unknown"):
            observe_rtl_coverage(self.universe, ["not-a-point"])

    def test_flat_backend_manifest_preserves_instance_mappings(self):
        universe = build_coverage_universe({"points": [{
            "point_id": "gpio_b:b1", "instance_id": "gpio_b", "module": "apb_gpio",
            "category": "ip", "kind": "branch", "source": "gpio.sv", "line": 13,
        }]})
        self.assertEqual(["gpio_b:b1"], universe["branch_points"])


if __name__ == "__main__":
    unittest.main()
