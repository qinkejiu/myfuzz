"""Coverage-universe and instance attribution tests for P13."""
from __future__ import annotations

import unittest

from myfuzz.integration.soc_coverage import (
    SocCoverageError,
    build_coverage_universe,
    coverage_category,
    coverage_delta,
    coverage_feedback_document,
    coverage_observation_plan,
    observe_rtl_coverage,
    universe_from_instance_bits,
)


def _bit(bit: int, path: str, module: str, subtype: str = "true", signal: str | None = None):
    return {"bit": bit, "instance_path": path, "module": module,
            "file": f"{module}.sv", "line": bit + 1, "column": 0,
            "kind": "if", "subtype": subtype,
            "signal": signal or f"__vi_branch_cov_{bit}"}


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


class SocCoverageInstanceUniverseTests(unittest.TestCase):
    """P13: the instrumented vector must resolve to real instance-mapped points."""

    BITS = (
        _bit(0, "myfuzz_soc_top/u_cpu/u_core/u_alu", "ibex_alu"),
        _bit(1, "myfuzz_soc_top/u_cpu/u_core/u_alu", "ibex_alu", "false"),
        _bit(2, "myfuzz_soc_top/u_pulp_gpio/u_apb_gpio", "apb_gpio"),
        _bit(3, "myfuzz_soc_top/u_pulp_spi/u_spi_master_controller",
             "spi_master_controller"),
        _bit(4, "myfuzz_soc_top/u_pulp_gpio_width", "mmio_width_adapter"),
        _bit(5, "myfuzz_soc_top/u_mem_0", "riscv_boot_memory_32"),
        _bit(6, "myfuzz_soc_top/u_fuzz_mmio", "fuzz_mmio_master"),
    )

    def _universe(self):
        return universe_from_instance_bits(
            self.BITS, ip_instances=["u_pulp_gpio", "u_pulp_spi"])

    def test_every_category_is_separated_by_subtree(self):
        universe = self._universe()
        by_id = {item["point_id"]: item["category"] for item in universe["points"]}
        for entry in self.BITS:
            point_id = f"{entry['instance_path']}:{entry['signal']}"
            self.assertIn(point_id, by_id)
        self.assertEqual("cpu", by_id["myfuzz_soc_top/u_cpu/u_core/u_alu:__vi_branch_cov_0"])
        self.assertEqual("ip", by_id["myfuzz_soc_top/u_pulp_spi/u_spi_master_controller:"
                                     "__vi_branch_cov_3"])
        self.assertEqual("fabric", by_id["myfuzz_soc_top/u_pulp_gpio_width:"
                                         "__vi_branch_cov_4"])
        self.assertEqual("model", by_id["myfuzz_soc_top/u_mem_0:__vi_branch_cov_5"])
        self.assertEqual("harness", by_id["myfuzz_soc_top/u_fuzz_mmio:__vi_branch_cov_6"])

    def test_a_peripheral_submodule_is_not_reclassified_as_fabric(self):
        # The adapter modules are fabric, but a real IP's own submodule is IP.
        self.assertEqual("ip", coverage_category(
            "myfuzz_soc_top/u_pulp_spi/u_spi_master_controller", "spi_master_controller",
            ip_instances=["u_pulp_spi"]))
        self.assertEqual("fabric", coverage_category(
            "myfuzz_soc_top/u_pulp_spi_adapter", "beat_to_apb",
            ip_instances=["u_pulp_spi"]))

    def test_two_instances_of_one_module_stay_distinct_points(self):
        universe = universe_from_instance_bits([
            _bit(0, "myfuzz_soc_top/u_a/u_leaf#0", "leaf", signal="__vi_branch_cov_0"),
            _bit(1, "myfuzz_soc_top/u_a/u_leaf#1", "leaf", signal="__vi_branch_cov_0"),
        ])
        self.assertEqual(2, len(universe["points"]))
        self.assertEqual(2, len({item["instance_id"] for item in universe["points"]}))

    def test_input_counters_cannot_enter_the_branch_universe(self):
        with self.assertRaisesRegex(SocCoverageError, "bit:kind"):
            universe_from_instance_bits([dict(_bit(0, "t/u_x", "m"), kind="toggle")])

    def test_observation_plan_spends_the_budget_on_cpu_and_ip_first(self):
        universe = self._universe()
        plan = coverage_observation_plan(universe, self.BITS, 3)
        self.assertEqual(3, plan["observed_count"])
        self.assertEqual(4, plan["unobserved_count"])
        self.assertEqual({"cpu": 2, "ip": 1}, plan["observed_by_category"])
        self.assertEqual([0, 1, 2], [item["bit"] for item in plan["observed"]])

    def test_observation_plan_reports_what_it_could_not_observe(self):
        universe = self._universe()
        plan = coverage_observation_plan(universe, self.BITS, 128)
        self.assertEqual(7, plan["observed_count"])
        self.assertEqual(0, plan["unobserved_count"])

    def test_observation_plan_rejects_a_bit_the_universe_does_not_declare(self):
        universe = self._universe()
        with self.assertRaisesRegex(SocCoverageError, "observation-bit:unknown"):
            coverage_observation_plan(universe, [_bit(0, "t/u_ghost", "ghost")], 8)
        with self.assertRaisesRegex(SocCoverageError, "observation-limit"):
            coverage_observation_plan(universe, self.BITS, 0)


if __name__ == "__main__":
    unittest.main()
