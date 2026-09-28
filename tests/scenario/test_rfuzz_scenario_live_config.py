"""Scenario RFuzz config exposes decision bytes and semantic target counters."""

import tomllib
import unittest

from myfuzz.integration.scenario_rfuzz_live import (
    _drain_idle_timeout_reached, render_scenario_rfuzz_config)
from myfuzz.scenario.feedback import CoverageTarget


class ScenarioLiveConfigTests(unittest.TestCase):
    def test_drain_timeout_counts_idle_time_after_latest_batch_progress(self):
        self.assertFalse(_drain_idle_timeout_reached(
            stop_requested_at=1.0, last_progress_at=40.0, now=41.0,
            idle_limit_seconds=30.0))
        self.assertTrue(_drain_idle_timeout_reached(
            stop_requested_at=1.0, last_progress_at=40.0, now=71.0,
            idle_limit_seconds=30.0))

    def test_decision_record_is_eight_bytes_and_counters_are_unscaled(self):
        raw = render_scenario_rfuzz_config(
            (CoverageTarget("gpio.irq", "gpio", "irq", 1, 1),
             CoverageTarget("cpu.mmio", "cpu", "data_req_valid", 1, 1)))
        config = tomllib.loads(raw)
        self.assertEqual(64, sum(item["width"] for item in config["input"]))
        self.assertEqual(2, len(config["counter"]))
        self.assertTrue(all(item["width"] == 8 and not item["scale"]
                            and not item["fail"] for item in config["counter"]))


if __name__ == "__main__":
    unittest.main()
