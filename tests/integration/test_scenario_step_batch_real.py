"""Batch boundaries leave a real OpenTitan GPIO trace unchanged."""

import os
import unittest

from myfuzz.scenario.examples import make_opentitan_gpio_runner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealStepBatchTests(unittest.TestCase):
    def run_ticks(self, batch_sizes):
        runner = make_opentitan_gpio_runner()
        runner.begin_test("real-step-batch")
        try:
            runner.inject_source("gpio", "gpio_in", 1,
                                 direction="IP_TO_CPU")
            remaining = 12
            index = 0
            while remaining:
                count = min(remaining, batch_sizes[index % len(batch_sizes)])
                runner.step_batch(("gpio",) * count)
                remaining -= count
                index += 1
            return runner.events, dict(runner.local_ticks), runner.final_state_document()
        finally:
            runner.finalize()

    def test_real_gpio_single_and_irregular_batches_match(self):
        baseline = self.run_ticks((1,))
        self.assertEqual(12, baseline[1]["gpio"])
        self.assertEqual(baseline, self.run_ticks((12,)))
        self.assertEqual(baseline, self.run_ticks((2, 5, 1)))


if __name__ == "__main__":
    unittest.main()
