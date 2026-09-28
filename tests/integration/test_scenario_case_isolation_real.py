"""A new real multi-component testcase starts from its own declared state."""

import os
from pathlib import Path
import unittest

from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.replay import record_scenario


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealCaseIsolationTests(unittest.TestCase):
    def test_second_case_does_not_inherit_first_cpu_or_gpio_state(self):
        first = GenomeCodec.decode((ROOT / "configs/scenario/"
                                    "ibex_two_gpio_closed_two_rounds.json").read_bytes())
        second = GenomeCodec.decode((ROOT / "configs/scenario/"
                                     "ibex_two_gpio_closed_two_rounds_variant.json").read_bytes())
        run_a = record_scenario(first, make_ibex_two_gpio_runner)
        run_b_after_a = record_scenario(second, make_ibex_two_gpio_runner)
        run_b_again = record_scenario(second, make_ibex_two_gpio_runner)

        def gpio_a_outputs(trace):
            return [event["outputs"]["gpio_out"] for event in trace.events
                    if event.get("component") == "gpio_a" and "outputs" in event]

        self.assertEqual("complete", run_a.status)
        self.assertEqual("complete", run_b_after_a.status)
        self.assertEqual(1, gpio_a_outputs(run_a)[-1])
        self.assertEqual(0, gpio_a_outputs(run_b_after_a)[0])
        self.assertEqual(3, gpio_a_outputs(run_b_after_a)[-1])
        self.assertEqual(run_b_after_a.semantic_sha256,
                         run_b_again.semantic_sha256)
        self.assertEqual(run_b_after_a.local_ticks, run_b_again.local_ticks)


if __name__ == "__main__":
    unittest.main()
