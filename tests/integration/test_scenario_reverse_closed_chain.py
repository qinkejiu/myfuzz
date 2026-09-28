"""External GPIO source changes must close through real CPU and GPIO A."""

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario import checker
from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.ip_cpu_ip_example import make_external_gpio_ibex_gpio_runner


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class ReverseClosedChainTests(unittest.TestCase):
    def test_two_external_source_rounds_require_real_cpu_to_a_effects(self):
        check = getattr(checker, "check_gpio_cpu_gpio_closed_chain", None)
        self.assertIsNotNone(check, "reverse closed-chain checker is required")
        self.assertIn("reverse_chain_expected_values",
                      inspect.signature(save_evidence_bundle).parameters)
        root = Path(__file__).resolve().parents[2]
        cases = (("external_gpio_ibex_gpio_closed_two_rounds.json",
                  (0x100, 0x300)),
                 ("external_gpio_ibex_gpio_closed_two_rounds_variant.json",
                  (0x100, 0x100)))
        for name, values in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                genome = GenomeCodec.decode((root / "configs/scenario" / name).read_bytes())
                bundle = Path(directory) / "bundle"
                trace = save_evidence_bundle(
                    genome, make_external_gpio_ibex_gpio_runner, bundle,
                    reverse_chain_expected_values=values)
                final_state = json.loads((bundle / "final_state.json").read_text())
                checks = [json.loads(line) for line in
                          (bundle / "checks.jsonl").read_text().splitlines()]
                self.assertTrue(any(item.get("checker") ==
                                    "gpio_cpu_gpio_closed_chain.v1" and
                                    item.get("complete") for item in checks))
                report = check(trace.events, final_state, expected_values=values)
                self.assertTrue(report["complete"], report["findings"])
                self.assertEqual(2, report["rounds"])

                no_source = [event for event in trace.events
                             if event.get("kind") != "source_injection"]
                self.assertFalse(check(no_source, final_state,
                                       expected_values=values)["complete"])
                wrong_response = deepcopy(trace.events)
                for event in wrong_response:
                    outputs = event.get("outputs", {})
                    if outputs.get("data_rsp_consumed") == 1 and \
                            outputs.get("data_rsp_rdata") in values:
                        outputs["data_rsp_rdata"] ^= 1
                self.assertFalse(check(wrong_response, final_state,
                                       expected_values=values)["complete"])


if __name__ == "__main__":
    unittest.main()
