"""Two closed real Ibex/GPIO rounds require ordered RTL observations."""

from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario import checker
from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class ClosedChainTests(unittest.TestCase):
    def test_two_real_rounds_require_read_consumption_and_clean_irq_end(self):
        check = getattr(checker, "check_cpu_gpio_closed_chain", None)
        self.assertIsNotNone(check, "closed-chain checker is required")
        self.assertIn("closed_chain_expected_value",
                      inspect.signature(save_evidence_bundle).parameters)
        root = Path(__file__).resolve().parents[2]
        cases = (("ibex_two_gpio_closed_two_rounds.json", 1),
                 ("ibex_two_gpio_closed_two_rounds_variant.json", 3))
        for name, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                genome = GenomeCodec.decode((root / "configs/scenario" / name).read_bytes())
                bundle = Path(directory) / "bundle"
                trace = save_evidence_bundle(genome, make_ibex_two_gpio_runner,
                                             bundle,
                                             closed_chain_expected_value=expected)
                final_state = json.loads((bundle / "final_state.json").read_text())
                checks = [json.loads(line) for line in
                          (bundle / "checks.jsonl").read_text().splitlines()]
                self.assertTrue(any(item.get("checker") ==
                                    "cpu_gpio_closed_chain.v1" and
                                    item.get("complete") for item in checks))
                report = check(trace.events, final_state,
                               expected_value=expected, min_rounds=2)
                self.assertTrue(report["complete"], report["findings"])
                self.assertEqual(2, report["rounds"])

                no_edge = [event for event in trace.events
                           if not (event.get("kind") == "dataflow_delivery"
                                   and tuple(event.get("source", ())) ==
                                   ("gpio_a", "gpio_out"))]
                self.assertFalse(check(no_edge, final_state,
                                       expected_value=expected, min_rounds=2)["complete"])

                wrong_response = deepcopy(trace.events)
                for event in wrong_response:
                    outputs = event.get("outputs", {})
                    if outputs.get("data_rsp_consumed") == 1 and \
                            outputs.get("data_rsp_rdata") == expected:
                        outputs["data_rsp_rdata"] ^= 1
                self.assertFalse(check(wrong_response, final_state,
                                       expected_value=expected, min_rounds=2)["complete"])


if __name__ == "__main__":
    unittest.main()
