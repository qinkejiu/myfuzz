"""A real Ibex response must be observed when RTL consumes it."""

import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.evidence import save_evidence_bundle
from myfuzz.scenario.examples import make_ibex_two_gpio_runner
from myfuzz.scenario.genome import GenomeCodec


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class IbexResponseObservationTests(unittest.TestCase):
    def test_real_mmio_read_receipt_is_consumed_by_cpu_with_same_value(self):
        root = Path(__file__).resolve().parents[2]
        genome = GenomeCodec.decode((root / "configs/scenario/"
                                     "ibex_two_gpio_closed_two_rounds.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            trace = save_evidence_bundle(genome, make_ibex_two_gpio_runner,
                                         Path(directory) / "bundle")
        reads = [event for event in trace.events
                 if event.get("kind") == "mmio_delivery"
                 and event.get("device_id") == "gpio_b"
                 and event.get("offset") == 0x10
                 and not event.get("write")]
        self.assertEqual(2, len(reads))
        for read in reads:
            later_cpu = [event for event in trace.events
                         if event.get("event_id", 0) > read["event_id"]
                         and event.get("component") == "cpu"
                         and event.get("outputs", {}).get("data_rsp_consumed") == 1
                         and event["outputs"].get("data_rsp_source_epoch") ==
                         read["source_transaction"]["source_epoch"]
                         and event["outputs"].get("data_rsp_source_sequence") ==
                         read["source_transaction"]["source_sequence"]]
            self.assertTrue(later_cpu, f"Ibex did not consume MMIO read {read['event_id']}")
            self.assertEqual(read["read_value"],
                             later_cpu[0]["outputs"]["data_rsp_rdata"])


if __name__ == "__main__":
    unittest.main()
