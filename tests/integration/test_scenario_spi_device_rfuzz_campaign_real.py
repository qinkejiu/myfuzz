"""Bounded, source-backed SPI Device RFuzz feedback campaign."""

from __future__ import annotations

import os
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor


@unittest.skipUnless(os.environ.get("MYFUZZ_SCENARIO_REAL") == "1",
                     "set MYFUZZ_SCENARIO_REAL=1 for source-backed RTL")
class RealSpiDeviceRfuzzCampaignTests(unittest.TestCase):
    def test_bounded_feedback_rotates_to_consumed_upstream_sources(self):
        from myfuzz.scenario.opentitan_mutation import make_opentitan_mutation_bundle

        factory, decoder, targets, seed = make_opentitan_mutation_bundle("spi_device")
        executor = ScenarioRfuzzExecutor(
            run_id="spi-device-bounded-feedback", decoder=decoder,
            factory=factory, targets=targets)
        path = decoder.graph.paths_to(targets[0].target_id,
                                      direction=seed.direction)[0]
        self.assertEqual(("cpu.program.immediate", "spi_device.frame_1",
                          "spi_device.frame_2"), path.source_ids)
        self.assertTrue(decoder.trusted_for_search)

        seed_record = bytes(8)
        self.assertEqual((b"\x01",), executor.execute_batch(
            InputBatch(1, 8, ((seed_record,),))))
        seed_receipt = executor.receipts[-1]
        self.assertEqual("complete", seed_receipt.status)
        self.assertGreater(seed_receipt.total_local_ticks, 0)
        self.assertEqual("01", seed_receipt.coverage_hex)

        first_hint = executor.mutation_hint()
        self.assertEqual((targets[0].target_id, 0, 8),
                         (first_hint["target_id"], first_hint["source"],
                          first_hint["energy"]))
        executor.note_published_hint(first_hint)
        cpu_record = bytes((0, 0, first_hint["source"], 0, 0, 1, 0, 0))
        self.assertEqual((b"\x00",), executor.execute_batch(
            InputBatch(2, 8, ((cpu_record,),))))
        cpu_receipt = executor.receipts[-1]
        self.assertEqual("path_incomplete", cpu_receipt.status)
        self.assertEqual(("cpu.program.immediate",),
                         cpu_receipt.applied_source_ids)
        self.assertEqual(first_hint["sequence"],
                         cpu_receipt.applied_hint_sequence)
        self.assertNotEqual(seed_receipt.semantic_sha256,
                            cpu_receipt.semantic_sha256)

        second_hint = executor.mutation_hint()
        self.assertEqual(1, second_hint["source"])
        self.assertEqual(2, second_hint["max_completed_buffer_id"])
        self.assertEqual(cpu_receipt.raw_sha256,
                         second_hint["latest_completed_batch"][0]["raw_sha256"])
        executor.note_published_hint(second_hint)
        peer_record = bytes((0, 0, second_hint["source"], 8, 0, 1, 0, 0))
        self.assertEqual((b"\x01",), executor.execute_batch(
            InputBatch(3, 8, ((peer_record,),))))
        peer_receipt = executor.receipts[-1]
        self.assertEqual("complete", peer_receipt.status)
        self.assertEqual(("spi_device.frame_1",),
                         peer_receipt.applied_source_ids)
        self.assertEqual(second_hint["sequence"],
                         peer_receipt.applied_hint_sequence)
        self.assertEqual({"cpu.program.immediate": 1,
                          "spi_device.frame_1": 1,
                          "spi_device.frame_2": 0},
                         executor.applied_source_uses)
        self.assertNotEqual(seed_receipt.semantic_sha256,
                            peer_receipt.semantic_sha256)
        self.assertEqual(("complete", "path_incomplete", "complete"),
                         tuple(receipt.status for receipt in executor.receipts))


if __name__ == "__main__":
    unittest.main()
