"""Regression checks for streaming interaction evidence collection."""

import unittest

from myfuzz.scenario.interaction_feedback import InteractionFeedback, summarize_interactions


class InteractionFeedbackIncrementalTest(unittest.TestCase):
    @staticmethod
    def _irq_read_write_events(*, reset: bool):
        read_tx = {"source_component": "cpu", "source_epoch": 0, "source_sequence": 1}
        write_tx = {"source_component": "cpu", "source_epoch": 0, "source_sequence": 2}
        read_fields = {"address": 0x40000008, "offset": 8, "beat_bytes": 4,
                       "byte_enable": 15, "write_value": None}
        write_fields = {"address": 0x4000100c, "offset": 12, "beat_bytes": 4,
                        "byte_enable": 15, "write_value": 1}
        return [
            {"event_id": 1, "kind": "source_start", "source": ["gpio_b", "irq"],
             "target": ["cpu", "irq"], "source_event_id": 1},
            {"event_id": 2, "kind": "pulse_start", "source": ["gpio_b", "irq"],
             "target": ["cpu", "irq"], "source_event_id": 1,
             "start_cpu_tick": 10, "end_cpu_tick_exclusive": 11},
            {"event_id": 3, "component": "cpu", "inputs": {"irq": 1}, "local_tick": 10},
            {"event_id": 4, "kind": "reset_barrier" if reset else "noop"},
            {"event_id": 5, "component": "cpu", "outputs": {"data_req_accepted": 1,
             "data_write": 0, "data_addr": 0x40000008}},
            {"event_id": 6, "kind": "mmio_acceptance", "device_id": "gpio_b",
             "source_transaction": read_tx, "write": False,
             "producer_event_id": 5, **read_fields},
            {"event_id": 7, "component": "gpio_b", "outputs": {}},
            {"event_id": 8, "kind": "mmio_delivery", "device_id": "gpio_b",
             "source_transaction": read_tx, "write": False, "read_value": 256,
             "producer_event_id": 7, **read_fields},
            {"event_id": 9, "component": "cpu", "inputs": {},
             "outputs": {"data_rsp_consumed": 1,
             "data_rsp_source_epoch": 0, "data_rsp_source_sequence": 1,
             "data_rsp_rdata": 256}},
            {"event_id": 10, "component": "cpu", "outputs": {"data_req_accepted": 1,
             "data_write": 1, "data_addr": 0x4000100c, "data_wdata": 1}},
            {"event_id": 11, "kind": "mmio_acceptance", "device_id": "gpio_a",
             "source_transaction": write_tx, "write": True,
             "producer_event_id": 10, **write_fields},
            {"event_id": 12, "component": "gpio_a", "outputs": {}},
            {"event_id": 13, "kind": "mmio_delivery", "device_id": "gpio_a",
             "source_transaction": write_tx, "write": True,
             "producer_event_id": 12, **write_fields},
        ]

    @classmethod
    def _irq_taken_read_write_events(cls, *, reset: bool = False):
        events = cls._irq_read_write_events(reset=reset)
        if reset:
            for event in events:
                if event["event_id"] >= 4:
                    event["event_id"] += 1
                if event.get("producer_event_id", 0) >= 4:
                    event["producer_event_id"] += 1
            events.insert(3, {"event_id": 4, "kind": "cpu_irq_taken",
                              "source": ["gpio_b", "irq"],
                              "target": ["cpu", "irq"], "source_event_id": 1})
        else:
            events[3] = {"event_id": 4, "kind": "cpu_irq_taken",
                         "source": ["gpio_b", "irq"],
                         "target": ["cpu", "irq"], "source_event_id": 1}
        return events

    def test_taken_path_requires_matching_real_irq_and_full_ordered_chain(self):
        events = self._irq_taken_read_write_events()
        summary = summarize_interactions(events)
        paths = {path["kind"]: path for path in summary["observed_paths"]}
        self.assertEqual(set(paths), {"irq_sample_read_then_write",
                                      "irq_taken_read_then_write"})
        self.assertIn(4, paths["irq_taken_read_then_write"]["witness_event_ids"])
        self.assertEqual(paths["irq_taken_read_then_write"]["components"],
                         ["gpio_b", "cpu", "gpio_a"])
        self.assertEqual(summary["closed_loops"], [])

        feedback = InteractionFeedback()
        feedback.ingest(events[:10])
        self.assertEqual(feedback.incremental_summary()["delta_observed_paths"], [])
        feedback.ingest(events[10:])
        self.assertEqual({path["kind"] for path in
                          feedback.incremental_summary()["delta_observed_paths"]},
                         set(paths))

    def test_taken_path_rejects_missing_wrong_or_late_taken(self):
        for mode in ("missing", "wrong_occurrence", "wrong_source", "late"):
            with self.subTest(mode=mode):
                events = self._irq_taken_read_write_events()
                taken = events[3]
                if mode == "missing":
                    taken["kind"] = "noop"
                elif mode == "wrong_occurrence":
                    taken["source_event_id"] = 2
                elif mode == "wrong_source":
                    taken["source"] = ["gpio_a", "irq"]
                else:
                    taken["event_id"] = 14
                    events.pop(3)
                    events.append(taken)
                summary = summarize_interactions(events)
                self.assertEqual([path["kind"] for path in summary["observed_paths"]],
                                 ["irq_sample_read_then_write"])

    def test_taken_path_rejects_cross_reset(self):
        events = self._irq_taken_read_write_events(reset=True)
        summary = summarize_interactions(events)
        self.assertEqual(summary["observed_paths"], [])
        self.assertEqual(summary["path_counts"], {})

    def test_suffixes_and_repeated_prefixes_match_full_ingest(self):
        events = [
            {"event_id": 1, "component": "a", "outputs": {"out": 7}},
            {"event_id": 2, "kind": "dataflow_delivery", "source": ["a", "out"],
             "target": ["b", "in"], "value": 7, "producer_event_id": 1},
            {"event_id": 3, "component": "b", "inputs": {"in": 7}},
            {"event_id": 4, "kind": "reset_barrier"},
            {"event_id": 5, "kind": "source_injection", "component": "a", "port": "in"},
        ]
        expected = summarize_interactions(events)
        streamed = InteractionFeedback()
        streamed.ingest(events[:2])
        first = streamed.incremental_summary()
        self.assertEqual(first["feature_deltas"], {"bound_delivered:a:b": 1})
        streamed.ingest(events[:2])
        streamed.ingest(events[2:])
        self.assertEqual(streamed.summary(), expected)
        delta = streamed.incremental_summary()["feature_deltas"]
        self.assertEqual(delta, {"bound_consumed:a:b": 1,
                                 "bound_input_consumed:a:b": 1,
                                 "reset_barrier": 1,
                                 "source_injected:a.in": 1})
        self.assertEqual(streamed.incremental_summary()["feature_deltas"], {})

    def test_returned_summary_cannot_mutate_retained_evidence(self):
        feedback = InteractionFeedback()
        feedback.ingest([
            {"event_id": 1, "component": "a", "outputs": {"out": 1}},
            {"event_id": 2, "kind": "dataflow_delivery", "source": ["a", "out"],
             "target": ["b", "in"], "value": 1, "producer_event_id": 1},
            {"event_id": 3, "component": "b", "inputs": {"in": 1}},
        ])
        original = feedback.summary()
        self.assertEqual(len(original["edges"]), 1)
        original["edges"][0]["source"] = "corrupted"
        self.assertEqual(feedback.summary()["edges"][0]["source"], "a")

    def test_reset_barrier_prevents_cross_epoch_observed_path(self):
        uninterrupted = summarize_interactions(self._irq_read_write_events(reset=False))
        self.assertEqual([path["kind"] for path in uninterrupted["observed_paths"]],
                         ["irq_sample_read_then_write"])
        interrupted = summarize_interactions(self._irq_read_write_events(reset=True))
        self.assertEqual(interrupted["observed_paths"], [])
        self.assertEqual(interrupted["path_counts"], {})

    def test_mismatched_mmio_payload_does_not_create_delivery_edge(self):
        for field, mismatch in (("address", 0x40001010), ("byte_enable", 7),
                                ("write_value", 2)):
            with self.subTest(field=field):
                events = self._irq_read_write_events(reset=False)
                events[-1][field] = mismatch
                summary = summarize_interactions(events)
                self.assertFalse(any(edge["kind"] == "mmio_write_delivered"
                                     for edge in summary["edges"]))
                self.assertEqual(summary["observed_paths"], [])
                retry_without_new_acceptance = dict(self._irq_read_write_events(reset=False)[-1])
                retry_without_new_acceptance["event_id"] = 14
                events.append(retry_without_new_acceptance)
                summary = summarize_interactions(events)
                self.assertFalse(any(edge["kind"] == "mmio_write_delivered"
                                     for edge in summary["edges"]))

    def test_incremental_report_contains_only_new_witnesses(self):
        events = self._irq_read_write_events(reset=False)
        feedback = InteractionFeedback()
        feedback.ingest(events[:9])
        first = feedback.incremental_summary()
        self.assertEqual(len(first["delta_edges"]), 3)
        self.assertEqual(first["delta_observed_paths"], [])
        feedback.ingest(events[9:])
        second = feedback.incremental_summary()
        self.assertEqual(len(second["delta_edges"]), 1)
        self.assertEqual(len(second["delta_observed_paths"]), 1)
        self.assertEqual(feedback.incremental_summary()["delta_edges"], [])
        self.assertEqual(feedback.incremental_summary()["delta_observed_paths"], [])
        self.assertEqual(len(feedback.summary()["edges"]), 4)
        self.assertEqual(len(feedback.summary()["observed_paths"]), 1)

    def test_journal_backed_online_feedback_matches_self_owned_summary(self):
        events = self._irq_taken_read_write_events(reset=False)
        backing = {event["event_id"]: event for event in events}
        online = InteractionFeedback(event_lookup=backing.get)
        online.ingest(events[:7])
        online.ingest(events[:7])
        online.ingest(events[7:])
        self.assertEqual(online.summary(), summarize_interactions(events))
        self.assertEqual(len(online._events), len(events))
        self.assertEqual(online._epoch_by_event_id, {})
        with self.assertRaisesRegex(ValueError, "different evidence"):
            online.ingest([{"event_id": 1, "kind": "wrong"}])
        with self.assertRaisesRegex(ValueError, "contiguous"):
            online.ingest([{"event_id": len(events) + 2, "kind": "noop"}])

    def test_journal_backed_feedback_skips_preexisting_bootstrap_prefix(self):
        events = [{"event_id": 1, "kind": "source_injection",
                   "component": "bootstrap", "port": "pin"},
                  {"event_id": 2, "kind": "source_injection",
                   "component": "cpu", "port": "pin"}]
        backing = {event["event_id"]: event for event in events}
        online = InteractionFeedback(event_lookup=backing.get, starting_event_id=1)
        online.ingest(events)
        self.assertEqual(1, online.summary()["event_count"])
        self.assertEqual({"source_injected:cpu.pin": 1}, online.summary()["stages"])


if __name__ == "__main__":
    unittest.main()
