"""Online RFuzz source scoring and instruction evidence boundaries."""

import unittest
from collections import Counter

from myfuzz.integration.scenario_rfuzz import (ScenarioRfuzzExecutor,
                                              _GpioPinIrqEvidence,
                                              _InstructionEvidence)
from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_online_decoder
from myfuzz.scenario.interaction_feedback import InteractionFeedback
from myfuzz.scenario.batch import BatchSourceEvent
from myfuzz.scenario.online_case_decoder import OnlineSource
from myfuzz.scenario.rv32i_sources import Rv32iInstruction, fragment_bytes
from myfuzz.scenario.session_runtime import OnlineInstruction


class OnlineCreditTests(unittest.TestCase):
    def test_new_witnessed_mmio_edge_changes_next_legal_path_selection(self):
        from tests.scenario.test_interaction_feedback_incremental import (
            InteractionFeedbackIncrementalTest)

        decoder = make_ibex_pulp_dual_source_online_decoder()
        executor = object.__new__(ScenarioRfuzzExecutor)
        executor.online_decoder = decoder
        executor._target_hits = {target for source in decoder.sources
                                 for target in source.coverage_target_ids}
        executor._selection_uses = Counter()
        executor._selection_gains = Counter()
        cpu_key = (0, 0, decoder.sources[0].source_id)
        executor._online_interval_witnesses = {cpu_key: {11}}
        raw = bytes((0, 1, 0, 0, 0, 0, 0, 0))
        before_weights = executor._online_weights()
        before = decoder.decode(raw, coverage_hints=before_weights)

        feedback = InteractionFeedback()
        feedback.ingest(InteractionFeedbackIncrementalTest._irq_read_write_events(reset=False))
        interaction = feedback.incremental_summary()
        interaction['new_run_features'] = sorted(interaction['feature_deltas'])
        self.assertIn('mmio_write_delivered:cpu:gpio_a', interaction['new_run_features'])
        executor._credit_online_interactions(interaction)

        after_weights = executor._online_weights()
        after = decoder.decode(raw, coverage_hints=after_weights)
        self.assertEqual('ip_to_cpu_to_ip.closed_loop', decoder.path_target(before.path_id))
        self.assertEqual('cpu_to_ip_to_cpu.closed_loop', decoder.path_target(after.path_id))
        self.assertGreater(after_weights[decoder.sources[0].source_id],
                           before_weights[decoder.sources[0].source_id])
        self.assertEqual(before_weights[decoder.sources[1].source_id],
                         after_weights[decoder.sources[1].source_id])

    def test_equal_online_weights_hint_prefers_less_used_source(self):
        executor = object.__new__(ScenarioRfuzzExecutor)
        cpu = OnlineSource("cpu.program", "instruction", "cpu",
                           "CPU_TO_IP_TO_CPU", "cpu.closed_loop")
        pin = OnlineSource("gpio_b.pin", "source", "gpio_b",
                           "IP_TO_CPU_TO_IP", "pin.closed_loop",
                           port="gpio_in", bit_offset=8, width=1)
        executor.online_decoder = type("Decoder", (), {
            "sources": (cpu, pin), "instruction_cursor": 0,
            "instruction_end": 4})()
        executor._target_hits = set()
        executor._selection_uses = Counter({(0, 0, cpu.source_id): 100,
                                            (0, 1, pin.source_id): 70})
        executor._selection_gains = Counter()
        executor._hint_sequence = 0
        executor.replay_only = False
        executor.run_id = "equal-weight-hint"
        executor._max_completed_buffer_id = 0
        executor._latest_completed_batch = ()
        self.assertEqual({cpu.source_id: 8, pin.source_id: 8},
                         executor._online_weights())
        self.assertEqual(pin.source_id, executor.mutation_hint()["source_id"])

    def test_unseen_declared_coverage_target_increases_source_weight(self):
        executor = object.__new__(ScenarioRfuzzExecutor)
        source = OnlineSource("cpu.program", "instruction", "cpu",
                              "CPU_TO_IP_TO_CPU", "cpu.closed_loop",
                              coverage_target_ids=("gpio_a_output_bit0",))
        executor.online_decoder = type("Decoder", (), {"sources": (source,)})()
        executor.targets = ()
        executor._target_hits = set()
        executor._selection_uses = {(0, 0, source.source_id): 0}
        executor._selection_gains = {(0, 0, source.source_id): 0}
        unseen = executor._online_weights()[source.source_id]
        executor._target_hits.add("gpio_a_output_bit0")
        seen = executor._online_weights()[source.source_id]
        self.assertEqual(64, unseen - seen)

    def test_multiword_instruction_needs_full_fetch_and_matching_mmio(self):
        data = fragment_bytes((
            Rv32iInstruction("LUI", rd=2, immediate=0),
            Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=7),
            Rv32iInstruction("LUI", rd=1, immediate=0x40001),
            Rv32iInstruction("SW", rs1=1, rs2=2, immediate=12)))
        source = OnlineInstruction("case:cpu", "cpu", 0x11000, data.hex())
        evidence = _InstructionEvidence(source)

        def read(event_id, address, offset):
            return {"event_id": event_id, "kind": "memory_read",
                    "component": "cpu", "address": address,
                    "transaction": {"channel_id": "instr"},
                    "data_hex": data[offset:offset + 4].hex(),
                    "writer_event_ids": [source.action_id] * 4}

        self.assertEqual((False, False), evidence.ingest((read(1, 0x11000, 0),)))
        self.assertEqual((False, False), evidence.ingest((read(2, 0x11004, 4),)))
        self.assertEqual((False, False), evidence.ingest((read(3, 0x11008, 8),)))
        self.assertEqual((True, False), evidence.ingest((read(4, 0x1100c, 12),)))
        self.assertEqual((True, False), evidence.ingest((
            {"event_id": 5, "kind": "mmio_acceptance", "component": "cpu",
             "address": 0x4000100c, "write": False},)))
        self.assertEqual((True, False), evidence.ingest((
            {"event_id": 6, "kind": "mmio_acceptance", "component": "cpu",
             "address": 0x4000100c, "write": True, "write_value": 1},)))
        self.assertEqual((True, True), evidence.ingest((
            {"event_id": 7, "kind": "mmio_acceptance", "component": "cpu",
             "address": 0x4000100c, "write": True, "write_value": 7},)))

    def test_store_without_static_value_cannot_claim_later_same_address(self):
        data = fragment_bytes((
            Rv32iInstruction("LUI", rd=1, immediate=0x40001),
            Rv32iInstruction("SW", rs1=1, rs2=2, immediate=12)))
        source = OnlineInstruction("unknown-value", "cpu", 0x11000, data.hex())
        evidence = _InstructionEvidence(source)
        self.assertIsNone(evidence.expected_mmio)

    def test_later_fetch_claims_same_value_transaction_once(self):
        data = fragment_bytes((
            Rv32iInstruction("LUI", rd=2, immediate=0),
            Rv32iInstruction("ADDI", rd=2, rs1=2, immediate=7),
            Rv32iInstruction("LUI", rd=1, immediate=0x40001),
            Rv32iInstruction("SW", rs1=1, rs2=2, immediate=12)))
        older = _InstructionEvidence(OnlineInstruction("older", "cpu", 0x11000, data.hex()))
        newer = _InstructionEvidence(OnlineInstruction("newer", "cpu", 0x11010, data.hex()))
        older.fetched_at = 10
        newer.fetched_at = 20
        pending = {"older": older, "newer": newer}
        ScenarioRfuzzExecutor._online_match_mmio(pending, {
            "event_id": 21, "kind": "mmio_acceptance", "component": "cpu",
            "address": 0x4000100c, "write": True, "write_value": 7})
        self.assertTrue(newer.downstream)
        self.assertFalse(older.downstream)
        self.assertTrue(older.superseded)
        self.assertEqual(21, newer.downstream_event_id)

    def test_interaction_novelty_requires_transaction_in_feature_witness(self):
        feedback = {
            "new_run_features": ["mmio_write_delivered:cpu:gpio_a",
                                 "irq_input_sampled:gpio_b:cpu",
                                 "observed_path:write_bound_then_read:cpu:gpio_a:gpio_b:cpu",
                                 "source_injected:gpio_b.gpio_in"],
            "delta_edges": [
                {"kind": "mmio_write_delivered", "source": "cpu",
                 "target": "gpio_a", "witness_event_ids": [21, 24]},
                {"kind": "irq_input_sampled", "source": "gpio_b",
                 "target": "cpu", "witness_event_ids": [30, 31, 32]}],
            "delta_observed_paths": [
                {"kind": "write_bound_then_read",
                 "components": ["cpu", "gpio_a", "gpio_b", "cpu"],
                 "witness_event_ids": [21, 24, 36, 42]}]}
        gain = ScenarioRfuzzExecutor._witnessed_interaction_gain
        self.assertEqual(2, gain(feedback, {21}))
        self.assertEqual(1, gain(feedback, {30}))
        self.assertEqual(0, gain(feedback, {8}))
        self.assertEqual(0, gain(feedback, set()))

    def test_gpio_pin_irq_witness_can_cross_case_boundaries(self):
        source = BatchSourceEvent("pin-case", "gpio_b", "gpio_in", 1, 8, 1)
        evidence = _GpioPinIrqEvidence(source)
        evidence.ingest({"event_id": 10, "kind": "source_injection",
                         "action_id": source.action_id}, None)
        low = {"event_id": 11, "kind": None, "component": "gpio_b",
               "local_tick": 4, "inputs": {"gpio_in": 256},
               "outputs": {"gpio_in_sync": 0, "irq": 0}}
        evidence.ingest(low, None)
        self.assertEqual(11, evidence.sampled_event_id)
        self.assertIsNone(evidence.start_event_id)
        high = {"event_id": 25, "kind": None, "component": "gpio_b",
                "local_tick": 5, "inputs": {"gpio_in": 256},
                "outputs": {"gpio_in_sync": 256, "irq": 1}}
        evidence.ingest(high, low)
        evidence.ingest({"event_id": 27, "kind": "source_start",
                         "source": ["gpio_b", "irq"], "source_tick": 5}, high)
        self.assertEqual(27, evidence.start_event_id)

    def test_pending_credit_evidence_is_bounded_without_session_mutation(self):
        executor = object.__new__(ScenarioRfuzzExecutor)
        executor._online_evidence_limit = 2
        executor._online_instruction_evidence = {
            str(index): _InstructionEvidence(OnlineInstruction(
                str(index), "cpu", 0x11000 + index * 4, "13000000"))
            for index in range(3)}
        executor._online_pin_evidence = {}
        executor._online_pending_sources = {
            str(index): (object(), (0, 0, "cpu.program")) for index in range(3)}
        executor._trim_online_evidence()
        self.assertEqual(["1", "2"], list(executor._online_instruction_evidence))
        self.assertEqual(["1", "2"], list(executor._online_pending_sources))

    def test_reset_barrier_discards_pending_cross_reset_credit(self):
        executor = object.__new__(ScenarioRfuzzExecutor)
        source = BatchSourceEvent("pin-case", "gpio_b", "gpio_in", 1, 8, 1)
        pin = _GpioPinIrqEvidence(source)
        pin.injection_event_id = 10
        pin.sampled_event_id = 11
        executor._online_pin_evidence = {source.action_id: pin}
        executor._online_last_gpio_step = {"gpio_b": {
            "event_id": 11, "outputs": {"gpio_in_sync": 0, "irq": 0}}}
        executor._online_instruction_evidence = {
            "cpu": _InstructionEvidence(OnlineInstruction(
                "cpu", "cpu", 0x11000, "13000000"))}
        executor._online_pending_sources = {
            source.action_id: (object(), (0, 0, "gpio_b.external_pin8")),
            "cpu": (object(), (0, 0, "cpu.program"))}
        executor._reset_online_credit_evidence()
        self.assertFalse(executor._online_pin_evidence)
        self.assertFalse(executor._online_last_gpio_step)
        self.assertFalse(executor._online_instruction_evidence)
        self.assertFalse(executor._online_pending_sources)


if __name__ == "__main__":
    unittest.main()
