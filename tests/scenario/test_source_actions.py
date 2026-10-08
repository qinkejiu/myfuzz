"""Versioned source actions, exact cross-case witnesses and bounded retention.

Every case here is software only: synthetic journal events stand in for real RTL
evidence, and no harness, memory service or RTL process is started. A synthetic
witness proves the contract, never a real dataflow chain.
"""

from dataclasses import replace
import json
import unittest

from myfuzz.scenario.source_actions import (
    ACTION_SCHEMA_VERSION, INTERRUPT_FLOW, PREREQUISITE_SCHEMA_VERSION,
    CrossCaseEffectTracker, EffectWitness, Prerequisite, PrerequisiteEvaluation,
    SourceAction, SourceActionGate, SourceActionPrerequisiteError,
    SourceActionUnknownAction, TerminationObservation,
    instruction_slot_unmaterialized_prerequisite, ip_register_evidence_ref,
    ip_register_prerequisite, irq_input_delivered_prerequisite,
    irq_input_evidence_ref, irq_pulse_pending_prerequisite,
    irq_pulse_evidence_ref, irq_taken_prerequisite, irq_taken_evidence_ref,
    legacy_memory_write_evidence_ref, legacy_write_prerequisite,
    ram_commit_evidence_ref, ram_commit_prerequisite,
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def commit_event(event_id, byte_offset, *, commit_id, version=1, value=0x5A,
                 memory_id="ram", generation=0, component="cpu"):
    """Synthetic memory_write_commit.v1 journal event (commit stream shape)."""
    commit_id = commit_id if len(commit_id) == 64 else (commit_id * 64)[:64]
    return {
        "event_id": event_id, "component": component, "kind": "memory_write_commit",
        "schema_version": "memory_write_commit.v1", "service_commit_sequence": event_id,
        "commit_id": commit_id,
        "commit_document": {
            "schema_version": "memory_write_commit_receipt.v1",
            "commit_id": commit_id,
            "memory_id": memory_id, "generation": generation,
            "byte_offset": byte_offset, "width_bytes": 1, "byte_enable": 1,
            "version": [generation, version], "commit_status": "complete",
            "enabled_byte_cells": [{"byte_offset": byte_offset, "value": value,
                                    "version": [generation, version],
                                    "writer_kind": "STORE",
                                    "writer_event_id": "case-a:store"}]}}


def legacy_write_event(event_id, byte_offset, *, version=3, byte_enable=0b0001,
                       width_bytes=4, value=0xAA, memory_id="ram",
                       generation=0, component="cpu"):
    return {"event_id": event_id, "component": component, "kind": "memory_write",
            "memory_id": memory_id, "generation": generation,
            "byte_offset": byte_offset, "address": 0x10000 + byte_offset,
            "width_bytes": width_bytes, "byte_enable": byte_enable,
            "value": value, "version": [generation, version]}


def register_commit_event(event_id, *, register="out", version=7,
                          component="gpio_b", reset_epoch=0,
                          observation_event_id=None, post_value=3):
    return {"event_id": event_id, "component": component,
            "kind": "gpio_register_commit",
            "schema_version": "gpio_register_commit.v1", "status": "observed",
            "reason": "actual_apb_register_write", "reset_epoch": reset_epoch,
            "local_tick": event_id, "register": register, "operation": "overwrite",
            "post_value": post_value,
            "observation_event_id": (event_id - 1 if observation_event_id is None
                                     else observation_event_id),
            "bit_resources": [{"version": version, "value": (post_value >> bit) & 1}
                              for bit in range(4)]}


def pulse_start_event(event_id, source_event_id, *, component="gpio_b"):
    return {"event_id": event_id, "component": component, "kind": "pulse_start",
            "source_event_id": source_event_id, "start_cpu_tick": 5,
            "end_cpu_tick_exclusive": 9}


def irq_input_event(event_id, source_event_id, *, cpu_tick=5, component="cpu",
                    value=1):
    return {"event_id": event_id, "component": component, "kind": "cpu_irq_input",
            "cpu_tick": cpu_tick, "value": value, "source_event_id": source_event_id}


def irq_taken_event(event_id, source_event_id, *, cpu_tick=5, component="cpu"):
    return {"event_id": event_id, "component": component, "kind": "cpu_irq_taken",
            "cpu_tick": cpu_tick, "source_event_id": source_event_id}


def instruction_source_event(event_id, address, *, component="cpu",
                             data_hex="13000000", source_event_id="case-a:insn"):
    return {"event_id": event_id, "component": component, "kind": "instruction_source",
            "address": address, "data_hex": data_hex,
            "source_event_id": source_event_id, "generation": 0}


def reset_event(event_id, *, component="cpu"):
    return {"event_id": event_id, "component": component, "kind": "reset_barrier"}


def instruction_action(action_id="case-b:insn", *, prerequisites=(),
                       ownership="fuzzable", kind="instruction",
                       payload=None, flow_id="F1", budget=32,
                       termination=None):
    if payload is None:
        payload = {"address": 0x11000, "words_hex": "13000000"}
    if termination is None:
        termination = TerminationObservation("retirement", f"rvfi:{action_id}")
    return SourceAction(action_id=action_id, kind=kind, component="cpu",
                        source_id="cpu.online_instruction", ownership=ownership,
                        flow_id=flow_id, payload=payload,
                        termination_observation=termination,
                        local_step_budget=budget, prerequisites=tuple(prerequisites))


def external_action(action_id="case-c:pin", *, prerequisites=(), ownership="fuzzable",
                    payload=None, flow_id="F4", budget=16):
    if payload is None:
        payload = {"port": "padin", "bit_offset": 2, "width": 1, "value": 1}
    return SourceAction(action_id=action_id, kind="external_event", component="gpio_b",
                        source_id="gpio_b.external_pin", ownership=ownership,
                        flow_id=flow_id, payload=payload,
                        termination_observation=TerminationObservation(
                            "delivery", f"gpio:{action_id}"),
                        local_step_budget=budget, prerequisites=tuple(prerequisites))


class SourceActionContractTests(unittest.TestCase):
    def test_instruction_action_round_trips_with_ordered_prerequisites(self):
        first = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        second = instruction_slot_unmaterialized_prerequisite(
            "cpu", 0x11000, "reservation:one")
        action = instruction_action(prerequisites=(first, second))
        self.assertEqual(2, len(action.prerequisites))
        self.assertEqual((first, second), action.prerequisites)
        self.assertEqual({"address": 0x11000, "words_hex": "13000000"},
                         dict(action.payload))
        self.assertEqual(64, len(action.action_sha256))
        document = action.document()
        self.assertEqual(ACTION_SCHEMA_VERSION, document["schema_version"])
        self.assertEqual(action, SourceAction.from_document(document))
        self.assertEqual(canonical(document),
                         canonical(SourceAction.from_document(document).document()))

    def test_external_event_payload_is_normalized_and_endpoint_class_kept(self):
        action = external_action(payload={"port": "padin", "bit_offset": 0,
                                          "width": 4, "value": 9,
                                          "endpoint_class": "ip_external_source"})
        self.assertEqual("ip_external_source", action.payload["endpoint_class"])
        defaulted = external_action(action_id="case-d:pin")
        self.assertEqual("environment_source", defaulted.payload["endpoint_class"])
        self.assertNotEqual(action.action_sha256, defaulted.action_sha256)

    def test_tampered_or_unknown_document_is_rejected(self):
        action = instruction_action()
        document = action.document()
        tampered = {**document, "payload": {"address": 0x22000,
                                            "words_hex": "13000000"}}
        with self.assertRaisesRegex(ValueError, "action_sha256"):
            SourceAction.from_document(tampered)
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            SourceAction.from_document({**document, "extra": 1})
        with self.assertRaisesRegex(ValueError, "schema_version"):
            SourceAction.from_document({**document,
                                        "schema_version": "source_action.v2"})
        self.assertEqual(document, action.document())

    def test_unknown_kind_and_missing_ownership_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "kind"):
            instruction_action(kind="program_fragment")
        with self.assertRaisesRegex(ValueError, "ownership"):
            instruction_action(ownership=None)
        with self.assertRaisesRegex(ValueError, "ownership"):
            instruction_action(ownership="Fuzzable")

    def test_loaded_documents_must_carry_their_own_content_digest(self):
        document = instruction_action().document()
        with self.assertRaisesRegex(ValueError, "action_sha256"):
            SourceAction.from_document({**document, "action_sha256": ""})
        prerequisite = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        with self.assertRaisesRegex(ValueError, "prerequisite_id"):
            Prerequisite.from_document({**prerequisite.document(),
                                        "prerequisite_id": ""})
        tracker = CrossCaseEffectTracker()
        witness = tracker.ingest([commit_event(1, 0x10000, commit_id="a")])[0]
        with self.assertRaisesRegex(ValueError, "witness_id"):
            EffectWitness.from_document({**witness.document(), "witness_id": ""})

    def test_non_fuzzable_payload_is_rejected_on_load_as_well(self):
        document = instruction_action(ownership="bound", payload={}).document()
        tampered = {**document,
                    "payload": {"address": 0x11000, "words_hex": "13000000"}}
        with self.assertRaisesRegex(ValueError, "mutable payload"):
            SourceAction.from_document(tampered)

    def test_non_fuzzable_action_must_not_carry_mutable_payload(self):
        for ownership in ("bound", "fixed"):
            with self.subTest(ownership=ownership), \
                    self.assertRaisesRegex(ValueError, "mutable payload"):
                instruction_action(ownership=ownership)
        bound = instruction_action(ownership="bound", payload={})
        self.assertEqual({}, dict(bound.payload))
        self.assertFalse(bound.payload_mutable)
        self.assertTrue(instruction_action().payload_mutable)

    def test_instruction_payload_is_validated(self):
        with self.assertRaisesRegex(ValueError, "word aligned"):
            instruction_action(payload={"address": 0x11002,
                                        "words_hex": "13000000"})
        with self.assertRaisesRegex(ValueError, "hexadecimal"):
            instruction_action(payload={"address": 0x11000, "words_hex": "zz"})
        with self.assertRaisesRegex(ValueError, "whole 32-bit words"):
            instruction_action(payload={"address": 0x11000, "words_hex": "1300"})
        with self.assertRaisesRegex(ValueError, "unknown or missing"):
            instruction_action(payload={"address": 0x11000,
                                        "words_hex": "13000000", "value": 1})

    def test_external_event_payload_is_validated(self):
        with self.assertRaisesRegex(ValueError, "port"):
            external_action(payload={"port": "", "bit_offset": 0, "width": 1,
                                     "value": 0})
        with self.assertRaisesRegex(ValueError, "width"):
            external_action(payload={"port": "padin", "bit_offset": 0,
                                     "width": 0, "value": 0})
        with self.assertRaisesRegex(ValueError, "value"):
            external_action(payload={"port": "padin", "bit_offset": 0,
                                     "width": 1, "value": 2})
        with self.assertRaisesRegex(ValueError, "endpoint_class"):
            external_action(payload={"port": "padin", "bit_offset": 0, "width": 1,
                                     "value": 1, "endpoint_class": "cpu_irq"})

    def test_external_event_cannot_drive_the_cpu_irq_as_a_mutable_source(self):
        with self.assertRaisesRegex(ValueError, INTERRUPT_FLOW):
            external_action(flow_id=INTERRUPT_FLOW)
        # The same declared flow is legal as an observation or a prerequisite.
        observed = external_action(prerequisites=(
            irq_input_delivered_prerequisite("cpu", 3, 5),))
        self.assertEqual(INTERRUPT_FLOW, observed.prerequisites[0].flow_id)
        observing = instruction_action(termination=TerminationObservation(
            "delivery", "cpu_irq_taken:3", flow_id=INTERRUPT_FLOW))
        self.assertEqual(INTERRUPT_FLOW,
                         observing.termination_observation.flow_id)
        with self.assertRaisesRegex(ValueError, "interrupt_flow"):
            external_action(payload={"port": "interrupt_flow", "bit_offset": 0,
                                     "width": 1, "value": 1})
        with self.assertRaisesRegex(ValueError, "flow_id"):
            instruction_action(termination=TerminationObservation(
                "consumption", "x", flow_id="F9"))

    def test_prerequisite_contract_is_strict(self):
        with self.assertRaisesRegex(ValueError, "prerequisite kind"):
            Prerequisite.create("irq_something", {"component": "cpu"},
                                "evidence")
        with self.assertRaisesRegex(ValueError, INTERRUPT_FLOW):
            Prerequisite.create("irq_taken",
                                {"cpu_component": "cpu", "source_event_id": 1,
                                 "cpu_tick": 5}, "evidence")
        with self.assertRaisesRegex(ValueError, "flow_id"):
            Prerequisite.create("ram_byte_version",
                                {"memory_id": "ram", "generation": 0,
                                 "byte_offset": 0}, "evidence",
                                flow_id=INTERRUPT_FLOW)
        with self.assertRaisesRegex(ValueError, "subject"):
            Prerequisite.create("ram_byte_version",
                                {"memory_id": "ram", "generation": 0}, "evidence")
        with self.assertRaisesRegex(ValueError, "evidence_ref"):
            Prerequisite.create("ram_byte_version",
                                {"memory_id": "ram", "generation": 0,
                                 "byte_offset": 0}, "")
        prerequisite = ram_commit_prerequisite("ram", 0, 0x10000, "b" * 64)
        self.assertEqual(PREREQUISITE_SCHEMA_VERSION,
                         prerequisite.document()["schema_version"])
        self.assertEqual(prerequisite,
                         Prerequisite.from_document(prerequisite.document()))
        tampered = {**prerequisite.document(), "evidence_ref": "c" * 64}
        with self.assertRaisesRegex(ValueError, "prerequisite_id"):
            Prerequisite.from_document(tampered)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            instruction_action(prerequisites=(prerequisite, prerequisite))

    def test_termination_and_budget_are_validated(self):
        with self.assertRaisesRegex(ValueError, "termination kind"):
            TerminationObservation("observed", "x")
        with self.assertRaisesRegex(ValueError, "evidence_ref"):
            TerminationObservation("retirement", "")
        with self.assertRaisesRegex(ValueError, "evidence_ref"):
            TerminationObservation("incomplete", "x")
        self.assertEqual("incomplete",
                         TerminationObservation("incomplete", "").kind)
        for budget in (0, -1, True, 1.5, 10 ** 9):
            with self.subTest(budget=budget), \
                    self.assertRaisesRegex(ValueError, "local_step_budget"):
                instruction_action(budget=budget)

    def test_action_and_prerequisite_ids_are_content_addressed(self):
        first = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        second = ram_commit_prerequisite("ram", 0, 0x10000, "b" * 64)
        self.assertNotEqual(first.prerequisite_id, second.prerequisite_id)
        action = instruction_action(prerequisites=(first,))
        changed = instruction_action(prerequisites=(second,))
        self.assertNotEqual(action.action_sha256, changed.action_sha256)
        self.assertEqual(64, len(first.prerequisite_id))


class CrossCaseEffectTrackerTests(unittest.TestCase):
    def test_ram_commit_requires_the_exact_commit_evidence(self):
        tracker = CrossCaseEffectTracker()
        event = commit_event(4, 0x10000, commit_id="a")
        tracker.ingest([event])
        matched = ram_commit_prerequisite("ram", 0, 0x10000,
                                          ram_commit_evidence_ref("a" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(
            prerequisites=(matched,))))
        other = ram_commit_prerequisite("ram", 0, 0x10000,
                                        ram_commit_evidence_ref("b" * 64))
        evaluation = tracker.satisfied(instruction_action(prerequisites=(other,)))
        self.assertFalse(evaluation)
        self.assertEqual((other,), evaluation.missing)
        self.assertEqual("missing_effects", evaluation.reason)
        self.assertEqual("source_action.prerequisites",
                         evaluation.document()["reason_field"])

    def test_later_commit_supersedes_earlier_evidence(self):
        tracker = CrossCaseEffectTracker()
        first = commit_event(1, 0x10000, commit_id="a", version=1)
        tracker.ingest([first])
        first_prerequisite = ram_commit_prerequisite(
            "ram", 0, 0x10000, ram_commit_evidence_ref("a" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(
            prerequisites=(first_prerequisite,))))
        tracker.ingest([commit_event(2, 0x10000, commit_id="b", version=2)])
        evaluation = tracker.satisfied(instruction_action(
            prerequisites=(first_prerequisite,)))
        self.assertFalse(evaluation)
        self.assertEqual((first_prerequisite,), evaluation.missing)
        second_prerequisite = ram_commit_prerequisite(
            "ram", 0, 0x10000, ram_commit_evidence_ref("b" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(
            prerequisites=(second_prerequisite,))))

    def test_legacy_memory_write_records_only_enabled_lanes(self):
        tracker = CrossCaseEffectTracker()
        tracker.ingest([legacy_write_event(6, 0x200, byte_enable=0b0101)])
        enabled = legacy_write_prerequisite("ram", 0, 0x200, 6)
        disabled = legacy_write_prerequisite("ram", 0, 0x201, 6)
        self.assertTrue(tracker.satisfied(instruction_action(
            prerequisites=(enabled,))))
        self.assertFalse(tracker.satisfied(instruction_action(
            prerequisites=(disabled,))))
        self.assertEqual(legacy_memory_write_evidence_ref(6),
                         tracker.matching_witness(enabled).evidence_ref)

    def test_ip_register_and_irq_effects_need_exact_identities(self):
        tracker = CrossCaseEffectTracker()
        commit = register_commit_event(9, version=7)
        tracker.ingest([commit])
        reference = ip_register_evidence_ref("gpio_b", "out", 0, 8, 7)
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            ip_register_prerequisite("gpio_b", "out", 0, 8, 7),))))
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            ip_register_prerequisite("gpio_b", "out", 0, 8, 6),))))
        self.assertEqual(reference, tracker.matching_witness(
            ip_register_prerequisite("gpio_b", "out", 0, 8, 7)).evidence_ref)

        tracker.ingest([pulse_start_event(10, 1)])
        pending = irq_pulse_pending_prerequisite("gpio_b", 1)
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(pending,))))
        tracker.ingest([irq_input_event(11, 1, cpu_tick=5)])
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            irq_input_delivered_prerequisite("cpu", 1, 5),))))
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            irq_input_delivered_prerequisite("cpu", 1, 6),))))
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            irq_pulse_pending_prerequisite("gpio_b", 1),))))
        tracker.ingest([irq_taken_event(12, 1, cpu_tick=5)])
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            irq_taken_prerequisite("cpu", 1, 5),))))
        self.assertEqual(
            irq_pulse_evidence_ref("gpio_b", 1),
            tracker.matching_witness(
                irq_pulse_pending_prerequisite("gpio_b", 1)).evidence_ref)
        self.assertEqual(
            irq_taken_evidence_ref("cpu", 1, 5),
            tracker.matching_witness(
                irq_taken_prerequisite("cpu", 1, 5)).evidence_ref)

    def test_irq_input_without_value_is_not_a_delivery(self):
        tracker = CrossCaseEffectTracker()
        tracker.ingest([irq_input_event(1, 2, value=0)])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            irq_input_delivered_prerequisite("cpu", 2, 5),))))

    def test_expired_pulse_is_not_restored_by_reingesting_its_start(self):
        tracker = CrossCaseEffectTracker()
        start = pulse_start_event(3, 1)
        tracker.ingest([start])
        tracker.ingest([{"event_id": 4, "component": "gpio_b",
                         "kind": "pulse_expired", "source_event_id": 1}])
        pending = irq_pulse_pending_prerequisite("gpio_b", 1)
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(pending,))))
        tracker.ingest([start])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(pending,))))
        tracker.ingest([pulse_start_event(5, 2)])
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            irq_pulse_pending_prerequisite("gpio_b", 2),))))

    def test_instruction_slot_stays_unmaterialized_only_until_real_evidence(self):
        tracker = CrossCaseEffectTracker()
        tracker.register_instruction_slot("cpu", 0x11000, "reservation:one",
                                          event_id=1)
        prerequisite = instruction_slot_unmaterialized_prerequisite(
            "cpu", 0x11000, "reservation:one")
        action = instruction_action(prerequisites=(prerequisite,))
        self.assertTrue(tracker.satisfied(action))
        tracker.ingest([instruction_source_event(2, 0x11000)])
        evaluation = tracker.satisfied(action)
        self.assertFalse(evaluation)
        self.assertEqual((prerequisite,), evaluation.missing)
        self.assertEqual("materialized_instruction_slot", evaluation.reason)

    def test_store_materializes_a_reserved_slot(self):
        tracker = CrossCaseEffectTracker()
        tracker.register_instruction_slot("cpu", 0x11000, "reservation:one",
                                          event_id=1)
        tracker.ingest([legacy_write_event(2, 0x1000, byte_enable=0b0001)])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", 0x11000, "reservation:one"),))))
        tracker.ingest([{"event_id": 3, "component": "cpu", "kind": "memory_write",
                         "address": 0x11000, "width_bytes": 4, "byte_enable": 0b0001,
                         "memory_id": "ram", "generation": 0, "byte_offset": 0x1000,
                         "value": 0x13, "version": [0, 4]}])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", 0x11000, "reservation:one"),))))

    def test_unknown_or_wrong_reservation_slot_is_not_satisfied(self):
        tracker = CrossCaseEffectTracker()
        tracker.register_instruction_slot("cpu", 0x11000, "reservation:one",
                                          event_id=1)
        unknown = instruction_action(prerequisites=(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", 0x12000, "reservation:one"),))
        self.assertFalse(tracker.satisfied(unknown))
        wrong_reference = instruction_action(prerequisites=(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", 0x11000, "reservation:two"),))
        self.assertFalse(tracker.satisfied(wrong_reference))

    def test_capacity_eviction_does_not_restore_dropped_evidence(self):
        tracker = CrossCaseEffectTracker(max_effects=2)
        events = [commit_event(index, 0x10000 + index, commit_id=chr(96 + index))
                  for index in (1, 2, 3)]
        tracker.ingest(events)
        self.assertEqual(2, tracker.pending_count)
        evicted = ram_commit_prerequisite(
            "ram", 0, 0x10001, ram_commit_evidence_ref("a" * 64))
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(evicted,))))
        tracker.ingest([events[0]])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(evicted,))))
        self.assertGreaterEqual(tracker.counters["stale"], 1)
        self.assertGreaterEqual(tracker.counters["evicted"], 1)

    def test_aging_expires_effects_and_blocks_replay_of_old_events(self):
        tracker = CrossCaseEffectTracker(max_age_events=10)
        event = commit_event(1, 0x10000, commit_id="a")
        tracker.ingest([event])
        prerequisite = ram_commit_prerequisite(
            "ram", 0, 0x10000, ram_commit_evidence_ref("a" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))
        tracker.ingest([{"event_id": 40, "component": "cpu", "kind": "local_tick_sample"}])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))
        self.assertGreaterEqual(tracker.counters["expired"], 1)
        tracker.ingest([event])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))

    def test_reset_drops_effects_and_old_evidence_cannot_return(self):
        tracker = CrossCaseEffectTracker()
        event = commit_event(2, 0x10000, commit_id="a")
        tracker.ingest([event])
        prerequisite = ram_commit_prerequisite(
            "ram", 0, 0x10000, ram_commit_evidence_ref("a" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))
        tracker.ingest([reset_event(5)])
        self.assertEqual(1, tracker.epoch)
        self.assertEqual(0, tracker.pending_count)
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))
        tracker.ingest([event])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(prerequisite,))))
        after = commit_event(6, 0x10000, commit_id="b", version=2)
        tracker.ingest([after])
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("b" * 64)),))))

    def test_reset_clears_slot_reservations_and_materialization(self):
        tracker = CrossCaseEffectTracker()
        tracker.register_instruction_slot("cpu", 0x11000, "reservation:one",
                                          event_id=1)
        tracker.ingest([instruction_source_event(2, 0x11000)])
        tracker.ingest([reset_event(3)])
        tracker.register_instruction_slot("cpu", 0x11000, "reservation:one",
                                          event_id=4)
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", 0x11000, "reservation:one"),))))

    def test_conflicting_duplicate_event_is_barred_not_overwritten(self):
        tracker = CrossCaseEffectTracker()
        tracker.ingest([commit_event(3, 0x10000, commit_id="a", version=1)])
        tracker.ingest([commit_event(3, 0x10000, commit_id="b", version=2)])
        self.assertGreaterEqual(tracker.counters["conflicts"], 1)
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("a" * 64)),))))
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("b" * 64)),))))
        # A barred subject stays barred: later evidence cannot silently win.
        tracker.ingest([commit_event(4, 0x10000, commit_id="c", version=3)])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("c" * 64)),))))
        self.assertTrue(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("a" * 64)),))))
        # Only a measured reset clears the barred subject.
        tracker.ingest([reset_event(9)])
        self.assertFalse(tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("a" * 64)),))))
        tracker.ingest([commit_event(10, 0x10000, commit_id="c", version=4)])
        recovered = tracker.satisfied(instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("c" * 64)),)))
        self.assertTrue(recovered, recovered.document())

    def test_effect_for_another_generation_or_memory_never_matches(self):
        tracker = CrossCaseEffectTracker()
        tracker.ingest([commit_event(5, 0x10000, commit_id="a", generation=1)])
        same_generation = ram_commit_prerequisite(
            "ram", 1, 0x10000, ram_commit_evidence_ref("a" * 64))
        other_generation = ram_commit_prerequisite(
            "ram", 0, 0x10000, ram_commit_evidence_ref("a" * 64))
        other_memory = ram_commit_prerequisite(
            "other", 1, 0x10000, ram_commit_evidence_ref("a" * 64))
        self.assertTrue(tracker.satisfied(instruction_action(
            prerequisites=(same_generation,))))
        self.assertFalse(tracker.satisfied(instruction_action(
            prerequisites=(other_generation,))))
        self.assertFalse(tracker.satisfied(instruction_action(
            prerequisites=(other_memory,))))

    def test_malformed_events_create_no_witness(self):
        tracker = CrossCaseEffectTracker()
        tracker.ingest([
            {"kind": "memory_write_commit", "commit_id": "a" * 64},
            {"event_id": 1, "kind": "memory_write_commit", "commit_id": 7},
            {"event_id": 2, "kind": "gpio_register_commit", "status": "unknown"},
            {"event_id": 3, "kind": "cpu_irq_input", "value": 1,
             "source_event_id": "not-an-int"},
            "not-an-event",
        ])
        self.assertEqual(0, tracker.pending_count)
        self.assertGreaterEqual(tracker.counters["malformed"], 3)
        self.assertFalse(tracker.degraded)

    def test_pending_stays_bounded_after_fifty_thousand_events(self):
        tracker = CrossCaseEffectTracker(max_effects=256, max_slots=32,
                                         max_age_events=1000)
        actions = []
        for index in range(1, 55001):
            selector = index % 5
            if selector == 0:
                event = commit_event(index, 0x10000 + index,
                                     commit_id=f"{index:064x}")
            elif selector == 1:
                event = register_commit_event(index, register=f"reg{index % 4}",
                                              version=index)
            elif selector == 2:
                event = pulse_start_event(index, index)
            elif selector == 3:
                event = irq_input_event(index, index, cpu_tick=index)
            else:
                event = instruction_source_event(
                    index, 0x11000 + (index % 16) * 4, source_event_id=f"s{index}")
            tracker.ingest([event])
            actions.append(event["event_id"])
        bounds = tracker.bounds
        self.assertLessEqual(tracker.pending_count, bounds["max_pending"])
        self.assertEqual(55000, tracker.cursor)
        self.assertLessEqual(len(tracker._effects), bounds["max_effects"])
        self.assertGreater(tracker.counters["evicted"] + tracker.counters["expired"], 0)
        self.assertTrue(bounds["max_pending"] <= bounds["max_effects"]
                        + 2 * bounds["max_slots"])

    def test_tracker_document_is_a_bounded_snapshot(self):
        tracker = CrossCaseEffectTracker(max_effects=4)
        tracker.ingest([commit_event(index, 0x10000 + index,
                                     commit_id=f"{index:064x}")
                        for index in range(1, 20)])
        document = tracker.document()
        self.assertEqual("cross_case_effect_tracker.v1", document["schema_version"])
        self.assertEqual(4, document["effect_count"])
        self.assertLessEqual(len(canonical(document)), 4096)
        json.loads(canonical(document))


class SourceActionGateTests(unittest.TestCase):
    def test_gate_refuses_unregistered_and_unsatisfied_actions(self):
        tracker = CrossCaseEffectTracker()
        gate = SourceActionGate(tracker)
        prerequisite = ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64)
        action = instruction_action(prerequisites=(prerequisite,))
        with self.assertRaisesRegex(SourceActionUnknownAction, "not registered"):
            gate.require(action)
        gate.register(action)
        with self.assertRaises(SourceActionPrerequisiteError) as caught:
            gate.require(action.action_id)
        evaluation = caught.exception.evaluation
        self.assertFalse(evaluation.satisfied)
        self.assertEqual((prerequisite,), evaluation.missing)
        tracker.ingest([commit_event(2, 0x10000, commit_id="a")])
        self.assertIs(action, gate.require(action.action_id))
        self.assertTrue(gate.evaluate(action).satisfied)
        self.assertTrue(gate.evaluate(action).document()["satisfied"])

    def test_gate_observe_ingests_receipt_evidence_by_case(self):
        tracker = CrossCaseEffectTracker()
        gate = SourceActionGate(tracker)

        class Receipt:
            case_id = "case-a"

            def __init__(self, events):
                self.events = events

        created = gate.observe(Receipt([commit_event(7, 0x10000, commit_id="a")]))
        self.assertEqual(1, len(created))
        self.assertEqual("case-a", tracker.matching_witness(
            ram_commit_prerequisite("ram", 0, 0x10000,
                                    ram_commit_evidence_ref("a" * 64))).case_id)

    def test_gate_can_record_without_enforcing(self):
        tracker = CrossCaseEffectTracker()
        gate = SourceActionGate(tracker, enforce=False)
        action = instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64),))
        gate.register(action)
        evaluation = gate.evaluate(action)
        self.assertFalse(evaluation.satisfied)
        self.assertIs(action, gate.require(action))
        self.assertGreaterEqual(gate.counters["refused"], 1)


class EffectWitnessTests(unittest.TestCase):
    def test_witness_document_is_content_addressed_and_round_trips(self):
        tracker = CrossCaseEffectTracker()
        created = tracker.ingest([commit_event(4, 0x10000, commit_id="a")])
        witness = created[0]
        self.assertIsInstance(witness, EffectWitness)
        self.assertEqual(64, len(witness.witness_id))
        document = witness.document()
        self.assertEqual("cross_case_effect_witness.v1", document["schema_version"])
        self.assertEqual(witness, EffectWitness.from_document(document))
        with self.assertRaisesRegex(ValueError, "witness_id"):
            EffectWitness.from_document({**document, "evidence_ref": "b" * 64})

    def test_evaluation_document_names_every_missing_prerequisite(self):
        tracker = CrossCaseEffectTracker()
        action = instruction_action(prerequisites=(
            ram_commit_prerequisite("ram", 0, 0x10000, "a" * 64),
            instruction_slot_unmaterialized_prerequisite("cpu", 0x11000, "r:1")))
        evaluation = tracker.satisfied(action)
        self.assertIsInstance(evaluation, PrerequisiteEvaluation)
        self.assertFalse(evaluation)
        self.assertEqual("case-b:insn", evaluation.action_id)
        document = evaluation.document()
        self.assertEqual(2, len(document["missing"]))
        self.assertEqual(["ram_byte_version", "instruction_slot_unmaterialized"],
                         [item["kind"] for item in document["missing"]])
        self.assertEqual("missing_effects", document["reason"])
        self.assertTrue(tracker.satisfied(instruction_action()).satisfied)


if __name__ == "__main__":
    unittest.main()
