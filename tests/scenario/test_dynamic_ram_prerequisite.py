"""Dynamic pre-admission RAM byte prerequisites bound from retained evidence.

Software only: synthetic journal events stand in for real RTL evidence, and no
harness, memory service or RTL process is started.  A bound witness proves that
a *recorded* observation matched the trusted declaration; it never claims an
unobserved causal chain and it never turns a RAM value into a fuzzable input.

Covered here:
* the P3 shape: case one's real Store commit is the retained witness case three's
  Load action is bound to, field by field, before the reader is admitted;
* the selection rule (latest retained evidence, deterministic tie break) and the
  proof document a reviewer recomputes (``bound_witness.v1``);
* fail-closed negatives: no retained witness, undeclared offset/memory/source
  kind, provenance the tracker never retained, a superseded version, and a
  forged or tampered proof document;
* the safety boundary: the binder never writes the committed byte value into an
  action payload, and an external source that would carry that value as its own
  mutable input is refused;
* boundedness: the retained index and the provenance index keep their declared
  bounds over a long synthetic sequence.
"""

from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from myfuzz.scenario import dynamic_prerequisites as dynamic_module
from myfuzz.scenario.source_actions import (
    BOUND_WITNESS_SCHEMA_VERSION, DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION,
    LATEST_EFFECT_ORDER, TRUSTED_RAM_DECLARATION_SCHEMA_VERSION,
    BoundWitness, CrossCaseEffectTracker, DynamicBindingRefused,
    DynamicBindingUnbound, DynamicEffectBinding, DynamicPrerequisiteBinder,
    SourceAction, SourceActionGate, SourceActionPrerequisiteError,
    TerminationObservation, TrustedRamByteDeclaration, bind_latest_effect,
    legacy_memory_write_evidence_ref, ram_commit_evidence_ref,
    ram_commit_prerequisite,
)

BYTE = 0x1000
OTHER_BYTE = 0x1004
MEMORY = "ram"


# --------------------------------------------------------------------------
# synthetic journal events (the shapes the receipts really carry)
# --------------------------------------------------------------------------

def commit_event(event_id, *, commit_id, byte_offset=BYTE, memory_id=MEMORY,
                 generation=0, version=1, value=0x5A, writer_kind="STORE",
                 commit_status="complete"):
    """Synthetic ``memory_write_commit.v1`` event (commit-stream shape)."""
    commit_id = commit_id if len(commit_id) == 64 else (commit_id * 64)[:64]
    return {
        "event_id": event_id, "component": "cpu", "kind": "memory_write_commit",
        "schema_version": "memory_write_commit.v1",
        "service_commit_sequence": event_id, "commit_id": commit_id,
        "commit_document": {
            "schema_version": "memory_write_commit_receipt.v1",
            "commit_id": commit_id, "memory_id": memory_id,
            "generation": generation, "byte_offset": byte_offset,
            "width_bytes": 1, "byte_enable": 1,
            "version": [generation, version], "commit_status": commit_status,
            "enabled_byte_cells": [{
                "byte_offset": byte_offset, "value": value,
                "version": [generation, version], "writer_kind": writer_kind,
                "writer_event_id": f"case:store:{event_id}"}]}}


def legacy_write_event(event_id, *, byte_offset=BYTE, memory_id=MEMORY,
                       generation=0, version=3, value=0xAA):
    """Synthetic legacy ``memory_write`` event: it declares no writer kind."""
    return {"event_id": event_id, "component": "cpu", "kind": "memory_write",
            "memory_id": memory_id, "generation": generation,
            "byte_offset": byte_offset, "address": 0x10000 + byte_offset,
            "width_bytes": 1, "byte_enable": 1, "value": value,
            "version": [generation, version]}


def instruction_source_event(event_id, address=0x11000):
    return {"event_id": event_id, "component": "cpu", "kind": "instruction_source",
            "address": address, "data_hex": "13000000",
            "source_event_id": f"s{event_id}", "generation": 0}


def reset_event(event_id):
    return {"event_id": event_id, "component": "cpu", "kind": "reset_barrier"}


def receipt(case_id, events):
    return SimpleNamespace(case_id=case_id, events=tuple(events))


def instruction_action(action_id="case-3:load", *, prerequisites=(),
                       address=0x11000):
    return SourceAction(
        action_id=action_id, kind="instruction", component="cpu",
        source_id="cpu.online_instruction", ownership="fuzzable", flow_id="F1",
        payload={"address": address, "words_hex": "13000000"},
        termination_observation=TerminationObservation("retirement",
                                                       f"rvfi:{action_id}"),
        local_step_budget=32, prerequisites=tuple(prerequisites))


def external_action(action_id="case-c:pin", *, value=1, prerequisites=()):
    return SourceAction(
        action_id=action_id, kind="external_event", component="gpio_b",
        source_id="gpio_b.external_pin", ownership="fuzzable", flow_id="F4",
        payload={"port": "padin", "bit_offset": 2, "width": 8, "value": value},
        termination_observation=TerminationObservation("delivery",
                                                       f"gpio:{action_id}"),
        local_step_budget=16, prerequisites=tuple(prerequisites))


def declaration(**kwargs):
    kwargs.setdefault("memory_id", MEMORY)
    kwargs.setdefault("byte_offsets", (BYTE,))
    return TrustedRamByteDeclaration(**kwargs)


def binder(tracker=None, *, spec=None, **kwargs):
    return DynamicPrerequisiteBinder(
        CrossCaseEffectTracker() if tracker is None else tracker,
        declaration() if spec is None else spec, **kwargs)


# --------------------------------------------------------------------------
# The P3 shape: case one's Store witness is what case three's Load is bound to
# --------------------------------------------------------------------------

def test_the_reader_case_is_bound_to_the_store_witness_field_by_field():
    tracker = CrossCaseEffectTracker(max_effects=64)
    gate = SourceActionGate(tracker)
    subject = binder(tracker, spec=declaration(writer_kinds=("STORE",)))
    commit_id = "a" * 64

    store = instruction_action("case-1:store", address=0x11000)
    gate.register(store)
    assert gate.require(store) is store
    reader = instruction_action("case-3:load", address=0x11004)

    # Before case one commits anything the reader cannot be bound: fail-closed.
    with pytest.raises(DynamicBindingUnbound, match="no retained witness"):
        subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE, case_id="case-3")
    assert subject.counters["refused"] + subject.counters["unbound"] == 1

    subject.observe(receipt("case-1", [commit_event(1, commit_id=commit_id,
                                                    version=3, value=0x5A)]))
    bound = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE,
                         case_id="case-3")
    assert isinstance(bound, DynamicEffectBinding)
    assert bound.state == "bound" and bool(bound) is True
    assert bound.action.action_id == reader.action_id
    # Exactly one prerequisite was injected and it pins the retained evidence.
    injected = bound.action.prerequisites
    assert len(injected) == len(reader.prerequisites) + 1
    assert injected[-1] is bound.prerequisite
    assert injected[-1].kind == "ram_byte_version"
    assert dict(injected[-1].subject) == {"memory_id": MEMORY, "generation": 0,
                                          "byte_offset": BYTE}
    assert injected[-1].evidence_ref == ram_commit_evidence_ref(commit_id)

    # The proof document names the selected witness field by field.
    proof = bound.document()["bound_witness"]
    assert proof["schema_version"] == BOUND_WITNESS_SCHEMA_VERSION
    assert proof["evidence_ref"] == ram_commit_evidence_ref(commit_id)
    assert proof["event_id"] == 1
    assert proof["generation"] == 0
    assert proof["byte_offset"] == BYTE
    assert proof["memory_id"] == MEMORY
    assert proof["value"] == 0x5A
    assert proof["case_id"] == "case-1"
    assert proof["writer_kind"] == "STORE"
    assert proof["consumer_case_id"] == "case-3"
    assert proof["prerequisite_id"] == injected[-1].prerequisite_id
    assert proof["selection"]["order"] == list(LATEST_EFFECT_ORDER)
    assert json.loads(json.dumps(bound.document())) == bound.document()

    # The payload the fuzzer mutates is untouched by the binding.
    assert dict(bound.action.payload) == dict(reader.payload)
    assert bound.document()["payload_unchanged"] is True
    assert bound.action.action_sha256 != reader.action_sha256

    # The gate admits the reader only because the store's own evidence is retained.
    gate.register(bound.action)
    admitted = gate.require(bound.action)
    assert admitted is bound.action
    evaluation = gate.evaluate(bound.action)
    assert evaluation.satisfied is True
    assert evaluation.matched == (ram_commit_evidence_ref(commit_id),)
    # And the reviewer can re-check the proof against the live tracker.
    assert subject.verify(proof).document() == proof


def test_the_bound_version_supersedes_and_a_stale_binding_can_no_longer_admit():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker)
    reader = instruction_action()
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a",
                                                    version=1, value=0x11)]))
    first = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert first.document()["bound_witness"]["value"] == 0x11
    assert tracker.satisfied(first.action).satisfied is True

    # A later committed write to the same byte moves the retained version.
    subject.observe(receipt("case-2", [commit_event(2, commit_id="b",
                                                    version=2, value=0x22)]))
    stale = tracker.satisfied(first.action)
    assert stale.satisfied is False
    assert stale.reason == "missing_effects"
    with pytest.raises(DynamicBindingRefused, match="superseded"):
        subject.verify(first.document()["bound_witness"])
    with pytest.raises(DynamicBindingRefused, match="conflicting"):
        subject.bind(first.action, memory_id=MEMORY, byte_offset=BYTE)

    # Rebinding the case's own (unbound) declaration follows the new version.
    second = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert second.prerequisite.evidence_ref == ram_commit_evidence_ref("b" * 64)
    assert second.document()["bound_witness"]["value"] == 0x22
    assert tracker.satisfied(second.action).satisfied is True
    assert subject.verify(second.document()["bound_witness"]).document() == \
        second.document()["bound_witness"]


def test_rebinding_an_identical_action_is_idempotent():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker)
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    first = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    again = subject.bind(first.action, memory_id=MEMORY, byte_offset=BYTE)
    assert again.state == "bound"
    assert again.action == first.action
    assert len(again.action.prerequisites) == 1
    assert subject.counters["idempotent"] == 1
    assert subject.counters["bound"] == 1


# --------------------------------------------------------------------------
# Selection: latest retained evidence, deterministic tie break
# --------------------------------------------------------------------------

def test_the_latest_event_wins_and_ties_break_on_generation():
    tracker = CrossCaseEffectTracker(max_effects=16)
    subject = binder(tracker)
    # Older evidence with a *higher* generation must not win: journal order first.
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a",
                                                    generation=0, version=1)]))
    subject.observe(receipt("case-2", [commit_event(2, commit_id="b",
                                                    generation=1, version=1)]))
    latest = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert latest.document()["bound_witness"]["evidence_ref"] == \
        ram_commit_evidence_ref("b" * 64)
    repeated = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert repeated.document()["bound_witness"] == latest.document()["bound_witness"]
    assert repeated.prerequisite.prerequisite_id == latest.prerequisite.prerequisite_id

    # Two retained versions at the *same* event id: the higher generation wins.
    tied = CrossCaseEffectTracker(max_effects=16)
    ties = binder(tied)
    ties.observe(receipt("case-1", [
        legacy_write_event(7, generation=0, version=3),
        legacy_write_event(7, generation=1, version=1)]))
    assert [(item.subject["generation"], item.event_id)
            for item in tied.retained_ram_witnesses(MEMORY, BYTE)] == [(1, 7), (0, 7)]
    chosen = ties.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    witness = chosen.document()["bound_witness"]
    assert (witness["generation"], witness["event_id"]) == (1, 7)
    assert witness["evidence_ref"] == legacy_memory_write_evidence_ref(7)
    # Deterministic: the same state answers the same reference every time.
    again = ties.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert again.document()["bound_witness"] == witness
    assert again.prerequisite.prerequisite_id == chosen.prerequisite.prerequisite_id


def test_the_selection_walks_the_bounded_retained_index_only():
    offsets = tuple(BYTE + index for index in range(20))
    tracker = CrossCaseEffectTracker(max_effects=4)
    subject = binder(tracker, spec=declaration(byte_offsets=offsets),
                     require_witness=False)
    for index in range(1, 21):
        subject.observe(receipt(f"case-{index}", [
            commit_event(index, commit_id=f"{index:064x}",
                         byte_offset=BYTE + index - 1, value=index)]))
    # Evidence dropped by capacity eviction can never be selected again.
    assert len(tracker.retained_ram_witnesses(MEMORY, BYTE)) == 0
    assert tracker.satisfied(instruction_action(prerequisites=(
        ram_commit_prerequisite(MEMORY, 0, BYTE,
                                ram_commit_evidence_ref(f"{1:064x}")),))).satisfied \
        is False
    gone = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert gone.state == "unbound" and gone.reason == "no_retained_witness"

    bound = subject.bind(instruction_action(), memory_id=MEMORY,
                         byte_offset=offsets[-1])
    proof = bound.document()["bound_witness"]
    assert proof["event_id"] == 20 and proof["value"] == 20
    assert proof["selection"]["retained_effects"] <= tracker.max_effects
    assert proof["selection"]["index_bound"] == tracker.max_effects
    assert proof["selection"]["examined"] == 1
    # The lookup is bounded by the retained index, never by the event history.
    assert (0 < tracker.counters["ram_byte_entries_examined"]
            <= tracker.max_effects * tracker.counters["ram_byte_queries"])
    assert tracker.counters["ram_byte_queries"] <= 20 + 5


# --------------------------------------------------------------------------
# Fail-closed negatives: undeclared requests, untrusted provenance, no witness
# --------------------------------------------------------------------------

def test_undeclared_memory_offset_and_source_kind_are_refused():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker, spec=declaration(byte_offsets=(BYTE, OTHER_BYTE),
                                               writer_kinds=("STORE",)))
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    reader = instruction_action()

    with pytest.raises(DynamicBindingRefused, match="undeclared byte_offset"):
        subject.bind(reader, memory_id=MEMORY, byte_offset=0x1008)
    with pytest.raises(DynamicBindingRefused, match="undeclared memory_id"):
        subject.bind(reader, memory_id="other", byte_offset=BYTE)
    # A request may narrow the declared source kinds, never widen them.
    with pytest.raises(DynamicBindingRefused, match="undeclared writer_kind"):
        subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE,
                     writer_kinds=("ISR",))
    narrowed = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE,
                            writer_kinds=("STORE",))
    assert narrowed.state == "bound" and \
        narrowed.document()["bound_witness"]["writer_kind"] == "STORE"
    assert subject.counters["refused"] == 3

    # A declaration with no source whitelist cannot accept a source request.
    plain = binder(tracker)
    with pytest.raises(DynamicBindingRefused, match="undeclared writer_kind"):
        plain.bind(reader, memory_id=MEMORY, byte_offset=BYTE,
                   writer_kinds=("STORE",))
    assert plain.bind(reader, memory_id=MEMORY,
                      byte_offset=BYTE).state == "bound"


def test_offsets_that_never_had_a_retained_witness_stay_unbound():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker, spec=declaration(byte_offsets=(BYTE, OTHER_BYTE)),
                     require_witness=False)
    reader = instruction_action()
    unbound = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert unbound.state == "unbound" and bool(unbound) is False
    assert unbound.reason == "no_retained_witness"
    assert unbound.prerequisite is None and unbound.action == reader
    assert unbound.document()["bound_witness"] is None
    assert unbound.document()["payload_unchanged"] is True
    assert subject.counters["unbound"] == 1

    # A witness for another memory or another byte is invisible.
    subject.observe(receipt("case-1", [
        commit_event(1, commit_id="a", memory_id="other"),
        commit_event(2, commit_id="b", byte_offset=0x2000)]))
    assert subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE).state == "unbound"
    assert subject.bind(reader, memory_id=MEMORY,
                        byte_offset=OTHER_BYTE).state == "unbound"

    # require_witness=True is the fail-closed default: the same state refuses.
    strict = binder(tracker, spec=declaration(byte_offsets=(BYTE, OTHER_BYTE)))
    with pytest.raises(DynamicBindingUnbound, match="no retained witness"):
        strict.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert strict.counters["unbound"] == 1


def test_evidence_from_an_undeclared_source_is_never_selected():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker, spec=declaration(writer_kinds=("STORE",)),
                     require_witness=False)
    reader = instruction_action()

    # The tracker retains the byte, but its writer is not the declared kind.
    subject.observe(receipt("case-1", [
        commit_event(1, commit_id="a", value=0x01, writer_kind="INITIAL_IMAGE")]))
    assert tracker.document()["effect_count"] == 1
    unbound = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert unbound.state == "unbound"
    assert unbound.reason == "writer_kind_not_declared"

    # A legacy write event declares no writer kind at all: fail-closed too.
    bare = CrossCaseEffectTracker()
    strict = binder(bare, spec=declaration(writer_kinds=("STORE",)),
                    require_witness=False)
    strict.observe(receipt("case-1", [legacy_write_event(2)]))
    assert bare.document()["effect_count"] == 1
    assert strict.bind(reader, memory_id=MEMORY,
                       byte_offset=BYTE).reason == "untrusted_source_provenance"

    # Provenance the binder never observed is missing even when retained, so a
    # declaration that names sources fails closed instead of trusting a claim.
    foreign = CrossCaseEffectTracker()
    foreign.ingest([commit_event(3, commit_id="c", writer_kind="STORE")])
    assert binder(foreign, spec=declaration(writer_kinds=("STORE",)),
                  require_witness=False).bind(
        reader, memory_id=MEMORY, byte_offset=BYTE).reason == \
        "untrusted_source_provenance"
    assert binder(foreign).bind(reader, memory_id=MEMORY,
                                byte_offset=BYTE).state == "bound"

    # A commit whose own document refuses completeness creates no witness.
    refused = CrossCaseEffectTracker()
    cold = binder(refused, spec=declaration(writer_kinds=("STORE",)),
                  require_witness=False)
    cold.observe(receipt("case-1", [commit_event(4, commit_id="d",
                                                 commit_status="aborted")]))
    assert refused.document()["effect_count"] == 0
    assert cold.bind(reader, memory_id=MEMORY,
                     byte_offset=BYTE).reason == "no_retained_witness"


def test_a_degraded_tracker_refuses_instead_of_binding():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker)
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    tracker._degraded = True
    with pytest.raises(DynamicBindingRefused, match="degraded"):
        subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)


def test_a_value_less_witness_is_refused_when_a_value_is_required():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker, require_value=True, require_witness=False)
    subject.observe(receipt("case-1", [legacy_write_event(1)]))
    unbound = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert unbound.state == "unbound" and unbound.reason == "missing_witness_value"
    # The same state binds when only the version is required.
    assert binder(tracker).bind(instruction_action(), memory_id=MEMORY,
                                byte_offset=BYTE).document()[
        "bound_witness"]["value"] is None


# --------------------------------------------------------------------------
# Safety boundary: a prerequisite, never a fuzzable input value
# --------------------------------------------------------------------------

def test_the_committed_value_never_becomes_a_fuzzable_source_input():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker)
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a", value=9)]))
    # An unrelated external source binds: only the prerequisite is injected.
    other = external_action(value=1)
    bound = subject.bind(other, memory_id=MEMORY, byte_offset=BYTE)
    assert dict(bound.action.payload) == dict(other.payload)
    # An external source that would carry the committed RAM byte as its own
    # mutable input is indistinguishable from value injection: refused.
    with pytest.raises(DynamicBindingRefused, match="ram_value_input_injection"):
        subject.bind(external_action(action_id="case-c:carrier", value=9),
                     memory_id=MEMORY, byte_offset=BYTE)
    # The binder has no parameter that could inject a value at all.
    with pytest.raises(TypeError):
        subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE,
                     value=9)
    assert bound.document()["value_injection"] is False
    assert bound.document()["payload_sha256_before"] == \
        bound.document()["payload_sha256_after"]


# --------------------------------------------------------------------------
# Tampered or forged proofs are refused
# --------------------------------------------------------------------------

def test_a_tampered_proof_document_is_refused():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker, spec=declaration(writer_kinds=("STORE",)))
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a", value=0x5A)]))
    bound = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    proof = bound.document()["bound_witness"]
    assert BoundWitness.from_document(proof).document() == proof

    for field, value in (("evidence_ref", ram_commit_evidence_ref("f" * 64)),
                         ("event_id", 99), ("value", 0x00), ("generation", 7),
                         ("byte_offset", OTHER_BYTE), ("case_id", "case-9"),
                         ("memory_id", "other"), ("writer_kind", "ISR")):
        tampered = {**proof, field: value}
        with pytest.raises(ValueError, match="bound_witness_id"):
            BoundWitness.from_document(tampered)
    with pytest.raises(ValueError, match="unknown or missing"):
        BoundWitness.from_document({**proof, "extra": 1})
    with pytest.raises(ValueError, match="schema_version"):
        BoundWitness.from_document({**proof,
                                    "schema_version": "bound_witness.v2"})

    # A caller who recomputes the content digest still cannot forge evidence.
    forged = BoundWitness.from_document(proof)
    for field, value, reason in (
            ("evidence_ref", ram_commit_evidence_ref("f" * 64), "unretained"),
            ("event_id", 99, "unretained"),
            ("value", 0x00, "unretained"),
            ("case_id", "case-9", "unretained"),
            ("writer_kind", "ISR", "undeclared writer_kind"),
            ("byte_offset", OTHER_BYTE, "undeclared byte_offset"),
            ("declaration_id", "0" * 64, "declaration")):
        forged_document = replace(forged, bound_witness_id="",
                                  **{field: value}).document()
        with pytest.raises(DynamicBindingRefused, match=reason):
            subject.verify(forged_document)
    # The genuine proof still verifies.
    assert subject.verify(proof).document() == proof

    # Tampering with the binding envelope is refused as well.
    envelope = bound.document()
    with pytest.raises(ValueError, match="binding_id"):
        DynamicEffectBinding.from_document({**envelope, "reason": "satisfied"})
    with pytest.raises(ValueError):
        DynamicEffectBinding.from_document({**envelope, "state": "unknown"})
    with pytest.raises(ValueError, match="unknown or missing"):
        DynamicEffectBinding.from_document({**envelope, "extra": 1})
    assert DynamicEffectBinding.from_document(envelope).document() == envelope


def test_a_proof_that_no_longer_matches_the_action_is_refused():
    tracker = CrossCaseEffectTracker()
    subject = binder(tracker)
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    bound = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert subject.verify(bound.document()["bound_witness"],
                          action=bound.action).document() == \
        bound.document()["bound_witness"]
    # Another action that never carried the prerequisite, or one whose payload
    # was edited afterwards, cannot ride the same proof.
    with pytest.raises(DynamicBindingRefused, match="action"):
        subject.verify(bound.document()["bound_witness"],
                       action=instruction_action("case-4:load"))
    with pytest.raises(DynamicBindingRefused, match="payload"):
        subject.verify(bound.document()["bound_witness"],
                       action=instruction_action(address=0x12000))


# --------------------------------------------------------------------------
# Boundedness and the appended surface
# --------------------------------------------------------------------------

def test_the_binder_stays_bounded_over_a_long_sequence():
    tracker = CrossCaseEffectTracker(max_effects=16, max_slots=8,
                                     max_age_events=10000)
    subject = binder(tracker, spec=declaration(byte_offsets=(BYTE, OTHER_BYTE),
                                               writer_kinds=("STORE",)),
                     max_provenance=16, require_witness=False)
    for index in range(1, 5001):
        if index % 101 == 0:
            events = [reset_event(index)]
        elif index % 3 == 0:
            events = [instruction_source_event(index)]
        else:
            events = [commit_event(index, commit_id=f"{index:064x}",
                                   byte_offset=BYTE if index % 2 else OTHER_BYTE,
                                   value=index % 256, version=index)]
        subject.observe(receipt(f"case-{index}", events))
        assert tracker.pending_count <= tracker.bounds["max_pending"]
        assert (subject.document()["provenance_count"]
                <= subject.bounds["max_provenance"])
    assert tracker.cursor == 5000
    assert subject.counters["provenance_evictions"] > 0
    bound = subject.bind(instruction_action(), memory_id=MEMORY, byte_offset=BYTE)
    assert bound.state == "bound"
    proof = bound.document()["bound_witness"]
    assert proof["event_id"] > 4900 and proof["selection"]["examined"] == 1
    assert (tracker.counters["ram_byte_entries_examined"]
            <= tracker.max_effects * tracker.counters["ram_byte_queries"])


def test_the_declaration_and_the_appended_module_reexport_the_same_objects():
    spec = declaration(byte_offsets=(BYTE, OTHER_BYTE), writer_kinds=("STORE",))
    document = spec.document()
    assert document["schema_version"] == TRUSTED_RAM_DECLARATION_SCHEMA_VERSION
    assert TrustedRamByteDeclaration.from_document(document) == spec
    assert spec.allows(MEMORY, BYTE) and not spec.allows(MEMORY, 0x2000)
    assert spec.allows_writer_kind("STORE") and not spec.allows_writer_kind("ISR")
    with pytest.raises(ValueError, match="declaration_id"):
        TrustedRamByteDeclaration.from_document({**document,
                                                 "writer_kinds": ["ISR"]})
    for name in ("BoundWitness", "DynamicBindingRefused", "DynamicBindingUnbound",
                 "DynamicEffectBinding", "DynamicPrerequisiteBinder",
                 "TrustedRamByteDeclaration", "bind_latest_effect",
                 "BOUND_WITNESS_SCHEMA_VERSION", "LATEST_EFFECT_ORDER"):
        assert getattr(dynamic_module, name) is globals()[name]

    subject = binder(CrossCaseEffectTracker())
    # A bare tracker has no trusted policy and no recorded provenance: refused.
    with pytest.raises(ValueError, match="DynamicPrerequisiteBinder"):
        bind_latest_effect(subject.tracker, instruction_action(),
                           memory_id=MEMORY, byte_offset=BYTE)
    with pytest.raises(ValueError, match="provenance"):
        bind_latest_effect(subject.tracker, instruction_action(),
                           declaration=spec, memory_id=MEMORY, byte_offset=BYTE)
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    bound = bind_latest_effect(subject, instruction_action(), memory_id=MEMORY,
                               byte_offset=BYTE)
    assert bound.state == "bound"
    assert bound.document()["schema_version"] == DYNAMIC_EFFECT_BINDING_SCHEMA_VERSION
    # Declaration construction is strict about its own whitelist.
    with pytest.raises(ValueError, match="strictly increasing"):
        declaration(byte_offsets=(OTHER_BYTE, BYTE))
    with pytest.raises(ValueError, match="byte_offset"):
        declaration(byte_offsets=())
    with pytest.raises(ValueError, match="writer_kinds"):
        declaration(writer_kinds=("STORE", "store"))


def test_the_gate_level_negative_paths_precede_any_admission():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    subject = binder(tracker, require_witness=False)
    # Case two has no Store witness yet: the gate would admit it with no RAM
    # prerequisite, which is why a recording caller must read the state.
    early = instruction_action("case-2:load")
    assert subject.bind(early, memory_id=MEMORY, byte_offset=BYTE).state == "unbound"
    gate.register(early)
    assert gate.require(early) is early
    subject.observe(receipt("case-1", [commit_event(1, commit_id="a")]))
    reader = instruction_action("case-3:load")
    bound = subject.bind(reader, memory_id=MEMORY, byte_offset=BYTE)
    assert tracker.satisfied(bound.action).satisfied is True
    # A measured reset drops the witness: the bound case is refused again.
    tracker.ingest([reset_event(2)])
    gate.register(bound.action)
    with pytest.raises(SourceActionPrerequisiteError) as caught:
        gate.require(bound.action)
    assert caught.value.evaluation.reason == "missing_effects"
    # Only the same evidence restored through a new event admits it again.
    tracker.ingest([commit_event(3, commit_id="a")])
    assert tracker.satisfied(bound.action).satisfied is True
