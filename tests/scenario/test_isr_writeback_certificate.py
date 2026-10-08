"""Exact-identity ISR GPIO A writeback endpoint certificates.

The audit answers one question with two halves:

* The half the artifacts *do* support: the handler's GPIO A ``PADOUT`` register
  commit, the A->B binding it drives, and the second CPU IRQ input are joined by
  exact field identities (six-field transaction key, target access id, bit
  version + observation event id, trigger id).
* The half the artifacts *do not* support: attaching that handler write to a
  certified ``CPU_TO_IP_TO_CPU``/``IP_TO_CPU_TO_IP`` chain. The handler write's
  ``cpu_retired_transaction_target_delivery`` reports
  ``registered_origin_status == "unknown"`` with empty ``registered_origins`` and
  ``source_refs``, and no event on the handler path names the IRQ take.

Journals here are hand-built single-pass streams whose every cross reference
points backwards, so the builder needs no symbolic resolution. The
chain-extension tests consume certificates produced by the real
``ChainCertificates`` producer so the audit is exercised against shipped output,
never a hand-written look-alike.
"""

import json

import pytest

from myfuzz.scenario.isr_writeback_certificate import (
    HANDLER_HOP_SEQUENCE,
    NOT_PROOF_OF,
    PROOF_SCOPE,
    SCHEMA_VERSION,
    IsrWritebackCertificates,
    audit_chain_extension,
)
from tests.scenario.test_chain_certificates import (
    _certificates,
    _cpu_journal,
    _transaction,
)


GPIO_A_ADDRESS = 0x40001000
PADOUT_OFFSET = 12
ISR_SPAN = (0x10200, 64)
ISR_PADOUT_PC = 0x10228
SLOT_PC = 0x11000
WRITE_VALUE = 1
COMMIT_VERSION = 3681
GPIO_B_INPUT_VERSION = 5407
SYNC1_VERSION = 5450
TRIGGER_ID = "gpio-b:0:trigger:2"


class _Journal:
    """Append-only event journal; every reference points at an earlier event."""

    def __init__(self):
        self.events = []
        self._ids = {}

    def add(self, name, kind, **fields):
        event = {"kind": kind, "event_id": len(self.events) + 1, **fields}
        self.events.append(event)
        assert name not in self._ids
        self._ids[name] = event["event_id"]
        return event["event_id"]

    def id(self, name):
        return self._ids[name]


def _resource(component, register, bit, version, value, observation_event_id,
              origin_status, origin_refs, transaction=None):
    return {"component": component, "register": register, "bit": bit,
            "version": version, "value": value, "local_tick": version,
            "observation_event_id": observation_event_id, "reset_epoch": 0,
            "origin_status": origin_status, "origin_refs": list(origin_refs),
            "dependencies": [], "transaction": transaction}


def _commit_origin(access_id, version, observation_event_id, transaction):
    """The exact identity a binding must repeat to be joined."""
    return {"component": "gpio_a", "register": "out", "bit": 0,
            "version": version, "value": WRITE_VALUE,
            "observation_event_id": observation_event_id, "reset_epoch": 0,
            "local_tick": version, "phase": None, "trigger_id": None,
            "transaction": dict(transaction)}


def _add_handler_write(journal, *, index=0, pc=ISR_PADOUT_PC,
                       access_id="gpio-access:gpio_a:0:5", sequence=13,
                       binding_versions=True, binding_refs=True,
                       retired_origin="unknown", retired_origins=(),
                       retired_refs=(), second_irq=True, transaction=None):
    """Append one handler GPIO A PADOUT write and the reflow it drives.

    ``index`` only names the events and the trigger id, so several writes can
    share one journal without ever colliding on an identity.
    """
    tag = f"{index}."
    trigger_id = f"gpio-b:0:trigger:{index + 2}"
    transaction = dict(transaction or _transaction(sequence))
    origin = _commit_origin(access_id, COMMIT_VERSION, 0, transaction)
    journal.add(tag + "acceptance", "mmio_acceptance", component="cpu",
                device_id="gpio_a", offset=PADOUT_OFFSET, write=True,
                write_value=WRITE_VALUE, address=GPIO_A_ADDRESS + PADOUT_OFFSET,
                beat_bytes=4, byte_enable=15, acceptance_order=9,
                source_sequence=sequence, source_transaction=dict(transaction),
                producer_event_id=80)
    journal.add(tag + "access", "gpio_apb_access", component="gpio_a",
                access_id=access_id, raw_offset=PADOUT_OFFSET,
                decoded_offset=PADOUT_OFFSET, write=True, wdata=WRITE_VALUE,
                status="observed", phase="pre", local_tick=170,
                reset_epoch=0, source_epoch=0, producer_event_id=81,
                source_transaction=dict(transaction))
    observation = journal.id(tag + "access")
    origin["observation_event_id"] = observation
    journal.add(tag + "commit", "gpio_register_commit", component="gpio_a",
                access_id=access_id, register="out", status="observed",
                local_tick=170, reset_epoch=0, observation_event_id=observation,
                producer_event_id=observation, bit_resources=[origin])
    # A->B binding: the segment repeats the committed version identity.
    refs = [_commit_origin(access_id, COMMIT_VERSION, observation, transaction)
            if binding_versions else
            {"component": "gpio_a", "register": "out", "bit": 0, "version": 9999,
             "value": WRITE_VALUE, "observation_event_id": observation,
             "reset_epoch": 0}]
    if not binding_refs:
        refs = []
    journal.add(tag + "binding", "gpio_input_applied", component="gpio_b",
                actual_input_value=257, requested_input_value=257,
                local_tick=167, reset_epoch=0, producer_event_id=82,
                segments=[{"bit_lo": 0, "value": WRITE_VALUE, "width": 1,
                           "origin": {"kind": "binding", "delivery_event_id": 90,
                                      "source_component": "gpio_a",
                                      "source_port": "gpio_out",
                                      "source_bit_lo": 0,
                                      "producer_local_tick": 171,
                                      "producer_phase": "post",
                                      "producer_reset_epoch": 0,
                                      "producer_resource_refs": refs}}])
    journal.add(tag + "input_resource", "gpio_input_applied_resource",
                component="gpio_b", local_tick=167, reset_epoch=0,
                observation_event_id=83, producer_event_id=83,
                origin_status="known", status="observed",
                bit_resources=[_resource(
                    "gpio_b", "input", 0, GPIO_B_INPUT_VERSION, WRITE_VALUE, 83,
                    "known",
                    ([_commit_origin(access_id, COMMIT_VERSION, observation,
                                     transaction)] if binding_refs else []))])
    if second_irq:
        journal.add(tag + "trigger", "gpio_irq_trigger", component="gpio_b",
                    trigger_id=trigger_id, mask=1, value=WRITE_VALUE,
                    local_tick=168, reset_epoch=0, producer_event_id=84,
                    causes=[{"pin": 0, "current_sample": {
                        "component": "gpio_b", "register": "sync1", "bit": 0,
                        "version": SYNC1_VERSION, "value": WRITE_VALUE,
                        "observation_event_id": 85, "origin_status": "known",
                        "origin_refs": refs if binding_refs else [],
                        "dependencies": []}}])
    journal.add(tag + "retire", "cpu_retire", component="cpu", valid=1, trap=0,
                intr=0, insn=2205219, order=45, pc_rdata=pc, pc_wdata=pc + 4,
                mem_addr=GPIO_A_ADDRESS + PADOUT_OFFSET, mem_wmask=15,
                mem_rmask=0, mem_wdata=WRITE_VALUE, mem_rdata=0, tick=153,
                local_tick=153, reset_epoch=0, execution_id="local-execution",
                source_component="cpu", source_epoch=0)
    journal.add(tag + "match", "cpu_retirement_match", component="cpu",
                status="accepted", instruction_origin_status="unknown",
                producer_event_id=journal.id(tag + "retire"), insn=2205219,
                pc=pc, order=45, source_refs=[],
                transaction_keys=[dict(transaction)], data_beats=[],
                instruction_responses=[], byte_cells=[])
    journal.add(tag + "delivery", "cpu_retired_transaction_target_delivery",
                component="cpu", status="linked_raw",
                producer_event_id=journal.id(tag + "match"),
                retirement_event_id=journal.id(tag + "match"),
                raw_rvfi_event_id=journal.id(tag + "retire"),
                delivery_event_id=91,
                registered_origin_status=retired_origin,
                registered_origins=[dict(item) for item in retired_origins],
                source_refs=list(retired_refs),
                consumer_resource={"device_id": "gpio_a",
                                   "offset": PADOUT_OFFSET, "write": True,
                                   "write_value": WRITE_VALUE,
                                   "read_value": None,
                                   "target_access_id": access_id,
                                   "address": GPIO_A_ADDRESS + PADOUT_OFFSET,
                                   "byte_enable": 15, "beat_bytes": 4,
                                   "delivery_order": 9})
    if second_irq:
        journal.add(tag + "backend", None, component="gpio_b", local_tick=170,
                    inputs={"gpio_in": 257}, outputs={"irq": 1})
        # Journal order, not physical order: the harness notifies the CPU input
        # before it records the GPIO IRQ observation (90/90 real triggers).
        journal.add(tag + "cpu_irq_input", "cpu_irq_input", value=1, width=1,
                    source=["gpio_b", "irq"], target=["cpu", "irq"],
                    source_bit_offset=0, target_bit_offset=0,
                    source_event_id=2, cpu_tick=154, cpu_step_event_id=87,
                    source_trigger={"trigger_id": trigger_id,
                                    "trigger_event_id": journal.id(
                                        tag + "trigger"),
                                    "observation_event_id": 85,
                                    "sample_event_id": 86})
        journal.add(tag + "irq_observation", "gpio_irq_observation",
                    component="gpio_b", trigger_id=trigger_id, mask=1,
                    value=WRITE_VALUE, local_tick=169, reset_epoch=0,
                    phase="pre", status="observed", producer_event_id=86,
                    observation_event_id=86,
                    causes=[{"pin": 0, "current_sample": {
                        "component": "gpio_b", "register": "sync1", "bit": 0,
                        "version": SYNC1_VERSION, "value": WRITE_VALUE,
                        "observation_event_id": 85, "origin_status": "known",
                        "origin_refs": refs if binding_refs else [],
                        "dependencies": []}}])
    return journal


def _handler_write_journal(**kwargs):
    """One write in its own journal."""
    return _add_handler_write(_Journal(), **kwargs)


def _ids(journal, name):
    """Event id of a named hop in a single-write journal (write index 0)."""
    return journal.id("0." + name)


def _consume(journal, **kwargs):
    consumer = IsrWritebackCertificates(**kwargs)
    result = list(consumer.ingest(journal.events))
    result.extend(consumer.flush())
    return result, consumer


def _by_status(certificates, status):
    return [item for item in certificates if item["status"] == status]


# ---------------------------------------------------------------- contracts


def test_declared_hop_sequence_and_contract_constants():
    assert SCHEMA_VERSION == "isr_writeback_certificate.v1"
    assert PROOF_SCOPE == (
        "exact_handler_gpio_a_padout_commit_to_bound_second_irq_input")
    assert HANDLER_HOP_SEQUENCE == (
        "handler_mmio_acceptance", "handler_register_commit", "binding_segment",
        "binding_input_resource", "bound_irq_trigger", "handler_retirement",
        "handler_retirement_match", "handler_target_delivery",
        "bound_cpu_irq_input", "bound_irq_observation")
    for missing in ("p5_chain_extension", "chain_completion",
                    "handler_execution_attribution_to_the_certified_irq_take",
                    "event_adjacency_or_ordering"):
        assert missing in NOT_PROOF_OF
    assert len(set(NOT_PROOF_OF)) == len(NOT_PROOF_OF)


# ------------------------------------------------------- certified fragment


def test_handler_writeback_certifies_with_exact_identity_hops():
    journal = _handler_write_journal()
    certificates, consumer = _consume(journal, handler_span=ISR_SPAN,
                                      handler_image_id="cpu.stream.isr")
    certified = _by_status(certificates, "certified")
    assert len(certified) == 1
    certificate = certified[0]
    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["proof_scope"] == PROOF_SCOPE
    assert certificate["not_proof_of"] == list(NOT_PROOF_OF)
    assert certificate["missing_hops"] == []
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(
        HANDLER_HOP_SEQUENCE)
    event_ids = [hop["event_id"] for hop in certificate["hops"]]
    assert event_ids == sorted(event_ids)
    assert certificate["transaction"] == _transaction(13)
    assert certificate["target_access_id"] == "gpio-access:gpio_a:0:5"
    assert certificate["writer"]["pc"] == ISR_PADOUT_PC
    assert certificate["writer"]["classification"] == {
        "image_id": "cpu.stream.isr", "span": list(ISR_SPAN),
        "basis": "declared_initial_image_span_observation_not_identity"}
    assert certificate["second_irq"] == {
        "trigger_id": TRIGGER_ID,
        "trigger_event_id": _ids(journal, "trigger"),
        "observation_event_id": _ids(journal, "irq_observation"),
        "cpu_irq_input_event_id": _ids(journal, "cpu_irq_input"),
        "cpu_step_event_id": 87}
    # the certified fragment still refuses the chain-attribution claim
    extension = certificate["chain_extension"]
    assert extension["joinable"] is False
    assert extension["missing_identity"]["field"] == (
        "registered_origins/registered_origin_status")
    assert extension["missing_identity"]["observed"] == "unknown"
    assert consumer.pending_count == 0
    assert consumer.counters()["handler_writes_observed"] == 1
    assert consumer.counters()["adjacency_fallbacks_used"] == 0


def test_certificate_id_is_deterministic_and_identity_bound():
    first, _ = _consume(_handler_write_journal(), handler_span=ISR_SPAN)
    second, _ = _consume(_handler_write_journal(), handler_span=ISR_SPAN)
    other, _ = _consume(_handler_write_journal(sequence=14, access_id=(
        "gpio-access:gpio_a:0:6")), handler_span=ISR_SPAN)
    assert first[0]["certificate_id"] == second[0]["certificate_id"]
    assert first[0]["certificate_id"] != other[0]["certificate_id"]


# ------------------------------------------------------------- fail closed


@pytest.mark.parametrize("fault, first_missing", (
    ("no_binding_versions", "binding_segment"),
    ("no_binding_refs", "binding_segment"),
    ("no_second_irq", "bound_irq_trigger"),
))
def test_unjoined_hop_never_certifies(fault, first_missing):
    kwargs = {}
    if fault == "no_binding_versions":
        kwargs["binding_versions"] = False
    if fault == "no_binding_refs":
        kwargs["binding_refs"] = False
    if fault == "no_second_irq":
        kwargs["second_irq"] = False
    journal = _handler_write_journal(**kwargs)
    certificates, consumer = _consume(journal, handler_span=ISR_SPAN)
    assert _by_status(certificates, "certified") == []
    incomplete = _by_status(certificates, "incomplete")
    assert len(incomplete) == 1
    assert incomplete[0]["missing_hops"][0] == first_missing
    # the denied hops keep their certified prefix and never invent a join
    observed = [hop["hop_id"] for hop in incomplete[0]["hops"]]
    assert observed == [name for name in HANDLER_HOP_SEQUENCE
                        if name not in incomplete[0]["missing_hops"]]
    assert consumer.counters()["adjacency_fallbacks_used"] == 0


def test_adjacent_binding_without_identity_is_not_a_join():
    """The binding event sits directly after the commit and is still refused."""
    journal = _handler_write_journal(binding_refs=False)
    certificates, _ = _consume(journal, handler_span=ISR_SPAN)
    assert [item["status"] for item in certificates] == ["incomplete"]
    attempts = certificates[0]["join_attempts"]
    keys = {attempt["key"]: attempt for attempt in attempts}
    assert keys["binding_version_identity"]["relation"] == "absent"
    assert keys["binding_version_identity"]["exact"] is False
    adjacency = [attempt for attempt in attempts
                 if attempt["key"] == "binding_event_adjacency"]
    assert len(adjacency) == 1
    assert adjacency[0]["exact"] is False
    assert adjacency[0]["relation"] == "adjacency_only"


def test_handler_span_is_classification_not_identity():
    journal = _handler_write_journal(pc=SLOT_PC)
    certificates, consumer = _consume(journal, handler_span=ISR_SPAN)
    assert _by_status(certificates, "certified") == []
    assert [item["status"] for item in certificates] == []
    counters = consumer.counters()
    assert counters["handler_writes_observed"] == 0
    assert counters["out_of_scope_writes"] == 1
    assert counters["padout_writes_seen"] == 1
    assert consumer.writeback_records() == ()


def test_writes_are_counted_even_when_samples_are_bounded():
    consumer = IsrWritebackCertificates(handler_span=ISR_SPAN, max_pending=64,
                                        max_writebacks=2, max_event_gap=4096)
    journal = _Journal()
    for index in range(6):
        _add_handler_write(journal, index=index, sequence=20 + index,
                           access_id=f"gpio-access:gpio_a:0:{9 + index}")
    certificates = list(consumer.ingest(journal.events))
    certificates.extend(consumer.flush())
    counters = consumer.counters()
    assert counters["handler_writes_observed"] == 6
    assert counters["certificates_certified"] == 6
    assert len(consumer.writeback_records()) == 2
    assert counters["retained_writeback_identities"] == 2
    assert counters["adjacency_fallbacks_used"] == 0


def test_expired_candidate_is_counted_and_never_restored():
    journal = _handler_write_journal()
    events = journal.events
    consumer = IsrWritebackCertificates(handler_span=ISR_SPAN, max_event_gap=8)
    assert list(consumer.ingest(events[:5])) == []
    assert consumer.pending_count == 1
    filler = [{"event_id": 6 + index, "kind": "state_dependency",
               "component": "cpu"} for index in range(9)]
    expired = list(consumer.ingest(filler))
    assert len(expired) == 1
    assert expired[0]["status"] == "incomplete"
    assert expired[0]["settled_reason"] == "max_event_gap"
    assert expired[0]["missing_hops"][0] == "bound_irq_trigger"
    assert [hop["hop_id"] for hop in expired[0]["hops"]] == [
        "handler_mmio_acceptance", "handler_register_commit", "binding_segment",
        "binding_input_resource"]
    assert consumer.counters()["evicted_or_expired"] == 1
    # every later event of the same write arrives after the one-shot settlement
    base = 6 + len(filler)
    rest = [{**event, "event_id": event["event_id"] + base - 6}
            for event in events[5:]]
    assert list(consumer.ingest(rest)) == []
    counters = consumer.counters()
    assert counters["certificates_certified"] == 0
    assert counters["adjacency_fallbacks_used"] == 0
    assert consumer.pending_count == 0


# ------------------------------------------------ chain extension: negative


def _certified_cpu_chain():
    certificates, _ = _certificates(_cpu_journal())
    certified = [item for item in certificates if item["status"] == "certified"
                 and item["direction"] == "CPU_TO_IP_TO_CPU"]
    assert len(certified) == 1
    return certified[0]


def test_chain_extension_is_not_joinable_without_a_handler_identity():
    chain = _certified_cpu_chain()
    journal = _handler_write_journal()
    _, consumer = _consume(journal, handler_span=ISR_SPAN)
    writebacks = consumer.writeback_records()
    assert len(writebacks) == 1
    assert writebacks[0]["writer_pc"] == ISR_PADOUT_PC
    audit = audit_chain_extension(chain, writebacks)
    assert audit["status"] == "not_joinable"
    assert audit["chain_certificate_id"] == chain["certificate_id"]
    assert audit["direction"] == "CPU_TO_IP_TO_CPU"
    attempts = {attempt["key"]: attempt for attempt in audit["join_attempts"]}
    assert attempts["admission_origin_identity"]["relation"] == "absent"
    assert attempts["admission_origin_identity"]["exact"] is False
    assert attempts["irq_take_identity"]["relation"] == "absent"
    assert attempts["target_access_identity"]["relation"] == "mismatch"
    assert attempts["writer_pc_classification"]["relation"] == (
        "classification_only")
    assert attempts["ordering_adjacency"]["relation"] == "adjacency_only"
    assert audit["missing_identity"]["field"] == (
        "registered_origins/registered_origin_status")
    assert audit["missing_identity"]["required"].startswith(
        "known + exactly one origin document equal to")
    assert audit["extended_hops"] == []


def test_chain_own_endpoint_is_never_used_as_a_writeback_identity():
    """A chain's own terminal PADOUT write can never self-join as a handler."""
    chain = _certified_cpu_chain()
    terminal = next(hop for hop in chain["hops"]
                    if hop["hop_id"] == "retired_target_delivery")
    record = {"writer_pc": ISR_PADOUT_PC,
              "target_access_id": terminal["evidence"]["target_access_id"],
              "delivery_event_id": terminal["evidence"]["delivery_event_id"],
              "retirement_event_id": terminal["evidence"]["retirement_event_id"],
              "registered_origin_status": "known",
              "registered_origins": [{"admission_id":
                                      chain["source_admission_id"]}],
              "source_refs": [chain["source_action_id"]],
              "irq_take_identity": None}
    audit = audit_chain_extension(chain, [record])
    assert audit["status"] == "not_joinable"
    assert audit["self_endpoint_excluded"] == 1
    assert audit["writeback_identities"] == []


def test_journaled_handler_origin_would_flip_the_same_audit_to_joinable():
    """The positive branch: exactly what the harness must journal to close it."""
    chain = _certified_cpu_chain()
    admission = {
        "admission_id": chain["source_admission_id"],
        "action_id": chain["source_action_id"]}
    journal = _handler_write_journal(
        pc=ISR_PADOUT_PC, retired_origin="known",
        retired_origins=[{"admission_id": admission["admission_id"]}],
        retired_refs=[admission["action_id"]])
    _, consumer = _consume(journal, handler_span=ISR_SPAN)
    audit = audit_chain_extension(chain, consumer.writeback_records())
    assert audit["status"] == "joined"
    assert audit["matched_join_keys"] == ["admission_origin_identity"]
    # journal-local event ids can echo the chain endpoint's ids; an echo is
    # never decisive and is reported separately
    assert audit["self_echo_keys"] == ["delivery_event_identity"]
    matched = next(attempt for attempt in audit["join_attempts"]
                   if attempt["key"] == "admission_origin_identity")
    assert matched["observed"] == admission
    assert audit["missing_identity"] is None


def test_audit_carries_the_exact_event_ids_and_transaction_keys_it_used():
    chain = _certified_cpu_chain()
    journal = _handler_write_journal()
    certificates, consumer = _consume(journal, handler_span=ISR_SPAN)
    audit = audit_chain_extension(chain, consumer.writeback_records())
    assert audit["chain_hop_event_ids"] == {
        "retired_target_delivery": next(
            hop["event_id"] for hop in chain["hops"]
            if hop["hop_id"] == "retired_target_delivery")}
    record = audit["writeback_identities"][0]
    assert record["retire_event_id"] == _ids(journal, "retire")
    assert record["retirement_event_id"] == _ids(journal, "match")
    assert record["delivery_event_id"] == _ids(journal, "delivery")
    assert record["commit_event_id"] == _ids(journal, "commit")
    assert record["transaction"] == _transaction(13)
    assert record["target_access_id"] == "gpio-access:gpio_a:0:5"
    assert record["irq_take_identity"] is None
    assert json.loads(json.dumps(audit)) == audit


# ------------------------------------------------------------ real artifact


REAL_RUN = "runs/current-dataflow-p5-chain-acceptance-20261007-online"


def _stream_real_run(**kwargs):
    """Stream one real saved run; bounded readers only, never a full load."""
    from myfuzz.scenario.acceptance_metrics import TraceEventStream

    stream = TraceEventStream(REAL_RUN, verify_semantic=False)
    consumer = IsrWritebackCertificates(**kwargs)
    certificates = []
    for event in stream.events():
        certificates.extend(consumer.ingest((event,)))
    certificates.extend(consumer.flush())
    return certificates, consumer, stream


def test_real_run_handler_writeback_is_certified_to_the_second_irq_input():
    from pathlib import Path

    if not Path(REAL_RUN).is_dir():
        pytest.skip("saved acceptance run is not present")
    certificates, consumer, stream = _stream_real_run(
        handler_image_id="cpu.stream.isr", max_event_gap=16384)
    counters = consumer.counters()
    assert stream.descriptor["format"] == "json.v1"
    # the handler span is learned from the artifact's own initial_image record
    assert consumer.handler_span == (66048, 68)
    assert counters["handler_writes_observed"] == 5
    assert counters["padout_writes_seen"] == 9
    assert counters["adjacency_fallbacks_used"] == 0
    assert counters["out_of_scope_writes"] == 4
    certified = _by_status(certificates, "certified")
    assert len(certified) == 2
    incomplete = _by_status(certificates, "incomplete")
    assert len(incomplete) == 3
    assert {item["missing_hops"][0] for item in incomplete} == {
        "bound_irq_trigger"}
    assert sorted(item["target_access_id"] for item in certified) == [
        "gpio-access:gpio_a:0:5", "gpio-access:gpio_a:0:7"]
    assert {item["transaction"]["source_sequence"]
            for item in certified} == {13, 24}
    first = next(item for item in certified
                 if item["target_access_id"] == "gpio-access:gpio_a:0:5")
    assert [(hop["hop_id"], hop["event_id"]) for hop in first["hops"]] == [
        ("handler_mmio_acceptance", 5908), ("handler_register_commit", 5925),
        ("binding_segment", 5951), ("binding_input_resource", 5953),
        ("bound_irq_trigger", 6007), ("handler_retirement", 6023),
        ("handler_retirement_match", 6024), ("handler_target_delivery", 6025),
        ("bound_cpu_irq_input", 6027), ("bound_irq_observation", 6058)]
    assert first["second_irq"] == {
        "trigger_id": "gpio_b:0:trigger:2", "trigger_event_id": 6007,
        "observation_event_id": 6058, "cpu_irq_input_event_id": 6027,
        "cpu_step_event_id": 6012}
    assert first["handler_record"]["registered_origin_status"] == "unknown"
    assert first["handler_record"]["registered_origins"] == []
    assert first["handler_record"]["source_refs"] == []
    for item in certified + incomplete:
        assert item["writer"]["pc"] == ISR_PADOUT_PC
        assert item["writer"]["classification"] == {
            "image_id": "cpu.stream.isr", "span": [66048, 68],
            "basis": "declared_initial_image_span_observation_not_identity"}
        assert item["chain_extension"]["joinable"] is False
        assert item["chain_extension"]["missing_identity"]["observed"] == (
            "unknown")
    for item in incomplete:
        # the ISR wrote 0: no rising edge, so no second interrupt exists to join
        assert item["second_irq"]["trigger_id"] is None


# ---------------------------------------------------------------- report CLI


def _cli_module():
    import importlib.util

    from pathlib import Path

    path = (Path(__file__).resolve().parents[2] / "scripts"
            / "report_isr_writeback_certificates.py")
    spec = importlib.util.spec_from_file_location(
        "report_isr_writeback_certificates", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_report_cli_writes_the_run_report_and_never_extends_a_chain(tmp_path):
    from pathlib import Path

    if not Path(REAL_RUN).is_dir():
        pytest.skip("saved acceptance run is not present")
    module = _cli_module()
    output = tmp_path / "isr_writeback.json"
    exit_code = module.main(["--run-dir", REAL_RUN, "--quiet", "--output",
                             str(output)])
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == "isr_writeback_run_report.v1"
    assert report["proof_scope"] == PROOF_SCOPE
    assert report["not_proof_of"] == list(NOT_PROOF_OF)
    assert report["trace_evidence"]["semantic_sha256_verified"] is True
    assert report["trace_evidence"]["events_ingested"] == 31795
    assert report["bounds"]["handler_span"] == [66048, 68]
    assert report["p5_chain_certificates"]["certified_total"] == 8
    assert report["p5_chain_certificates"]["certified_by_direction"] == {
        "CPU_TO_IP_TO_CPU": 3, "IP_TO_CPU_TO_IP": 5}
    assert report["summary"]["chains_audited"] == 8
    assert report["summary"]["chains_extended"] == 0
    assert report["summary"]["chains_not_joinable"] == 8
    assert report["summary"]["chain_extension_verdict"] == "not_joinable"
    assert report["summary"]["adjacency_fallbacks_used"] == 0
    assert report["summary"]["missing_identity"]["field"] == (
        "registered_origins/registered_origin_status")
    assert report["handler_writeback_counters"]["handler_writes_observed"] == 5
    assert len(report["handler_writeback_identities"]) == 5
    keys = {attempt["key"] for audit in report["chain_extension_audits"]
            for attempt in audit["join_attempts"]}
    assert keys == {
        "admission_origin_identity", "irq_take_identity",
        "handler_read_link_identity", "target_access_identity",
        "transaction_identity", "retirement_event_identity",
        "delivery_event_identity", "writer_pc_classification",
        "ordering_adjacency"}
    assert all(audit["extended_hops"] == []
               for audit in report["chain_extension_audits"])
    handler = next(item for item in report["handler_writeback_identities"]
                   if item["target_access_id"] == "gpio-access:gpio_a:0:5")
    assert handler["retire_event_id"] == 6023
    assert handler["retirement_event_id"] == 6024
    assert handler["delivery_event_id"] == 6025
    assert handler["commit_event_id"] == 5925
    assert handler["acceptance_event_id"] == 5908
    assert handler["apb_access_event_id"] == 5923
    assert handler["transaction"]["source_sequence"] == 13
    assert handler["registered_origin_status"] == "unknown"
    assert handler["second_irq"]["trigger_id"] == "gpio_b:0:trigger:2"


def test_certificate_reports_a_present_origin_identity_without_claiming_a_join():
    """The fragment certificate never decides chain attribution by itself."""
    journal = _handler_write_journal(
        retired_origin="known", retired_origins=[{"admission_id": "a" * 64}],
        retired_refs=["case:some.action"])
    certificates, _ = _consume(journal, handler_span=ISR_SPAN)
    assert certificates[0]["chain_extension"] == {
        "joinable": False, "decided_by": "audit_chain_extension",
        "handler_origin_identity_present": True,
        "extension_hop": "handler_padout_writeback", "missing_identity": None}


def test_audit_without_an_anchor_hop_reports_no_anchor():
    chain = _certified_cpu_chain()
    chain = {**chain, "hops": [hop for hop in chain["hops"]
                               if hop["hop_id"] != "retired_target_delivery"]}
    audit = audit_chain_extension(chain, [])
    assert audit["status"] == "no_anchor"
    assert audit["extended_hops"] == []
    assert audit["missing_identity"]["field"] == "retired_target_delivery"
    assert audit["chain_hop_event_ids"] == {}
