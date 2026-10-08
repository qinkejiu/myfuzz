"""Exact nonzero IRQ serial token joins: bounded, incremental and fail-closed.

Every positive case needs an exactly equal nonzero decision/retirement token, one
execution/reset epoch, a legal event gap and a corroborated take identity. Every
negative case must produce no certificate; forged evidence must be recorded as a
rejection without raising, except a non-contiguous journal which raises.
"""

import copy
import json
from functools import lru_cache

import pytest

from myfuzz.scenario.irq_serial_certificates import IrqSerialCertificates


SERIAL_SCHEMA = "ibex_irq_serial_observation.v1"
ZERO_SEMANTICS = "no_provable_source_lineage"


def _role(port, phase, value, status=None):
    if status is None:
        status = "unobservable" if value is None else "observed"
    return {"physical_port": port, "phase": phase, "value": value, "status": status}


def serial_observation(*, decision, retirement, sampling="pre_post_rising",
                       decision_phase="pre", retirement_phase="post"):
    return {"schema_version": SERIAL_SCHEMA, "sampling": sampling, "width_bits": 64,
            "zero_semantics": ZERO_SEMANTICS,
            "decision": _role("irq_decision_serial", decision_phase, decision),
            "retirement": _role("irq_retirement_serial", retirement_phase, retirement)}


def _base(kind, *, producer, component="cpu", execution="local-execution", epoch=0,
          tick=None, **fields):
    return {"kind": kind, "component": component, "source_component": component,
            "execution_id": execution, "reset_epoch": epoch, "source_epoch": epoch,
            "tick": tick, "producer_event_id": producer, **fields}


def decision_event(*, serial=7, producer=10, component="cpu",
                   execution="local-execution", epoch=0,
                   kind="cpu_external_irq_taken", take_key=("cpu", 0, 1),
                   source_trigger=None, observation=None, extra=None):
    fields = dict(irq_taken_pre=1)
    if take_key is not None:
        fields["take_key"] = list(take_key)
    if source_trigger is not None:
        fields["source_trigger"] = dict(source_trigger)
    if extra:
        fields.update(extra)
    return _base(kind, producer=producer, component=component, execution=execution,
                 epoch=epoch, tick=2,
                 irq_serial_observation=(observation if observation is not None else
                                         serial_observation(decision=serial,
                                                            retirement=0)),
                 **fields)


def retirement_event(*, serial=7, producer=20, component="cpu",
                     execution="local-execution", epoch=0, valid=1, intr=1, order=3,
                     observation=None, extra=None):
    fields = dict(valid=valid, intr=intr, order=order, pc_rdata=0x10000, insn=0x13)
    if extra:
        fields.update(extra)
    return _base("cpu_retire", producer=producer, component=component,
                 execution=execution, epoch=epoch, tick=3,
                 irq_serial_observation=(observation if observation is not None else
                                         serial_observation(decision=0, retirement=serial,
                                                            sampling="post_rising",
                                                            decision_phase="post")),
                 **fields)


def filler(count, *, epoch=0):
    return [_base(None, producer=index, epoch=epoch, tick=index,
                  inputs={"irq": 0}, outputs={}) for index in range(count)]


def reset_event(*, epoch, producer=0, component="cpu"):
    return _base("cpu_reset", producer=producer, component=component, epoch=epoch,
                 tick=1, reason="measured_reset")


def pin8_event(kind, *, trigger_id, trigger_event_id, observation_event_id,
               sample_event_id, producer=1, component="gpio_b"):
    return {"kind": kind, "component": component,
            "producer_event_id": producer,
            "source_trigger": {"trigger_id": trigger_id,
                               "trigger_event_id": trigger_event_id,
                               "observation_event_id": observation_event_id,
                               "sample_event_id": sample_event_id}}


def trigger(trigger_id="trig-1", trigger_event_id=5, observation_event_id=6,
            sample_event_id=7):
    return {"trigger_id": trigger_id, "trigger_event_id": trigger_event_id,
            "observation_event_id": observation_event_id, "sample_event_id": sample_event_id}


def journal(*events):
    return [{**event, "event_id": index} for index, event in enumerate(events, start=1)]


def reasons(consumer):
    return [record["reason"] for record in consumer.rejections()]


def test_exact_nonzero_serial_join_certifies_one_native_take():
    events = journal(decision_event(serial=4, producer=10, take_key=("cpu", 0, 1)),
                     retirement_event(serial=4, producer=11, order=1))
    certificates = IrqSerialCertificates().ingest(events)
    assert len(certificates) == 1
    proof = certificates[0]
    assert proof["schema_version"] == "irq_serial_certificate.v1"
    assert proof["kind"] == "irq_serial_certificate"
    assert proof["scope"] == "external_irq_decision_serial_to_rvfi_retirement_serial"
    assert proof["proof_scope"] == "exact_nonzero_irq_serial_token_equality"
    assert "event_adjacency" in proof["not_proof_of"]
    assert proof["decision_serial"] == proof["retirement_serial"] == 4
    assert proof["decision_event_id"] == 1
    assert proof["retirement_event_id"] == 2
    assert proof["event_gap"] == 1
    assert proof["hops"] == 1
    assert proof["execution_id"] == "local-execution"
    assert proof["reset_epoch"] == 0
    assert proof["component"] == "cpu"
    assert proof["take_identity"] == {"take_key": ["cpu", 0, 1]}
    assert proof["take_identity_event_id"] == 1
    assert proof["retirement_order"] == 1
    assert proof["irq_serial_observation_schema"] == SERIAL_SCHEMA
    assert json.loads(json.dumps(proof)) == proof


def test_sample_and_taken_of_one_step_merge_into_one_certified_decision():
    events = journal(decision_event(serial=9, producer=7, take_key=None,
                                    kind="cpu_external_irq_sample"),
                     decision_event(serial=9, producer=7, take_key=("cpu", 0, 1)),
                     retirement_event(serial=9, producer=8, order=2))
    certificates = IrqSerialCertificates().ingest(events)
    assert len(certificates) == 1
    assert certificates[0]["decision_event_id"] == 1
    assert certificates[0]["take_identity_event_id"] == 2
    assert certificates[0]["take_identity"] == {"take_key": ["cpu", 0, 1]}


def test_one_decision_certifies_exactly_one_retirement():
    events = journal(decision_event(serial=4),
                     retirement_event(serial=4, producer=20, order=1),
                     retirement_event(serial=4, producer=21, order=2))
    consumer = IrqSerialCertificates()
    assert len(consumer.ingest(events)) == 1
    assert "unmatched_retirement_serial" in reasons(consumer)
    assert consumer.pending_count == 0


def test_unequal_serials_never_certify():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4),
                                   retirement_event(serial=5))) == ()
    assert "unmatched_retirement_serial" in reasons(consumer)
    assert consumer.pending_count == 1


def test_zero_decision_serial_and_zero_retirement_serial_never_certify():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=0),
                                   retirement_event(serial=0))) == ()
    assert "zero_decision_serial" in reasons(consumer)
    assert "zero_retirement_serial" in reasons(consumer)
    assert consumer.pending_count == 0


def test_cross_epoch_and_cross_execution_retirement_never_certify():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4, epoch=0),
                                   retirement_event(serial=4, epoch=1))) == ()
    matched = [record for record in consumer.rejections()
               if record["reason"] == "unmatched_retirement_serial"]
    assert matched[0]["reset_epoch"] == 1
    assert matched[0]["retirement_serial"] == 4
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4, execution="exec-a"),
                                   retirement_event(serial=4, execution="exec-b"))) == ()
    assert consumer.pending_count == 1


def test_gap_beyond_max_event_gap_never_certifies_and_never_restores_credit():
    consumer = IrqSerialCertificates(max_pending=8, max_event_gap=4)
    events = journal(decision_event(serial=4), *filler(5, epoch=0),
                     retirement_event(serial=4, producer=30))
    assert consumer.ingest(events) == ()
    assert "decision_serial_expired" in reasons(consumer)
    assert consumer.pending_count == 0
    late = journal(retirement_event(serial=4, producer=31, order=9))
    late = [{**event, "event_id": event["event_id"] + len(events)} for event in late]
    assert consumer.ingest(late) == ()
    assert "unmatched_retirement_serial" in reasons(consumer)
    assert consumer.pending_count == 0


def test_missing_take_identity_never_certifies():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4, take_key=None),
                                   retirement_event(serial=4))) == ()
    assert "missing_decision_take_identity" in reasons(consumer)


def test_retirement_must_be_a_valid_interrupt_retirement():
    for field, reason in (("valid", "retirement_not_valid"),
                          ("intr", "retirement_not_interrupt")):
        consumer = IrqSerialCertificates()
        events = journal(decision_event(serial=4),
                         retirement_event(serial=4, **{field: 0}))
        assert consumer.ingest(events) == (), field
        assert reason in reasons(consumer), field


def test_take_key_must_match_scope_and_never_repeat():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4, take_key=("cpu", 3, 1)),
                                   retirement_event(serial=4))) == ()
    assert "take_key_scope_mismatch" in reasons(consumer)
    consumer = IrqSerialCertificates()
    events = journal(decision_event(serial=4, producer=1, take_key=("cpu", 0, 2)),
                     decision_event(serial=5, producer=2, take_key=("cpu", 0, 2)),
                     retirement_event(serial=5, producer=3))
    assert consumer.ingest(events) == ()
    assert "take_key_reused_or_regressed" in reasons(consumer)


def test_source_trigger_identity_requires_exactly_equal_corroborating_pair():
    ref = trigger()
    corroborated = journal(pin8_event("cpu_irq_input", **ref),
                           pin8_event("cpu_irq_taken", **ref, producer=2),
                           decision_event(serial=4, take_key=None, source_trigger=ref,
                                          producer=3),
                           retirement_event(serial=4, producer=4))
    certificates = IrqSerialCertificates().ingest(corroborated)
    assert len(certificates) == 1
    assert certificates[0]["take_identity"] == {"source_trigger": trigger()}
    assert certificates[0]["take_identity_event_id"] == 3


def test_trigger_id_or_referenced_event_mismatch_never_certifies():
    ref = trigger()
    mismatched = trigger(trigger_event_id=9)
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(
        pin8_event("cpu_irq_input", **ref),
        pin8_event("cpu_irq_taken", **mismatched, producer=2),
        decision_event(serial=4, take_key=None, source_trigger=ref, producer=3),
        retirement_event(serial=4, producer=4))) == ()
    assert "trigger_identity_mismatch" in reasons(consumer)


def test_uncorroborated_source_trigger_never_certifies():
    ref = trigger()
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(
        pin8_event("cpu_irq_input", **ref),
        decision_event(serial=4, take_key=None, source_trigger=ref, producer=3),
        retirement_event(serial=4, producer=4))) == ()
    assert "take_identity_uncorroborated" in reasons(consumer)
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(
        decision_event(serial=4, take_key=None, source_trigger=trigger(), producer=3),
        retirement_event(serial=4, producer=4))) == ()
    assert "take_identity_uncorroborated" in reasons(consumer)


def test_conflicting_duplicate_decision_serial_never_certifies():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(decision_event(serial=4, producer=1,
                                                  take_key=("cpu", 0, 1)),
                                   decision_event(serial=4, producer=2,
                                                  take_key=("cpu", 0, 2)),
                                   retirement_event(serial=4, producer=3))) == ()
    assert "duplicate_decision_serial" in reasons(consumer)
    assert consumer.pending_count == 0


def test_conflicting_identity_on_one_step_never_certifies():
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(
        decision_event(serial=4, producer=1, take_key=("cpu", 0, 1),
                       kind="cpu_external_irq_sample"),
        decision_event(serial=4, producer=1, take_key=("cpu", 0, 2)),
        retirement_event(serial=4, producer=2))) == ()
    assert "decision_identity_conflict" in reasons(consumer)
    assert consumer.pending_count == 0


def test_reset_events_clear_pending_credit():
    consumer = IrqSerialCertificates(max_pending=8, max_event_gap=64)
    events = journal(decision_event(serial=4, epoch=0),
                     reset_event(epoch=1, producer=1),
                     retirement_event(serial=4, epoch=1, producer=2))
    assert consumer.ingest(events) == ()
    assert consumer.pending_count == 0
    assert "unmatched_retirement_serial" in reasons(consumer)


@pytest.mark.parametrize("value", [True, False, -1, 1 << 64, "7", 7.0])
def test_forged_serial_value_types_are_rejected(value):
    consumer = IrqSerialCertificates()
    forged = serial_observation(decision=7, retirement=0)
    forged["decision"]["value"] = value
    events = journal(
        decision_event(serial=7, take_key=("cpu", 0, 1), observation=forged),
        retirement_event(serial=7, producer=11))
    assert consumer.ingest(events) == ()
    assert "malformed_irq_serial_value" in reasons(consumer)
    assert consumer.pending_count == 0


@pytest.mark.parametrize("document", [
    {"schema_version": "irq_serial_observation.v0"},
    {"schema_version": SERIAL_SCHEMA, "sampling": "pre_post_rising", "width_bits": 64,
     "zero_semantics": ZERO_SEMANTICS,
     "decision": {"physical_port": "irq_decision_serial", "phase": "pre",
                  "value": 7, "status": "observed"},
     "retirement": {"physical_port": "irq_retirement_serial", "phase": "post",
                    "value": None, "status": "observed"}},
    {"schema_version": SERIAL_SCHEMA, "sampling": "guessed", "width_bits": 64,
     "zero_semantics": ZERO_SEMANTICS,
     "decision": {"physical_port": "irq_decision_serial", "phase": "pre",
                  "value": 7, "status": "observed"},
     "retirement": {"physical_port": "irq_retirement_serial", "phase": "post",
                    "value": 0, "status": "observed"}},
    {"schema_version": SERIAL_SCHEMA, "sampling": "pre_post_rising", "width_bits": 64,
     "zero_semantics": ZERO_SEMANTICS,
     "decision": {"physical_port": "rvfi_order", "phase": "pre",
                  "value": 7, "status": "observed"},
     "retirement": {"physical_port": "irq_retirement_serial", "phase": "post",
                    "value": 0, "status": "observed"}},
])
def test_malformed_serial_documents_are_rejected(document):
    consumer = IrqSerialCertificates()
    assert consumer.ingest(journal(
        decision_event(serial=7, take_key=("cpu", 0, 1), observation=document),
        retirement_event(serial=7, producer=11))) == ()
    assert reasons(consumer)[0].startswith("malformed_irq_serial_")
    assert "scope_barred_after_observed_evidence_conflict" in reasons(consumer)


def test_malformed_observation_bars_the_scope_until_a_real_reset():
    consumer = IrqSerialCertificates(max_pending=8, max_event_gap=64)
    forged = {"schema_version": SERIAL_SCHEMA}
    events = journal(decision_event(serial=7, take_key=("cpu", 0, 1),
                                    observation=forged),
                     decision_event(serial=7, producer=11, take_key=("cpu", 0, 1)),
                     retirement_event(serial=7, producer=12))
    assert consumer.ingest(events) == ()
    assert "scope_barred_after_observed_evidence_conflict" in reasons(consumer)
    recovered = journal(decision_event(serial=8, take_key=("cpu", 0, 2)),
                        retirement_event(serial=8, producer=21))
    recovered = [{**event, "event_id": event["event_id"] + len(events)}
                 for event in recovered]
    assert consumer.ingest(recovered) == ()
    after_reset = journal(reset_event(epoch=1, producer=30),
                          decision_event(serial=9, epoch=1, take_key=("cpu", 1, 1)),
                          retirement_event(serial=9, epoch=1, producer=31))
    after_reset = [{**event, "event_id": event["event_id"] + len(events) + len(recovered)}
                   for event in after_reset]
    assert len(consumer.ingest(after_reset)) == 1


def test_legacy_events_without_serial_fields_are_incomplete_without_error():
    consumer = IrqSerialCertificates()
    legacy_decision = decision_event(serial=4)
    legacy_decision.pop("irq_serial_observation")
    legacy_retirement = retirement_event(serial=4, producer=11)
    legacy_retirement.pop("irq_serial_observation")
    quiet = retirement_event(serial=0, producer=12, intr=0, order=2)
    quiet.pop("irq_serial_observation")
    assert consumer.ingest(journal(legacy_decision, legacy_retirement, quiet)) == ()
    assert reasons(consumer) == ["missing_irq_serial_observation",
                                 "missing_irq_serial_observation"]
    assert consumer.pending_count == 0


def test_unobservable_legacy_subject_artifact_events_are_incomplete_without_error():
    consumer = IrqSerialCertificates()
    events = journal(
        decision_event(observation=serial_observation(decision=None, retirement=None)),
        retirement_event(serial=4, observation=serial_observation(
            decision=None, retirement=None, sampling="post_rising",
            decision_phase="post")))
    assert consumer.ingest(events) == ()
    assert "unobservable_decision_serial" in reasons(consumer)
    assert "unobservable_retirement_serial" in reasons(consumer)


def test_journal_must_be_contiguous():
    consumer = IrqSerialCertificates()
    consumer.ingest(journal(decision_event(serial=4)))
    with pytest.raises(ValueError):
        consumer.ingest([{"event_id": 3, "kind": "cpu_retire", "intr": 1}])
    with pytest.raises(ValueError):
        consumer.ingest([{"kind": "cpu_retire", "intr": 1}])
    with pytest.raises(ValueError):
        consumer.ingest([{"event_id": True, "kind": "cpu_retire", "intr": 1}])


def test_long_synthetic_journal_keeps_every_cache_bounded():
    consumer = IrqSerialCertificates(max_pending=16, max_event_gap=64)
    events = journal(*[decision_event(serial=index + 1, producer=index,
                                      take_key=("cpu", 0, index + 1))
                       for index in range(50_000)])
    assert consumer.ingest(events) == ()
    assert consumer.pending_count <= consumer.max_pending
    counts = consumer.state_counts()
    assert set(counts) == {"pending_decisions", "take_identities", "trigger_references",
                           "rejections"}
    assert all(0 <= value <= consumer.max_pending for value in counts.values())


def test_every_refusal_has_a_minimal_repair_that_certifies():
    """Each guard is load-bearing: repairing exactly one fact yields one certificate."""
    ref = trigger()
    mismatched = trigger(trigger_event_id=9)
    forged = serial_observation(decision=4, retirement=0)
    forged["decision"]["value"] = True
    legacy = decision_event(serial=4)
    legacy.pop("irq_serial_observation")
    cases = [
        # unequal serials
        (IrqSerialCertificates, journal(decision_event(serial=4), retirement_event(serial=5)),
         journal(decision_event(serial=4), retirement_event(serial=4))),
        # zero decision serial
        (IrqSerialCertificates, journal(decision_event(serial=0), retirement_event(serial=0)),
         journal(decision_event(serial=4), retirement_event(serial=4))),
        # forged serial value type
        (IrqSerialCertificates,
         journal(decision_event(serial=4, observation=forged), retirement_event(serial=4)),
         journal(decision_event(serial=4), retirement_event(serial=4))),
        # missing take identity
        (IrqSerialCertificates,
         journal(decision_event(serial=4, take_key=None), retirement_event(serial=4)),
         journal(decision_event(serial=4, take_key=("cpu", 0, 1)),
                retirement_event(serial=4))),
        # missing measured serial observation (legacy event)
        (IrqSerialCertificates, journal(legacy, retirement_event(serial=4)),
         journal(decision_event(serial=4), retirement_event(serial=4))),
        # cross epoch
        (IrqSerialCertificates,
         journal(decision_event(serial=4, epoch=0), retirement_event(serial=4, epoch=1)),
         journal(decision_event(serial=4, epoch=0), retirement_event(serial=4, epoch=0))),
        # trigger_id/reference mismatch
        (IrqSerialCertificates,
         journal(pin8_event("cpu_irq_input", **ref),
                 pin8_event("cpu_irq_taken", **mismatched, producer=2),
                 decision_event(serial=4, take_key=None, source_trigger=ref, producer=3),
                 retirement_event(serial=4, producer=4)),
         journal(pin8_event("cpu_irq_input", **ref),
                 pin8_event("cpu_irq_taken", **ref, producer=2),
                 decision_event(serial=4, take_key=None, source_trigger=ref, producer=3),
                 retirement_event(serial=4, producer=4))),
        # gap beyond max_event_gap
        (lambda: IrqSerialCertificates(max_pending=8, max_event_gap=4),
         journal(decision_event(serial=4), *filler(5), retirement_event(serial=4, producer=30)),
         journal(decision_event(serial=4), retirement_event(serial=4, producer=30))),
        # reset-cleared credit
        (IrqSerialCertificates,
         journal(decision_event(serial=4, epoch=0), reset_event(epoch=1, producer=1),
                 retirement_event(serial=4, epoch=1, producer=2)),
         journal(reset_event(epoch=1, producer=1),
                 decision_event(serial=4, epoch=1, take_key=("cpu", 1, 1)),
                 retirement_event(serial=4, epoch=1, producer=2))),
    ]
    for index, (factory, broken, repaired) in enumerate(cases):
        assert factory().ingest(broken) == (), index
        assert len(factory().ingest(repaired)) == 1, index


def test_bounds_must_be_positive_integers():
    for kwargs in ({"max_pending": 0}, {"max_pending": True}, {"max_event_gap": 0},
                   {"max_event_gap": 1.0}, {"max_pending": "8"}):
        with pytest.raises(ValueError):
            IrqSerialCertificates(**kwargs)


def test_serial_observation_contract_is_versioned_typed_and_enforced():
    from myfuzz.local_harness.ibex_irq_receipt_contract import (
        ibex_irq_serial_observation, ibex_irq_serial_observation_contract,
        validate_ibex_irq_serial_observation_contract)
    contract = ibex_irq_serial_observation_contract()
    validate_ibex_irq_serial_observation_contract(contract)
    assert contract["schema_version"] == SERIAL_SCHEMA
    assert contract["ports"] == {"decision": "irq_decision_serial",
                                 "retirement": "irq_retirement_serial"}
    assert contract["width_bits"] == 64
    assert contract["zero_semantics"] == ZERO_SEMANTICS
    changed = copy.deepcopy(contract)
    changed["width_bits"] = True
    with pytest.raises(ValueError):
        validate_ibex_irq_serial_observation_contract(changed)
    for value in (True, -1, 1 << 64, "7", 7.0):
        with pytest.raises(ValueError):
            ibex_irq_serial_observation(sampling="post_rising", decision_value=value,
                                        retirement_value=0, decision_phase="post",
                                        retirement_phase="post")
    with pytest.raises(ValueError):
        ibex_irq_serial_observation(sampling="guessed", decision_value=0,
                                    retirement_value=0, decision_phase="pre",
                                    retirement_phase="post")


class _StubCpuSession:
    """Minimal session surface used by the runner's cpu_observation drain."""

    reset_epoch = 0

    def __init__(self, events):
        self.cpu_events = list(events)

    def identity_document(self):
        return {"fixture": "irq_serial_runner.v1"}

    def begin_case(self, testcase):
        pass

    def end_case(self):
        pass

    def step_local(self, inputs):
        return {}


@lru_cache(maxsize=1)
def _measured_session_event_groups():
    """Measured GeneratedCve2Session events: one IRQ take, then one retirement."""
    from tests.local_harness.test_cpu_native_irq_receipt import CpuNativeIrqReceiptTests
    CpuNativeIrqReceiptTests.setUpClass()
    helper = CpuNativeIrqReceiptTests()
    cpu = helper.cpu()
    names = {row["physical_port"]: row["runtime_name"]
             for row in cpu._artifact_document["physical_exports"]}
    serial = {row["physical_port"]: row for row in
              cpu._artifact_document["physical_exports"]}

    def decision(payload, irq):
        payload["samples"][0]["pre"]["physical"][names["irq_decision_serial"]] = 4
        payload["samples"][0]["post"]["physical"][names["irq_decision_serial"]] = 0
        payload["samples"][0]["post"]["physical"][names["irq_retirement_serial"]] = 0

    def retirement(payload, irq):
        post = payload["samples"][0]["post"]["physical"]
        for port, value in (("rvfi_valid", 1), ("rvfi_order", 1), ("rvfi_insn", 0x13),
                            ("rvfi_pc_rdata", 0x1012C), ("rvfi_intr", 1),
                            ("irq_retirement_serial", 4)):
            post[serial[port]["runtime_name"]] = value

    helper.step(cpu, taken=1, irq_valid=1, mutation=decision)
    taken = copy.deepcopy(cpu.cpu_events)
    cpu.cpu_events.clear()
    helper.step(cpu, irq=0, mutation=retirement)
    return tuple(taken), copy.deepcopy(cpu.cpu_events)


def test_runner_drained_session_events_certify_one_exact_join():
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner
    taken, retired = _measured_session_event_groups()
    session = _StubCpuSession(taken)
    ownership = compile_ownership((InputField("cpu", "irq", 1),),
                                  (InputOwner("cpu", "irq", 0, 1, "source", "irq"),))
    runner = ScenarioRunner(sessions={"cpu": session}, ownership=ownership, bindings=())
    runner._append_external_events("cpu", 1)
    session.cpu_events.extend(retired)
    runner._append_external_events("cpu", 2)
    journal = [event for event in runner.events]
    assert [event["kind"] for event in journal] == [
        "cpu_external_irq_sample", "cpu_external_irq_taken", "cpu_irq_notification",
        "cpu_external_irq_sample", "cpu_retire"]
    assert journal[0]["irq_serial_observation"]["decision"] == {
        "physical_port": "irq_decision_serial", "phase": "pre", "value": 4,
        "status": "observed"}
    assert journal[1]["take_key"] == ["cpu", 0, 1]
    certificates = IrqSerialCertificates().ingest(journal)
    assert len(certificates) == 1
    proof = certificates[0]
    assert proof["decision_serial"] == proof["retirement_serial"] == 4
    assert proof["decision_event_id"] == 1
    assert proof["take_identity_event_id"] == 2
    assert proof["retirement_event_id"] == 5
    assert proof["event_gap"] == 4
    assert proof["take_identity"] == {"take_key": ["cpu", 0, 1]}
    assert proof["decision_sampling"] == "pre_post_rising"
    assert proof["retirement_sampling"] == "post_rising"
