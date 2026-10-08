"""RVFI IRQ serial token witness fused into the full chain certificate.

The optional ``cpu_irq_serial_token`` hop is joined by exact identity only: the
certified ``irq_serial_certificate.v1`` decision ``producer_event_id`` must equal
the CPU step event id the chain's ``cpu_irq_taken`` hop was emitted for, i.e. the
same CPU step produced both the pin8 IRQ router take and the native Ibex IRQ
receipt the serial token was physically observed on.

Fail-closed rules under test (documented in ``chain_certificates``):

* ``serial_token_status="absent"`` -- no certified token is attributable to the
  admission's take; the chain keeps its legacy verdict and hop sequence.
* ``serial_token_status="witnessed"`` -- the hop is attached and its evidence
  carries the exact certificate fields.
* ``serial_token_status="refused"`` -- a token *is* attributable but any
  corroboration fails; the admission is settled ``incomplete`` with
  ``serial_token_reason`` naming the first failed check. It is never silently
  ignored.

``require_serial_token=True`` makes the hop required, so only a witnessed token
can certify an IP-observed chain.
"""

import hashlib
import json

import pytest

from myfuzz.scenario.acceptance_metrics import TraceEventStream
from myfuzz.scenario.chain_certificates import (
    CPU_IRQ_SERIAL_HOP,
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    SERIAL_TOKEN_ABSENT,
    SERIAL_TOKEN_REFUSED,
    SERIAL_TOKEN_WITNESSED,
    SCHEMA_VERSION,
    ChainCertificates,
)
from myfuzz.scenario.irq_serial_certificates import (
    CERTIFICATE_SCHEMA as SERIAL_CERTIFICATE_SCHEMA,
    PROOF_SCOPE as SERIAL_PROOF_SCOPE,
    IrqSerialCertificates,
)
from tests.scenario.test_chain_certificates import (
    CPU_HOPS,
    FIXTURE,
    IP_HOPS,
    ROOT,
    _certificates,
    _cpu_journal,
    _ip_journal,
    _merge,
    _pin8_admission,
    _provenance,
    _stream_fixture,
)
from tests.scenario.test_irq_serial_certificates import serial_observation


RUN = ROOT / "runs/current-dataflow-p5-paired-20261007-online"
SERIAL_SCHEMA = "ibex_irq_serial_observation.v1"
SERIAL_SCOPE = "external_irq_decision_serial_to_rvfi_retirement_serial"

# Declared IP sequence with the optional serial witness hop directly after the
# CPU interrupt take and before the ISR PADIN MMIO leg.
IP_HOPS_SERIAL = IP_HOPS[:10] + (CPU_IRQ_SERIAL_HOP,) + IP_HOPS[10:]


def _native_decision(step, *, serial, take_key, epoch, case_index, kind, observation=None):
    event = {
        "kind": kind, "component": "cpu", "source_component": "cpu",
        "execution_id": "local-execution", "reset_epoch": epoch,
        "source_epoch": epoch, "tick": 41, "local_tick": 41,
        "irq_taken_pre": 1, "producer_event_id": step,
        "irq_serial_observation": observation if observation is not None else
        serial_observation(decision=serial, retirement=0),
        "provenance": _provenance(case_index),
    }
    if take_key is not None:
        event["take_key"] = list(take_key)
    return event


def _native_retirement(step, *, serial, epoch, case_index, observation=None):
    return {
        "kind": "cpu_retire", "component": "cpu", "source_component": "cpu",
        "execution_id": "local-execution", "reset_epoch": epoch,
        "source_epoch": epoch, "tick": 44, "local_tick": 44, "valid": 1,
        "trap": 0, "intr": 1, "insn": 0x13, "order": 43, "pc_rdata": 0x10200,
        "producer_event_id": step,
        "irq_serial_observation": observation if observation is not None else
        serial_observation(decision=0, retirement=serial, sampling="post_rising",
                           decision_phase="post", retirement_phase="post"),
        "provenance": _provenance(case_index),
    }


def _serial_ip_journal(case_index=1, *, tokens=(7,), take_sequences=(1,), epoch=0,
                       tag="", kind="cpu_external_irq_taken",
                       decision_before="cpu_irq_input",
                       retirement_before="isr_padin_mmio_acceptance",
                       decision_observation=None, retirement_observation=None):
    """IP chain journal plus ``tokens`` native IRQ serial joins.

    Every join is inserted as a native decision event before ``decision_before``
    followed by its interrupt retirement before ``retirement_before``; both name
    the journal's own ``ip_step`` CPU step event, which is the exact identity the
    chain's ``cpu_irq_taken`` hop was emitted for.
    """
    journal = _ip_journal(case_index, tag=tag)
    step = journal.ref("ip_step")
    for index, serial in enumerate(tokens):
        sequence = take_sequences[index]
        take_key = None if sequence is None else ("cpu", epoch, sequence)
        journal.insert_before(decision_before, _native_decision(
            step, serial=serial, take_key=take_key, epoch=epoch,
            case_index=case_index, kind=kind, observation=decision_observation))
        journal.insert_before(retirement_before, _native_retirement(
            step, serial=serial, epoch=epoch, case_index=case_index,
            observation=retirement_observation))
    return journal


def _isolate(journal, case_index):
    """Make an IP journal case-unique so several of them can be audited together.

    The stock ``_ip_journal`` reuses one trigger id and one ``source_event_id``,
    and the per-hop auditors require globally advancing, exactly matching source
    identities; only those two families need to be re-keyed for side-by-side
    auditing (access ids and transaction keys are always checked by exact event
    id, so a shared value cannot join two cases).
    """
    trigger_id = f"gpio_b:0:trigger:{case_index}"
    for name in ("gpio_b_native_irq_trigger", "gpio_b_native_irq_observation"):
        journal.edit(name, lambda event, tid=trigger_id: {**event,
                                                          "trigger_id": tid})
    for name in ("ip_source_start", "ip_pulse_start", "cpu_irq_input",
                 "cpu_irq_taken"):
        journal.edit(name, lambda event, tid=trigger_id, sid=case_index: {
            **event, "source_event_id": sid,
            "source_trigger": {**event["source_trigger"], "trigger_id": tid}})
    return journal


def _partition(certificate, sequence, required):
    """hops/missing_hops must stay recomputable from the declared sequence."""
    observed = [hop["hop_id"] for hop in certificate["hops"]]
    assert len(set(observed)) == len(observed)
    assert observed == [name for name in sequence if name in observed]
    assert [hop["event_id"] for hop in certificate["hops"]] == sorted(
        hop["event_id"] for hop in certificate["hops"])
    for hop in certificate["hops"]:
        assert type(hop["event_id"]) is int and hop["event_id"] > 0
        assert isinstance(hop["evidence"], dict) and hop["evidence"]
    if certificate["status"] == "certified":
        assert certificate["missing_hops"] == []
        assert observed == [name for name in sequence
                            if name in required or name in observed]
    else:
        assert certificate["missing_hops"] == [
            name for name in required if name not in observed]


def _hop(certificate, name):
    return next(hop for hop in certificate["hops"] if hop["hop_id"] == name)


def test_serial_witness_hop_is_inserted_between_take_and_isr():
    journal = _serial_ip_journal()
    decision_id = journal.ids["cpu_irq_input"] - 1
    retirement_id = journal.ids["isr_padin_mmio_acceptance"] - 1
    assert journal.events[decision_id - 1]["kind"] == "cpu_external_irq_taken"
    assert journal.events[retirement_id - 1]["kind"] == "cpu_retire"
    certificates, consumer = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["status"] == "certified"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_WITNESSED
    assert certificate["serial_token_reason"] is None
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS_SERIAL)
    assert [hop["event_id"] for hop in certificate["hops"]] == [
        retirement_id if name == CPU_IRQ_SERIAL_HOP else journal.ids[name]
        for name in IP_HOPS_SERIAL]
    serial_hop = _hop(certificate, CPU_IRQ_SERIAL_HOP)
    assert serial_hop["event_id"] == retirement_id
    evidence = serial_hop["evidence"]
    assert evidence["kind"] == "irq_serial_certificate"
    assert evidence["decision_serial"] == evidence["retirement_serial"] == 7
    assert evidence["decision_event_id"] == decision_id
    assert evidence["retirement_event_id"] == retirement_id
    assert evidence["take_identity"] == {"take_key": ["cpu", 0, 1]}
    assert evidence["take_identity_event_id"] == decision_id
    assert evidence["take_identity_schema_version"] == "irq_serial_take_identity.v1"
    assert evidence["proof_scope"] == SERIAL_PROOF_SCOPE
    assert evidence["scope"] == SERIAL_SCOPE
    assert evidence["irq_serial_observation_schema"] == SERIAL_SCHEMA
    assert evidence["execution_id"] == "local-execution"
    assert evidence["reset_epoch"] == 0
    assert evidence["component"] == "cpu"
    assert evidence["event_gap"] == retirement_id - decision_id
    assert "complete_propagation_chain" in evidence["not_proof_of"]
    # The certificate id rule and the proof scope of the fused chain never move,
    # and the endpoint case is still proven by the very same events.
    admission = _pin8_admission()
    assert certificate["certificate_id"] == hashlib.sha256(json.dumps(
        [IP_TO_CPU_TO_IP, admission.admission_id],
        separators=(",", ":")).encode("utf-8")).hexdigest()
    assert certificate["proof_scope"] == "ip_to_cpu_to_ip_certified_hops"
    assert certificate["endpoint_case_id"] == "case-1"
    assert certificate["completed_event_id"] == \
        journal.ids["isr_padin_retirement"]
    assert certificate["completed_local_ticks"] == {"gpio_b": 221, "cpu": 207}
    _partition(certificate, IP_HOPS_SERIAL, IP_HOPS_SERIAL)
    assert consumer.serial_witness_count == 0


def test_absent_serial_keeps_the_legacy_ip_chain_unchanged():
    journal = _ip_journal()
    certificates, consumer = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "certified"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert certificate["serial_token_reason"] is None
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS)
    assert [hop["event_id"] for hop in certificate["hops"]] == [
        journal.ids[name] for name in IP_HOPS]
    assert all(hop["evidence"]["kind"] != "irq_serial_certificate"
               for hop in certificate["hops"])
    _partition(certificate, IP_HOPS, IP_HOPS)
    assert consumer.serial_witness_count == 0


def test_require_serial_token_demands_the_witness_hop():
    plain, _ = _certificates(_ip_journal(), require_serial_token=True)
    assert len(plain) == 1
    certificate = plain[0]
    assert certificate["status"] == "incomplete"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert certificate["missing_hops"][0] == CPU_IRQ_SERIAL_HOP
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS[:10])
    _partition(certificate, IP_HOPS_SERIAL, IP_HOPS_SERIAL)

    witnessed, _ = _certificates(_serial_ip_journal(), require_serial_token=True)
    assert witnessed[0]["status"] == "certified"
    assert [hop["hop_id"] for hop in witnessed[0]["hops"]] == list(IP_HOPS_SERIAL)
    assert witnessed[0]["serial_token_status"] == SERIAL_TOKEN_WITNESSED

    # No IRQ take identity exists in the CPU -> IP -> CPU direction, so the
    # serial token can never be an admission requirement there.
    cpu, _ = _certificates(_cpu_journal(), require_serial_token=True)
    assert cpu[0]["status"] == "certified"
    assert [hop["hop_id"] for hop in cpu[0]["hops"]] == list(CPU_HOPS)
    assert cpu[0]["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert cpu[0]["serial_token_reason"] is None


def test_require_serial_token_is_a_boolean_flag():
    with pytest.raises(ValueError):
        ChainCertificates(require_serial_token=1)
    with pytest.raises(ValueError):
        ChainCertificates(require_serial_token="yes")


def test_attributed_epoch_mismatch_refuses_the_chain():
    # The native token was observed in reset epoch 1 while the fused chain's own
    # trigger lives in epoch 0: the token is attributable to this take, so it can
    # never be silently dropped.
    journal = _serial_ip_journal(epoch=1)
    certificates, consumer = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_REFUSED
    assert certificate["serial_token_reason"] == "serial_reset_epoch_mismatch"
    assert CPU_IRQ_SERIAL_HOP not in [hop["hop_id"] for hop in certificate["hops"]]
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS[:10])
    assert certificate["missing_hops"][0] == "isr_padin_mmio_acceptance"
    _partition(certificate, IP_HOPS_SERIAL, IP_HOPS)
    assert consumer.flush() == ()
    assert consumer.serial_witness_count == 0

    required, _ = _certificates(journal, require_serial_token=True)
    assert required[0]["status"] == "incomplete"
    assert required[0]["serial_token_reason"] == "serial_reset_epoch_mismatch"
    assert required[0]["missing_hops"][0] == CPU_IRQ_SERIAL_HOP


def test_witness_retirement_before_the_chain_take_refuses():
    journal = _serial_ip_journal(retirement_before="cpu_irq_input")
    certificates, _ = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_REFUSED
    assert certificate["serial_token_reason"] == "serial_witness_out_of_order"
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS[:10])


def test_second_token_for_one_take_refuses_the_chain():
    journal = _serial_ip_journal(tokens=(7, 8), take_sequences=(1, 2))
    certificates, _ = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_REFUSED
    assert certificate["serial_token_reason"] == "duplicate_serial_witness"
    assert certificate["serial_token_status"] != SERIAL_TOKEN_WITNESSED
    assert CPU_IRQ_SERIAL_HOP not in [hop["hop_id"] for hop in certificate["hops"]]


def test_two_tokens_buffered_for_one_take_refuse_when_it_is_taken():
    # Both tokens retire before the chain's own take is proven, so both are
    # retained under one exact step identity: the conflict must refuse rather
    # than silently keep the later token.
    journal = _serial_ip_journal(tokens=(7, 8), take_sequences=(1, 2),
                                 retirement_before="cpu_irq_input")
    certificates, consumer = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "incomplete"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_REFUSED
    assert certificate["serial_token_reason"] == "duplicate_serial_witness"
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS[:10])
    assert consumer.serial_witness_count == 0


ZERO_OBSERVATION = serial_observation(decision=0, retirement=0)


@pytest.mark.parametrize("decision,retirement,decision_observation,"
                         "retirement_observation", (
    # The hardware's own zero semantics: no provable source lineage at all.
    (0, 0, ZERO_OBSERVATION, serial_observation(
        decision=0, retirement=0, sampling="post_rising", decision_phase="post")),
    # A nonzero decision token that no retirement ever matches.
    (7, 9, None, serial_observation(
        decision=0, retirement=9, sampling="post_rising", decision_phase="post")),
))
def test_non_certifying_serials_leave_the_chain_unwitnessed(
        decision, retirement, decision_observation, retirement_observation):
    journal = _serial_ip_journal(
        tokens=(decision,), take_sequences=(1,),
        decision_observation=decision_observation,
        retirement_observation=retirement_observation)
    certificates, _ = _certificates(journal)
    assert len(certificates) == 1
    certificate = certificates[0]
    assert certificate["status"] == "certified"
    assert certificate["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert certificate["serial_token_reason"] is None
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS)

    required, _ = _certificates(journal, require_serial_token=True)
    assert required[0]["status"] == "incomplete"
    assert required[0]["missing_hops"][0] == CPU_IRQ_SERIAL_HOP


def test_malformed_serial_observation_never_witnesses_without_a_certificate():
    forged = serial_observation(decision=7, retirement=0)
    forged["schema_version"] = "ibex_irq_serial_observation.v0"
    journal = _serial_ip_journal(decision_observation=forged)
    certificates, _ = _certificates(journal)
    assert certificates[0]["status"] == "certified"
    assert certificates[0]["serial_token_status"] == SERIAL_TOKEN_ABSENT
    required, _ = _certificates(journal, require_serial_token=True)
    assert required[0]["status"] == "incomplete"
    assert required[0]["missing_hops"][0] == CPU_IRQ_SERIAL_HOP


def test_serial_witness_never_crosses_to_an_unrelated_admission():
    """Two interleaved IP admissions: only the token's own step is witnessed."""
    journal = _merge(_isolate(_serial_ip_journal(case_index=1, tag="one_"), 1),
                     _isolate(_ip_journal(case_index=2, tag="two_"), 2))
    certificates, _ = _certificates(journal)
    by_case = {certificate["source_case_index"]: certificate
               for certificate in certificates}
    assert set(by_case) == {1, 2}
    witnessed = by_case[1]
    assert witnessed["status"] == "certified"
    assert witnessed["serial_token_status"] == SERIAL_TOKEN_WITNESSED
    assert [hop["hop_id"] for hop in witnessed["hops"]] == list(IP_HOPS_SERIAL)
    other = by_case[2]
    assert other["status"] == "certified"
    assert other["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert [hop["hop_id"] for hop in other["hops"]] == list(IP_HOPS)


def _unmatched_token(step, serial, sequence, *, tick):
    """A native IRQ receipt pair on a CPU step no admission take ever names."""
    decision = {
        "kind": "cpu_external_irq_taken", "component": "cpu",
        "source_component": "cpu", "execution_id": "local-execution",
        "reset_epoch": 0, "source_epoch": 0, "tick": tick, "local_tick": tick,
        "irq_taken_pre": 1, "producer_event_id": step,
        "take_key": ["cpu", 0, sequence],
        "irq_serial_observation": serial_observation(decision=serial,
                                                     retirement=0),
        "provenance": _provenance(1),
    }
    retirement = {
        "kind": "cpu_retire", "component": "cpu", "source_component": "cpu",
        "execution_id": "local-execution", "reset_epoch": 0, "source_epoch": 0,
        "tick": tick + 1, "local_tick": tick + 1, "valid": 1, "trap": 0,
        "intr": 1, "insn": 0x13, "order": tick, "pc_rdata": 0x10200,
        "producer_event_id": step,
        "irq_serial_observation": serial_observation(
            decision=0, retirement=serial, sampling="post_rising",
            decision_phase="post"),
        "provenance": _provenance(1),
    }
    return decision, retirement


def test_pending_and_serial_witness_state_stay_bounded():
    consumer = ChainCertificates(max_pending=4)
    journal = _serial_ip_journal()
    produced = []
    for event in journal.events:
        produced.extend(consumer.ingest((event,)))
        assert consumer.pending_count <= 4
        assert consumer.serial_witness_count <= 4
    assert len(produced) == 1
    assert produced[0]["status"] == "certified"
    assert produced[0]["serial_token_status"] == SERIAL_TOKEN_WITNESSED

    # A long tail of fillers and 30 certified tokens that name no live
    # admission take: every retained cache, including the unmatched witness
    # buffer, must stay bounded by ``max_pending``.
    tail = []
    for index in range(30):
        decision, retirement = _unmatched_token(
            900000 + index, 1000 + index, 10 + index, tick=1000 + 8 * index)
        tail.extend((decision, {"kind": "state_dependency"},
                     {"kind": "state_dependency"}, retirement))
        tail.extend({"kind": "state_dependency"} for _ in range(50))
    event_id = journal.events[-1]["event_id"]
    pending_peak = 0
    witness_peak = 0
    for event in tail:
        event_id += 1
        produced.extend(consumer.ingest(({**event, "event_id": event_id},)))
        pending_peak = max(pending_peak, consumer.pending_count)
        witness_peak = max(witness_peak, consumer.serial_witness_count)
        assert consumer.pending_count <= 4
        assert consumer.serial_witness_count <= 4
    assert pending_peak <= 4 and witness_peak == 4
    assert len(produced) == 1
    assert consumer.flush() == ()
    assert consumer.pending_count == 0
    assert consumer.serial_witness_count == 4


def test_real_fixture_without_serial_keeps_the_legacy_report():
    assert FIXTURE.is_file(), FIXTURE
    consumer = ChainCertificates()
    admissions, certificates, peak = _stream_fixture(consumer)
    assert len(admissions) == len(certificates) == 25
    assert peak <= consumer.max_pending
    certified = [c for c in certificates if c["status"] == "certified"]
    incomplete = [c for c in certificates if c["status"] == "incomplete"]
    assert len(certified) == 7
    assert len(incomplete) == 18
    assert [c["direction"] for c in certified].count(IP_TO_CPU_TO_IP) == 5
    assert [c["direction"] for c in certified].count(CPU_TO_IP_TO_CPU) == 2
    assert sorted(c["source_case_index"] for c in certified) == [1, 4, 6, 10, 16,
                                                                 20, 22]
    for certificate in certificates:
        expected = IP_HOPS if certificate["direction"] == IP_TO_CPU_TO_IP \
            else CPU_HOPS
        assert certificate["serial_token_status"] == SERIAL_TOKEN_ABSENT
        assert certificate["serial_token_reason"] is None
        if certificate["status"] == "certified":
            assert [hop["hop_id"] for hop in certificate["hops"]] == list(expected)
        _partition(certificate, expected, expected)


def test_real_fixture_require_serial_token_leaves_only_the_cpu_chains():
    assert FIXTURE.is_file(), FIXTURE
    consumer = ChainCertificates(require_serial_token=True)
    admissions, certificates, _ = _stream_fixture(consumer)
    assert len(admissions) == len(certificates) == 25
    certified = [c for c in certificates if c["status"] == "certified"]
    # A trace without any RVFI serial receipt can never witness the IP direction.
    assert [c["direction"] for c in certified] == [CPU_TO_IP_TO_CPU] * 2
    by_case = {c["source_case_index"]: c for c in certificates}
    for index in (1, 4, 6, 10, 16, 20, 22):
        certificate = by_case[index]
        if certificate["direction"] == IP_TO_CPU_TO_IP:
            assert certificate["status"] == "incomplete"
            assert certificate["missing_hops"][0] == CPU_IRQ_SERIAL_HOP
        else:
            assert certificate["status"] == "certified"
            assert certificate["missing_hops"] == []


def test_real_saved_trace_fuses_independently_recomputed_serial_tokens():
    if not (RUN / "online_final_trace.json").is_file():
        pytest.skip(f"saved serial trace is not available: {RUN}")
    chain = ChainCertificates()
    serial = IrqSerialCertificates()
    chains = []
    tokens = []
    peak = 0
    for event in TraceEventStream(RUN).events():
        chains.extend(chain.ingest((event,)))
        tokens.extend(serial.ingest((event,)))
        peak = max(peak, chain.pending_count)
    chains.extend(chain.flush())
    assert peak <= chain.max_pending
    assert chain.serial_witness_count == 0
    # One certificate per fuzz_source admission, exactly as before the fusion.
    assert len(chains) == 24
    assert len(tokens) == 5
    assert [token["decision_serial"] for token in tokens] == [1, 2, 3, 4, 5]
    assert all(token["schema_version"] == SERIAL_CERTIFICATE_SCHEMA
               and token["status"] == "certified" for token in tokens)

    witnessed = [c for c in chains
                 if c["serial_token_status"] == SERIAL_TOKEN_WITNESSED]
    assert len(witnessed) == len(tokens)
    by_step = {token["decision_producer_event_id"]: token for token in tokens}
    assert len(by_step) == len(tokens)
    for certificate in witnessed:
        assert certificate["status"] == "certified"
        assert certificate["direction"] == IP_TO_CPU_TO_IP
        assert certificate["serial_token_reason"] is None
        assert [hop["hop_id"] for hop in certificate["hops"]] == list(IP_HOPS_SERIAL)
        serial_hop = _hop(certificate, CPU_IRQ_SERIAL_HOP)
        take = _hop(certificate, "cpu_irq_taken")
        token = by_step[take["evidence"]["step_event_id"]]
        assert serial_hop["event_id"] == token["retirement_event_id"]
        for name in ("decision_serial", "retirement_serial", "decision_event_id",
                     "decision_producer_event_id", "retirement_event_id",
                     "take_identity", "take_identity_event_id",
                     "take_identity_schema_version", "execution_id", "reset_epoch",
                     "component", "event_gap", "scope", "proof_scope",
                     "irq_serial_observation_schema", "zero_semantics"):
            assert serial_hop["evidence"][name] == token[name], name
        assert serial_hop["evidence"]["decision_serial"] == \
            serial_hop["evidence"]["retirement_serial"]
        _partition(certificate, IP_HOPS_SERIAL, IP_HOPS_SERIAL)

    certified = [c for c in chains if c["status"] == "certified"]
    incomplete = [c for c in chains if c["status"] == "incomplete"]
    assert len(certified) == 8
    assert len(incomplete) == 16
    assert [c["direction"] for c in certified].count(IP_TO_CPU_TO_IP) == 5
    assert [c["direction"] for c in certified].count(CPU_TO_IP_TO_CPU) == 3
    assert len(witnessed) == 5
