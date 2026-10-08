"""Closed-loop feedback consumed from certified runtime chain certificates.

Every certificate used here is produced by the frozen ``ChainCertificates``
producer over a synthetic contiguous journal; the journal builders are imported
from :mod:`tests.scenario.test_chain_certificates` so the hop identities stay a
single source of truth. Nothing below infers causality from adjacency:

* ``certified`` -> exactly one ``closed_loop`` hit,
* ``incomplete`` with a proven downstream consumer -> ``partial_propagation``,
* ``incomplete`` with only source-side stages -> ``stage_reached``.

Counts and hit identities must be recomputable: the same journal fed to two
fresh producer/consumer pairs yields the same canonical summary bytes.
"""

from copy import deepcopy
import hashlib
import json

import pytest

from myfuzz.scenario.chain_certificates import (
    CPU_IRQ_SERIAL_HOP,
    CPU_TO_IP_TO_CPU,
    IP_TO_CPU_TO_IP,
    SCHEMA_VERSION as CERTIFICATE_SCHEMA_VERSION,
    SERIAL_TOKEN_ABSENT,
    SERIAL_TOKEN_WITNESSED,
    declared_hop_sequence,
)
from myfuzz.scenario.closed_loop_feedback import (
    CERTIFIED,
    CLOSED_LOOP,
    FEEDBACK_SCHEMA_VERSION,
    INCOMPLETE,
    PARTIAL_PROPAGATION,
    STAGE_REACHED,
    ClosedLoopFeedback,
    EnergyGains,
    certificate_hit,
    edge_feature,
    energy_weights,
    failure_feature,
    hit_feature,
    target_feature,
    transition_feature,
)
from myfuzz.scenario.dependency import (
    DependencyGraph,
    DependencyRule,
    FuzzableSource,
)
from myfuzz.scenario.mutation import choose_mutation
from tests.scenario.test_chain_certificates import (
    _certificates,
    _cpu_admission,
    _cpu_journal,
    _ip_journal,
    _merge,
    _pin8_admission,
    _provenance,
)
from tests.scenario.test_chain_certificate_serial_token import _serial_ip_journal


IP_TERMINAL_HOP = "isr_padin_retirement"
CPU_TERMINAL_HOP = "retired_target_delivery"
DIRECTION = IP_TO_CPU_TO_IP


def _produced(journal, **kwargs):
    certificates, consumer = _certificates(journal, **kwargs)
    assert consumer.pending_count == 0
    return certificates


def _certified_ip_certificate():
    certificates = _produced(_ip_journal())
    assert len(certificates) == 1
    assert certificates[0]["status"] == CERTIFIED
    return certificates[0]


def _witnessed_serial_certificate():
    certificates = _produced(_serial_ip_journal())
    assert len(certificates) == 1
    assert certificates[0]["status"] == CERTIFIED
    assert certificates[0]["serial_token_status"] == SERIAL_TOKEN_WITNESSED
    return certificates[0]


def _hit_pairs(hit):
    return [(hop["hop_id"], hop["event_id"]) for hop in hit["hops"]]


def _expected_hit_id(kind, direction, admission_id, hops):
    """Independent copy of the documented hit identity formula."""
    payload = json.dumps(
        [FEEDBACK_SCHEMA_VERSION, kind, direction, admission_id,
         [[hop["hop_id"], hop["event_id"]] for hop in hops]],
        separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _consume(certificates):
    feedback = ClosedLoopFeedback()
    recorded = feedback.ingest(certificates)
    return feedback, recorded


# --------------------------------------------------------------------- hits


def test_certified_ip_chain_yields_exactly_one_closed_loop_hit():
    journal = _ip_journal()
    certificates = _produced(journal)
    feedback, recorded = _consume(certificates)

    assert len(recorded) == 1
    hit = recorded[0]
    assert hit["kind"] == CLOSED_LOOP
    assert hit["schema_version"] == FEEDBACK_SCHEMA_VERSION
    assert hit["status"] == CERTIFIED
    assert hit["direction"] == IP_TO_CPU_TO_IP
    assert hit["source_admission_id"] == _pin8_admission().admission_id
    assert hit["source_action_id"] == _pin8_admission().action_id
    assert hit["source_id"] == "gpio_b.external_pin8"
    assert hit["source_component"] == "gpio_b"
    assert hit["certificate_id"] == certificates[0]["certificate_id"]

    # Ordered hop identity: hop_id plus its real delivery/consumption event.
    terminal = certificates[0]["hops"][-1]
    assert _hit_pairs(hit) == [(hop["hop_id"], hop["event_id"])
                               for hop in certificates[0]["hops"]]
    assert hit["hop_count"] == len(certificates[0]["hops"])
    assert hit["terminal_hop"] == {"hop_id": terminal["hop_id"],
                                   "event_id": terminal["event_id"]}
    assert hit["declared_terminal_hop"] == IP_TERMINAL_HOP
    assert hit["reached_terminal_hop"] is True
    assert hit["missing_hops"] == []
    assert hit["first_missing_hop"] is None
    assert hit["cross_case"] is False
    assert hit["source_case_id"] == "case-1"
    assert hit["endpoint_case_id"] == "case-1"
    # A different component served the ISR leg, so consumption is proven.
    assert hit["downstream_components"] == ["cpu"]
    assert hit["serial_token_status"] == SERIAL_TOKEN_ABSENT
    assert hit["hit_id"] == _expected_hit_id(
        CLOSED_LOOP, IP_TO_CPU_TO_IP, hit["source_admission_id"], hit["hops"])
    assert len(hit["hit_id"]) == 64

    summary = feedback.summary()
    assert summary["certificate_schema_version"] == CERTIFICATE_SCHEMA_VERSION
    assert summary["certificate_count"] == 1
    assert summary["closed_loop_count"] == 1
    assert summary["partial_propagation_count"] == 0
    assert summary["stage_reached_count"] == 0
    assert summary["closed_loops"] == [hit]
    assert summary["partial_propagation"] == []
    assert summary["stage_reached"] == []
    assert summary["feature_counts"] == {
        f"closed_loop:{IP_TO_CPU_TO_IP}:gpio_b.external_pin8": 1}
    assert hit_feature(hit) == \
        f"closed_loop:{IP_TO_CPU_TO_IP}:gpio_b.external_pin8"


def test_certified_cpu_chain_yields_one_closed_loop_hit():
    journal = _cpu_journal()
    certificates = _produced(journal)
    feedback, recorded = _consume(certificates)

    assert len(recorded) == 1
    hit = recorded[0]
    assert hit["kind"] == CLOSED_LOOP
    assert hit["direction"] == CPU_TO_IP_TO_CPU
    assert hit["source_admission_id"] == _cpu_admission().admission_id
    assert hit["source_id"] == "cpu.online_instruction"
    assert hit["source_component"] == "cpu"
    assert hit["declared_terminal_hop"] == CPU_TERMINAL_HOP
    assert hit["reached_terminal_hop"] is True
    assert hit["downstream_components"] == ["gpio_a"]
    assert feedback.summary()["closed_loop_count"] == 1


def test_missing_terminal_hop_is_partial_propagation_not_a_closed_loop():
    journal = _ip_journal().without(IP_TERMINAL_HOP)
    certificates = _produced(journal)
    assert certificates[0]["status"] == INCOMPLETE
    feedback, recorded = _consume(certificates)

    assert len(recorded) == 1
    hit = recorded[0]
    assert hit["kind"] == PARTIAL_PROPAGATION
    assert hit["status"] == INCOMPLETE
    assert hit["reached_terminal_hop"] is False
    assert hit["declared_terminal_hop"] == IP_TERMINAL_HOP
    assert hit["terminal_hop"]["hop_id"] == "isr_padin_data_response"
    assert hit["missing_hops"] == [IP_TERMINAL_HOP]
    assert hit["first_missing_hop"] == IP_TERMINAL_HOP
    assert hit["downstream_components"] == ["cpu"]
    assert hit["hit_id"] == _expected_hit_id(
        PARTIAL_PROPAGATION, IP_TO_CPU_TO_IP, hit["source_admission_id"],
        hit["hops"])

    summary = feedback.summary()
    assert summary["closed_loop_count"] == 0
    assert summary["partial_propagation_count"] == 1
    assert summary["stage_reached_count"] == 0
    assert summary["closed_loops"] == []
    assert summary["partial_propagation"] == [hit]


def test_upstream_only_chain_is_stage_reached_not_partial():
    # Without the CPU interrupt input event the native gpio_b stages are all a
    # chain can ever prove, so the admission must not be promoted.
    journal = _ip_journal().without("cpu_irq_input")
    certificates = _produced(journal)
    assert certificates[0]["status"] == INCOMPLETE
    stage_hops = declared_hop_sequence(IP_TO_CPU_TO_IP)[:8]
    assert [hop["hop_id"] for hop in certificates[0]["hops"]] == list(stage_hops)
    feedback, recorded = _consume(certificates)

    hit = recorded[0]
    assert hit["kind"] == STAGE_REACHED
    assert hit["propagated"] is False
    assert hit["downstream_components"] == []
    assert hit["stage_boundary_hop"] == "cpu_irq_input"
    assert hit["reached_terminal_hop"] is False
    assert hit["missing_hops"][0] == "cpu_irq_input"
    assert feedback.summary()["closed_loop_count"] == 0
    assert feedback.summary()["partial_propagation_count"] == 0
    assert feedback.summary()["stage_reached_count"] == 1


def test_cross_case_certificate_is_marked_cross_case():
    journal = _ip_journal()
    # The admitted case is 1; the terminal retirement is observed in case 2.
    journal.mutate("isr_padin_retirement",
                   provenance=_provenance(2, case_id="case-2"))
    certificates = _produced(journal)
    feedback, recorded = _consume(certificates)

    assert certificates[0]["status"] == CERTIFIED
    assert len(recorded) == 1
    hit = recorded[0]
    assert hit["kind"] == CLOSED_LOOP
    assert hit["cross_case"] is True
    assert hit["source_case_id"] == "case-1"
    assert hit["source_case_index"] == 1
    assert hit["endpoint_case_id"] == "case-2"
    assert hit["endpoint_case_index"] == 2
    assert hit["source_admission_id"] == _pin8_admission().admission_id


def test_repeated_certificates_do_not_double_count():
    certificates = _produced(_ip_journal())
    # A cumulative prefix replay re-derives the identical certificate.
    replay = _produced(_ip_journal())
    assert _canonical(certificates) == _canonical(replay)

    feedback, first = _consume(certificates)
    assert len(first) == 1
    assert feedback.ingest(certificates) == ()
    assert feedback.ingest(replay) == ()
    summary = feedback.summary()
    assert summary["certificate_count"] == 1
    assert summary["closed_loop_count"] == 1
    assert summary["feature_counts"] == {
        f"closed_loop:{IP_TO_CPU_TO_IP}:gpio_b.external_pin8": 1}


def test_duplicate_certificate_id_with_different_evidence_is_refused():
    certificate = _certified_ip_certificate()
    forged = deepcopy(certificate)
    forged["hops"].pop()
    feedback = ClosedLoopFeedback()
    feedback.ingest([certificate])
    with pytest.raises(ValueError, match="reused"):
        feedback.ingest([forged])
    assert feedback.summary()["closed_loop_count"] == 1


def test_two_runs_agree_on_counts_and_hit_identities():
    def run():
        journal = _merge(_ip_journal(tag="ip-"), _cpu_journal(tag="cpu-"))
        certificates = _produced(journal)
        feedback, _ = _consume(certificates)
        return feedback.summary()

    first, second = run(), run()
    assert _canonical(first) == _canonical(second)
    assert first["closed_loop_count"] == 2
    assert sorted(hit["hit_id"] for hit in first["closed_loops"]) == \
        sorted(hit["hit_id"] for hit in second["closed_loops"])
    assert len({hit["hit_id"] for hit in first["closed_loops"]}) == 2


def test_incremental_summary_reports_only_new_hits():
    certificates = _produced(_ip_journal())
    feedback = ClosedLoopFeedback()
    feedback.ingest(certificates)
    first = feedback.incremental_summary()
    second = feedback.incremental_summary()
    assert len(first["closed_loops"]) == 1
    assert first["closed_loops"] == first["delta_closed_loops"]
    assert second["closed_loops"] == []
    assert second["closed_loop_count"] == 1


def test_ingest_does_not_mutate_the_certificate():
    certificate = _certified_ip_certificate()
    before = deepcopy(certificate)
    ClosedLoopFeedback().ingest([certificate])
    assert certificate == before


# ------------------------------------------------------- fail-closed inputs


def test_malformed_certificates_are_refused_not_counted():
    certificate = _certified_ip_certificate()

    def tampered(**changes):
        forged = deepcopy(certificate)
        forged.update(changes)
        return forged

    forged_hop = deepcopy(certificate)
    forged_hop["hops"][3]["hop_id"] = "isr_padin_retirement_forged"
    cross_direction = deepcopy(certificate)
    cross_direction["hops"][3]["hop_id"] = CPU_TERMINAL_HOP
    string_event = deepcopy(certificate)
    string_event["hops"][3]["event_id"] = str(string_event["hops"][3]["event_id"])
    duplicate_hop = deepcopy(certificate)
    duplicate_hop["hops"][4]["hop_id"] = duplicate_hop["hops"][3]["hop_id"]
    reordered = deepcopy(certificate)
    reordered["hops"][2], reordered["hops"][3] = \
        reordered["hops"][3], reordered["hops"][2]
    nonmonotonic = deepcopy(certificate)
    nonmonotonic["hops"][2]["event_id"] = nonmonotonic["hops"][5]["event_id"] + 1
    early_missing = deepcopy(certificate)
    early_missing["missing_hops"] = ["cpu_irq_input"]
    # A witnessed serial hop whose certificate claims no witness is refused.
    serial_without_witness = deepcopy(_witnessed_serial_certificate())
    serial_without_witness["serial_token_status"] = SERIAL_TOKEN_ABSENT
    missing_hop_entry = deepcopy(certificate)
    missing_hop_entry["hops"][2].pop("evidence")
    empty_hops = deepcopy(certificate)
    empty_hops["hops"] = []

    malformed = [
        ("schema_version", tampered(schema_version="runtime_chain_certificate.v2")),
        ("status", tampered(status="maybe")),
        ("direction", tampered(direction="SIDEWAYS")),
        ("certificate_id", tampered(certificate_id="0" * 64)),
        ("source_admission_id", tampered(source_admission_id="forged")),
        ("hop_id", forged_hop),
        ("hop_id", cross_direction),
        ("event_id", string_event),
        ("hop_id", duplicate_hop),
        ("hop_id", reordered),
        ("event_id", nonmonotonic),
        ("missing_hops", early_missing),
        ("serial_token_status", serial_without_witness),
        ("hop_id", missing_hop_entry),
        ("hops", empty_hops),
        ("missing_hops", tampered(status=CERTIFIED, missing_hops=[IP_TERMINAL_HOP])),
        ("certificate", "not-a-mapping"),
    ]
    for pattern, forged in malformed:
        with pytest.raises(ValueError, match=pattern):
            certificate_hit(forged)

    # A refused certificate leaves the consumer's counts untouched.
    feedback = ClosedLoopFeedback()
    before = feedback.summary()
    for pattern, forged in malformed:
        with pytest.raises(ValueError, match=pattern):
            feedback.ingest([forged])
    assert feedback.summary() == before
    assert feedback.summary()["certificate_count"] == 0


def test_certificate_hit_accepts_a_witnessed_serial_hop():
    certificate = _witnessed_serial_certificate()
    feedback, recorded = _consume([certificate])
    hit, = recorded
    assert hit["kind"] == CLOSED_LOOP
    assert hit["serial_token_status"] == SERIAL_TOKEN_WITNESSED
    assert hit["reached_terminal_hop"] is True
    assert [hop["hop_id"] for hop in hit["hops"]] == [
        hop["hop_id"] for hop in certificate["hops"]]
    assert hit["hops"][10]["hop_id"] == CPU_IRQ_SERIAL_HOP
    assert feedback.summary()["closed_loop_count"] == 1


# ----------------------------------------------------------- energy weights


def _base_weights():
    return {"gpio_b.external_pin8": 10, "cpu.online_instruction": 10}


def test_energy_weights_without_feedback_reproduces_the_baseline():
    base = _base_weights()
    result = energy_weights(base)
    assert result == base
    assert result is not base
    assert energy_weights(base, closed_loops=(), partial_propagation=(),
                          stage_reached=(), new_edges=(),
                          new_state_transitions=(), new_targets=(),
                          failures=()) == base
    result["gpio_b.external_pin8"] = 0
    assert base["gpio_b.external_pin8"] == 10


def test_closed_loop_feedback_changes_source_and_path_weights():
    certificates = _produced(_ip_journal())
    feedback, _ = _consume(certificates)
    hit, = feedback.summary()["closed_loops"]
    feature = hit_feature(hit)
    assert feature == f"closed_loop:{IP_TO_CPU_TO_IP}:gpio_b.external_pin8"

    base = _base_weights()
    default = energy_weights(base, closed_loops=[hit])
    assert default["gpio_b.external_pin8"] == \
        base["gpio_b.external_pin8"] + EnergyGains().closed_loop
    assert default["cpu.online_instruction"] == base["cpu.online_instruction"]

    attributed = energy_weights(
        base, closed_loops=[hit],
        attribution={feature: ["gpio_b.external_pin8", "F5:pin8-path"]})
    assert attributed["gpio_b.external_pin8"] == \
        base["gpio_b.external_pin8"] + EnergyGains().closed_loop
    assert attributed["F5:pin8-path"] == EnergyGains().closed_loop
    assert attributed["cpu.online_instruction"] == base["cpu.online_instruction"]


def test_edges_transitions_targets_and_failures_change_weights():
    base = _base_weights()
    edge = {"kind": "bound_input_consumed", "source": "gpio_a", "target": "gpio_b"}
    gains = EnergyGains()
    weights = energy_weights(
        base,
        new_edges=[edge],
        new_state_transitions=["memory:RAW:ram0"],
        new_targets=["F5-pin8-irq"],
        failures=["dut_violation"],
        attribution={
            edge_feature(edge): ["gpio_b.external_pin8"],
            transition_feature("memory:RAW:ram0"): ["cpu.online_instruction"],
            target_feature("F5-pin8-irq"): ["cpu.online_instruction"],
            failure_feature("dut_violation"): ["cpu.online_instruction"],
        })
    assert weights["gpio_b.external_pin8"] == base["gpio_b.external_pin8"] + gains.new_edge
    assert weights["cpu.online_instruction"] == (
        base["cpu.online_instruction"] + gains.new_state_transition
        + gains.new_target - gains.failure_penalty)


def test_failure_penalty_clamps_at_the_floor():
    base = {"cpu.online_instruction": 1}
    weights = energy_weights(
        base, failures=["dut_violation"],
        attribution={failure_feature("dut_violation"): ["cpu.online_instruction"]},
        gains=EnergyGains(failure_penalty=64, floor=0))
    assert weights["cpu.online_instruction"] == 0
    floored = energy_weights(
        base, failures=["dut_violation"],
        attribution={failure_feature("dut_violation"): ["cpu.online_instruction"]},
        gains=EnergyGains(failure_penalty=64, floor=3))
    assert floored["cpu.online_instruction"] == 3


def test_energy_weights_are_order_independent_and_deduplicate():
    certificates = _produced(_ip_journal())
    feedback, _ = _consume(certificates)
    hit, = feedback.summary()["closed_loops"]
    edge = {"kind": "bound_input_consumed", "source": "gpio_a", "target": "gpio_b"}
    attribution = {
        hit_feature(hit): ["gpio_b.external_pin8"],
        edge_feature(edge): ["gpio_b.external_pin8"],
    }
    forward = energy_weights(_base_weights(), closed_loops=[hit], new_edges=[edge],
                             attribution=attribution)
    reverse = energy_weights(_base_weights(), new_edges=[edge, edge],
                             closed_loops=[hit, hit], attribution=attribution)
    assert forward == reverse
    assert forward["gpio_b.external_pin8"] == (
        10 + EnergyGains().closed_loop + EnergyGains().new_edge)


def test_energy_weights_refuses_ambiguous_or_invalid_input():
    edge = {"kind": "bound_input_consumed", "source": "gpio_a", "target": "gpio_b"}
    with pytest.raises(ValueError, match="attribution"):
        energy_weights(_base_weights(), new_edges=[edge])
    with pytest.raises(ValueError, match="attribution"):
        energy_weights(_base_weights(), new_state_transitions=["memory:RAW:ram0"])
    with pytest.raises(ValueError, match="weight"):
        energy_weights({"cpu.online_instruction": -1})
    with pytest.raises(ValueError, match="weight"):
        energy_weights({"cpu.online_instruction": True})
    with pytest.raises(ValueError, match="weight"):
        energy_weights({"": 1})
    with pytest.raises(ValueError, match="gain"):
        EnergyGains(closed_loop=-1)
    with pytest.raises(ValueError, match="gains"):
        energy_weights(_base_weights(), gains={"closed_loop": 1})
    with pytest.raises(ValueError, match="feedback item"):
        energy_weights(_base_weights(), closed_loops=[{"kind": CLOSED_LOOP}])
    with pytest.raises(ValueError, match="feedback item"):
        energy_weights(_base_weights(),
                       new_edges=[{"kind": "bound_input_consumed"}])


def test_energy_weights_drive_the_mutation_source_choice():
    graph = DependencyGraph(
        sources=(FuzzableSource("a.pin", "gpio_b", "pin", 0, 1, (DIRECTION,)),
                 FuzzableSource("b.pin", "gpio_b", "pin", 1, 1, (DIRECTION,))),
        rules=(DependencyRule("cpu.result", ("a.pin", "b.pin"), "DATA_BINDING"),))
    base = {"a.pin": 4, "b.pin": 4}
    baseline = choose_mutation(graph, {"cpu.result": 1}, direction=DIRECTION,
                               source_weights=energy_weights(base))
    assert baseline.focus_source == "a.pin"

    certificates = _produced(_ip_journal())
    feedback, _ = _consume(certificates)
    hit, = feedback.summary()["closed_loops"]
    weights = energy_weights(
        base, closed_loops=[hit],
        attribution={hit_feature(hit): ["b.pin"]})
    credited = choose_mutation(graph, {"cpu.result": 1}, direction=DIRECTION,
                               source_weights=weights)
    assert credited.focus_source == "b.pin"
    assert credited.target == "cpu.result"
