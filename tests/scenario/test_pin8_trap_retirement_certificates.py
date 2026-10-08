"""Architectural, weaker pin8 IRQ acceptance to trap retirement relation."""

import json
from functools import lru_cache
from pathlib import Path

from myfuzz.scenario.pin8_trap_retirement_certificates import Pin8TrapRetirementCertificates


TRACE = (Path(__file__).resolve().parents[2] / "runs" /
         "current-dataflow-p2-pin8-cpu-irq-identity-snapshot-20261007-online" /
         "online_final_trace.json")


@lru_cache(maxsize=1)
def _events():
    return json.loads(TRACE.read_text())["events"]


def _run(events):
    return Pin8TrapRetirementCertificates().ingest(events)


def _changed(event_id, changes):
    events = list(_events())
    events[event_id - 1] = {**events[event_id - 1], **changes}
    return events


def test_real_trace_has_five_weak_architectural_trap_relations():
    proofs = _run(_events())
    assert len(proofs) == 5
    assert {p["proof_scope"] for p in proofs} == {
        "single_pending_irq_architectural_trap_relation"}
    assert all(p["scope"] == "pin8_cpu_irq_taken_to_trap_retirement" for p in proofs)
    assert all(p["retirement_order"] == p["acceptance_order"] + 1 for p in proofs)
    assert all(p["retirement_pc_wdata"] == 0x10200 for p in proofs)
    assert [p["retirement_event_id"] for p in proofs] == [
        6726, 13818, 20855, 25658, 28264]


def test_wrong_retirement_intr_order_or_pc_rejects_first_relation():
    for changes in ({"intr": 0}, {"order": 37}, {"pc_wdata": 0x10100},
                    {"producer_event_id": 6522}):
        proofs = _run(_changed(6726, changes))
        assert len(proofs) == 4, changes
        assert all(p["retirement_event_id"] != 6726 for p in proofs)


def test_wrong_acceptance_order_or_nonphysical_retirement_rejects_first_relation():
    for event_id, changes in ((6522, {"outputs": {
            **_events()[6521]["outputs"], "rvfi_order": 34}}),
                              (6726, {"observation": None})):
        proofs = _run(_changed(event_id, changes))
        assert len(proofs) == 4


def test_intervening_retire_or_competing_irq_or_reset_rejects_first_relation():
    for kind in ("cpu_retire", "cpu_irq_taken", "cpu_reset"):
        events = _changed(6600, {"kind": kind})
        proofs = _run(events)
        assert len(proofs) == 4, kind


def test_event_gap_bound_prevents_late_trap_claim():
    proofs = Pin8TrapRetirementCertificates(max_event_gap=128).ingest(_events())
    assert proofs == ()
