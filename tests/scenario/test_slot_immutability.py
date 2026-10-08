"""Slot immutability evidence over saved traces: synthetic and real artifacts.

Software only: no RTL is compiled, rendered into a process or started.  The
synthetic traces below are hand-written event records with the shipped record
shapes, so each verdict (immutable, violated, insufficient_evidence) is pinned
against an exact reason and event id.  The last tests re-read two existing real
run directories read-only and pin their per-slot statistics.
"""

from __future__ import annotations

import json

import pytest

from myfuzz.scenario.slot_immutability import (
    ARGUMENT_ERROR_EXIT_CODE, EXIT_CODES, SLOT_IMMUTABILITY_SCHEMA_VERSION,
    SlotImmutabilityError, analyze_events, load_events, main,
    program_range_from_run, report_for_run)


RESERVATION = (0x1000, 0x1020)
RUN_P3 = "runs/p3-lane-selectivity2-20261007-online"
RUN_P4 = "runs/p4-shift-fuzz-20261007-online"
REAL_PINS = {
    RUN_P3: {"slot_count": 1716, "immutable": 1716, "violated": 0,
             "insufficient_evidence": 0, "read_evidence_event_count": 1714,
             "materializations_by_kind": {"instruction_source": 117,
                                          "initial_image": 5},
             "reads_by_kind": {"instr_response": 828, "memory_read": 886},
             "reservation_slots": 1480, "event_count": 168917,
             "unobserved_program_bytes": 124984},
    RUN_P4: {"slot_count": 1296, "immutable": 1296, "violated": 0,
             "insufficient_evidence": 0, "read_evidence_event_count": 1420,
             "materializations_by_kind": {"instruction_source": 83,
                                          "initial_image": 5},
             "reads_by_kind": {"instr_response": 686, "memory_read": 734},
             "reservation_slots": 1060, "event_count": 118963,
             "unobserved_program_bytes": 125404},
}


# --------------------------------------------------------------------------
# Record builders (shipped shapes only)
# --------------------------------------------------------------------------

def program_instruction(event_id, address, data, *, case_id=None, memory_id=None):
    event = {"event_id": event_id, "kind": "instruction_source",
             "component": "cpu", "address": address,
             "data_hex": data.hex(), "generation": 0}
    if memory_id is not None:
        event["memory_id"] = memory_id
    if case_id is not None:
        event["provenance"] = {"observed_case": {"case_id": case_id}}
    return event


def image(event_id, address, data, image_id="cpu.stream.image"):
    return {"event_id": event_id, "kind": "initial_image", "component": "cpu",
            "address": address, "data_hex": data.hex(), "image_id": image_id}


def read(event_id, address, data, memory_id="ram"):
    return {"event_id": event_id, "kind": "memory_read", "component": "cpu",
            "memory_id": memory_id, "address": address,
            "byte_offset": address - 0x10000,
            "data_hex": data.hex(), "value": int.from_bytes(data, "little"),
            "width_bytes": len(data), "versions": [], "writer_event_ids": [],
            "writer_kinds": []}


def write(event_id, address, value, *, width_bytes=4, byte_enable=0xF,
          producer_event_id=None, memory_id="ram"):
    return {"event_id": event_id, "kind": "memory_write", "component": "cpu",
            "memory_id": memory_id, "address": address,
            "byte_offset": address - 0x10000, "value": value,
            "width_bytes": width_bytes, "byte_enable": byte_enable,
            "generation": 0, "transaction": {},
            "producer_event_id": (event_id if producer_event_id is None
                                  else producer_event_id)}


def commit(event_id, address, value, *, width_bytes=4, byte_enable=0xF,
           producer_event_id=None, commit_status="complete",
           performed_effect=True, values=None, memory_id="ram"):
    byte_offset = address - 0x10000
    lanes = values
    if lanes is None:
        lanes = {lane: (value >> (8 * lane)) & 0xFF for lane in range(width_bytes)
                 if byte_enable >> lane & 1}
    return {"event_id": event_id, "kind": "memory_write_commit",
            "component": "cpu", "schema_version": "memory_write_commit.v1",
            "producer_event_id": (event_id if producer_event_id is None
                                  else producer_event_id),
            "commit_id": f"{event_id:064x}",
            "commit_document": {
                "schema_version": "memory_write_commit_receipt.v1",
                "commit_id": f"{event_id:064x}", "memory_id": memory_id,
                "generation": 0, "byte_offset": byte_offset,
                "width_bytes": width_bytes, "byte_enable": byte_enable,
                "version": [0, event_id], "commit_status": commit_status,
                "performed_effect": performed_effect,
                "enabled_byte_cells": [
                    {"byte_offset": byte_offset + lane, "value": cell,
                     "version": [0, event_id], "writer_kind": "STORE",
                     "writer_event_id": "transaction"}
                    for lane, cell in sorted(lanes.items())]}}


def response(event_id, address, rdata, *, be=0xF, write=False, error=False):
    return {"event_id": event_id, "kind": "instr_response", "component": "cpu",
            "address": address, "aligned_address": address & ~3,
            "rdata": rdata, "be": be, "write": write, "error": error,
            "wdata": 0, "transaction": {}, "tick": event_id}


def initialized(event_id, byte_offset, value, memory_id="ram"):
    return {"event_id": event_id, "kind": "memory_initialization",
            "component": "cpu", "memory_id": memory_id,
            "byte_offset": byte_offset, "value": value, "generation": 0}


def analyze(events, program_range=RESERVATION, **kwargs):
    return analyze_events(events, program_range=program_range, **kwargs)


_REPORT_CACHE: dict = {}


def cached_report_for_run(directory):
    """Analyze each real run once per session; parsing 169k events is real work."""
    if directory not in _REPORT_CACHE:
        _REPORT_CACHE[directory] = report_for_run(directory)
    return _REPORT_CACHE[directory]


def slot_of(report, address):
    return next(slot for slot in report.slots if slot.address == address)


# --------------------------------------------------------------------------
# Immutable: materialization plus agreeing reads
# --------------------------------------------------------------------------

def test_instruction_source_materialization_and_matching_reads_are_immutable():
    report = analyze((
        program_instruction(1, 0x1000, bytes.fromhex("13000000"), case_id="case-0"),
        read(2, 0x1000, bytes.fromhex("13000000")),
        response(3, 0x1000, 0x00000013),
        response(4, 0x1000, 0x00000013, write=True),
        response(5, 0x1000, 0xDEADBEEF, error=True),
    ))
    assert report.run_conclusion == "immutable"
    assert report.counts == {"immutable": 4, "violated": 0,
                             "insufficient_evidence": 0}
    slot = slot_of(report, 0x1000)
    assert slot.verdict == "immutable"
    assert slot.reason == "first_materialization_uncontradicted"
    assert slot.first_event_id == 1 and slot.first_kind == "instruction_source"
    assert slot.first_case_id == "case-0" and slot.value == 0x13
    assert slot.read_event_ids == [2, 3]
    summary = report.summary()
    assert summary["materializations_by_kind"] == {"instruction_source": 1}
    assert summary["reads_by_kind"] == {"memory_read": 1, "instr_response": 1}
    assert summary["read_evidence_event_count"] == 2
    assert summary["reassertion_count"] == 0
    assert summary["malformed_event_ids"] == []
    # A write response and an errored response are ignored, never read evidence.
    assert report.ignored_event_kinds["instr_response"] == 2
    assert report.unobserved_program_bytes == len(range(*RESERVATION)) - 4
    assert json.loads(json.dumps(report.document()))["run_conclusion"] == "immutable"


def test_reasserting_the_same_value_is_recorded_but_not_a_violation():
    word = bytes.fromhex("13000000")
    report = analyze((
        program_instruction(1, 0x1000, word, case_id="case-0"),
        program_instruction(2, 0x1000, word, case_id="case-1"),
    ))
    assert report.run_conclusion == "immutable"
    assert report.counts["immutable"] == 4
    assert report.reassertion_event_ids == (2, 2, 2, 2)
    assert slot_of(report, 0x1000).reassertion_event_ids == [2]
    assert slot_of(report, 0x1000).conflict_event_id is None


# --------------------------------------------------------------------------
# Violated: a later different value
# --------------------------------------------------------------------------

def test_a_later_case_submitting_a_different_value_is_violated():
    report = analyze((
        program_instruction(1, 0x1000, bytes.fromhex("13000000"), case_id="case-0"),
        program_instruction(9, 0x1000, bytes.fromhex("b7100140"), case_id="case-7"),
    ))
    assert report.run_conclusion == "violated"
    assert report.counts == {"immutable": 0, "violated": 4,
                             "insufficient_evidence": 0}
    assert report.conflicts_by_kind == {
        "later_materialization_different_value": 4,
        "later_read_different_value": 0}
    slot = slot_of(report, 0x1000)
    assert (slot.conflict_event_id, slot.conflict_kind, slot.conflict_value) == (
        9, "later_materialization_different_value", 0xB7)
    assert slot.first_event_id == 1 and slot.first_case_id == "case-0"
    assert "different value" in report.conclusion_reason
    document = report.document()
    assert document["run_conclusion"] == "violated"
    assert document["slots"]["ram@4096"]["conflicting_event_id"] == 9


def test_a_store_over_fetched_program_bytes_is_violated():
    report = analyze((
        program_instruction(1, 0x1000, bytes.fromhex("13000000")),
        write(2, 0x1000, 0x400110B7, producer_event_id=2),
        commit(3, 0x1000, 0x400110B7, producer_event_id=2),
    ))
    assert report.run_conclusion == "violated"
    assert report.counts["violated"] == 4
    assert slot_of(report, 0x1003).conflict_event_id == 2
    assert slot_of(report, 0x1003).conflict_kind == "later_materialization_different_value"


def test_a_later_read_of_a_different_value_is_violated():
    report = analyze((
        program_instruction(1, 0x1000, bytes.fromhex("13000000")),
        read(4, 0x1000, bytes.fromhex("b7100140")),
    ))
    assert report.run_conclusion == "violated"
    assert report.conflicts_by_kind["later_read_different_value"] == 4
    slot = slot_of(report, 0x1002)
    assert slot.conflict_event_id == 4
    assert slot.conflict_value == 0x01
    assert slot.read_event_ids == [4]


def test_a_store_may_not_change_lanes_it_did_not_enable():
    """Only enabled lanes are materialized, so a later write of another value
    to a *disabled* lane is that lane's first materialization, not a conflict."""
    report = analyze((
        write(1, 0x1000, 0x0000B7FF, width_bytes=2, byte_enable=0b11,
              producer_event_id=1),
        commit(2, 0x1000, 0x0000B7FF, width_bytes=2, byte_enable=0b11,
               producer_event_id=1),
        write(3, 0x1002, 0x40000013, producer_event_id=3),
        commit(4, 0x1002, 0x40000013, producer_event_id=3),
    ))
    assert report.run_conclusion == "immutable"
    assert report.counts["immutable"] == 6
    assert slot_of(report, 0x1000).value == 0xFF
    assert slot_of(report, 0x1001).value == 0xB7
    assert slot_of(report, 0x1002).first_event_id == 3
    assert slot_of(report, 0x1002).first_kind == "memory_write"
    assert slot_of(report, 0x1002).value == 0x13


# --------------------------------------------------------------------------
# Insufficient evidence: never a pass
# --------------------------------------------------------------------------

def test_memory_initialization_materializes_a_program_byte():
    report = analyze((initialized(1, 0x100, 0x13),
                      read(2, 0x10100, bytes((0x13,)))),
                     program_range=(0x10100, 0x10101))
    assert report.run_conclusion == "immutable"
    slot = slot_of(report, 0x10100)
    assert (slot.first_kind, slot.first_event_id, slot.value) == (
        "memory_initialization", 1, 0x13)
    assert slot.read_event_ids == [2]
    # Without an event that states the memory's base, the byte offset cannot be
    # turned into a program address: the record is malformed, never a pass.
    thin = analyze((initialized(1, 0x100, 0x13),),
                   program_range=(0x10100, 0x10101))
    assert thin.malformed_event_ids == (1,)
    assert thin.run_conclusion == "insufficient_evidence"


def test_a_read_before_materialization_is_insufficient_not_immutable():
    word = bytes.fromhex("13000000")
    report = analyze((
        read(1, 0x1000, word),
        program_instruction(2, 0x1000, word),
        read(3, 0x1000, word),
    ))
    assert report.run_conclusion == "insufficient_evidence"
    assert report.counts == {"immutable": 0, "violated": 0,
                             "insufficient_evidence": 4}
    assert report.insufficient_by_reason == {"read_before_materialization": 4}
    slot = slot_of(report, 0x1000)
    assert slot.early_read_event_id == 1
    assert slot.first_event_id == 2
    assert slot.read_event_ids == [3]
    assert slot.verdict == "insufficient_evidence"
    assert "not claimed immutable" in report.conclusion_reason


def test_a_read_without_any_materialization_is_insufficient():
    report = analyze((read(1, 0x1000, bytes.fromhex("13000000")),))
    assert report.run_conclusion == "insufficient_evidence"
    # The read states a value no write, fetch supply or image ever determined.
    assert report.insufficient_by_reason == {"read_before_materialization": 4}
    assert slot_of(report, 0x1000).first_event_id is None
    assert slot_of(report, 0x1000).value is None
    assert slot_of(report, 0x1000).early_read_event_id == 1
    assert slot_of(report, 0x1000).reason == "read_before_materialization"


def test_a_store_without_a_complete_commit_receipt_is_not_materialized():
    report = analyze((
        write(1, 0x1000, 0x400000B7, producer_event_id=1),
        read(2, 0x1000, bytes.fromhex("b7000040")),
    ))
    assert report.run_conclusion == "insufficient_evidence"
    assert report.insufficient_by_reason == {"store_without_commit_receipt": 4}
    assert report.summary()["materializations_by_kind"] == {}
    assert slot_of(report, 0x1000).first_event_id is None


def test_a_store_whose_commit_did_not_take_effect_is_not_materialized():
    report = analyze((
        write(1, 0x1000, 0x400000B7, producer_event_id=1),
        commit(2, 0x1000, 0x400000B7, producer_event_id=1,
               performed_effect=False),
    ))
    assert report.run_conclusion == "insufficient_evidence"
    assert report.insufficient_by_reason == {"store_not_committed": 4}


def test_a_commit_receipt_that_disagrees_with_its_write_is_not_materialized():
    report = analyze((
        write(1, 0x1000, 0x400000B7, producer_event_id=1),
        commit(2, 0x1000, 0x400000B7, producer_event_id=1,
               values={0: 0x00, 1: 0x00, 2: 0x00, 3: 0x00}),
    ))
    assert report.run_conclusion == "insufficient_evidence"
    assert report.insufficient_by_reason == {
        "store_commit_disagrees_with_write": 4}


def test_unread_instruction_bytes_of_a_program_are_still_materialized():
    report = analyze((program_instruction(1, 0x1000, bytes.fromhex("13000000")),))
    assert report.run_conclusion == "immutable"
    assert report.summary()["read_evidence_event_count"] == 0
    assert report.counts["immutable"] == 4


def test_no_evidence_at_all_is_insufficient_not_a_pass():
    report = analyze(({"event_id": 1, "kind": "cpu_retire"},))
    assert report.run_conclusion == "insufficient_evidence"
    assert report.summary()["slot_count"] == 0
    assert "no slot can be judged" in report.conclusion_reason


# --------------------------------------------------------------------------
# Fail-closed scope and record handling
# --------------------------------------------------------------------------

def test_a_malformed_record_is_reported_and_never_materializes():
    report = analyze((
        {"event_id": 1, "kind": "memory_write", "component": "cpu",
         "memory_id": "ram", "value": 1, "width_bytes": 4, "byte_enable": 15},
        {"event_id": 2, "kind": "instruction_source", "component": "cpu",
         "address": 0x1000, "data_hex": "not-hex"},
    ))
    assert report.malformed_event_ids == (1, 2)
    assert report.run_conclusion == "insufficient_evidence"
    assert report.summary()["slot_count"] == 0


def test_a_missing_program_range_refuses_instead_of_guessing(tmp_path):
    with pytest.raises(SlotImmutabilityError):
        program_range_from_run(tmp_path)
    (tmp_path / "online_events.jsonl").write_text("", encoding="utf-8")
    with pytest.raises(SlotImmutabilityError):
        report_for_run(tmp_path)
    with pytest.raises(SlotImmutabilityError):
        analyze_events((), program_range=(0x1000, 0x1000))
    # An empty trace is legal (nothing is claimed); a malformed line is not.
    assert load_events(tmp_path / "online_events.jsonl") == ()
    (tmp_path / "online_events.jsonl").write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(SlotImmutabilityError):
        load_events(tmp_path / "online_events.jsonl")


def test_contradictory_memory_bases_refuse_the_trace():
    events = ({"event_id": 1, "kind": "memory_read", "memory_id": "ram",
               "address": 0x1000, "byte_offset": 0, "data_hex": "13000000"},
              {"event_id": 2, "kind": "memory_read", "memory_id": "ram",
               "address": 0x1000, "byte_offset": 8, "data_hex": "13000000"})
    with pytest.raises(SlotImmutabilityError):
        analyze(events)


def test_declared_initial_images_join_the_universe_and_can_be_excluded():
    events = (image(1, 0x0800, bytes.fromhex("13000000")),
              read(2, 0x0800, bytes.fromhex("13000000")))
    included = analyze(events)
    assert included.run_conclusion == "immutable"
    assert included.summary()["slot_count"] == 4
    assert included.region_slot_counts()["initial_image:cpu.stream.image"] == 4
    excluded = analyze(events, include_initial_images=False)
    assert excluded.summary()["slot_count"] == 0
    assert excluded.run_conclusion == "insufficient_evidence"


def test_the_declared_reservation_is_read_from_the_run_manifest(tmp_path):
    (tmp_path / "decoder_manifest.json").write_text(json.dumps(
        {"instruction_start": 0x1000, "instruction_end": 0x1010}),
        encoding="utf-8")
    assert program_range_from_run(tmp_path) == (
        (0x1000, 0x1010),
        "decoder_manifest.json:instruction_start..instruction_end")


# --------------------------------------------------------------------------
# The command line gate
# --------------------------------------------------------------------------

def _run_directory(tmp_path, events):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "decoder_manifest.json").write_text(json.dumps(
        {"instruction_start": RESERVATION[0], "instruction_end": RESERVATION[1]}),
        encoding="utf-8")
    with open(tmp_path / "online_events.jsonl", "w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    return tmp_path


def test_cli_gate_exit_codes_follow_the_recorded_verdict(tmp_path):
    word = bytes.fromhex("13000000")
    immutable = _run_directory(tmp_path / "ok", (
        program_instruction(1, 0x1000, word), read(2, 0x1000, word)))
    violated = _run_directory(tmp_path / "bad", (
        program_instruction(1, 0x1000, word),
        program_instruction(2, 0x1000, bytes.fromhex("b7000040"))))
    thin = _run_directory(tmp_path / "thin", ({"event_id": 1, "kind": "noise"},))
    assert main([str(immutable)]) == EXIT_CODES["immutable"] == 0
    assert main([str(violated)]) == EXIT_CODES["violated"] == 1
    assert main([str(thin)]) == EXIT_CODES["insufficient_evidence"] == 2
    assert main([str(thin), str(violated)]) == 1
    assert main([str(tmp_path / "absent")]) == ARGUMENT_ERROR_EXIT_CODE


def test_cli_writes_the_versioned_report(tmp_path, capsys):
    word = bytes.fromhex("13000000")
    directory = _run_directory(tmp_path / "ok", (
        program_instruction(1, 0x1000, word, case_id="case-0"),
        read(2, 0x1000, word)))
    out = tmp_path / "report.json"
    assert main([str(directory), "--json-out", str(out)]) == 0
    line = capsys.readouterr().out.strip()
    assert line.startswith(f"{SLOT_IMMUTABILITY_SCHEMA_VERSION} {directory}: "
                           "conclusion=immutable slots=4")
    assert "scope: this run only" in line
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == SLOT_IMMUTABILITY_SCHEMA_VERSION
    assert document["run_conclusion"] == "immutable"
    assert document["proof_scope"]["rtl_executed_by_checker"] is False
    assert document["proof_scope"]["covers"] == (
        "the online event trace of this run only")
    assert document["slots"]["ram@4096"]["first_materialization_case_id"] == "case-0"


# --------------------------------------------------------------------------
# Real saved artifacts, read-only
# --------------------------------------------------------------------------

@pytest.mark.parametrize("run", [RUN_P3, RUN_P4])
def test_real_run_program_slots_are_immutable(run):
    pinned = REAL_PINS[run]
    report = cached_report_for_run(run)
    summary = report.summary()
    assert report.event_count == pinned["event_count"]
    assert summary["slot_count"] == pinned["slot_count"]
    assert summary["immutable"] == pinned["immutable"]
    assert summary["violated"] == pinned["violated"] == 0
    assert summary["insufficient_evidence"] == pinned["insufficient_evidence"] == 0
    assert summary["read_evidence_event_count"] == pinned["read_evidence_event_count"]
    assert summary["materializations_by_kind"] == pinned["materializations_by_kind"]
    assert summary["reads_by_kind"] == pinned["reads_by_kind"]
    assert summary["conflicts_by_kind"] == {
        "later_materialization_different_value": 0,
        "later_read_different_value": 0}
    assert summary["insufficient_by_reason"] == {}
    assert summary["malformed_event_ids"] == []
    assert summary["reassertion_count"] == 0
    assert summary["region_slots"][
        "declared.online_instruction_reservation"] == pinned["reservation_slots"]
    assert report.run_conclusion == "immutable"
    assert report.unobserved_program_bytes == pinned["unobserved_program_bytes"]
    line = report.gate_line()
    assert "conclusion=immutable" in line
    assert "scope: this run only" in line
    assert str(pinned["unobserved_program_bytes"]) in line
    # No store materialized a program byte in either run: the Store branch of
    # the checker is exercised by the synthetic tests above, not by this run.
    assert "memory_write" not in summary["materializations_by_kind"]


def test_real_run_p3_slot_evidence_is_pinned_to_events():
    report = cached_report_for_run(RUN_P3)
    first = next(slot for slot in report.slots if slot.address == 69632)
    assert (first.first_event_id, first.first_kind, first.value) == (
        2155, "instruction_source", 0x13)
    assert first.first_case_id == "online-0-af5570f5a1810b7af78caf4b"
    assert first.region_id == "declared.online_instruction_reservation"
    assert first.read_event_ids == [2156, 2165]
    assert first.verdict == "immutable"
    bootstrap = next(slot for slot in report.slots if slot.address == 65664)
    assert (bootstrap.first_event_id, bootstrap.first_kind) == (
        1, "initial_image")
    assert bootstrap.region_id == "initial_image:cpu.stream.bootstrap"
    # Every program byte with a materialization event is judged; none is left
    # without evidence in this run.
    assert all(slot.first_event_id is not None for slot in report.slots)
    assert all(slot.verdict == "immutable" for slot in report.slots)


def test_real_run_gate_refuses_a_run_without_a_declared_range(tmp_path):
    assert main([str(tmp_path)]) == ARGUMENT_ERROR_EXIT_CODE
