"""P3 acceptance report: every plan criterion against one saved run artifact.

The fixtures are purely synthetic run directories (no RTL, no process, no
simulator).  Each one is written by hand so that every expectation below is a
value this test computes itself:

* the event journal is the real chain-certificate journal of
  ``test_chain_certificates`` (so the *real* frozen producer certifies the
  synthetic chains) merged in case order with hand-written ``memory_write`` /
  ``memory_read`` events;
* the manifest, run identity, receipts and plan are written as the real writers
  write them, and every identity (manifest sha256, writer transaction key,
  version pairs, case indexes, event ids) is recomputed in this file.

Negative cases are explicit: a removed store must stay ``null`` instead of
being reported as a pass; a store consumed inside its own case is measured but
not met; same-case chains are not cross-case; a run without a finding leaves
``finding_stops_and_replays`` ``null`` with a reason; a missing trace or
manifest leaves the gate unready.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.genome import GenomeCodec, ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.p3_acceptance import (
    EXIT_NOT_READY,
    EXIT_READY,
    SCHEMA_VERSION,
    p3_acceptance_report,
    render_markdown,
)
from tests.scenario.test_chain_certificates import (
    CPU_HOPS,
    IP_HOPS,
    _Journal,
    _cpu_journal,
    _ip_journal,
    _merge,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "run_p3_acceptance_gate.py"

MANIFEST_NAME = "online_session_manifest.json"
RUN_ID = "synthetic-p3-run"
EXECUTION_ID = "local-execution"
TESTCASE_ID = "ibex-dual-source-stream"
TEMPLATE_PATH_ID = "synthetic-path"
COMPONENTS = ("cpu", "gpio_a", "gpio_b")

#: First declared hop of each direction that can already have crossed a case
#: boundary; everything from there on is retagged to the endpoint case.
CROSS_CASE_TAIL = {"IP_TO_CPU_TO_IP": "isr_padin_mmio_acceptance",
                   "CPU_TO_IP_TO_CPU": "instruction_retirement"}

CASE_IDS = tuple(f"case-{index}" for index in range(4))

# Hand-written memory effects (case 0 store -> case 2 load).
STORE_SEQUENCE = 7
STORE_ADDRESS = 0x3000
STORE_BYTE_ENABLE = 0b0001
STORE_WIDTH_BYTES = 4
STORE_VALUE = 0xAA
STORE_VERSION = [0, 7]
STORE_READ_VALUE = 0xAA

MATERIALIZE_SEQUENCE = 11
MATERIALIZE_OFFSET = 0x3010
MATERIALIZE_VERSION = [0, 5]
MATERIALIZE_WRITER = "first-touch:ram:0:12304"
MATERIALIZE_VALUE = 0x5A

IRQ_FINDING = "gpio_b_irq_source_mismatch"


# ------------------------------------------------------------------- identities


def _transaction(sequence: int, channel: str = "data") -> TransactionKey:
    return TransactionKey(execution_id=EXECUTION_ID, testcase_id=TESTCASE_ID,
                          source_component="cpu", source_epoch=0,
                          channel_id=channel, source_sequence=sequence)


def _event_provenance(case_index: int | None) -> dict:
    case = (None if case_index is None
            else {"case_id": f"case-{case_index}", "case_index": case_index})
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": case, "origin_status": "unknown",
            "origin_admission_ids": [], "invalid_origin_references": 0,
            "unknown_writer_ids": [], "edge_candidates": [], "resource": None,
            "proof_scope": "observation_only"}


def _manifest_document() -> dict:
    sessions = {}
    for index, component in enumerate(COMPONENTS):
        sessions[component] = {
            "type": f"myfuzz.local_harness.{component}_session.SyntheticSession",
            "identity": {
                "schema_version": "generated_local_session_identity.v1",
                "source_component": component,
                "build_identity": {
                    "schema_version": "local_harness_build_identity.v1",
                    "artifact_digest": f"{index + 1:02x}" * 32,
                    "build_digest": f"{index + 11:02x}" * 32,
                    "workers": 1, "waveforms": False, "timeout_seconds": 300}}}
    return {
        "schema_version": "online_session_manifest.v1",
        "runner": {
            "schema_version": "scenario_runner_identity.v1",
            "sessions": sessions,
            "memories": {"cpu": {"initialization_algorithm": "memory-init-v1",
                                 "initialization_seed": 37,
                                 "instruction_slots": [["ram", 4096]]}},
            "bindings": [], "irq_pulses": [], "windows": {},
            "ownership": {"fields": [], "owners": []}},
        "online_source_files": [{"path": "src/myfuzz/scenario/session_runtime.py",
                                 "sha256": "e" * 64}],
        "checker": {"module": "tests.scenario.test_p3_acceptance",
                    "qualname": "synthetic_checker"},
    }


def _manifest_bytes() -> bytes:
    return (json.dumps(_manifest_document(), sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _manifest_identity(raw: bytes) -> str:
    """The frozen writer hashes the canonical document, not the trailing LF."""
    return hashlib.sha256(raw[:-1] if raw.endswith(b"\n") else raw).hexdigest()


def _template_genome() -> ScenarioGenome:
    return ScenarioGenome(testcase_id=TESTCASE_ID, direction="CPU_TO_IP_TO_CPU",
                          path_id=TEMPLATE_PATH_ID, schedule_order=("cpu",),
                          max_steps=1, actions=())


def _raw_records() -> bytes:
    """The run's declared genome as one raw byte stream (chunk-fed input)."""
    return GenomeCodec.encode(_template_genome())


#: One real-shaped RFuzz record, exactly as the live corpus stores it.  These
#: bytes are a *record* stream, not a genome document, so they can never be
#: mistaken for the normalized genome payload of the chunk check.
RAW_RECORDS = bytes(8)


# ---------------------------------------------------------------- event journal


def _rows(journal: _Journal) -> list[list]:
    return [list(row) for row in journal._rows]


def _take_rows(journal: _Journal, names) -> tuple[list[list], list[list]]:
    """Split one journal into the rows before and from its first named hop."""
    index = min(journal.index(name) for name in names)
    rows = _rows(journal)
    return rows[:index], rows[index:]


def _compose(rows: list[list]) -> _Journal:
    journal = _Journal()
    for name, event in rows:
        journal.add(name, dict(event))
    return journal


def _boot_rows() -> list[list]:
    return [
        ["boot_image", {"kind": "initial_image", "component": "cpu",
                        "image_id": "cpu.stream.bootstrap",
                        "address": 0x10000, "data_hex": "13000000",
                        "provenance": _event_provenance(None)}],
        ["boot_startup", {"kind": "cpu_native_startup", "component": "cpu",
                          "phase": "post", "local_tick": 0,
                          "provenance": _event_provenance(None)}],
    ]


def _store_rows() -> list[list]:
    key = _transaction(STORE_SEQUENCE)
    return [["case0_store", {
        "kind": "memory_write", "component": "cpu", "memory_id": "ram",
        "generation": 0, "address": STORE_ADDRESS, "byte_offset": STORE_ADDRESS,
        "width_bytes": STORE_WIDTH_BYTES, "byte_enable": STORE_BYTE_ENABLE,
        "value": STORE_VALUE, "version": list(STORE_VERSION),
        "transaction": asdict(key), "provenance": _event_provenance(0)}]]


def _load_rows() -> list[list]:
    key = _transaction(STORE_SEQUENCE)
    return [
        ["case2_materialization", {
            "kind": "memory_initialization", "component": "cpu",
            "memory_id": "ram", "generation": 0,
            "byte_offset": MATERIALIZE_OFFSET, "value": MATERIALIZE_VALUE,
            "version": list(MATERIALIZE_VERSION),
            "writer_event_id": MATERIALIZE_WRITER,
            "transaction": asdict(_transaction(MATERIALIZE_SEQUENCE)),
            "provenance": _event_provenance(2)}],
        ["case2_load", {
            "kind": "memory_read", "component": "cpu", "memory_id": "ram",
            "generation": 0, "address": STORE_ADDRESS,
            "byte_offset": STORE_ADDRESS, "width_bytes": STORE_WIDTH_BYTES,
            "value": STORE_READ_VALUE, "data_hex": "aa112233",
            "versions": [list(STORE_VERSION), [0, 3], [0, 3], [0, 4]],
            "writer_event_ids": [str(key), "initial-image", "initial-image",
                                 "initial-image"],
            "transaction": asdict(_transaction(12)),
            "provenance": _event_provenance(2)}],
        ["case2_materialized_read", {
            "kind": "memory_read", "component": "cpu", "memory_id": "ram",
            "generation": 0, "address": MATERIALIZE_OFFSET,
            "byte_offset": MATERIALIZE_OFFSET, "width_bytes": 4,
            "value": MATERIALIZE_VALUE, "data_hex": "5a000000",
            "versions": [list(MATERIALIZE_VERSION), [0, 3], [0, 4], [0, 6]],
            "writer_event_ids": [MATERIALIZE_WRITER, "initial-image",
                                 "initial-image", "initial-image"],
            "transaction": asdict(_transaction(13)),
            "provenance": _event_provenance(2)}],
    ]


def _cross_case_journal(*, cross_case: bool) -> _Journal:
    """One IP chain and one CPU chain, both retagged across a case boundary."""
    ip = _ip_journal(case_index=1, tag="ip_")
    cpu = _cpu_journal(case_index=1, tag="cpu_")
    if not cross_case:
        return _merge(_ip_journal(tag="ip_"), _cpu_journal(tag="cpu_"))

    def retag(rows: list[list], endpoint: int) -> None:
        for row in rows:
            provenance = dict(row[1].get("provenance") or {})
            provenance["observed_case"] = {"case_id": f"case-{endpoint}",
                                           "case_index": endpoint}
            row[1]["provenance"] = provenance

    ip_head, ip_tail = _take_rows(ip, (CROSS_CASE_TAIL["IP_TO_CPU_TO_IP"],))
    cpu_head, cpu_tail = _take_rows(
        cpu, (CROSS_CASE_TAIL["CPU_TO_IP_TO_CPU"],))
    retag(ip_tail, 3)
    retag(cpu_tail, 3)
    return _compose(_boot_rows() + _store_rows() + ip_head + cpu_head
                    + _load_rows() + ip_tail + cpu_tail)


def _journal() -> _Journal:
    return _cross_case_journal(cross_case=True)


# ------------------------------------------------------------------- run writer


def _receipts_run_id(run_id: str) -> str:
    return run_id


def _receipt(case_index: int, *, run_id: str = RUN_ID, **overrides) -> dict:
    document = {
        "case_id": f"case-{case_index}", "status": "complete", "run_id": run_id,
        "slot": case_index, "buffer_id": 0,
        "manifest_sha256": _manifest_identity(_manifest_bytes()),
        "source_selection_reason": "direct_source_byte",
        "applied_source_ids": ["gpio_b.external_pin8"],
        "interaction_source_gains": {}, "interaction_new_features": [],
        "interaction_deferred": True, "violations": [],
        "coverage_hex": "00000000",
        "raw_sha256": hashlib.sha256(RAW_RECORDS).hexdigest(),
        "online_raw_records_hex": [RAW_RECORDS.hex()],
    }
    document.update(overrides)
    return document


def _receipts(*, finding: bool, run_id: str = RUN_ID) -> list[dict]:
    rows = [
        _receipt(0, run_id=run_id),
        _receipt(1, run_id=run_id,
                 applied_source_ids=["cpu.online_instruction"]),
        _receipt(2, run_id=run_id,
                 applied_source_ids=["cpu.online_instruction"],
                 interaction_source_gains={"cpu.online_instruction": 3,
                                           "gpio_b.external_pin8": 4},
                 interaction_new_features=["memory:RAW:ram",
                                           "irq_taken:gpio_b:cpu"],
                 interaction_deferred=None),
        _receipt(3, run_id=run_id,
                 source_selection_reason="feedback_weighted_legal_source",
                 applied_source_ids=["gpio_b.external_pin8"]),
    ]
    if finding:
        rows[3].update({"status": "dut_violation", "violations": [IRQ_FINDING],
                        "candidate_disposition": "admitted"})
    return rows


def _plan_document(case_count: int) -> dict:
    template = json.loads(GenomeCodec.encode(_template_genome()))
    return {"schema_version": 4, "template": template, "instruction_slots": [],
            "warmup_advances": [],
            "cases": [{"case_id": f"case-{index}"} for index in range(case_count)]}


def _identity_document(run_id: str) -> dict:
    body = {"schema_version": "scenario_online_run_identity.v1",
            "execution_mode": "online_cases",
            "run_config": {"run_id": run_id, "duration_seconds": 1.0},
            "session": {"manifest_file": MANIFEST_NAME,
                        "manifest_sha256": _manifest_identity(_manifest_bytes()),
                        "component_identity_sha256": "d" * 64}}
    return {"schema_version": "scenario_online_run_identity.v1",
            "sha256": hashlib.sha256(
                json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest(),
            "identity": body}


def _write_run(directory: Path, *, journal: _Journal | None = None,
               manifest: bool = True, trace: bool = True,
               receipts: bool = True, plan: bool = True,
               finding: bool = False, finding_replay: bool = True,
               corpus: bool = False, case_count: int = 4,
               run_id: str = RUN_ID, plan_case_ids=None,
               plan_leading=0) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    journal = _journal() if journal is None else journal
    events = journal.events
    if manifest:
        (directory / MANIFEST_NAME).write_bytes(_manifest_bytes())
        identity = _identity_document(run_id)
        (directory / "online_run_identity.json").write_text(
            json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")
    if trace:
        (directory / "online_events.jsonl").write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8")
        (directory / "online_final_trace.meta.json").write_text(
            json.dumps({"schema_version": "online_trace_jsonl.v1",
                        "events_file": "online_events.jsonl",
                        "event_count": len(events), "status": "complete",
                        "local_ticks": {"cpu": 40}}), encoding="utf-8")
    if receipts:
        (directory / "receipts.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n"
                    for row in _receipts(finding=finding, run_id=run_id)),
            encoding="utf-8")
    if plan:
        document = _plan_document(case_count)
        if plan_case_ids is not None:
            document["cases"] = [{"case_id": case_id}
                                 for case_id in plan_case_ids]
        elif plan_leading:
            leading = [f"{run_id}-warmup-{index}"
                       for index in range(plan_leading)]
            document["cases"] = ([{"case_id": case_id} for case_id in leading]
                                 + document["cases"])
        (directory / "online_plan.json").write_text(
            json.dumps(document, sort_keys=True), encoding="utf-8")
    (directory / "report.json").write_text(json.dumps(
        {"tests": case_count, "run_id": run_id,
         "statuses": ({"complete": case_count - 1, "dut_violation": 1} if finding
                      else {"complete": case_count}),
         "session_status": "finding" if finding else "complete",
         "effective_search_seconds": 1.0, "elapsed_seconds": 1.2}),
        encoding="utf-8")
    if finding and finding_replay:
        (directory / "minimal_replay.json").write_text(json.dumps(
            {"schema_version": "p5_controlled_fault_replay.v1",
             "calibration_only": True,
             "findings": [{"finding_id": "fault-finding-1",
                           "fault_id": "fault-1",
                           "case_id": f"case-{case_count - 1}",
                           "expected_finding": IRQ_FINDING,
                           "detected_by": IRQ_FINDING,
                           "observation_event_id": 1}]}), encoding="utf-8")
    if corpus:
        (directory / "corpus").mkdir(exist_ok=True)
        (directory / "corpus" / "entry_0000.json").write_text(json.dumps(
            {"entry": {"id": 0, "inputs": list(_raw_records()),
                       "is_valid": True}}), encoding="utf-8")
    return directory


def _item(report: dict, key: str) -> dict:
    return next(item for item in report["gate"]["items"] if item["key"] == key)


def _written_event_id(directory: Path, name: str) -> int:
    """The event id of one named journal row, read back from the artifact."""
    journal = _journal()
    wanted = journal.ids[name]
    for line in (directory / "online_events.jsonl").read_text(
            encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("event_id") == wanted:
            return wanted
    raise AssertionError(f"event id {wanted} for {name!r} is not in the trace")


# -------------------------------------------------------------------- positives


def test_complete_run_measures_every_artifact_level_item(tmp_path):
    run = _write_run(tmp_path / "run")
    report = p3_acceptance_report(run)

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["run_dir"] == str(run)
    assert report["run_id"] == RUN_ID
    assert report["manifest"]["available"] is True
    assert report["manifest"]["session_manifest_count"] == 1
    assert set(report["manifest"]["components"]) == set(COMPONENTS)
    assert report["trace"]["available"] is True
    assert report["trace"]["event_count_match"] is True
    assert report["receipts"]["available"] is True
    assert report["receipts"]["count"] == 4

    # -- single initialization -------------------------------------------------
    initialization = report["single_initialization"]
    assert initialization["measured"] is True
    assert initialization["met"] is True
    evidence = initialization["evidence"]
    assert evidence["case_count"] == 4
    assert evidence["distinct_case_count"] == 4
    assert evidence["case_indexes"] == [0, 1, 2, 3]
    assert evidence["case_index_monotone"] is True
    assert evidence["case_index_contiguous"] is True
    assert evidence["receipts_bind_manifest_identity"] is True
    assert evidence["trace_case_ids_without_receipt"] == []
    assert evidence["receipt_case_ids_without_trace_events"] == []
    assert evidence["plan_leading_case_ids"] == []
    assert evidence["rebuild_evidence"] == []
    assert evidence["rebuild_evidence_measured"] is True
    assert evidence["initialization"]["initial_image_count"] == 1
    assert evidence["initialization"]["initial_image_after_first_case"] == 0
    assert evidence["initialization"]["native_startup_count"] == 1
    assert evidence["reset_epochs"] == [0]  # one reset epoch, from the journals
    assert evidence["boot_markers"]["measured"] is True
    assert evidence["boot_markers"]["met"] is True
    parts = evidence["parts"]
    assert parts["session_identity"]["met"] is True
    assert parts["case_sequence"]["measured"] is True
    assert parts["case_sequence"]["met"] is True
    assert parts["no_rebuild"]["met"] is True

    # -- store then load -------------------------------------------------------
    store = report["store_then_load"]
    assert store["measured"] is True
    assert store["met"] is True
    memory = store["evidence"]
    ids = _journal().ids
    assert memory["event_kinds"] == {"memory_write": 1, "memory_write_commit": 0,
                                     "memory_read": 2, "memory_initialization": 1}
    assert memory["cross_case_matches"] == 1
    assert memory["same_case_matches"] == 0
    assert memory["value_conflicts"] == 0
    match = memory["first_cross_case_match"]
    assert match["write_event_id"] == ids["case0_store"]
    assert match["read_event_id"] == ids["case2_load"]
    assert (match["write_case_index"], match["read_case_index"]) == (0, 2)
    assert (match["write_case_id"], match["read_case_id"]) == ("case-0", "case-2")
    assert match["lanes"] == [{"lane": 0, "byte_offset": STORE_ADDRESS,
                               "version": list(STORE_VERSION),
                               "writer_event_id": str(_transaction(STORE_SEQUENCE)),
                               "value": STORE_VALUE, "read_value": STORE_READ_VALUE}]
    byte_enable = memory["byte_enable"]
    assert byte_enable["partial_byte_enable_writes"] == 1
    assert byte_enable["enabled_lane_matches"] == 1
    assert byte_enable["non_enabled_lane_adoptions"] == 0
    assert byte_enable["lane_selectivity"]["measured"] is True
    assert byte_enable["lane_selectivity"]["met"] is True
    store_parts = memory["parts"]
    assert store_parts["cross_case_exact_match"]["measured"] is True
    assert store_parts["cross_case_exact_match"]["met"] is True
    assert store_parts["byte_enable_lane_selectivity"]["measured"] is True
    assert store_parts["byte_enable_lane_selectivity"]["met"] is True
    assert store_parts["first_unknown_read_reuse"]["met"] is True
    reuse = memory["first_unknown_read_reuse"]
    assert reuse["materialized_lanes"] == 1
    assert reuse["reused_lanes"] == 1
    assert reuse["rematerialized_lanes"] == 0
    assert reuse["measured"] is True
    assert reuse["met"] is True
    assert byte_enable["non_enabled_lane_checks"] == 3

    # -- cross-case chains (real frozen producer) ------------------------------
    chains = report["cross_case_chains"]
    assert chains["measured"] is True
    assert chains["met"] is True
    chain_evidence = chains["evidence"]
    assert chain_evidence["certified_count"] == 2
    assert chain_evidence["cross_case_count"] == 2
    assert chain_evidence["same_case_count"] == 0
    assert chain_evidence["all_directions_have_cross_case"] is True
    assert chain_evidence["directions_without_cross_case"] == []
    for direction in ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"):
        row = chain_evidence["by_direction"][direction]
        assert row["cross_case_count"] == 1, direction
        assert row["same_case_count"] == 0, direction
        assert row["case_gap"]["p50"] == 2, direction
        representative = row["representative_cross_case_chain"]
        assert (representative["source_case_index"],
                representative["endpoint_case_index"]) == (1, 3), direction
        assert representative["source_case_id"] == "case-1"
        assert representative["endpoint_case_id"] == "case-3"

    # -- feedback changes the next input ---------------------------------------
    feedback = report["feedback_changes_next_input"]
    assert feedback["measured"] is True
    assert feedback["met"] is True
    feedback_evidence = feedback["evidence"]
    assert feedback_evidence["feedback_case_indexes"] == [2]
    transition = feedback_evidence["first_transition"]
    assert transition["feedback_case_index"] == 2
    assert transition["next_case_index"] == 3
    assert transition["selection_changed"] is True
    assert transition["source_selection_reason_before"] == "direct_source_byte"
    assert transition["source_selection_reason_after"] == "feedback_weighted_legal_source"
    assert transition["applied_source_ids_before"] == ["cpu.online_instruction"]
    assert transition["applied_source_ids_after"] == ["gpio_b.external_pin8"]
    assert feedback_evidence["interaction_source_gains"] == {
        "cpu.online_instruction": 3, "gpio_b.external_pin8": 4}

    # -- finding: none in this artifact ----------------------------------------
    finding = report["finding_stops_and_replays"]
    assert finding["measured"] is False
    assert finding["met"] is None
    assert "no finding" in finding["reason"]
    assert "runs/current-dataflow-p5-fault-calibration-20261007-online" in (
        finding["reason"])

    # -- chunk split invariance ------------------------------------------------
    chunk = report["chunk_split_invariance"]
    normalized = chunk["evidence"]["normalized_input_level"]
    assert normalized["measured"] is True
    assert normalized["met"] is True
    assert normalized["payload_bytes"] > 0
    assert normalized["split_patterns_checked"] >= 4
    assert normalized["identical"] is True
    assert chunk["evidence"]["rtl_event_level"]["measured"] is False
    assert chunk["evidence"]["rtl_event_level"]["met"] is None
    assert chunk["measured"] is True
    assert chunk["met"] is True

    # -- execution identity (real runner gate, stub harness) -------------------
    identity = report["execution_identity"]
    assert identity["measured"] is True
    assert identity["met"] is True
    identity_evidence = identity["evidence"]
    assert identity_evidence["gate"]["same_execution_id_reused_receipt"] is True
    assert identity_evidence["gate"]["additional_harness_steps"] == 0
    assert identity_evidence["gate"]["other_execution_id_rejected"] is True
    assert identity_evidence["gate"]["rejection_reason"] == (
        "stale_execution: STEP belongs to another testcase run")
    assert identity_evidence["gate"]["other_execution_id_harness_steps"] == 0
    assert identity_evidence["trace_execution_ids"] == [EXECUTION_ID]
    assert identity_evidence["trace_testcase_ids"] == [TESTCASE_ID,
                                                        "synthetic"]

    # -- gate ------------------------------------------------------------------
    gate = report["gate"]
    assert gate["exit_code"] == EXIT_NOT_READY
    assert gate["ready"] is False
    assert gate["critical_missing"] == ["finding_stops_and_replays"]
    assert gate["critical_unmet"] == []
    informational = _item(report, "chunk_split_invariance.rtl_event_level")
    assert informational["critical"] is False
    assert informational["measured"] is False
    assert informational["met"] is None
    assert any(limit["quantity"] == "chunk_split_invariance.rtl_event_level"
               for limit in report["limits"])

    markdown = render_markdown(report)
    assert markdown.startswith("# P3 acceptance report")
    assert "## 证据边界" in markdown
    assert markdown.index("### 实测") < markdown.index("### null / unknown")
    assert markdown.index("### null / unknown") < markdown.index("### 限制")


def test_stop_point_and_prefix_are_measured_but_in_run_artifact_is_not_proof(
        tmp_path):
    run = _write_run(tmp_path / "fault", finding=True)
    report = p3_acceptance_report(run)

    finding = report["finding_stops_and_replays"]
    assert finding["measured"] is True
    assert finding["met"] is False
    evidence = finding["evidence"]
    assert evidence["report_session_status"] == "finding"
    assert evidence["report_statuses"] == {"complete": 3, "dut_violation": 1}
    assert evidence["finding_case_ids"] == ["case-3"]
    assert evidence["finding_case_indexes"] == [3]
    assert evidence["receipts_after_finding"] == 0
    assert evidence["trace_case_indexes_after_finding"] == []
    assert evidence["saved_prefix"]["plan_available"] is True
    assert evidence["saved_prefix"]["plan_cases"] == 4
    assert evidence["saved_prefix"]["plan_last_case_id"] == "case-3"
    assert evidence["saved_prefix"]["prefix_matches_executed_cases"] is True
    assert evidence["saved_prefix"]["plan_leading_case_ids"] == []
    replay = evidence["fresh_replay"]
    # The run's own minimal_replay.json is the declared replay input, never
    # proof that a fresh harness reproduced the finding.
    assert replay["measured"] is False
    assert replay["met"] is None
    assert replay["declared_replay_input"]["case_id"] == "case-3"
    assert replay["declared_replay_input"]["detected_by"] == IRQ_FINDING
    assert "declared replay input" in replay["reason"]
    assert "finding_stops_and_replays" in report["gate"]["critical_unmet"]

    gate = report["gate"]
    assert gate["exit_code"] == EXIT_NOT_READY
    assert gate["ready"] is False


def test_cli_reports_ready_as_exit_zero_and_writes_documents(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    reproduce = _write_run(tmp_path / "reproduce", finding=True,
                           finding_replay=False,
                           run_id=f"{RUN_ID}-reproduce")
    json_out = tmp_path / "out" / "p3.json"
    markdown_out = tmp_path / "out" / "p3.md"
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze", "--run-dir", str(run),
         "--compare-run", str(reproduce),
         "--json-out", str(json_out), "--markdown-out", str(markdown_out)],
        capture_output=True, text=True)
    assert result.returncode == EXIT_READY, result.stdout + result.stderr
    document = json.loads(result.stdout)
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["gate"]["exit_code"] == EXIT_READY
    assert json.loads(json_out.read_text(encoding="utf-8")) == document
    markdown = markdown_out.read_text(encoding="utf-8")
    assert markdown.startswith("# P3 acceptance report")
    assert "## 证据边界" in markdown
    assert "finding_stops_and_replays" in markdown


def test_cli_exits_two_when_a_critical_item_is_missing(tmp_path):
    run = _write_run(tmp_path / "run")
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze", "--run-dir", str(run)],
        capture_output=True, text=True)
    assert result.returncode == EXIT_NOT_READY, result.stdout + result.stderr
    document = json.loads(result.stdout)
    assert document["gate"]["exit_code"] == EXIT_NOT_READY
    assert document["gate"]["critical_missing"] == ["finding_stops_and_replays"]


def test_finding_run_reproduced_by_a_compare_run(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    replay = _write_run(tmp_path / "reproduce", finding=True,
                        finding_replay=False,
                        run_id=f"{RUN_ID}-reproduce")

    without = p3_acceptance_report(run)
    assert without["finding_stops_and_replays"]["met"] is False
    assert "no comparison run was supplied" in (
        without["finding_stops_and_replays"]["reason"])

    report = p3_acceptance_report(run, compare_run=replay)
    evidence = report["finding_stops_and_replays"]["evidence"]
    assert evidence["fresh_replay"]["measured"] is True
    assert evidence["fresh_replay"]["met"] is True
    compare = evidence["fresh_replay"]["compare_run"]
    assert compare["different_run"] is True
    assert compare["same_case_id"] is True
    assert compare["same_violations"] is True
    assert report["finding_stops_and_replays"]["met"] is True
    assert report["compare_run_dir"] == str(replay)
    assert report["compare_run"]["different_run"] is True
    assert report["gate"]["exit_code"] == EXIT_READY


def test_compare_run_must_be_a_different_directory(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True)
    with pytest.raises(ValueError, match="different run directory"):
        p3_acceptance_report(run, compare_run=run)


def test_a_copied_run_identity_is_not_a_fresh_reproduction(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    copy = _write_run(tmp_path / "copy", finding=True, finding_replay=False)

    report = p3_acceptance_report(run, compare_run=copy)
    compare = report["finding_stops_and_replays"]["evidence"]["fresh_replay"][
        "compare_run"]
    assert compare["different_run"] is False
    assert report["finding_stops_and_replays"]["met"] is False
    assert "cannot reproduce anything" in (
        report["finding_stops_and_replays"]["reason"])


# --------------------------------------------------------------------- negatives


def test_missing_trace_reports_null_sections_and_exit_two(tmp_path):
    run = _write_run(tmp_path / "run", trace=False)
    report = p3_acceptance_report(run)

    assert report["trace"]["available"] is False
    assert report["trace"]["reason"]
    assert report["single_initialization"]["measured"] is False
    assert report["single_initialization"]["met"] is None
    assert report["single_initialization"]["reason"]
    assert report["store_then_load"]["measured"] is False
    assert report["store_then_load"]["met"] is None
    assert report["cross_case_chains"]["measured"] is False
    assert report["cross_case_chains"]["met"] is None
    assert report["chunk_split_invariance"]["measured"] is False
    assert report["chunk_split_invariance"]["met"] is None

    gate = report["gate"]
    assert gate["exit_code"] == EXIT_NOT_READY
    assert "trace" in gate["critical_missing"]
    assert "single_initialization" in gate["critical_missing"]
    assert "store_then_load" in gate["critical_missing"]
    assert "cross_case_chains" in gate["critical_missing"]


def test_missing_manifest_reports_null_session_identity_and_exit_two(tmp_path):
    run = _write_run(tmp_path / "run", manifest=False)
    report = p3_acceptance_report(run)

    assert report["manifest"]["available"] is False
    assert report["manifest"]["reason"]
    assert report["run_identity"]["available"] is False
    initialization = report["single_initialization"]
    assert initialization["measured"] is False
    assert initialization["met"] is None
    assert "manifest" in initialization["reason"]
    # The trace alone still measures the memory effects.
    assert report["store_then_load"]["met"] is True
    assert report["gate"]["exit_code"] == EXIT_NOT_READY
    assert "manifest" in report["gate"]["critical_missing"]
    assert "single_initialization" in report["gate"]["critical_missing"]


def test_absent_store_is_null_and_never_a_pass(tmp_path):
    journal = _compose(_boot_rows() + _load_rows())
    run = _write_run(tmp_path / "run", journal=journal, case_count=4)
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is False
    assert store["met"] is None
    assert "no memory_write" in store["reason"]
    assert store["evidence"]["event_kinds"]["memory_write"] == 0
    assert report["gate"]["exit_code"] == EXIT_NOT_READY
    assert "store_then_load" in report["gate"]["critical_missing"]


def test_store_consumed_in_its_own_case_is_measured_but_not_met(tmp_path):
    rows = _boot_rows() + _store_rows()
    for row in rows:
        if row[0] == "case0_store":
            row[1]["provenance"] = _event_provenance(2)
    journal = _compose(rows + _load_rows())
    run = _write_run(tmp_path / "run", journal=journal)
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is True
    assert store["met"] is False
    assert store["evidence"]["cross_case_matches"] == 0
    assert store["evidence"]["same_case_matches"] == 1
    assert store["evidence"]["first_cross_case_match"] is None
    assert "not across a case boundary" in store["reason"]
    assert report["gate"]["exit_code"] == EXIT_NOT_READY
    assert "store_then_load" in report["gate"]["critical_unmet"]


def test_version_mismatch_is_not_a_store_then_load(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        if row[0] == "case2_load":
            row[1]["versions"] = [[0, 99], [0, 3], [0, 3], [0, 4]]
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is True
    assert store["met"] is False
    assert store["evidence"]["cross_case_matches"] == 0
    assert store["evidence"]["same_case_matches"] == 0
    assert store["evidence"]["lane_matches"] == 0
    assert "no later memory_read snapshot" in store["reason"]


def test_read_value_conflict_refuses_the_match(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        if row[0] == "case2_load":
            row[1]["data_hex"] = "ab112233"  # lane 0 no longer carries 0xAA
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is True
    assert store["met"] is False
    assert store["evidence"]["lane_matches"] == 1
    assert store["evidence"]["cross_case_matches"] == 0
    assert store["evidence"]["value_conflicts"] == 1
    assert "value" in store["reason"]


def test_same_case_chains_are_not_cross_case(tmp_path):
    journal = _merge(_boot_rows_journal(), _same_case_journal())
    run = _write_run(tmp_path / "run", journal=journal)
    report = p3_acceptance_report(run)

    chains = report["cross_case_chains"]
    assert chains["measured"] is True
    assert chains["met"] is False
    assert chains["evidence"]["certified_count"] == 2
    assert chains["evidence"]["cross_case_count"] == 0
    assert chains["evidence"]["same_case_count"] == 2
    assert chains["evidence"]["all_directions_have_cross_case"] is False
    assert sorted(chains["evidence"]["directions_without_cross_case"]) == [
        "CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"]
    assert "crossed a case boundary" in chains["reason"]
    assert report["gate"]["exit_code"] == EXIT_NOT_READY
    assert "cross_case_chains" in report["gate"]["critical_unmet"]


def test_feedback_without_a_changed_next_input_is_not_met(tmp_path):
    run = _write_run(tmp_path / "run")
    receipts_path = run / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    rows[3]["source_selection_reason"] = "direct_source_byte"
    rows[3]["applied_source_ids"] = ["cpu.online_instruction"]
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run)
    feedback = report["feedback_changes_next_input"]
    assert feedback["measured"] is True
    assert feedback["met"] is False
    assert feedback["evidence"]["first_transition"]["selection_changed"] is False
    assert "did not change" in feedback["reason"]


def test_absent_feedback_signal_is_null(tmp_path):
    run = _write_run(tmp_path / "run")
    receipts_path = run / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        row["interaction_source_gains"] = {}
        row["interaction_new_features"] = []
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run)
    feedback = report["feedback_changes_next_input"]
    assert feedback["measured"] is False
    assert feedback["met"] is None
    assert "no receipt records" in feedback["reason"]
    assert "feedback_changes_next_input" in report["gate"]["critical_missing"]


def test_finding_without_a_replay_artifact_is_not_met(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    report = p3_acceptance_report(run)

    finding = report["finding_stops_and_replays"]
    assert finding["measured"] is True
    assert finding["met"] is False
    assert finding["evidence"]["receipts_after_finding"] == 0
    assert finding["evidence"]["fresh_replay"]["measured"] is False
    assert "fresh-harness reproduction is unmeasured" in finding["reason"]
    assert "finding_stops_and_replays" in report["gate"]["critical_unmet"]


def test_case_after_a_finding_breaks_the_stop_claim(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True)
    receipts_path = run / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    rows.append(_receipt(3, status="complete"))
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run)
    finding = report["finding_stops_and_replays"]
    assert finding["measured"] is True
    assert finding["met"] is False
    assert finding["evidence"]["receipts_after_finding"] == 1
    assert "accepted another case" in finding["reason"]


def test_fewer_than_three_cases_does_not_meet_single_initialization(tmp_path):
    journal = _compose(_boot_rows() + _store_rows() + _load_rows())
    run = _write_run(tmp_path / "run", journal=journal, case_count=2)
    receipts_path = run / "receipts.jsonl"
    receipts_path.write_text(
        json.dumps(_receipt(0), sort_keys=True) + "\n" +
        json.dumps(_receipt(2), sort_keys=True) + "\n", encoding="utf-8")

    report = p3_acceptance_report(run)
    initialization = report["single_initialization"]
    assert initialization["measured"] is True
    assert initialization["met"] is False
    assert initialization["evidence"]["case_count"] == 2
    assert "at least 3" in initialization["reason"]


def test_second_initialization_is_rebuild_evidence(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    rows.insert(3, ["second_boot_image", {
        "kind": "initial_image", "component": "cpu",
        "image_id": "cpu.stream.bootstrap", "address": 0x10000,
        "data_hex": "13000000", "provenance": _event_provenance(None)}])
    journal = _compose(rows)
    run = _write_run(tmp_path / "run", journal=journal)
    report = p3_acceptance_report(run)

    initialization = report["single_initialization"]
    assert initialization["measured"] is True
    assert initialization["met"] is False
    assert initialization["evidence"]["rebuild_evidence"] == [
        "initial_image_written_after_the_first_case"]
    assert "re-initialization" in initialization["reason"]


def test_chunk_level_requires_a_normalized_payload(tmp_path):
    run = _write_run(tmp_path / "run", plan=False)
    report = p3_acceptance_report(run)

    chunk = report["chunk_split_invariance"]
    assert chunk["measured"] is False
    assert chunk["met"] is None
    assert chunk["evidence"]["normalized_input_level"]["measured"] is False
    assert "no normalized genome payload" in chunk["reason"]
    assert "chunk_split_invariance" in report["gate"]["critical_missing"]


def test_chunk_level_uses_corpus_when_the_plan_is_absent(tmp_path):
    run = _write_run(tmp_path / "run", plan=False, corpus=True)
    report = p3_acceptance_report(run)

    chunk = report["chunk_split_invariance"]
    assert chunk["measured"] is True
    assert chunk["met"] is True
    assert chunk["evidence"]["normalized_input_level"]["raw_payload_source"] == (
        "corpus/entry_0000.json:entry.inputs")


def test_declared_semantic_digest_mismatch_fails_closed(tmp_path):
    run = _write_run(tmp_path / "run")
    meta_path = run / "online_final_trace.meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["semantic_sha256"] = "0" * 64
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    report = p3_acceptance_report(run)
    assert report["trace"]["semantic_sha256_verified"] is False
    assert report["trace"]["available"] is False
    assert "does not match the recomputed" in report["trace"]["reason"]
    assert report["single_initialization"]["measured"] is False
    assert report["store_then_load"]["measured"] is False
    assert report["cross_case_chains"]["measured"] is False
    assert report["gate"]["exit_code"] == EXIT_NOT_READY
    assert "trace" in report["gate"]["critical_missing"]
    assert "single_initialization" in report["gate"]["critical_missing"]


def test_cli_reports_a_hard_error_as_exit_one(tmp_path):
    result = subprocess.run(
        [sys.executable, str(CLI), "analyze",
         "--run-dir", str(tmp_path / "does-not-exist")],
        capture_output=True, text=True)
    assert result.returncode == 1
    assert "does not exist" in result.stderr


# ------------------------------------------------------------------ small parts


def _boot_rows_journal() -> _Journal:
    return _compose(_boot_rows())


def _same_case_journal() -> _Journal:
    return _merge(_ip_journal(tag="ip_"), _cpu_journal(tag="cpu_"))


def test_hand_computed_hop_names_match_the_declared_contracts(tmp_path):
    """The retagged tails really are the declared cross-case tails."""
    assert CROSS_CASE_TAIL["IP_TO_CPU_TO_IP"] in IP_HOPS
    assert CROSS_CASE_TAIL["CPU_TO_IP_TO_CPU"] in CPU_HOPS
    journal = _journal()
    assert journal.ids["case0_store"] < journal.ids["case2_load"]
    run = _write_run(Path(tmp_path) / "run")
    assert _written_event_id(run, "case0_store") == journal.ids["case0_store"]


def test_compare_run_with_a_different_finding_does_not_reproduce(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False)
    other = _write_run(tmp_path / "other", finding=True, finding_replay=False,
                       run_id=f"{RUN_ID}-other")
    receipts_path = other / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    rows[-1]["violations"] = ["some_other_violation"]
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run, compare_run=other)
    finding = report["finding_stops_and_replays"]
    compare = finding["evidence"]["fresh_replay"]["compare_run"]
    assert compare["available"] is True
    assert compare["same_case_id"] is True
    assert compare["same_violations"] is False
    assert finding["measured"] is True
    assert finding["met"] is False
    assert "does not record the same finding on the same case_id" in (
        finding["reason"])
    assert "finding_stops_and_replays" in report["gate"]["critical_unmet"]



# --------------------------------------------------- strictness of the halves


def test_full_byte_enable_only_leaves_lane_selectivity_null(tmp_path):
    """No partial byte_enable: the lane half is null, so the item is not met."""
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        if row[0] == "case0_store":
            row[1]["byte_enable"] = 0b1111
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is True  # the cross-case half is measurable
    assert store["met"] is False  # but the lane half is unobserved
    parts = store["evidence"]["parts"]
    assert parts["cross_case_exact_match"]["met"] is True
    assert parts["byte_enable_lane_selectivity"]["measured"] is False
    assert parts["byte_enable_lane_selectivity"]["met"] is None
    assert "byte_enable_lane_selectivity" in store["reason"]
    assert "was not observed" in store["reason"]
    assert any(limit["quantity"] == "store_then_load.byte_enable_lane_selectivity"
               for limit in report["limits"])
    assert "store_then_load" in report["gate"]["critical_unmet"]


def test_materialization_without_reuse_is_not_met(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        if row[0] == "case2_materialized_read":
            row[1]["versions"] = [[0, 99], [0, 3], [0, 4], [0, 6]]
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    store = report["store_then_load"]
    assert store["measured"] is True
    assert store["met"] is False
    reuse = store["evidence"]["first_unknown_read_reuse"]
    assert reuse["measured"] is True
    assert reuse["met"] is False
    assert reuse["reused_lanes"] == 0
    assert "reuse was not observed" in reuse["reason"]
    assert "first_unknown_read_reuse" in store["reason"]


def test_absent_boot_markers_are_null_not_a_pass(tmp_path):
    # The full journal keeps every case index; only the two boot markers are
    # removed, so the *marker* half is what is missing.
    rows = [row for row in _rows(_journal()) if row[0] != "boot_startup"]
    for row in rows:
        row[1].pop("reset_epoch", None)
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    initialization = report["single_initialization"]
    markers = initialization["evidence"]["boot_markers"]
    assert markers["measured"] is False
    assert markers["met"] is None
    assert markers["native_startup_count"] == 0
    assert markers["reset_epochs"] is None
    assert "stays null" in markers["reason"]
    assert any(limit["quantity"] == "single_initialization.boot_markers"
               for limit in report["limits"])
    # The session identity itself is still measured and holds.
    assert initialization["measured"] is True
    assert initialization["met"] is True


def test_trace_without_case_attribution_is_unmeasured(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        provenance = dict(row[1].get("provenance") or {})
        provenance["observed_case"] = None
        row[1]["provenance"] = provenance
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    initialization = report["single_initialization"]
    assert initialization["measured"] is False
    assert initialization["met"] is None
    sequence = initialization["evidence"]["parts"]["case_sequence"]
    assert sequence["measured"] is False
    assert sequence["met"] is None
    assert "no observed_case identity" in initialization["reason"]
    assert "single_initialization" in report["gate"]["critical_missing"]
    # The memory join never relied on case attribution for its own existence.
    assert report["store_then_load"]["evidence"]["lane_matches"] == 1
    assert report["store_then_load"]["evidence"]["unattributed_matches"] == 1


def test_plan_with_a_bootstrap_prefix_keeps_the_session_measured(tmp_path):
    run = _write_run(tmp_path / "run", plan_leading=1)
    report = p3_acceptance_report(run)

    initialization = report["single_initialization"]
    assert initialization["measured"] is True
    assert initialization["met"] is True
    assert initialization["evidence"]["plan_leading_case_ids"] == [
        f"{RUN_ID}-warmup-0"]
    assert initialization["evidence"]["trace_case_ids_without_receipt"] == []

    finding = _write_run(tmp_path / "fault", finding=True, plan_leading=1)
    report = p3_acceptance_report(finding)
    prefix = report["finding_stops_and_replays"]["evidence"]["saved_prefix"]
    assert prefix["plan_cases"] == 5
    assert prefix["plan_leading_case_ids"] == [f"{RUN_ID}-warmup-0"]
    assert prefix["prefix_matches_executed_cases"] is True
    assert prefix["plan_last_case_id"] == "case-3"


def test_long_plan_keeps_every_case_id(tmp_path):
    case_ids = [f"case-{index}" for index in range(4)] + [
        f"long-{index}" for index in range(4, 80)]
    run = _write_run(tmp_path / "run", plan_case_ids=case_ids)
    report = p3_acceptance_report(run)

    plan = report["plan"]
    assert plan["case_count"] == len(case_ids)
    assert plan["case_ids"] == case_ids  # never silently clipped to 64
    assert plan["case_ids_sample"] == case_ids[:64]


def test_finding_prefix_must_end_in_the_executed_cases(tmp_path):
    run = _write_run(tmp_path / "fault", finding=True, finding_replay=False,
                     plan_case_ids=["case-0", "case-1", "case-2"])
    report = p3_acceptance_report(run)

    prefix = report["finding_stops_and_replays"]["evidence"]["saved_prefix"]
    assert prefix["plan_cases"] == 3
    assert prefix["plan_last_case_id"] == "case-2"
    assert prefix["prefix_matches_executed_cases"] is False
    assert report["finding_stops_and_replays"]["met"] is False
    assert "does not end in the executed case sequence" in (
        report["finding_stops_and_replays"]["reason"])


def test_truncated_receipts_downgrade_every_criterion_that_used_them(tmp_path):
    run = _write_run(tmp_path / "run")
    report = p3_acceptance_report(run, max_case_ids=3)

    assert report["receipts"]["truncated"] is True
    assert report["receipts"]["count"] == 3
    assert any(limit["quantity"] == "receipts" for limit in report["limits"])
    assert report["single_initialization"]["measured"] is False
    assert report["single_initialization"]["met"] is None
    assert report["finding_stops_and_replays"]["measured"] is False
    assert report["feedback_changes_next_input"]["measured"] is False
    gate = report["gate"]
    assert "single_initialization" in gate["critical_missing"]
    assert "feedback_changes_next_input" in gate["critical_missing"]


def test_receipts_without_case_ids_are_unmeasured(tmp_path):
    run = _write_run(tmp_path / "run")
    receipts_path = run / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    for index, row in enumerate(rows):
        row["case_id"] = None
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run)
    assert report["receipts"]["missing_case_id_rows"] == 4
    assert report["single_initialization"]["measured"] is False
    assert "no usable case_id" in report["single_initialization"]["reason"]


def test_execution_identity_needs_a_run_identity_in_the_trace(tmp_path):
    rows = _boot_rows() + _store_rows() + _load_rows()
    for row in rows:
        row[1].pop("transaction", None)
    run = _write_run(tmp_path / "run", journal=_compose(rows))
    report = p3_acceptance_report(run)

    identity = report["execution_identity"]
    assert identity["measured"] is False
    assert identity["met"] is False
    assert identity["evidence"]["trace_execution_ids"] == []
    assert "cannot be bound to one execution" in identity["reason"]
    assert any(limit["quantity"] == "execution_identity.artifact"
               for limit in report["limits"])


def test_deferred_feedback_cannot_change_the_next_input(tmp_path):
    run = _write_run(tmp_path / "run")
    receipts_path = run / "receipts.jsonl"
    rows = [json.loads(line) for line in
            receipts_path.read_text(encoding="utf-8").splitlines()]
    rows[2]["interaction_deferred"] = True
    receipts_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8")

    report = p3_acceptance_report(run)
    feedback = report["feedback_changes_next_input"]
    assert feedback["measured"] is False
    assert feedback["met"] is None
    assert feedback["evidence"]["feedback_case_indexes"] == []
    assert feedback["evidence"]["deferred_feedback_case_indexes"] == [2]
    assert "deferred batch feedback" in feedback["reason"]
    assert "feedback_changes_next_input" in report["gate"]["critical_missing"]


def test_cli_usage_error_is_a_hard_error(tmp_path):
    result = subprocess.run([sys.executable, str(CLI), "analyze"],
                            capture_output=True, text=True)
    assert result.returncode == 1
    document = json.loads(result.stdout)
    assert document["schema_version"] == "p3_acceptance_gate_error.v1"
    assert "argument error" in document["error"]
