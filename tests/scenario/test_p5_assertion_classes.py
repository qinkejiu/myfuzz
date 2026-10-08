"""P5 assertion classes: protocol checker / provenance-order / CPU-IP behaviour.

The report under test reads ONE saved run directory read-only and must answer,
separately and with exact evidence keys, three questions the frozen P5 checklist
asks for ("用协议检查器、跨组件来源/顺序不变量及 CPU/IP 行为断言分别报告问题；
生成约束和检查期望分开，异常真实输出不能因路径未就绪被过滤"):

* ``protocol_checker`` -- the run's own checker findings, read from
  ``receipts.jsonl`` ``violations`` with the checker identity from the saved
  manifest;
* ``cross_component_provenance_and_order`` -- the shipped
  ``runtime_edge_provenance.v1`` / ``runtime_chain_certificate.v1`` analysis of
  the same artifacts: certified/incomplete/unknown edges and the exact
  ``missing`` hops, plus the incomplete chain certificates and their
  ``missing_hops``;
* ``cpu_ip_behaviour`` -- the CPU/IP behaviour records the run really contains
  (retirement, IRQ acceptance/expiry, consumption), never a synthesised zero.

The synthetic run directories are built from the hand-joined journals of
``test_chain_certificates`` and ``test_edge_provenance``, so the certificates
and edge rows the report renders are produced by the real frozen consumers.
The negative cases construct artifacts whose abnormal records cannot be
attributed to any class: the fail-closed gate must then fail with a precise
reason instead of passing with the record silently dropped.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.assertion_classes import (
    ASSERTION_CLASSES,
    CLASS_CROSS_COMPONENT,
    CLASS_CPU_IP,
    CLASS_PROTOCOL_CHECKER,
    NOT_A_RUNTIME_EDGE,
    SCHEMA_VERSION,
    assertion_class_report,
)
from myfuzz.scenario.edge_provenance import EDGE_PROVENANCE_REPORT_SCHEMA
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract,
    RuntimePathContract,
)
from tests.scenario.test_chain_certificates import (
    _cpu_journal,
    _ip_journal,
    _merge,
)
from tests.scenario.test_edge_provenance import (
    BINDING_KEY,
    GRAPH_SHA256,
    MMIO_KEY,
    RESOURCE_KEY,
    _binding_journal,
    _contract,
    _endpoints,
    _provenance,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts/report_p5_assertion_classes.py"

PIN8_PATH_ID = "pin8-path"
CPU_PATH_ID = "cpu-path"
NOT_A_RUNTIME_KEY = (77, 0)
CAUSAL_ONLY_KEY = (88, 0)


# --------------------------------------------------------------- synthetic runs


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compiled(contract: RuntimePathContract, selections, paths):
    """One ``runtime_paths`` compiled document for a synthetic contract."""
    return {
        "schema_version": "compiled_runtime_path_contract.v1",
        "graph_sha256": contract.graph_sha256,
        "contract_sha256": contract.identity_sha256,
        "topology_sha256": "0" * 64,
        "topology": {
            "bindings": [
                {"source_component": "dev_a", "source_port": "out",
                 "source_bit_offset": 0, "target_component": "dev_b",
                 "target_port": "in", "target_bit_offset": 0, "width": 8},
            ],
            "routers": [{"initiator": "cpu", "windows": [
                {"device_id": "dev_b", "base": 0x40000000, "size": 0x1000}]}],
        },
        "paths": paths,
        "proof_scope": "selected_declared_topology_only",
        "runtime_causality_verified": False,
        "resource_versions_verified": False,
        "declaration": {
            "schema_version": "runtime_path_declaration.v1",
            "contract": contract.document(),
            "graph": {"edges": []},
            "selections": selections,
        },
    }


def _write_run(directory, *, events, receipts=None, runtime_paths=None,
               decoder_manifest=True, targets=True, identity=True,
               report=True, plan=True):
    """Write one streaming-format synthetic run directory."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "online_events.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8")
    (directory / "online_final_trace.meta.json").write_text(json.dumps({
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl",
        "event_count": len(events),
        "semantic_sha256": None,
        "status": "complete"}), encoding="utf-8")
    if receipts is not None:
        (directory / "receipts.jsonl").write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in receipts),
            encoding="utf-8")
    if runtime_paths is not None:
        (directory / "online_session_manifest.json").write_text(json.dumps({
            "schema_version": "online_session_manifest.v1",
            "checker": {"module": "myfuzz.scenario.synthetic_checker",
                        "qualname": "SyntheticChecker",
                        "config": {},
                        "source": {"path": "src/myfuzz/scenario/assertion_classes.py",
                                   "sha256": "0" * 64}},
            "runtime_paths": runtime_paths}, sort_keys=True), encoding="utf-8")
    if decoder_manifest:
        (directory / "decoder_manifest.json").write_text(json.dumps({
            "schema_version": "scenario_online_decoder_manifest.v1",
            "flow_by_target": {"cpu_to_ip_to_cpu.closed_loop": "F4",
                               "ip_to_cpu_to_ip.closed_loop": "F5"},
            "allowed_mmio_operations": ["LW", "SW"],
            "dependency_mode": "runtime_contract",
            "graph": {"edges": []},
            "mmio_windows": [], "ownership": {}, "path_mapping": {},
            "runtime_contract": {"schema_version": "runtime_path_contract.v1"},
            "sources": [], "schedule": {}, "support_words": [],
        }, sort_keys=True), encoding="utf-8")
    if targets:
        (directory / "targets.json").write_text(json.dumps([
            {"component": "gpio_a", "mask": 1, "port": "gpio_out",
             "target_id": "gpio_a_output_bit0", "value": 1}]), encoding="utf-8")
    if identity:
        (directory / "online_run_identity.json").write_text(json.dumps({
            "schema_version": "scenario_online_run_identity_envelope.v1",
            "sha256": "1" * 64,
            "identity": {"execution_mode": "online_cases", "run_config": {
                "run_id": "synthetic-run"}}}, sort_keys=True), encoding="utf-8")
    if report:
        (directory / "report.json").write_text(json.dumps({
            "execution_status": "complete", "tests": len(receipts or ()),
            "statuses": {}}), encoding="utf-8")
    if plan:
        (directory / "online_plan.json").write_text(json.dumps({
            "schema_version": 10,
            "cases": [],
            "source_admissions": {"schema_version": "source_admission_registry.v1",
                                  "admissions": []}}, sort_keys=True),
            encoding="utf-8")
    return directory


def _receipt(case_id="case-1", **overrides):
    row = {
        "case_id": case_id,
        "status": "complete",
        "violations": [],
        "candidate_disposition": "admitted",
        "candidate_disposition_reason": "rtl_case_committed",
        "rejection": None,
        "error": None,
        "path_id": CPU_PATH_ID,
        "source_id": "cpu.online_instruction",
        "direction": "CPU_TO_IP_TO_CPU",
        "raw_sha256": "a" * 64,
    }
    row.update(overrides)
    return row


def _rejected_receipt(case_id=None, code="mmio.window_denied",
                      pointer="mmio.operation", slot=3):
    return _receipt(
        case_id=case_id, slot=slot, status="input_invalid",
        candidate_disposition="rejected",
        candidate_disposition_reason="decode_rejected",
        rejection={"schema_version": "candidate_rejection.v1", "code": code,
                   "pointer": pointer, "detail": {"operation": "SW"}},
        error=f"RejectionError: online candidate rejected: {code} [@{pointer}]",
        raw_sha256="b" * 64)


def _chain_journal(case_index=1):
    return _merge(_ip_journal(case_index=case_index),
                  _cpu_journal(case_index=case_index))


def _chain_runtime_paths(*, extra_hop=True):
    """Compiled declaration with no runtime edges: every hop stays declared-only."""
    contract = RuntimePathContract(GRAPH_SHA256, (), ())
    selections = [
        {"direction": "IP_TO_CPU_TO_IP", "path_id": PIN8_PATH_ID,
         "target": "ip_to_cpu_to_ip.closed_loop",
         "edges": [{"kind": "DATA_BINDING", "rule_index": 2,
                    "prerequisite_index": 0,
                    "prerequisite": "gpio_a.output",
                    "target": "gpio_b.bound_low"}]},
        {"direction": "CPU_TO_IP_TO_CPU", "path_id": CPU_PATH_ID,
         "target": "cpu_to_ip_to_cpu.closed_loop",
         "edges": [{"kind": "DATA_BINDING", "rule_index": 4,
                    "prerequisite_index": 0,
                    "prerequisite": "gpio_b.irq",
                    "target": "cpu.irq"}]},
    ]
    if extra_hop:
        selections[0]["edges"].append(
            {"kind": "PERSISTENT_STATE_RULE", "rule_index": NOT_A_RUNTIME_KEY[0],
             "prerequisite_index": NOT_A_RUNTIME_KEY[1],
             "prerequisite": "gpio_a.padout", "target": "gpio_a.isr_padout"})
    paths = [{"direction": row["direction"], "path_id": row["path_id"],
              "target": row["target"]} for row in selections]
    return _compiled(contract, selections, paths)


def _edge_runtime_paths(*, causal_only=False):
    """Compiled declaration of the binding / MMIO / RAM-version synthetic edges."""
    base = _contract()
    edges = list(base.edges)
    if causal_only:
        # A declared relation with no runtime join shape in this consumer: the
        # edge must stay ``unknown`` with its reason, never certified.
        edges.append(RuntimeEdgeContract(*CAUSAL_ONLY_KEY,
                                         relation="causal_order"))
    contract = RuntimePathContract(base.graph_sha256, base.nodes, tuple(edges))
    selections = [{
        "direction": "CPU_TO_IP_TO_CPU", "path_id": CPU_PATH_ID,
        "target": "cpu_to_ip_to_cpu.closed_loop",
        "edges": [
            {"kind": "DATA_BINDING", "rule_index": BINDING_KEY[0],
             "prerequisite_index": BINDING_KEY[1],
             "prerequisite": "dev_a.out", "target": "dev_b.in"},
            {"kind": "PERSISTENT_STATE_RULE", "rule_index": MMIO_KEY[0],
             "prerequisite_index": MMIO_KEY[1],
             "prerequisite": "cpu.mmio", "target": "dev_b.mmio"},
            {"kind": "PERSISTENT_STATE_RULE", "rule_index": RESOURCE_KEY[0],
             "prerequisite_index": RESOURCE_KEY[1],
             "prerequisite": "ram.bytes", "target": "ram.bytes"},
            {"kind": "PERSISTENT_STATE_RULE", "rule_index": NOT_A_RUNTIME_KEY[0],
             "prerequisite_index": NOT_A_RUNTIME_KEY[1],
             "prerequisite": "dev_b.ram", "target": "dev_b.ram"},
        ]}]
    paths = [{"direction": "CPU_TO_IP_TO_CPU", "path_id": CPU_PATH_ID,
              "target": "cpu_to_ip_to_cpu.closed_loop"}]
    return _compiled(contract, selections, paths)


def _cpu_ip_events():
    """One CPU/IP journal slice: retirement, IRQ and consumption records."""
    journal = _merge(_cpu_journal(case_index=1), _ip_journal(case_index=1))
    journal.mutate("instruction_retirement_match",
                   instruction_origin_status="unknown")
    journal.mutate("cpu_irq_taken", source_trigger={
        "trigger_id": "gpio_b:0:trigger:9", "trigger_event_id": 1,
        "observation_event_id": 1, "sample_event_id": 1})
    journal.add("irq_sample", {
        "kind": "cpu_external_irq_sample", "component": "cpu", "local_tick": 9,
        "expected_input": 1, "actual_pre_input": 0, "actual_post_input": 0,
        "irq_masked_pre": 0, "irq_taken_pre": 0, "execution_id": "local-execution",
        "command_scope": {"command_sequence": 9, "component": "cpu",
                          "reset_epoch": 0},
        "provenance": _provenance(1)})
    journal.add("retirement_refused", {
        "kind": "cpu_retirement_match", "component": "cpu", "status": "rejected",
        "reason": "unsupported_instruction_observation_only",
        "schema_version": "cpu_retirement_match.v1", "insn": 810618995,
        "pc": 65720, "order": 15,
        "producer_event_id": journal.ref("instruction_retirement"),
        "proof_scope": "retired_instruction_origin",
        "origin_relation": "retired_instruction_bytes",
        "provenance": _provenance(1)})
    return journal


# ------------------------------------------------------------------- class split


def test_classes_are_counted_and_listed_separately(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "run", events=journal.events,
        receipts=[_receipt(case_id="online-1"),
                  _receipt(case_id="online-2",
                           violations=["gpio_b_irq_source_mismatch"],
                           status="dut_violation")],
        runtime_paths=_chain_runtime_paths())
    report = assertion_class_report(directory)
    classes = report["assertion_classes"]
    assert report["schema_version"] == SCHEMA_VERSION
    assert set(classes) == set(ASSERTION_CLASSES)

    protocol = classes[CLASS_PROTOCOL_CHECKER]
    assert protocol["data_present"] is True
    assert protocol["finding_count"] == 1
    assert protocol["observed_record_count"] == 2
    finding = protocol["findings"][0]
    assert finding["assertion_class"] == CLASS_PROTOCOL_CHECKER
    assert finding["record_class"] == "protocol_violation"
    assert finding["evidence"] == {
        "receipt_index": 1, "case_id": "online-2",
        "violation": "gpio_b_irq_source_mismatch", "status": "dut_violation",
        "candidate_disposition": "admitted"}

    cross = classes[CLASS_CROSS_COMPONENT]
    assert cross["data_present"] is True
    assert cross["edge_status"]["not_a_runtime_edge_count"] == 3
    not_ready = [row for row in cross["findings"]
                 if row["record_class"] == "not_a_runtime_edge"]
    assert len(not_ready) == 3
    not_ready = [row for row in not_ready
                 if row["evidence"]["rule_index"] == NOT_A_RUNTIME_KEY[0]]
    assert len(not_ready) == 1
    evidence = not_ready[0]["evidence"]
    assert evidence["rule_index"] == NOT_A_RUNTIME_KEY[0]
    assert evidence["prerequisite_index"] == NOT_A_RUNTIME_KEY[1]
    assert evidence["status"] == NOT_A_RUNTIME_EDGE
    assert evidence["direction"] == "IP_TO_CPU_TO_IP"
    assert evidence["path_id"] == PIN8_PATH_ID
    assert evidence["declared_kind"] == "PERSISTENT_STATE_RULE"
    assert "declares no observable runtime relation" in not_ready[0]["reason"]
    # A chain certificate is not an edge: the provenance report is named too.
    assert cross["edge_status"]["schema_version"] == EDGE_PROVENANCE_REPORT_SCHEMA
    assert cross["chain_certificates"]["certified_count"] >= 1

    cpu_ip = classes[CLASS_CPU_IP]
    assert cpu_ip["data_present"] is True
    assert cpu_ip["finding_count"] == len(cpu_ip["findings"]) >= 1


def test_each_class_only_carries_its_own_evidence_kinds(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "run", events=journal.events,
        receipts=[_receipt(case_id="online-1",
                           violations=["gpio_b_irq_source_mismatch"],
                           status="dut_violation")],
        runtime_paths=_chain_runtime_paths())
    classes = assertion_class_report(directory)["assertion_classes"]
    assert {row["record_class"] for row in classes[CLASS_PROTOCOL_CHECKER]["findings"]} \
        == {"protocol_violation"}
    assert all(row["assertion_class"] == CLASS_CROSS_COMPONENT
               for row in classes[CLASS_CROSS_COMPONENT]["findings"])
    assert all(row["assertion_class"] == CLASS_CPU_IP
               for row in classes[CLASS_CPU_IP]["findings"])
    # Every finding is keyed by a stable record id that names its own class.
    ids = [row["record_id"] for section in classes.values()
           for row in section["findings"]]
    assert len(ids) == len(set(ids))
    for section in classes.values():
        for row in section["findings"]:
            assert row["record_id"].startswith(row["record_class"] + ":")
            assert row["expectation_id"]


def test_cross_component_lists_certified_and_missing_hops_with_reasons(tmp_path):
    journal = _binding_journal().without("binding_consumer")
    directory = _write_run(tmp_path / "run", events=journal.events,
                           receipts=[_receipt()],
                           runtime_paths=_edge_runtime_paths())
    cross = assertion_class_report(directory)["assertion_classes"][
        CLASS_CROSS_COMPONENT]
    rows = {(row["rule_index"], row["prerequisite_index"]): row
            for row in cross["edge_status"]["edges"]}
    binding = rows[BINDING_KEY]
    assert binding["status"] == "incomplete"
    assert binding["missing"] == ["consumer"]
    assert binding["hop_ids"] == ["producer", "delivery"]
    assert binding["hop_event_ids"] == [row["event_id"] for row in binding["hops"]]
    assert binding["reason"] == "end_of_journal"
    finding = next(row for row in cross["findings"]
                   if row["record_class"] == "runtime_edge_incomplete"
                   and row["evidence"]["rule_index"] == BINDING_KEY[0])
    assert finding["evidence"]["missing"] == ["consumer"]
    assert finding["evidence"]["reason"] == "end_of_journal"
    assert finding["evidence"]["status"] == "incomplete"
    assert finding["evidence"]["directions"] == ["CPU_TO_IP_TO_CPU"]
    assert finding["reason"] == (
        "declared runtime edge (2, 0) is missing 1 required hop(s) "
        "['consumer'] (reason 'end_of_journal')")
    certified = rows[MMIO_KEY]
    assert certified["status"] == "certified"
    assert certified["missing"] == []
    assert certified["hop_ids"] == ["producer", "delivery"]


def test_chain_certificate_incomplete_hops_are_listed_with_reasons(tmp_path):
    journal = _merge(_ip_journal(case_index=1).drop("pin8_injection"))
    directory = _write_run(tmp_path / "run", events=journal.events,
                           receipts=[_receipt()],
                           runtime_paths=_chain_runtime_paths(extra_hop=False))
    cross = assertion_class_report(directory)["assertion_classes"][
        CLASS_CROSS_COMPONENT]
    certificates = cross["chain_certificates"]
    assert certificates["incomplete_count"] >= 1
    row = next(item for item in certificates["incomplete_certificates"])
    assert row["certificate_id"]
    assert row["direction"] == "IP_TO_CPU_TO_IP"
    assert row["missing_hops"]
    assert row["missing_hops"][0] == row["first_missing_hop"]
    assert row["hop_ids"] == [hop["hop_id"] for hop in row["hops"]]
    finding = next(item for item in cross["findings"]
                   if item["record_class"] == "chain_certificate_incomplete")
    assert finding["evidence"]["certificate_id"] == row["certificate_id"]
    assert finding["evidence"]["missing_hops"] == row["missing_hops"]
    assert finding["reason"]


def test_cpu_ip_findings_name_exact_records_and_shapes(tmp_path):
    journal = _cpu_ip_events()
    directory = _write_run(tmp_path / "run", events=journal.events,
                           receipts=[_receipt()],
                           runtime_paths=_chain_runtime_paths(extra_hop=False))
    cpu_ip = assertion_class_report(directory)["assertion_classes"][CLASS_CPU_IP]
    counts = cpu_ip["observed_record_counts"]
    assert counts["retirement"] >= 1
    assert counts["retirement_match"] >= 2
    assert counts["irq_sample"] == 1
    by_class = {}
    for row in cpu_ip["findings"]:
        by_class.setdefault(row["record_class"], []).append(row)
    refused = by_class["retirement_observation_refused"][0]
    assert refused["evidence"]["status"] == "rejected"
    assert refused["evidence"]["reason"] == "unsupported_instruction_observation_only"
    assert refused["evidence"]["insn"] == 810618995
    assert refused["evidence"]["pc"] == 65720
    assert refused["evidence"]["order"] == 15
    assert refused["evidence"]["event_id"] > 0
    assert refused["evidence"]["retirement_event_id"] > 0
    untyped = by_class["retirement_origin_untyped"][0]
    assert untyped["evidence"]["instruction_origin_status"] == "unknown"
    assert untyped["evidence"]["retirement_event_id"] > 0
    assert untyped["evidence"]["schema_version"] == "cpu_retirement_match.v1"
    mismatch = by_class["irq_input_expectation_mismatch"][0]
    assert mismatch["evidence"]["expected_input"] == 1
    assert mismatch["evidence"]["actual_post_input"] == 0
    assert mismatch["evidence"]["irq_masked_pre"] == 0
    assert by_class["irq_observed_without_cpu_acceptance"], by_class.keys()
    irq = by_class["irq_observed_without_cpu_acceptance"][0]
    assert irq["evidence"]["trigger_id"]
    assert irq["evidence"]["observation_event_ids"]
    assert irq["evidence"]["acceptance_event_ids"] == []


# ------------------------------------------------- null instead of a fake zero


def test_class_without_data_reports_null_and_reason(tmp_path):
    events = [{"kind": "local_tick_sample", "component": "dev_a",
               "local_tick": 1, "event_id": 1, "outputs": {"out": 0}},
              {"kind": "dataflow_delivery", "source": ["dev_a", "out"],
               "target": ["dev_b", "in"], "event_id": 2, "value": 0}]
    directory = _write_run(tmp_path / "bare", events=events,
                           runtime_paths=None, report=False)
    report = assertion_class_report(directory)
    classes = report["assertion_classes"]
    cpu_ip = classes[CLASS_CPU_IP]
    assert cpu_ip["data_present"] is False
    assert cpu_ip["finding_count"] is None
    assert cpu_ip["findings"] == []
    assert "cpu_ip_behaviour" in cpu_ip["finding_count_reason"]
    assert cpu_ip["observed_record_counts"] == {}
    protocol = classes[CLASS_PROTOCOL_CHECKER]
    assert protocol["data_present"] is False
    assert protocol["finding_count"] is None
    assert "receipts.jsonl" in protocol["finding_count_reason"]
    assert protocol["observed_record_count"] is None
    cross = classes[CLASS_CROSS_COMPONENT]
    assert cross["data_present"] is False
    assert cross["finding_count"] is None
    assert "online_session_manifest.json" in cross["finding_count_reason"]
    assert cross["edge_status"]["available"] is False
    assert cross["chain_certificates"]["certified_count"] == 0
    assert cross["chain_certificates"]["certificate_count"] == 0
    assert report["not_silently_filtered"]["gate"]["passed"] is True


def test_run_without_a_declaration_keeps_the_certificates_it_can_read(tmp_path):
    """A missing declaration must not delete the chain evidence of the trace."""
    journal = _chain_journal()
    directory = _write_run(tmp_path / "no-manifest", events=journal.events,
                           receipts=[_receipt()])
    report = assertion_class_report(directory)
    cross = report["assertion_classes"][CLASS_CROSS_COMPONENT]
    assert cross["data_present"] is True
    assert cross["finding_count"] == 0
    assert cross["edge_status"]["available"] is False
    assert cross["edge_status"]["edges"] == []
    assert "online_session_manifest.json" in \
        cross["edge_status"]["unavailable_reason"]
    assert cross["chain_certificates"]["certified_count"] >= 1
    assert cross["chain_certificates"]["reason"] is None
    assert any("online_session_manifest.json" in row["reason"]
               for row in report["limits"])


def test_measured_zero_is_zero_and_not_null(tmp_path):
    journal = _chain_journal()
    directory = _write_run(tmp_path / "clean", events=journal.events,
                           receipts=[_receipt(case_id="online-1")],
                           runtime_paths=_chain_runtime_paths(extra_hop=False))
    protocol = assertion_class_report(directory)["assertion_classes"][
        CLASS_PROTOCOL_CHECKER]
    assert protocol["data_present"] is True
    assert protocol["finding_count"] == 0
    assert protocol["finding_count_reason"] is None
    assert protocol["observed_record_count"] == 1


# ------------------------------------------- declaration vs expectation split


def test_declaration_constraints_and_check_expectations_are_separate(tmp_path):
    journal = _chain_journal()
    directory = _write_run(tmp_path / "run", events=journal.events,
                           receipts=[_receipt()],
                           runtime_paths=_chain_runtime_paths())
    report = assertion_class_report(directory)
    declaration = report["declaration_constraints"]
    expectations = report["check_expectations"]

    assert set(declaration) == {"run_identity", "decoder_manifest",
                                "runtime_path_contract", "declared_targets",
                                "plan"}
    assert declaration["decoder_manifest"]["sha256"] == _sha256(
        directory / "decoder_manifest.json")
    assert declaration["decoder_manifest"]["flow_by_target"] == {
        "cpu_to_ip_to_cpu.closed_loop": "F4",
        "ip_to_cpu_to_ip.closed_loop": "F5"}
    contract = declaration["runtime_path_contract"]
    assert contract["contract_identity_sha256"]
    assert contract["declared_runtime_edge_count"] == 0
    assert contract["declared_hop_count"] == 3
    assert contract["status"] == "selected_declared_topology_only"
    assert contract["runtime_causality_verified"] is False
    assert [row["direction"] for row in contract["declared_paths"]] == [
        "IP_TO_CPU_TO_IP", "CPU_TO_IP_TO_CPU"]
    assert declaration["declared_targets"][0]["target_id"] == "gpio_a_output_bit0"
    assert declaration["run_identity"]["schema_version"] == \
        "scenario_online_run_identity_envelope.v1"

    assert expectations["run_checker"]["module"] == \
        "myfuzz.scenario.synthetic_checker"
    ids = [row["expectation_id"] for row in expectations["expectations"]]
    assert len(ids) == len(set(ids))
    assert {row["assertion_class"] for row in expectations["expectations"]} == \
        set(ASSERTION_CLASSES)
    for row in expectations["expectations"]:
        assert row["asserts"] and row["declared_by"]
    # A constraint is never an expectation and every finding names its class.
    assert not set(declaration) & set(expectations)
    for section_name in ASSERTION_CLASSES:
        for row in report["assertion_classes"][section_name]["findings"]:
            assert row["expectation_id"] in ids
            assert row["assertion_class"] == section_name


# ------------------------------------------------ fail-closed (never filtered)


def test_not_ready_paths_are_enumerated_not_dropped(tmp_path):
    events = _binding_journal().without("binding_consumer").events
    directory = _write_run(tmp_path / "run", events=events,
                           receipts=[_receipt(), _rejected_receipt()],
                           runtime_paths=_edge_runtime_paths())
    section = assertion_class_report(directory)["not_silently_filtered"]
    assert section["gate"]["passed"] is True
    assert section["unrepresented"] == []
    assert section["abnormal_record_count"] == section["represented_record_count"]
    by_class = section["by_record_class"]
    assert by_class["not_a_runtime_edge"] == 1
    assert by_class["runtime_edge_incomplete"] == 1
    assert by_class["case_refused_before_rtl"] == 1
    refusal = section["cases_refused_before_rtl"][0]
    assert refusal["evidence"]["receipt_index"] == 1
    assert refusal["evidence"]["rejection_code"] == "mmio.window_denied"
    assert refusal["evidence"]["rejection_pointer"] == "mmio.operation"
    assert refusal["evidence"]["candidate_disposition"] == "rejected"
    assert refusal["assertion_class"] is None
    assert "refused before any RTL command" in refusal["reason"]
    not_ready = section["not_ready_declared_paths"]
    assert not_ready["not_a_runtime_edge"][0]["evidence"]["rule_index"] == \
        NOT_A_RUNTIME_KEY[0]
    assert not_ready["incomplete"][0]["evidence"]["missing"] == ["consumer"]
    assert "not dropped" in section["statement"]


def test_unknown_and_incomplete_edges_are_all_enumerated(tmp_path):
    events = _binding_journal().events
    directory = _write_run(tmp_path / "run", events=events,
                           receipts=[_receipt()],
                           runtime_paths=_edge_runtime_paths(causal_only=True))
    report = assertion_class_report(directory)
    cross = report["assertion_classes"][CLASS_CROSS_COMPONENT]
    rows = {(row["rule_index"], row["prerequisite_index"]): row
            for row in cross["edge_status"]["edges"]}
    assert rows[CAUSAL_ONLY_KEY]["status"] == "unknown"
    assert rows[CAUSAL_ONLY_KEY]["reason"] == "declared_shape_unsupported"
    unknown = [row for row in cross["findings"]
               if row["record_class"] == "runtime_edge_unknown"]
    assert [row["evidence"]["rule_index"] for row in unknown] == [CAUSAL_ONLY_KEY[0]]
    section = report["not_silently_filtered"]
    assert section["by_record_class"]["runtime_edge_unknown"] == 1
    assert section["not_ready_declared_paths"]["unknown"][0]["evidence"][
        "reason"] == "declared_shape_unsupported"
    assert section["gate"]["passed"] is True


def test_unclassifiable_abnormal_record_fails_the_gate(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "quarantine", events=journal.events,
        receipts=[_receipt(case_id="online-1"),
                  _receipt(case_id=None, candidate_disposition="quarantined",
                           candidate_disposition_reason="unknown_phase")],
        runtime_paths=_chain_runtime_paths(extra_hop=False))
    section = assertion_class_report(directory)["not_silently_filtered"]
    assert section["gate"]["passed"] is False
    assert section["gate"]["exit_code"] == 2
    assert "quarantined" in section["gate"]["reason"]
    assert section["unrepresented"][0]["record_class"] == \
        "unclassified_abnormal_record"
    assert section["unrepresented"][0]["evidence"]["receipt_index"] == 1
    assert section["abnormal_record_count"] == section["represented_record_count"] + 1


def test_truncated_findings_fail_the_gate(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "truncate", events=journal.events,
        receipts=[_receipt(case_id="online-1",
                           violations=["gpio_b_irq_source_mismatch"],
                           status="dut_violation"),
                  _receipt(case_id="online-2",
                           violations=["gpio_b_padin_read_mismatch"],
                           status="dut_violation")],
        runtime_paths=_chain_runtime_paths(extra_hop=False))
    report = assertion_class_report(directory, max_findings_per_class=1)
    section = report["not_silently_filtered"]
    assert section["gate"]["passed"] is False
    assert "truncat" in section["gate"]["reason"]
    assert section["unrepresented"]
    assert all(row["record_class"] == "truncated_finding"
               for row in section["unrepresented"])
    assert report["assertion_classes"][CLASS_PROTOCOL_CHECKER]["truncated"] is True


def test_uncertain_receipt_is_not_reported_as_refused(tmp_path):
    """``uncertain_effect`` is a shipped refused-looking status, not a refusal."""
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "uncertain", events=journal.events,
        receipts=[_receipt(case_id="online-1",
                           candidate_disposition="uncertain",
                           candidate_disposition_reason="uncertain_effect",
                           status="uncertain_effect")],
        runtime_paths=_chain_runtime_paths(extra_hop=False))
    section = assertion_class_report(directory)["not_silently_filtered"]
    assert section["cases_refused_before_rtl"] == []
    assert len(section["cases_uncertain"]) == 1
    row = section["cases_uncertain"][0]
    assert row["evidence"]["status"] == "uncertain_effect"
    assert row["evidence"]["candidate_disposition"] == "uncertain"
    assert row["evidence"]["rtl_command_observed"] is True
    assert "no unambiguous case result" in row["reason"]
    assert section["gate"]["passed"] is True


# ------------------------------------------------------------------- CLI shape


def _run_cli(directory, out, *extra):
    environment = {"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, str(CLI), "--run", str(directory), "--out", str(out),
         *extra],
        capture_output=True, text=True, env=environment, cwd=str(ROOT))


def test_cli_writes_one_document_and_is_byte_identical(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "run", events=journal.events,
        receipts=[_receipt(case_id="online-1",
                           violations=["gpio_b_irq_source_mismatch"],
                           status="dut_violation")],
        runtime_paths=_chain_runtime_paths())
    first, second = tmp_path / "first.json", tmp_path / "second.json"
    assert _run_cli(directory, first).returncode == 0
    assert _run_cli(directory, second).returncode == 0
    assert first.read_bytes() == second.read_bytes()
    document = json.loads(first.read_text(encoding="utf-8"))
    assert document["schema_version"] == SCHEMA_VERSION
    assert "#" not in first.read_text(encoding="utf-8")


def test_cli_exit_code_is_two_when_the_gate_fails(tmp_path):
    journal = _chain_journal()
    directory = _write_run(
        tmp_path / "quarantine", events=journal.events,
        receipts=[_receipt(candidate_disposition="quarantined",
                           candidate_disposition_reason="unknown_phase")],
        runtime_paths=_chain_runtime_paths(extra_hop=False))
    out = tmp_path / "failed.json"
    completed = _run_cli(directory, out)
    assert completed.returncode == 2
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["not_silently_filtered"]["gate"]["passed"] is False


def test_cli_rejects_a_run_without_a_trace(tmp_path):
    directory = tmp_path / "empty"
    directory.mkdir()
    (directory / "receipts.jsonl").write_text("", encoding="utf-8")
    completed = _run_cli(directory, tmp_path / "out.json")
    assert completed.returncode == 1
    assert not (tmp_path / "out.json").exists()
    assert "trace" in completed.stderr


# --------------------------------------------------------------- real artifacts

REAL_RUN = ROOT / "runs/current-dataflow-p5-chain-acceptance-20261007-online"


@pytest.mark.skipif(not REAL_RUN.is_dir(), reason="saved real run is absent")
def test_real_saved_run_reports_the_three_classes_without_adjacency():
    report = assertion_class_report(REAL_RUN)
    classes = report["assertion_classes"]
    for name in ASSERTION_CLASSES:
        assert classes[name]["data_present"] is True, name
    cross = classes[CLASS_CROSS_COMPONENT]
    edge_status = cross["edge_status"]
    assert edge_status["total"] == (edge_status["declared_runtime_edge_count"]
                                    + edge_status["not_a_runtime_edge_count"])
    assert edge_status["declared_runtime_edge_count"] == 9
    assert edge_status["not_a_runtime_edge_count"] == 6
    assert cross["chain_certificates"]["certified_count"] == 8
    assert cross["chain_certificates"]["incomplete_count"] == 16
    for row in cross["edge_status"]["edges"]:
        assert row["hop_event_ids"] == [hop["event_id"] for hop in row["hops"]]
        assert row["reason"] is None or isinstance(row["reason"], str)
    assert report["not_silently_filtered"]["gate"]["passed"] is True
    assert report["not_silently_filtered"]["by_record_class"][
        "not_a_runtime_edge"] == 6
    cpu_ip = classes[CLASS_CPU_IP]
    assert cpu_ip["observed_record_counts"]["retirement"] > 0
    assert cpu_ip["observed_record_counts"]["irq_sample"] > 0
