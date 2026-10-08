"""UART chain certificates over one saved online trace.

Every positive case is a hand-built journal whose hops are exact identity joins
(``@name`` references resolved once at build time); negative cases drop, add or
tamper single hops and require fail-closed ``incomplete`` certificates, named
first missing hops and counted refusals. The same fixture is materialised both
as a JSONL run directory and as a monolithic ``online_final_trace.json`` so the
streaming reader and the producer are exercised together.

Nothing here starts RTL, a fuzzer or Verilator: the fixture is a synthetic
artifact written into ``tmp_path``.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.scenario.source_provenance import SourceAdmission
from myfuzz.scenario.uart_chain_certificates import (
    CERTIFIED,
    DIRECTION,
    INCOMPLETE,
    SCHEMA_VERSION,
    UART_COMPONENT,
    UART_HOPS,
    UART_HOP_ORDER,
    UartChainCertificates,
    uart_chain_certificates,
)


ROOT = Path(__file__).resolve().parents[2]

# Independent copy of the frozen hop contract the module must declare.
HOPS = (
    "uart_source_admission",
    "uart_source_injection",
    "uart_frame_admission",
    "uart_source_frame_begin",
    "uart_rx_receiver_start",
    "uart_rx_receiver_complete",
    "uart_fifo_push",
    "uart_irq_update",
    "uart_source_frame_end",
    "uart_frame_validation",
    "uart_irq_binding_delivery",
    "uart_cpu_irq_sample",
    "uart_cpu_irq_taken",
    "uart_fifo_pop",
    "uart_rdata_access",
    "uart_retired_read_match",
)

CASE_ID = "online-0-af5570f5a1810b7af78caf4b"
CASE_INDEX = 1
ENDPOINT_CASE_ID = "online-1-819b265ed890cbfc934efd3e"
ENDPOINT_CASE_INDEX = 2
ACTION = f"{CASE_ID}:uart.external_rx_byte"
FRAME = "uart-frame:0:1"
ENTRY = ["uart", 0, 0, 2]
RECEIVER = ["uart", 0, 1]
VALUE = 0x5A
ADDRESS = 1073741848
WINDOW_BASE = 1073741824
WINDOW_SIZE = 4096
SOURCE_KEY = ["uart", 0, "rx_watermark", 1]
TRANSACTION = {"channel_id": "data", "execution_id": "local-execution",
               "source_component": "cpu", "source_epoch": 0,
               "source_sequence": 5, "testcase_id": "ibex-uart-online-stream"}
EXECUTION = "local-execution"

ADMISSION = SourceAdmission.create(
    case_id=CASE_ID, case_index=CASE_INDEX, source_id="uart.external_rx_byte",
    path_id="336a8cd3ec99de1a143944a912bcfb379d27c1e90a3d18169a6c2b5c8b2b3453",
    direction="IP_TO_CPU", component="uart", action_id=ACTION,
    role="fuzz_source", input_kind="source_event",
    input_sha256="be28a36b9022c3b23483de359b122922731bf8e1b4940cfe27ea8aef26e78685")


def _provenance(case_id, case_index, *, origin="unknown", admissions=()):
    return {"schema_version": "event_source_provenance.v1",
            "observed_case": {"case_id": case_id, "case_index": case_index},
            "origin_status": origin, "origin_admission_ids": list(admissions),
            "invalid_origin_references": 0, "unknown_writer_ids": [],
            "edge_candidates": [], "resource": None,
            "proof_scope": "observation_only"}


def _tick(local_tick):
    return {"kind": "uart_tick_observation", "component": "uart",
            "reset_epoch": 0, "local_tick": local_tick}


def _access_context(access_id="uart-access:uart:0:4"):
    return {"access_id": access_id, "source_transaction": dict(TRANSACTION),
            "raw_offset": 24, "byte_enable": 15, "address": ADDRESS,
            "window_base": WINDOW_BASE, "window_size": WINDOW_SIZE,
            "write": False, "route_context_mode": "router",
            "delivery_context": {"source_transaction": dict(TRANSACTION),
                                 "device_id": "uart", "address": ADDRESS,
                                 "offset": 24, "write": False, "be": 15,
                                 "value": 0, "window_base": WINDOW_BASE,
                                 "window_size": WINDOW_SIZE}}


def _irq_input_context():
    return {"schema_version": "native_irq_input_context.v1",
            "binding_delivery_event_id": "@delivery", "expected_input": 1,
            "source_output_key": list(SOURCE_KEY), "target_component": "cpu",
            "target_epoch": 0}


def uart_journal(*, case_id=CASE_ID, case_index=CASE_INDEX,
                 endpoint_case_id=ENDPOINT_CASE_ID,
                 endpoint_case_index=ENDPOINT_CASE_INDEX,
                 admission=ADMISSION, with_irq=True, with_read=True,
                 with_assertion=None, value=VALUE, drop=(), patch=None,
                 extra=(), suffix=1, tag=""):
    """One UART frame journal, ordered exactly like the saved artifact."""
    if with_assertion is None:
        with_assertion = with_irq
    frame = "uart-frame:0:%d" % suffix
    entry = [UART_COMPONENT, 0, 0, 2 * suffix]
    receiver = [UART_COMPONENT, 0, 2 * suffix - 1]
    access_id = "uart-access:uart:0:%d" % (3 * suffix + 1)
    journal = _Journal(tag)
    journal.add("tick_admission", _tick(1))
    journal.add("admission", {
        "kind": "source_admission", "component": "uart", "reset_epoch": 0,
        "local_tick": 1, "admission": admission.document(),
        "provenance": _provenance(case_id, case_index, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("injection", {
        "kind": "source_injection", "component": "uart", "reset_epoch": 0,
        "local_tick": 1, "action_id": admission.action_id,
        "direction": "IP_TO_CPU", "port": "uart_rx_byte", "value": value,
        "bit_offset": 0, "width": 8, "source_ref": "external_uart_rx_byte",
        "provenance": _provenance(case_id, case_index, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("frame_admission", {
        "kind": "uart_source_frame_admission", "component": "uart",
        "reset_epoch": 0, "local_tick": 2, "frame_id": frame,
        "action_id": admission.action_id, "byte": value, "port": "uart_rx_byte",
        "bit_offset": 0, "width": 8, "start_tick": 10, "end_tick": 20,
        "fifo_origin": "rx", "frame_semantics": "8n1",
        "session_case_id": case_id,
        "provenance": _provenance(case_id, case_index, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("frame_begin", {
        "kind": "uart_source_frame_begin", "component": "uart",
        "reset_epoch": 0, "local_tick": 3, "frame_id": frame,
        "action_id": admission.action_id, "byte": value, "port": "uart_rx_byte",
        "bit_offset": 0, "width": 8,
        "provenance": _provenance(case_id, case_index, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("tick_start", _tick(4))
    journal.add("receiver_start", {
        "kind": "uart_rx_receiver_start", "component": "uart", "reset_epoch": 0,
        "local_tick": 5, "receiver_id": list(receiver),
        "observation_event_id": "@tick_start",
        "config": [1, 32768, 0, 0, 0, 0, 0],
        "input_ref": {"frame_id": frame, "action_id": admission.action_id,
                      "admission_id": admission.admission_id, "bit_index": 0,
                      "bit_value": 0, "drive_tick": 4,
                      "receipt_id": {"execution": "local-driver:uart:1",
                                     "sequence": 3}}})
    journal.add("tick_complete", _tick(6))
    journal.add("receiver_complete", {
        "kind": "uart_rx_receiver_complete", "component": "uart",
        "reset_epoch": 0, "local_tick": 7, "receiver_id": list(receiver),
        "observation_event_id": "@tick_complete", "value": value,
        "frame_error": 0, "parity_error": 0, "sample_refs": [],
        "provenance": _provenance(case_id, case_index)})
    journal.add("tick_push", _tick(8))
    journal.add("push", {
        "kind": "uart_fifo_push", "component": "uart", "reset_epoch": 0,
        "local_tick": 8, "entry_id": list(entry), "frame_id": frame,
        "receiver_id": list(receiver), "completion_event": "@tick_complete",
        "observation_event_id": "@tick_push", "value": value,
        "retained": True,
        "provenance": _provenance(endpoint_case_id, endpoint_case_index)})
    if with_assertion:
        journal.add("update", {
            "kind": "uart_irq_update", "schema_version": "uart_irq_update.v1",
            "component": "uart", "reset_epoch": 0, "local_tick": 9,
            "irq_class": "rx_watermark", "pre_output": 0, "post_output": 1,
            "pre_state": 0, "post_state": 1, "pre_enable": 1, "pre_test": 0,
            "pre_test_qe": 0, "pre_watermark_test": 0, "post_watermark_test": 0,
            "watermark_threshold": 1, "watermark_level": 0, "pre_depth": 1,
            "pre_entry_ids": [list(entry)], "origin_status": "unknown",
            "proof_scope": "native_irq_cause_observation"})
        journal.add("definition", {
            "kind": "uart_irq_output_definition",
            "schema_version": "uart_irq_output_definition.v1",
            "component": "uart", "reset_epoch": 0, "local_tick": 9,
            "source_output_key": list(SOURCE_KEY), "value": 1,
            "pre_entry_ids": [list(entry)], "trusted_definition": True,
            "irq_update_event_id": "@update",
            "definition_observation_event_id": "@tick_push",
            "producer_event_id": "@update", "observation_event_id": "@tick_push"})
    journal.add("frame_end", {
        "kind": "uart_source_frame_end", "component": "uart", "reset_epoch": 0,
        "local_tick": 10, "frame_id": frame, "action_id": admission.action_id,
        "byte": value, "port": "uart_rx_byte", "bit_offset": 0, "width": 8,
        "start_tick": 10, "end_tick": 20, "waveform_matched": True,
        "mismatch_count": 0, "sample_count": 320, "bit_witness": [],
        "provenance": _provenance(case_id, case_index, origin="known",
                                  admissions=[admission.admission_id])})
    journal.add("frame_validation", {
        "kind": "uart_frame_validation", "component": "uart", "reset_epoch": 0,
        "local_tick": 11, "frame_id": frame, "action_id": admission.action_id,
        "admission_id": admission.admission_id, "byte": value,
        "port": "uart_rx_byte", "bit_offset": 0, "width": 8,
        "waveform_matched": True, "source_drive_refs": [{"bit_index": index}
                                                        for index in range(10)],
        "command_scope": {"component": "uart", "reset_epoch": 0,
                          "command_sequence": 4},
        "provenance": _provenance(case_id, case_index)})
    if with_irq:
        journal.add("delivery", {
            "kind": "native_irq_binding_delivery",
            "schema_version": "native_irq_binding_delivery.v1",
            "source_component": "uart", "source_epoch": 0,
            "source_local_tick": 9, "source_phase": "post",
            "source_observation_event_id": "@tick_push",
            "source_receipt_ref": {"command_scope": {"component": "uart",
                                                     "reset_epoch": 0,
                                                     "command_sequence": 4},
                                   "local_tick": 9, "phase": "post"},
            "irq_class": "rx_watermark", "target_component": "cpu",
            "target_epoch": 0, "target_port": "irq",
            "source_port": "uart_rx_watermark", "width": 1,
            "source_bit_offset": 0, "target_bit_offset": 0, "value": 1,
            "source_output_key": list(SOURCE_KEY),
            "dataflow_delivery_event_id": "@tick_push"})
        journal.add("sample", {
            "kind": "cpu_external_irq_sample",
            "schema_version": "cpu_external_irq_sample.v1", "component": "cpu",
            "reset_epoch": 0, "local_tick": 12,
            "command_scope": {"component": "cpu", "reset_epoch": 0,
                              "command_sequence": 12},
            "receipt_id": {"execution": "local-driver:cpu:1", "sequence": 12},
            "expected_input": 1, "actual_pre_input": 1, "actual_post_input": 1,
            "irq_masked_pre": 0, "irq_taken_pre": 1,
            "binding_delivery_event_id": "@delivery",
            "source_output_key": list(SOURCE_KEY),
            "input_context": _irq_input_context()})
        journal.add("take", {
            "kind": "cpu_external_irq_taken",
            "schema_version": "cpu_external_irq_taken.v1", "component": "cpu",
            "reset_epoch": 0, "local_tick": 12,
            "command_scope": {"component": "cpu", "reset_epoch": 0,
                              "command_sequence": 12},
            "receipt_id": {"execution": "local-driver:cpu:1", "sequence": 12},
            "expected_input": 1, "actual_pre_input": 1, "actual_post_input": 1,
            "irq_masked_pre": 0, "irq_taken_pre": 1,
            "binding_delivery_event_id": "@delivery", "sample_event_id": "@sample",
            "sample_ref": {"command_scope": {"component": "cpu",
                                             "reset_epoch": 0,
                                             "command_sequence": 12},
                           "local_tick": 12},
            "take_key": ["cpu", 0, 1], "source_output_key": list(SOURCE_KEY),
            "input_context": _irq_input_context(),
            "irq_serial_observation": {"schema_version":
                                       "ibex_irq_serial_observation.v1",
                                       "decision": {"status": "observed",
                                                    "value": 1},
                                       "retirement": {"status": "observed",
                                                      "value": 0},
                                       "zero_semantics":
                                       "no_provable_source_lineage"}})
    if with_read:
        journal.add("tick_response", _tick(13))
        journal.add("tick_pop", _tick(14))
        journal.add("pop", {
            "kind": "uart_fifo_pop", "component": "uart", "reset_epoch": 0,
            "local_tick": 15, "entry_id": list(entry), "value": value,
            "observation_event_id": "@tick_pop", "clear": False,
            "access": _access_context(access_id)})
        journal.add("access", {
            "kind": "uart_rdata_access", "component": "uart", "reset_epoch": 0,
            "local_tick": 16, "access_id": access_id,
            "source_transaction": dict(TRANSACTION), "raw_offset": 24,
            "write": False, "byte_enable": 15, "address": ADDRESS,
            "window_base": WINDOW_BASE, "window_size": WINDOW_SIZE,
            "route_context_mode": "router", "read_value": value, "error": 0,
            "actual_request_event_id": "@tick_pop",
            "actual_response_event_id": "@tick_response", "request_tick": 14,
            "response_tick": 15,
            "command_scope": {"component": "uart", "reset_epoch": 0,
                              "command_sequence": 4},
            "delivery_context": _access_context(access_id)["delivery_context"],
            "provenance": _provenance(endpoint_case_id, endpoint_case_index)})
        journal.add("read_proof", {
            "kind": "uart_consumption_match",
            "schema_version": "uart_consumption_match.v1", "component": "uart",
            "reset_epoch": 0, "local_tick": 16, "status": "accepted",
            "proof_scope": "uart_fifo_read_consumption", "entry_id": list(entry),
            "frame_id": frame, "read_value": value, "access_event": "@access",
            "pop_event": "@tick_pop", "request_event": "@tick_pop",
            "response_event": "@tick_response",
            "source_transaction": dict(TRANSACTION)})
        journal.add("retire", {"kind": "cpu_retire", "component": "cpu",
                               "reset_epoch": 0, "local_tick": 17})
        journal.add("retire_match", {"kind": "cpu_retirement_match",
                                     "component": "cpu", "status": "accepted",
                                     "reset_epoch": 0, "local_tick": 18})
        journal.add("retired_read_match", {
            "kind": "uart_retired_read_match",
            "schema_version": "uart_retired_read_match.v1", "status": "accepted",
            "proof_scope": "cpu_retired_uart_rdata_read",
            "entry_id": list(entry), "frame_id": frame, "read_value": value,
            "destination_register": 3, "insn": 25207171, "pc": 66096,
            "order": 81, "retirement_event_id": "@retire",
            "retirement_match_event_id": "@retire_match",
            "uart_read_proof_event_id": "@read_proof",
            "uart_access_event_id": "@access",
            "uart_request_event_id": "@tick_pop",
            "uart_response_event_id": "@tick_response",
            "fullkey": dict(TRANSACTION),
            "graph_path_certified": True,
            "cpu_scope": {"execution_id": EXECUTION, "source_component": "cpu",
                          "source_epoch": 0},
            "source_admission": admission.document(),
            "observation_event_id": "@retire_match",
            "provenance": _provenance(endpoint_case_id, endpoint_case_index)})
    for name in drop:
        journal.drop(name)
    for row_name, fields in (patch or {}).items():
        journal.patch(row_name, fields)
    for name, event in extra:
        journal.add(name, event)
    return journal


class _Journal:
    """Ordered journal builder with lazily assigned symbolic event references."""

    def __init__(self, tag=""):
        self._rows = []
        self._built = None
        self._tag = tag

    def add(self, name, event):
        self._rows.append([name, dict(event), self._tag])
        self._built = None

    def extend(self, other):
        """Append another journal's rows; event ids are assigned once, later."""
        self._rows.extend([list(row) for row in other._rows])
        self._built = None

    def drop(self, name):
        self._rows = [row for row in self._rows if row[0] != name]
        self._built = None

    def patch(self, name, fields):
        for row in self._rows:
            if row[0] == name:
                row[1].update(fields)
        self._built = None

    @property
    def events(self):
        return self._build()[0]

    @property
    def ids(self):
        return self._build()[1]

    def _build(self):
        if self._built is None:
            ids = {}
            for position, (name, _, tag) in enumerate(self._rows, 1):
                if name is not None:
                    key = tag + name
                    assert key not in ids, key
                    ids[key] = position
            events = []
            for position, (_, event, tag) in enumerate(self._rows, 1):
                resolved = _resolve(event, ids, tag)
                resolved["event_id"] = position
                events.append(resolved)
            self._built = (events, ids)
        return self._built


def _resolve(value, ids, tag=""):
    if isinstance(value, str) and value.startswith("@"):
        name, _, delta = value[1:].partition("+")
        key = tag + name
        assert key in ids, name
        return ids[key] + (int(delta) if delta else 0)
    if isinstance(value, dict):
        return {key: _resolve(item, ids, tag) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve(item, ids, tag) for item in value]
    return value


def _consume(journal, **kwargs):
    """All certificates of one journal, settled at end of stream."""
    producer = UartChainCertificates(**kwargs)
    certificates = list(producer.ingest(journal.events))
    certificates.extend(producer.flush())
    return producer, certificates


def _single(journal, **kwargs):
    producer, certificates = _consume(journal, **kwargs)
    assert len(certificates) == 1, certificates
    return producer, certificates[0]


def _write_run(directory, journal, *, monolithic=False):
    directory.mkdir(parents=True, exist_ok=True)
    events = journal.events
    if monolithic:
        (directory / "online_final_trace.json").write_text(json.dumps(
            {"events": events, "local_ticks": {"uart": 20, "cpu": 20},
             "status": "complete"}), encoding="utf-8")
        return directory
    (directory / "online_events.jsonl").write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8")
    (directory / "online_final_trace.meta.json").write_text(json.dumps({
        "schema_version": "online_trace_jsonl.v1",
        "events_file": "online_events.jsonl", "event_count": len(events),
        "status": "complete"}), encoding="utf-8")
    return directory


def _cli(*arguments):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{ROOT / 'src'}:{ROOT}"
    return subprocess.run(
        (sys.executable, str(ROOT / "scripts/report_uart_chain_certificates.py"),
         *(str(argument) for argument in arguments)),
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=300)


def _document_bytes(document):
    return json.dumps(document, sort_keys=True, indent=1).encode("utf-8")


# ------------------------------------------------------------------ contract


def test_declared_hop_sequence_is_the_frozen_contract():
    assert UART_HOPS == HOPS
    assert len(set(UART_HOPS)) == len(UART_HOPS)
    assert DIRECTION == "IP_TO_CPU"
    assert SCHEMA_VERSION == "runtime_uart_chain_certificate.v1"
    # Every enforced ordering edge must hold along the declared linear order,
    # which is what makes the declared order a topological order of the DAG.
    position = {hop: index for index, hop in enumerate(UART_HOPS)}
    for before, after in UART_HOP_ORDER:
        assert before in position and after in position
        assert position[before] < position[after], (before, after)


def test_bounds_must_be_positive_integers():
    for kwargs in ({"max_pending": 0}, {"max_event_gap": 0},
                   {"max_pending": True}, {"max_event_gap": "wide"}):
        with pytest.raises(ValueError):
            UartChainCertificates(**kwargs)


# ------------------------------------------------------------- full chain


def test_full_chain_emits_one_certified_certificate():
    producer, certificate = _single(uart_journal())

    assert certificate["schema_version"] == SCHEMA_VERSION
    assert certificate["status"] == CERTIFIED
    assert certificate["direction"] == DIRECTION
    assert certificate["source_admission_id"] == ADMISSION.admission_id
    assert certificate["source_action_id"] == ACTION
    assert certificate["source_id"] == "uart.external_rx_byte"
    assert certificate["source_case_id"] == CASE_ID
    assert certificate["source_case_index"] == CASE_INDEX
    assert certificate["frame_id"] == FRAME
    assert certificate["entry_id"] == ENTRY
    assert certificate["missing_hops"] == []
    assert certificate["first_missing_hop"] is None
    assert certificate["first_missing_hop_reason"] == (
        "all_required_hops_witnessed")
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(HOPS)
    assert certificate["irq_mode"] == "irq_taken"
    assert certificate["proof_scope"] == "saved_artifact_uart_witness_chain"
    assert certificate["not_proof_of"]
    assert any("no other behaviour" in entry
               for entry in certificate["not_proof_of"])
    assert certificate["settled_reason"] == "required_hops_completed"
    assert certificate["completed_event_id"] > 0
    document = producer.document()
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["hop_sequence"] == list(HOPS)
    assert document["certified_total"] == 1
    assert document["incomplete_total"] == 0
    assert document["candidates_total"] == 1
    assert document["by_status"] == {CERTIFIED: 1, INCOMPLETE: 0}
    assert document["first_missing_hop_histogram"] == {}
    assert document["refusals_total"] == 0
    assert document["refusals_by_reason"] == {}
    assert document["self_consistent"] is True
    assert document["limits"]
    assert all(limit["value"] for limit in document["limits"])
    for hop in HOPS:
        assert document["witness_counts"][hop] == 1
    assert document["hop_event_counts"]["uart_fifo_push"] == 1
    assert document["hop_event_counts"]["uart_irq_update"] == 1
    assert document["hop_event_counts"]["uart_retired_read_match"] == 1


def test_every_hop_carries_its_exact_evidence_event():
    journal = uart_journal()
    ids = journal.ids
    _, certificate = _single(journal)
    observed = {hop["hop_id"]: hop for hop in certificate["hops"]}
    for hop in HOPS:
        assert "event_id" in observed[hop]
    assert observed["uart_source_admission"]["event_id"] == ids["admission"]
    assert observed["uart_source_injection"]["event_id"] == ids["injection"]
    assert observed["uart_frame_admission"]["event_id"] == ids["frame_admission"]
    assert observed["uart_source_frame_begin"]["event_id"] == ids["frame_begin"]
    assert observed["uart_rx_receiver_start"]["event_id"] == ids["receiver_start"]
    assert observed["uart_rx_receiver_complete"]["event_id"] == ids["receiver_complete"]
    assert observed["uart_fifo_push"]["event_id"] == ids["push"]
    assert observed["uart_irq_update"]["event_id"] == ids["update"]
    assert observed["uart_source_frame_end"]["event_id"] == ids["frame_end"]
    assert observed["uart_frame_validation"]["event_id"] == ids["frame_validation"]
    assert observed["uart_irq_binding_delivery"]["event_id"] == ids["delivery"]
    assert observed["uart_cpu_irq_sample"]["event_id"] == ids["sample"]
    assert observed["uart_cpu_irq_taken"]["event_id"] == ids["take"]
    assert observed["uart_fifo_pop"]["event_id"] == ids["pop"]
    assert observed["uart_rdata_access"]["event_id"] == ids["access"]
    assert observed["uart_retired_read_match"]["event_id"] == ids["retired_read_match"]
    assert observed["uart_fifo_push"]["evidence"]["entry_id"] == ENTRY
    assert observed["uart_fifo_push"]["evidence"]["value"] == VALUE
    assert observed["uart_rdata_access"]["evidence"]["address"] == ADDRESS
    assert observed["uart_rdata_access"]["evidence"]["raw_offset"] == 24
    assert observed["uart_cpu_irq_taken"]["evidence"]["source_output_key"] == SOURCE_KEY
    assert observed["uart_retired_read_match"]["evidence"]["destination_register"] == 3
    # Hop event ids respect every enforced ordering edge.
    edges = set(UART_HOP_ORDER)
    for before, after in edges:
        assert observed[before]["event_id"] < observed[after]["event_id"], (before, after)


def test_certificate_id_is_the_canonical_admission_and_frame_digest():
    _, certificate = _single(uart_journal())
    expected = hashlib.sha256(json.dumps(
        [DIRECTION, ADMISSION.admission_id, FRAME],
        separators=(",", ":")).encode("utf-8")).hexdigest()
    assert certificate["certificate_id"] == expected


def test_cross_case_link_is_only_claimed_when_cases_really_differ():
    _, differing = _single(uart_journal())
    assert differing["source_case_id"] == CASE_ID
    assert differing["endpoint_case_id"] == ENDPOINT_CASE_ID
    assert differing["endpoint_case_source"] == "uart_retired_read_match"
    assert differing["cross_case"] is True
    assert differing["cross_case_reason"] is None

    _, same = _single(uart_journal(endpoint_case_id=CASE_ID,
                                   endpoint_case_index=CASE_INDEX))
    assert same["cross_case"] is False
    assert same["cross_case_reason"] == "source_and_endpoint_case_ids_match"


def test_bootstrap_admission_role_is_recorded_and_certified():
    bootstrap = SourceAdmission.create(
        case_id="uart-fixed-warmup", case_index=0,
        source_id="uart.external_rx_byte",
        path_id=ADMISSION.path_id, direction="IP_TO_CPU", component="uart",
        action_id="uart-fixed-warmup-rx", role="bootstrap",
        input_kind="source_event", input_sha256=ADMISSION.input_sha256)
    _, certificate = _single(uart_journal(
        admission=bootstrap, case_id="uart-fixed-warmup", case_index=0))
    assert certificate["status"] == CERTIFIED
    assert certificate["source_role"] == "bootstrap"


# ------------------------------------------------------- missing hops


def test_missing_hop_is_incomplete_with_named_first_missing_hop():
    producer, certificate = _single(uart_journal(drop=("frame_begin",)))

    assert certificate["status"] == INCOMPLETE
    assert certificate["first_missing_hop"] == "uart_source_frame_begin"
    assert certificate["first_missing_hop_reason"] is None
    assert certificate["missing_hops"] == list(HOPS[3:])
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(HOPS[:3])
    assert certificate["settled_reason"] == "journal_end"
    document = producer.document()
    assert document["first_missing_hop_histogram"] == {
        "uart_source_frame_begin": 1}
    assert document["incomplete_total"] == 1
    assert document["certified_total"] == 0


def test_missing_admission_leaves_the_frame_candidate_tracked():
    journal = uart_journal(drop=("admission", "injection"))
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["first_missing_hop"] == "uart_source_admission"
    # Frozen truncation rule: with the very first required hop absent, every
    # required hop is absent from the emitted prefix. The witnessed ones stay
    # visible in witnessed_hop_ids.
    assert certificate["missing_hops"] == list(HOPS)
    assert certificate["witnessed_hop_ids"] == list(HOPS[2:])
    assert producer.document()["candidates_total"] == 1


def test_missing_terminal_hop_is_incomplete():
    _, certificate = _single(uart_journal(drop=("retired_read_match",)))
    assert certificate["status"] == INCOMPLETE
    assert certificate["first_missing_hop"] == "uart_retired_read_match"
    assert certificate["missing_hops"] == ["uart_retired_read_match"]


# ---------------------------------------------------------- IRQ leg honesty


def test_asserted_watermark_without_a_take_names_the_binding_hop():
    journal = uart_journal(with_irq=False, with_assertion=True)
    ids = journal.ids
    producer, certificate = _single(journal)
    # The assertion itself is witnessed by the definition, never by adjacency.
    assert certificate["status"] == INCOMPLETE
    assert certificate["first_missing_hop"] == "uart_irq_binding_delivery"
    assert certificate["missing_hops"] == list(HOPS[10:])
    assert certificate["irq_mode"] == "irq_asserted_no_take"
    assert certificate["irq_mode_reason"] == (
        "watermark_asserted_while_entry_was_queue_head_without_a_joined_take")
    assert certificate["read_chain_state"] == "witnessed"
    assert certificate["polling_consistent"] is True
    assert certificate["polling_consistent_reason"] == (
        "irq_asserted_without_a_joined_take_while_the_read_chain_completed")
    assert any("not prove the CPU took an interrupt" in entry
               for entry in certificate["not_proof_of"])
    update = next(hop for hop in certificate["hops"]
                  if hop["hop_id"] == "uart_irq_update")
    assert update["event_id"] == ids["update"]
    assert update["evidence"]["attribution"] == "queue_head_entry"
    assert update["evidence"]["source_output_key"] == SOURCE_KEY
    assert update["evidence"]["definition_event_id"] == ids["definition"]
    assert producer.document()["irq_mode_histogram"] == {
        "irq_asserted_no_take": 1}
    # The witnessed read chain stays visible even though the required prefix
    # is truncated at the first missing hop.
    assert [hop["hop_id"] for hop in certificate["hops"]] == list(HOPS[:10])
    assert certificate["witnessed_hop_ids"] == [
        "uart_source_admission", "uart_source_injection", "uart_frame_admission",
        "uart_source_frame_begin", "uart_rx_receiver_start",
        "uart_rx_receiver_complete", "uart_fifo_push", "uart_irq_update",
        "uart_source_frame_end", "uart_frame_validation", "uart_fifo_pop",
        "uart_rdata_access", "uart_retired_read_match"]


def test_no_irq_witness_at_all_is_polling_consistent_not_a_causal_claim():
    producer, certificate = _single(uart_journal(with_irq=False),
                                    require_irq_leg=False)
    assert certificate["status"] == CERTIFIED
    assert certificate["missing_hops"] == []
    assert certificate["irq_mode"] == "no_irq_witness"
    assert certificate["irq_mode_reason"] == (
        "no_watermark_assertion_named_this_entry_as_queue_head")
    assert certificate["read_chain_state"] == "witnessed"
    assert certificate["polling_consistent"] is True
    assert certificate["polling_consistent_reason"] == (
        "read_chain_witnessed_without_any_irq_witness_for_this_entry")
    assert any("not prove the CPU took an interrupt" in entry
               for entry in certificate["not_proof_of"])
    assert producer.document()["certified_total"] == 1
    assert producer.document()["irq_mode_histogram"] == {"no_irq_witness": 1}


def test_irq_taken_is_never_reported_as_polling_consistent():
    _, certificate = _single(uart_journal())
    assert certificate["irq_mode"] == "irq_taken"
    assert certificate["irq_mode_reason"] == (
        "cpu_external_irq_taken_joined_to_queue_head_entry")
    assert certificate["polling_consistent"] is False
    assert certificate["polling_consistent_reason"] == (
        "cpu_irq_take_joined_to_this_entry")


def test_cpu_irq_take_scope_contradicting_the_retirement_is_refused():
    journal = uart_journal()
    ids = journal.ids
    journal.patch("retired_read_match", {
        "cpu_scope": {"execution_id": EXECUTION, "source_component": "cpu",
                      "source_epoch": 9}})
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "cpu_irq_take_scope_mismatch"
    assert producer.document()["refusals_by_reason"] == {
        "cpu_irq_take_scope_mismatch": 1}
    assert "uart_cpu_irq_taken" in producer.document()["refused_hops"]
    assert certificate["missing_hops"]
    assert ids["take"] < ids["access"]


# ------------------------------------------------------------- refusals


def test_contradicting_byte_join_is_refused_never_accepted():
    journal = uart_journal()
    journal.patch("frame_validation", {"byte": VALUE ^ 0xFF})
    producer, certificate = _single(journal)

    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "uart_frame_byte_mismatch"
    assert "uart_frame_validation" not in [
        hop["hop_id"] for hop in certificate["hops"]]
    document = producer.document()
    assert document["refusals_total"] == 1
    assert document["refusals_by_reason"] == {"uart_frame_byte_mismatch": 1}
    assert document["refused_hops"] == ["uart_frame_validation"]
    assert document["refusals"][0]["hop_id"] == "uart_frame_validation"
    assert document["refusals"][0]["reason"] == "uart_frame_byte_mismatch"
    assert document["refusals"][0]["event_id"] == journal.ids["frame_validation"]
    assert document["certified_total"] == 0
    assert document["first_missing_hop_histogram"] == {
        "uart_frame_validation": 1}


def test_second_push_for_one_frame_is_refused():
    journal = uart_journal(drop=("retire", "retire_match", "read_proof",
                                 "pop", "access", "retired_read_match"))
    duplicate = {"kind": "uart_fifo_push", "component": "uart",
                 "reset_epoch": 0, "local_tick": 21,
                 "entry_id": ["uart", 0, 0, 99], "frame_id": FRAME,
                 "receiver_id": list(RECEIVER),
                 "completion_event": "@tick_complete",
                 "observation_event_id": "@tick_pop", "value": VALUE,
                 "retained": True}
    journal.add("second_push", duplicate)
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "conflicting_uart_fifo_push"
    assert producer.document()["refusals_by_reason"] == {
        "conflicting_uart_fifo_push": 1}
    assert producer.document()["refusals"][0]["event_id"] == len(journal.events)
    assert producer.document()["refused_hops"] == ["uart_fifo_push"]


def test_receiver_value_contradiction_is_refused():
    journal = uart_journal()
    journal.patch("receiver_complete", {"value": VALUE ^ 0x01})
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "receiver_byte_mismatch"
    assert producer.document()["refusals_by_reason"] == {
        "receiver_byte_mismatch": 1}


def test_frame_error_completion_never_certifies():
    journal = uart_journal()
    journal.patch("receiver_complete", {"frame_error": 1})
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "receiver_error_flags"
    assert producer.document()["refusals_by_reason"] == {
        "receiver_error_flags": 1}


def test_retired_read_value_contradiction_is_refused():
    journal = uart_journal()
    journal.patch("retired_read_match", {"read_value": VALUE ^ 0x02})
    producer, certificate = _single(journal)
    assert certificate["status"] == INCOMPLETE
    assert certificate["contradiction_reason"] == "retired_read_value_mismatch"
    assert producer.document()["refusals_by_reason"] == {
        "retired_read_value_mismatch": 1}


def test_contradiction_after_settlement_is_still_counted():
    journal = uart_journal()
    ids = journal.ids
    producer = UartChainCertificates()
    settled = list(producer.ingest(journal.events))
    assert [row["status"] for row in settled] == [CERTIFIED]
    late = dict(_resolve({"kind": "uart_frame_validation", "component": "uart",
                          "reset_epoch": 0, "local_tick": 30,
                          "frame_id": FRAME, "action_id": ACTION,
                          "admission_id": ADMISSION.admission_id,
                          "byte": VALUE ^ 0x0F, "port": "uart_rx_byte",
                          "waveform_matched": True,
                          "provenance": _provenance(CASE_ID, CASE_INDEX)},
                         ids))
    late["event_id"] = len(journal.events) + 1
    assert list(producer.ingest([late])) == []
    document = producer.document()
    assert document["refusals_total"] == 1
    assert document["refusals"][0]["reason"] == "contradicts_settled_certificate"
    assert document["refusals"][0]["certificate_id"] == settled[0]["certificate_id"]
    assert document["certified_total"] == 1


# -------------------------------------------------------------- bounds


def test_max_pending_eviction_settles_the_oldest_candidate_incomplete():
    """Two tagged frames in one journal: the second evicts the first."""
    producer = UartChainCertificates(max_pending=1)
    merged = uart_journal(tag="a_", drop=("retire", "retire_match", "read_proof",
                                         "pop", "access", "retired_read_match"))
    merged.extend(uart_journal(
        tag="b_", suffix=2, case_id="online-2", case_index=2,
        admission=SourceAdmission.create(
            case_id="online-2", case_index=2, source_id="uart.external_rx_byte",
            path_id=ADMISSION.path_id, direction="IP_TO_CPU", component="uart",
            action_id="online-2:uart.external_rx_byte", role="fuzz_source",
            input_kind="source_event", input_sha256=ADMISSION.input_sha256)))
    # A trailing record that names the evicted frame with a contradicting byte.
    late = _Journal("c_")
    late.add("late_frame_end", {
        "kind": "uart_source_frame_end", "component": "uart", "reset_epoch": 0,
        "local_tick": 30, "frame_id": "uart-frame:0:1", "action_id": ACTION,
        "byte": 1, "port": "uart_rx_byte", "waveform_matched": True,
        "provenance": _provenance(CASE_ID, CASE_INDEX)})
    merged.extend(late)

    emitted = list(producer.ingest(merged.events))
    assert [row["status"] for row in emitted] == [INCOMPLETE, CERTIFIED]
    evicted = emitted[0]
    assert evicted["settled_reason"] == "evicted_by_max_pending"
    assert evicted["source_case_index"] == 1
    assert evicted["first_missing_hop"] == "uart_fifo_pop"
    assert emitted[1]["frame_id"] == "uart-frame:0:2"
    assert producer.pending_count <= 1
    document = producer.document()
    assert document["candidates_total"] == 2
    assert document["evicted_total"] == 1
    assert document["certified_total"] == 1
    assert document["incomplete_total"] == 1
    assert document["limits"]
    # The late record is recognised as naming the evicted frame and refused.
    assert document["late_events_after_settlement"] >= 1
    assert document["refusals_by_reason"] == {
        "contradicts_settled_certificate": 1}
    assert document["refused_hops"] == ["uart_source_frame_end"]
    assert document["refusals"][0]["certificate_id"] == evicted["certificate_id"]


def test_max_event_gap_expiry_settles_before_the_later_hops():
    journal = uart_journal()
    producer = UartChainCertificates(max_event_gap=1)
    emitted = list(producer.ingest(journal.events))
    emitted.extend(producer.flush())
    assert [row["status"] for row in emitted] == [INCOMPLETE]
    assert emitted[0]["settled_reason"] == "event_gap_exceeded"
    assert emitted[0]["first_missing_hop"] == "uart_rx_receiver_start"
    assert emitted[0]["hops"][-1]["hop_id"] == "uart_source_frame_begin"
    document = producer.document()
    assert document["expired_total"] == 1
    assert document["certified_total"] == 0


def test_caches_are_bounded_by_max_pending():
    producer = UartChainCertificates(max_pending=1, max_event_gap=1)
    journal = uart_journal()
    list(producer.ingest(journal.events))
    assert producer.cache_size <= 4 * producer.max_pending + 8


# ------------------------------------------------------------ null + reason


def test_unknown_endpoint_case_is_null_with_a_reason():
    journal = uart_journal(with_read=False, with_irq=False)
    _, certificate = _single(journal)
    assert certificate["endpoint_case_id"] is None
    assert certificate["endpoint_case_reason"] == "endpoint_case_not_witnessed"
    assert certificate["cross_case"] is None
    assert certificate["cross_case_reason"] == "endpoint_case_unknown"
    assert certificate["irq_mode"] == "no_irq_witness"
    assert certificate["polling_consistent"] is None
    assert certificate["polling_consistent_reason"] == (
        "read_chain_not_witnessed")
    assert certificate["read_chain_state"] == "incomplete"
    assert certificate["retirement_insn"] is None
    assert certificate["retirement_insn_reason"] == (
        "uart_retired_read_match_absent")


def test_absent_trace_digest_is_null_with_a_reason(tmp_path):
    journal = uart_journal()
    run = _write_run(tmp_path / "run", journal)
    meta = {"schema_version": "online_trace_jsonl.v1",
            "events_file": "online_events.jsonl",
            "event_count": len(journal.events)}
    (run / "online_final_trace.meta.json").write_text(
        json.dumps(meta), encoding="utf-8")
    document = uart_chain_certificates(run)
    assert document["trace"]["declared_semantic_sha256"] is None
    assert document["trace"]["semantic_sha256_recomputed"] is None
    assert document["trace"]["semantic_sha256_verified"] is None
    assert document["trace"]["semantic_sha256_reason"] == (
        "artifact_declares_no_semantic_sha256")
    assert document["trace"]["events_ingested"] == len(journal.events)

    meta["semantic_sha256"] = "0" * 64
    (run / "online_final_trace.meta.json").write_text(
        json.dumps(meta), encoding="utf-8")
    document = uart_chain_certificates(run)
    assert document["trace"]["declared_semantic_sha256"] == "0" * 64
    assert document["trace"]["semantic_sha256_recomputed"] is None
    assert document["trace"]["semantic_sha256_verified"] is None
    assert document["trace"]["semantic_sha256_reason"] == (
        "artifact_declares_no_local_ticks_or_status")


def test_counts_are_honest_zero_not_null_when_nothing_was_observed(tmp_path):
    run = _write_run(tmp_path / "empty", _empty_journal())
    document = uart_chain_certificates(run)
    assert document["candidates_total"] == 0
    assert document["certified_total"] == 0
    assert document["incomplete_total"] == 0
    assert document["witness_counts"]["uart_fifo_push"] == 0
    assert document["first_missing_hop_histogram"] == {}
    assert document["first_missing_hop_histogram_reason"] == (
        "no_incomplete_candidate_was_tracked")
    assert document["self_consistent"] is True


def _empty_journal():
    journal = _Journal()
    journal.add("tick", _tick(1))
    return journal


# ----------------------------------------------------------- determinism


def test_two_runs_over_one_artifact_are_byte_identical(tmp_path):
    run = _write_run(tmp_path / "run", uart_journal())
    first = _document_bytes(uart_chain_certificates(run))
    second = _document_bytes(uart_chain_certificates(run))
    assert first == second
    assert json.loads(first.decode("utf-8"))["certified_total"] == 1

    journal = uart_journal()
    one = _document_bytes(_consume(journal)[0].document())
    two = _document_bytes(_consume(journal)[0].document())
    assert one == two


def test_jsonl_and_monolithic_artifacts_produce_the_same_certificates(tmp_path):
    journal = uart_journal()
    streaming = uart_chain_certificates(_write_run(tmp_path / "jsonl", journal))
    monolithic = uart_chain_certificates(
        _write_run(tmp_path / "json", journal, monolithic=True))
    assert monolithic["trace"]["format"] == "json.v1"
    assert streaming["trace"]["format"] == "jsonl.v1"
    for document in (streaming, monolithic):
        document.pop("trace")
    assert _document_bytes(streaming) == _document_bytes(monolithic)


def test_ingest_requires_a_contiguous_event_journal():
    journal = uart_journal()
    events = journal.events
    producer = UartChainCertificates()
    with pytest.raises(ValueError):
        producer.ingest([events[1]])


# -------------------------------------------------------------------- CLI


def test_cli_writes_the_document_and_exits_zero(tmp_path):
    run = _write_run(tmp_path / "run", uart_journal())
    out = tmp_path / "out" / "uart_chain_certificates.json"
    result = _cli("--run", run, "--json-out", out)
    assert result.returncode == 0, result.stderr
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["certified_total"] == 1
    assert document["self_consistent"] is True
    assert "certified=1" in result.stdout
    assert "incomplete=0" in result.stdout


def test_cli_exit_codes_are_one_on_read_error_and_three_on_usage_error(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = _cli("--run", empty, "--json-out", tmp_path / "out.json")
    assert result.returncode == 1, result.stdout
    assert "no UART chain certificates" in result.stderr
    assert "online_final_trace.json" in result.stderr

    result = _cli("--run", tmp_path / "missing", "--json-out",
                  tmp_path / "out.json")
    assert result.returncode == 3, result.stdout
    result = _cli("--json-out", tmp_path / "out.json")
    assert result.returncode == 3, result.stdout
    result = _cli()
    assert result.returncode == 3, result.stdout


def test_cli_never_starts_rtl_and_reads_only_the_saved_run():
    source = (ROOT / "scripts/report_uart_chain_certificates.py").read_text(
        encoding="utf-8")
    for forbidden in ("verilator", "subprocess", "os.system", "Popen",
                      "pytest", "shutil.rmtree"):
        assert forbidden not in source
