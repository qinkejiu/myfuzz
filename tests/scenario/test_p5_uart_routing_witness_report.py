"""The read-only routing-witness reporter must not overstate what it read.

The saved UART run predates ``report.json:source_target_transactions``, so the
reporter derives the table from ``receipts.jsonl`` plus the run's own trace.
Two things it must get right, and did not at first:

* the saved gate declares ``component: cpu``; a UART-side candidate was never
  judged by it, so the reporter must say ``not_judged`` instead of borrowing the
  receipt's ``admitted`` disposition for a decision the gate never made;
* a candidate refused before any RTL command has no ``kind`` in its
  ``online_source`` document, but its declared action does, so the identity must
  be read from the action the receipt actually holds.

The reporter must also never write inside the run directory it reads.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_cli():
    script = REPO_ROOT / "scripts" / "report_p5_uart_routing_witness.py"
    spec = importlib.util.spec_from_file_location(
        "report_p5_uart_routing_witness", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, document) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                    encoding="utf-8")


def _access_event(case_id: str, *, event_id: int, request: int,
                  response: int) -> dict:
    return {
        "kind": "uart_rdata_access", "schema_version": "uart_rdata_access.v1",
        "event_id": event_id, "address": 0x40000018, "raw_offset": 0x18,
        "window_base": 0x40000000, "window_size": 0x1000,
        "access_id": "uart-access:uart:0:4",
        "source_transaction": {"channel_id": "data", "execution_id": "e",
                               "source_component": "cpu", "source_epoch": 0,
                               "source_sequence": 5, "testcase_id": "t"},
        "write": False, "read_value": 90, "local_tick": 12,
        "status": "observed", "actual_request_event_id": request,
        "actual_response_event_id": response,
        "provenance": {"observed_case": {"case_id": case_id, "case_index": 1}},
    }


def _pop_event(*, event_id: int, observation_event_id: int) -> dict:
    """A pop names the request event it answered, not the access's own event."""
    return {
        "kind": "uart_fifo_pop", "schema_version": "uart_fifo_pop.v1",
        "event_id": event_id, "component": "uart", "entry_id": ["uart", 0, 0, 2],
        "value": 90, "observation_event_id": observation_event_id,
        "provenance": {"observed_case": {"case_id": "online-1-x"}},
    }


def build_saved_run(root: Path) -> Path:
    """A tiny but real-shaped saved run: report + receipts + monolithic trace."""
    run = root / "uart-online"
    run.mkdir(parents=True, exist_ok=True)
    _write_json(run / "report.json", {
        "session_status": "complete", "execution_status": "complete",
        "statuses": {"complete": 2, "input_invalid": 1}, "tests": 3,
        "source_action_gate": {
            "schema_version": "online_source_action_gate_report.v1",
            "enforce": True, "action_ids": [],
            "gate": {"schema_version": "uart_waveform_admission_gate.v1",
                     "kind": "uart_rx_waveform_idle", "component": "cpu",
                     "window": {"base": 0x40000000, "size": 0x1000},
                     "enforce": True, "refusals": 1},
        },
    })
    admitted_cpu = {
        "case_id": "online-1-x", "status": "complete",
        "candidate_disposition": "admitted",
        "source_id": "cpu.online_instruction",
        "online_source": {"component": "cpu", "kind": "instruction",
                          "action_id": "online-1-x:cpu.online_instruction"},
        "source_action": {
            "schema_version": "online_source_action.v1",
            "action": {"action_id": "online-1-x:cpu.online_instruction",
                       "component": "cpu", "kind": "instruction",
                       "payload": {"address": 0x11000,
                                   "words_hex": "b7000040" + "238e2000"}},
            "evaluation": {"satisfied": True, "reason": "satisfied"},
            "refusal": None},
    }
    admitted_uart = {
        "case_id": "online-2-y", "status": "complete",
        "candidate_disposition": "admitted",
        "source_id": "uart.external_rx_byte",
        "online_source": {"component": "uart", "kind": "source_event",
                          "action_id": "online-2-y:uart.external_rx_byte"},
        "source_action": {
            "schema_version": "online_source_action.v1",
            "action": {"action_id": "online-2-y:uart.external_rx_byte",
                       "component": "uart", "kind": "external_event",
                       "payload": {"port": "uart_rx_byte", "value": 90}},
            "evaluation": {"satisfied": True, "reason": "satisfied"},
            "refusal": None},
    }
    refused_cpu = {
        "case_id": "online-3-z", "status": "input_invalid",
        "candidate_disposition": "rejected",
        # A refused candidate's online_source is the raw decoded input: it has
        # a component but no kind.
        "online_source": {"action_id": "online-3-z:cpu.online_instruction",
                          "component": "cpu", "address": 0x11000,
                          "data_hex": "37b1c70c13016100b7000040238e2000"},
        "source_action": {
            "schema_version": "online_source_action.v1",
            "action": {"action_id": "online-3-z:cpu.online_instruction",
                       "component": "cpu", "kind": "instruction",
                       "payload": {"address": 0x11000,
                                   "words_hex": "37b1c70c13016100b7000040238e2000"}},
            "evaluation": {"satisfied": False,
                           "reason": "uart_rx_waveform_conflict",
                           "missing": [{"kind": "transport_idle",
                                        "evidence_ref": "uart-waveform-idle:1832",
                                        "subject": {"transport": "uart_rx_waveform",
                                                    "local_tick": 1832,
                                                    "horizon_tick": 1870}}]},
            "refusal": {"reason": "source_action_prerequisite_unsatisfied",
                        "detail": {"evaluation_reason":
                                   "uart_rx_waveform_conflict"}}},
    }
    _write_jsonl(run / "receipts.jsonl",
                 [admitted_cpu, admitted_uart, refused_cpu])
    _write_json(run / "online_final_trace.json", {
        "status": "complete", "local_ticks": {"cpu": 32, "uart": 40},
        "genome_sha256": "0" * 64, "manifest_sha256": "1" * 64,
        "events": [
            _access_event("online-1-x", event_id=10, request=11, response=12),
            _pop_event(event_id=13, observation_event_id=11),
            _access_event("online-1-x", event_id=20, request=21, response=22),
            _pop_event(event_id=23, observation_event_id=21),
        ],
    })
    return run


def test_the_report_is_derived_and_says_so(tmp_path):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    document = cli.derive_document(run, case_limit=16, access_limit=4,
                                   witness_limit=4, max_buffered_per_case=16)
    assert document["schema_version"] == "p5_uart_routing_witness_report.v1"
    assert document["witness_source"] == "derived_by_this_script"
    assert document["recorded_by_the_run"] is None
    assert document["provenance"]["report.json"][
        "carries_source_target_transactions"] is False
    totals = document["derived"]["totals"]
    assert totals["cases"] == 3
    assert totals["cases_with_register_access"] == 1
    assert totals["register_accesses"] == 2
    assert totals["matched_consumption_witnesses"] == 2
    assert totals["event_slices_unavailable"] == 1


def test_a_candidate_outside_the_gates_component_is_not_judged(tmp_path):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    document = cli.derive_document(run, case_limit=16, access_limit=4,
                                   witness_limit=4, max_buffered_per_case=16)
    gate = document["gate_decisions"]
    by_case = {row["case_id"]: row for row in gate["records"]}
    assert by_case["online-1-x"]["decision"] == "admitted"
    assert by_case["online-2-y"]["decision"] == "not_judged"
    assert "cpu" in by_case["online-2-y"]["reason"]
    assert by_case["online-3-z"]["decision"] == "refused"
    assert by_case["online-3-z"]["evidence_ref"] == "uart-waveform-idle:1832"
    assert by_case["online-3-z"]["prerequisite_kind"] == "transport_idle"
    assert by_case["online-3-z"]["declared_window_accesses"]
    assert gate["not_judged"] == 1 and gate["admitted"] == 1 and gate["refused"] == 1


def test_a_refused_candidate_kind_comes_from_its_declared_action(tmp_path):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    document = cli.derive_document(run, case_limit=16, access_limit=4,
                                   witness_limit=4, max_buffered_per_case=16)
    records = {row["case_id"]: row for row in
               document["derived"]["cases"]["records"]}
    assert records["online-3-z"]["source_kind"] == "instruction"
    assert records["online-3-z"]["register_accesses"]["count"] is None
    assert "no event slice" in records["online-3-z"]["register_accesses"]["reason"]
    assert records["online-2-y"]["source_kind"] == "source_event"


def test_the_reporter_never_writes_inside_the_run_directory(tmp_path):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    before = {path.name: path.read_bytes() for path in sorted(run.iterdir())}
    cli.derive_document(run, case_limit=16, access_limit=4, witness_limit=4,
                        max_buffered_per_case=16)
    after = {path.name: path.read_bytes() for path in sorted(run.iterdir())}
    assert after == before


def test_a_run_that_carries_the_key_is_reported_verbatim_and_compared(tmp_path):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    report = json.loads((run / "report.json").read_text())
    report["source_target_transactions"] = {
        "schema_version": "online_source_target_transactions.v1",
        "totals": {"register_accesses": 2, "cases_with_register_access": 1,
                   "target_consumption_witnesses": 2,
                   "cases_with_target_consumption_witness": 1,
                   "matched_consumption_witnesses": 2},
    }
    _write_json(run / "report.json", report)
    document = cli.derive_document(run, case_limit=16, access_limit=4,
                                   witness_limit=4, max_buffered_per_case=16)
    assert document["witness_source"] == "report.json:source_target_transactions"
    assert document["recorded_by_the_run"]["schema_version"] == (
        "online_source_target_transactions.v1")
    assert document["agreement_with_recorded"]["agrees"] is True


def test_the_cli_writes_only_the_paths_it_is_given(tmp_path, capsys):
    cli = _load_cli()
    run = build_saved_run(tmp_path)
    out = tmp_path / "out" / "witness.json"
    exit_code = cli.main(["--run-dir", str(run), "--json-out", str(out)])
    assert exit_code == 0
    assert out.is_file()
    printed = json.loads(capsys.readouterr().out)
    assert printed["cases"] == 3
    assert printed["witness_source"] == "derived_by_this_script"


def test_a_directory_without_receipts_is_refused(tmp_path, capsys):
    cli = _load_cli()
    run = tmp_path / "empty"
    run.mkdir()
    exit_code = cli.main(["--run-dir", str(run)])
    assert exit_code == 2
    assert "receipts.jsonl" in json.loads(capsys.readouterr().out)["error"]
