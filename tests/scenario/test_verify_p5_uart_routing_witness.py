"""The independent verifier must not trust the producer it is checking.

``scripts/verify_p5_uart_routing_witness.py`` re-derives the P5 UART routing
witness table from ``receipts.jsonl`` and the streamed trace, then compares each
claim to what the saved witness JSON and the report say.  These tests pin the
behaviour that matters for a *verifier*:

* every claim entry compares a literal expectation against an independent
  recomputation and the producer's reported value, so a disagreement is a
  first-class outcome (exit 4), not an exception;
* the three-witness chain is joined by the documented keys, and a refused
  retirement, an access with no retirement, or a duplicated witness event all
  turn into disagreements instead of being silently absorbed;
* ``null`` refusal rows (pre-RTL rejection) are distinguished from a measured
  zero, and the verifier checks that the run really produced no event slice for
  them;
* the verifier never materializes the trace through ``read_text``/``json.load``
  and never imports the producer's module for its derivation.

The synthetic runs are tiny (one real chain, one refusal, one idle case); the
expectations are injected so the same code path can be exercised without
reproducing the full 60-receipt saved run.  The saved run itself is verified by
running the script, not by this file.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve ``cls.__module__`` through sys.modules (3.12+).
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Module-level load: before the verifier exists this is a collection error, which
# is the RED state this file was written against.
VERIFY = _load_module("verify_p5_uart_routing_witness",
                      "scripts/verify_p5_uart_routing_witness.py")

WINDOW = {"base": 0x40000000, "size": 0x1000}
UART_ACCESS_ID = "uart-access:uart:0:4"
#: ``lui x1, 0x40000; sb x2, 2(x1)`` encoded with the real S-type immediate
#: split (imm in bits 31:25/11:7), which both the shipped ISA decoder and the
#: verifier's independent decode read as 0x40000002.
SB_WORDS_CORRECT = "b700004023812000"
#: the words the saved run really carries: an S-type store whose immediate is
#: 0x1c (TXDATA), which the gate's decoder reads as 0x40000002.
SB_WORDS_SAVED_RUN = "b7000040238e2000"


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                    encoding="utf-8")


def _case(case_id: str, index: int) -> dict:
    return {"case_id": case_id, "case_index": index}


def _prov(case_id: str, index: int) -> dict:
    return {"observed_case": _case(case_id, index)}


def _admission(case_id: str, *, admission_id: str = "adm-origin",
               action_id: str | None = None) -> dict:
    return {
        "schema_version": "source_admission.v1",
        "admission_id": admission_id,
        "case_id": case_id,
        "case_index": 1,
        "action_id": action_id or f"{case_id}:uart.external_rx_byte",
        "component": "uart",
        "direction": "IP_TO_CPU",
        "role": "fuzz_source",
        "source_id": "uart.external_rx_byte",
    }


def _uart_receipt(case_id: str, *, byte: int = 90) -> dict:
    return {
        "case_id": case_id,
        "status": "complete",
        "candidate_disposition": "admitted",
        "source_id": "uart.external_rx_byte",
        "online_source": {"component": "uart", "kind": "source_event",
                          "port": "uart_rx_byte", "value": byte, "width": 8,
                          "action_id": f"{case_id}:uart.external_rx_byte"},
        "source_action": {
            "action": {"action_id": f"{case_id}:uart.external_rx_byte",
                       "component": "uart", "kind": "source_event",
                       "source_id": "uart.external_rx_byte", "payload": {}},
            "evaluation": {"satisfied": True, "missing": [], "reason": "satisfied"},
            "refusal": None,
        },
    }


def _cpu_receipt(case_id: str, *, status: str = "complete",
                 disposition: str = "admitted", words_hex: str = "13000000",
                 missing: list[dict] | None = None,
                 refusal_reason: str | None = None) -> dict:
    document = {
        "case_id": case_id,
        "status": status,
        "candidate_disposition": disposition,
        "source_id": "cpu.online_instruction",
        "online_source": {"component": "cpu", "kind": "instruction",
                          "address": 69648, "data_hex": words_hex,
                          "action_id": f"{case_id}:cpu.online_instruction"},
        "source_action": {
            "action": {"action_id": f"{case_id}:cpu.online_instruction",
                       "component": "cpu", "kind": "instruction",
                       "source_id": "cpu.online_instruction",
                       "payload": {"address": 69648, "words_hex": words_hex}},
            "evaluation": {"satisfied": disposition == "admitted",
                           "missing": list(missing or []),
                           "reason": refusal_reason or "satisfied"},
            "refusal": (None if refusal_reason is None else
                        {"reason": "source_action_prerequisite_unsatisfied",
                         "detail": {"evaluation_reason": refusal_reason}}),
        },
    }
    return document


def _refusal_missing(evidence: str, tick: int) -> list[dict]:
    return [{"evidence_ref": evidence, "kind": "transport_idle",
             "subject": {"transport": "uart_rx_waveform", "local_tick": tick,
                         "horizon_tick": tick + 38}}]


def _access(case_id: str, index: int, *, event_id: int, request: int,
            access_id: str = UART_ACCESS_ID, read_value: int = 90,
            offset: int = 0x18) -> dict:
    return {
        "kind": "uart_rdata_access", "event_id": event_id,
        "access_id": access_id, "address": WINDOW["base"] + offset,
        "raw_offset": offset, "window_base": WINDOW["base"],
        "window_size": WINDOW["size"], "write": False, "read_value": read_value,
        "local_tick": 12, "status": "observed",
        "actual_request_event_id": request, "actual_response_event_id": request + 5,
        "source_transaction": {"channel_id": "data", "execution_id": "e",
                               "source_component": "cpu", "source_epoch": 0,
                               "source_sequence": 5, "testcase_id": "t"},
        "provenance": _prov(case_id, index),
    }


def _pop(case_id: str, index: int, *, event_id: int, request: int,
         access_id: str = UART_ACCESS_ID, entry: list | None = None,
         value: int = 90) -> dict:
    entry = entry or ["uart", 0, 0, 2]
    return {
        "kind": "uart_fifo_pop", "event_id": event_id, "entry_id": entry,
        "value": value, "observation_event_id": request, "local_tick": 11,
        "access": {"access_id": access_id},
        "provenance": _prov(case_id, index),
    }


def _consumption(case_id: str, index: int, *, event_id: int,
                 observation_event_id: int, entry: list | None = None,
                 frame_id: str | None = "uart-frame:0:1",
                 disposition: str = "popped", status: str = "accepted",
                 read_value: int | None = 90,
                 admission: dict | None = None,
                 proof_scope: str = "uart_fifo_read_consumption") -> dict:
    return {
        "kind": "uart_consumption_match", "event_id": event_id,
        "entry_id": entry or ["uart", 0, 0, 2], "frame_id": frame_id,
        "disposition": disposition, "status": status, "read_value": read_value,
        "observation_event_id": observation_event_id, "local_tick": 12,
        "proof_scope": proof_scope, "path_id": "path-1",
        "source_admission": admission,
        "provenance": _prov(case_id, index),
    }


def _retired(case_id: str, index: int, *, event_id: int, access_event_id: int,
             proof_event_id: int, entry: list | None = None,
             status: str = "accepted", read_value: int = 90,
             admission: dict | None = None) -> dict:
    return {
        "kind": "uart_retired_read_match", "event_id": event_id,
        "entry_id": entry or ["uart", 0, 0, 2], "frame_id": "uart-frame:0:1",
        "status": status, "read_value": read_value,
        "uart_access_event_id": access_event_id,
        "uart_read_proof_event_id": proof_event_id,
        "observation_event_id": event_id - 1, "proof_scope":
            "cpu_retired_uart_rdata_read",
        "source_admission": admission,
        "provenance": _prov(case_id, index),
    }


def _frame_admission(case_id: str, index: int, *, event_id: int, byte: int,
                     admission_id: str = "adm-origin") -> dict:
    return {
        "kind": "uart_source_frame_admission", "event_id": event_id,
        "byte": byte, "frame_id": "uart-frame:0:1", "port": "uart_rx_byte",
        "width": 8, "action_id": f"{case_id}:uart.external_rx_byte",
        "provenance": {**_prov(case_id, index),
                       "origin_admission_ids": [admission_id]},
    }


def _push(case_id: str, index: int, *, event_id: int, value: int,
          entry: list | None = None) -> dict:
    return {
        "kind": "uart_fifo_push", "event_id": event_id, "value": value,
        "entry_id": entry or ["uart", 0, 0, 2], "frame_id": "uart-frame:0:1",
        "provenance": _prov(case_id, index),
    }


def _build_run(tmp_path: Path, *, sb_words: str = SB_WORDS_CORRECT,
               retired_status: str = "accepted",
               extra_access_only_case: bool = False,
               duplicate_event_id: bool = False) -> Path:
    """One tiny faithful run: a real chain, a refused candidate, an idle case."""
    run = tmp_path / "run"
    run.mkdir(parents=True, exist_ok=True)
    origin = _admission("case-uart")
    events = [
        {"kind": "initial_image", "event_id": 1},
        _frame_admission("case-uart", 1, event_id=8, byte=90),
        _push("case-uart", 1, event_id=50, value=90),
        _access("case-cpu", 2, event_id=110, request=100),
        _pop("case-cpu", 2, event_id=104, request=100),
        _consumption("case-cpu", 2, event_id=111, observation_event_id=110,
                     admission=origin),
        _retired("case-cpu", 2, event_id=120, access_event_id=110,
                 proof_event_id=111, status=retired_status, admission=origin),
        _consumption("case-uart", 1, event_id=60, observation_event_id=50,
                     disposition="retained", status="accepted",
                     read_value=None, admission=origin,
                     proof_scope="uart_fifo_retention"),
        _consumption("case-uart", 1, event_id=61, observation_event_id=50,
                     disposition=None, status="accepted", read_value=None,
                     proof_scope="native_irq_cause"),
    ]
    if extra_access_only_case:
        events.append(_access("case-orphan", 4, event_id=210, request=200,
                              access_id="uart-access:uart:0:5",
                              read_value=91))
    if duplicate_event_id:
        events.append(_consumption("case-uart", 1, event_id=60,
                                   observation_event_id=50,
                                   proof_scope="native_irq_cause"))
    _write_json(run / "online_final_trace.json",
                {"events": events, "local_ticks": {"cpu": 1}, "status": "complete"})
    _write_jsonl(run / "receipts.jsonl", [
        _cpu_receipt("case-cpu"),
        _uart_receipt("case-uart", byte=90),
        _cpu_receipt("case-idle"),
        _cpu_receipt("case-refused", status="input_invalid",
                     disposition="rejected", words_hex=sb_words,
                     missing=_refusal_missing("uart-waveform-idle:1832", 1832),
                     refusal_reason="uart_rx_waveform_conflict"),
    ])
    _write_json(run / "report.json", {
        "schema_version": "online_session_report.v1",
        "session_status": "complete",
        "statuses": {"complete": 3, "input_invalid": 1},
        "source_action_gate": {
            "schema_version": "online_source_action_gate_report.v1",
            "enforce": True,
            "gate": {"schema_version": "uart_waveform_admission_gate.v1",
                     "component": "cpu", "enforce": True, "kind":
                         "uart_rx_waveform_idle", "refusals": 1,
                     "window": dict(WINDOW)},
        },
    })
    return run


def _produce_witness(run: Path, out: Path) -> dict:
    producer = _load_module("report_p5_uart_routing_witness",
                            "scripts/report_p5_uart_routing_witness.py")
    document = producer.derive_document(run, case_limit=256, access_limit=16,
                                        witness_limit=16,
                                        max_buffered_per_case=4096)
    _write_json(out, document)
    return document


_FROZENSET_EXPECTATIONS = ("refusal_evidence", "gated_components",
                           "declared_admitted_with_accesses")
_TUPLE_EXPECTATIONS = ("chain_access_ids", "chain_values")


def _expectations(**overrides):
    converted = {}
    for key, value in overrides.items():
        if key in _FROZENSET_EXPECTATIONS:
            value = frozenset(value)
        elif key in _TUPLE_EXPECTATIONS:
            value = tuple(value)
        converted[key] = value
    return dataclasses.replace(VERIFY.DEFAULT_EXPECTATIONS, **converted)


def _expectation_overrides() -> dict:
    """JSON-friendly literals for a one-chain synthetic run (CLI seam)."""
    return {
        "receipt_rows": 4, "receipt_complete": 3, "receipt_input_invalid": 1,
        "chain_count": 1, "chain_access_ids": [UART_ACCESS_ID],
        "chain_values": [90], "uart_side_chains": 1, "cpu_side_chains": 0,
        "consumption_witnesses": 5, "joined_witnesses": 3,
        "unjoined_witnesses": 2, "cases_without_any_witness": 1,
        "gate_judged": 3, "gate_admitted": 2, "gate_refused": 1,
        "gate_not_judged": 1,
        "refusal_evidence": ["uart-waveform-idle:1832"],
        "gated_components": ["cpu"], "null_rows": 1,
        "declared_access_count": 1, "declared_admitted_with_accesses": [],
        "declared_access_word_offset": 4,
        "doc_chains_reading_injected_byte": 1,
    }


def _claims(document: dict) -> dict:
    return {entry["claim"]: entry for entry in document["claims"]}


def _fixture(tmp_path: Path, **knobs):
    run = _build_run(tmp_path, **knobs)
    witness = tmp_path / "witness.json"
    _produce_witness(run, witness)
    return run, witness, _expectations(**_expectation_overrides())


def test_all_claims_agree_on_a_faithful_synthetic_run(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert document["ok"] is True, document["disagreements"]
    assert document["disagreements"] == []
    assert claims["receipts_total_and_statuses"]["agree"] is True
    assert claims["three_joined_witnesses_per_chain"]["agree"] is True
    assert claims["chain_matched_complete"]["agree"] is True
    assert claims["refusal_rows_null_with_reason"]["agree"] is True
    assert claims["witness_source_is_derived_by_this_script"]["agree"] is True
    hops = document["per_case_hops"]
    assert [row["case_id"] for row in hops] == ["case-cpu"]
    hop = hops[0]
    assert hop["access_id"] == UART_ACCESS_ID
    assert hop["offset"] == 0x18
    assert hop["read_value"] == 90
    assert hop["hops"] == {
        "access": True, "fifo_pop_joined": True,
        "consumption_match_joined": True, "retired_read_match_joined": True,
        "retired_read_match_accepted": True,
    }
    assert hop["joined_witnesses"] == 3
    assert hop["unjoined_witnesses"] == 0
    assert hop["byte_chain"]["all_equal"] is True


def test_hop_table_records_the_join_keys_and_no_double_counting(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    hop = document["per_case_hops"][0]
    assert hop["joins"]["fifo_pop"]["observation_event_id"] == 100
    assert hop["joins"]["fifo_pop"]["access_actual_request_event_id"] == 100
    assert hop["joins"]["consumption_match"]["observation_event_id"] == 110
    assert hop["joins"]["consumption_match"]["access_event_id"] == 110
    assert hop["joins"]["retired_read_match"]["uart_access_event_id"] == 110
    assert hop["joins"]["retired_read_match"]["access_event_id"] == 110
    assert hop["joins"]["retired_read_match"]["uart_read_proof_event_id"] == 111
    assert hop["joins"]["consumption_match"]["entry_id"] == ["uart", 0, 0, 2]
    assert hop["joins"]["fifo_pop"]["entry_id"] == ["uart", 0, 0, 2]
    assert hop["joined_witness_event_ids"] == [104, 111, 120]
    claims = _claims(document)
    assert claims["joined_witnesses_are_distinct_records"]["agree"] is True


def test_receipt_status_claim_disagrees_when_the_json_says_otherwise(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = json.loads(witness.read_text(encoding="utf-8"))
    document["provenance"]["receipts.jsonl"]["statuses"] = {"complete": 4}
    _write_json(witness, document)
    result = VERIFY.verify(run, witness, expectations=expectations,
                            report_doc=tmp_path / "absent.md")
    claim = _claims(result)["receipts_total_and_statuses"]
    assert claim["agree"] is False
    assert claim["recomputed"]["statuses"] == {"complete": 3, "input_invalid": 1}
    assert claim["reported"]["statuses"] == {"complete": 4}
    assert any(entry["claim"] == "receipts_total_and_statuses"
               for entry in result["disagreements"])


def test_gate_split_uses_the_gate_component_not_the_receipt_disposition(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    gate = claims["gate_judged_split"]
    assert gate["agree"] is True
    assert gate["recomputed"] == {"judged": 3, "admitted": 2, "refused": 1,
                                  "not_judged": 1}
    uart_row = [row for row in document["gate_decisions"]
                if row["case_id"] == "case-uart"][0]
    assert uart_row["decision"] == "not_judged"
    assert uart_row["candidate_disposition"] == "admitted"
    refused = [row for row in document["gate_decisions"]
               if row["decision"] == "refused"][0]
    assert refused["evidence_ref"] == "uart-waveform-idle:1832"
    assert refused["prerequisite_kind"] == "transport_idle"
    assert refused["declared_window_accesses"] == [
        {"operation": "SB", "address": 0x40000002, "word_offset": 4}]


def test_declared_sb_address_is_recomputed_with_riscv_store_semantics(tmp_path):
    run, witness, expectations = _fixture(tmp_path, sb_words=SB_WORDS_SAVED_RUN)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    recorded = claims["declared_accesses_match_witness_json"]
    assert recorded["agree"] is True  # the JSON really records 0x40000002
    correct = claims["declared_address_is_riscv_correct"]
    assert correct["agree"] is False
    assert correct["recomputed"] == [0x4000001C]
    assert correct["reported"] == [0x40000002]
    assert "S-type" in correct["note"]


def test_a_refused_retirement_breaks_the_chain_claim(tmp_path):
    run, witness, expectations = _fixture(tmp_path, retired_status="rejected")
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert claims["all_retired_matches_accepted"]["agree"] is False
    assert claims["chain_matched_complete"]["agree"] is True
    hop = document["per_case_hops"][0]
    assert hop["hops"]["retired_read_match_joined"] is True
    assert hop["hops"]["retired_read_match_accepted"] is False
    assert hop["retired_match_statuses"] == ["rejected"]


def test_an_access_with_no_retirement_is_reported_not_dropped(tmp_path):
    run, witness, expectations = _fixture(tmp_path, extra_access_only_case=True)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert claims["no_access_without_accepted_retirement"]["agree"] is False
    assert claims["three_joined_witnesses_per_chain"]["agree"] is False
    orphan = [row for row in document["per_case_hops"]
              if row["case_id"] == "case-orphan"][0]
    assert orphan["hops"]["access"] is True
    assert orphan["hops"]["fifo_pop_joined"] is False
    assert orphan["hops"]["retired_read_match_joined"] is False
    assert claims["read_chain_cases"]["recomputed"] == 2


def test_a_duplicated_witness_event_id_is_flagged(tmp_path):
    run, witness, expectations = _fixture(tmp_path, duplicate_event_id=True)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert claims["witness_event_ids_unique"]["agree"] is False
    assert claims["witness_event_ids_unique"]["recomputed"] == [60]


def test_null_refusal_row_is_verified_against_the_trace(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    null_claim = claims["refusal_rows_null_with_reason"]
    assert null_claim["agree"] is True
    assert null_claim["recomputed"] == {
        "cases": ["case-refused"],
        "register_accesses_null": True,
        "consumption_witnesses_null": True,
        "reason_present": True,
    }
    not_derivable = claims["refusal_rows_could_not_be_derived"]
    assert not_derivable["agree"] is True
    assert not_derivable["recomputed"] == {
        "cases": ["case-refused"], "events_in_trace": 0,
        "receipts_show_pre_rtl_refusal": True}
    # A producer that wrote a measured zero for a pre-RTL refusal is wrong.
    producer_document = json.loads(witness.read_text(encoding="utf-8"))
    for record in producer_document["derived"]["cases"]["records"]:
        if record["case_id"] == "case-refused":
            record["register_accesses"]["count"] = 0
            record["target_consumption_witnesses"]["count"] = 0
    _write_json(witness, producer_document)
    result = VERIFY.verify(run, witness, expectations=expectations,
                            report_doc=tmp_path / "absent.md")
    assert _claims(result)["refusal_rows_null_with_reason"]["agree"] is False


def test_global_entry_join_caveat_is_computed_without_changing_totals():
    unjoined = [{"case_id": "case-uart", "event_id": 60, "kind":
                 "uart_consumption_match", "entry_id": ["uart", 0, 0, 2]}]
    globally_joined = {("uart", 0, 0, 2): ("case-cpu", UART_ACCESS_ID)}
    caveats = VERIFY.global_entry_join_caveats(unjoined, globally_joined)
    assert caveats == [{"case_id": "case-uart", "event_id": 60,
                        "entry_id": ["uart", 0, 0, 2],
                        "joined_in_case": "case-cpu",
                        "joined_access_id": UART_ACCESS_ID}]
    assert VERIFY.global_entry_join_caveats([], globally_joined) == []


def test_totals_disagree_when_the_json_totals_are_tampered(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    producer_document = json.loads(witness.read_text(encoding="utf-8"))
    producer_document["derived"]["totals"]["target_consumption_witnesses"] = 6
    producer_document["derived"]["totals"]["cases_without_any_witness"] = 0
    _write_json(witness, producer_document)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert claims["consumption_witnesses_total"]["agree"] is False
    assert claims["consumption_witnesses_total"]["recomputed"] == 5
    assert claims["consumption_witnesses_total"]["detail"]["kind_totals"] == {
        "uart_consumption_match": 3, "uart_fifo_pop": 1,
        "uart_retired_read_match": 1}
    assert claims["cases_without_any_witness"]["agree"] is False
    assert claims["cases_without_any_witness"]["recomputed"] == 1


def test_witness_source_claim_requires_the_run_to_lack_the_key(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    report = json.loads((run / "report.json").read_text(encoding="utf-8"))
    report["source_target_transactions"] = {
        "schema_version": "online_source_target_transactions.v1"}
    _write_json(run / "report.json", report)
    _produce_witness(run, witness)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    claims = _claims(document)
    assert claims["witness_source_is_derived_by_this_script"]["agree"] is False
    assert claims["run_report_lacks_transactions_key"]["agree"] is False
    assert document["reported"]["witness_source"] == \
        "report.json:source_target_transactions"


def test_verifier_never_materializes_the_trace(tmp_path, monkeypatch):
    run, witness, expectations = _fixture(tmp_path)
    trace_path = (run / "online_final_trace.json").resolve()
    original = Path.read_text

    def guarded(self, *args, **kwargs):
        if self.resolve() == trace_path:
            raise AssertionError("the trace was materialized with read_text()")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    assert document["ok"] is True


def test_main_exit_codes_and_writes_the_result(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    out = tmp_path / "verify.json"
    overrides = json.dumps(_expectation_overrides())
    assert VERIFY.main(["--run-dir", str(run), "--witness-json", str(witness),
                        "--json-out", str(out),
                        "--report-doc", str(tmp_path / "absent.md"),
                        "--expectations-json", overrides]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["schema_version"] == VERIFY.SCHEMA_VERSION
    assert written["ok"] is True
    # disagreement -> 4
    document = json.loads(witness.read_text(encoding="utf-8"))
    document["derived"]["totals"]["target_consumption_witnesses"] = 99
    _write_json(witness, document)
    assert VERIFY.main(["--run-dir", str(run), "--witness-json", str(witness),
                        "--json-out", str(out),
                        "--report-doc", str(tmp_path / "absent.md"),
                        "--expectations-json", overrides]) == 4
    assert json.loads(out.read_text(encoding="utf-8"))["ok"] is False
    # read error -> 1
    assert VERIFY.main(["--run-dir", str(tmp_path / "missing"),
                        "--witness-json", str(witness),
                        "--json-out", str(out),
                        "--report-doc", str(tmp_path / "absent.md")]) == 1
    # usage error -> 3 (no --run-dir) and a malformed expectations document
    assert VERIFY.main(["--witness-json", str(witness)]) == 3
    assert VERIFY.main(["--run-dir", str(run), "--witness-json", str(witness),
                        "--json-out", str(out), "--expectations-json",
                        "{not json"]) == 3


def test_secondary_run_check_is_opt_in_and_reports_the_recorded_scope(tmp_path):
    run, witness, expectations = _fixture(tmp_path)
    document = VERIFY.verify(run, witness, expectations=expectations,
                              report_doc=tmp_path / "absent.md")
    assert document["secondary_checks"] == []
    checked = VERIFY.secondary_run_check(run)
    assert checked["checked"] is True
    # the synthetic report carries no source_target_transactions key
    assert checked["recorded_has_source_target_transactions"] is False
    assert checked["recorded_matches_doc_section_3"] is False
    assert checked["agrees"] is False
    assert checked["scope_delta"]["trace_scope_witnesses"] == 5
    assert checked["scope_delta"]["bootstrap_witnesses"] == 0
    assert checked["scope_delta"]["bootstrap_explains_difference"] is False


@pytest.mark.parametrize("words_hex,expected", [
    (SB_WORDS_CORRECT, [{"operation": "SB", "address": 0x40000002,
                         "word_offset": 4}]),
    (SB_WORDS_SAVED_RUN, [{"operation": "SB", "address": 0x4000001C,
                           "word_offset": 4}]),
    ("13000000", []),
])
def test_independent_riscv_decode_uses_store_semantics(words_hex, expected):
    assert VERIFY.decode_riscv_accesses(
        bytes.fromhex(words_hex), window_base=WINDOW["base"],
        window_size=WINDOW["size"]) == expected
