"""Per-case UART routing/consumption witnesses for the online report.

The heterogeneous UART run really produces routing evidence: seven of its CPU
instruction cases issue a TL-UL read of the UART ``RDATA`` register, each one
served by a FIFO pop, witnessed as an accepted ``uart_consumption_match`` and
retired by the CPU as an ``uart_retired_read_match``.  None of that reached
``report.json`` -- the run reported routing/consumption as ``null``.

These tests pin the derivation rules on real-shaped trace events (the same key
names and the same joins the saved trace uses), the bounded-list contract
(``truncated`` + ``omitted``), the explicit ``null`` + ``reason`` contract, and
the gate's own per-candidate decisions.
"""

from __future__ import annotations

import json

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.rv32i_sources import (
    MmioWindow,
    fragment_bytes,
    mmio_access_fragment,
)
from myfuzz.scenario.source_actions import (
    SourceAction,
    SourceActionPrerequisiteError,
    TerminationObservation,
)
from myfuzz.scenario.uart_routing_witness import (
    CONSUMPTION_WITNESS_KINDS,
    REGISTER_ACCESS_KINDS,
    SCHEMA_VERSION,
    UartRoutingWitnessRecorder,
    case_source_target_transactions,
)
from myfuzz.scenario.uart_waveform_gate import (
    UART_WAVEFORM_CONFLICT_REASON,
    UartWaveformAdmissionGate,
)

from tests.scenario.test_online_source_action_gate import (
    LEFT_RAW,
    TARGET,
    _runner_and_session,
    ip_decoder,
)

UART_BASE = 0x40000000
WINDOW = (UART_BASE, 0x1000)
ACCESS_ID = "uart-access:uart:0:4"
TRANSACTION = {"channel_id": "data", "execution_id": "local-execution",
               "source_component": "cpu", "source_epoch": 0,
               "source_sequence": 5, "testcase_id": "ibex-uart-online-stream"}


def uart_access_event(*, event_id: int = 13710, request: int = 13689,
                      response: int = 13699, access_id: str = ACCESS_ID,
                      offset: int = 0x18, read_value: int = 90) -> dict:
    """One real-shaped ``uart_rdata_access`` fact from the saved trace."""
    return {
        "kind": "uart_rdata_access", "schema_version": "uart_rdata_access.v1",
        "event_id": event_id, "address": UART_BASE + offset,
        "raw_offset": offset, "window_base": UART_BASE, "window_size": 0x1000,
        "access_id": access_id, "source_transaction": dict(TRANSACTION),
        "write": False, "read_value": read_value, "local_tick": 1392,
        "status": "observed", "error": 0,
        "actual_request_event_id": request,
        "actual_response_event_id": response,
        "component": "uart", "reset_epoch": 0,
    }


def uart_pop_event(*, event_id: int = 13698, access_id: str = ACCESS_ID,
                   observation_event_id: int = 13689,
                   entry_id=("uart", 0, 0, 2), value: int = 90) -> dict:
    return {
        "kind": "uart_fifo_pop", "schema_version": "uart_fifo_pop.v1",
        "event_id": event_id, "component": "uart", "local_tick": 1390,
        "entry_id": list(entry_id), "value": value,
        "observation_event_id": observation_event_id,
        "producer_event_id": observation_event_id, "origin_status": "unknown",
        "clear": False,
        "access": {"access_id": access_id, "address": UART_BASE + 0x18,
                   "raw_offset": 0x18, "write": False,
                   "source_transaction": dict(TRANSACTION)},
    }


def uart_consumption_event(*, event_id: int, disposition: str,
                           observation_event_id: int, proof_scope: str,
                           entry_id=("uart", 0, 0, 2),
                           frame_id: str = "uart-frame:0:1") -> dict:
    return {
        "kind": "uart_consumption_match",
        "schema_version": "uart_consumption_match.v1",
        "event_id": event_id, "component": "uart", "local_tick": 1390,
        "status": "accepted", "disposition": disposition,
        "proof_scope": proof_scope, "entry_id": list(entry_id),
        "frame_id": frame_id, "observation_event_id": observation_event_id,
        "live_at_proof_time": True, "retained_at_push": True,
        "push_event": 7266, "validation_event": 7374,
    }


def uart_retired_read_event(*, event_id: int = 13762,
                            uart_access_event_id: int = 13710,
                            uart_read_proof_event_id: int = 13711,
                            read_value: int = 90) -> dict:
    return {
        "kind": "uart_retired_read_match",
        "schema_version": "uart_retired_read_match.v1",
        "event_id": event_id, "status": "accepted",
        "proof_scope": "cpu_retired_uart_rdata_read", "read_value": read_value,
        "uart_access_event_id": uart_access_event_id,
        "uart_read_proof_event_id": uart_read_proof_event_id,
        "pc": 66096, "entry_id": ["uart", 0, 0, 2],
        "frame_id": "uart-frame:0:1",
        "path_id": "33" * 32,
    }


def one_routed_case_events() -> tuple[dict, ...]:
    """The event slice of one case that really routed a UART read to the CPU."""
    return (
        uart_consumption_event(event_id=7375, disposition="retained",
                               observation_event_id=7374,
                               proof_scope="uart_fifo_retention"),
        uart_pop_event(),
        uart_access_event(),
        uart_consumption_event(event_id=13711, disposition="popped",
                               observation_event_id=13710,
                               proof_scope="uart_fifo_read_consumption"),
        uart_retired_read_event(),
    )


# --------------------------------------------------------------- derivation


def test_register_accesses_carry_the_measured_identity():
    record = case_source_target_transactions(
        case_id="online-1-819b265ed890cbfc934efd3e",
        events=one_routed_case_events(),
        case_index=2, component="cpu", source_kind="instruction",
        source_id="cpu.online_instruction")
    accesses = record["register_accesses"]
    assert accesses["count"] == 1
    assert accesses["truncated"] is False and accesses["omitted"] == 0
    access, = accesses["records"]
    assert access["address"] == UART_BASE + 0x18
    assert access["offset"] == 0x18
    assert access["access_id"] == ACCESS_ID
    assert access["source_transaction"] == TRANSACTION
    assert access["read_value"] == 90
    assert access["status"] == "observed"
    assert access["event_id"] == 13710


def test_every_consumption_witness_is_recorded_with_its_join():
    record = case_source_target_transactions(
        case_id="online-1-819b265ed890cbfc934efd3e",
        events=one_routed_case_events())
    witnesses = record["target_consumption_witnesses"]
    assert witnesses["count"] == 4
    by_kind = {row["kind"]: row for row in witnesses["records"]}
    assert set(by_kind) == {"uart_fifo_pop", "uart_retired_read_match",
                            "uart_consumption_match"}
    retired = by_kind["uart_retired_read_match"]
    assert retired["matched_access_id"] == ACCESS_ID
    assert retired["match_basis"] == (
        "uart_retired_read_match.uart_access_event_id == "
        "uart_rdata_access.event_id")
    assert retired["status"] == "accepted"
    pop = by_kind["uart_fifo_pop"]
    assert pop["matched_access_id"] == ACCESS_ID
    assert pop["match_basis"] == (
        "uart_fifo_pop.observation_event_id == "
        "uart_rdata_access.actual_request_event_id")
    consumption = [row for row in witnesses["records"]
                   if row["kind"] == "uart_consumption_match"]
    assert len(consumption) == 2
    popped = [row for row in consumption if row["disposition"] == "popped"]
    assert popped[0]["matched_access_id"] == ACCESS_ID
    assert popped[0]["match_basis"] == (
        "uart_consumption_match.observation_event_id == "
        "uart_rdata_access.event_id")
    retained = [row for row in consumption if row["disposition"] == "retained"]
    assert retained[0]["matched_access_id"] == ACCESS_ID
    assert retained[0]["match_basis"] == (
        "uart_consumption_match.entry_id == matched uart_fifo_pop.entry_id "
        "(frame_id is compared too when the pop carries one)")


def test_the_case_summary_states_which_accesses_are_covered():
    record = case_source_target_transactions(
        case_id="online-1-819b265ed890cbfc934efd3e",
        events=one_routed_case_events())
    matched = record["matched"]
    assert matched["accesses_with_a_consumption_witness"] == 1
    assert matched["accesses_without_a_consumption_witness"] == 0
    assert matched["witnesses_matched"] == 4
    assert matched["witnesses_unmatched"] == 0
    assert matched["complete"] is True
    assert record["reason"] is None


def test_a_case_without_any_uart_witness_reports_a_measured_zero():
    """A UART-side candidate whose byte was never read produced 0 accesses."""
    record = case_source_target_transactions(
        case_id="online-3-87356b6a4a24e573e22e85ec",
        events=({"kind": "uart_source_frame_admission", "event_id": 8},
                {"kind": "uart_tick_observation", "event_id": 9}),
        component="uart", source_kind="source_event",
        source_id="uart.external_rx_byte")
    assert record["register_accesses"]["count"] == 0
    assert record["register_accesses"]["records"] == []
    assert record["target_consumption_witnesses"]["count"] == 0
    assert record["matched"]["complete"] is False
    # A measured zero is not a missing quantity: it carries no null.
    assert record["register_accesses"].get("reason") is None
    assert record["reason"] == (
        "the case produced no UART register access and no target consumption "
        "witness in its own event slice")


def test_a_case_without_an_event_slice_reports_null_plus_reason():
    record = case_source_target_transactions(
        case_id="online-6-1a0521246692a4c060af514b", events=None,
        component="cpu", source_kind="instruction")
    assert record["register_accesses"]["count"] is None
    assert record["register_accesses"]["records"] == []
    assert "no event slice" in record["register_accesses"]["reason"]
    assert record["target_consumption_witnesses"]["count"] is None
    assert record["target_consumption_witnesses"]["reason"]
    assert record["matched"] is None
    assert "refused before any RTL command" in record["reason"]


def test_capped_lists_declare_truncation_and_the_omitted_count():
    events = []
    for index in range(3):
        events.append(uart_access_event(event_id=100 + index * 10,
                                        request=101 + index * 10,
                                        response=102 + index * 10,
                                        access_id=f"uart-access:uart:0:{index}"))
        events.append(uart_pop_event(event_id=103 + index * 10,
                                     access_id=f"uart-access:uart:0:{index}",
                                     observation_event_id=101 + index * 10))
    record = case_source_target_transactions(
        case_id="online-9-x", events=tuple(events), access_limit=2,
        witness_limit=1)
    accesses = record["register_accesses"]
    assert accesses["count"] == 3
    assert len(accesses["records"]) == 2
    assert accesses["truncated"] is True and accesses["omitted"] == 1
    witnesses = record["target_consumption_witnesses"]
    assert witnesses["count"] == 3
    assert len(witnesses["records"]) == 1
    assert witnesses["truncated"] is True and witnesses["omitted"] == 2


def test_the_kind_vocabulary_matches_the_shipped_witness_events():
    assert REGISTER_ACCESS_KINDS == ("uart_rdata_access",)
    assert CONSUMPTION_WITNESS_KINDS == ("uart_fifo_pop",
                                         "uart_retired_read_match",
                                         "uart_consumption_match")


# ----------------------------------------------------------------- recorder


def test_the_recorder_bounds_the_case_table_and_counts_the_omitted_cases():
    recorder = UartRoutingWitnessRecorder(case_limit=2)
    for index in range(3):
        recorder.observe_case(case_id=f"online-{index}-x",
                              case_index=index, component="cpu",
                              events=one_routed_case_events())
    document = recorder.document()
    assert document["schema_version"] == SCHEMA_VERSION
    cases = document["cases"]
    assert cases["count"] == 3
    assert len(cases["records"]) == 2
    assert cases["truncated"] is True and cases["omitted"] == 1
    assert cases["limit"] == 2
    assert document["totals"]["cases"] == 3
    assert document["totals"]["register_accesses"] == 3
    assert document["totals"]["cases_with_register_access"] == 3
    assert document["totals"]["matched_consumption_witnesses"] == 12
    assert document["totals"]["scope"] == "all_observed_cases"


def test_the_document_says_so_when_no_gate_decision_log_exists():
    recorder = UartRoutingWitnessRecorder()
    recorder.observe_case(case_id="online-0-x", events=one_routed_case_events())
    document = recorder.document()
    assert document["source_action_gate"]["decisions"] is None
    assert document["source_action_gate"]["reason"]


def test_the_document_carries_the_gates_own_per_candidate_decisions():
    recorder = UartRoutingWitnessRecorder()
    recorder.observe_case(case_id="online-0-x", events=one_routed_case_events())
    gate = _recording_gate()
    document = recorder.document(gate=gate)
    decisions = document["source_action_gate"]["decisions"]
    assert decisions["count"] == 2
    refused = [row for row in decisions["records"]
               if row["decision"] == "refused"]
    assert refused[0]["reason"] == UART_WAVEFORM_CONFLICT_REASON
    assert refused[0]["evidence_ref"] == "uart-waveform-idle:1832"
    assert refused[0]["prerequisite_kind"] == "transport_idle"
    assert refused[0]["case_id"] == "online-6-1a0521246692a4c060af514b"
    admitted = [row for row in decisions["records"]
                if row["decision"] == "admitted"]
    assert admitted[0]["case_id"] == "online-7-aaaa"
    assert document["schema_version"] == SCHEMA_VERSION
    # The whole document is JSON-serialisable evidence.
    assert json.loads(json.dumps(document)) == document


def _recording_gate(*, conflict: bool = True) -> UartWaveformAdmissionGate:
    class _Session:
        def register_access_conflict(self):
            if not conflict:
                return None
            return {"local_tick": 1832, "horizon_tick": 1870,
                    "source_start_tick": 1800, "source_end_tick": 1900}

    fragment = mmio_access_fragment(
        "LW", UART_BASE + 0x18, windows=(MmioWindow(UART_BASE, 0x1000),),
        base_register=3, data_register=2)
    action = SourceAction(
        action_id="online-6-1a0521246692a4c060af514b:cpu.online_instruction",
        kind="instruction", component="cpu", source_id="cpu.online_instruction",
        ownership="fuzzable", flow_id="F4",
        payload={"address": 0x11000, "words_hex": fragment_bytes(fragment).hex()},
        termination_observation=TerminationObservation("retirement", "rvfi:6"),
        local_step_budget=64)
    gate = UartWaveformAdmissionGate(session=_Session(), window=WINDOW)
    gate.register(action)
    case = _Case("online-6-1a0521246692a4c060af514b")
    with pytest.raises(SourceActionPrerequisiteError):
        gate.require_case(case)

    admitted_action = SourceAction(
        action_id="online-7-aaaa:cpu.online_instruction", kind="instruction",
        component="cpu", source_id="cpu.online_instruction", ownership="fuzzable",
        flow_id="F4", payload={"address": 0x11000,
                               "words_hex": bytes.fromhex("13000000").hex()},
        termination_observation=TerminationObservation("retirement", "rvfi:7"),
        local_step_budget=64)
    admitted = UartWaveformAdmissionGate(session=_Session(), window=WINDOW)
    admitted.register(admitted_action)
    admitted.require_case(_Case("online-7-aaaa"))
    return _MergedGate(gate, admitted)


class _Case:
    def __init__(self, case_id: str) -> None:
        self.case_id = case_id


class _MergedGate:
    """One gate view whose decision log is the concatenation of two gates."""

    def __init__(self, *gates) -> None:
        self._gates = gates
        self.enforce = True

    def decisions(self) -> dict:
        records = [row for gate in self._gates
                   for row in gate.decisions()["records"]]
        return {"count": len(records), "records": records, "truncated": False,
                "omitted": 0, "limit": 256, "refused": 1, "admitted": 1}

    def document(self) -> dict:
        return {"schema_version": "uart_waveform_admission_gate.v1",
                "kind": "uart_rx_waveform_idle", "component": "cpu",
                "enforce": True, "refusals": 1}


# ------------------------------------------------- executor hook (no RTL)


class _CaptureRecorder:
    def __init__(self) -> None:
        self.observed: list[dict] = []

    def observe_case(self, **kwargs):
        self.observed.append(kwargs)
        return {"case_id": kwargs.get("case_id")}


def test_a_recorder_without_observe_case_is_refused():
    subject = ip_decoder()
    runner, session, _harness = _runner_and_session(decoder=subject)
    with pytest.raises(ValueError, match="observe_case"):
        ScenarioRfuzzExecutor(
            run_id="witness-hook", factory=lambda: runner, targets=(TARGET,),
            session=session, online_decoder=subject,
            case_witness_recorder=object())


def test_the_executor_hands_each_admitted_case_its_own_event_slice():
    subject = ip_decoder()
    runner, session, _harness = _runner_and_session(decoder=subject)
    recorder = _CaptureRecorder()
    executor = ScenarioRfuzzExecutor(
        run_id="witness-hook", factory=lambda: runner, targets=(TARGET,),
        session=session, online_decoder=subject,
        case_witness_recorder=recorder)
    executor.execute_batch(InputBatch(3, 8, ((LEFT_RAW,),)))
    assert len(recorder.observed) == 1
    observed = recorder.observed[0]
    assert observed["case_id"]
    assert observed["component"] == "a"
    assert observed["source_kind"] == "source_event"
    events = observed["events"]
    assert events and all(isinstance(event, dict) for event in events)
    # The slice is the case's own events, not the whole session journal.
    recorded_ids = [event.get("event_id") for event in events]
    assert recorded_ids == sorted(recorded_ids)
    assert len(runner.events) >= len(events)


# ------------------------------------------------- the report key itself


def test_the_report_key_is_absent_for_a_run_without_a_recorder():
    from myfuzz.integration.scenario_rfuzz_live import (
        _source_target_transactions_record)

    class _Executor:
        case_witness_recorder = None

    assert _source_target_transactions_record(_Executor()) is None


def test_the_report_key_is_the_versioned_witness_document():
    from myfuzz.integration.scenario_rfuzz_live import (
        _source_target_transactions_record)

    class _Executor:
        def __init__(self):
            self.case_witness_recorder = recorder
            self.source_action_gate = gate

    recorder = UartRoutingWitnessRecorder()
    recorder.observe_case(case_id="online-1-x", events=one_routed_case_events(),
                          component="cpu")
    gate = _recording_gate()
    document = _source_target_transactions_record(_Executor())
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["totals"]["register_accesses"] == 1
    assert document["source_action_gate"]["decisions"]["refused"] == 1


def test_a_witness_records_the_origin_case_and_action_it_name():
    """The routing half: whose injected frame did this read really consume?"""
    retired = uart_retired_read_event()
    retired["source_admission"] = {
        "schema_version": "source_admission.v1",
        "admission_id": "ac" * 32,
        "case_id": "online-0-af5570f5a1810b7af78caf4b",
        "case_index": 1, "action_id": "online-0-af5570f5a1810b7af78caf4b:uart.external_rx_byte",
        "component": "uart", "direction": "IP_TO_CPU", "role": "fuzz_source",
        "source_id": "uart.external_rx_byte", "input_kind": "source_event",
        "input_sha256": "be" * 32, "path_id": "33" * 32,
        "unexpected_extra_key": "must not be copied"}
    events = tuple(one_routed_case_events()) + (retired,)
    record = case_source_target_transactions(case_id="online-10-x", events=events)
    witnesses = record["target_consumption_witnesses"]["records"]
    with_origin = [row for row in witnesses if row["origin_admission"]]
    assert len(with_origin) == 1
    origin = with_origin[0]["origin_admission"]
    assert origin["case_id"] == "online-0-af5570f5a1810b7af78caf4b"
    assert origin["action_id"].endswith(":uart.external_rx_byte")
    assert origin["role"] == "fuzz_source"
    assert "unexpected_extra_key" not in origin


def test_the_recorder_counts_the_distinct_origins_it_saw():
    recorder = UartRoutingWitnessRecorder()
    retired = uart_retired_read_event()
    retired["source_admission"] = {"case_id": "online-0-origin",
                                   "action_id": "online-0-origin:uart.rx"}
    recorder.observe_case(case_id="online-10-x",
                          events=tuple(one_routed_case_events()) + (retired,))
    recorder.observe_case(case_id="online-11-x",
                          events=tuple(one_routed_case_events()) + (retired,))
    document = recorder.document()
    assert document["totals"]["distinct_origin_cases"] == 1
    assert document["totals"]["distinct_origin_actions"] == 1
    assert "source_admission" in document["totals"]["origin_scope"]
