"""The shipped Ibex/PULP wiring binds a later case's result-slot read to the
RAM byte version an earlier case really committed.

Software only: no RTL is compiled, rendered into a process or started.  The
offline CPU stub below performs real step calls and journals the *same record
shapes* the generated CPU journals (``instruction_source`` with
``component``/``address``/``data_hex`` and ``memory_write_commit`` with
``commit_id``/``commit_document``), drained during the step exactly like
``ScenarioRunner._append_external_events`` drains the generated service stream.
The DUT evidence is therefore explicitly synthetic, while the whole chain
(decoder -> ``source_action`` -> adapter ``register`` -> binder -> shipped slot
policy -> ``submit_case`` -> adapter ``observe`` -> tracker witness -> next
case) is the production wiring.

Declared policy of the adapter (also the docstring of the module under test):

* only an ``instruction`` action of the gate's own component whose fragment
  *proves* an ``LW`` effective address equal to ``RESULT_ADDRESS`` is bound;
  "proves" means the base register was materialized **inside the same fragment**
  by ``LUI`` (or ``LUI`` + ``ADDI``), because the case runs after the fixed
  bootstrap and no register value may be assumed;
* an unreadable payload, an ``LW`` with an unmaterialized base, an ``LW`` of any
  other address, another component or kind, and every unknown encoding keep the
  shipped slot-only path untouched;
* binding *adds* a ``ram_byte_version`` prerequisite; it never touches the
  payload, and the bound action is what the slot policy registers and reserves;
* ``DynamicBindingUnbound``/``DynamicBindingRefused`` propagate, so the refusal
  happens before any RTL command.

Covered here:
* the policy rule and its negatives (unit level, no session);
* the adapter is the shipped slot gate plus one binding step, and a
  non-matching case takes that path byte for byte (control comparison);
* a bound case: prerequisite subject/evidence ref, payload untouched, slot
  words still exactly the declared ones, satisfied evaluation;
* no witness -> ``DynamicBindingUnbound`` with zero runner events, ticks, cases
  and harness steps; a superseded witness -> ``SourceActionPrerequisiteError``
  with zero RTL as well;
* ``observe`` feeds the one shared tracker exactly once per receipt;
* ``document()`` publishes both policies, the passthrough ``enforce``/
  ``action_ids`` and the ``dynamic_prerequisite_binder.v1`` block, including in
  the live ``report.json``;
* the Ibex factory and online runtime attach the adapter by default;
* the appended opt-in enablers of that positive direction: the Ibex online
  decoder declares the result-slot window beside GPIO A PADOUT (the shared and
  CV32E40P builders keep their previous single window), and the host-memory
  commit stream is a declared, default-off switch whose enabled mode really
  journals a ``memory_write_commit`` (authenticated through the installed
  service callback, then acknowledged) so the ``STORE`` whitelist can be
  satisfied -- verified end to end against the *real* ``MemoryService``.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_pulp_dual_source import (
    DUAL_SOURCE_MEMORY_REGIONS, HostRamCommitJournal,
    ONLINE_SLOT_RESERVATION_PREFIX, RAM_PREREQUISITE_BINDING_GATE_SCHEMA_VERSION,
    RESULT_ADDRESS, RESULT_SLOT_READ_RULE, RESULT_SLOT_WRITER_KINDS,
    RamPrerequisiteBindingGate, _addi, _lui, _lw, _sw,
    install_host_ram_commit_journal, instruction_words,
    make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_online_decoder,
    make_ibex_pulp_dual_source_stream_bootstrap,
    make_pulp_dual_source_dynamic_binding_gate,
    make_pulp_dual_source_source_action_gate, materialized_lw_addresses,
    reads_result_slot, result_slot_declaration, result_slot_ram_location,
)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource, OnlineSource,
)
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.runtime_path_contract import (RuntimeNode,
                                                   RuntimePathContract)
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario.session_runtime import ScenarioSession, _online_manifest
from myfuzz.scenario.source_actions import (
    SLOT_RESERVATION_GATE_SCHEMA_VERSION, CrossCaseEffectTracker,
    DynamicBindingUnbound, DynamicPrerequisiteBinder,
    InstructionSlotReservationGate, SourceAction, SourceActionGate,
    SourceActionPrerequisiteError, TerminationObservation,
    TrustedRamByteDeclaration, ram_commit_evidence_ref,
)

SOURCE = "cpu.online_instruction"
TARGET = "cpu_to_ip_to_cpu.closed_loop"
DIRECTION = "CPU_TO_IP_TO_CPU"
WINDOW_START = 0x1000
WINDOW_END = 0x1040
TARGET_COVERAGE = CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1)
#: Byte three selects the MMIO template (``entropy[0] % 5`` in
#: ``decode_instruction_fragment``): 3 is the declared ``LW`` and 4 the declared
#: ``SW`` of the one window that covers ``RESULT_ADDRESS``; byte two directly
#: names the one declared instruction source and the rest stays entropy.
LW_RAW = bytes((0, 0, 0, 3, 0, 0, 0, 0))
SW_RAW = bytes((0, 0, 0, 4, 0, 0, 0, 0))
#: The exact two-word fragment the decoder builds for that one window: LUI x1,
#: 0x10; LW x2, 0(x1) -- a read of ``RESULT_ADDRESS``.
LW_WORDS_HEX = "b700010003a10000"
COMMIT_ONE = "a" * 64
COMMIT_TWO = "b" * 64


def _hex(*words: int) -> str:
    return b"".join(word.to_bytes(4, "little") for word in words).hex()


def commit_event(event_id: int, *, commit_id: str = COMMIT_ONE, version: int = 1,
                 value: int = 0x5A, generation: int = 0) -> dict:
    """Synthetic ``memory_write_commit.v1`` event: the real journal shape.

    ``memory_service.py`` publishes exactly these keys for a completed host
    memory write (``commit_id`` over the canonical commit document, per-cell
    ``writer_kind == 'STORE'`` and a two-element ``version``).
    """
    memory_id, byte_offset = result_slot_ram_location()
    return {
        "event_id": event_id, "component": "cpu", "kind": "memory_write_commit",
        "schema_version": "memory_write_commit.v1",
        "service_commit_sequence": event_id, "commit_id": commit_id,
        "commit_document": {
            "schema_version": "memory_write_commit_receipt.v1",
            "commit_id": commit_id, "memory_id": memory_id,
            "generation": generation, "byte_offset": byte_offset,
            "width_bytes": 1, "byte_enable": 1,
            "version": [generation, version], "commit_status": "complete",
            "enabled_byte_cells": [{
                "byte_offset": byte_offset, "value": value,
                "version": [generation, version], "writer_kind": "STORE",
                "writer_event_id": f"case:isr:{event_id}"}]}}


class _CountingTracker(CrossCaseEffectTracker):
    """The shipped tracker plus a counter for its own ingestion calls.

    One ``observe`` of the adapter must mean exactly one ``ingest`` here: that
    is the "tracker is fed once" property, measured instead of asserted by
    reading side effects.
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.ingests = 0

    def ingest(self, events, *, case_id=None):
        self.ingests += 1
        return super().ingest(events, case_id=case_id)


class _Cpu:
    """Offline CPU harness: real steps plus real-shaped journal records.

    ``commits`` are the host-memory commits this case's own execution produced
    (the real ISR ``sw`` to the result slot): they are journaled once, during
    the first step that runs while they are pending, like the generated memory
    service stream.
    """

    def __init__(self, *, commits=()) -> None:
        self.runner = None
        self.steps = 0
        self.slots: tuple[int, int] | None = None
        self.accepted: list[tuple[int, str, str]] = []
        self.pending: list[dict] = []
        self.commits = list(commits)

    def begin_case(self, testcase_id):
        pass

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        self.slots = (address, count)

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str):
        self.accepted.append((address, data.hex(), source_event_id))
        self.pending.append({
            "kind": "instruction_source", "address": address,
            "data_hex": data.hex(), "source_event_id": source_event_id,
            "generation": 0})

    def step_local(self, inputs):
        self.steps += 1
        # The generated CPU journals its service events while it steps.  The
        # journal position is authoritative, so a scripted record's own
        # ``event_id`` is overwritten with the next free id.
        while self.pending:
            record = {"component": "cpu", **self.pending.pop(0)}
            record["event_id"] = len(self.runner._events) + 1
            self.runner._events.append(record)
        if self.commits:
            record = {"component": "cpu", **self.commits.pop(0)}
            record["event_id"] = len(self.runner._events) + 1
            self.runner._events.append(record)
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


def _contract_digest(graph) -> str:
    return hashlib.sha256(json.dumps(
        graph.edge_document(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def instruction_decoder(*, windows=((RESULT_ADDRESS, 4),), cursor=None,
                        window=(WINDOW_START, WINDOW_END)):
    """One declared CPU instruction source over the reserved online window.

    The one declared MMIO window covers ``RESULT_ADDRESS``, so the decoder's
    ``LW`` template really reads the wiring's result slot.  ``window`` is the
    instruction reservation the cases are proposed in: the tests that install a
    *real* ``PersistentMemory`` keep it inside that memory's declared regions.
    """
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource(SOURCE, "instruction", "cpu", (DIRECTION,)),),
        rules=(DependencyRule(TARGET, (SOURCE,), "EVENT_ORDER"),))
    contract = RuntimePathContract(_contract_digest(graph),
                                   (RuntimeNode(SOURCE, "cpu", "logical"),
                                    RuntimeNode(TARGET, "cpu", "logical")), ())
    return OnlineCaseDecoder(
        sources=(OnlineSource(SOURCE, "instruction", "cpu", DIRECTION, TARGET,
                              coverage_target_ids=("cpu_data_write",)),),
        ownership=compile_ownership((), ()), graph=graph, runtime_contract=contract,
        schedule=("cpu",), instruction_start=window[0],
        instruction_end=window[1],
        instruction_cursor=(window[0] if cursor is None else cursor),
        advance_rounds=2, max_input_bytes=8,
        windows=tuple(MmioWindow(base, size) for base, size in windows),
        flow_by_target={TARGET: "F4"},
        allowed_mmio_operations=("LW", "SW"))


def binding_gate(*, window=(WINDOW_START, WINDOW_END), component="cpu",
                 tracker=None) -> RamPrerequisiteBindingGate:
    """The shipped adapter, over a small declared window."""
    return make_pulp_dual_source_dynamic_binding_gate(
        component=component, instruction_start=window[0], instruction_end=window[1],
        tracker=tracker)


def slot_gate(*, window=(WINDOW_START, WINDOW_END), component="cpu", tracker=None):
    """The shipped slot-only policy: the control for the unchanged path."""
    return make_pulp_dual_source_source_action_gate(
        component=component, instruction_start=window[0], instruction_end=window[1],
        tracker=tracker)


def instruction_action(words_hex, *, address=WINDOW_START, component="cpu",
                       action_id="case-1:cpu.online_instruction") -> SourceAction:
    return SourceAction(
        action_id=action_id, kind="instruction", component=component,
        source_id=SOURCE, ownership="fuzzable", flow_id="F4",
        payload={"address": address, "words_hex": words_hex},
        termination_observation=TerminationObservation("retirement",
                                                       f"rvfi:{action_id}"),
        local_step_budget=64)


def _runner_and_session(*, decoder, gate, harness=None):
    harness = _Cpu() if harness is None else harness
    runner = ScenarioRunner(sessions={"cpu": harness}, ownership=decoder.ownership,
                            bindings=())
    harness.runner = runner
    template = ScenarioGenome(testcase_id="ibex-pulp-ram-prerequisite",
                              direction=DIRECTION, path_id=TARGET,
                              schedule_order=("cpu",), max_steps=64, actions=())
    session = ScenarioSession(template, runner, checker=lambda receipt: (),
                              prerequisite_gate=gate)
    session.declare_instruction_slots(
        "cpu", decoder.instruction_start,
        (decoder.instruction_end - decoder.instruction_start) // 4)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    return runner, session, harness


def online_executor(*, decoder=None, gate=None, harness=None):
    """Wire a real executor around the offline CPU stub."""
    subject = instruction_decoder() if decoder is None else decoder
    runner, session, harness = _runner_and_session(decoder=subject, gate=gate,
                                                   harness=harness)
    executor = ScenarioRfuzzExecutor(
        run_id="ibex-pulp-ram-prerequisite", factory=lambda: runner,
        targets=(TARGET_COVERAGE,), session=session, online_decoder=subject)
    return executor, session, harness, subject


def _kinds(action: dict) -> list[str]:
    return [item["kind"] for item in action["prerequisites"]]


def _addresses(action: dict) -> list[int]:
    return [item["subject"]["address"] for item in action["prerequisites"]
            if item["kind"] == "instruction_slot_unmaterialized"]


def _rtl_state(session, harness) -> tuple:
    """Everything a refusal must leave untouched."""
    return (session.runner.event_count, dict(session.runner.local_ticks),
            len(session.cases), harness.steps, tuple(harness.accepted))


# --------------------------------------------------------------------------
# The declared policy: a proven LW of RESULT_ADDRESS, and nothing else
# --------------------------------------------------------------------------

def test_the_declared_result_slot_and_its_trusted_ram_declaration():
    assert RESULT_ADDRESS == 0x10000
    assert result_slot_ram_location() == ("ram", 0)
    assert result_slot_declaration().document() == TrustedRamByteDeclaration(
        memory_id="ram", byte_offsets=(0,),
        writer_kinds=RESULT_SLOT_WRITER_KINDS).document()
    assert RESULT_SLOT_WRITER_KINDS == ("STORE",)
    with pytest.raises(ValueError, match="no region containing"):
        result_slot_ram_location(0x40001000)


def test_the_declared_policy_proves_the_result_slot_read_from_its_own_base():
    # LUI x1, 0x10; LW x2, 0(x1) -- exactly the fragment the decoder builds for
    # the one declared window, and exactly what the module's own encoders emit.
    assert LW_WORDS_HEX == _hex(_lui(1, RESULT_ADDRESS >> 12), _lw(2, 1, 0))
    assert instruction_words(LW_WORDS_HEX) == (0x000100B7, 0x0000A103)
    assert materialized_lw_addresses(LW_WORDS_HEX) == (RESULT_ADDRESS,)
    assert reads_result_slot(LW_WORDS_HEX) is True
    # LUI + ADDI + LW materializes the same address (the ISR pointer idiom).
    assert reads_result_slot(_hex(_lui(3, 0x10), _addi(3, 3, 0), _lw(2, 3, 0))) is True
    # A store between the pointer and the read writes no register.
    assert reads_result_slot(_hex(_lui(1, 0x10), _sw(2, 1, 0), _lw(2, 1, 0))) is True


def test_an_unproven_or_unreadable_fragment_is_never_read_as_the_result_slot():
    # The base this fragment never wrote is unknown: the case runs after the
    # fixed bootstrap, so no register value is assumed.
    assert materialized_lw_addresses(_hex(_lw(2, 1, 0))) == ()
    assert reads_result_slot(_hex(_lw(2, 1, 0))) is False
    # A proven base outside the result slot stays a proven other address.
    padout = _hex(_lui(1, 0x40001), _lw(2, 1, 0x0C))
    assert materialized_lw_addresses(padout) == (0x4000100C,)
    assert reads_result_slot(padout) is False
    # Overwriting the base before the read loses the materialization.
    assert materialized_lw_addresses(
        _hex(_lui(1, 0x10), _lui(1, 0x40001), _lw(2, 1, 0x0C))) == (0x4000100C,)
    # x0 is hardwired zero, so a zero base is never the result slot.
    assert reads_result_slot(_hex(_lui(0, 0x10), _lw(2, 0, 0))) is False
    # An encoding this folder cannot classify invalidates every materialization.
    assert materialized_lw_addresses(
        _hex(_lui(1, 0x10), 0x0000006F, _lw(2, 1, 0))) == ()
    # An unreadable payload is refused, never guessed at.
    for payload in ("", "zz", "a103", "0xa103", "B7000100", None, 3):
        assert instruction_words(payload) is None
        assert materialized_lw_addresses(payload) == ()
        assert reads_result_slot(payload) is False


# --------------------------------------------------------------------------
# The adapter: the shipped slot policy plus exactly one binding step
# --------------------------------------------------------------------------

def test_a_case_that_is_not_a_proven_result_slot_read_keeps_the_old_path():
    tracker = CrossCaseEffectTracker(max_slots=16)
    adapter = binding_gate(tracker=tracker)
    control = slot_gate(tracker=CrossCaseEffectTracker(max_slots=16))
    assert isinstance(adapter, InstructionSlotReservationGate)
    # The declared slot policy is the shipped one, not a reimplementation.
    assert adapter.declaration() == control.declaration() == slot_gate().declaration()
    assert (adapter.first_address, adapter.last_address) == (WINDOW_START, WINDOW_END)

    action = instruction_action(_hex(0x00000013))
    assert adapter.register(action).document() == control.register(action).document()
    assert adapter.document()["slot_gate"] == control.document()
    assert adapter.counters["policy_matched"] == 0
    assert adapter.counters["policy_not_matched"] == 1
    assert tracker.document()["slot_count"] == 1

    # An unproven result-slot read is *not* bound either: with no witness at all
    # the read registers normally instead of refusing, because a fragment this
    # folder cannot prove is never bound (no guess).
    unproven = instruction_action(_hex(_lw(2, 1, 0)), address=WINDOW_START + 4,
                                  action_id="case-2:cpu.online_instruction")
    registered = adapter.register(unproven)
    assert _kinds(registered.document()) == ["instruction_slot_unmaterialized"]
    assert adapter.counters["policy_not_matched"] == 2
    assert adapter.binder.counters["requests"] == 0

    # Another component is outside this policy *and* outside the shipped slot
    # policy, which delegates it unchanged: only this wiring's CPU is examined.
    other = instruction_action(LW_WORDS_HEX, address=WINDOW_START + 8,
                               component="other", action_id="case-3:cpu.online_instruction")
    assert _kinds(adapter.register(other).document()) == []
    assert adapter.counters["policy_not_matched"] == 3
    # ``SourceAction`` already refuses an unreadable payload, so this counter
    # stays a defensive zero over the shipped online path.
    assert adapter.counters["policy_unparsed"] == 0


def test_a_proven_result_slot_read_is_bound_and_the_bound_action_is_admitted():
    tracker = _CountingTracker(max_slots=16)
    adapter = binding_gate(tracker=tracker)
    control = slot_gate(tracker=CrossCaseEffectTracker(max_slots=16))
    action = instruction_action(LW_WORDS_HEX)

    # Before the producer case commits anything the read cannot be bound: the
    # policy refuses fail-closed instead of admitting an unproven consumer.
    with pytest.raises(DynamicBindingUnbound, match="no retained witness"):
        adapter.register(action)
    assert adapter.counters["policy_matched"] == 1
    assert adapter.binder.counters["unbound"] == 1
    # The slot policy never saw the refused action.
    assert tracker.document()["slot_count"] == 0

    # The real commit of an earlier case is what makes the binding possible.
    adapter.observe(SimpleNamespace(case_id="case-1", events=(commit_event(2),)))
    registered = adapter.register(action)
    document = registered.document()
    assert _kinds(document) == ["ram_byte_version", "instruction_slot_unmaterialized",
                                "instruction_slot_unmaterialized"]
    ram = document["prerequisites"][0]
    assert ram["kind"] == "ram_byte_version"
    assert ram["subject"] == {"memory_id": "ram", "generation": 0, "byte_offset": 0}
    assert ram["evidence_ref"] == ram_commit_evidence_ref(COMMIT_ONE)
    # The fuzzer's payload is untouched: binding is a prerequisite, not a value.
    assert dict(registered.payload) == dict(action.payload)
    assert registered.action_sha256 != action.action_sha256
    # The slot policy still reserved exactly the words the payload names.
    assert _addresses(document) == [WINDOW_START, WINDOW_START + 4]
    assert _addresses(document) == _addresses(control.register(action).document())
    evaluation = adapter.evaluate(registered)
    assert evaluation.satisfied is True and evaluation.reason == "satisfied"
    assert ram["evidence_ref"] in evaluation.matched
    # One observe fed the one shared tracker exactly once, and the binder that
    # proves the prerequisite reads that same tracker.
    assert tracker.ingests == 1
    assert adapter.counters["observations"] == 1
    assert adapter.binder.tracker is adapter.tracker is adapter.gate.tracker


def test_the_adapter_requires_a_binder_over_the_tracker_its_slot_policy_reads():
    tracker = CrossCaseEffectTracker(max_slots=16)
    other = CrossCaseEffectTracker(max_slots=16)
    with pytest.raises(ValueError, match="must bind the tracker"):
        RamPrerequisiteBindingGate(
            SourceActionGate(tracker), component="cpu",
            first_address=WINDOW_START, last_address=WINDOW_END,
            reservation_ref_prefix=ONLINE_SLOT_RESERVATION_PREFIX,
            binder=DynamicPrerequisiteBinder(other, result_slot_declaration()),
            result_address=RESULT_ADDRESS, memory_id="ram", byte_offset=0)
    with pytest.raises(ValueError, match="does not cover the declared result slot"):
        RamPrerequisiteBindingGate(
            SourceActionGate(tracker), component="cpu",
            first_address=WINDOW_START, last_address=WINDOW_END,
            reservation_ref_prefix=ONLINE_SLOT_RESERVATION_PREFIX,
            binder=DynamicPrerequisiteBinder(tracker, result_slot_declaration()),
            result_address=RESULT_ADDRESS, memory_id="ram", byte_offset=4)


# --------------------------------------------------------------------------
# Fail-closed before any RTL command, and the cross-case positive direction
# --------------------------------------------------------------------------

def test_no_retained_witness_refuses_the_case_before_any_rtl_command():
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(tracker=tracker)
    executor, session, harness, subject = online_executor(gate=gate)
    assert session.prerequisite_gate is gate
    assert executor.source_action_gate is gate
    assert executor._source_action_gate_observes_itself is True
    before = _rtl_state(session, harness)

    executor.execute_batch(InputBatch(1, 8, ((LW_RAW,),)))

    receipt, decision = executor.receipts[-1], executor.online_decisions[-1]
    # Refused before any RTL command: nothing reached the runner, memory or case
    # history, exactly like the existing pre-RTL refusals.
    assert _rtl_state(session, harness) == before
    assert (before[0], before[2], before[3], before[4]) == (0, 0, 0, ())
    assert not any(before[1].values())
    assert receipt.status == "input_invalid"
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == "source_action_not_constructible"
    assert decision["rejection"] is None and receipt.rejection is None
    structured = receipt.source_action
    assert structured["refusal"]["reason"] == "source_action_not_constructible"
    assert structured["refusal"]["detail"]["error_type"] == "DynamicBindingUnbound"
    assert "no_retained_witness" in structured["refusal"]["detail"]["message"]
    assert structured["action"] is None and structured["evaluation"] is None
    # The policy really ran and the failure really came from the missing witness.
    assert gate.counters["policy_matched"] == 1
    assert gate.binder.counters["unbound"] == 1
    assert gate.binder.counters["bound"] == 0
    assert tracker.ingests == 0 and tracker.document()["pending_count"] == 0
    assert subject.instruction_cursor == WINDOW_START


def test_a_later_case_consumes_the_ram_version_an_earlier_case_committed():
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(tracker=tracker)
    harness = _Cpu(commits=(commit_event(1),))
    executor, session, harness, subject = online_executor(gate=gate, harness=harness)

    executor.execute_batch(InputBatch(2, 8, ((SW_RAW,), (LW_RAW,))))

    first, second = executor.receipts[-2], executor.receipts[-1]
    assert (first.status, second.status) == ("complete", "complete")
    # Case one is not a result-slot read: it took the shipped slot-only path.
    assert _kinds(first.source_action["action"]) == \
        ["instruction_slot_unmaterialized"] * 4
    assert first.source_action["evaluation"]["satisfied"] is True

    # The later read of RESULT_ADDRESS is bound to that exact commit.
    structured = second.source_action
    action = structured["action"]
    assert _kinds(action) == ["ram_byte_version", "instruction_slot_unmaterialized",
                              "instruction_slot_unmaterialized"]
    ram = action["prerequisites"][0]
    assert ram["subject"] == {"memory_id": "ram", "generation": 0, "byte_offset": 0}
    assert ram["evidence_ref"] == ram_commit_evidence_ref(COMMIT_ONE)
    assert _addresses(action) == [WINDOW_START + 16, WINDOW_START + 20]
    evaluation = structured["evaluation"]
    assert evaluation["satisfied"] is True and evaluation["reason"] == "satisfied"
    assert evaluation["matched_evidence_refs"] == [
        ram["evidence_ref"], *[item["evidence_ref"]
                               for item in action["prerequisites"][1:]]]
    assert structured["refusal"] is None
    decision = executor.online_decisions[-1]
    assert decision["candidate_disposition"] == "admitted"
    assert decision["candidate_disposition_reason"] == "rtl_case_committed"
    assert (harness.accepted[1][0], harness.accepted[1][1]) == \
        (WINDOW_START + 16, LW_WORDS_HEX)
    # One observe per admitted case, and the case's own evidence materialized
    # exactly the slots it reserved.
    assert tracker.ingests == 2 and gate.counters["observations"] == 2
    assert gate.counters["policy_matched"] == 1
    assert gate.counters["policy_not_matched"] == 1
    assert gate.tracker.document()["materialized_count"] == 6
    binding = gate.document()["dynamic_binding"]
    assert binding["schema_version"] == "dynamic_prerequisite_binder.v1"
    assert binding["counters"]["bound"] == 1
    assert binding["counters"]["requests"] == 1
    assert binding["declaration"]["writer_kinds"] == ["STORE"]


def test_a_bound_case_whose_witness_is_superseded_is_refused_before_any_rtl():
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(tracker=tracker)
    executor, session, harness, subject = online_executor(
        gate=gate, harness=_Cpu(commits=(commit_event(1),)))
    executor.execute_batch(InputBatch(4, 8, ((SW_RAW,),)))
    assert executor.receipts[-1].status == "complete"

    case = subject.decode(LW_RAW)
    registered = gate.register(subject.source_action(case))
    assert _kinds(registered.document())[0] == "ram_byte_version"
    assert gate.require_case(case).action_id == case.source.action_id

    # A later case commits the next version of the same byte: the pinned
    # evidence is no longer retained, so the bound prerequisite is missing.
    gate.observe(SimpleNamespace(
        case_id="case-later",
        events=(commit_event(9, commit_id=COMMIT_TWO, version=2, value=0x77),)))
    before = _rtl_state(session, harness)
    with pytest.raises(SourceActionPrerequisiteError) as refusal:
        session.submit_case(case)
    assert refusal.value.evaluation.satisfied is False
    assert refusal.value.evaluation.reason == "missing_effects"
    assert [item.kind for item in refusal.value.evaluation.missing] == \
        ["ram_byte_version"]
    # The superseded evidence is never silently re-pointed at the new version,
    # while the still-unmaterialized slot reservations of this case still match.
    assert refusal.value.evaluation.matched == tuple(
        gate.reservation_ref(word) for word in _addresses(registered.document()))
    assert _rtl_state(session, harness) == before
    assert gate.counters["refusals"] == 1
    assert tracker.counters["refused"] == 1
    assert gate.binder.counters["bound"] == 1


def test_observe_feeds_the_one_shared_tracker_exactly_once_per_receipt():
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(tracker=tracker)
    gate.observe(SimpleNamespace(case_id="case-1", events=(commit_event(1),)))
    assert tracker.ingests == 1 and gate.counters["observations"] == 1
    assert gate.binder.tracker is gate.tracker is gate.gate.tracker

    executor, session, harness, subject = online_executor(gate=gate)
    executor.execute_batch(InputBatch(3, 8, ((SW_RAW,),)))
    # The session owns this gate, so the executor does not feed it a second time.
    assert executor._source_action_gate_observes_itself is True
    assert tracker.ingests == 2 and gate.counters["observations"] == 2
    # A repeated ingestion of the same events would be visible here.
    assert tracker.counters["restored_attempts"] == 0


# --------------------------------------------------------------------------
# The published policy document and the live artifacts a root gate reads
# --------------------------------------------------------------------------

def test_the_document_publishes_both_policies_and_the_passthrough_fields():
    tracker = CrossCaseEffectTracker(max_slots=16)
    gate = binding_gate(tracker=tracker)
    document = gate.document()
    # The previously published slot keys keep their values ...
    assert document["schema_version"] == SLOT_RESERVATION_GATE_SCHEMA_VERSION
    assert document["enforce"] is True and document["enforce"] == gate.enforce
    assert document["action_ids"] == list(gate.action_ids) == []
    assert document["declaration"] == slot_gate().declaration()
    assert document["gate"]["schema_version"] == "source_action_gate.v1"
    # ... and the adapter publishes both policy blocks beside them.
    assert document["slot_gate"]["schema_version"] == \
        SLOT_RESERVATION_GATE_SCHEMA_VERSION
    binding = document["dynamic_binding"]
    assert binding["schema_version"] == "dynamic_prerequisite_binder.v1"
    assert binding["declaration"] == result_slot_declaration().document()
    assert binding["counters"] == gate.binder.counters
    assert binding["bounds"]["max_provenance"] == tracker.max_effects
    policy = document["ram_prerequisite"]
    assert policy["schema_version"] == RAM_PREREQUISITE_BINDING_GATE_SCHEMA_VERSION
    assert policy["rule"] == RESULT_SLOT_READ_RULE
    assert policy["result_address"] == RESULT_ADDRESS
    assert policy["memory_id"] == "ram" and policy["byte_offset"] == 0
    assert policy["writer_kinds"] == ["STORE"]
    assert policy["declaration_id"] == result_slot_declaration().declaration_id
    assert policy["on_unproven_fragment"] == "not_bound"
    assert json.loads(json.dumps(document)) == document

    # ``enforce`` is the wrapped gate's own flag, passed through unchanged.
    subject = CrossCaseEffectTracker(max_slots=16)
    relaxed = RamPrerequisiteBindingGate(
        SourceActionGate(subject, enforce=False), component="cpu",
        first_address=WINDOW_START, last_address=WINDOW_END,
        reservation_ref_prefix=ONLINE_SLOT_RESERVATION_PREFIX,
        binder=DynamicPrerequisiteBinder(subject, result_slot_declaration()),
        result_address=RESULT_ADDRESS, memory_id="ram", byte_offset=0)
    assert relaxed.enforce is False
    assert relaxed.document()["enforce"] is False
    assert relaxed.document()["slot_gate"]["enforce"] is False


def test_live_transport_records_the_dynamic_binding_and_the_bound_receipt():
    """The exact keys a root gate reads out of ``receipts.jsonl``/``report.json``."""
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live  # noqa: F401
    from tests.integration.test_scenario_rfuzz_terminal_identity import (
        TerminalIdentityTests)

    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(tracker=tracker)
    executor, session, harness, subject = online_executor(
        gate=gate, harness=_Cpu(commits=(commit_event(1),)))
    transport = TerminalIdentityTests(methodName="runTest")
    transport.setUp()
    try:
        transport.run_transport(executor, tests=((SW_RAW,), (LW_RAW,)))
        rows = [json.loads(line) for line in
                (transport.output / "receipts.jsonl").read_text().splitlines()]
        assert [row["status"] for row in rows] == ["complete", "complete"]
        bound = rows[1]["source_action"]["action"]
        ram = bound["prerequisites"][0]
        assert ram["kind"] == "ram_byte_version"
        assert ram["evidence_ref"] == ram_commit_evidence_ref(COMMIT_ONE)
        assert ram["subject"] == {"memory_id": "ram", "generation": 0,
                                  "byte_offset": 0}
        evaluation = rows[1]["source_action"]["evaluation"]
        assert evaluation["satisfied"] is True
        assert ram["evidence_ref"] in evaluation["matched_evidence_refs"]
        assert rows[1]["source_action"]["refusal"] is None
        assert rows[1]["candidate_disposition_reason"] == "rtl_case_committed"

        report = json.loads((transport.output / "report.json").read_text())
        recorded = report["source_action_gate"]
        assert recorded["schema_version"] == "online_source_action_gate_report.v1"
        assert recorded["enforce"] is True
        assert recorded["action_ids"] == [row["source_action"]["action"]["action_id"]
                                          for row in rows]
        policy = recorded["gate"]
        # Every previously published slot key keeps its value at its old path,
        # so an existing root gate keeps reading the same report document.
        assert policy["schema_version"] == "instruction_slot_reservation_gate.v1"
        assert policy["declaration"]["declared_words"] == 16
        assert policy["gate"]["schema_version"] == "source_action_gate.v1"
        assert policy["slot_gate"]["schema_version"] == \
            "instruction_slot_reservation_gate.v1"
        assert policy["slot_gate"]["counters"]["queries"] == 4
        assert policy["slot_gate"]["counters"]["reservations"] == 6
        assert policy["slot_gate"]["counters"]["refusals"] == 0
        binding = policy["dynamic_binding"]
        assert binding["schema_version"] == "dynamic_prerequisite_binder.v1"
        assert binding["counters"]["requests"] == 1
        assert binding["counters"]["bound"] == 1
        assert binding["counters"]["unbound"] == 0
        assert binding["counters"]["refused"] == 0
        assert binding["counters"]["provenance_records"] == 1
        assert binding["declaration"]["memory_id"] == "ram"
        assert binding["declaration"]["byte_offsets"] == [0]
        assert binding["declaration"]["writer_kinds"] == ["STORE"]
        assert policy["ram_prerequisite"]["rule"] == RESULT_SLOT_READ_RULE
        assert policy["counters"]["policy_matched"] == 1
        assert policy["counters"]["policy_not_matched"] == 1
        assert policy["counters"]["observations"] == 2
        assert policy["gate"]["tracker"]["slot_count"] == 6
        assert policy["gate"]["tracker"]["materialized_count"] == 6
        assert report["statuses"] == {"complete": 2}
        assert gate.tracker is tracker
    finally:
        transport.doCleanups()


# --------------------------------------------------------------------------
# Shipped factory and runtime wiring (no RTL is started)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rendered_wiring(tmp_path_factory):
    cache = tmp_path_factory.mktemp("ibex-pulp-ram-prerequisite")
    return {"cache": cache,
            "ibex": make_ibex_pulp_dual_source_factory(cache)}


def test_the_ibex_factory_declares_one_fresh_binding_gate_per_session(rendered_wiring):
    factory = rendered_wiring["ibex"]
    build = factory.new_source_action_gate
    gate = build()
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    # The adapter is still the shipped slot gate for every existing caller.
    assert isinstance(gate, RamPrerequisiteBindingGate)
    assert isinstance(gate, InstructionSlotReservationGate)
    assert gate.component == "cpu"
    assert (gate.first_address, gate.last_address) == \
        (bootstrap.instruction_start, bootstrap.instruction_end)
    assert gate.declared_words == bootstrap.instruction_count == 31616
    assert gate.declaration() == make_pulp_dual_source_source_action_gate(
        component="cpu").declaration()
    assert gate.result_address == RESULT_ADDRESS
    assert (gate.memory_id, gate.byte_offset) == ("ram", 0)
    assert gate.tracker.max_slots == 31616
    # Gate state is run state: a second session shares no tracker and no binder.
    other = build()
    assert other is not gate and other.tracker is not gate.tracker
    assert other.binder is not gate.binder
    assert gate.tracker.document()["slot_count"] == 0
    assert not hasattr(make_ibex_pulp_dual_source_factory(
        rendered_wiring["cache"], source_actions=False), "new_source_action_gate")


class _StopBeforeRtl(RuntimeError):
    """Sentinel: the recording session must never let a harness be begun."""


class _RecordingSession:
    """Records construction; refuses at begin() so no RTL process can start."""

    def __init__(self, template, runner, *, checker=None, prerequisite_gate=None):
        self.template, self.runner, self.checker = template, runner, checker
        self.prerequisite_gate = prerequisite_gate
        self.calls: list[tuple] = []

    def declare_instruction_slots(self, component, address, count=1):
        self.calls.append(("slots", component, address, count))

    def configure_runtime_paths(self, *args, **kwargs):
        self.calls.append(("paths",))

    def begin(self):
        raise _StopBeforeRtl("no RTL in a software test")

    def finish(self):
        pass


def _runtime_session(rendered_wiring, monkeypatch, **kwargs):
    from myfuzz.integration import ibex_pulp_online
    recorded = {}

    def session_factory(template, runner, **session_kwargs):
        recorded["session"] = _RecordingSession(template, runner, **session_kwargs)
        return recorded["session"]

    monkeypatch.setattr(ibex_pulp_online, "ScenarioSession", session_factory)
    with pytest.raises(_StopBeforeRtl):
        ibex_pulp_online.make_ibex_pulp_online_runtime(
            cache_dir=rendered_wiring["cache"], run_id="ram-prerequisite-wiring",
            **kwargs)
    return recorded["session"]


def test_the_ibex_online_runtime_attaches_the_binding_gate_by_default(
        rendered_wiring, monkeypatch):
    session = _runtime_session(rendered_wiring, monkeypatch)
    gate = session.prerequisite_gate
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    assert isinstance(gate, RamPrerequisiteBindingGate)
    assert isinstance(gate, InstructionSlotReservationGate)
    assert gate.component == "cpu" and gate.result_address == RESULT_ADDRESS
    assert (gate.memory_id, gate.byte_offset) == ("ram", 0)
    assert (gate.first_address, gate.last_address) == \
        (bootstrap.instruction_start, bootstrap.instruction_end)
    assert gate.declared_words == bootstrap.instruction_count
    assert session.calls[0] == ("slots", "cpu", bootstrap.instruction_start,
                               bootstrap.instruction_count)
    assert session.calls[1] == ("paths",)
    # The gate is the session's own object, so the executor that is built from
    # this session discovers it instead of trusting a caller's claim.
    assert session.runner.sessions["cpu"]._process is None


def test_the_runtime_fallback_policy_is_the_binding_gate():
    from myfuzz.integration.ibex_pulp_online import _declared_source_action_gate
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    decoder = make_ibex_pulp_dual_source_online_decoder(bootstrap=bootstrap)
    gate = _declared_source_action_gate(bootstrap, decoder)
    assert isinstance(gate, RamPrerequisiteBindingGate)
    assert gate.component == "cpu"
    assert (gate.first_address, gate.last_address) == \
        (bootstrap.instruction_start, bootstrap.instruction_end)
    assert gate.result_address == RESULT_ADDRESS


def test_the_ibex_online_runtime_legacy_path_carries_no_gate(rendered_wiring,
                                                             monkeypatch):
    session = _runtime_session(rendered_wiring, monkeypatch, source_actions=False)
    assert session.prerequisite_gate is None
    assert session.calls[0][0] == "slots"


# --------------------------------------------------------------------------
# Appended enabler one: the Ibex online decoder declares the result-slot window
# --------------------------------------------------------------------------

#: The MMIO window this wiring already declared (GPIO A PADOUT, offset 12).
PADOUT_WINDOW = 0x4000100C
#: The shipped decoder routes one record to one of its two declared paths by a
#: domain-separated digest of the whole record, so each record below is the
#: complete eight bytes that select the CPU instruction path; the assertions
#: re-check the routing instead of trusting the comment.  Byte three selects the
#: ``LW``/``SW`` template and byte four selects the declared window.
LW_RESULT_RAW = bytes.fromhex("0000000301000000")
LW_PADOUT_RAW = bytes.fromhex("0000000300000004")
SW_RESULT_RAW = bytes.fromhex("0000000401000002")
#: Instruction reservation of the tests that install a *real* host memory: it
#: must lie inside ``DUAL_SOURCE_MEMORY_REGIONS`` (0x10000..0x30000).
MEMORY_WINDOW = (0x20000, 0x20040)


def _windows(decoder) -> list[tuple[int, int]]:
    return [(window.base, window.size) for window in decoder.windows]


def test_the_shared_decoders_keep_their_previous_single_window():
    """Only the Ibex online runtime opts in; every other builder is unchanged."""
    from myfuzz.scenario.cv32e40p_pulp_dual_source import (
        make_cv32e40p_pulp_dual_source_online_decoder)
    from myfuzz.scenario.online_case_decoder import OnlineInstruction
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    assert _windows(make_ibex_pulp_dual_source_online_decoder(
        bootstrap=bootstrap)) == [(PADOUT_WINDOW, 4)]
    assert _windows(make_cv32e40p_pulp_dual_source_online_decoder(
        bootstrap=bootstrap)) == [(PADOUT_WINDOW, 4)]
    # The pre-enabler behaviour of that declaration, pinned: the very record
    # that reads the result slot once the window exists lands on GPIO A PADOUT
    # and is never a result-slot read.
    before = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=bootstrap).decode(LW_RESULT_RAW)
    assert isinstance(before.source, OnlineInstruction)
    assert before.source.data.hex() == _hex(_lui(1, 0x40001), _lw(2, 1, 0x0C))
    assert reads_result_slot(before.source.data.hex()) is False
    # The opt-in declaration is explicit and additive.
    assert _windows(make_ibex_pulp_dual_source_online_decoder(
        bootstrap=bootstrap, result_slot_readback=True)) == \
        [(PADOUT_WINDOW, 4), (RESULT_ADDRESS, 4)]


def test_the_opted_in_decoder_proposes_the_result_slot_read_and_a_store_to_it():
    from myfuzz.scenario.online_case_decoder import OnlineInstruction

    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(),
        result_slot_readback=True)
    read = decoder.decode(LW_RESULT_RAW)
    assert isinstance(read.source, OnlineInstruction)
    assert read.source.data.hex() == LW_WORDS_HEX == "b700010003a10000"
    assert reads_result_slot(read.source.data.hex()) is True
    decoder.commit(read)
    # The window this wiring already declared is unchanged: the same read
    # template still lands on GPIO A PADOUT and is never bound.
    padout = decoder.decode(LW_PADOUT_RAW)
    assert isinstance(padout.source, OnlineInstruction)
    assert padout.source.data.hex() == _hex(_lui(1, 0x40001), _lw(2, 1, 0x0C))
    assert reads_result_slot(padout.source.data.hex()) is False
    decoder.commit(padout)
    store = decoder.decode(SW_RESULT_RAW)
    assert isinstance(store.source, OnlineInstruction)
    words = instruction_words(store.source.data.hex())
    assert len(words) == 4 and words[-2:] == (_lui(1, 0x10), _sw(2, 1, 0))
    assert store.source.data.hex().endswith(_hex(_lui(1, 0x10), _sw(2, 1, 0)))


def test_the_ibex_online_runtime_asks_for_the_result_slot_window(
        rendered_wiring, monkeypatch):
    from myfuzz.integration import ibex_pulp_online
    captured = {}
    monkeypatch.setattr(ibex_pulp_online, "make_ibex_pulp_dual_source_factory",
                        lambda *args, **kwargs: (lambda: None))
    monkeypatch.setattr(ibex_pulp_online, "make_pulp_dual_source_online_runtime",
                        lambda **kwargs: captured.update(kwargs) or SimpleNamespace())
    ibex_pulp_online.make_ibex_pulp_online_runtime(
        cache_dir=rendered_wiring["cache"], run_id="result-slot-window")
    assert _windows(captured["decoder"]) == [(PADOUT_WINDOW, 4), (RESULT_ADDRESS, 4)]


# --------------------------------------------------------------------------
# Appended enabler two: the host-memory commit stream is an explicit switch
# --------------------------------------------------------------------------

class _MemoryCpu:
    """Offline CPU harness backed by the *real* host-memory service.

    ``step_local`` performs one real ``MemoryService.write`` to the declared
    result slot -- the ISR store -- and journals nothing itself: the runner
    drains the service's own event and commit streams exactly like it does for
    a generated CPU, so the evidence this test consumes is the production
    producer's own record.
    """

    def __init__(self, *, memory_commit_receipts: bool = True) -> None:
        self.memory = PersistentMemory(
            regions=DUAL_SOURCE_MEMORY_REGIONS, initialization_seed=37,
            max_initialized_bytes=0x20000)
        self.ledger = TransactionLedger()
        self.service = MemoryService(
            self.memory, self.ledger,
            commit_stream_capacity=256 if memory_commit_receipts else None)
        self.router = None
        self.runner = None
        self.steps = 0
        self.slots: tuple[int, int] | None = None
        self.accepted: list[tuple[int, str, str]] = []
        self.store_pending = True

    def begin_case(self, testcase_id):
        pass

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        # The generated CPU reserves the online words in its host memory; the
        # stub does the same so the real service accepts exactly those bytes.
        self.slots = (address, count)
        self.memory.declare_instruction_slots(address, count)

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str):
        self.accepted.append((address, data.hex(), source_event_id))
        # The real service journals this install itself.
        self.service.accept_instructions(address, data, source_event_id=source_event_id)

    def step_local(self, inputs):
        self.steps += 1
        if self.store_pending:
            # The fixed ISR's ``sw x2, 0(x3)`` to RESULT_ADDRESS, as one real
            # completed host-memory data transaction of this component.
            self.store_pending = False
            self.service.write(
                TransactionKey("execution-1", "case-1", "cpu", 0, "data", 1),
                RESULT_ADDRESS, 0x5A, width_bytes=1, byte_enable=1)
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


def _memory_executor(*, gate, memory_commit_receipts: bool = True):
    harness = _MemoryCpu(memory_commit_receipts=memory_commit_receipts)
    decoder = instruction_decoder(window=MEMORY_WINDOW)
    runner, session, harness = _runner_and_session(
        decoder=decoder, gate=gate, harness=harness)
    journal = None
    if memory_commit_receipts:
        # The shipped wiring installs exactly this on the runner of a session
        # whose commit stream is enabled.
        journal = install_host_ram_commit_journal(
            runner, component="cpu", service=harness.service)
    executor = ScenarioRfuzzExecutor(
        run_id="ibex-pulp-ram-prerequisite", factory=lambda: runner,
        targets=(TARGET_COVERAGE,), session=session, online_decoder=decoder)
    return executor, session, harness, journal


def _commit_events(runner) -> list[dict]:
    return [event for event in runner.events_since(0)
            if event.get("kind") == "memory_write_commit"]


def test_the_commit_stream_switch_is_default_off_and_leaves_identity_unchanged(
        rendered_wiring):
    cache = rendered_wiring["cache"]
    runners = [make_ibex_pulp_dual_source_factory(cache)(),
               make_ibex_pulp_dual_source_factory(
                   cache, memory_commit_receipts=False)()]
    identities = [runner.sessions["cpu"].identity_document() for runner in runners]
    assert identities[0] == identities[1]
    # The session manifest identity of the default path is byte-identical too.
    assert _online_manifest(runners[0], None) == _online_manifest(runners[1], None)
    for runner in runners:
        assert "memory_commit_stream" not in \
            runner.sessions["cpu"].identity_document()
        assert runner.sessions["cpu"].service.commit_stream_enabled is False
        assert runner.sessions["cpu"].memory_commit_receipts_enabled is False
        # No commit journal is installed, so no previous runner behaviour moves.
        assert runner._uart_ram_commit_join is None


def test_the_commit_stream_switch_declares_exactly_one_observation(
        rendered_wiring):
    cache = rendered_wiring["cache"]
    runner = make_ibex_pulp_dual_source_factory(
        cache, memory_commit_receipts=True)()
    identity = runner.sessions["cpu"].identity_document()
    assert identity["memory_commit_stream"] == {
        "schema_version": "memory_write_commit_stream.v1", "capacity": 256}
    assert runner.sessions["cpu"].service.commit_stream_enabled is True
    assert isinstance(runner._uart_ram_commit_join, HostRamCommitJournal)
    # The switch changes that one declared observation and nothing else.
    plain = make_ibex_pulp_dual_source_factory(cache)()
    assert {key: value for key, value in identity.items()
            if key != "memory_commit_stream"} == \
        plain.sessions["cpu"].identity_document()
    assert _online_manifest(runner, None) != _online_manifest(plain, None)
    # The journal authenticator emits no certificate of its own.
    assert runner._uart_ram_commit_join.consume({"kind": "memory_write"}) == ()


def test_the_commit_stream_switch_is_boolean_and_plumbed_to_the_runtime(
        rendered_wiring, monkeypatch):
    from myfuzz.integration import ibex_pulp_online
    cache = rendered_wiring["cache"]
    for builder in (make_ibex_pulp_dual_source_factory,
                    ibex_pulp_online.make_ibex_pulp_dual_source_factory):
        with pytest.raises(ValueError,
                           match="memory_commit_receipts must be boolean"):
            builder(cache, memory_commit_receipts=1)
    with pytest.raises(ValueError, match="memory_commit_receipts must be boolean"):
        ibex_pulp_online.make_ibex_pulp_online_runtime(
            cache_dir=cache, run_id="switch", memory_commit_receipts=1)

    default = _runtime_session(rendered_wiring, monkeypatch)
    assert default.runner.sessions["cpu"].service.commit_stream_enabled is False
    assert default.runner._uart_ram_commit_join is None
    enabled = _runtime_session(rendered_wiring, monkeypatch,
                               memory_commit_receipts=True)
    assert enabled.runner.sessions["cpu"].service.commit_stream_enabled is True
    assert isinstance(enabled.runner._uart_ram_commit_join, HostRamCommitJournal)


def test_a_real_host_ram_commit_reaches_the_journal_and_binds_the_next_case():
    """End to end through the real producer: no stub commit record at all."""
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(window=MEMORY_WINDOW, tracker=tracker)
    executor, session, harness, journal = _memory_executor(gate=gate)
    assert isinstance(journal, HostRamCommitJournal)

    executor.execute_batch(InputBatch(6, 8, ((SW_RAW,), (LW_RAW,))))

    first, second = executor.receipts[-2], executor.receipts[-1]
    assert (first.status, second.status) == ("complete", "complete")
    events = _commit_events(session.runner)
    assert len(events) == 1
    commit = events[0]
    commit_id = commit["commit_id"]
    document = commit["commit_document"]
    # The real commit shape the declared whitelist consumes.
    assert len(commit_id) == 64 and document["commit_id"] == commit_id
    assert document["memory_id"] == "ram" and document["byte_offset"] == 0
    assert document["commit_status"] == "complete"
    assert [cell["writer_kind"] for cell in document["enabled_byte_cells"]] == ["STORE"]
    assert [cell["value"] for cell in document["enabled_byte_cells"]] == [0x5A]
    # Authenticated and acknowledged: the bounded stream cannot fill up, and the
    # naive legacy record that preceded it is not what the reader was bound to.
    assert harness.service.pending_commit_count == 0
    assert [event["kind"] for event in session.runner.events_since(0)
            if event.get("kind") in ("memory_write", "memory_write_commit")] == \
        ["memory_write", "memory_write_commit"]

    action = second.source_action["action"]
    ram = action["prerequisites"][0]
    assert ram["kind"] == "ram_byte_version"
    assert ram["evidence_ref"] == ram_commit_evidence_ref(commit_id) == commit_id
    assert ram["subject"] == {"memory_id": "ram", "generation": 0, "byte_offset": 0}
    evaluation = second.source_action["evaluation"]
    assert evaluation["satisfied"] is True
    assert evaluation["matched_evidence_refs"][0] == commit_id
    assert evaluation["missing"] == []
    assert second.source_action["refusal"] is None
    binding = gate.document()["dynamic_binding"]
    assert binding["counters"]["bound"] == 1
    assert binding["counters"]["unbound"] == 0
    assert binding["counters"]["provenance_records"] == 1
    assert binding["declaration"]["writer_kinds"] == ["STORE"]


def test_a_legacy_only_stream_cannot_satisfy_the_store_whitelist():
    """Default off: the same write journals no commit, so the gate refuses."""
    tracker = _CountingTracker(max_slots=64)
    gate = binding_gate(window=MEMORY_WINDOW, tracker=tracker)
    executor, session, harness, journal = _memory_executor(
        gate=gate, memory_commit_receipts=False)
    assert journal is None
    assert session.runner._uart_ram_commit_join is None

    executor.execute_batch(InputBatch(7, 8, ((SW_RAW,), (LW_RAW,))))

    assert _commit_events(session.runner) == []
    assert [event["kind"] for event in session.runner.events_since(0)
            if event.get("kind") in ("memory_write", "memory_write_commit")] == \
        ["memory_write"]
    first, second = executor.receipts[-2], executor.receipts[-1]
    assert first.status == "complete"
    # The declared ``STORE`` whitelist has no provenance here, so the reader is
    # refused fail-closed instead of binding an unattributed witness.
    assert second.status == "input_invalid"
    assert second.source_action["refusal"]["reason"] == \
        "source_action_not_constructible"
    assert second.source_action["refusal"]["detail"]["error_type"] == \
        "DynamicBindingUnbound"
    assert "untrusted_source_provenance" in \
        second.source_action["refusal"]["detail"]["message"]
    assert gate.binder.counters["unbound"] == 1
    assert gate.binder.counters["bound"] == 0


def test_the_saved_commit_stream_mode_reads_only_a_verified_manifest(tmp_path):
    from myfuzz.integration.ibex_pulp_online import _saved_memory_commit_mode

    def saved(contract=None):
        identity = {}
        if contract is not None:
            identity["memory_commit_stream"] = contract
        raw = json.dumps({"runner": {"sessions": {"cpu": {"identity": identity}}}}).encode()
        (tmp_path / "online_session_manifest.json").write_bytes(raw)
        return {"artifacts": {
            "online_session_manifest.json": hashlib.sha256(raw).hexdigest()}}

    # A saved bundle without the field stays on the default-off mode, and so
    # does a bundle that declares no CPU session at all (the shared replay entry
    # also serves the second CPU of this wiring).
    assert _saved_memory_commit_mode(tmp_path, None) is False
    assert _saved_memory_commit_mode(tmp_path, saved()) is False
    raw = json.dumps({"runner": {"sessions": {}}}).encode()
    (tmp_path / "online_session_manifest.json").write_bytes(raw)
    assert _saved_memory_commit_mode(tmp_path, {"artifacts": {
        "online_session_manifest.json": hashlib.sha256(raw).hexdigest()}}) is False
    contract = {"schema_version": "memory_write_commit_stream.v1", "capacity": 256}
    assert _saved_memory_commit_mode(tmp_path, saved(contract)) is True
    with pytest.raises(ValueError, match="contract mismatch"):
        _saved_memory_commit_mode(tmp_path, saved(
            {"schema_version": "memory_write_commit_stream.v1", "capacity": True}))
    with pytest.raises(ValueError, match="changed after verification"):
        _saved_memory_commit_mode(tmp_path, {"artifacts": {
            "online_session_manifest.json": "0" * 64}})


def test_replay_forwards_the_saved_commit_stream_mode(tmp_path, monkeypatch):
    """A saved bundle selects the mode it was recorded in, and only that one."""
    from myfuzz.integration import ibex_pulp_online

    plan = tmp_path / "online_plan.json"
    plan.write_bytes(b"{}")
    trace = tmp_path / "online_final_trace.json"
    trace.write_text(json.dumps({"genome_sha256": "0" * 64, "status": "complete",
                                 "events": [], "local_ticks": {},
                                 "semantic_sha256": "0" * 64,
                                 "manifest_sha256": "0" * 64}))
    monkeypatch.setattr(ibex_pulp_online, "_verify_online_run_identity",
                        lambda *args, **kwargs: {})
    for name in ("_saved_cpu_retirement_mode", "_saved_gpio_consumption_mode",
                 "_saved_pin8_native_irq_mode"):
        monkeypatch.setattr(ibex_pulp_online, name, lambda *args, **kwargs: False)
    monkeypatch.setattr(ibex_pulp_online, "replay_online_session",
                        lambda *args, **kwargs: "matched")
    captured = {}

    def factory(*args, **kwargs):
        captured.update(kwargs)
        return lambda: None

    monkeypatch.setattr(ibex_pulp_online, "make_ibex_pulp_dual_source_factory",
                        factory)
    monkeypatch.setattr(ibex_pulp_online, "_saved_memory_commit_mode",
                        lambda *args, **kwargs: True)
    assert ibex_pulp_online.replay_ibex_pulp_online_files(
        cache_dir=tmp_path / "cache", plan_path=plan, trace_path=trace) == "matched"
    assert captured == {"cpu_retirement": False, "gpio_consumption": False,
                        "memory_commit_receipts": True}
    # An older bundle that declares no commit stream keeps the default path: the
    # keyword is not forwarded, so a builder that cannot take it still works.
    captured.clear()
    monkeypatch.setattr(ibex_pulp_online, "_saved_memory_commit_mode",
                        lambda *args, **kwargs: False)
    assert ibex_pulp_online.replay_ibex_pulp_online_files(
        cache_dir=tmp_path / "cache", plan_path=plan, trace_path=trace) == "matched"
    assert captured == {"cpu_retirement": False, "gpio_consumption": False}
