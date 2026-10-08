"""The online RFuzz path binds every candidate to a declared source action.

Software only: the lightweight offline harness executes no RTL. The journal
records used for cross-case evidence are synthetic ``memory_write_commit``
records appended by the stub during a real step call, so the whole chain
(decoder -> ``source_action`` -> gate ``register``/``require_case`` ->
``submit_case`` -> gate ``observe`` -> tracker witness -> next case) is the
production wiring, while the DUT evidence itself is explicitly synthetic.

Covered here:
* a missing declared prerequisite refuses the candidate before any RTL command
  (runner event count, local ticks and case history stay unchanged);
* a satisfied prerequisite admits the case and the tracker observes the real
  receipt events of that case;
* the retained witness is consumed by a later case (cross-case);
* a legacy decoder without a declared flow category cannot construct an action
  and says so, instead of inventing a flow;
* a bound producer (including a CPU IRQ input) can never become a mutable
  source action;
* a tampered action or declaration document is refused;
* a repeated slot returns the original receipt unchanged;
* with no gate configured the online path behaves exactly as before.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                        FuzzableSource)
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource,
    OnlineSource, OnlineSourceActionDeclaration, OnlineSourceActionRefusal,
)
from myfuzz.scenario.ownership import (InputField, InputOwner,
                                       compile_ownership)
from myfuzz.scenario.runner import Binding, ScenarioRunner
from myfuzz.scenario.runtime_path_contract import (RuntimeEdgeContract,
                                                   RuntimeNode,
                                                   RuntimePathContract)
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.source_actions import (
    CrossCaseEffectTracker, SourceAction, SourceActionGate,
    ram_commit_prerequisite,
)


LEFT = "s1"
RIGHT = "s2"
PATH_TARGET = "target"
COMMIT_ID = "a" * 64
RAM_PREREQUISITE = ram_commit_prerequisite("ram", 0, 0x10000, COMMIT_ID)
TARGET = CoverageTarget("ip.observed", "a", "out", 1, 1)
#: Byte two selects a declared source directly; bytes three.. seven stay entropy.
LEFT_RAW = bytes((0, 0, 0, 7, 0, 0, 0, 0))
RIGHT_RAW = bytes((0, 0, 1, 7, 0, 0, 0, 0))
RIGHT_RAW_OTHER = bytes((0, 0, 1, 9, 1, 0, 0, 0))


def _contract_digest(graph) -> str:
    return hashlib.sha256(json.dumps(
        graph.edge_document(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def _ownership():
    """Two fuzzable pins on 'a' and one bound pin on 'b' fed by 'a.out'."""
    return compile_ownership(
        (InputField("a", "pin", 1), InputField("a", "pin2", 1),
         InputField("b", "pin", 1)),
        (InputOwner("a", "pin", 0, 1, "source", "external_left"),
         InputOwner("a", "pin2", 0, 1, "source", "external_right"),
         InputOwner("b", "pin", 0, 1, "bound", "a.out")))


def _bound_irq_ownership():
    """The same two ports, the second now owned by a real producer."""
    return compile_ownership(
        (InputField("a", "pin", 1), InputField("a", "pin2", 1),
         InputField("b", "pin", 1)),
        (InputOwner("a", "pin", 0, 1, "source", "external_left"),
         InputOwner("a", "pin2", 0, 1, "bound", "cpu.irq"),
         InputOwner("b", "pin", 0, 1, "bound", "a.out")))


def _declaration(flow=True):
    """One declared runtime path carrying both fuzzable sources."""
    graph = DependencyGraph(
        sources=(FuzzableSource(LEFT, "a", "pin", 0, 1, ("IP_TO_IP",)),
                 FuzzableSource(RIGHT, "a", "pin2", 0, 1, ("IP_TO_IP",))),
        rules=(DependencyRule("out", (LEFT, RIGHT), "EVENT_ORDER"),
               DependencyRule(PATH_TARGET, ("out",), "DATA_BINDING")))
    nodes = (RuntimeNode(LEFT, "a", "physical", "pin", 0, 1),
             RuntimeNode(RIGHT, "a", "physical", "pin2", 0, 1),
             RuntimeNode("out", "a", "physical", "out", 0, 1),
             RuntimeNode(PATH_TARGET, "b", "physical", "pin", 0, 1))
    contract = RuntimePathContract(_contract_digest(graph), nodes,
                                   (RuntimeEdgeContract(1, 0, "direct_binding"),))
    paths = tuple(("IP_TO_IP", path) for path in
                  graph.edge_paths_to(PATH_TARGET, direction="IP_TO_IP"))
    return graph, contract, paths


def _online_graph():
    return OnlineDependencyGraph(
        sources=(OnlineDependencySource(LEFT, "source", "a", ("IP_TO_IP",),
                                        port="pin"),
                 OnlineDependencySource(RIGHT, "source", "a", ("IP_TO_IP",),
                                        port="pin2")),
        rules=(DependencyRule("out", (LEFT, RIGHT), "EVENT_ORDER"),
               DependencyRule(PATH_TARGET, ("out",), "DATA_BINDING")))


def ip_decoder(*, declarations=(), flow=True, ownership=None):
    """Two declared external sources on one declared runtime path."""
    subject_ownership = _ownership() if ownership is None else ownership
    graph, contract, _ = _declaration()
    return OnlineCaseDecoder(
        sources=(OnlineSource(LEFT, "source", "a", "IP_TO_IP", PATH_TARGET,
                              port="pin", coverage_target_ids=("ip.observed",)),
                 OnlineSource(RIGHT, "source", "a", "IP_TO_IP", PATH_TARGET,
                              port="pin2", coverage_target_ids=("ip.observed",))),
        ownership=subject_ownership, graph=_online_graph(),
        runtime_contract=contract, schedule=("a", "b"),
        instruction_start=0, instruction_end=4, advance_rounds=2,
        max_input_bytes=8,
        flow_by_target=({PATH_TARGET: "F5"} if flow else None),
        source_actions=tuple(declarations))


def instruction_decoder(*, declarations=(), flow=True):
    """One declared CPU instruction source over a reserved online slot."""
    subject_ownership = compile_ownership((), ())
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource("cpu.it", "instruction", "cpu",
                                        ("IP_TO_IP",)),),
        rules=(DependencyRule("cpu.target", ("cpu.it",), "EVENT_ORDER"),))
    contract = RuntimePathContract(_contract_digest(graph), (), ())
    return OnlineCaseDecoder(
        sources=(OnlineSource("cpu.it", "instruction", "cpu", "IP_TO_IP",
                              "cpu.target",
                              coverage_target_ids=("cpu.observed",)),),
        ownership=subject_ownership, graph=graph, runtime_contract=contract,
        schedule=("cpu",), instruction_start=0x1000, instruction_end=0x1008,
        advance_rounds=2, max_input_bytes=8,
        windows=(MmioWindow(0x40000000, 0x1000),),
        flow_by_target=({"cpu.target": "F4"} if flow else None),
        source_actions=tuple(declarations))


class _Pin:
    """Offline harness: records steps and appends declared journal evidence."""

    def __init__(self, *, journal=False):
        self.runner = None
        self.journal = journal
        self.steps = 0
        self.journal_records: tuple[dict, ...] = ()

    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        self.steps += 1
        if self.journal and self.runner is not None:
            for record in self.journal_records:
                self.runner._events.append(
                    {"event_id": len(self.runner._events) + 1, **record})
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


def commit_record(*, memory_id="ram", generation=0, byte_offset=0x10000,
                  commit_id=COMMIT_ID):
    """One real-shaped ``memory_write_commit`` journal record (synthetic here)."""
    return {
        "component": "cpu", "kind": "memory_write_commit",
        "schema_version": "memory_write_commit.v1", "commit_id": commit_id,
        "commit_document": {
            "schema_version": "memory_write_commit_receipt.v1",
            "commit_id": commit_id, "memory_id": memory_id,
            "generation": generation, "byte_offset": byte_offset,
            "width_bytes": 1, "byte_enable": 1, "version": [0, 1],
            "commit_status": "complete",
            "enabled_byte_cells": [
                {"byte_offset": byte_offset, "value": 0x5A, "version": [0, 1],
                 "writer_kind": "STORE", "writer_event_id": "case"}]}}


def _runner_and_session(*, decoder, session_gate=None, template_id="online-gate"):
    harness = _Pin(journal=True)
    runner = ScenarioRunner(sessions={"a": harness, "b": _Pin()},
                            ownership=decoder.ownership,
                            bindings=(Binding("a", "out", "b", "pin", 1),))
    harness.runner = runner
    template = ScenarioGenome(testcase_id=template_id, direction="IP_TO_IP",
                              path_id=PATH_TARGET, schedule_order=("a", "b"),
                              max_steps=64, actions=())
    session = ScenarioSession(template, runner, checker=lambda receipt: (),
                              prerequisite_gate=session_gate)
    graph, contract, paths = _declaration()
    session.configure_runtime_paths(graph, contract, paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    return runner, session, harness


def online_executor(*, decoder=None, gate=None, session_gate=None,
                    executor_gate=None, targets=(TARGET,), session=None,
                    runner=None, harness=None, discover_gate=False):
    """Wire a real executor around the offline harness stub."""
    subject = ip_decoder() if decoder is None else decoder
    if session is None:
        runner, session, harness = _runner_and_session(
            decoder=subject, session_gate=(session_gate if session_gate is not None
                                           else gate))
    bound = executor_gate if executor_gate is not None else gate
    executor = ScenarioRfuzzExecutor(
        run_id="online-source-action", factory=lambda: runner, targets=targets,
        session=session, online_decoder=subject,
        **({} if bound is None or discover_gate
           else {"source_action_gate": bound}))
    return executor, session, harness, subject


class _RecordingGate:
    """Forwards to a real gate and records the call order around the RTL calls."""

    def __init__(self, inner, runner):
        self.inner = inner
        self.runner = runner
        self.required = []
        self.observed = []
        self.required_at_event_count = []

    def register(self, action):
        return self.inner.register(action)

    def evaluate(self, action):
        return self.inner.evaluate(action)

    def require_case(self, case):
        self.required.append(case.case_id)
        self.required_at_event_count.append(self.runner.event_count)
        return self.inner.require_case(case)

    def observe(self, receipt):
        self.observed.append(receipt.case_id)
        return self.inner.observe(receipt)

    @property
    def enforce(self):
        return self.inner.enforce

    def document(self):
        return self.inner.document()


# --------------------------------------------------------------------------
# Pre-RTL refusal and pre-RTL admission
# --------------------------------------------------------------------------

def test_missing_prerequisite_refuses_before_any_rtl_command():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    declaration = OnlineSourceActionDeclaration(RIGHT, (RAM_PREREQUISITE,))
    executor, session, harness, subject = online_executor(
        decoder=ip_decoder(declarations=(declaration,)), gate=gate)
    delivered = []
    before = (session.runner.event_count, dict(session.runner.local_ticks))
    executor.execute_batch(InputBatch(1, 8, ((RIGHT_RAW,),)),
                           on_receipt=delivered.append)

    receipt = executor.receipts[-1]
    decision = executor.online_decisions[-1]
    # The refusal is pre-RTL: nothing reached the runner, memory or history.
    assert (session.runner.event_count, dict(session.runner.local_ticks)) == before
    assert session.cases == ()
    assert harness.steps == 0
    assert subject.instruction_cursor == 0
    # It is reported with the existing disposition keys and a structured reason.
    assert receipt.status == "input_invalid"
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == \
        "source_action_prerequisite_unsatisfied"
    assert decision["rejection"] is None
    assert receipt.rejection is None
    structured = receipt.source_action
    assert structured["schema_version"] == "online_source_action.v1"
    assert structured["action"]["kind"] == "external_event"
    assert structured["refusal"]["reason"] == \
        "source_action_prerequisite_unsatisfied"
    assert [item["kind"] for item in structured["evaluation"]["missing"]] == \
        ["ram_byte_version"]
    assert structured["evaluation"]["reason"] == "missing_effects"
    assert json.loads(json.dumps(structured)) == structured
    assert delivered == [receipt]
    # A refused candidate never stops the live session.
    assert executor._session_stop_reason is None
    assert tracker.counters["refused"] == 1


def test_declared_action_identity_comes_from_existing_declarations():
    gate = SourceActionGate(CrossCaseEffectTracker())
    executor, session, harness, subject = online_executor(
        decoder=ip_decoder(declarations=()), gate=gate)
    executor.execute_batch(InputBatch(2, 8, ((LEFT_RAW,),)))

    receipt, decision = executor.receipts[-1], executor.online_decisions[-1]
    assert receipt.status == "complete"
    assert decision["candidate_disposition"] == "admitted"
    assert decision["candidate_disposition_reason"] == "rtl_case_committed"
    action = receipt.source_action["action"]
    assert action["schema_version"] == "source_action.v1"
    assert action["kind"] == "external_event"
    assert action["source_id"] == LEFT
    assert action["component"] == "a"
    assert action["ownership"] == "fuzzable"
    assert action["flow_id"] == "F5"
    assert action["local_step_budget"] == 4
    assert action["termination_observation"] == {
        "schema_version": "source_termination_observation.v1",
        "kind": "incomplete", "evidence_ref": "", "flow_id": "F5"}
    assert action["prerequisites"] == []
    assert receipt.source_action["evaluation"]["satisfied"] is True
    assert json.loads(json.dumps(receipt.source_action)) == receipt.source_action
    # The registered action is exactly the decoded case input.
    source = receipt.online_case["source"]
    assert action["payload"] == {"port": source["port"],
                                 "bit_offset": source["bit_offset"],
                                 "width": source["width"], "value": source["value"],
                                 "endpoint_class": "environment_source"}
    assert harness.steps == 2


def test_instruction_action_payload_is_the_decoded_reserved_slot():
    subject = instruction_decoder()
    case = subject.decode(bytes(8))
    action = subject.source_action(case)
    assert (action.kind, action.component, action.source_id) == (
        "instruction", "cpu", "cpu.it")
    assert action.ownership == "fuzzable"
    assert action.flow_id == "F4"
    assert action.action_id == case.source.action_id
    assert action.payload == {"address": 0x1000,
                              "words_hex": case.source.data_hex}
    assert action.local_step_budget == 2
    assert action.termination_observation.kind == "incomplete"


def test_declared_termination_observation_is_used_when_present():
    from myfuzz.scenario.source_actions import TerminationObservation

    declared = TerminationObservation("delivery", "declared:evidence:ref", "F5")
    declaration = OnlineSourceActionDeclaration(LEFT, (), declared)
    subject = ip_decoder(declarations=(declaration,))
    case = subject.decode(LEFT_RAW)
    assert subject.source_action(case).termination_observation == declared


def test_gate_is_required_before_the_first_step_and_observes_the_receipt():
    tracker = CrossCaseEffectTracker()
    inner = SourceActionGate(tracker)
    subject = ip_decoder()
    runner, session, harness = _runner_and_session(
        decoder=subject, session_gate=None)
    recording = _RecordingGate(inner, runner)
    executor = ScenarioRfuzzExecutor(
        run_id="online-source-action-order", factory=lambda: runner,
        targets=(TARGET,), session=session, online_decoder=subject,
        source_action_gate=recording)
    executor.execute_batch(InputBatch(3, 8, ((LEFT_RAW,),)))

    assert len(recording.required) == 1
    assert recording.required[0] == recording.observed[0]
    # require_case ran before any step; observe ran after the case.
    assert recording.required_at_event_count == [0]
    assert harness.steps == 2
    assert runner.event_count > 0
    # The tracker retains only declared event shapes, so its cursor is the
    # highest journal event id that carried a string kind.
    kinded = [event["event_id"] for event in runner.events
              if isinstance(event.get("kind"), str)]
    assert tracker.document()["cursor"] == max(kinded)


# --------------------------------------------------------------------------
# Cross-case evidence
# --------------------------------------------------------------------------

def test_submit_success_is_observed_and_a_later_case_consumes_the_witness():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    declaration = OnlineSourceActionDeclaration(RIGHT, (RAM_PREREQUISITE,))
    executor, session, harness, subject = online_executor(
        decoder=ip_decoder(declarations=(declaration,)), gate=gate)

    # Case one cannot start: no evidence exists yet.
    executor.execute_batch(InputBatch(11, 8, ((RIGHT_RAW,),)))
    assert executor.receipts[-1].status == "input_invalid"
    assert session.cases == ()

    # Case two is admitted and its real receipt events feed the tracker.
    harness.journal_records = (commit_record(),)
    executor.execute_batch(InputBatch(12, 8, ((LEFT_RAW,),)))
    assert executor.receipts[-1].status == "complete"
    witness = tracker.matching_witness(RAM_PREREQUISITE)
    assert witness is not None
    assert witness.evidence_ref == COMMIT_ID
    assert tracker.satisfied(RAM_PREREQUISITE).satisfied is True

    # Case three consumes that witness across the case boundary.
    harness.journal_records = ()
    executor.execute_batch(InputBatch(13, 8, ((RIGHT_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "complete"
    evaluation = receipt.source_action["evaluation"]
    assert evaluation["satisfied"] is True
    assert evaluation["matched_evidence_refs"] == [COMMIT_ID]
    assert [case.case_id for case in session.cases][-1] == \
        executor.online_decisions[-1]["case_id"]


def test_duplicate_slot_returns_the_original_receipt_unchanged():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    executor, session, harness, subject = online_executor(gate=gate)
    delivered = []
    executor.execute_batch(InputBatch(21, 8, ((LEFT_RAW,),)),
                           on_receipt=delivered.append)
    first = executor.receipts[-1]
    steps, effects = harness.steps, tracker.document()["effect_count"]
    delivered.clear()
    executor.execute_batch(InputBatch(21, 8, ((LEFT_RAW,),)),
                           on_receipt=delivered.append)
    assert len(executor.receipts) == 1
    assert delivered == [first]
    assert executor.receipts[-1] == first
    assert (harness.steps, tracker.document()["effect_count"]) == (steps, effects)
    with pytest.raises(ValueError, match="slot identity reused with different input"):
        executor.execute_batch(InputBatch(21, 8, ((RIGHT_RAW,),)))


# --------------------------------------------------------------------------
# Fail-closed action construction
# --------------------------------------------------------------------------

def test_legacy_decoder_without_flow_declaration_refuses_the_action():
    gate = SourceActionGate(CrossCaseEffectTracker())
    subject = ip_decoder(flow=False)
    assert subject.document()["schema_version"] == "online_case_decoder.v2"
    case = subject.decode(LEFT_RAW)
    with pytest.raises(OnlineSourceActionRefusal) as caught:
        subject.source_action(case)
    assert caught.value.reason == "flow_category_undeclared"
    assert caught.value.detail["target_id"] == PATH_TARGET

    executor, session, harness, _ = online_executor(decoder=subject, gate=gate)
    executor.execute_batch(InputBatch(31, 8, ((LEFT_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "input_invalid"
    assert harness.steps == 0 and session.cases == ()
    structured = receipt.source_action
    assert structured["action"] is None
    assert structured["refusal"]["reason"] == "source_action_not_constructible"
    assert structured["refusal"]["detail"]["refusal"] == "flow_category_undeclared"
    assert executor.online_decisions[-1]["candidate_disposition_reason"] == \
        "source_action_not_constructible"


def test_declared_actions_require_declared_runtime_paths_and_flows():
    declaration = OnlineSourceActionDeclaration(RIGHT, (RAM_PREREQUISITE,))
    with pytest.raises(ValueError, match="declared runtime paths and flows"):
        ip_decoder(declarations=(declaration,), flow=False)
    with pytest.raises(ValueError, match="undeclared online source"):
        ip_decoder(declarations=(OnlineSourceActionDeclaration("a.other",
                                                               (RAM_PREREQUISITE,)),))
    with pytest.raises(ValueError, match="duplicate source action declaration"):
        ip_decoder(declarations=(declaration, declaration))


def test_action_requires_the_current_decoded_proposal():
    subject = ip_decoder()
    stale = subject.decode(LEFT_RAW)
    subject.decode(RIGHT_RAW)
    with pytest.raises(OnlineSourceActionRefusal) as caught:
        subject.source_action(stale)
    assert caught.value.reason == "case_not_current_proposal"


def test_bound_producer_can_never_become_a_mutable_source_action():
    subject = ip_decoder()
    case = subject.decode(RIGHT_RAW)
    # A later ownership change cannot turn a bound producer into a source.
    subject.ownership = _bound_irq_ownership()
    with pytest.raises(ValueError) as caught:
        subject.source_action(case)
    from myfuzz.scenario.rejection_codes import rejection_of
    rejection = rejection_of(caught.value)
    assert rejection is not None
    assert rejection.code.value == "ownership.bound_input"
    assert rejection.pointer == "source.port"


def test_decoder_construction_refuses_a_bound_irq_source():
    bound = _bound_irq_ownership()
    with pytest.raises(ValueError, match="bound input cannot be mutated"):
        ip_decoder(ownership=bound)


def test_contract_refuses_a_cpu_irq_endpoint_class():
    from myfuzz.scenario.source_actions import TerminationObservation
    with pytest.raises(ValueError, match="cannot be a mutable source"):
        SourceAction(action_id="case:irq", kind="external_event", component="cpu",
                     source_id="cpu.irq", ownership="fuzzable", flow_id="F5",
                     payload={"port": "irq", "bit_offset": 0, "width": 1,
                              "value": 1, "endpoint_class": "cpu_irq"},
                     termination_observation=TerminationObservation(
                         "delivery", "irq:one"),
                     local_step_budget=1)


def test_tampered_action_and_declaration_documents_are_refused():
    subject = ip_decoder(declarations=(
        OnlineSourceActionDeclaration(RIGHT, (RAM_PREREQUISITE,)),))
    case = subject.decode(RIGHT_RAW)
    action = subject.source_action(case)
    document = action.document()
    for field, value in (("flow_id", "F1"), ("local_step_budget", 1),
                         ("source_id", "other"), ("action_sha256", "0" * 64)):
        with pytest.raises(ValueError):
            SourceAction.from_document({**document, field: value})

    saved = json.loads(json.dumps(subject.document()))
    assert saved["schema_version"] == "online_case_decoder.v4"
    assert saved["source_actions"][0]["source_id"] == RIGHT
    rebuilt = OnlineCaseDecoder.from_document(saved)
    assert json.loads(json.dumps(rebuilt.document())) == saved
    assert rebuilt.source_action(rebuilt.decode(RIGHT_RAW)).document() == document
    tampered = json.loads(json.dumps(saved))
    tampered["source_actions"][0]["prerequisites"][0]["subject"]["byte_offset"] += 4
    with pytest.raises(ValueError):
        OnlineCaseDecoder.from_document(tampered)
    unknown = json.loads(json.dumps(saved))
    unknown["source_actions"][0]["source_id"] = "a.unknown"
    with pytest.raises(ValueError):
        OnlineCaseDecoder.from_document(unknown)
    extra = json.loads(json.dumps(saved))
    extra["source_actions"][0]["prerequisites"][0]["invented"] = 1
    with pytest.raises(ValueError):
        OnlineCaseDecoder.from_document(extra)
    # The refusal vocabulary itself is closed.
    with pytest.raises(ValueError, match="unknown source action refusal reason"):
        OnlineSourceActionRefusal("invented_reason")


def test_gate_configuration_is_fail_closed():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    # A gate that cannot register actions cannot serve the online path.
    class _NoRegister:
        def __init__(self, inner):
            self.inner = inner

        def require_case(self, case):
            return self.inner.require_case(case)

        def observe(self, receipt):
            return self.inner.observe(receipt)

    subject = ip_decoder()
    runner, session, _ = _runner_and_session(
        decoder=subject, session_gate=_NoRegister(gate))
    with pytest.raises(ValueError, match="must expose register"):
        ScenarioRfuzzExecutor(run_id="no-register", factory=lambda: runner,
                              targets=(TARGET,), session=session,
                              online_decoder=subject)

    # Two different gates would admit cases the session never checks.
    other = SourceActionGate(CrossCaseEffectTracker())
    with pytest.raises(ValueError, match="session prerequisite gate"):
        ScenarioRfuzzExecutor(run_id="two-gates", factory=lambda: runner,
                              targets=(TARGET,), session=session,
                              online_decoder=subject, source_action_gate=other)

    # A gate is meaningless without the online decoder path it binds.
    from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
    genome = ScenarioGenome(testcase_id="genome", direction="IP_TO_IP",
                            path_id="out", schedule_order=("a", "b"),
                            max_steps=64, actions=())
    genome_decoder = GenomeRecordDecoder(
        graph=_declaration()[0], ownership=_ownership(),
        templates=(DecoderTemplate("out", genome),), source_bindings=None)
    with pytest.raises(ValueError, match="online decoder path"):
        ScenarioRfuzzExecutor(run_id="genome-gate", factory=lambda: runner,
                              targets=(TARGET,), decoder=genome_decoder,
                              allow_legacy_search=True, source_action_gate=gate)


def test_unregistered_case_action_is_refused_without_side_effects():
    gate = SourceActionGate(CrossCaseEffectTracker())
    executor, session, harness, _ = online_executor(gate=gate)
    # A registered action can never admit a case under a foreign action id.
    executor.online_decoder = _ForgingDecoder(ip_decoder())
    executor.execute_batch(InputBatch(41, 8, ((LEFT_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "input_invalid"
    assert isinstance(receipt.error, str) and receipt.error
    assert receipt.source_action["refusal"]["reason"] == \
        "source_action_not_constructible"
    assert receipt.source_action["refusal"]["detail"]["error_type"] == \
        "SourceActionUnknownAction"
    assert harness.steps == 0 and session.cases == ()


class _ForgingDecoder:
    """Wrap a decoder so the case rides an action id the gate never registered."""

    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def source_action(self, case):
        return replace(self.inner.source_action(case),
                       action_id=case.source.action_id + ":forged",
                       action_sha256="")


# --------------------------------------------------------------------------
# Backward compatibility
# --------------------------------------------------------------------------

def test_without_a_gate_the_online_path_is_unchanged():
    executor, session, harness, subject = online_executor(gate=None)
    assert executor.source_action_gate is None
    executor.execute_batch(InputBatch(51, 8, ((LEFT_RAW,),),))
    receipt, decision = executor.receipts[-1], executor.online_decisions[-1]
    assert receipt.status == "complete"
    assert receipt.source_action is None and decision["source_action"] is None
    assert decision["candidate_disposition"] == "admitted"
    assert decision["rejection"] is None
    assert session.prerequisite_gate is None
    assert [case.case_id for case in session.cases] == [decision["case_id"]]


def test_legacy_decoder_without_flow_still_runs_without_a_gate():
    executor, session, harness, subject = online_executor(
        decoder=ip_decoder(flow=False), gate=None)
    executor.execute_batch(InputBatch(52, 8, ((LEFT_RAW,),)))
    assert executor.receipts[-1].status == "complete"
    assert executor.receipts[-1].source_action is None


def test_session_gate_is_discovered_by_the_executor():
    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    executor, session, harness, subject = online_executor(
        gate=gate, discover_gate=True)
    assert executor.source_action_gate is gate
    executor.execute_batch(InputBatch(53, 8, ((LEFT_RAW,),)))
    assert executor.receipts[-1].status == "complete"
    assert executor.receipts[-1].source_action["action"] is not None
    assert len(session.cases) == 1


def _case_checker(receipt):
    return ()


def test_live_transport_records_the_gate_decision_and_tracker_state():
    """The live artifacts carry the action decision and the tracker snapshot."""
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
    from tests.integration.test_scenario_rfuzz_terminal_identity import (
        TerminalIdentityTests)

    tracker = CrossCaseEffectTracker()
    gate = SourceActionGate(tracker)
    declaration = OnlineSourceActionDeclaration(RIGHT, (RAM_PREREQUISITE,))
    subject = ip_decoder(declarations=(declaration,))
    transport = TerminalIdentityTests(methodName="runTest")
    transport.setUp()
    try:
        runner, session, harness = _runner_and_session(decoder=subject,
                                                       session_gate=gate)
        executor = ScenarioRfuzzExecutor(
            run_id="online-source-action-live", factory=lambda: runner,
            targets=(TARGET,), session=session, online_decoder=subject)
        # The session owns the gate; the executor discovers it.
        assert executor.source_action_gate is gate
        transport.run_transport(executor, records=(RIGHT_RAW,))
        rows = [json.loads(line) for line in
                (transport.output / "receipts.jsonl").read_text().splitlines()]
        assert len(rows) == 1
        assert rows[0]["status"] == "input_invalid"
        assert rows[0]["candidate_disposition_reason"] == \
            "source_action_prerequisite_unsatisfied"
        assert rows[0]["source_action"]["refusal"]["reason"] == \
            "source_action_prerequisite_unsatisfied"
        assert rows[0]["rejection"] is None
        report = json.loads((transport.output / "report.json").read_text())
        recorded = report["source_action_gate"]
        assert recorded["schema_version"] == "online_source_action_gate_report.v1"
        assert recorded["enforce"] is True
        assert recorded["action_ids"] == [f"{rows[0]['case_id']}:{RIGHT}"]
        assert recorded["gate"]["schema_version"] == "source_action_gate.v1"
        assert recorded["gate"]["tracker"]["schema_version"] == \
            "cross_case_effect_tracker.v1"
        assert recorded["gate"]["tracker"]["counters"]["refused"] == 1
        assert report["statuses"] == {"input_invalid": 1}
    finally:
        transport.doCleanups()


def test_live_transport_without_a_gate_reports_none():
    from tests.integration.test_scenario_rfuzz_terminal_identity import (
        TerminalIdentityTests)

    subject = ip_decoder()
    transport = TerminalIdentityTests(methodName="runTest")
    transport.setUp()
    try:
        runner, session, harness = _runner_and_session(decoder=subject)
        executor = ScenarioRfuzzExecutor(
            run_id="online-no-gate-live", factory=lambda: runner,
            targets=(TARGET,), session=session, online_decoder=subject)
        transport.run_transport(executor, records=(LEFT_RAW,))
        rows = [json.loads(line) for line in
                (transport.output / "receipts.jsonl").read_text().splitlines()]
        assert rows[0]["source_action"] is None
        assert rows[0]["status"] == "complete"
        report = json.loads((transport.output / "report.json").read_text())
        assert report["source_action_gate"] is None
    finally:
        transport.doCleanups()
