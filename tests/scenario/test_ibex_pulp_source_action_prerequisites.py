"""The shipped Ibex/PULP online policy gates each case's own fetch slot.

Software only: no RTL is compiled, rendered into a process or started.  The
offline CPU stub below performs real step calls and journals the *same record
shape* the generated CPU's memory service journals (``instruction_source`` with
``component``/``address``/``data_hex``), drained during the step exactly like
``ScenarioRunner._append_external_events`` drains the service stream.  The DUT
evidence is therefore explicitly synthetic, while the whole chain (decoder ->
``source_action`` -> gate ``register``/``require_case`` -> ``submit_case`` ->
gate ``observe`` -> tracker witness -> next case) is the production wiring.

Covered here:
* the shipped policy is a *declared*, bounded declaration, not a registration:
  the window is the bootstrap's declared online reservation, nothing is
  registered up front, and a tracker too small for the declared window is
  refused at construction;
* every admitted instruction case is bound to the exact word(s) its own
  declared payload fills and those reservations are registered lazily;
* a satisfied prerequisite admits the case normally, and the case's real
  ``instruction_source`` evidence materializes exactly those words;
* a later case on a fresh slot is admitted while the earlier case's slots are
  then refused (cross-case), and a case that names an already materialized slot
  is refused with ``input_invalid`` plus the existing structured keys and zero
  change to runner event count, local ticks, case history or step count;
* a static once-declared slot prerequisite cannot follow the moving cursor, so
  it is refused for the second case: the reason the shipped policy resolves the
  address per case;
* an instruction action outside the declared window fails closed;
* the Ibex factory and runtime attach one fresh shipped gate per session by
  default, while ``source_actions=False`` is the explicitly declared legacy
  path (no gate, no per-case action, no receipt field);
* the CV32E40P factory on the same shared wiring keeps the legacy path.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.cv32e40p_pulp_dual_source import (
    make_cv32e40p_pulp_dual_source_factory)
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ibex_pulp_dual_source import (
    ONLINE_INSTRUCTION_START, ONLINE_SLOT_RESERVATION_PREFIX,
    make_ibex_pulp_dual_source_factory, make_ibex_pulp_dual_source_stream_bootstrap,
    make_pulp_dual_source_source_action_gate)
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder, OnlineDependencyGraph, OnlineDependencySource,
    OnlineSource, OnlineSourceActionDeclaration)
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario.session_runtime import ScenarioSession
from myfuzz.scenario.source_actions import (
    CrossCaseEffectTracker, InstructionSlotReservationGate, SourceActionGate,
    SourceActionInputMismatch, SourceActionSlotWindowError,
    instruction_slot_unmaterialized_prerequisite)


SOURCE = "cpu.online_instruction"
TARGET = "cpu_to_ip_to_cpu.closed_loop"
DIRECTION = "CPU_TO_IP_TO_CPU"
WINDOW_START = 0x1000
WINDOW_END = 0x1020
TARGET_COVERAGE = CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1)
#: Byte two directly selects the one declared source; bytes three.. seven stay
#: entropy, so two records share a slot but never a case identity.
FIRST_RAW = bytes((0, 0, 0, 7, 0, 0, 0, 0))
SECOND_RAW = bytes((0, 0, 0, 9, 1, 0, 0, 0))


def _contract_digest(graph) -> str:
    return hashlib.sha256(json.dumps(
        graph.edge_document(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def instruction_decoder(*, declarations=(), flow=True, window=(WINDOW_START, WINDOW_END),
                        cursor=None):
    """One declared CPU instruction source over a reserved online window."""
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
        schedule=("cpu",), instruction_start=window[0], instruction_end=window[1],
        instruction_cursor=(window[0] if cursor is None else cursor),
        advance_rounds=2, max_input_bytes=8,
        windows=(MmioWindow(0x4000100c, 4),),
        flow_by_target=({TARGET: "F4"} if flow else None),
        source_actions=tuple(declarations))


class _Cpu:
    """Offline CPU harness: real steps plus real-shaped slot journal records."""

    def __init__(self):
        self.runner = None
        self.steps = 0
        self.slots: tuple[int, int] | None = None
        self.accepted: list[tuple[int, str, str]] = []
        self.pending: list[dict] = []

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
        # The generated CPU journals its service events while it steps.
        while self.pending:
            self.runner._events.append(
                {"event_id": len(self.runner._events) + 1,
                 "component": "cpu", **self.pending.pop(0)})
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


def shipped_gate(*, window=(WINDOW_START, WINDOW_END), component="cpu", tracker=None):
    """The shipped policy builder, over a small declared window."""
    return make_pulp_dual_source_source_action_gate(
        component=component, instruction_start=window[0], instruction_end=window[1],
        tracker=tracker)


def _runner_and_session(*, decoder, gate=None):
    harness = _Cpu()
    runner = ScenarioRunner(sessions={"cpu": harness}, ownership=decoder.ownership,
                            bindings=())
    harness.runner = runner
    template = ScenarioGenome(testcase_id="ibex-pulp-slot-policy", direction=DIRECTION,
                              path_id=TARGET, schedule_order=("cpu",), max_steps=64,
                              actions=())
    session = ScenarioSession(template, runner, checker=lambda receipt: (),
                              prerequisite_gate=gate)
    session.declare_instruction_slots("cpu", decoder.instruction_start,
                                      (decoder.instruction_end
                                       - decoder.instruction_start) // 4)
    session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                    decoder.runtime_paths,
                                    source_ownership=decoder.ownership)
    session.begin()
    return runner, session, harness


def online_executor(*, decoder=None, gate=None):
    """Wire a real executor around the offline CPU stub."""
    subject = instruction_decoder() if decoder is None else decoder
    runner, session, harness = _runner_and_session(decoder=subject, gate=gate)
    executor = ScenarioRfuzzExecutor(
        run_id="ibex-pulp-slot-policy", factory=lambda: runner,
        targets=(TARGET_COVERAGE,), session=session, online_decoder=subject)
    return executor, session, harness, subject


def _action_words(action: dict) -> list[int]:
    return [item["subject"]["address"] for item in action["prerequisites"]]


def _refs(action: dict) -> list[str]:
    return [item["evidence_ref"] for item in action["prerequisites"]]


# --------------------------------------------------------------------------
# The declaration: window, bound, lazy registration, fail-closed capacity
# --------------------------------------------------------------------------

def test_shipped_window_is_the_declared_bootstrap_reservation_and_registers_nothing():
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    gate = shipped_gate(window=(bootstrap.instruction_start, bootstrap.instruction_end))
    declaration = gate.document()["declaration"]
    assert declaration == {
        "component": "cpu", "first_address": 0x11000, "last_address": 0x2FE00,
        "word_bytes": 4, "declared_words": 31616,
        "reservation_ref_prefix": ONLINE_SLOT_RESERVATION_PREFIX,
        "registration": "lazy_per_admitted_case",
        "prerequisite_kind": "instruction_slot_unmaterialized"}
    assert gate.declared_words == bootstrap.instruction_count == 31616
    # The declared window is an upper bound, never a registration: eagerly
    # registering 0x11000..0x2fe00 would fill a 512-slot tracker and evict the
    # earliest slots before their cases could query them.
    assert gate.tracker.max_slots == 31616
    assert gate.tracker.document()["slot_count"] == 0
    assert gate.tracker.document()["materialized_count"] == 0
    assert ONLINE_INSTRUCTION_START == 0x11000 and gate.first_address == 0x11000
    assert gate.reservation_ref(0x11000) == f"{ONLINE_SLOT_RESERVATION_PREFIX}:0x00011000"


def test_the_policy_refuses_a_tracker_too_small_for_its_declared_window():
    with pytest.raises(ValueError, match="exceeds the tracker slot capacity"):
        shipped_gate(window=(0x1000, 0x1020),
                     tracker=CrossCaseEffectTracker(max_slots=7))
    # Exactly the declared word count is admissible.
    assert shipped_gate(window=(0x1000, 0x1020),
                        tracker=CrossCaseEffectTracker(max_slots=8)).declared_words == 8
    with pytest.raises(ValueError, match="requires a nonempty word window"):
        shipped_gate(window=(0x1008, 0x1000))


def test_a_bad_policy_window_or_component_is_refused():
    with pytest.raises(ValueError, match="must be nonempty and strictly increasing"):
        InstructionSlotReservationGate(SourceActionGate(CrossCaseEffectTracker()),
                                       component="cpu", first_address=0x1000,
                                       last_address=0x1000,
                                       reservation_ref_prefix="ref")
    with pytest.raises(ValueError, match="must be word aligned"):
        InstructionSlotReservationGate(SourceActionGate(CrossCaseEffectTracker()),
                                       component="cpu", first_address=0x1002,
                                       last_address=0x1010,
                                       reservation_ref_prefix="ref")
    with pytest.raises(ValueError, match="requires a CPU component"):
        shipped_gate(component="")


# --------------------------------------------------------------------------
# Per-case binding, admission and the real materialization it produces
# --------------------------------------------------------------------------

def test_each_admitted_case_is_bound_registered_and_then_materialized():
    gate = shipped_gate()
    executor, session, harness, subject = online_executor(gate=gate)
    assert session.prerequisite_gate is gate
    assert executor.source_action_gate is gate

    executor.execute_batch(InputBatch(1, 8, ((FIRST_RAW,),)))

    receipt, decision = executor.receipts[-1], executor.online_decisions[-1]
    assert receipt.status == "complete"
    assert decision["candidate_disposition"] == "admitted"
    assert decision["candidate_disposition_reason"] == "rtl_case_committed"
    structured = receipt.source_action
    assert structured["schema_version"] == "online_source_action.v1"
    action = structured["action"]
    words = _action_words(action)
    assert words == [WINDOW_START + 4 * index
                     for index in range(len(action["prerequisites"]))]
    assert [item["kind"] for item in action["prerequisites"]] == \
        ["instruction_slot_unmaterialized"] * len(words)
    assert _refs(action) == [gate.reservation_ref(word) for word in words]
    # The requirement was answered by this session's own tracker, not invented.
    evaluation = structured["evaluation"]
    assert evaluation["satisfied"] is True
    assert evaluation["reason"] == "satisfied"
    assert evaluation["matched_evidence_refs"] == _refs(action)
    assert structured["refusal"] is None
    assert json.loads(json.dumps(structured)) == structured
    # The case really filled exactly those words, so its own journal evidence
    # materialized them; the reservation count equals the fragment word count.
    tracker = gate.tracker.document()
    assert tracker["slot_count"] == len(words)
    assert tracker["materialized_count"] == len(words)
    assert gate.counters["reservations"] == len(words)
    # Two queries per admitted case: the executor binds before submitting and
    # the session re-queries before any RTL command.
    assert gate.counters["queries"] == 2
    assert gate.counters["refusals"] == 0
    assert subject.instruction_cursor == WINDOW_START + 4 * len(words)
    assert harness.steps == 2
    assert [item[0] for item in harness.accepted] == [WINDOW_START]


# --------------------------------------------------------------------------
# Cross-case: a later case consumes the tracker state the earlier case left
# --------------------------------------------------------------------------

def test_a_later_case_on_a_fresh_slot_is_admitted_and_the_earlier_slots_refused():
    gate = shipped_gate()
    executor, session, harness, subject = online_executor(gate=gate)
    executor.execute_batch(InputBatch(2, 8, ((FIRST_RAW,),)))
    first = executor.receipts[-1]
    assert first.status == "complete"
    first_words = _action_words(first.source_action["action"])

    executor.execute_batch(InputBatch(3, 8, ((SECOND_RAW,),)))
    second = executor.receipts[-1]
    assert second.status == "complete"
    second_words = _action_words(second.source_action["action"])
    assert set(first_words).isdisjoint(second_words)
    # The later case's own requirement was satisfied from tracker state, and its
    # receipt names exactly the reservation it consumed.
    assert second.source_action["evaluation"]["satisfied"] is True
    assert second.source_action["evaluation"]["matched_evidence_refs"] == \
        [gate.reservation_ref(word) for word in second_words]

    # Cross-case: the slots case one materialized are refused from then on.
    for word in first_words:
        evaluation = gate.tracker.satisfied(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", word, gate.reservation_ref(word)))
        assert evaluation.satisfied is False
        assert evaluation.reason == "materialized_instruction_slot"
    for word in second_words:
        assert gate.tracker.satisfied(
            instruction_slot_unmaterialized_prerequisite(
                "cpu", word, gate.reservation_ref(word))).satisfied is False
    assert gate.counters["queries"] == 4
    assert gate.counters["refusals"] == 0


def test_a_case_that_names_a_materialized_slot_is_refused_before_any_rtl_command():
    gate = shipped_gate()
    executor, session, harness, subject = online_executor(gate=gate)
    executor.execute_batch(InputBatch(4, 8, ((FIRST_RAW,),)))
    first = executor.receipts[-1]
    assert first.status == "complete"
    materialized = _action_words(first.source_action["action"])

    # A caller that re-uses the declared window (a fresh decoder over the same
    # reservation) proposes that very slot again.
    executor.online_decoder = instruction_decoder()
    before = (session.runner.event_count, dict(session.runner.local_ticks),
              len(session.cases), harness.steps, tuple(harness.accepted))
    executor.execute_batch(InputBatch(5, 8, ((SECOND_RAW,),)))

    receipt, decision = executor.receipts[-1], executor.online_decisions[-1]
    # Refused before any RTL command: nothing reached the runner, memory or
    # case history, exactly like the existing pre-RTL refusals.
    assert (session.runner.event_count, dict(session.runner.local_ticks),
            len(session.cases), harness.steps, tuple(harness.accepted)) == before
    assert receipt.status == "input_invalid"
    assert decision["candidate_disposition"] == "rejected"
    assert decision["candidate_disposition_reason"] == \
        "source_action_prerequisite_unsatisfied"
    assert decision["rejection"] is None and receipt.rejection is None
    structured = receipt.source_action
    assert structured["refusal"]["reason"] == "source_action_prerequisite_unsatisfied"
    assert structured["refusal"]["detail"]["evaluation_reason"] == \
        "materialized_instruction_slot"
    assert structured["refusal"]["detail"]["missing_kinds"] == \
        ["instruction_slot_unmaterialized"]
    assert set(_action_words(structured["action"])).issuperset(materialized)
    assert structured["evaluation"]["satisfied"] is False
    # The evidence decides per word: the already materialized word is missing
    # while every still-fresh word of the same action matched.
    action_words = _action_words(structured["action"])
    missing_words = [item["subject"]["address"]
                     for item in structured["evaluation"]["missing"]]
    assert set(missing_words) == set(materialized)
    assert structured["evaluation"]["matched_evidence_refs"] == [
        gate.reservation_ref(word) for word in action_words
        if word not in missing_words]
    # Two queries for the admitted case, one for the refused one: the executor
    # refuses before the session is reached.
    assert gate.counters["queries"] == 3
    assert gate.counters["refusals"] == 1
    assert gate.counters["redeclared_reservations"] >= 1


def test_a_static_declared_slot_cannot_follow_the_moving_cursor():
    """Why the shipped policy resolves the address per case, with evidence."""
    static = instruction_slot_unmaterialized_prerequisite(
        "cpu", WINDOW_START, "static-slot:declared")
    subject = instruction_decoder(declarations=(
        OnlineSourceActionDeclaration(SOURCE, (static,)),))
    gate = SourceActionGate(CrossCaseEffectTracker(max_slots=8))
    # The module contract requires the caller to register the declared
    # reservation; here it is the declaration itself.
    gate.tracker.register_instruction_slot("cpu", WINDOW_START, "static-slot:declared",
                                           event_id=1)
    executor, session, harness, _ = online_executor(decoder=subject, gate=gate)
    executor.execute_batch(InputBatch(6, 8, ((FIRST_RAW,),)))
    assert executor.receipts[-1].status == "complete"

    executor.execute_batch(InputBatch(7, 8, ((SECOND_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "input_invalid"
    assert receipt.source_action["action"]["prerequisites"] == \
        [static.document()]
    # The second case's own target is still fresh, yet the once-declared slot is
    # already materialized by case one.
    assert receipt.source_action["refusal"]["detail"]["evaluation_reason"] == \
        "materialized_instruction_slot"
    assert session.runner.sessions["cpu"].accepted[-1][0] == WINDOW_START
    assert harness.steps == 2


# --------------------------------------------------------------------------
# Fail-closed policy boundary
# --------------------------------------------------------------------------

def test_an_instruction_action_outside_the_declared_window_is_refused():
    gate = shipped_gate(window=(0x1000, 0x1008))
    subject = instruction_decoder(window=(0x1000, 0x1020), cursor=0x1008)
    case = subject.decode(FIRST_RAW)
    with pytest.raises(SourceActionSlotWindowError, match="outside the declared slot window"):
        gate.register(subject.source_action(case))
    assert gate.counters["refused_out_of_window"] == 1

    executor, session, harness, _ = online_executor(
        decoder=instruction_decoder(window=(0x1000, 0x1020), cursor=0x1008), gate=gate)
    before = (session.runner.event_count, dict(session.runner.local_ticks), harness.steps)
    executor.execute_batch(InputBatch(8, 8, ((FIRST_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "input_invalid"
    assert receipt.source_action["refusal"]["reason"] == \
        "source_action_not_constructible"
    assert receipt.source_action["refusal"]["detail"]["error_type"] == \
        "SourceActionSlotWindowError"
    assert (session.runner.event_count, dict(session.runner.local_ticks),
            harness.steps) == before
    assert session.cases == ()


def test_a_gate_that_does_not_return_an_action_is_refused():
    gate = shipped_gate()
    executor, session, harness, subject = online_executor(gate=gate)

    class _Forger:
        def __getattr__(self, name):
            return getattr(gate, name)

        def register(self, action):
            return None

    executor.source_action_gate = _Forger()
    executor.execute_batch(InputBatch(9, 8, ((FIRST_RAW,),)))
    receipt = executor.receipts[-1]
    assert receipt.status == "input_invalid"
    assert receipt.source_action["refusal"]["detail"]["error_type"] == "ValueError"
    assert "must return the admitted action" in \
        receipt.source_action["refusal"]["detail"]["message"]
    assert harness.steps == 0 and session.cases == ()


# --------------------------------------------------------------------------
# Shipped factory and runtime wiring (no RTL is started)
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def rendered_factories(tmp_path_factory):
    cache = tmp_path_factory.mktemp("ibex-pulp-slot-policy")
    return {
        "ibex": make_ibex_pulp_dual_source_factory(cache),
        "legacy": make_ibex_pulp_dual_source_factory(cache, source_actions=False),
        "cv32e40p": make_cv32e40p_pulp_dual_source_factory(cache),
    }


def test_ibex_factory_declares_one_fresh_shipped_gate_per_session(rendered_factories):
    factory = rendered_factories["ibex"]
    build = factory.new_source_action_gate
    gate = build()
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    assert isinstance(gate, InstructionSlotReservationGate)
    assert gate.component == "cpu"
    assert (gate.first_address, gate.last_address) == \
        (bootstrap.instruction_start, bootstrap.instruction_end)
    assert gate.declared_words == bootstrap.instruction_count == 31616
    # Gate state is run state: a second session never shares the first tracker.
    other = build()
    assert other is not gate and other.tracker is not gate.tracker
    assert gate.tracker.document()["slot_count"] == 0


def test_legacy_switches_declare_no_gate_on_either_cpu(rendered_factories):
    assert not hasattr(rendered_factories["legacy"], "new_source_action_gate")
    assert not hasattr(rendered_factories["cv32e40p"], "new_source_action_gate")


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


def _runtime_session(tmp_path, monkeypatch, **kwargs):
    from myfuzz.integration import ibex_pulp_online
    recorded = {}

    def session_factory(template, runner, **session_kwargs):
        recorded["session"] = _RecordingSession(template, runner, **session_kwargs)
        return recorded["session"]

    monkeypatch.setattr(ibex_pulp_online, "ScenarioSession", session_factory)
    with pytest.raises(_StopBeforeRtl):
        ibex_pulp_online.make_ibex_pulp_online_runtime(
            cache_dir=tmp_path, run_id="slot-policy-wiring", **kwargs)
    return recorded["session"]


def test_ibex_online_runtime_attaches_the_shipped_gate_by_default(tmp_path, monkeypatch):
    session = _runtime_session(tmp_path, monkeypatch)
    gate = session.prerequisite_gate
    bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    assert isinstance(gate, InstructionSlotReservationGate)
    assert gate.component == "cpu"
    assert (gate.first_address, gate.last_address) == \
        (bootstrap.instruction_start, bootstrap.instruction_end)
    assert gate.declared_words == bootstrap.instruction_count
    assert session.calls[0] == ("slots", "cpu", bootstrap.instruction_start,
                               bootstrap.instruction_count)
    assert session.calls[1] == ("paths",)
    # The gate is the session's own object, so the executor that is built from
    # this session discovers it instead of trusting a caller's claim.
    assert session.runner.sessions["cpu"]._process is None


def test_ibex_online_runtime_legacy_path_carries_no_gate(tmp_path, monkeypatch):
    session = _runtime_session(tmp_path, monkeypatch, source_actions=False)
    assert session.prerequisite_gate is None
    assert session.calls[0][0] == "slots"


def test_shared_wiring_second_cpu_keeps_the_legacy_path(rendered_factories):
    runner = rendered_factories["cv32e40p"]()
    assert getattr(runner, "source_action_gate", None) is None
    assert all(session._process is None for session in runner.sessions.values())


# --------------------------------------------------------------------------
# The live artifacts a root gate reads
# --------------------------------------------------------------------------

def test_live_transport_records_the_shipped_policy_and_its_tracker_state():
    """The receipts and the report expose the exact keys a root gate checks."""
    from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
    from tests.integration.test_scenario_rfuzz_terminal_identity import (
        TerminalIdentityTests)

    gate = shipped_gate()
    executor, session, harness, subject = online_executor(gate=gate)
    transport = TerminalIdentityTests(methodName="runTest")
    transport.setUp()
    try:
        transport.run_transport(executor, records=(FIRST_RAW,))
        rows = [json.loads(line) for line in
                (transport.output / "receipts.jsonl").read_text().splitlines()]
        assert len(rows) == 1
        assert rows[0]["status"] == "complete"
        assert rows[0]["candidate_disposition"] == "admitted"
        assert rows[0]["candidate_disposition_reason"] == "rtl_case_committed"
        structured = rows[0]["source_action"]
        action = structured["action"]
        assert [item["kind"] for item in action["prerequisites"]] == \
            ["instruction_slot_unmaterialized"] * len(action["prerequisites"])
        assert structured["evaluation"]["matched_evidence_refs"] == _refs(action)
        assert structured["refusal"] is None

        report = json.loads((transport.output / "report.json").read_text())
        recorded = report["source_action_gate"]
        assert recorded["schema_version"] == "online_source_action_gate_report.v1"
        assert recorded["enforce"] is True
        assert recorded["action_ids"] == [f"{rows[0]['case_id']}:{SOURCE}"]
        policy = recorded["gate"]
        # The declared policy is what a reviewer recomputes the bound
        # prerequisite and its evidence reference from.
        assert policy["schema_version"] == "instruction_slot_reservation_gate.v1"
        assert policy["declaration"] == gate.declaration()
        assert policy["counters"]["bound_actions"] == 1
        assert policy["counters"]["reservations"] == len(action["prerequisites"])
        assert policy["counters"]["queries"] == 2
        assert policy["counters"]["refusals"] == 0
        tracker = policy["gate"]["tracker"]
        assert policy["gate"]["schema_version"] == "source_action_gate.v1"
        assert tracker["schema_version"] == "cross_case_effect_tracker.v1"
        assert tracker["slot_count"] == len(action["prerequisites"])
        assert tracker["materialized_count"] == len(action["prerequisites"])
        assert tracker["counters"]["refused"] == 0
        assert tracker["bounds"]["max_slots"] == gate.declared_words
        assert report["statuses"] == {"complete": 1}
    finally:
        transport.doCleanups()


def test_the_gate_compares_one_declared_input_under_either_spelling():
    """The action vocabulary (``words_hex``) and the case record (``data_hex``).

    Without this mapping an instruction source action can never be admitted:
    the action payload names the declared bytes ``words_hex`` while the online
    instruction record names the same bytes ``data_hex``.
    """
    class _Spelled:
        component = "cpu"

        def __init__(self, address, spellings):
            self.address = address
            for name, value in spellings.items():
                setattr(self, name, value)

    subject = instruction_decoder()
    action = subject.source_action(subject.decode(FIRST_RAW))
    words = action.payload["words_hex"]
    for spellings in ({"words_hex": words}, {"data_hex": words},
                      {"words_hex": words, "data_hex": words}):
        SourceActionGate._assert_case_input(action, _Spelled(WINDOW_START, spellings))
    with pytest.raises(SourceActionInputMismatch, match="conflicting words_hex"):
        SourceActionGate._assert_case_input(
            action, _Spelled(WINDOW_START, {"words_hex": words,
                                            "data_hex": "93000000"}))
    with pytest.raises(SourceActionInputMismatch, match="does not declare words_hex"):
        SourceActionGate._assert_case_input(action, _Spelled(WINDOW_START, {}))
    with pytest.raises(SourceActionInputMismatch, match="differs from action"):
        SourceActionGate._assert_case_input(
            action, _Spelled(WINDOW_START + 4, {"data_hex": words}))
