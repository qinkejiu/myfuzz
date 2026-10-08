"""Live wiring of the opt-in declared path-switch operator.

Software only: no RTL is compiled, rendered into a process or started.  The
synthetic decoders below declare real switch pools and every admitted case is
still submitted to a real ``ScenarioRunner`` journal through the stub session,
so the shipped online loop is the thing under test.

Covered here:
* the switch is off by default, resolves from ``MYFUZZ_PATH_SWITCH`` only on the
  online decoder path, and requires that path when enabled explicitly;
* a granted switch retargets the *submitted* case inside the declared pool: the
  decision names the applied record, the retargeted path and source, and the
  ``declared_path_switch`` selection reason, and the decoder's own retained
  record carries the same operator id;
* the draw is a pure function of the raw record and the declared pool: the
  applied target is the row the documented domain-separated digest names, two
  executors fed the same raws propose identical switches, and a switch never
  consumes an extra case (case ids and the decoder sequence of an enabled run
  match the disabled twin slot for slot);
* a switch that changed nothing keeps the unswitched candidate identity and the
  unswitched selection reason while still reporting its applied record;
* a declared but unavailable target is refused by the decoder's own shipped code
  (``budget.exhausted``), the refusal is recorded with its request and code, and
  the unswitched case is still submitted unchanged;
* the run-level switch state document is schema-versioned, counts attempts,
  changed switches, no-ops and refusals, and is reported even when off.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json

import pytest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import (
    PATH_SWITCH_ENV,
    PATH_SWITCH_REFUSAL_VERSION,
    PATH_SWITCH_STATE_VERSION,
    ScenarioRfuzzExecutor,
)
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder,
    OnlineDependencyGraph,
    OnlineDependencySource,
    OnlineSource,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract,
    RuntimeNode,
    RuntimePathContract,
)
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, ScenarioSession

#: The domain-separated digest the operator draws its declared target from.
#: Pinned here so the choice is checked against the documented rule instead of
#: against the implementation's own internals.
SWITCH_DOMAIN = b"myfuzz.online.path_switch.v1\0"

DIRECTION = "IP_TO_IP"
FLOW = "F5"
TARGET = "target"
SCHEDULE = ("a", "b", "cpu")
CASE_RAW = bytes((0, 0, 255, 7, 0, 0, 0, 0))
ALT_RAW = bytes((0, 0, 0, 7, 0, 0, 0, 0))
CPU_SOURCE, PIN_SOURCE = "cpu.it", "a.pin"
CPU_PATH, PIN_PATH = "cpu-path", "pin-path"


def _rows_by_source(decoder) -> dict[str, dict]:
    """The declared switch pool keyed by the one source each row declares."""
    rows = decoder.path_switch_targets()
    return {row["source_ids"][0]: row for row in rows}


def _row_index(decoder, row) -> int:
    return list(decoder.path_switch_targets()).index(row)


def _ownership():
    return compile_ownership(
        (InputField("a", "pin", 1),),
        (InputOwner("a", "pin", 0, 1, "source", "external_pin"),))


def _graph():
    return OnlineDependencyGraph(
        sources=(OnlineDependencySource(CPU_SOURCE, "instruction", "cpu",
                                        (DIRECTION,)),
                 OnlineDependencySource(PIN_SOURCE, "source", "a", (DIRECTION,),
                                        port="pin")),
        rules=(DependencyRule(TARGET, (CPU_SOURCE,), "EVENT_ORDER"),
               DependencyRule(TARGET, (PIN_SOURCE,), "EVENT_ORDER")))


def _contract(graph):
    nodes = (RuntimeNode(CPU_SOURCE, "cpu", "logical"),
             RuntimeNode(PIN_SOURCE, "a", "physical", "pin", 0, 1),
             RuntimeNode(TARGET, "b", "logical"))
    return RuntimePathContract(
        hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
                                  separators=(",", ":"), ensure_ascii=False)
                       .encode("utf-8")).hexdigest(),
        nodes, (RuntimeEdgeContract(0, 0, "causal_order"),
                RuntimeEdgeContract(1, 0, "causal_order")))


def two_path_decoder(*, instruction_end=0x2000) -> OnlineCaseDecoder:
    """One CPU instruction path beside one external pin path to one target.

    With ``instruction_end`` level with the start of the reservation, the CPU
    path is declared but has no eligible source, which is exactly the declared
    but unavailable target the live operator must refuse.
    """
    graph = _graph()
    return OnlineCaseDecoder(
        sources=(OnlineSource(CPU_SOURCE, "instruction", "cpu", DIRECTION, TARGET),
                 OnlineSource(PIN_SOURCE, "source", "a", DIRECTION, TARGET,
                              port="pin")),
        ownership=_ownership(), graph=graph, runtime_contract=_contract(graph),
        schedule=SCHEDULE, instruction_start=0x1000,
        instruction_end=instruction_end, advance_rounds=2, max_input_bytes=8,
        windows=(MmioWindow(0x40000000, 0x1000),), support_words=2,
        flow_by_target={TARGET: FLOW})


class _StubSession(ScenarioSession):
    """One real session journal fed by synthetic case events.

    The template is derived from the decoder under test (direction, declared
    path and schedule), so one stub serves the synthetic two-path pool and the
    real Ibex dual-source declaration unchanged.
    """

    def __init__(self, runner, decoder):
        source = decoder.sources[0]
        super().__init__(ScenarioGenome(
            testcase_id="path-switch-stub", direction=source.direction,
            path_id=source.path_id, schedule_order=tuple(decoder.advances[0].schedule),
            max_steps=(decoder.max_steps or 512), actions=()), runner)
        self._manifest_sha256 = hashlib.sha256(b"path-switch-stub").hexdigest()
        self._manifest_document = {"schema_version": "online_session_manifest.v1",
                                   "stub": True}

    def submit_case(self, case, *, source_role="fuzz_source"):
        start = self.runner.event_count
        ticks_before = dict(self.runner.local_ticks)
        return OnlineCaseReceipt(case.case_id, start, self.runner.event_count,
                                 self.runner.events_since(start), ticks_before,
                                 dict(self.runner.local_ticks), "running")

    def finish(self, *, defer_semantic_hash=False):
        from myfuzz.scenario.replay import ScenarioTrace
        return ScenarioTrace(self._manifest_sha256, "complete", self.runner.events,
                             dict(self.runner.local_ticks), "s" * 64,
                             self._manifest_sha256)

    def encode_plan(self):
        return b"path-switch-stub-plan"


def _executor(decoder=None, **kwargs) -> ScenarioRfuzzExecutor:
    decoder = two_path_decoder() if decoder is None else decoder
    schedule = tuple(decoder.advances[0].schedule)
    runner = ScenarioRunner(sessions={name: object() for name in schedule},
                            ownership=decoder.ownership, bindings=())
    session = _StubSession(runner, decoder)
    if decoder.runtime_contract is not None:
        # A contract-declaring decoder requires the session to hold the same
        # declared routes before the first case, exactly as a real runtime does.
        session.configure_runtime_paths(decoder.graph, decoder.runtime_contract,
                                        decoder.runtime_paths,
                                        source_ownership=decoder.ownership)
    return ScenarioRfuzzExecutor(
        run_id="path-switch-live", online_decoder=decoder,
        session=session, factory=lambda: None,
        targets=(CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),),
        **kwargs)


def _run(executor, raws, *, buffer_id=1) -> None:
    executor.batch_size = len(raws)
    executor.execute_batch(InputBatch(buffer_id, 8, tuple((raw,) for raw in raws)))


def _switch(decision) -> dict | None:
    return decision.get("path_switch")


def _unswitched_decision(raw: bytes, decoder=None) -> dict:
    """The decision a disabled twin makes for one record, in the shipped loop."""
    off = _executor(decoder=decoder, path_switch=False)
    _run(off, (raw,))
    return off.online_decisions[0]


def _raw_for_row(decoder, wanted: int, *, decode_source: str | None = None) -> bytes:
    """A raw record whose declared-pool draw lands on row ``wanted``.

    The draw rule is the shipped one: a raw-derived digest over the declared
    rows in declaration order.  With ``decode_source``, the record must also
    decode to that declared source before the operator runs, which is what makes
    the switched and unswitched arms differ by the operator alone.
    """
    rows = decoder.path_switch_targets()
    for byte in range(256):
        raw = bytes((0, 0, 255, byte, byte, 0, 0, 0))
        digest = hashlib.sha256(SWITCH_DOMAIN + raw).digest()
        if int.from_bytes(digest[:8], "little") % len(rows) != wanted:
            continue
        if decode_source is None:
            return raw
        # The search predicate is the shipped loop itself: the executor decodes
        # with its own published coverage hints, so only a real disabled run can
        # say which declared source this record selects.
        if _unswitched_decision(raw)["source_id"] == decode_source:
            return raw
    raise AssertionError("no raw record draws the declared switch row")


# ------------------------------------------------------------- the opt-in gate


def test_switch_is_off_by_default_and_resolves_from_the_environment(monkeypatch):
    monkeypatch.delenv(PATH_SWITCH_ENV, raising=False)
    default = _executor()
    assert default.path_switch is False
    assert default.path_switch_source == "default"

    # An explicit constructor value always wins over the environment.
    monkeypatch.setenv(PATH_SWITCH_ENV, "1")
    assert _executor(path_switch=True).path_switch is True
    assert _executor(path_switch=True).path_switch_source == "constructor"
    assert _executor(path_switch=False).path_switch is False
    assert _executor().path_switch is True
    assert _executor().path_switch_source == "environment"

    monkeypatch.setenv(PATH_SWITCH_ENV, "0")
    assert _executor().path_switch is False

    monkeypatch.setenv(PATH_SWITCH_ENV, "maybe")
    with pytest.raises(ValueError, match=PATH_SWITCH_ENV):
        _executor()

    with pytest.raises(ValueError, match="boolean"):
        _executor(path_switch=1)


def test_switch_requires_the_online_decoder_path():
    with pytest.raises(ValueError, match="online decoder"):
        ScenarioRfuzzExecutor(run_id="no-online", path_switch=True,
                              factory=lambda: None, targets=())


# --------------------------------------------------- granted switch on the loop


def test_granted_switch_retargets_the_submitted_case_and_names_its_operator():
    decoder = two_path_decoder()
    rows = _rows_by_source(decoder)
    cpu_row, pin_row = rows[CPU_SOURCE], rows[PIN_SOURCE]
    assert len(decoder.path_switch_targets()) == 2
    # A raw whose draw names the CPU row, while the unswitched decode selects the
    # pin path: the two arms then differ only by the operator.
    raw = _raw_for_row(decoder, _row_index(decoder, cpu_row),
                       decode_source=PIN_SOURCE)
    off, on = _executor(path_switch=False), _executor(path_switch=True)
    _run(off, (raw,))
    _run(on, (raw,))
    base, switched = off.online_decisions[0], on.online_decisions[0]
    assert base["path_id"] == pin_row["path_id"] != cpu_row["path_id"]

    assert _switch(base) is None
    record = _switch(switched)
    assert record["schema_version"] == "online_path_switch.v1"
    assert record["changed"] is True
    # The request names the declared target path and a declared source of that
    # path, so the applied record declares both operator families.
    assert record["families"] == ["path_switch", "source_switch"]
    assert record["from_path_id"] == pin_row["path_id"]
    assert record["path_id"] == cpu_row["path_id"]
    assert record["from_source_id"] == PIN_SOURCE
    assert record["source_id"] == CPU_SOURCE
    assert record["flow_id"] == FLOW
    assert switched["source_selection_reason"] == "declared_path_switch"
    # The retargeted identity is the decision's own identity, and the decoder
    # retains the same applied record under the same case id.
    assert switched["candidate_id"] != base["candidate_id"]
    retained = on.online_decoder._switch_records[switched["case_id"]]
    assert retained.operator_id == record["operator_id"]
    assert (switched["path_id"], switched["source_id"]) == (
        retained.path_id, retained.source_id)
    # Retargeting is not an extra submission: the switched case replaced the
    # unswitched one in the same slot, with the same case identity.
    assert len(on.receipts) == len(off.receipts) == 1
    assert switched["case_id"] == base["case_id"]
    assert (on.receipts[0].online_case["case_id"]
            == off.receipts[0].online_case["case_id"])
    assert on.online_decoder._sequence == off.online_decoder._sequence == 1


def test_noop_switch_keeps_the_candidate_identity_and_the_selection_reason():
    decoder = two_path_decoder()
    pin_row = _rows_by_source(decoder)[PIN_SOURCE]
    # The draw names the very row the raw decodes to, so the switch is granted
    # and changes nothing.
    raw = _raw_for_row(decoder, _row_index(decoder, pin_row),
                       decode_source=PIN_SOURCE)
    on, off = _executor(path_switch=True), _executor(path_switch=False)
    _run(on, (raw,))
    _run(off, (raw,))
    decision, base = on.online_decisions[0], off.online_decisions[0]
    assert base["path_id"] == pin_row["path_id"]

    record = _switch(decision)
    assert record["changed"] is False
    assert record["from_path_id"] == record["path_id"] == pin_row["path_id"]
    assert record["from_source_id"] == record["source_id"] == PIN_SOURCE
    # A switch that changed nothing keeps the unswitched identity and reason.
    assert decision["candidate_id"] == base["candidate_id"]
    assert decision["path_id"] == base["path_id"]
    assert decision["source_id"] == base["source_id"]
    assert decision["source_selection_reason"] == base["source_selection_reason"]
    assert len(on.receipts) == 1


def test_applied_switch_is_the_row_named_by_the_raw_derived_draw():
    decoder = two_path_decoder()
    rows = {row["path_id"]: row for row in decoder.path_switch_targets()}
    raws = tuple(ALT_RAW if index % 2 else _raw_for_row(decoder, index % 2)
                 for index in range(4))
    first, second = _executor(path_switch=True), _executor(path_switch=True)
    _run(first, raws)
    _run(second, raws)

    for raw, left, right in zip(raws, first.online_decisions,
                                second.online_decisions):
        digest = hashlib.sha256(SWITCH_DOMAIN + raw).digest()
        expected = list(rows)[int.from_bytes(digest[:8], "little") % len(rows)]
        record = _switch(left)
        assert record["path_id"] == expected
        assert record["path_id"] in rows
        assert record["from_path_id"] in rows
        # Same raw, same declared pool, same applied operator and candidate.
        assert record == _switch(right)
        assert left["candidate_id"] == right["candidate_id"]
        assert left["path_id"] == right["path_id"] == record["path_id"]


def test_switch_never_consumes_an_extra_case_across_a_batch():
    raws = (CASE_RAW, ALT_RAW, bytes((0, 0, 1, 9, 1, 0, 0, 0)),
            bytes((0, 0, 1, 3, 4, 0, 0, 0)))
    on, off = _executor(path_switch=True), _executor(path_switch=False)
    _run(on, raws)
    _run(off, raws)
    assert [row["case_id"] for row in on.online_decisions] == [
        row["case_id"] for row in off.online_decisions]
    assert [receipt.raw_sha256 for receipt in on.receipts] == [
        receipt.raw_sha256 for receipt in off.receipts]
    assert [receipt.online_case["case_id"] for receipt in on.receipts] == [
        receipt.online_case["case_id"] for receipt in off.receipts]
    assert len(on.receipts) == len(off.receipts) == len(raws)
    assert on.online_decoder._sequence == off.online_decoder._sequence == len(raws)


# ------------------------------------------------------------------ refusals


def test_declared_but_unavailable_target_is_refused_by_the_shipped_code():
    decoder = two_path_decoder(instruction_end=0x1000)
    rows = _rows_by_source(decoder)
    cpu_row, pin_row = rows[CPU_SOURCE], rows[PIN_SOURCE]
    assert cpu_row["switchable"] is False
    assert cpu_row["eligible_source_ids"] == ()
    assert pin_row["switchable"] is True
    raw = _raw_for_row(decoder, _row_index(decoder, cpu_row))

    on, off = _executor(decoder=decoder, path_switch=True), \
        _executor(decoder=two_path_decoder(instruction_end=0x1000),
                  path_switch=False)
    _run(on, (raw,))
    _run(off, (raw,))
    decision, base = on.online_decisions[0], off.online_decisions[0]
    assert base["path_id"] == pin_row["path_id"]

    assert _switch(decision) is None
    refusal = decision["path_switch_refusal"]
    assert refusal["schema_version"] == PATH_SWITCH_REFUSAL_VERSION
    assert refusal["reason"] == "switch_rejected"
    assert refusal["request"]["path_id"] == cpu_row["path_id"]
    assert refusal["request"]["source_id"] == CPU_SOURCE
    assert refusal["rejection"]["code"] == "budget.exhausted"
    assert refusal["rejection"]["pointer"] == "switch.source_id"
    declared = [row["path_id"] for row in decoder.path_switch_targets()]
    assert refusal["declared_paths"] == declared
    assert refusal["switchable_paths"] == [pin_row["path_id"]]
    assert refusal["target"] == {"path_id": cpu_row["path_id"], "switchable": False,
                                 "eligible_source_ids": []}
    # A refused switch consumes nothing: the unswitched case was submitted with
    # the shipped identity and the shipped selection reason.
    assert decision["candidate_id"] == base["candidate_id"]
    assert decision["path_id"] == base["path_id"]
    assert decision["source_id"] == base["source_id"]
    assert decision["source_selection_reason"] != "declared_path_switch"
    assert len(on.receipts) == 1


# ------------------------------------------------------------ run-level state


def test_switch_state_document_counts_attempts_changes_and_refusals():
    off = _executor(path_switch=False)
    assert off.path_switch_state() == {
        "schema_version": PATH_SWITCH_STATE_VERSION, "enabled": False,
        "source": "constructor", "status": "disabled", "attempts": 0,
        "granted": 0, "changed": 0, "refusals": {}, "rejection_codes": {},
        "operator_ids": {}}

    on = _executor(path_switch=True)
    _run(on, (CASE_RAW, ALT_RAW, bytes((0, 0, 1, 9, 1, 0, 0, 0))))
    state = on.path_switch_state()
    granted = [decision["path_switch"] for decision in on.online_decisions
               if decision.get("path_switch") is not None]
    assert state["schema_version"] == PATH_SWITCH_STATE_VERSION
    assert state["enabled"] is True and state["source"] == "constructor"
    assert state["status"] == "active"
    assert state["attempts"] == 3
    assert state["granted"] + sum(state["refusals"].values()) == state["attempts"]
    assert state["granted"] == len(granted)
    assert state["changed"] == sum(1 for record in granted if record["changed"])
    assert state["operator_ids"] == dict(Counter(
        record["operator_id"] for record in granted))
    assert json.loads(json.dumps(state, sort_keys=True)) == state

    spent_decoder = two_path_decoder(instruction_end=0x1000)
    spent = _executor(decoder=spent_decoder, path_switch=True)
    _run(spent, (_raw_for_row(spent_decoder, _row_index(
        spent_decoder, _rows_by_source(spent_decoder)[CPU_SOURCE])),))
    assert spent.path_switch_state()["refusals"] == {"switch_rejected": 1}
    assert spent.path_switch_state()["rejection_codes"] == {"budget.exhausted": 1}
    assert spent.path_switch_state()["granted"] == 0
    assert spent.path_switch_state()["attempts"] == 1


def test_real_ibex_profile_refuses_its_spent_cpu_target():
    """The real dual-source declaration, with its own reservation spent.

    The decoder is the shipped Ibex + dual GPIO oracle; the reservation is
    advanced to its declared end through the decoder's own decode/commit API, so
    the CPU path turns from switchable to declared-but-unavailable exactly as it
    does in a long real run.  The operator then asks for that declared target and
    the decoder's own shipped code is what refuses it; the full executor loop
    around a refusal is covered by the synthetic two-path pool above, this one
    binds the real declaration and its real code.
    """
    from myfuzz.scenario.ibex_pulp_dual_source import (
        make_ibex_pulp_dual_source_online_decoder,
        make_ibex_pulp_dual_source_stream_bootstrap)
    from myfuzz.scenario.session_runtime import OnlineInstruction

    cpu_id, pin_id = "cpu.online_instruction", "gpio_b.external_pin8"
    decoder = make_ibex_pulp_dual_source_online_decoder(
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap(),
        result_slot_readback=True)
    live = _rows_by_source(decoder)
    assert live[cpu_id]["switchable"] is True and live[pin_id]["switchable"] is True
    assert (live[cpu_id]["flow_id"], live[pin_id]["flow_id"]) == ("F4", "F5")
    committed = 0
    while decoder.instruction_cursor + 4 <= decoder.instruction_end:
        case, disposition = decoder.decode_candidate(
            CASE_RAW, coverage_hints={cpu_id: 65536})
        assert case is not None
        decoder.commit(case)
        committed += 1
    assert decoder.instruction_cursor == decoder.instruction_end

    spent = _rows_by_source(decoder)
    assert spent[cpu_id]["switchable"] is False
    assert spent[cpu_id]["eligible_source_ids"] == ()
    assert spent[pin_id]["switchable"] is True
    raw = _raw_for_row(decoder, _row_index(decoder, spent[cpu_id]))
    case, _ = decoder.decode_candidate(raw, coverage_hints={pin_id: 65536})
    assert not isinstance(case.source, OnlineInstruction)

    executor = object.__new__(ScenarioRfuzzExecutor)
    executor.online_decoder = decoder
    executor.path_switch, executor.path_switch_source = True, "constructor"
    executor._path_switch_records = Counter()
    executor._path_switch_attempts = executor._path_switch_granted = 0
    executor._path_switch_changed = 0
    executor._path_switch_refusals = Counter()
    executor._path_switch_codes = Counter()
    switched, record, refusal = executor._apply_path_switch(raw, case)

    # A refused switch consumes nothing: the very case the decoder proposed is
    # still the one the caller may submit.
    assert switched is case and record is None
    assert refusal["reason"] == "switch_rejected"
    assert refusal["request"]["path_id"] == spent[cpu_id]["path_id"]
    assert refusal["request"]["source_id"] == cpu_id
    assert refusal["rejection"]["code"] == "budget.exhausted"
    assert refusal["rejection"]["pointer"] == "switch.source_id"
    assert refusal["declared_paths"] == [spent[cpu_id]["path_id"],
                                         spent[pin_id]["path_id"]]
    assert refusal["switchable_paths"] == [spent[pin_id]["path_id"]]
    assert refusal["target"] == {"path_id": spent[cpu_id]["path_id"],
                                 "switchable": False, "eligible_source_ids": []}
    state = executor.path_switch_state()
    assert state["attempts"] == 1 and state["granted"] == 0
    assert state["refusals"] == {"switch_rejected": 1}
    assert state["rejection_codes"] == {"budget.exhausted": 1}
    assert committed > 0
