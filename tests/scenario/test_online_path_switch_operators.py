"""Declared, opt-in path/source switch operators for the online candidate pool.

Software only: no RTL is compiled, rendered into a process or started.  The
synthetic decoder below declares four runtime paths to one target, all in flow
F5: two single-source paths, one path carrying two external sources, and one
path carrying a CPU instruction source beside an external source.  That is the
declared candidate pool the switch operator may move inside.

Covered here:
* a legal declared path switch retargets the current proposal, keeps the raw
  input identity, and writes the operator identity into the candidate decision
  and into ``candidate_id``;
* a legal source switch inside one declared path, including CPU instruction
  source <-> external source on the same path;
* a legal input-slice switch decided by the compiled ownership map;
* refusals reuse the shipped codes only: ``path.undeclared`` (unknown path or
  unknown flow), ``path.source_mismatch`` (source not declared on the resolved
  path), the five ``ownership.*`` codes, ``budget.exhausted`` (a switched
  instruction source whose reservation is already exhausted) and
  ``slot.proposal_mismatch`` (no current proposal);
* a refused switch consumes nothing: the original proposal stays current and
  stays committable;
* the switched case's declared prerequisites follow the switched source, and
  the shipped ``SourceActionGate`` refuses such a case before any RTL command
  while its declared prerequisite is unwitnessed;
* switch request/record documents round-trip, a forged operator id is refused;
* the real Ibex + dual GPIO profile switches between its two declared F4/F5
  paths and refuses a bound/fixed GPIO B input slice by ownership alone;
* the default decode distribution and every default candidate id are unchanged
  (pinned against values computed before the operator existed).
"""

from __future__ import annotations

import hashlib
import json

import pytest

from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_online_decoder)
from myfuzz.scenario.rejection_codes import RejectionError
from myfuzz.scenario.online_case_decoder import (
    CandidateDisposition, InputSlice, OnlineCaseDecoder, OnlineDependencyGraph,
    OnlineDependencySource, OnlineSource, OnlineSourceActionDeclaration,
    PathSwitchRecord, PathSwitchRequest)
from myfuzz.scenario.ownership import (InputField, InputOwner,
                                       compile_ownership)
from myfuzz.scenario.runtime_path_contract import (RuntimeEdgeContract,
                                                   RuntimeNode,
                                                   RuntimePathContract)
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario.session_runtime import OnlineInstruction
from myfuzz.scenario.source_actions import (
    CrossCaseEffectTracker, SourceActionGate, SourceActionPrerequisiteError,
    instruction_slot_unmaterialized_prerequisite)


TARGET = "target"
LEFT, RIGHT, CPU = "s.left", "s.right", "cpu.it"
DIRECTION = "IP_TO_IP"
FLOW = "F5"
CASE_RAW = bytes((0, 0, 255, 7, 0, 0, 0, 0))


# --------------------------------------------------------------------------
# The declared candidate pool: four paths to one target, all flow F5
# --------------------------------------------------------------------------

OWNERSHIP = compile_ownership(
    (InputField("a", "pin", 1), InputField("a", "pin2", 1),
     InputField("b", "pin", 3)),
    (InputOwner("a", "pin", 0, 1, "source", "external_left"),
     InputOwner("a", "pin2", 0, 1, "source", "external_right"),
     InputOwner("b", "pin", 0, 1, "bound", "a.out"),
     InputOwner("b", "pin", 1, 1, "fixed", "constant_zero"),
     InputOwner("b", "pin", 2, 1, "source", "external_third")))

RULES = (DependencyRule(TARGET, (LEFT,), "EVENT_ORDER"),
         DependencyRule(TARGET, (RIGHT,), "EVENT_ORDER"),
         DependencyRule(TARGET, (LEFT, RIGHT), "DATA_BINDING"),
         DependencyRule(TARGET, (CPU, LEFT), "DATA_BINDING"))


def _digest(graph) -> str:
    return hashlib.sha256(json.dumps(
        graph.edge_document(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode("utf-8")).hexdigest()


def _graph() -> OnlineDependencyGraph:
    return OnlineDependencyGraph(
        sources=(OnlineDependencySource(LEFT, "source", "a", (DIRECTION,),
                                        port="pin"),
                 OnlineDependencySource(RIGHT, "source", "a", (DIRECTION,),
                                        port="pin2"),
                 OnlineDependencySource(CPU, "instruction", "cpu",
                                        (DIRECTION,))),
        rules=RULES)


def _contract(graph) -> RuntimePathContract:
    nodes = (RuntimeNode(LEFT, "a", "physical", "pin", 0, 1),
             RuntimeNode(RIGHT, "a", "physical", "pin2", 0, 1),
             RuntimeNode(CPU, "cpu", "logical"),
             RuntimeNode(TARGET, "b", "logical"))
    return RuntimePathContract(_digest(graph), nodes,
                               (RuntimeEdgeContract(2, 0, "direct_binding"),))


def switch_decoder(*, declarations=(), instruction_end=0x2000, flow=True):
    """One decoder whose declared pool holds every switchable combination."""
    graph = _graph()
    return OnlineCaseDecoder(
        sources=(OnlineSource(LEFT, "source", "a", DIRECTION, TARGET,
                              port="pin"),
                 OnlineSource(RIGHT, "source", "a", DIRECTION, TARGET,
                              port="pin2"),
                 OnlineSource(CPU, "instruction", "cpu", DIRECTION, TARGET)),
        ownership=OWNERSHIP, graph=graph, runtime_contract=_contract(graph),
        schedule=("a", "b", "cpu"), instruction_start=0x1000,
        instruction_end=instruction_end, advance_rounds=2, max_input_bytes=8,
        windows=(MmioWindow(0x40000000, 0x1000),), support_words=2,
        flow_by_target=({TARGET: FLOW} if flow else None),
        source_actions=tuple(declarations))


def source_id_of(case):
    return case.source.action_id.rsplit(":", 1)[-1]


def path_ids(decoder):
    return {row["target"]: row["path_id"]
            for row in decoder.document()["path_mapping"]}


def pool_of(decoder, path_id):
    return tuple(source.source_id for path, sources in decoder._path_candidates
                 if path == path_id for source in sources)


def raw_for_path(decoder, wanted):
    """Return a raw input whose unswitched decode selects ``wanted``."""
    for byte in range(256):
        raw = bytes((0, 0, 255, byte, byte, 0, 0, 0))
        case = decoder.decode(raw)
        selected = case.path_id
        decoder.commit(case)
        if selected == wanted:
            return raw
    raise AssertionError("no raw input selects the declared path")


def one_path_per_source(decoder):
    """Map source id -> the single declared path that carries exactly it."""
    found = {}
    for path, sources in decoder._path_candidates:
        if len(sources) == 1:
            found[sources[0].source_id] = path
    return found


# --------------------------------------------------------------------------
# Legal switches
# --------------------------------------------------------------------------

def test_declared_path_switch_retargets_the_proposal_and_writes_its_identity():
    decoder = switch_decoder()
    singles = one_path_per_source(decoder)
    assert set(singles) == {LEFT, RIGHT}
    before = decoder.decode(CASE_RAW)
    assert before.path_id == singles[LEFT]

    request = PathSwitchRequest(path_id=singles[RIGHT])
    case, disposition = decoder.switch_proposal(request)

    assert case is not None
    assert disposition.disposition == "admitted"
    assert disposition.reason == "declared_switch_applied"
    assert disposition.selection == "declared_path_switch"
    record = disposition.switch
    assert isinstance(record, PathSwitchRecord)
    assert record.families == ("path_switch",)
    assert record.from_path_id == singles[LEFT]
    assert record.path_id == singles[RIGHT]
    assert record.from_source_id == LEFT
    assert record.source_id == RIGHT
    assert record.flow_id == FLOW
    assert record.changed is True
    assert record.ownership_producer == "external_right"
    assert record.request == request
    # The retargeted proposal carries the switched path and source input, keeps
    # the raw input case identity, and stays committable.
    assert case.path_id == singles[RIGHT]
    assert case.source.action_id == f"{case.case_id}:{RIGHT}"
    assert case.source.component == "a" and case.source.port == "pin2"
    assert case.case_id == before.case_id
    metadata = decoder.decision_metadata(case)
    assert metadata["path_id"] == singles[RIGHT]
    assert metadata["source_id"] == RIGHT
    assert metadata["flow_id"] == FLOW
    assert metadata["switch_operator_id"] == record.operator_id
    # Passing the request back must reproduce exactly the same candidate id; a
    # request the proposal did not apply is refused instead of mislabelled.
    assert decoder.decision_metadata(case, switch=request) == metadata
    with pytest.raises(RejectionError) as forged:
        decoder.decision_metadata(case, switch=PathSwitchRequest(source_id=LEFT))
    assert forged.value.rejection.code == "slot.proposal_mismatch"
    assert forged.value.rejection.pointer == "switch.request"
    assert metadata["candidate_id"] != decoder.decision_metadata(before)["candidate_id"]
    decoder.commit(case)


def test_legal_source_switch_inside_one_declared_path_keeps_the_flow():
    decoder = switch_decoder()
    two_sources = next(path for path, sources in decoder._path_candidates
                       if {source.source_id for source in sources}
                       == {LEFT, RIGHT})
    base = decoder.decode(raw_for_path(decoder, two_sources))
    assert base.path_id == two_sources
    started = source_id_of(base)
    other = RIGHT if started == LEFT else LEFT

    request = PathSwitchRequest(source_id=other)
    case, disposition = decoder.switch_proposal(request)

    assert case is not None
    record = disposition.switch
    assert record.families == ("source_switch",)
    assert record.from_path_id == record.path_id == two_sources
    assert record.from_source_id == started and record.source_id == other
    assert record.changed is True
    assert record.flow_id == FLOW
    assert case.path_id == two_sources and case.source.action_id.endswith(other)
    assert decoder.decision_metadata(case)["flow_id"] == FLOW
    decoder.commit(case)


def test_noop_switch_keeps_the_candidate_identity():
    decoder = switch_decoder()
    raws = (CASE_RAW, bytes((0, 0, 0, 7, 0, 0, 0, 0)),
            bytes((0, 0, 1, 9, 1, 0, 0, 0)))
    for raw in raws:
        base, base_disposition = decoder.decode_candidate(raw)
        before = decoder.decision_metadata(base)
        started = source_id_of(base)

        case, disposition = decoder.switch_proposal(
            PathSwitchRequest(source_id=started))

        assert case is not None and case == base
        record = disposition.switch
        assert record.changed is False
        assert record.from_path_id == record.path_id == base.path_id
        assert record.from_source_id == record.source_id == started
        # A switch that changed nothing keeps the unswitched selection reason and
        # the unswitched candidate identity.
        assert disposition.selection == base_disposition.selection
        assert disposition.reason == "declared_switch_applied"
        after = decoder.decision_metadata(case)
        assert after == before
        assert "switch_operator_id" not in after
        decoder.commit(case)


def test_source_switch_between_cpu_instruction_and_external_source_on_one_path():
    decoder = switch_decoder()
    mixed = next(path for path, sources in decoder._path_candidates
                 if {source.source_id for source in sources} == {CPU, LEFT})
    decoder.decode(raw_for_path(decoder, mixed))

    program, program_disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=CPU))
    assert program is not None
    assert isinstance(program.source, OnlineInstruction)
    assert program.source.address == decoder.instruction_cursor
    assert len(bytes.fromhex(program.source.data_hex)) % 4 == 0
    assert program_disposition.switch.families == ("path_switch", "source_switch")
    assert program_disposition.switch.source_id == CPU
    assert program_disposition.switch.flow_id == FLOW
    action = decoder.source_action(program)
    assert (action.kind, action.source_id, action.flow_id) == (
        "instruction", CPU, FLOW)

    # The retargeted proposal is still the current one, so a second declared
    # switch resolves from the switched identity.
    external, external_disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=LEFT))
    assert external_disposition.switch.from_source_id == CPU
    assert external_disposition.switch.changed is True
    assert external is not None
    assert not isinstance(external.source, OnlineInstruction)
    assert (external.source.component, external.source.port) == ("a", "pin")
    assert external_disposition.switch.flow_id == FLOW
    action = decoder.source_action(external)
    assert (action.kind, action.source_id, action.flow_id) == (
        "external_event", LEFT, FLOW)
    assert action.payload["value"] == external.source.value
    decoder.commit(external)


def test_legal_input_slice_switch_is_decided_by_the_ownership_map():
    decoder = switch_decoder()
    single = one_path_per_source(decoder)[RIGHT]
    decoder.decode(CASE_RAW)

    case, disposition = decoder.switch_proposal(PathSwitchRequest(
        path_id=single, input_slice=InputSlice("a", "pin2", 0, 1)))

    assert case is not None
    assert case.source.action_id.endswith(RIGHT)
    assert disposition.switch.source_id == RIGHT
    assert disposition.switch.ownership_producer == "external_right"


def test_switch_targets_list_the_declared_candidate_pool():
    decoder = switch_decoder()
    rows = decoder.path_switch_targets()
    assert len(rows) == len(decoder._path_candidates) == 4
    assert {row["path_id"] for row in rows} == {
        path for path, _ in decoder._path_candidates}
    assert all(row["flow_id"] == FLOW for row in rows)
    assert all(row["switchable"] for row in rows)
    assert [row["source_ids"] for row in rows] == [
        pool_of(decoder, row["path_id"]) for row in rows]
    filtered = decoder.path_switch_targets(flow_id=FLOW)
    assert [row["path_id"] for row in filtered] == [row["path_id"] for row in rows]
    assert decoder.path_switch_targets(flow_id="F4") == ()


# --------------------------------------------------------------------------
# Refusals: shipped codes only, and nothing is consumed
# --------------------------------------------------------------------------

def _refuse(decoder, request):
    case, disposition = decoder.switch_proposal(request)
    assert case is None
    assert disposition.disposition == "rejected"
    assert disposition.reason == "switch_rejected"
    assert disposition.switch is None
    return disposition.rejection


def test_undeclared_switch_path_and_flow_reuse_the_path_code():
    decoder = switch_decoder()
    original = decoder.decode(CASE_RAW)
    rejection = _refuse(decoder, PathSwitchRequest(path_id="not.declared"))
    assert rejection.code == "path.undeclared"
    assert rejection.pointer == "switch.path_id"
    rejection = _refuse(decoder, PathSwitchRequest(flow_id="F6"))
    assert rejection.code == "path.undeclared"
    assert rejection.pointer == "switch.flow_id"
    # A refused switch consumed nothing: the original proposal is still current
    # and still committable.
    assert decoder._proposal is not None
    assert decoder.decision_metadata(original)["path_id"] == original.path_id
    decoder.commit(original)


def test_switch_source_not_declared_on_the_resolved_path_is_refused():
    decoder = switch_decoder()
    single = one_path_per_source(decoder)[LEFT]
    decoder.decode(CASE_RAW)
    rejection = _refuse(decoder, PathSwitchRequest(path_id=single,
                                                   source_id=RIGHT))
    assert rejection.code == "path.source_mismatch"
    assert rejection.pointer == "switch.source_id"
    assert rejection.detail["path_id"] == single
    # A slice that no declared source of the resolved path matches is the same
    # declared-pool refusal.
    rejection = _refuse(decoder, PathSwitchRequest(
        path_id=single, input_slice=InputSlice("b", "pin", 2, 1)))
    assert rejection.code == "path.source_mismatch"
    assert rejection.pointer == "switch.input_slice"


def test_ownership_refuses_an_unowned_input_slice():
    decoder = switch_decoder()
    single = one_path_per_source(decoder)[LEFT]
    decoder.decode(CASE_RAW)
    cases = ((InputSlice("b", "pin", 0, 1), "ownership.bound_input"),
             (InputSlice("b", "pin", 1, 1), "ownership.fixed_input"),
             (InputSlice("a", "pinx", 0, 1), "ownership.undeclared_field"),
             (InputSlice("a", "pin", 0, 4), "ownership.range_exceeds_field"))
    for slice_, expected in cases:
        rejection = _refuse(decoder, PathSwitchRequest(path_id=single,
                                                       input_slice=slice_))
        assert rejection.code == expected
        assert rejection.pointer == "switch.input_slice"


def test_switch_to_an_exhausted_instruction_reservation_is_refused():
    decoder = switch_decoder(instruction_end=0x1004)
    mixed = next(path for path, sources in decoder._path_candidates
                 if CPU in {source.source_id for source in sources})
    decoder.decode(CASE_RAW)
    program, disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=CPU))
    assert program is not None and disposition.disposition == "admitted"
    decoder.commit(program)
    assert decoder.instruction_cursor + 4 > decoder.instruction_end

    decoder.decode(CASE_RAW)
    rejection = _refuse(decoder, PathSwitchRequest(path_id=mixed, source_id=CPU))
    assert rejection.code == "budget.exhausted"
    assert rejection.pointer == "switch.source_id"
    assert rejection.detail["instruction_cursor"] == decoder.instruction_cursor
    assert rejection.detail["instruction_end"] == decoder.instruction_end


def test_a_switched_instruction_fragment_that_does_not_fit_degrades_to_a_nop():
    """The switched case is materialized by the same rule as an unswitched one,
    including the declared reservation fallback, instead of a second policy."""
    decoder = switch_decoder(instruction_end=0x1008)
    mixed = next(path for path, sources in decoder._path_candidates
                 if CPU in {source.source_id for source in sources})
    # Entropy byte three selects the declared SW template: a sixteen-byte
    # fragment that cannot fit the eight remaining reserved bytes.
    raw = bytes((0, 0, 0, 4, 1, 2, 0x0C, 0x10))
    decoder.decode(raw)
    assert decoder.instruction_cursor == 0x1000

    case, disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=CPU))

    assert case is not None
    assert isinstance(case.source, OnlineInstruction)
    assert case.source.data_hex == "13000000"
    assert case.source.address == 0x1000
    assert disposition.disposition == "degraded"
    assert disposition.reason == "instruction_reservation_fallback"
    assert disposition.selection == "declared_path_switch"
    assert disposition.rejection.code == "slot.out_of_reservation"
    assert disposition.rejection.detail["requested_bytes"] == 16
    assert disposition.switch.source_id == CPU
    decoder.commit(case)


def test_switch_without_a_current_proposal_is_refused():
    decoder = switch_decoder()
    with pytest.raises(RejectionError) as raised:
        decoder.switch_proposal(PathSwitchRequest(source_id=RIGHT))
    # A caller contract error is fail-closed, not a candidate disposition: no
    # candidate exists at all.
    assert raised.value.rejection.code == "slot.proposal_mismatch"
    assert raised.value.rejection.pointer == "instruction.proposal"
    case = decoder.decode(CASE_RAW)
    decoder.commit(case)
    with pytest.raises(RejectionError):
        decoder.switch_proposal(PathSwitchRequest(source_id=RIGHT))


def test_switch_request_and_record_documents_round_trip_and_refuse_forgeries():
    request = PathSwitchRequest(path_id="p" * 4, source_id=RIGHT,
                                input_slice=InputSlice("a", "pin2", 0, 1))
    assert PathSwitchRequest.from_document(request.document()) == request
    assert request.document()["schema_version"] == "online_path_switch_request.v1"

    decoder = switch_decoder()
    decoder.decode(CASE_RAW)
    _, disposition = decoder.switch_proposal(PathSwitchRequest(source_id=LEFT))
    record = disposition.switch
    document = record.document()
    assert document["schema_version"] == "online_path_switch.v1"
    assert PathSwitchRecord.from_document(document) == record
    assert record.operator_id.startswith("online-path-switch.v1:")
    forged = {**document, "operator_id": "online-path-switch.v1:" + "0" * 64}
    with pytest.raises(ValueError):
        PathSwitchRecord.from_document(forged)
    with pytest.raises(ValueError):
        PathSwitchRecord.from_document({**document, "schema_version": "other.v1"})
    with pytest.raises(ValueError):
        PathSwitchRequest()
    with pytest.raises(ValueError):
        PathSwitchRequest(flow_id="F9")
    with pytest.raises(ValueError):
        PathSwitchRequest(path_id=1)
    with pytest.raises(ValueError):
        PathSwitchRequest.from_document({"schema_version": "x"})


def test_switched_prerequisites_follow_the_switched_source_and_the_gate_refuses():
    slot = 0x1000
    prerequisite = instruction_slot_unmaterialized_prerequisite(
        "cpu", slot, "reservation:" + "a" * 64)
    declaration = OnlineSourceActionDeclaration(CPU, (prerequisite,))
    decoder = switch_decoder(declarations=(declaration,))
    mixed = next(path for path, sources in decoder._path_candidates
                 if {source.source_id for source in sources} == {CPU, LEFT})
    decoder.decode(raw_for_path(decoder, mixed))

    external, external_disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=LEFT))
    assert external is not None
    assert decoder.source_action(external).prerequisites == ()

    program, program_disposition = decoder.switch_proposal(
        PathSwitchRequest(path_id=mixed, source_id=CPU))
    assert program is not None
    assert program_disposition.switch.source_id == CPU
    action = decoder.source_action(program)
    assert action.prerequisites == (prerequisite,)
    gate = SourceActionGate(CrossCaseEffectTracker())
    gate.register(action)
    with pytest.raises(SourceActionPrerequisiteError):
        gate.require_case(program)


def test_switched_proposal_replays_from_the_saved_manifest():
    trusted = switch_decoder()
    restored = OnlineCaseDecoder.from_document(trusted.document())
    by_sources = {tuple(sorted(source.source_id for source in sources)): path
                  for path, sources in trusted._path_candidates}
    raws = [CASE_RAW, bytes((0, 0, 255, 9, 1, 0, 0, 0))]
    requests = [PathSwitchRequest(path_id=by_sources[(LEFT, RIGHT)],
                                  source_id=RIGHT),
                PathSwitchRequest(path_id=by_sources[(CPU, LEFT)],
                                  source_id=CPU)]
    for raw, request in zip(raws, requests):
        left = trusted.decode(raw)
        right = restored.decode(raw)
        assert left == right
        left_case, left_disposition = trusted.switch_proposal(request)
        right_case, right_disposition = restored.switch_proposal(request)
        assert left_case == right_case
        assert left_disposition.switch.document() == right_disposition.switch.document()
        assert (trusted.decision_metadata(left_case)
                == restored.decision_metadata(right_case))
        trusted.commit(left_case)
        restored.commit(right_case)


def unswitched_candidate_id(metadata):
    """Recompute the legacy candidate id from the declared identity keys."""
    identity = {key: metadata[key] for key in (
        "direction", "flow_id", "path_id", "target_id", "source_id",
        "operator_id")}
    digest = hashlib.sha256(json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode()).hexdigest()
    return "online-candidate.v1:" + digest


def test_retained_switch_identities_are_bounded(monkeypatch):
    """The documented bound: only retained switch records keep the operator in
    the candidate id, and the oldest identity is evicted first."""
    monkeypatch.setattr(
        "myfuzz.scenario.online_case_decoder.MAX_RETAINED_SWITCHES", 1)
    decoder = switch_decoder()
    single = one_path_per_source(decoder)[RIGHT]
    switched = []
    for raw in (CASE_RAW, bytes((0, 0, 255, 9, 1, 0, 0, 0))):
        decoder.decode(raw)
        case, disposition = decoder.switch_proposal(
            PathSwitchRequest(path_id=single))
        assert case is not None and disposition.switch.changed is True
        decoder.commit(case)
        switched.append((case, disposition.switch))
    assert len(decoder._switch_records) == 1
    assert next(iter(decoder._switch_records)) == switched[-1][0].case_id

    retained = decoder.decision_metadata(switched[-1][0])
    assert retained["switch_operator_id"] == switched[-1][1].operator_id
    assert retained["candidate_id"] != unswitched_candidate_id(retained)

    evicted = decoder.decision_metadata(switched[0][0])
    assert "switch_operator_id" not in evicted
    assert evicted["candidate_id"] == unswitched_candidate_id(evicted)


# --------------------------------------------------------------------------
# The real Ibex + dual GPIO profile
# --------------------------------------------------------------------------

def test_real_profile_switches_between_its_two_declared_paths():
    decoder = make_ibex_pulp_dual_source_online_decoder()
    rows = decoder.path_switch_targets()
    assert [row["flow_id"] for row in rows] == ["F4", "F5"]
    cpu_path, pin_path = rows[0]["path_id"], rows[1]["path_id"]
    case = decoder.decode(CASE_RAW)
    assert case.path_id == cpu_path
    assert isinstance(case.source, OnlineInstruction)

    switched, disposition = decoder.switch_proposal(
        PathSwitchRequest(flow_id="F5"))
    assert switched is not None
    assert switched.path_id == pin_path
    assert switched.source.action_id.endswith("gpio_b.external_pin8")
    assert disposition.switch.families == ("path_switch",)
    assert disposition.switch.flow_id == "F5"
    assert disposition.switch.ownership_producer == "external_b.pin8"
    assert decoder.decision_metadata(switched)["flow_id"] == "F5"

    back, back_disposition = decoder.switch_proposal(
        PathSwitchRequest(flow_id="F4"))
    assert back is not None and isinstance(back.source, OnlineInstruction)
    assert back.path_id == cpu_path
    assert back_disposition.switch.from_path_id == pin_path
    decoder.commit(back)


def test_real_profile_gpio_slice_switch_is_decided_by_ownership():
    decoder = make_ibex_pulp_dual_source_online_decoder()
    decoder.decode(CASE_RAW)
    bound = _refuse(decoder, PathSwitchRequest(
        flow_id="F5", input_slice=InputSlice("gpio_b", "gpio_in", 0, 8)))
    assert bound.code == "ownership.bound_input"
    fixed = _refuse(decoder, PathSwitchRequest(
        flow_id="F5", input_slice=InputSlice("gpio_b", "gpio_in", 9, 23)))
    assert fixed.code == "ownership.fixed_input"
    undeclared = _refuse(decoder, PathSwitchRequest(
        flow_id="F5", input_slice=InputSlice("gpio_b", "gpio_in", 0, 33)))
    assert undeclared.code == "ownership.range_exceeds_field"

    case, disposition = decoder.switch_proposal(PathSwitchRequest(
        flow_id="F5", input_slice=InputSlice("gpio_b", "gpio_in", 8, 1)))
    assert case is not None
    assert case.source.action_id.endswith("gpio_b.external_pin8")
    assert disposition.switch.ownership_producer == "external_b.pin8"


# --------------------------------------------------------------------------
# Default decode distribution and identity are unchanged
# --------------------------------------------------------------------------

GOLDEN = (
    (bytes((0, 0, 255, 7, 0, 0, 0, 0)),
     "542b422a912c69091d5c51733e950013f097c412fc3a6fe693f7fdc11a662ed8",
     "cpu.online_instruction", "F4", "CPU_TO_IP_TO_CPU",
     "online-candidate.v1:d54b2285cbe61b0dae90eb8843a4632d244d49eb4bbc7d1ffafb18658243347c"),
    (bytes((0, 1, 255, 7, 0, 0, 0, 0)),
     "542b422a912c69091d5c51733e950013f097c412fc3a6fe693f7fdc11a662ed8",
     "cpu.online_instruction", "F4", "CPU_TO_IP_TO_CPU",
     "online-candidate.v1:d54b2285cbe61b0dae90eb8843a4632d244d49eb4bbc7d1ffafb18658243347c"),
    (bytes((0, 0, 0, 7, 0, 0, 0, 0)),
     "7943a650707727109140f795e5119ca82eb9a6ec3895845341998eba525975b8",
     "gpio_b.external_pin8", "F5", "IP_TO_CPU_TO_IP",
     "online-candidate.v1:b53ab9dd3e70817105ed65ba77ad11221d96e7382468799bee1092a42f75fe43"),
    (bytes((0, 0, 1, 9, 1, 0, 0, 0)),
     "7943a650707727109140f795e5119ca82eb9a6ec3895845341998eba525975b8",
     "gpio_b.external_pin8", "F5", "IP_TO_CPU_TO_IP",
     "online-candidate.v1:b53ab9dd3e70817105ed65ba77ad11221d96e7382468799bee1092a42f75fe43"),
)


def test_default_decode_identity_is_unchanged_by_the_switch_operator():
    """Golden values were computed from the decoder before this operator.

    The operator is opt-in: without ``switch_proposal`` the default path choice,
    the source choice, the selection reason and every candidate id must stay
    exactly as they were.
    """
    decoder = make_ibex_pulp_dual_source_online_decoder()
    for raw, path_id, source_id, flow_id, direction, candidate_id in GOLDEN:
        case, disposition = decoder.decode_candidate(raw)
        metadata = decoder.decision_metadata(case)
        assert (case.path_id, case.source.action_id.split(":")[-1], metadata["flow_id"],
                case.direction, metadata["candidate_id"]) == (
            path_id, source_id, flow_id, direction, candidate_id)
        assert "switch_operator_id" not in metadata
        assert disposition.document() == {
            "schema_version": "online_candidate_decision.v1",
            "candidate_disposition": "admitted",
            "candidate_disposition_reason": "decoder_case_ready",
            "source_selection_reason": disposition.selection,
            "rejection": None,
        }
        decoder.commit(case)
        # The identity of an already committed candidate is unchanged too.
        assert decoder.decision_metadata(case)["candidate_id"] == candidate_id


def test_switch_disposition_document_shape_is_legacy_without_a_switch():
    decoder = switch_decoder()
    case, disposition = decoder.decode_candidate(CASE_RAW)
    assert disposition.switch is None
    assert set(disposition.document()) == {
        "schema_version", "candidate_disposition", "candidate_disposition_reason",
        "source_selection_reason", "rejection"}
    _, switched = decoder.switch_proposal(PathSwitchRequest(source_id=LEFT))
    assert set(switched.document()) == set(disposition.document()) | {"switch"}
    assert switched.document()["switch"]["schema_version"] == "online_path_switch.v1"
    assert CandidateDisposition("admitted", "decoder_case_ready").document() == {
        "schema_version": "online_candidate_decision.v1",
        "candidate_disposition": "admitted",
        "candidate_disposition_reason": "decoder_case_ready",
        "source_selection_reason": None,
        "rejection": None,
    }
