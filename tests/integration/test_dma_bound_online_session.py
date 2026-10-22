"""Online-session integration for the versioned DMA binding envelope.

These tests exercise preflight and software session state only. They never
start a generated transport or native process.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from unittest.mock import Mock

import pytest

from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.session_runtime import (
    OnlineCase, ScenarioSession, replay_online_session, _checker_identity,
)


class _SessionStub:
    def begin_case(self, testcase_id):
        pass

    def step_local(self, inputs):
        return {"value": inputs.get("source", 0)}

    def end_case(self):
        pass


def _factory():
    ownership = compile_ownership(
        (InputField("cpu", "source", 8),),
        (InputOwner("cpu", "source", 0, 8, "source", "program"),),
    )
    return ScenarioRunner(sessions={"cpu": _SessionStub()}, ownership=ownership,
                          bindings=())


def _template():
    return ScenarioGenome(testcase_id="bound-online", direction="CPU_TO_IP",
                          path_id="unit", schedule_order=("cpu",),
                          max_steps=4, actions=())


def _dma_template():
    return ScenarioGenome(testcase_id="bound-online", direction="CPU_TO_IP",
                          path_id="unit", schedule_order=("cpu", "dma", "uart"),
                          max_steps=4, actions=())


def _completed_legacy_plan():
    session = ScenarioSession(_template(), _factory())
    session.begin()
    session.submit_case(OnlineCase(
        "legacy", "CPU_TO_IP", "unit",
        BatchSourceEvent("legacy-source", "cpu", "source", 1),
        (BatchAdvance(("cpu",)),),
    ))
    reference = session.finish()
    return session.encode_plan(), reference


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _dma_route_setup():
    from tests.integration.test_dma_intent_binding_replay import declaration_fixture
    from tests.scenario import test_dma_intent_topology_binding as fixtures
    from tests.scenario import test_runtime_path_contract as routes

    _wiring, prepared, _route_links = fixtures.fixture()
    declaration = declaration_fixture()

    def factory():
        _graph, base_runner, _contract, _path, _dma, _memory = (
            routes.DmaMasterRouteContractTests().fixture())
        return ScenarioRunner(
            sessions=base_runner.sessions,
            ownership=_factory().ownership,
            bindings=(),
        )

    return declaration, prepared, factory


def _valid_bound_wrapper():
    # Reuse the codec fixture so this test remains independent of generated
    # artifacts and validates the actual online replay dispatch.
    from tests.integration.test_dma_intent_binding_replay import encode_fixture

    return encode_fixture("online_session_plan")


def test_bound_online_wrapper_requires_external_identity_before_factory():
    encoded, _payload, _declaration, _rows = _valid_bound_wrapper()
    factory = Mock(side_effect=AssertionError("factory reached"))
    reference = ScenarioTrace("0" * 64, "complete", (), {}, "0" * 64, "0" * 64)

    with pytest.raises(ValueError, match="expected.*identity|identity.*expected"):
        replay_online_session(encoded, factory, reference)

    factory.assert_not_called()


@pytest.mark.parametrize("schema", [22, 23])
def test_bound_native_completion_plan_keeps_its_native_replay_gate(schema):
    from myfuzz.scenario.dma_binding_replay import encode_dma_bound_payload
    from myfuzz.scenario.native_packet_session import (
        native_packet_source_binding_configuration,
        native_packet_source_completion_configuration,
    )
    from tests.integration.test_dma_intent_binding_replay import (
        credential_fixture, declaration_fixture,
    )

    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    payload = _canonical({
        "schema_version": schema,
        "native_packet_configuration": native_packet_source_binding_configuration(1),
        "native_source_completion": native_packet_source_completion_configuration(1),
        "warmup_advances": [],
        "cases": [],
    })
    encoded = encode_dma_bound_payload(
        payload,
        payload_kind="online_session_plan",
        declaration=declaration,
        binding_compilations={"session": credential},
    )
    outer_identity = json.loads(encoded)["identity_sha256"]
    reference = ScenarioTrace(
        hashlib.sha256(payload).hexdigest(), "complete", (), {},
        "unused-semantic-hash", "unused-manifest-hash",
    )
    factory = Mock(side_effect=AssertionError("native comparison policy must fail first"))

    with pytest.raises(ValueError, match="native saved configuration or owned comparison policy"):
        replay_online_session(
            encoded, factory, reference,
            expected_dma_binding_identity_sha256=outer_identity,
            native_max_cases=1,
            native_reference_execution="a" * 32,
            native_source_binding=True,
        )

    factory.assert_not_called()


def test_changed_saved_online_credential_refuses_before_factory():
    encoded, _payload, _declaration, _rows = _valid_bound_wrapper()
    outer = json.loads(encoded)
    original_identity = outer["identity_sha256"]
    credential = outer["binding_compilations"][0]["credential"]
    credential["routes"][0]["runtime_route_sha256"] = "0" * 64
    credential["identity_sha256"] = _digest({
        key: value for key, value in credential.items() if key != "identity_sha256"
    })
    outer["identity_sha256"] = _digest({
        key: value for key, value in outer.items() if key != "identity_sha256"
    })
    changed = _canonical(outer)
    factory = Mock(side_effect=AssertionError("factory reached"))
    reference = ScenarioTrace("0" * 64, "complete", (), {}, "0" * 64, "0" * 64)

    with pytest.raises(ValueError):
        replay_online_session(
            changed, factory, reference,
            expected_dma_binding_identity_sha256=original_identity,
        )

    factory.assert_not_called()


def test_saved_credential_must_join_the_embedded_runtime_compilation_before_factory():
    from myfuzz.scenario.dma_binding_replay import encode_dma_bound_payload
    from tests.integration.test_dma_intent_binding_replay import credential_fixture

    declaration, prepared, source_factory = _dma_route_setup()
    source = ScenarioSession(_dma_template(), source_factory())
    source.configure_runtime_paths(
        prepared.graph, prepared.contract, prepared.runtime_paths,
        replay_only=True, provenance=False,
    )
    inner_plan = source.encode_plan()
    credential = credential_fixture(declaration)
    compilation_document = {
        key: value for key, value in source.runtime_path_document.items()
        if key != "declaration"
    }
    credential["runtime_compilation_sha256"] = hashlib.sha256(
        _canonical(compilation_document)).hexdigest()
    credential["topology_sha256"] = compilation_document["topology_sha256"]
    credential["identity_sha256"] = _digest({
        key: value for key, value in credential.items()
        if key != "identity_sha256"
    })
    encoded = encode_dma_bound_payload(
        inner_plan, payload_kind="online_session_plan", declaration=declaration,
        binding_compilations={"session": credential},
    )
    outer = json.loads(encoded)
    outer["binding_compilations"][0]["credential"][
        "runtime_compilation_sha256"] = "0" * 64
    changed_credential = outer["binding_compilations"][0]["credential"]
    changed_credential["identity_sha256"] = _digest({
        key: value for key, value in changed_credential.items()
        if key != "identity_sha256"
    })
    outer["identity_sha256"] = _digest({
        key: value for key, value in outer.items() if key != "identity_sha256"
    })
    changed = _canonical(outer)
    factory = Mock(side_effect=AssertionError("factory reached"))
    reference = ScenarioTrace(
        hashlib.sha256(inner_plan).hexdigest(), "complete", (), {},
        "unused-semantic-hash", "unused-manifest-hash",
    )

    with pytest.raises(ValueError, match="runtime compilation"):
        replay_online_session(
            changed, factory, reference,
            expected_dma_binding_identity_sha256=outer["identity_sha256"],
        )

    factory.assert_not_called()


def test_fresh_runner_binding_credential_is_compared_before_session_begin(monkeypatch):
    from types import SimpleNamespace

    import myfuzz.scenario.dma_intent_topology_binding as dma_binding
    from myfuzz.scenario.dma_binding_replay import encode_dma_bound_payload
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.integration.test_dma_intent_binding_replay import credential_fixture

    declaration, prepared, factory = _dma_route_setup()
    source = ScenarioSession(_dma_template(), factory())
    source.configure_runtime_paths(
        prepared.graph, prepared.contract, prepared.runtime_paths,
        replay_only=True, provenance=False,
    )
    inner_plan = source.encode_plan()
    saved_credential = credential_fixture(declaration)
    compilation_document = {
        key: value for key, value in source.runtime_path_document.items()
        if key != "declaration"
    }
    saved_credential["runtime_compilation_sha256"] = hashlib.sha256(
        _canonical(compilation_document)).hexdigest()
    saved_credential["topology_sha256"] = compilation_document["topology_sha256"]
    saved_credential["identity_sha256"] = _digest({
        key: value for key, value in saved_credential.items()
        if key != "identity_sha256"
    })
    wrapper = encode_dma_bound_payload(
        inner_plan, payload_kind="online_session_plan", declaration=declaration,
        binding_compilations={"session": saved_credential},
    )
    wrapper_document = json.loads(wrapper)
    calls = []

    def bind_with_changed_credential(saved_declaration, runner, *, artifact_links):
        calls.append((saved_declaration, artifact_links))
        runtime_prepared = PreparedRuntimePathContract.from_document(
            saved_declaration.document()["prepared_runtime_paths"])
        compilation = runtime_prepared.bind(runner)
        changed_credential = deepcopy(saved_credential)
        changed_credential["identity_sha256"] = "f" * 64
        return SimpleNamespace(runtime_compilation=compilation,
                               document=lambda: changed_credential)

    monkeypatch.setattr(dma_binding, "bind_dma_intent_topology",
                        bind_with_changed_credential)
    factory_calls = []

    def tracked_factory():
        factory_calls.append(True)
        return factory()

    reference = ScenarioTrace(
        hashlib.sha256(inner_plan).hexdigest(), "complete", (), {},
        "unused-semantic-hash", "unused-manifest-hash",
    )

    with pytest.raises(ValueError, match="DMA.*binding.*credential|binding.*credential"):
        replay_online_session(
            wrapper, tracked_factory, reference,
            expected_dma_binding_identity_sha256=wrapper_document["identity_sha256"],
        )

    assert len(factory_calls) == 1
    assert len(calls) == 1


def test_unwrapped_legacy_online_plan_replays_without_binding_identity():
    plan, reference = _completed_legacy_plan()

    replay = replay_online_session(plan, _factory, reference)

    assert replay.matches
    assert replay.actual_trace.genome_sha256 == hashlib.sha256(plan).hexdigest()


def test_session_opt_in_stores_detached_dma_binding_material(monkeypatch):
    from types import SimpleNamespace

    import myfuzz.scenario.dma_intent_topology_binding as dma_binding
    from myfuzz.scenario.dma_intent_topology_binding import prepare_dma_intent_binding
    from tests.scenario import test_dma_intent_topology_binding as fixtures

    wiring, prepared, route_links = fixtures.fixture()
    declaration = prepare_dma_intent_binding(wiring, prepared, route_links=route_links)
    artifact_links = {"dma": {"schema_version": "test-link.v1"}}
    compilation = SimpleNamespace(document=lambda: {
        "schema_version": "runtime_path_compilation.v2",
        "compiled": "same legacy runtime document",
    })
    credential = {"schema_version": "dma_intent_topology_binding.v1",
                  "tier": "topology_bound", "identity_sha256": "c" * 64}
    bound = SimpleNamespace(runtime_compilation=compilation,
                             document=lambda: deepcopy(credential))
    bind = Mock(return_value=bound)
    monkeypatch.setattr(dma_binding, "bind_dma_intent_topology", bind)

    session = ScenarioSession(_template(), _factory())
    session.configure_runtime_paths(
        prepared.graph, prepared.contract, prepared.runtime_paths,
        replay_only=True, provenance=False,
        dma_intent_binding=declaration, dma_artifact_links=artifact_links,
    )

    bind.assert_called_once_with(declaration, session.runner,
                                 artifact_links=artifact_links)
    assert session.dma_binding_document() == declaration.document()
    assert session.dma_binding_artifact_links() == artifact_links
    assert session.dma_binding_compilation_document() == credential
    assert session.runtime_path_document == {
        **compilation.document(), "declaration": prepared.document(),
    }
    session.dma_binding_artifact_links()["dma"]["schema_version"] = "mutated"
    assert session.dma_binding_artifact_links() == artifact_links


def test_continuous_replay_passes_verified_outer_binding_identity(tmp_path, monkeypatch):
    import myfuzz.integration.scenario_rfuzz_live as live
    import myfuzz.integration.scenario_rfuzz_replay as replay_module
    import myfuzz.scenario.session_runtime as session_runtime

    trace = ScenarioTrace("inner-plan", "complete", (), {}, "semantic", "manifest")
    (tmp_path / "report.json").write_bytes(_canonical({
        "execution_mode": "continuous_decoder",
    }))
    (tmp_path / "online_final_trace.json").write_bytes(_canonical({
        "genome_sha256": trace.genome_sha256,
        "status": trace.status,
        "events": [],
        "local_ticks": {},
        "semantic_sha256": trace.semantic_sha256,
        "manifest_sha256": trace.manifest_sha256,
    }))
    plan_path = tmp_path / "online_plan.json"
    plan_path.write_bytes(b"outer-bound-plan")
    binding_identity = "a" * 64
    identity = {
        "execution_mode": "continuous_decoder",
        "checker": _checker_identity(None),
        "decoder_checker": "decoder-identity",
        "dma_binding_identity_sha256": binding_identity,
        "_p7_dma_binding_payload": object(),
    }
    monkeypatch.setattr(live, "_verify_online_run_identity", lambda *a, **k: identity)
    monkeypatch.setattr(live, "_fresh_checker_identity", lambda *a, **k: "decoder-identity")
    captured = {}

    def fake_replay(plan, factory, reference, **kwargs):
        captured.update(plan=plan, factory=factory, reference=reference, kwargs=kwargs)
        return Mock(matches=True)

    monkeypatch.setattr(session_runtime, "replay_online_session", fake_replay)
    replay_module.replay_scenario_rfuzz_continuous(
        tmp_path, factory=lambda: None, session_checker=None,
        decoder_checker=None,
    )

    assert captured["kwargs"]["expected_dma_binding_identity_sha256"] == binding_identity
    assert captured["plan"] == b"outer-bound-plan"


def test_online_run_identity_requires_report_binding_schema_marker(tmp_path):
    from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity

    identity = {
        "schema_version": "scenario_online_run_identity.v1",
        "dma_binding_required": "p7_dma_bound_payload.v1",
        "dma_binding_identity_sha256": "a" * 64,
        "dma_binding_payload_sha256": "b" * 64,
    }
    envelope = {
        "schema_version": "scenario_online_run_identity_envelope.v1",
        "sha256": _digest(identity),
        "identity": identity,
    }
    (tmp_path / "online_run_identity.json").write_bytes(_canonical(envelope))
    (tmp_path / "report.json").write_bytes(_canonical({
        "online_run_identity_sha256": envelope["sha256"],
        "dma_binding_identity_sha256": identity["dma_binding_identity_sha256"],
        "dma_binding_payload_sha256": identity["dma_binding_payload_sha256"],
    }))
    plan_path = tmp_path / "online_plan.json"
    plan_path.write_bytes(b"not-an-envelope")
    trace = ScenarioTrace("c" * 64, "complete", (), {}, "d" * 64, "e" * 64)

    with pytest.raises(ValueError, match="report.*binding.*schema|binding.*schema.*report"):
        _verify_online_run_identity(
            tmp_path, plan_path=plan_path, trace_path=tmp_path / "trace.json",
            trace=trace,
        )


def test_bound_online_manifest_tracks_binding_helpers_without_changing_legacy_sources():
    from myfuzz.scenario.session_runtime import _online_manifest

    ordinary = _online_manifest(_factory(), None)
    bound = _online_manifest(_factory(), None, dma_binding_required=True)
    ordinary_paths = {row["path"] for row in ordinary["online_source_files"]}
    bound_paths = {row["path"] for row in bound["online_source_files"]}
    required = {
        "src/myfuzz/local_harness/dma_artifact_endpoint_links.py",
        "src/myfuzz/scenario/dma_binding_replay.py",
        "src/myfuzz/scenario/dma_intent_topology_binding.py",
        "src/myfuzz/scenario/dma_route_intent.py",
    }

    assert not (ordinary_paths & required)
    assert required <= bound_paths

