"""Saved-plan readers retain typed DMA routes across fresh replay boundaries."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.integration.scenario_rfuzz_live import _verify_runtime_path_material
from myfuzz.scenario.dependency import DependencyGraph
from myfuzz.scenario.replay import ScenarioTrace
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimePathContract,
)
from myfuzz.scenario.session_runtime import replay_online_session
from tests.scenario.test_runtime_edge_index import (
    dma_ram_route_fixture, dma_route_fixture, fixture,
)


def _sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _fixture():
    compiled, contract = dma_route_fixture()
    path_id = compiled["paths"][0]["path_id"]
    decoder = {
        "runtime_contract": contract,
        "graph": compiled["declaration"]["graph"],
        "path_mapping": compiled["declaration"]["selections"],
    }
    record = {
        "status": "contract_preflight",
        "declaration": compiled["declaration"],
        "compiled": {path_id: compiled},
    }
    return compiled, contract, decoder, record


def _tamper_drop_route(compiled):
    changed = deepcopy(compiled)
    changed["topology"]["dma_master_routes"] = []
    changed["topology_sha256"] = _sha256(changed["topology"])
    return changed


def _tamper_route_target_identity(compiled):
    changed = deepcopy(compiled)
    changed["topology"]["dma_master_routes"][0]["target"][
        "identity_sha256"] = "0" * 64
    changed["topology_sha256"] = _sha256(changed["topology"])
    return changed


def _two_selected_route_fixture_with_one_saved_snapshot():
    compiled, contract, _decoder, _record = _fixture()
    graph_document = deepcopy(compiled["declaration"]["graph"])
    graph_document["sources"][0]["directions"].append("CPU_TO_IP")
    graph = DependencyGraph.from_edge_document(graph_document)
    runtime_contract = replace(
        RuntimePathContract.from_document(contract),
        graph_sha256=_sha256(graph.edge_document()),
    )
    selected = tuple((direction, graph.edge_paths_to(
        "dma-receive", direction=direction)[0])
        for direction in ("IP_TO_IP", "CPU_TO_IP"))
    prepared = PreparedRuntimePathContract(graph, runtime_contract, selected)
    declaration = prepared.document()

    # The route fixture's topology is direction-independent. Reuse that real
    # topology compile for one of the two valid declarations, while selecting
    # only one path in this saved-run map.
    path_row = declaration["selections"][0]
    one_path_compile = deepcopy(compiled)
    one_path_compile["graph_sha256"] = runtime_contract.graph_sha256
    one_path_compile["contract_sha256"] = runtime_contract.identity_sha256
    one_path_compile["declaration"] = declaration
    one_path_compile["paths"] = [{key: path_row[key]
                                  for key in ("direction", "path_id", "target")}]
    decoder = {
        "runtime_contract": runtime_contract.document(),
        "graph": graph.edge_document(),
        "path_mapping": declaration["selections"],
    }
    record = {
        "status": "contract_preflight",
        "declaration": declaration,
        "compiled": {path_row["path_id"]: one_path_compile},
    }
    return runtime_contract, prepared, decoder, record


def test_historical_v1_runtime_path_bytes_remain_canonical_and_readable():
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex

    compiled, contract = fixture()
    declaration = compiled["declaration"]
    decoder = {"runtime_contract": contract, "graph": declaration["graph"],
               "path_mapping": declaration["selections"]}
    record = {"status": "contract_preflight", "declaration": declaration,
              "compiled": {"session": compiled}}

    assert contract["schema_version"] == "runtime_path_contract.v1"
    assert declaration["schema_version"] == "prepared_runtime_paths.v1"
    assert compiled["schema_version"] == "runtime_path_compilation.v1"
    assert RuntimePathContract.from_document(contract).document() == contract
    assert PreparedRuntimePathContract.from_document(declaration).document() == declaration
    assert RuntimeEdgeIndex(compiled, contract).document()["schema_version"] == \
        "runtime_edge_index.v1"
    _verify_runtime_path_material(record, decoder, session=True)


def test_historical_v1_readers_keep_accepting_empty_partial_compilation_maps():
    compiled, contract = fixture()
    declaration = compiled["declaration"]
    decoder = {"runtime_contract": contract,
               "graph": declaration["graph"],
               "path_mapping": declaration["selections"]}
    record = {"status": "contract_preflight", "declaration": declaration,
              "compiled": {}}
    _verify_runtime_path_material(record, decoder)

    prepared = PreparedRuntimePathContract.from_document(declaration)
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = prepared.contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    executor._install_runtime_replay_identity(record)
    assert executor.fresh_runtime_path_documents == {}


def test_route_v2_saved_identity_is_accepted_and_independent_recompile_is_stable():
    compiled, contract, decoder, record = _fixture()
    fresh_compiled, fresh_contract = dma_route_fixture()

    assert contract == fresh_contract
    assert compiled == fresh_compiled
    assert compiled["schema_version"] == "runtime_path_compilation.v2"
    assert compiled["declaration"]["schema_version"] == "prepared_runtime_paths.v2"
    assert contract["schema_version"] == "runtime_path_contract.v2"
    _verify_runtime_path_material(record, decoder)

    prepared = PreparedRuntimePathContract.from_document(compiled["declaration"])
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = prepared.contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    executor._install_runtime_replay_identity(record)
    assert executor.fresh_runtime_path_documents == record["compiled"]


def test_ram_route_resource_identity_survives_saved_readers_and_rejects_tampering():
    compiled, contract = dma_ram_route_fixture()
    fresh_compiled, fresh_contract = dma_ram_route_fixture()
    path_id = compiled["paths"][0]["path_id"]
    decoder = {
        "runtime_contract": contract,
        "graph": compiled["declaration"]["graph"],
        "path_mapping": compiled["declaration"]["selections"],
    }
    record = {
        "status": "contract_preflight",
        "declaration": compiled["declaration"],
        "compiled": {path_id: compiled},
    }

    assert compiled == fresh_compiled
    assert contract == fresh_contract
    assert compiled["topology"]["dma_master_routes"][0]["target"]["kind"] == \
        "persistent_memory"
    _verify_runtime_path_material(record, decoder)

    prepared = PreparedRuntimePathContract.from_document(compiled["declaration"])
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = prepared.contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    executor._install_runtime_replay_identity(record)
    assert executor.fresh_runtime_path_documents == record["compiled"]

    changed = deepcopy(compiled)
    changed["topology"]["dma_master_routes"][0]["target"]["identity"][
        "resource"]["memory_id"] = "other-ram"
    changed["topology_sha256"] = _sha256(changed["topology"])
    with pytest.raises(ValueError, match="runtime path"):
        _verify_runtime_path_material({**record,
            "compiled": {path_id: changed}}, decoder)
    with pytest.raises(ValueError, match="runtime path"):
        executor._install_runtime_replay_identity({**record,
            "compiled": {path_id: changed}})


def test_static_and_executor_replay_readers_reject_route_omission():
    compiled, contract, decoder, record = _fixture()
    path_id = compiled["paths"][0]["path_id"]

    dropped = _tamper_drop_route(compiled)
    with pytest.raises(ValueError, match="runtime path"):
        _verify_runtime_path_material({**record,
            "compiled": {path_id: dropped}}, decoder)

    prepared = PreparedRuntimePathContract.from_document(compiled["declaration"])
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = prepared.contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    with pytest.raises(ValueError, match="runtime path"):
        executor._install_runtime_replay_identity({**record,
            "compiled": {path_id: dropped}})

    changed_identity = _tamper_route_target_identity(compiled)
    with pytest.raises(ValueError, match="runtime path"):
        _verify_runtime_path_material({**record,
            "compiled": {path_id: changed_identity}}, decoder)


def test_route_v2_saved_readers_reject_empty_compilation_snapshot():
    compiled, _contract, decoder, record = _fixture()
    empty = {**record, "compiled": {}}
    with pytest.raises(ValueError, match="runtime path"):
        _verify_runtime_path_material(empty, decoder)

    prepared = PreparedRuntimePathContract.from_document(compiled["declaration"])
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = prepared.contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    with pytest.raises(ValueError, match="runtime path"):
        executor._install_runtime_replay_identity(empty)


def test_route_v2_saved_readers_reject_missing_selected_path_key():
    runtime_contract, prepared, decoder, record = \
        _two_selected_route_fixture_with_one_saved_snapshot()
    assert len(prepared.path_ids) == 2
    assert set(record["compiled"]) == {prepared.path_ids[0]}

    with pytest.raises(ValueError, match="runtime path"):
        _verify_runtime_path_material(record, decoder)

    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor._prepared_runtime_paths = prepared
    executor.runtime_contract = runtime_contract
    executor._runtime_declaration_document = prepared.document()
    executor.fresh_runtime_path_documents = {}
    with pytest.raises(ValueError, match="runtime path"):
        executor._install_runtime_replay_identity(record)


def test_online_saved_plan_rejects_v2_route_loss_before_constructing_fresh_runner():
    compiled, _contract, _decoder, _record = _fixture()
    runner_factory = Mock(side_effect=AssertionError("route loss must fail preflight"))
    reference = ScenarioTrace("0" * 64, "ok", (), {}, "0" * 64)
    plan = {
        "schema_version": 8,
        "template": "invalid-template-is-not-reached",
        "instruction_slots": [],
        "warmup_advances": [],
        "cases": [],
        "runtime_paths": _tamper_drop_route(compiled),
    }

    with pytest.raises(ValueError, match="runtime path"):
        replay_online_session(json.dumps(plan).encode(), runner_factory, reference)
    runner_factory.assert_not_called()


def test_online_saved_plan_accepts_route_v2_before_fresh_runner_construction():
    compiled, _contract, _decoder, _record = _fixture()
    runner_factory = Mock(side_effect=AssertionError("template preflight must run first"))
    plan = {
        "schema_version": 8,
        "template": "replaced-by-the-decoder-sentinel",
        "instruction_slots": [],
        "warmup_advances": [],
        "cases": [],
        "runtime_paths": compiled,
    }
    encoded_plan = json.dumps(plan).encode()
    reference = ScenarioTrace(hashlib.sha256(encoded_plan).hexdigest(),
                              "ok", (), {}, "0" * 64)

    with patch("myfuzz.scenario.session_runtime.GenomeCodec.decode",
               side_effect=RuntimeError("route-v2-plan-preflight-accepted")):
        with pytest.raises(RuntimeError, match="route-v2-plan-preflight-accepted"):
            replay_online_session(encoded_plan, runner_factory, reference)
    runner_factory.assert_not_called()

