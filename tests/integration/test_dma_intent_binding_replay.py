"""Pure strict codec coverage for saved DMA topology binding payloads."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import importlib
import json

import pytest

from myfuzz.local_harness.dma_artifact_endpoint_links import (
    DMA_MASTER_SHAPE,
    PROVIDER_ID,
    _PROVIDER_CONTRACT,
    _sha,
    parse_dma_artifact_endpoint_links,
)
from myfuzz.scenario.dma_intent_topology_binding import prepare_dma_intent_binding
from myfuzz.scenario.dma_route_intent import parse_dma_master_route_intents
from myfuzz.scenario.compiled_paths import load_path_wiring
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
from tests.scenario import test_dma_intent_topology_binding as declaration_fixtures

try:
    codec = importlib.import_module("myfuzz.scenario.dma_binding_replay")
except ModuleNotFoundError:
    codec = None

DmaIntentBindingError = getattr(codec, "DmaIntentBindingError", None)
encode_dma_bound_payload = getattr(codec, "encode_dma_bound_payload", None)
parse_dma_bound_payload = getattr(codec, "parse_dma_bound_payload", None)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def declaration_fixture():
    wiring, prepared, route_links = declaration_fixtures.fixture()
    wiring_document = deepcopy(wiring.document)
    for row in route_links:
        link = row["endpoint_link"]
        physical = endpoint_links_document(link["artifact_endpoint_id"])["links"][0]
        link["artifact_link_id"] = physical["link_id"]
        link["template_binding"] = deepcopy(physical["template_binding"])
    for binding in wiring_document["dma_master_route_bindings"]:
        binding["initiator"] = deepcopy(route_links[0]["endpoint_link"]["template_binding"])
    wiring = load_path_wiring(wiring_document)
    return prepare_dma_intent_binding(wiring, prepared, route_links=route_links)


def ordinary_payload(kind: str) -> bytes:
    if kind == "online_session_plan":
        return b'{ "schema_version" : 10, "cases" : [] }\n'
    identity = {"schema_version": "scenario_fresh_run_identity.v1", "run_config": {}}
    envelope = {
        "schema_version": "scenario_fresh_run_identity_envelope.v1",
        "sha256": digest(identity),
        "identity": identity,
    }
    return b"\n " + canonical(envelope) + b" \n"


def endpoint_links_document(endpoint_id: str) -> dict:
    contracts = [contract for contract in __import__(
        "myfuzz.local_harness.template_contracts", fromlist=["list_template_contracts"]
    ).list_template_contracts() if (
        contract.template_id, contract.template_version, contract.variant_id
    ) == ("master.wishbone-pipelined", "1", "dma-full-word-no-select")]
    assert len(contracts) == 1
    contract = contracts[0]
    template_binding = {
        "profile_endpoint_sha256": "1" * 64,
        "template_id": contract.template_id,
        "template_version": contract.template_version,
        "variant_id": contract.variant_id,
        "contract_sha256": contract.identity_sha256,
        "selection_sha256": "2" * 64,
    }
    roles = []
    for role, (direction, width) in sorted(DMA_MASTER_SHAPE.items()):
        roles.append({
            "role": role,
            "direction": direction,
            "width": width,
            "physical_port": "physical_" + role,
            "member_path": [],
            "raw_lo": 0,
            "raw_hi": width - 1,
            "port_width": width,
            "backend_port": "mwb_" + role,
        })
    document = {
        "schema_version": "dma_artifact_endpoint_links.v1",
        "provider_id": PROVIDER_ID,
        "provider_version": "1",
        "provider_contract_sha256": _sha(_PROVIDER_CONTRACT),
        "runtime_artifact_sha256": "3" * 64,
        "runtime_sv_sha256": "4" * 64,
        "cpp_sha256": "5" * 64,
        "links": [{
            "link_id": "mwb",
            "endpoint_id": endpoint_id,
            "function": "memory_master",
            "protocol_side": "master",
            "backend_channel": "mwb",
            "template_binding": template_binding,
            "roles": roles,
        }],
    }
    document["identity_sha256"] = digest(document)
    return parse_dma_artifact_endpoint_links(document).document()


def credential_fixture(declaration):
    document = declaration.document()
    prepared = PreparedRuntimePathContract.from_document(
        document["prepared_runtime_paths"]
    )
    routes = {route.key: route for route in prepared.contract.dma_master_routes}
    intents = {
        intent.route_id: intent for intent in parse_dma_master_route_intents(
            document["wiring"]["dma_master_routes"]
        )
    }
    endpoint_ids = {}
    for row in document["route_links"]:
        route = routes[(row["rule_index"], row["prerequisite_index"])]
        endpoint_ids[route.initiator_component] = row["endpoint_link"]["artifact_endpoint_id"]
    credential = {
        "schema_version": "dma_intent_topology_binding.v1",
        "declaration_sha256": declaration.identity_sha256,
        "prepared_sha256": digest(document["prepared_runtime_paths"]),
        "runtime_contract_sha256": prepared.contract.identity_sha256,
        "runtime_compilation_sha256": "6" * 64,
        "topology_sha256": "7" * 64,
        "artifact_links": [
            {"instance_id": instance_id,
             "endpoint_links": endpoint_links_document(endpoint_id)}
            for instance_id, endpoint_id in sorted(endpoint_ids.items())
        ],
        "routes": [],
        "tier": "topology_bound",
    }
    for row in document["route_links"]:
        route = routes[(row["rule_index"], row["prerequisite_index"])]
        credential["routes"].append({
            "route_id": row["route_id"],
            "intent_sha256": intents[row["route_id"]].identity_sha256,
            "rule_index": row["rule_index"],
            "prerequisite_index": row["prerequisite_index"],
            "runtime_route_sha256": route.identity_sha256,
            "endpoint_link_sha256": digest(row["endpoint_link"]),
        })
    credential["routes"].sort(key=lambda row: row["route_id"])
    credential["identity_sha256"] = digest(credential)
    return credential


def encode_fixture(kind: str = "online_session_plan"):
    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    compilation_ids = (
        ["session"] if kind == "online_session_plan" else
        [row["path_id"] for row in declaration.document()["prepared_runtime_paths"]["selections"]]
    )
    rows = {selection_id: deepcopy(credential) for selection_id in compilation_ids}
    payload = ordinary_payload(kind)
    encoded = encode_dma_bound_payload(
        payload,
        payload_kind=kind,
        declaration=declaration,
        binding_compilations=rows,
    )
    return encoded, payload, declaration, rows


def outer_document(encoded: bytes) -> dict:
    return json.loads(encoded)


def reseal_outer(document: dict) -> bytes:
    value = deepcopy(document)
    value["identity_sha256"] = digest({
        key: item for key, item in value.items() if key != "identity_sha256"
    })
    return canonical(value)


def test_codec_module_exports_the_approved_strict_payload_api():
    assert codec is not None
    assert isinstance(DmaIntentBindingError, type)
    assert callable(encode_dma_bound_payload)
    assert callable(parse_dma_bound_payload)


@pytest.fixture(autouse=True)
def skip_behavioral_tests_until_codec_exists(request):
    if (request.node.name != "test_codec_module_exports_the_approved_strict_payload_api"
            and (codec is None or not callable(encode_dma_bound_payload)
                 or not callable(parse_dma_bound_payload))):
        pytest.skip("strict DMA payload codec has not been implemented yet")


@pytest.mark.parametrize("kind", ["online_session_plan", "fresh_run_identity"])
def test_round_trip_preserves_exact_inner_bytes_and_complete_credentials(kind):
    encoded, payload, declaration, expected_rows = encode_fixture(kind)
    outer = outer_document(encoded)
    parsed = parse_dma_bound_payload(
        encoded, expected_identity_sha256=outer["identity_sha256"]
    )

    assert parsed.payload_bytes == payload
    assert parsed.payload_kind == kind
    assert parsed.declaration.document() == declaration.document()
    assert list(parsed.binding_compilations) == outer["binding_compilations"]
    assert [row["selection_id"] for row in parsed.binding_compilations] == sorted(expected_rows)
    assert parsed.identity_sha256 == outer["identity_sha256"]
    assert set(outer) == {
        "schema_version", "payload_kind", "payload_encoding", "payload_bytes",
        "payload_sha256", "binding_declaration", "binding_compilations",
        "identity_sha256",
    }


@pytest.mark.parametrize("schema", [22, 23])
def test_native_source_completion_plan_schemas_round_trip_in_bound_envelope(schema):
    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    payload = canonical({"schema_version": schema})

    encoded = encode_dma_bound_payload(
        payload,
        payload_kind="online_session_plan",
        declaration=declaration,
        binding_compilations={"session": credential},
    )
    outer = outer_document(encoded)
    parsed = parse_dma_bound_payload(
        encoded, expected_identity_sha256=outer["identity_sha256"]
    )

    assert parsed.payload_bytes == payload
    assert json.loads(parsed.payload_bytes)["schema_version"] == schema


def test_encoder_sorts_mapping_rows_and_requires_exact_selection_ids():
    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    payload = ordinary_payload("online_session_plan")
    encoded = encode_dma_bound_payload(
        payload,
        payload_kind="online_session_plan",
        declaration=declaration,
        binding_compilations={"session": credential},
    )
    assert [row["selection_id"] for row in outer_document(encoded)["binding_compilations"]] == ["session"]

    for invalid in ({}, {"other": credential}, {"session": credential, "extra": credential}):
        with pytest.raises(DmaIntentBindingError):
            encode_dma_bound_payload(
                payload,
                payload_kind="online_session_plan",
                declaration=declaration,
                binding_compilations=invalid,
            )
    with pytest.raises(DmaIntentBindingError):
        encode_dma_bound_payload(
            payload,
            payload_kind="online_session_plan",
            declaration=declaration,
            binding_compilations=[
                {"selection_id": "session", "credential": credential},
                {"selection_id": "session", "credential": credential},
            ],
        )


@pytest.mark.parametrize("mutation", ["unknown-key", "missing-key", "outer-digest", "external-digest"])
def test_parser_refuses_nonclosed_or_unpinned_outer_document(mutation):
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    expected = outer["identity_sha256"]
    if mutation == "unknown-key":
        outer["extra"] = True
        broken = reseal_outer(outer)
    elif mutation == "missing-key":
        del outer["payload_sha256"]
        broken = reseal_outer(outer)
    elif mutation == "outer-digest":
        outer["identity_sha256"] = "0" * 64
        broken = canonical(outer)
    else:
        broken = encoded
        expected = "0" * 64
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(broken, expected_identity_sha256=expected)


def test_parser_requires_canonical_base64_even_when_decoded_bytes_are_equal():
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    original = outer["payload_bytes"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    replacement = None
    padding = len(original) - len(original.rstrip("="))
    last_data_index = len(original) - padding - 1
    for char in alphabet:
        candidate = (original[:last_data_index] + char
                     + original[last_data_index + 1:])
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except Exception:
            continue
        if candidate != original and decoded == base64.b64decode(original, validate=True):
            replacement = candidate
            break
    assert replacement is not None
    outer["payload_bytes"] = replacement
    broken = reseal_outer(outer)
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            broken, expected_identity_sha256=json.loads(broken)["identity_sha256"]
        )


@pytest.mark.parametrize("kind,payload_kind", [
    ("online_session_plan", "fresh_run_identity"),
    ("fresh_run_identity", "online_session_plan"),
])
def test_payload_kind_must_match_ordinary_inner_schema(kind, payload_kind):
    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    ids = ["session"] if payload_kind == "online_session_plan" else [
        row["path_id"] for row in declaration.document()["prepared_runtime_paths"]["selections"]
    ]
    with pytest.raises(DmaIntentBindingError):
        encode_dma_bound_payload(
            ordinary_payload(kind), payload_kind=payload_kind, declaration=declaration,
            binding_compilations={selection_id: credential for selection_id in ids},
        )


def test_nested_bound_envelopes_and_unwrapped_legacy_payloads_are_refused():
    encoded, payload, declaration, rows = encode_fixture()
    outer = outer_document(encoded)
    with pytest.raises(DmaIntentBindingError):
        encode_dma_bound_payload(
            encoded, payload_kind="online_session_plan", declaration=declaration,
            binding_compilations=rows,
        )
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(payload, expected_identity_sha256="0" * 64)
    fresh_legacy = ordinary_payload("fresh_run_identity")
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(fresh_legacy, expected_identity_sha256="0" * 64)
    nested = reseal_outer({**outer, "payload_bytes": base64.b64encode(encoded).decode("ascii"),
                           "payload_sha256": hashlib.sha256(encoded).hexdigest()})
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            nested, expected_identity_sha256=json.loads(nested)["identity_sha256"],
        )


def test_parser_requires_exact_compilation_ids_after_outer_resealing():
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    row = deepcopy(outer["binding_compilations"][0])
    for changed_rows in ([], [row, row], [{**row, "selection_id": "other"}]):
        outer["binding_compilations"] = changed_rows
        broken = reseal_outer(outer)
        with pytest.raises(DmaIntentBindingError):
            parse_dma_bound_payload(
                broken, expected_identity_sha256=json.loads(broken)["identity_sha256"]
            )


def test_parser_checks_decoded_payload_digest_after_outer_resealing():
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    decoded = base64.b64decode(outer["payload_bytes"], validate=True)
    outer["payload_bytes"] = base64.b64encode(decoded.replace(b'"cases"', b'"caseX"')).decode("ascii")
    broken = reseal_outer(outer)
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            broken, expected_identity_sha256=json.loads(broken)["identity_sha256"]
        )


@pytest.mark.parametrize("corruption", ["route", "link", "credential-digest"])
def test_parser_refuses_corrupt_credential_even_after_local_and_outer_resealing(corruption):
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    credential = outer["binding_compilations"][0]["credential"]
    if corruption == "route":
        credential["routes"][0]["runtime_route_sha256"] = "0" * 64
    elif corruption == "link":
        credential["routes"][0]["endpoint_link_sha256"] = "0" * 64
    else:
        credential["identity_sha256"] = "0" * 64
    if corruption != "credential-digest":
        credential["identity_sha256"] = digest({
            key: value for key, value in credential.items() if key != "identity_sha256"
        })
    broken = reseal_outer(outer)
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            broken, expected_identity_sha256=json.loads(encoded)["identity_sha256"]
        )


def test_parser_joins_artifact_template_binding_to_declared_route_even_after_resealing():
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    credential = outer["binding_compilations"][0]["credential"]
    endpoint_links = credential["artifact_links"][0]["endpoint_links"]
    endpoint_links["links"][0]["template_binding"]["profile_endpoint_sha256"] = "a" * 64
    endpoint_links["identity_sha256"] = digest({
        key: value for key, value in endpoint_links.items()
        if key != "identity_sha256"
    })
    credential["identity_sha256"] = digest({
        key: value for key, value in credential.items()
        if key != "identity_sha256"
    })
    broken = reseal_outer(outer)

    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            broken, expected_identity_sha256=json.loads(broken)["identity_sha256"]
        )


def test_parser_rejects_duplicate_json_keys():
    encoded, _, _, _ = encode_fixture()
    outer = outer_document(encoded)
    duplicate = (b'{"schema_version":"p7_dma_bound_payload.v1",'
                 + encoded[1:])
    with pytest.raises(DmaIntentBindingError):
        parse_dma_bound_payload(
            duplicate, expected_identity_sha256=outer["identity_sha256"]
        )


def test_fresh_payload_compilation_ids_are_exact_prepared_path_ids():
    declaration = declaration_fixture()
    credential = credential_fixture(declaration)
    selections = declaration.document()["prepared_runtime_paths"]["selections"]
    expected = sorted(row["path_id"] for row in selections)
    rows = {path_id: credential for path_id in expected}
    encoded = encode_dma_bound_payload(
        ordinary_payload("fresh_run_identity"), payload_kind="fresh_run_identity",
        declaration=declaration, binding_compilations=rows,
    )
    assert [row["selection_id"] for row in outer_document(encoded)["binding_compilations"]] == expected
    if expected:
        incomplete = {path_id: credential for path_id in expected[1:]}
        with pytest.raises(DmaIntentBindingError):
            encode_dma_bound_payload(
                ordinary_payload("fresh_run_identity"), payload_kind="fresh_run_identity",
                declaration=declaration, binding_compilations=incomplete,
            )
