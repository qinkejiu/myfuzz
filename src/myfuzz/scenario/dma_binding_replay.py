"""Strict detached save/replay envelope for DMA topology bindings.

The wrapper preserves the complete ordinary payload bytes and carries the
static declaration plus one complete live topology credential per selected
runtime path. It does not create or authorize a Runner.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import re

from myfuzz.local_harness.dma_artifact_endpoint_links import (
    parse_dma_artifact_endpoint_links,
)

from .dma_intent_topology_binding import (
    DmaIntentBindingError,
    PreparedDmaIntentBinding,
)
from .dma_route_intent import parse_dma_master_route_intents
from .runtime_path_contract import (
    PreparedRuntimePathContract,
    _canonical,
    _digest,
)


SCHEMA = "p7_dma_bound_payload.v1"
_OUTER_KEYS = {
    "schema_version", "payload_kind", "payload_encoding", "payload_bytes",
    "payload_sha256", "binding_declaration", "binding_compilations",
    "identity_sha256",
}
_COMPILATION_KEYS = {"selection_id", "credential"}
_CREDENTIAL_KEYS = {
    "schema_version", "declaration_sha256", "prepared_sha256",
    "runtime_contract_sha256", "runtime_compilation_sha256",
    "topology_sha256", "artifact_links", "routes", "tier", "identity_sha256",
}
_CREDENTIAL_ROUTE_KEYS = {
    "route_id", "intent_sha256", "rule_index", "prerequisite_index",
    "runtime_route_sha256", "endpoint_link_sha256",
}
_ARTIFACT_ROW_KEYS = {"instance_id", "endpoint_links"}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ONLINE_PLAN_SCHEMAS = frozenset(range(4, 26))


def _fail(pointer: str) -> None:
    raise DmaIntentBindingError("dma-binding-replay-material-invalid", pointer)


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"non-JSON numeric constant: {value}")


def _loads(data: bytes, pointer: str):
    if type(data) is not bytes:
        _fail(pointer)
    try:
        return json.loads(
            data,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid", pointer
        ) from error


def _hash(value, pointer: str) -> None:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        _fail(pointer)


def _closed(value, keys: set[str], pointer: str) -> None:
    if type(value) is not dict or set(value) != keys:
        _fail(pointer)


def _canonical_document(document, pointer: str) -> bytes:
    try:
        return _canonical(document)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid", pointer
        ) from error


def _parse_declaration(value) -> PreparedDmaIntentBinding:
    try:
        if isinstance(value, PreparedDmaIntentBinding):
            value = value.document()
        if type(value) is not dict:
            _fail("/binding_declaration")
        return PreparedDmaIntentBinding.from_document(value)
    except DmaIntentBindingError:
        raise
    except (ValueError, TypeError, AttributeError, KeyError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid", "/binding_declaration"
        ) from error


def _expected_selection_ids(payload_kind: str,
                            declaration: PreparedDmaIntentBinding) -> tuple[str, ...]:
    if payload_kind == "online_session_plan":
        return ("session",)
    if payload_kind != "fresh_run_identity":
        _fail("/payload_kind")
    try:
        prepared = PreparedRuntimePathContract.from_document(
            declaration.document()["prepared_runtime_paths"]
        )
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid",
            "/binding_declaration/prepared_runtime_paths",
        ) from error
    return tuple(sorted(prepared.path_ids))


def _validate_inner_payload(payload_bytes: bytes, payload_kind: str) -> None:
    document = _loads(payload_bytes, "/payload_bytes")
    if type(document) is not dict:
        _fail("/payload_bytes")
    schema = document.get("schema_version")
    if schema == SCHEMA:
        _fail("/payload_bytes/schema_version")
    if payload_kind == "online_session_plan":
        # Existing online plan readers use a closed integer-versioned document.
        # Keep their full version-specific validation at the replay entry point.
        if type(schema) is not int or schema not in _ONLINE_PLAN_SCHEMAS:
            _fail("/payload_kind")
        return
    if payload_kind != "fresh_run_identity":
        _fail("/payload_kind")
    _closed(document, {"schema_version", "sha256", "identity"}, "/payload_bytes")
    identity = document["identity"]
    if (document["schema_version"] != "scenario_fresh_run_identity_envelope.v1"
            or type(identity) is not dict
            or identity.get("schema_version") != "scenario_fresh_run_identity.v1"):
        _fail("/payload_kind")
    _hash(document["sha256"], "/payload_bytes/sha256")
    if document["sha256"] != _digest(identity):
        _fail("/payload_bytes/sha256")


def _as_credential_document(value, pointer: str) -> dict:
    if isinstance(value, Mapping):
        value = dict(value)
    else:
        method = getattr(value, "document", None)
        if not callable(method):
            _fail(pointer)
        try:
            value = method()
        except (ValueError, TypeError, AttributeError) as error:
            raise DmaIntentBindingError(
                "dma-binding-replay-material-invalid", pointer
            ) from error
    if type(value) is not dict:
        _fail(pointer)
    return json.loads(_canonical_document(value, pointer))


def _compilation_rows(binding_compilations) -> list[dict]:
    rows = []
    if isinstance(binding_compilations, Mapping):
        source = list(binding_compilations.items())
        for selection_id, credential in source:
            if type(selection_id) is not str or not selection_id or selection_id.strip() != selection_id:
                _fail("/binding_compilations")
            rows.append({
                "selection_id": selection_id,
                "credential": _as_credential_document(
                    credential, "/binding_compilations/" + selection_id
                ),
            })
    elif type(binding_compilations) in (list, tuple):
        for index, row in enumerate(binding_compilations):
            pointer = f"/binding_compilations/{index}"
            _closed(row, _COMPILATION_KEYS, pointer)
            selection_id = row["selection_id"]
            if type(selection_id) is not str or not selection_id or selection_id.strip() != selection_id:
                _fail(pointer + "/selection_id")
            rows.append({
                "selection_id": selection_id,
                "credential": _as_credential_document(row["credential"], pointer + "/credential"),
            })
    else:
        _fail("/binding_compilations")
    rows.sort(key=lambda row: row["selection_id"])
    if not rows or len({row["selection_id"] for row in rows}) != len(rows):
        _fail("/binding_compilations")
    return rows


def _validate_credential(credential: object, declaration: PreparedDmaIntentBinding,
                         pointer: str) -> None:
    _closed(credential, _CREDENTIAL_KEYS, pointer)
    if credential["schema_version"] != "dma_intent_topology_binding.v1":
        _fail(pointer + "/schema_version")
    if credential["tier"] != "topology_bound":
        _fail(pointer + "/tier")
    for name in (
        "declaration_sha256", "prepared_sha256", "runtime_contract_sha256",
        "runtime_compilation_sha256", "topology_sha256", "identity_sha256",
    ):
        _hash(credential[name], pointer + "/" + name)
    document = declaration.document()
    prepared_document = document["prepared_runtime_paths"]
    try:
        prepared = PreparedRuntimePathContract.from_document(prepared_document)
        contract = prepared.contract
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid", "/binding_declaration/prepared_runtime_paths"
        ) from error
    if (credential["declaration_sha256"] != declaration.identity_sha256
            or credential["prepared_sha256"] != _digest(prepared_document)
            or credential["runtime_contract_sha256"] != contract.identity_sha256):
        _fail(pointer)
    if credential["identity_sha256"] != _digest({
        key: value for key, value in credential.items() if key != "identity_sha256"
    }):
        _fail(pointer + "/identity_sha256")

    route_documents = document["route_links"]
    route_by_key = {route.key: route for route in prepared.contract.dma_master_routes}
    intent_by_id = {
        route.route_id: route for route in parse_dma_master_route_intents(
            document["wiring"]["dma_master_routes"]
        )
    }
    expected_route_rows = {}
    expected_artifact_links = {}
    for declaration_row in route_documents:
        key = (declaration_row["rule_index"], declaration_row["prerequisite_index"])
        route = route_by_key.get(key)
        intent = intent_by_id.get(declaration_row["route_id"])
        if route is None or intent is None:
            _fail("/binding_declaration/route_links")
        endpoint = declaration_row["endpoint_link"]
        expected_route_rows[declaration_row["route_id"]] = {
            "route_id": declaration_row["route_id"],
            "intent_sha256": intent.identity_sha256,
            "rule_index": declaration_row["rule_index"],
            "prerequisite_index": declaration_row["prerequisite_index"],
            "runtime_route_sha256": route.identity_sha256,
            "endpoint_link_sha256": _digest(endpoint),
        }
        expected_artifact_links.setdefault(route.initiator_component, set()).add(
            (endpoint["artifact_link_provider_id"], endpoint["artifact_link_id"],
             endpoint["artifact_endpoint_id"], _canonical(endpoint["template_binding"]))
        )

    routes = credential["routes"]
    if type(routes) is not list or len(routes) != len(expected_route_rows):
        _fail(pointer + "/routes")
    seen_route_ids = []
    for index, row in enumerate(routes):
        at = f"{pointer}/routes/{index}"
        _closed(row, _CREDENTIAL_ROUTE_KEYS, at)
        route_id = row["route_id"]
        if type(route_id) is not str or route_id not in expected_route_rows:
            _fail(at + "/route_id")
        for name in ("intent_sha256", "runtime_route_sha256", "endpoint_link_sha256"):
            _hash(row[name], at + "/" + name)
        for name in ("rule_index", "prerequisite_index"):
            if type(row[name]) is not int or row[name] < 0:
                _fail(at + "/" + name)
        if row != expected_route_rows[route_id]:
            _fail(at)
        seen_route_ids.append(route_id)
    if seen_route_ids != sorted(expected_route_rows):
        _fail(pointer + "/routes")

    artifact_links = credential["artifact_links"]
    if type(artifact_links) is not list or len(artifact_links) != len(expected_artifact_links):
        _fail(pointer + "/artifact_links")
    seen_instances = []
    for index, row in enumerate(artifact_links):
        at = f"{pointer}/artifact_links/{index}"
        _closed(row, _ARTIFACT_ROW_KEYS, at)
        instance_id = row["instance_id"]
        if type(instance_id) is not str or instance_id not in expected_artifact_links:
            _fail(at + "/instance_id")
        try:
            endpoint_links = parse_dma_artifact_endpoint_links(
                row["endpoint_links"], pointer=at + "/endpoint_links"
            ).document()
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise DmaIntentBindingError(
                getattr(error, "code", "dma-binding-replay-material-invalid"),
                getattr(error, "pointer", at + "/endpoint_links"),
            ) from error
        if endpoint_links["provider_id"] != next(iter(expected_artifact_links[instance_id]))[0]:
            _fail(at + "/endpoint_links/provider_id")
        physical_links = endpoint_links["links"]
        if type(physical_links) is not list:
            _fail(at + "/endpoint_links/links")
        actual_ids = {
            (endpoint_links["provider_id"], link.get("link_id"),
             link.get("endpoint_id"), _canonical(link.get("template_binding")))
            for link in physical_links if type(link) is dict
        }
        if actual_ids != expected_artifact_links[instance_id]:
            _fail(at + "/endpoint_links/links")
        seen_instances.append(instance_id)
    if seen_instances != sorted(expected_artifact_links):
        _fail(pointer + "/artifact_links")


def _validate_rows(rows: object, payload_kind: str,
                   declaration: PreparedDmaIntentBinding) -> tuple[dict, ...]:
    if type(rows) is not list or not rows:
        _fail("/binding_compilations")
    expected_ids = _expected_selection_ids(payload_kind, declaration)
    actual_ids = []
    credentials = []
    for index, row in enumerate(rows):
        pointer = f"/binding_compilations/{index}"
        _closed(row, _COMPILATION_KEYS, pointer)
        selection_id = row["selection_id"]
        if type(selection_id) is not str or not selection_id or selection_id.strip() != selection_id:
            _fail(pointer + "/selection_id")
        actual_ids.append(selection_id)
        _validate_credential(row["credential"], declaration, pointer + "/credential")
        credentials.append(row)
    if actual_ids != sorted(actual_ids) or tuple(actual_ids) != expected_ids:
        _fail("/binding_compilations")
    return tuple(credentials)


@dataclass(frozen=True, slots=True)
class DmaBoundPayload:
    """Immutable view of a validated outer envelope and its original bytes."""

    _payload_bytes: bytes
    payload_kind: str
    declaration: PreparedDmaIntentBinding
    _binding_compilations_bytes: bytes
    identity_sha256: str

    @property
    def payload_bytes(self) -> bytes:
        return self._payload_bytes

    @property
    def binding_compilations(self) -> tuple[dict, ...]:
        return tuple(json.loads(self._binding_compilations_bytes))

    @property
    def credential_rows(self) -> tuple[dict, ...]:
        return self.binding_compilations


def encode_dma_bound_payload(payload_bytes, *, payload_kind, declaration,
                             binding_compilations) -> bytes:
    """Encode one strictly selected ordinary payload and its live credentials."""
    if type(payload_bytes) is not bytes:
        _fail("/payload_bytes")
    if payload_kind not in ("online_session_plan", "fresh_run_identity"):
        _fail("/payload_kind")
    _validate_inner_payload(payload_bytes, payload_kind)
    parsed_declaration = _parse_declaration(declaration)
    rows = _compilation_rows(binding_compilations)
    document = {
        "schema_version": SCHEMA,
        "payload_kind": payload_kind,
        "payload_encoding": "base64",
        "payload_bytes": base64.b64encode(payload_bytes).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "binding_declaration": parsed_declaration.document(),
        "binding_compilations": rows,
    }
    document["identity_sha256"] = _digest(document)
    encoded = _canonical_document(document, "/")
    # Run the exact detached parser before returning so the writer cannot emit
    # a shape that the replay reader itself would reject.
    parse_dma_bound_payload(encoded,
                            expected_identity_sha256=document["identity_sha256"])
    return encoded


def parse_dma_bound_payload(envelope_bytes, *, expected_identity_sha256) -> DmaBoundPayload:
    """Strictly parse and pin one outer envelope before any runtime factory."""
    if type(envelope_bytes) is not bytes:
        _fail("/")
    _hash(expected_identity_sha256, "/expected_identity_sha256")
    document = _loads(envelope_bytes, "/")
    _closed(document, _OUTER_KEYS, "/")
    if document["schema_version"] != SCHEMA:
        _fail("/schema_version")
    if document["payload_kind"] not in ("online_session_plan", "fresh_run_identity"):
        _fail("/payload_kind")
    if document["payload_encoding"] != "base64":
        _fail("/payload_encoding")
    _hash(document["payload_sha256"], "/payload_sha256")
    _hash(document["identity_sha256"], "/identity_sha256")
    identity = _digest({key: value for key, value in document.items()
                        if key != "identity_sha256"})
    if identity != document["identity_sha256"]:
        _fail("/identity_sha256")
    if document["identity_sha256"] != expected_identity_sha256:
        _fail("/identity_sha256")

    encoded_payload = document["payload_bytes"]
    if type(encoded_payload) is not str:
        _fail("/payload_bytes")
    try:
        decoded_payload = base64.b64decode(encoded_payload.encode("ascii"), validate=True)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise DmaIntentBindingError(
            "dma-binding-replay-material-invalid", "/payload_bytes"
        ) from error
    if base64.b64encode(decoded_payload).decode("ascii") != encoded_payload:
        _fail("/payload_bytes")
    if hashlib.sha256(decoded_payload).hexdigest() != document["payload_sha256"]:
        _fail("/payload_sha256")
    _validate_inner_payload(decoded_payload, document["payload_kind"])

    declaration = _parse_declaration(document["binding_declaration"])
    rows = _validate_rows(document["binding_compilations"],
                          document["payload_kind"], declaration)
    return DmaBoundPayload(
        _payload_bytes=decoded_payload,
        payload_kind=document["payload_kind"],
        declaration=declaration,
        _binding_compilations_bytes=_canonical_document(list(rows), "/binding_compilations"),
        identity_sha256=document["identity_sha256"],
    )

