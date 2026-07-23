from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIRECTIONS = frozenset(("input", "output", "inout"))
_SCHEMAS = frozenset(("hdl_facts.v2", "protocol.v1", "composition_ir.v1", "candidate_manifest.v1"))


class ContractError(ValueError):
    """Stable contract error formatted as ``schema:path:reason``."""

    def __init__(self, schema_id: str, path: str, reason: str) -> None:
        super().__init__(f"{schema_id}:{path.replace('.', ':')}:{reason}")
        self.schema_id = schema_id
        self.path = path
        self.reason = reason


def _error(schema_id: str, path: str, reason: str) -> None:
    raise ContractError(schema_id, path, reason)


def _object(value: object, schema_id: str, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(schema_id, path, "type")
    return value


def _array(value: object, schema_id: str, path: str) -> Sequence[object]:
    if not isinstance(value, list):
        _error(schema_id, path, "type")
    return value


def _require(document: Mapping[str, object], schema_id: str, keys: Sequence[str]) -> None:
    for key in keys:
        if key not in document:
            _error(schema_id, key, "missing")


def _positive_id(value: object, schema_id: str, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _error(schema_id, path, "invalid-id")
    return value


def _unique_ids(items: object, schema_id: str, path: str, key: str = "id") -> None:
    seen: set[int] = set()
    for index, item in enumerate(_array(items, schema_id, path)):
        record = _object(item, schema_id, f"{path}[{index}]")
        identifier = _positive_id(record.get(key), schema_id, f"{path}[{index}].{key}")
        if identifier in seen:
            _error(schema_id, f"{path}[{index}].{key}", "duplicate-id")
        seen.add(identifier)


def _string(value: object, schema_id: str, path: str) -> str:
    if not isinstance(value, str) or not value:
        _error(schema_id, path, "type")
    return value


def _hash(value: object, schema_id: str, path: str) -> None:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        _error(schema_id, path, "invalid-hash")


def _validate_hardware_facts(document: Mapping[str, object], schema_id: str) -> None:
    _unique_ids(document.get("ports", []), schema_id, "ports")
    _unique_ids(document.get("modules", []), schema_id, "modules")
    _require(document, schema_id, ("tool", "modules", "parameters", "ports", "instances", "pin_bindings", "expressions", "dataflow_edges", "control_edges", "clock_reset_checks", "local_address_facts", "source_locations", "source_symbols", "diagnostics"))
    port_ids = {record["id"] for record in (_object(item, schema_id, f"ports[{index}]") for index, item in enumerate(_array(document["ports"], schema_id, "ports")))}
    for index, item in enumerate(_array(document["ports"], schema_id, "ports")):
        port = _object(item, schema_id, f"ports[{index}]")
        _require(port, schema_id, ("id", "module_id", "direction", "width", "signed"))
        if "declared_role" not in port:
            _error(schema_id, f"ports[{index}].declared_role", "missing")
        _string(port["declared_role"], schema_id, f"ports[{index}].declared_role")
        if port["direction"] not in _DIRECTIONS:
            _error(schema_id, f"ports[{index}].direction", "invalid")
        _positive_id(port["id"], schema_id, f"ports[{index}].id")
        _positive_id(port["module_id"], schema_id, f"ports[{index}].module_id")
        if not isinstance(port["width"], int) or isinstance(port["width"], bool) or port["width"] <= 0:
            _error(schema_id, f"ports[{index}].width", "invalid")
    tool = _object(document["tool"], schema_id, "tool")
    _require(tool, schema_id, ("frontend", "verilator_revision", "input_hash"))
    _hash(tool["input_hash"], schema_id, "tool.input_hash")
    for index, item in enumerate(_array(document["modules"], schema_id, "modules")):
        module = _object(item, schema_id, f"modules[{index}]")
        _require(module, schema_id, ("id", "ports", "instances"))
        for port_id in _array(module["ports"], schema_id, f"modules[{index}].ports"):
            if port_id not in port_ids:
                _error(schema_id, f"modules[{index}].ports", "unresolved-reference")


def _validate_protocol(document: Mapping[str, object], schema_id: str) -> None:
    _unique_ids(document.get("channels", []), schema_id, "channels")
    _require(document, schema_id, ("protocol_id", "plugin_version", "capability_profile", "endpoint_roles", "channels", "temporal_rules", "dependency_edges", "legal_adapters", "projection_actions", "capability_limits"))
    _string(document["protocol_id"], schema_id, "protocol_id")
    field_ids: set[int] = set()
    for channel_index, channel_value in enumerate(_array(document["channels"], schema_id, "channels")):
        channel = _object(channel_value, schema_id, f"channels[{channel_index}]")
        _require(channel, schema_id, ("id", "role", "fields"))
        _unique_ids(channel["fields"], schema_id, f"channels[{channel_index}].fields")
        for field_index, field_value in enumerate(_array(channel["fields"], schema_id, f"channels[{channel_index}].fields")):
            field = _object(field_value, schema_id, f"channels[{channel_index}].fields[{field_index}]")
            _require(field, schema_id, ("id", "role", "direction", "width", "required"))
            field_ids.add(_positive_id(field["id"], schema_id, f"channels[{channel_index}].fields[{field_index}].id"))
    _unique_ids(document["projection_actions"], schema_id, "projection_actions")
    for index, action_value in enumerate(_array(document["projection_actions"], schema_id, "projection_actions")):
        action = _object(action_value, schema_id, f"projection_actions[{index}]")
        _require(action, schema_id, ("id", "kind", "field_ids", "category", "max_state_bits"))
        for field_id in _array(action["field_ids"], schema_id, f"projection_actions[{index}].field_ids"):
            if field_id not in field_ids:
                _error(schema_id, f"projection_actions[{index}].field_ids", "unresolved-reference")


def _validate_composition(document: Mapping[str, object], schema_id: str) -> None:
    _unique_ids(document.get("components", []), schema_id, "components")
    _require(document, schema_id, ("candidate_id", "parent_input_hash", "graph_hash", "components", "instances", "nets", "endpoint_bindings", "adapters", "address_regions", "clock_domains", "reset_domains", "external_ports", "unresolved_optional_endpoints", "evidence", "assumptions", "rejected_alternatives", "score_vector", "diagnostics"))
    _hash(document["parent_input_hash"], schema_id, "parent_input_hash")
    _hash(document["graph_hash"], schema_id, "graph_hash")
    component_ids = {_object(item, schema_id, f"components[{index}]")["id"] for index, item in enumerate(_array(document["components"], schema_id, "components"))}
    seen_endpoints: set[int] = set()
    for index, binding_value in enumerate(_array(document["endpoint_bindings"], schema_id, "endpoint_bindings")):
        binding = _object(binding_value, schema_id, f"endpoint_bindings[{index}]")
        if "fields" not in binding:
            _error(schema_id, f"endpoint_bindings[{index}].fields", "missing")
        _require(binding, schema_id, ("endpoint_id", "component_id", "protocol_id", "side", "fields"))
        endpoint_id = _positive_id(binding["endpoint_id"], schema_id, f"endpoint_bindings[{index}].endpoint_id")
        if endpoint_id in seen_endpoints:
            _error(schema_id, f"endpoint_bindings[{index}].endpoint_id", "duplicate-id")
        seen_endpoints.add(endpoint_id)
        if binding["component_id"] not in component_ids:
            _error(schema_id, f"endpoint_bindings[{index}].component_id", "unresolved-reference")
        fields = _array(binding["fields"], schema_id, f"endpoint_bindings[{index}].fields")
        for field_index, field_value in enumerate(fields):
            field = _object(field_value, schema_id, f"endpoint_bindings[{index}].fields[{field_index}]")
            _require(field, schema_id, ("field_role", "port_id"))
            _string(field["field_role"], schema_id, f"endpoint_bindings[{index}].fields[{field_index}].field_role")
            _positive_id(field["port_id"], schema_id, f"endpoint_bindings[{index}].fields[{field_index}].port_id")


def _validate_manifest(document: Mapping[str, object], schema_id: str) -> None:
    _unique_ids(document.get("top_port_abi", []), schema_id, "top_port_abi", "port_id")
    _require(document, schema_id, ("lifecycle", "candidate_id", "composition_ir_hash", "top", "harnesses", "top_port_abi", "address_map", "raw_bit_mappings", "validation", "coverage_universe", "source_map", "build_cache_key", "resources", "diagnostics", "evidence", "assumptions"))
    if document["lifecycle"] not in ("top_validated", "runtime_ready"):
        _error(schema_id, "lifecycle", "invalid")
    _hash(document["composition_ir_hash"], schema_id, "composition_ir_hash")
    _hash(document["build_cache_key"], schema_id, "build_cache_key")
    top = _object(document["top"], schema_id, "top")
    _require(top, schema_id, ("module", "source", "content_hash"))
    _hash(top["content_hash"], schema_id, "top.content_hash")
    harnesses = _object(document["harnesses"], schema_id, "harnesses")
    mappings = _object(document["raw_bit_mappings"], schema_id, "raw_bit_mappings")
    for group in ("flat-direct", "candidate-direct", "candidate-depaware"):
        if group not in harnesses or group not in mappings:
            _error(schema_id, group, "missing")
    for index, port_value in enumerate(_array(document["top_port_abi"], schema_id, "top_port_abi")):
        port = _object(port_value, schema_id, f"top_port_abi[{index}]")
        _require(port, schema_id, ("port_id", "emitted_name", "direction", "width"))
        if port["direction"] not in _DIRECTIONS:
            _error(schema_id, f"top_port_abi[{index}].direction", "invalid")


def validate_contract(document: object, schema_id: str) -> None:
    if schema_id not in _SCHEMAS:
        raise ContractError(schema_id, "schema_id", "unsupported")
    value = _object(document, schema_id, "document")
    version = value.get("schema_version")
    if version is None:
        _error(schema_id, "schema_version", "missing")
    if version != schema_id:
        _error(schema_id, "schema_version", "unsupported")
    if schema_id == "hdl_facts.v2":
        _validate_hardware_facts(value, schema_id)
    elif schema_id == "protocol.v1":
        _validate_protocol(value, schema_id)
    elif schema_id == "composition_ir.v1":
        _validate_composition(value, schema_id)
    else:
        _validate_manifest(value, schema_id)
