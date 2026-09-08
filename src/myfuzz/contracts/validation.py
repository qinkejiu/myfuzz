from __future__ import annotations

import re
from collections.abc import Mapping, Sequence


_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SOURCE_REVISION = re.compile(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})\Z")
_WINDOWS_DRIVE_QUALIFIED_PATH = re.compile(r"[A-Za-z]:")
_DIRECTIONS = frozenset(("input", "output", "inout"))
_SCHEMAS = frozenset(("hdl_facts.v2", "protocol.v1", "composition_ir.v1", "candidate_manifest.v1", "interface_description.v1", "interface_annotations.v1"))


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


def _source_revision(value: object, schema_id: str, path: str) -> None:
    if not isinstance(value, str) or _SOURCE_REVISION.fullmatch(value) is None:
        _error(schema_id, path, "invalid-hash")


def _boolean(value: object, schema_id: str, path: str) -> None:
    if not isinstance(value, bool):
        _error(schema_id, path, "type")


def _relative_path(value: object, schema_id: str, path: str) -> None:
    if not isinstance(value, str) or not value:
        _error(schema_id, path, "invalid-path")
    if value.startswith("/") or _WINDOWS_DRIVE_QUALIFIED_PATH.match(value) or "\\" in value:
        _error(schema_id, path, "invalid-path")
    if any(part in ("", ".", "..") for part in value.split("/")):
        _error(schema_id, path, "invalid-path")


def _strings(value: object, schema_id: str, path: str) -> None:
    for index, item in enumerate(_array(value, schema_id, path)):
        _string(item, schema_id, f"{path}[{index}]")


def _validate_interface_description(document: Mapping[str, object], schema_id: str) -> None:
    _require(document, schema_id, ("source", "endpoints"))
    source = _object(document["source"], schema_id, "source")
    for key in ("root", "revision", "top_module"):
        if key not in source:
            _error(schema_id, f"source.{key}", "missing")
    _relative_path(source["root"], schema_id, "source.root")
    _source_revision(source["revision"], schema_id, "source.revision")
    _string(source["top_module"], schema_id, "source.top_module")
    for key in ("files", "include_roots"):
        if key in source:
            for index, item in enumerate(_array(source[key], schema_id, f"source.{key}")):
                _relative_path(item, schema_id, f"source.{key}[{index}]")
    if "filelist" in source:
        _relative_path(source["filelist"], schema_id, "source.filelist")
    variable_names: set[str] = set()
    for index, value in enumerate(_array(source.get("filelist_variables", []), schema_id, "source.filelist_variables")):
        path = f"source.filelist_variables[{index}]"
        item = _object(value, schema_id, path)
        _require(item, schema_id, ("name", "value"))
        name = _string(item["name"], schema_id, f"{path}.name")
        item_value = _string(item["value"], schema_id, f"{path}.value")
        parts = item_value.split("/")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            _error(schema_id, f"{path}.name", "invalid")
        if (not item_value or "\0" in item_value or "\\" in item_value or "$" in item_value
                or item_value.startswith(("+", "-", "/")) or re.match(r"[A-Za-z]:", item_value)
                or "__MYFUZZ_FILELIST_ROOT__" in item_value
                or (item_value != "." and any(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", part) is None for part in parts))
                or (item_value != "." and any(part in {"", ".", ".."} for part in parts))):
            _error(schema_id, f"{path}.value", "invalid")
        if name in variable_names:
            _error(schema_id, f"{path}.name", "duplicate")
        variable_names.add(name)
    repository_paths: set[str] = set()
    for index, value in enumerate(_array(source.get("repositories", []), schema_id, "source.repositories")):
        path = f"source.repositories[{index}]"
        item = _object(value, schema_id, path)
        _require(item, schema_id, ("path", "revision"))
        _relative_path(item["path"], schema_id, f"{path}.path")
        repository_path = _string(item["path"], schema_id, f"{path}.path")
        revision = _string(item["revision"], schema_id, f"{path}.revision")
        if not re.fullmatch(r"git:[0-9a-f]{40}", revision):
            _error(schema_id, f"{path}.revision", "invalid")
        if repository_path in repository_paths:
            _error(schema_id, f"{path}.path", "duplicate")
        repository_paths.add(repository_path)
    if "elaboration" in source:
        elaboration = _object(source["elaboration"], schema_id, "source.elaboration")
        _require(elaboration, schema_id, ("frontend",))
        if elaboration["frontend"] != "verilator-json":
            _error(schema_id, "source.elaboration.frontend", "invalid")
        if elaboration.get("warning_policy", "fatal") not in {"fatal", "recorded-nonfatal"}:
            _error(schema_id, "source.elaboration.warning_policy", "invalid")
        for kind in ("defines", "parameters"):
            names: set[str] = set()
            for index, value in enumerate(_array(elaboration.get(kind, []), schema_id, f"source.elaboration.{kind}")):
                path = f"source.elaboration.{kind}[{index}]"
                item = _object(value, schema_id, path)
                _require(item, schema_id, ("name", "value"))
                name = _string(item["name"], schema_id, f"{path}.name")
                item_value = _string(item["value"], schema_id, f"{path}.value")
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                    _error(schema_id, f"{path}.name", "invalid")
                pattern = r"[A-Za-z0-9_]+" if kind == "defines" else r"-?(?:0|[1-9][0-9]*)"
                if re.fullmatch(pattern, item_value) is None:
                    _error(schema_id, f"{path}.value", "invalid")
                if name in names:
                    _error(schema_id, f"{path}.name", "duplicate-role")
                names.add(name)

    endpoint_ids: set[str] = set()
    for endpoint_index, endpoint_value in enumerate(_array(document["endpoints"], schema_id, "endpoints")):
        endpoint_path = f"endpoints[{endpoint_index}]"
        endpoint = _object(endpoint_value, schema_id, endpoint_path)
        _require(endpoint, schema_id, ("endpoint_id", "function"))
        endpoint_id = _string(endpoint["endpoint_id"], schema_id, f"{endpoint_path}.endpoint_id")
        if endpoint_id in endpoint_ids:
            _error(schema_id, f"{endpoint_path}.endpoint_id", "duplicate-role")
        endpoint_ids.add(endpoint_id)
        _string(endpoint["function"], schema_id, f"{endpoint_path}.function")
        if "module" in endpoint:
            _string(endpoint["module"], schema_id, f"{endpoint_path}.module")
        for key in ("hierarchy", "aliases"):
            if key in endpoint:
                _strings(endpoint[key], schema_id, f"{endpoint_path}.{key}")
        if "required" in endpoint:
            _boolean(endpoint["required"], schema_id, f"{endpoint_path}.required")
        if "protocol" in endpoint:
            protocol = _array(endpoint["protocol"], schema_id, f"{endpoint_path}.protocol")
            if len(protocol) != 2:
                _error(schema_id, f"{endpoint_path}.protocol", "invalid-pair")
            _string(protocol[0], schema_id, f"{endpoint_path}.protocol[0]")
            _string(protocol[1], schema_id, f"{endpoint_path}.protocol[1]")

        roles: set[str] = set()
        for field_index, field_value in enumerate(_array(endpoint.get("fields", []), schema_id, f"{endpoint_path}.fields")):
            field_path = f"{endpoint_path}.fields[{field_index}]"
            field = _object(field_value, schema_id, field_path)
            _require(field, schema_id, ("role",))
            role = _string(field["role"], schema_id, f"{field_path}.role")
            if role in roles:
                _error(schema_id, f"{field_path}.role", "duplicate-role")
            roles.add(role)
            if "aliases" in field:
                _strings(field["aliases"], schema_id, f"{field_path}.aliases")
            if "physical" in field:
                if "aliases" in field:
                    _error(schema_id, field_path, "physical-aliases-mutually-exclusive")
                if "elaboration" not in source:
                    _error(schema_id, field_path, "physical-requires-elaboration")
                if endpoint.get("module", source["top_module"]) != source["top_module"] or endpoint.get("hierarchy"):
                    _error(schema_id, field_path, "physical-requires-selected-top")
                physical = _object(field["physical"], schema_id, f"{field_path}.physical")
                _require(physical, schema_id, ("port", "member_path"))
                if set(physical) != {"port", "member_path"}:
                    _error(schema_id, f"{field_path}.physical", "unknown-member")
                for key, value in (("port", physical["port"]),):
                    name = _string(value, schema_id, f"{field_path}.physical.{key}")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                        _error(schema_id, f"{field_path}.physical.{key}", "invalid")
                path_values = _array(physical["member_path"], schema_id, f"{field_path}.physical.member_path")
                if not path_values:
                    _error(schema_id, f"{field_path}.physical.member_path", "empty")
                for path_index, value in enumerate(path_values):
                    name = _string(value, schema_id, f"{field_path}.physical.member_path[{path_index}]")
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                        _error(schema_id, f"{field_path}.physical.member_path[{path_index}]", "invalid")
            if "required" in field:
                _boolean(field["required"], schema_id, f"{field_path}.required")
            if "randomizable" in field:
                _boolean(field["randomizable"], schema_id, f"{field_path}.randomizable")


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


def _validate_interface_annotations(document: Mapping[str, object], schema_id: str) -> None:
    def record(value: object, path: str, keys: Sequence[str]) -> Mapping[str, object]:
        result = _object(value, schema_id, path)
        for key in keys:
            if key not in result:
                _error(schema_id, f"{path}.{key}", "missing")
        return result

    def enum(value: object, path: str, choices: Sequence[str]) -> None:
        if not isinstance(value, str) or value not in choices:
            _error(schema_id, path, "invalid")

    def strings(value: object, path: str, *, nonempty: bool = False) -> Sequence[object]:
        items = _array(value, schema_id, path)
        _strings(value, schema_id, path)
        if nonempty and not items:
            _error(schema_id, path, "empty")
        if len(items) != len(set(items)):
            _error(schema_id, path, "duplicate")
        return items

    def nullable_name(value: object, path: str) -> None:
        if value is not None:
            _string(value, schema_id, path)

    def evidence(value: object, path: str, choices: Sequence[str]) -> tuple[str, ...]:
        items = strings(value, path, nonempty=True)
        for index, item in enumerate(items):
            enum(item, f"{path}[{index}]", choices)
        return tuple(items)

    def location(value: object, path: str, *, column: bool = False) -> None:
        keys = ("file", "line", "column") if column else ("file", "line")
        source_location = record(value, path, keys)
        _relative_path(source_location["file"], schema_id, f"{path}.file")
        if source_location["file"] not in source_files:
            _error(schema_id, f"{path}.file", "unknown-source")
        _positive_id(source_location["line"], schema_id, f"{path}.line")
        if "column" in source_location:
            _positive_id(source_location["column"], schema_id, f"{path}.column")

    def diagnostics(value: object, path: str) -> None:
        for index, item in enumerate(_array(value, schema_id, path)):
            item_path = f"{path}[{index}]"
            diagnostic = record(item, item_path, ("code", "severity", "message"))
            for key in ("code", "message"):
                _string(diagnostic[key], schema_id, f"{item_path}.{key}")
            enum(diagnostic["severity"], f"{item_path}.severity", ("info", "warning", "error"))
            if "source" in diagnostic:
                location(diagnostic["source"], f"{item_path}.source")

    _require(document, schema_id, ("source", "endpoints", "diagnostics"))
    source = record(document["source"], "source", ("revision", "content_hash", "files", "modules"))
    _source_revision(source["revision"], schema_id, "source.revision")
    _hash(source["content_hash"], schema_id, "source.content_hash")
    source_files = strings(source["files"], "source.files", nonempty=True)
    for index, path in enumerate(source_files):
        _relative_path(path, schema_id, f"source.files[{index}]")
    modules = strings(source["modules"], "source.modules", nonempty=True)
    diagnostics(document["diagnostics"], "diagnostics")
    endpoint_ids: set[str] = set()
    for index, endpoint_value in enumerate(_array(document["endpoints"], schema_id, "endpoints")):
        path = f"endpoints[{index}]"
        endpoint = record(endpoint_value, path, ("endpoint_id", "function", "module", "fields", "clock", "reset",
                                                "timing", "protocol_candidates", "evidence", "confidence", "diagnostics"))
        for key in ("endpoint_id", "function", "module"):
            _string(endpoint[key], schema_id, f"{path}.{key}")
        if endpoint["endpoint_id"] in endpoint_ids:
            _error(schema_id, f"{path}.endpoint_id", "duplicate-role")
        endpoint_ids.add(endpoint["endpoint_id"])
        if endpoint["module"] not in modules:
            _error(schema_id, f"{path}.module", "unknown-module")
        for key in ("clock", "reset"):
            nullable_name(endpoint[key], f"{path}.{key}")
        enum(endpoint["confidence"], f"{path}.confidence", ("high", "medium", "low"))
        evidence(endpoint["evidence"], f"{path}.evidence",
                 ("explicit_module", "hierarchy_hint", "endpoint_alias", "source_top_module"))
        diagnostics(endpoint["diagnostics"], f"{path}.diagnostics")
        roles: set[str] = set()
        physical_keys: set[tuple[str, tuple[object, ...]]] = set()
        for field_index, field_value in enumerate(_array(endpoint["fields"], schema_id, f"{path}.fields")):
            field_path = f"{path}.fields[{field_index}]"
            field = record(field_value, field_path, ("role", "port", "direction", "width", "signed", "source", "evidence", "confidence"))
            for key, seen in (("role", roles),):
                name = _string(field[key], schema_id, f"{field_path}.{key}")
                if name in seen:
                    _error(schema_id, f"{field_path}.{key}", "duplicate")
                seen.add(name)
            port = _string(field["port"], schema_id, f"{field_path}.port")
            member_keys = ("member_path", "raw_lo", "raw_hi", "container_width")
            present_member_keys = tuple(key for key in member_keys if key in field)
            if present_member_keys and len(present_member_keys) != len(member_keys):
                _error(schema_id, field_path, "incomplete-member-range")
            member_path = tuple(_array(field.get("member_path", []), schema_id, f"{field_path}.member_path"))
            physical_key = (port, member_path)
            if physical_key in physical_keys:
                _error(schema_id, field_path, "duplicate-physical")
            physical_keys.add(physical_key)
            if present_member_keys:
                if not member_path:
                    _error(schema_id, f"{field_path}.member_path", "empty")
                _strings(field["member_path"], schema_id, f"{field_path}.member_path")
                for key in ("raw_lo", "raw_hi", "container_width"):
                    if key not in field:
                        _error(schema_id, f"{field_path}.{key}", "missing")
                    value = field[key]
                    minimum = 1 if key == "container_width" else 0
                    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                        _error(schema_id, f"{field_path}.{key}", "invalid")
                if (field["raw_hi"] < field["raw_lo"]
                        or field["raw_hi"] - field["raw_lo"] + 1 != field["width"]
                        or field["raw_hi"] >= field["container_width"]):
                    _error(schema_id, field_path, "invalid-member-range")
            enum(field["direction"], f"{field_path}.direction", ("input", "output", "inout"))
            _positive_id(field["width"], schema_id, f"{field_path}.width")
            _boolean(field["signed"], schema_id, f"{field_path}.signed")
            if "randomizable" in field:
                _boolean(field["randomizable"], schema_id, f"{field_path}.randomizable")
            location(field["source"], f"{field_path}.source", column=True)
            field_evidence = evidence(field["evidence"], f"{field_path}.evidence", ("explicit_alias", "source_documentation",
                                      "exact_role_label", "normalized_name", "hdl_declaration", "explicit_member", "compiler_elaboration"))
            if member_path and not {"explicit_member", "compiler_elaboration"}.issubset(field_evidence):
                _error(schema_id, f"{field_path}.evidence", "missing-member-evidence")
            enum(field["confidence"], f"{field_path}.confidence", ("high", "medium", "low"))
        for timing_index, timing_value in enumerate(_array(endpoint["timing"], schema_id, f"{path}.timing")):
            timing_path = f"{path}.timing[{timing_index}]"
            timing = record(timing_value, timing_path, ("kind", "fields", "clock", "source"))
            enum(timing["kind"], f"{timing_path}.kind", ("sequential_assignment", "combinational_assignment",
                 "reset_membership", "stall_holds_payload", "transfer_accept", "response_after_request"))
            _strings(timing["fields"], schema_id, f"{timing_path}.fields")
            nullable_name(timing["clock"], f"{timing_path}.clock")
            location(timing["source"], f"{timing_path}.source")
        for candidate_index, candidate_value in enumerate(_array(endpoint["protocol_candidates"], schema_id, f"{path}.protocol_candidates")):
            candidate_path = f"{path}.protocol_candidates[{candidate_index}]"
            candidate = record(candidate_value, candidate_path, ("id", "version", "status", "orientation", "evidence"))
            for key in ("id", "version"):
                _string(candidate[key], schema_id, f"{candidate_path}.{key}")
            enum(candidate["status"], f"{candidate_path}.status", ("consistent",))
            enum(candidate["orientation"], f"{candidate_path}.orientation", ("host", "device"))
            enum(candidate["evidence"], f"{candidate_path}.evidence", ("declared",))


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
    elif schema_id == "candidate_manifest.v1":
        _validate_manifest(value, schema_id)
    elif schema_id == "interface_annotations.v1":
        _validate_interface_annotations(value, schema_id)
    else:
        _validate_interface_description(value, schema_id)
