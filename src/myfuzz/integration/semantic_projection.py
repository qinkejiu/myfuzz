"""Stable semantic views used by the identifier-opacity regression gate."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import copy
import math

from myfuzz.contracts import validate_contract


_IDENTIFIER_ANNOTATIONS = frozenset(
    {
        "name",
        "original_name",
        "module_name",
        "instance_name",
        "port_name",
        "net_name",
        "file_name",
        "directory_name",
        "design_name",
        "target_name",
        "source_name",
        "emitted_name",
        "module",
        "source",
        "file",
        "filename",
        "directory",
        "path",
        "source_symbol",
        "source_location",
    }
)
_DIAGNOSTIC_METADATA = frozenset(
    {
        "diagnostics",
        "diagnostic",
        "diagnostic_label",
        "evidence",
        "evidence_id",
        "evidence_ids",
        "validation_evidence_id",
        "source_locations",
        "source_symbols",
        "source_map",
        "source_text",
        "debug_path",
        "source_path",
        "output_path",
    }
)
_HASH_METADATA = frozenset(
    {
        "content_hash",
        "abi_hash",
        "coverage_universe_hash",
        "coverage_metadata_hash",
        "dependency_graph_hash",
        "composition_ir_hash",
        "input_manifest_hash",
        "build_cache_key",
        "instrumented_rtl_hash",
        "top_content_hash",
        "projection_plan_hash",
        "input_hash",
        "parent_input_hash",
        "graph_hash",
    }
)
_HDL_SECTIONS = frozenset(
    {
        "modules",
        "parameters",
        "ports",
        "instances",
        "pin_bindings",
        "expressions",
        "dataflow_edges",
        "control_edges",
        "adapter_edges",
        "clock_reset_checks",
        "local_address_facts",
    }
)
_COMPOSITION_NAMED_SECTIONS = frozenset(
    {
        "components",
        "instances",
        "nets",
        "endpoint_bindings",
        "adapters",
        "address_regions",
        "clock_domains",
        "reset_domains",
        "external_ports",
    }
)
_HDL_REQUIRED = frozenset(
    {
        "modules",
        "parameters",
        "ports",
        "instances",
        "pin_bindings",
        "expressions",
        "dataflow_edges",
        "control_edges",
        "clock_reset_checks",
        "local_address_facts",
    }
)
_COMPOSITION_REQUIRED = frozenset(
    {
        "candidate_id",
        "components",
        "instances",
        "nets",
        "endpoint_bindings",
        "adapters",
        "address_regions",
        "clock_domains",
        "reset_domains",
        "external_ports",
        "unresolved_optional_endpoints",
        "score_vector",
    }
)
_MANIFEST_REQUIRED = frozenset(
    {
        "candidate_id",
        "lifecycle",
        "harnesses",
        "top_port_abi",
        "address_map",
        "raw_bit_mappings",
        "coverage_universe",
    }
)
_HARNESS_REQUIRED = frozenset(
    {
        "candidate_id",
        "harnesses",
        "raw_bit_mappings",
        "dependency_graph",
        "protocols",
    }
)
_EMPTY: tuple[object, ...] = ()


def _ignored_key(path: str, key: str) -> bool:
    root = path.split(".", 1)[0].split("[", 1)[0]
    if root == "endpoint_bindings" and ".parameters" in path:
        return False
    if root in _HDL_SECTIONS:
        return key in (_IDENTIFIER_ANNOTATIONS | _DIAGNOSTIC_METADATA)
    if root in _COMPOSITION_NAMED_SECTIONS:
        return key in (_IDENTIFIER_ANNOTATIONS | _DIAGNOSTIC_METADATA)
    if root == "top_port_abi":
        return key in (_IDENTIFIER_ANNOTATIONS | _DIAGNOSTIC_METADATA)
    if root == "harnesses":
        return key in _HASH_METADATA
    if root == "flat_baseline":
        return key in (
            _IDENTIFIER_ANNOTATIONS | _DIAGNOSTIC_METADATA | _HASH_METADATA
        )
    return False


def _scalar(value: object, path: str) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    raise TypeError(f"{path} contains an unsupported semantic value")


def _freeze(value: object, path: str, *, ordered: bool = False) -> object:
    if isinstance(value, Mapping):
        items: list[tuple[str, object]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            if _ignored_key(path, key):
                continue
            items.append((key, _freeze(item, f"{path}.{key}", ordered=ordered)))
        return tuple(sorted(items, key=lambda pair: pair[0]))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = tuple(
            _freeze(item, f"{path}[{index}]", ordered=ordered)
            for index, item in enumerate(value)
        )
        if ordered:
            return items
        return tuple(sorted(items, key=repr))
    return _scalar(value, path)


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{path} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise TypeError(f"{path} must have string keys")
    return value  # type: ignore[return-value]


def _require_sequence(value: object, path: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{path} must be an array")
    return value


def _require_integer(value: object, path: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TypeError(f"{path} must be an integer >= {minimum}")
    return value


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{path} must be a non-empty string")
    return value


def _require_stable_scalar(value: object, path: str) -> str | int:
    if isinstance(value, str):
        return _require_string(value, path)
    return _require_integer(value, path)


def _require_positive_identifier(value: object, path: str) -> str | int:
    if isinstance(value, str):
        if (
            value.isascii()
            and value.isdigit()
            and value == str(int(value))
            and int(value) > 0
        ):
            return value
        raise TypeError(f"{path} must be a canonical positive integer ID")
    return _require_integer(value, path, minimum=1)


def _record_sequence(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    result: list[Mapping[str, object]] = []
    for index, item in enumerate(_require_sequence(value, path)):
        result.append(_require_mapping(item, f"{path}[{index}]"))
    return tuple(result)


def _require_record_fields(
    record: Mapping[str, object],
    path: str,
    fields: Sequence[str],
) -> None:
    missing = [field for field in fields if field not in record]
    if missing:
        raise ValueError(f"{path} is missing semantic fields: {', '.join(missing)}")


def _validate_edge_records(value: object, path: str) -> None:
    pairs = (
        ("source_port_id", "target_port_id"),
        ("from_port_id", "to_port_id"),
        ("source_id", "target_id"),
    )
    for index, edge in enumerate(_record_sequence(value, path)):
        edge_path = f"{path}[{index}]"
        pair = next((candidate for candidate in pairs if all(key in edge for key in candidate)), None)
        if pair is None:
            raise ValueError(f"{edge_path} is missing numeric edge endpoints")
        _require_integer(edge[pair[0]], f"{edge_path}.{pair[0]}", minimum=1)
        _require_integer(edge[pair[1]], f"{edge_path}.{pair[1]}", minimum=1)
        if "kind" in edge:
            _require_string(edge["kind"], f"{edge_path}.kind")


def _validate_hdl_semantics(document: Mapping[str, object]) -> None:
    for key in ("parameters", "instances", "pin_bindings", "expressions"):
        _record_sequence(document[key], key)
    _validate_edge_records(document["dataflow_edges"], "dataflow_edges")
    _validate_edge_records(document["control_edges"], "control_edges")
    if "adapter_edges" in document:
        _validate_edge_records(document["adapter_edges"], "adapter_edges")
    for key in ("clock_reset_checks", "local_address_facts"):
        _record_sequence(document[key], key)


def _validate_composition_semantics(document: Mapping[str, object]) -> None:
    collections = (
        "components",
        "instances",
        "nets",
        "endpoint_bindings",
        "adapters",
        "address_regions",
        "clock_domains",
        "reset_domains",
        "external_ports",
    )
    records = {key: _record_sequence(document[key], key) for key in collections}
    for index, record in enumerate(records["components"]):
        _require_record_fields(record, f"components[{index}]", ("id", "module_id", "role"))
        _require_integer(record["id"], f"components[{index}].id", minimum=1)
        _require_integer(record["module_id"], f"components[{index}].module_id", minimum=1)
        _require_string(record["role"], f"components[{index}].role")
    for index, record in enumerate(records["nets"]):
        path = f"nets[{index}]"
        _require_record_fields(record, path, ("id", "source_port_id", "sink_port_ids", "semantic_role"))
        _require_integer(record["id"], f"{path}.id", minimum=1)
        _require_integer(record["source_port_id"], f"{path}.source_port_id", minimum=1)
        for sink_index, sink in enumerate(_require_sequence(record["sink_port_ids"], f"{path}.sink_port_ids")):
            _require_integer(sink, f"{path}.sink_port_ids[{sink_index}]", minimum=1)
        _require_string(record["semantic_role"], f"{path}.semantic_role")
    for index, record in enumerate(records["endpoint_bindings"]):
        path = f"endpoint_bindings[{index}]"
        _require_record_fields(
            record,
            path,
            (
                "endpoint_id",
                "component_id",
                "protocol_id",
                "version",
                "side",
                "parameters",
                "fields",
            ),
        )
        _require_integer(record["endpoint_id"], f"{path}.endpoint_id", minimum=1)
        _require_integer(record["component_id"], f"{path}.component_id", minimum=1)
        for field in ("protocol_id", "version", "side"):
            _require_string(record[field], f"{path}.{field}")
        parameters = _require_mapping(record["parameters"], f"{path}.parameters")
        for parameter, value in parameters.items():
            _require_string(parameter, f"{path}.parameters key")
            _require_integer(value, f"{path}.parameters.{parameter}", minimum=1)
        for field_index, field in enumerate(
            _record_sequence(record["fields"], f"{path}.fields")
        ):
            field_path = f"{path}.fields[{field_index}]"
            _require_record_fields(
                field,
                field_path,
                ("field_role", "port_id", "direction", "width", "signed"),
            )
            _require_string(field["field_role"], f"{field_path}.field_role")
            _require_integer(field["port_id"], f"{field_path}.port_id", minimum=1)
            _require_string(field["direction"], f"{field_path}.direction")
            _require_integer(field["width"], f"{field_path}.width", minimum=1)
            if not isinstance(field["signed"], bool):
                raise TypeError(f"{field_path}.signed must be a boolean")
    for index, record in enumerate(records["adapters"]):
        path = f"adapters[{index}]"
        _require_record_fields(record, path, ("source_port_id", "target_port_id"))
        _require_integer(record["source_port_id"], f"{path}.source_port_id", minimum=1)
        _require_integer(record["target_port_id"], f"{path}.target_port_id", minimum=1)
        if "port_bindings" in record:
            for binding_index, binding in enumerate(
                _record_sequence(record["port_bindings"], f"{path}.port_bindings")
            ):
                binding_path = f"{path}.port_bindings[{binding_index}]"
                _require_record_fields(
                    binding,
                    binding_path,
                    ("field_role", "source_port_id", "target_port_id"),
                )
                _require_string(binding["field_role"], f"{binding_path}.field_role")
                _require_integer(binding["source_port_id"], f"{binding_path}.source_port_id", minimum=1)
                _require_integer(binding["target_port_id"], f"{binding_path}.target_port_id", minimum=1)
    for index, record in enumerate(records["address_regions"]):
        path = f"address_regions[{index}]"
        _require_record_fields(record, path, ("component_id", "base", "size"))
        _require_integer(record["component_id"], f"{path}.component_id", minimum=1)
        _require_integer(record["base"], f"{path}.base")
        _require_integer(record["size"], f"{path}.size", minimum=1)
    for index, value in enumerate(_require_sequence(document["score_vector"], "score_vector")):
        _require_integer(value, f"score_vector[{index}]", minimum=-(2**127))


def _validate_destination(record: Mapping[str, object], path: str) -> None:
    _require_record_fields(record, path, ("destination_id", "port_id", "width"))
    _require_integer(record["destination_id"], f"{path}.destination_id")
    _require_integer(record["port_id"], f"{path}.port_id", minimum=1)
    _require_integer(record["width"], f"{path}.width", minimum=1)
    component = record.get("component_id")
    if component is not None:
        _require_integer(component, f"{path}.component_id", minimum=1)


def _validate_mapping(record: Mapping[str, object], path: str) -> None:
    fields = ("raw_lo", "raw_hi", "destination_id", "destination_lo", "action", "category")
    _require_record_fields(record, path, fields)
    for field in fields[:4]:
        _require_integer(record[field], f"{path}.{field}")
    if int(record["raw_hi"]) < int(record["raw_lo"]):
        raise ValueError(f"{path} has an inverted raw range")
    _require_string(record["action"], f"{path}.action")
    _require_string(record["category"], f"{path}.category")


def _validate_harness_artifact(value: object, path: str) -> None:
    artifact = _require_mapping(value, path)
    _require_record_fields(artifact, path, ("mode", "raw_width", "destinations", "mapping"))
    _require_string(artifact["mode"], f"{path}.mode")
    _require_integer(artifact["raw_width"], f"{path}.raw_width")
    for index, record in enumerate(_record_sequence(artifact["destinations"], f"{path}.destinations")):
        _validate_destination(record, f"{path}.destinations[{index}]")
    for index, record in enumerate(_record_sequence(artifact["mapping"], f"{path}.mapping")):
        _validate_mapping(record, f"{path}.mapping[{index}]")


def _validate_harness_groups(value: object, path: str) -> None:
    groups = _require_mapping(value, path)
    for group, artifact in groups.items():
        _require_string(group, f"{path} group")
        if isinstance(artifact, Mapping):
            _validate_harness_artifact(artifact, f"{path}.{group}")
        else:
            _record_sequence(artifact, f"{path}.{group}")


def _validate_raw_groups(value: object, path: str) -> None:
    groups = _require_mapping(value, path)
    for group, mappings in groups.items():
        _require_string(group, f"{path} group")
        for index, record in enumerate(_record_sequence(mappings, f"{path}.{group}")):
            _validate_mapping(record, f"{path}.{group}[{index}]")


def _validate_dependency(value: object, path: str = "dependency_graph") -> None:
    wrapper = _require_mapping(value, path)
    graph = _require_mapping(wrapper.get("document", wrapper), f"{path}.document")
    _require_record_fields(
        graph,
        f"{path}.document",
        ("node_ids", "group_ids", "indptr", "indices", "edge_kinds", "external_endpoint_port_ids", "adapter_edges"),
    )
    for key in ("node_ids", "group_ids"):
        for index, node in enumerate(_record_sequence(graph[key], f"{path}.document.{key}")):
            node_path = f"{path}.document.{key}[{index}]"
            _require_record_fields(node, node_path, ("kind", "components"))
            _require_string(node["kind"], f"{node_path}.kind")
            for component_index, component in enumerate(
                _require_sequence(node["components"], f"{node_path}.components")
            ):
                _require_stable_scalar(
                    component,
                    f"{node_path}.components[{component_index}]",
                )
    for key in ("indptr", "indices"):
        for index, value in enumerate(_require_sequence(graph[key], f"{path}.document.{key}")):
            _require_integer(value, f"{path}.document.{key}[{index}]")
    for index, value in enumerate(_require_sequence(graph["edge_kinds"], f"{path}.document.edge_kinds")):
        _require_string(value, f"{path}.document.edge_kinds[{index}]")
    for index, value in enumerate(
        _require_sequence(
            graph["external_endpoint_port_ids"],
            f"{path}.document.external_endpoint_port_ids",
        )
    ):
        _require_positive_identifier(
            value,
            f"{path}.document.external_endpoint_port_ids[{index}]",
        )
    for index, edge in enumerate(_record_sequence(graph["adapter_edges"], f"{path}.document.adapter_edges")):
        edge_path = f"{path}.document.adapter_edges[{index}]"
        _require_record_fields(edge, edge_path, ("source_port_id", "target_port_id", "adapter_id"))
        for key in ("source_port_id", "target_port_id", "adapter_id"):
            _require_stable_scalar(edge[key], f"{edge_path}.{key}")


def _validate_manifest_semantics(document: Mapping[str, object]) -> None:
    _validate_harness_groups(document["harnesses"], "harnesses")
    _validate_raw_groups(document["raw_bit_mappings"], "raw_bit_mappings")
    facts = document.get("hdl_facts")
    if facts is not None:
        descriptor = _require_mapping(facts, "hdl_facts")
        _require_record_fields(descriptor, "hdl_facts", ("top_module_id",))
        _require_integer(descriptor["top_module_id"], "hdl_facts.top_module_id", minimum=1)
    if "dependency_graph" in document:
        _validate_dependency(document["dependency_graph"])


def _validate_harness_fragment(document: Mapping[str, object]) -> None:
    _require_string(document["candidate_id"], "candidate_id")
    _validate_harness_groups(document["harnesses"], "harnesses")
    _validate_raw_groups(document["raw_bit_mappings"], "raw_bit_mappings")
    for index, protocol in enumerate(_record_sequence(document["protocols"], "protocols")):
        path = f"protocols[{index}]"
        _require_record_fields(protocol, path, ("protocol_id", "version"))
        _require_string(protocol["protocol_id"], f"{path}.protocol_id")
        _require_string(protocol["version"], f"{path}.version")
    _validate_dependency(document["dependency_graph"])


def _require_keys(document: Mapping[str, object], keys: frozenset[str], kind: str) -> None:
    missing = sorted(keys - document.keys())
    if missing:
        raise ValueError(f"{kind} is missing semantic sections: {', '.join(missing)}")


def _section(
    document: Mapping[str, object],
    *keys: str,
    ordered: bool = False,
) -> tuple[object, ...]:
    values = tuple(
        (key, _freeze(document[key], key, ordered=ordered))
        for key in keys
        if key in document
    )
    return values


def _dependency(document: Mapping[str, object]) -> tuple[object, ...]:
    value = document.get("dependency_graph")
    if value is None:
        return _EMPTY
    graph = _require_mapping(value, "dependency_graph")
    nested = graph.get("document", graph)
    nested = _require_mapping(nested, "dependency_graph.document")
    return (("dependency_graph", _freeze(nested, "dependency_graph.document", ordered=True)),)


def _hdl_projection(document: Mapping[str, object]) -> tuple[object, ...]:
    _require_keys(document, _HDL_REQUIRED, "hdl_facts.v2")
    validate_contract(document, "hdl_facts.v2")
    _validate_hdl_semantics(document)
    return (
        ("identity", _section(document, "modules", "parameters", "ports", "instances")),
        ("edges", _section(document, "dataflow_edges", "control_edges")),
        ("connectivity", _section(document, "pin_bindings", "expressions", "external_endpoint_port_ids")),
        ("adapters", _section(document, "adapter_edges")),
        ("address_regions", _section(document, "local_address_facts")),
        ("protocol_bindings", _EMPTY),
        ("domains", _section(document, "clock_reset_checks")),
        ("score_vector", _EMPTY),
        ("raw_destinations", _EMPTY),
        ("raw_mappings", _EMPTY),
        ("dependency_graph", _EMPTY),
        ("coverage", _EMPTY),
    )


def _composition_projection(document: Mapping[str, object]) -> tuple[object, ...]:
    _require_keys(document, _COMPOSITION_REQUIRED, "composition_ir.v1")
    validate_contract(document, "composition_ir.v1")
    _validate_composition_semantics(document)
    return (
        ("identity", _section(document, "candidate_id", "components", "instances")),
        ("edges", _section(document, "nets")),
        (
            "connectivity",
            _section(document, "external_ports", "external_endpoint_port_ids", "unresolved_optional_endpoints"),
        ),
        ("adapters", _section(document, "adapters")),
        ("address_regions", _section(document, "address_regions")),
        ("protocol_bindings", _section(document, "endpoint_bindings")),
        ("domains", _section(document, "clock_domains", "reset_domains")),
        ("score_vector", _section(document, "score_vector", ordered=True)),
        ("raw_destinations", _EMPTY),
        ("raw_mappings", _EMPTY),
        ("dependency_graph", _EMPTY),
        ("coverage", _EMPTY),
    )


def _harness_semantics(document: Mapping[str, object]) -> tuple[object, ...]:
    harnesses = _require_mapping(document["harnesses"], "harnesses")
    values: list[tuple[str, object]] = []
    for group, artifact in sorted(harnesses.items()):
        if not isinstance(group, str) or not group:
            raise TypeError("harness group names must be non-empty strings")
        values.append((group, _freeze(artifact, f"harnesses.{group}")))
    return tuple(values)


def _raw_semantics(document: Mapping[str, object]) -> tuple[object, ...]:
    mappings = _require_mapping(document["raw_bit_mappings"], "raw_bit_mappings")
    values: list[tuple[str, object]] = []
    for group, records in sorted(mappings.items()):
        if not isinstance(group, str) or not group:
            raise TypeError("raw mapping group names must be non-empty strings")
        values.append((group, _freeze(records, f"raw_bit_mappings.{group}")))
    return tuple(values)


def _manifest_projection(document: Mapping[str, object]) -> tuple[object, ...]:
    _require_keys(document, _MANIFEST_REQUIRED, "candidate_manifest.v1")
    validate_contract(document, "candidate_manifest.v1")
    _validate_manifest_semantics(document)
    identity = list(_section(document, "candidate_id", "lifecycle", "combinational_design"))
    facts = document.get("hdl_facts")
    if facts is not None:
        descriptor = _require_mapping(facts, "hdl_facts")
        identity.append(("hdl_facts", _section(descriptor, "top_module_id")))
    return (
        ("identity", tuple(identity)),
        ("edges", _EMPTY),
        ("connectivity", _section(document, "top_port_abi", "flat_baseline")),
        ("adapters", _EMPTY),
        ("address_regions", _section(document, "address_map")),
        ("protocol_bindings", _section(document, "protocols", "protocol_ids")),
        ("domains", _EMPTY),
        ("score_vector", _EMPTY),
        ("raw_destinations", _harness_semantics(document)),
        ("raw_mappings", _raw_semantics(document)),
        ("dependency_graph", _dependency(document)),
        ("coverage", _section(document, "coverage_universe")),
    )


def _harness_projection(document: Mapping[str, object]) -> tuple[object, ...]:
    _require_keys(document, _HARNESS_REQUIRED, "harness manifest fragment")
    _validate_harness_fragment(document)
    return (
        ("identity", _section(document, "candidate_id")),
        ("edges", _EMPTY),
        ("connectivity", _EMPTY),
        ("adapters", _EMPTY),
        ("address_regions", _EMPTY),
        ("protocol_bindings", _section(document, "protocol_ids", "protocols")),
        ("domains", _EMPTY),
        ("score_vector", _EMPTY),
        ("raw_destinations", _harness_semantics(document)),
        ("raw_mappings", _raw_semantics(document)),
        ("dependency_graph", _dependency(document)),
        ("coverage", _EMPTY),
    )


def semantic_projection(document: Mapping[str, object]) -> tuple[object, ...]:
    """Project a supported A/B artifact without diagnostic identifier text."""
    document = _require_mapping(document, "document")
    schema = document.get("schema_version")
    if schema == "hdl_facts.v2":
        return _hdl_projection(document)
    if schema == "composition_ir.v1":
        return _composition_projection(document)
    if schema == "candidate_manifest.v1":
        return _manifest_projection(document)
    if _HARNESS_REQUIRED <= document.keys():
        return _harness_projection(document)
    if schema is not None and not isinstance(schema, str):
        raise TypeError("document.schema_version must be a string")
    raise ValueError("unsupported semantic projection document")


def assert_semantic_rename_invariant(
    original: Mapping[str, object],
    renamed: Mapping[str, object],
    run: Callable[[Mapping[str, object]], Mapping[str, object]],
) -> None:
    """Run detached inputs and assert that only diagnostic identifiers changed."""
    original = _require_mapping(original, "original")
    renamed = _require_mapping(renamed, "renamed")
    if not callable(run):
        raise TypeError("run must be callable")

    baseline_output = run(copy.deepcopy(dict(original)))
    renamed_output = run(copy.deepcopy(dict(renamed)))
    baseline_output = _require_mapping(baseline_output, "run(original)")
    renamed_output = _require_mapping(renamed_output, "run(renamed)")
    baseline = semantic_projection(baseline_output)
    changed = semantic_projection(renamed_output)
    if baseline == changed:
        return
    for left, right in zip(baseline, changed):
        if left != right:
            raise AssertionError(f"semantic projection differs in section {left[0]!r}")
    raise AssertionError("semantic projections have different shapes")


__all__ = ["assert_semantic_rename_invariant", "semantic_projection"]
