"""Load declarative experiment inputs without interpreting design identifiers."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class ExperimentConfigurationError(ValueError):
    """Raised when an experiment declaration is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class SourceList:
    source_list_id: int
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Component:
    component_id: int
    role: str
    source_list_ids: tuple[int, ...]
    port_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Port:
    port_id: int
    component_id: int
    role: str | None
    uninterpreted_external: bool
    direction: str
    width: int


@dataclass(frozen=True, slots=True)
class FieldBinding:
    field_role: str
    port_id: int


@dataclass(frozen=True, slots=True)
class ProtocolEndpoint:
    endpoint_id: int
    component_id: int
    protocol_id: str
    version: str
    side: str
    field_bindings: tuple[FieldBinding, ...]


@dataclass(frozen=True, slots=True)
class ReferenceEvaluation:
    mode: str
    allowed_stage: str
    comparison: str
    command: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class ExperimentConfig:
    path: Path
    target_id: int
    source_lists: tuple[SourceList, ...]
    components: tuple[Component, ...]
    ports: tuple[Port, ...]
    protocol_endpoints: tuple[ProtocolEndpoint, ...]
    generated_candidate_count: int
    seeds: tuple[int, ...]
    cycle_budget: int
    raw_width: int
    coverage_metric: str
    reference: ReferenceEvaluation | None
    document: Mapping[str, object]


_DIRECTIONS = frozenset(("input", "output", "inout"))
_SIDES = frozenset(("initiator", "target"))


def _object(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExperimentConfigurationError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ExperimentConfigurationError(f"{label} must be an array")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExperimentConfigurationError(f"{label} must be a non-empty string")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ExperimentConfigurationError(f"{label} must be a positive integer")
    return value


def _unique_positive_ids(records: Sequence[object], label: str, key: str) -> set[int]:
    identifiers: set[int] = set()
    for index, value in enumerate(records):
        identifier = _positive_int(_object(value, f"{label}[{index}]").get(key), f"{label}[{index}].{key}")
        if identifier in identifiers:
            raise ExperimentConfigurationError(f"{label}.{key} values must be unique")
        identifiers.add(identifier)
    return identifiers


def _parse_source_lists(document: Mapping[str, object]) -> tuple[SourceList, ...]:
    records = _array(document.get("source_lists"), "source_lists")
    _unique_positive_ids(records, "source_lists", "source_list_id")
    result: list[SourceList] = []
    for index, value in enumerate(records):
        record = _object(value, f"source_lists[{index}]")
        source_list_id = _positive_int(record.get("source_list_id"), f"source_lists[{index}].source_list_id")
        files = tuple(_string(item, f"source_lists[{index}].files") for item in _array(record.get("files"), f"source_lists[{index}].files"))
        if not files or len(files) != len(set(files)):
            raise ExperimentConfigurationError("source_lists.files must be a non-empty unique list")
        result.append(SourceList(source_list_id, files))
    if not result:
        raise ExperimentConfigurationError("source_lists must not be empty")
    return tuple(result)


def _parse_components(document: Mapping[str, object], source_list_ids: set[int]) -> tuple[Component, ...]:
    records = _array(document.get("components"), "components")
    _unique_positive_ids(records, "components", "component_id")
    result: list[Component] = []
    for index, value in enumerate(records):
        record = _object(value, f"components[{index}]")
        component_id = _positive_int(record.get("component_id"), f"components[{index}].component_id")
        role = _string(record.get("role"), f"components[{index}].role")
        declared_sources = tuple(_positive_int(item, f"components[{index}].source_list_ids") for item in _array(record.get("source_list_ids"), f"components[{index}].source_list_ids"))
        if not declared_sources or len(declared_sources) != len(set(declared_sources)) or not set(declared_sources) <= source_list_ids:
            raise ExperimentConfigurationError("components.source_list_ids must resolve uniquely")
        result.append(Component(component_id, role, declared_sources, ()))
    if not result:
        raise ExperimentConfigurationError("components must not be empty")
    return tuple(result)


def _parse_ports(document: Mapping[str, object], component_ids: set[int]) -> tuple[Port, ...]:
    records = _array(document.get("ports"), "ports")
    _unique_positive_ids(records, "ports", "port_id")
    result: list[Port] = []
    for index, value in enumerate(records):
        record = _object(value, f"ports[{index}]")
        port_id = _positive_int(record.get("port_id"), f"ports[{index}].port_id")
        component_id = _positive_int(record.get("component_id"), f"ports[{index}].component_id")
        if component_id not in component_ids:
            raise ExperimentConfigurationError("ports.component_id must resolve")
        role_value = record.get("role")
        role = _string(role_value, f"ports[{index}].role") if role_value is not None else None
        uninterpreted_external = record.get("uninterpreted_external", False)
        if not isinstance(uninterpreted_external, bool) or (role is None and not uninterpreted_external):
            raise ExperimentConfigurationError("ports require a role or uninterpreted_external declaration")
        direction = record.get("direction")
        if direction not in _DIRECTIONS:
            raise ExperimentConfigurationError("ports.direction is invalid")
        width = _positive_int(record.get("width"), f"ports[{index}].width")
        result.append(Port(port_id, component_id, role, uninterpreted_external, direction, width))
    if not result:
        raise ExperimentConfigurationError("ports must not be empty")
    return tuple(result)


def _parse_protocol_endpoints(document: Mapping[str, object], component_ids: set[int], port_ids: set[int]) -> tuple[ProtocolEndpoint, ...]:
    records = _array(document.get("protocol_endpoints"), "protocol_endpoints")
    _unique_positive_ids(records, "protocol_endpoints", "endpoint_id")
    result: list[ProtocolEndpoint] = []
    for index, value in enumerate(records):
        record = _object(value, f"protocol_endpoints[{index}]")
        endpoint_id = _positive_int(record.get("endpoint_id"), f"protocol_endpoints[{index}].endpoint_id")
        component_id = _positive_int(record.get("component_id"), f"protocol_endpoints[{index}].component_id")
        if component_id not in component_ids:
            raise ExperimentConfigurationError("protocol_endpoints.component_id must resolve")
        side = record.get("side")
        if side not in _SIDES:
            raise ExperimentConfigurationError("protocol_endpoints.side is invalid")
        bindings: list[FieldBinding] = []
        field_roles: set[str] = set()
        for field_index, field_value in enumerate(_array(record.get("field_bindings"), f"protocol_endpoints[{index}].field_bindings")):
            field = _object(field_value, f"protocol_endpoints[{index}].field_bindings[{field_index}]")
            field_role = _string(field.get("field_role"), f"protocol_endpoints[{index}].field_bindings[{field_index}].field_role")
            port_id = _positive_int(field.get("port_id"), f"protocol_endpoints[{index}].field_bindings[{field_index}].port_id")
            if port_id not in port_ids or field_role in field_roles:
                raise ExperimentConfigurationError("protocol endpoint field bindings must resolve uniquely")
            field_roles.add(field_role)
            bindings.append(FieldBinding(field_role, port_id))
        if not bindings:
            raise ExperimentConfigurationError("protocol endpoint field bindings must not be empty")
        result.append(
            ProtocolEndpoint(
                endpoint_id,
                component_id,
                _string(record.get("protocol_id"), f"protocol_endpoints[{index}].protocol_id"),
                _string(record.get("version"), f"protocol_endpoints[{index}].version"),
                side,
                tuple(bindings),
            )
        )
    if not result:
        raise ExperimentConfigurationError("protocol_endpoints must not be empty")
    return tuple(result)


def _parse_reference(document: Mapping[str, object]) -> ReferenceEvaluation | None:
    value = document.get("reference")
    if value is None:
        return None
    record = _object(value, "reference")
    command_value = record.get("command")
    command: tuple[str, ...] | None
    if command_value is None:
        command = None
    else:
        command = tuple(_string(item, "reference.command") for item in _array(command_value, "reference.command"))
        if not command:
            raise ExperimentConfigurationError("reference.command must not be empty")
    reference = ReferenceEvaluation(
        _string(record.get("mode"), "reference.mode"),
        _string(record.get("allowed_stage"), "reference.allowed_stage"),
        _string(record.get("comparison"), "reference.comparison"),
        command,
    )
    if reference.mode != "evaluation-only" or reference.allowed_stage != "report":
        raise ExperimentConfigurationError("reference must be evaluation-only report metadata")
    return reference


def load_experiment_config(path: str | Path) -> ExperimentConfig:
    """Load one validated experiment declaration from a JSON file."""
    source = Path(path)
    try:
        document = _object(json.loads(source.read_text(encoding="utf-8")), str(source))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentConfigurationError(f"cannot load experiment configuration: {source}") from error
    if document.get("schema_version") != "experiment.v1":
        raise ExperimentConfigurationError("schema_version must be experiment.v1")
    target = _object(document.get("target"), "target")
    target_id = _positive_int(target.get("target_id"), "target.target_id")
    source_lists = _parse_source_lists(document)
    components = _parse_components(document, {item.source_list_id for item in source_lists})
    ports = _parse_ports(document, {item.component_id for item in components})
    components = tuple(
        Component(
            component.component_id,
            component.role,
            component.source_list_ids,
            tuple(port.port_id for port in ports if port.component_id == component.component_id),
        )
        for component in components
    )
    if any(not component.port_ids for component in components):
        raise ExperimentConfigurationError("each component must declare at least one port")
    protocol_endpoints = _parse_protocol_endpoints(
        document,
        {item.component_id for item in components},
        {item.port_id for item in ports},
    )
    candidates = _object(document.get("generated_candidates"), "generated_candidates")
    generated_candidate_count = _positive_int(candidates.get("count"), "generated_candidates.count")
    seeds = tuple(_positive_int(item, "seeds") for item in _array(document.get("seeds"), "seeds"))
    if not seeds or len(seeds) != len(set(seeds)):
        raise ExperimentConfigurationError("seeds must be a non-empty unique list")
    budget = _object(document.get("budget"), "budget")
    cycle_budget = _positive_int(budget.get("cycles"), "budget.cycles")
    raw_width = _positive_int(document.get("raw_width"), "raw_width")
    coverage = _object(document.get("coverage"), "coverage")
    coverage_metric = _string(coverage.get("metric"), "coverage.metric")
    groups = tuple(_string(item, "harness_groups") for item in _array(document.get("harness_groups"), "harness_groups"))
    if set(groups) != {"flat-direct", "candidate-direct", "candidate-depaware"} or len(groups) != 3:
        raise ExperimentConfigurationError("harness_groups must declare each supported group once")
    return ExperimentConfig(
        source.resolve(),
        target_id,
        source_lists,
        components,
        ports,
        protocol_endpoints,
        generated_candidate_count,
        seeds,
        cycle_budget,
        raw_width,
        coverage_metric,
        _parse_reference(document),
        document,
    )


def load_experiment_configs(paths: Iterable[str | Path]) -> tuple[ExperimentConfig, ...]:
    """Load a caller-selected ordered set of independent experiment declarations."""
    return tuple(load_experiment_config(path) for path in paths)
