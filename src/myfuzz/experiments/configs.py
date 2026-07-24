"""Load declarative experiment inputs without interpreting design identifiers."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PurePosixPath
import stat
from typing import BinaryIO, Literal

from myfuzz.protocols import ProtocolCatalog, load_protocol_catalog
from myfuzz.protocols.model import ProtocolDefinitionError
from myfuzz.protocols.widths import (
    ProtocolWidthError,
    compile_width_expression,
    width_parameters,
)


class ExperimentConfigurationError(ValueError):
    """Raised when an experiment declaration is incomplete or inconsistent."""


@dataclass(frozen=True, slots=True)
class SourceList:
    source_list_id: int
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ClockResetPolicy:
    clock_role: str
    reset_role: str
    reset_active_level: int
    reset_synchronous: bool
    declarations: tuple["ClockResetBinding", ...] = ()


@dataclass(frozen=True, slots=True)
class ClockResetBinding:
    component_id: int
    port_id: int
    kind: str
    domain_id: int
    active_level: int
    synchronous: bool


@dataclass(frozen=True, slots=True)
class AddressConstraints:
    width: int
    alignment_bytes: int


@dataclass(frozen=True, slots=True)
class Component:
    component_id: int
    role: str
    source_list_ids: tuple[int, ...]
    port_ids: tuple[int, ...]
    generated: bool = False


@dataclass(frozen=True, slots=True)
class SourceCapability:
    """A preflight-opened source inode exposed without a re-resolvable path."""

    declared_path: str
    source_list_ids: tuple[int, ...]
    _descriptor: int = field(repr=False, compare=False)

    def open(self) -> BinaryIO:
        if self._descriptor < 0:
            raise ValueError("source capability is closed")
        try:
            duplicate = os.open(
                f"/proc/self/fd/{self._descriptor}",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as error:
            raise ValueError("source capability is closed") from error
        return os.fdopen(duplicate, "rb", closefd=True)

    def read_bytes(self) -> bytes:
        with self.open() as stream:
            return stream.read()

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor < 0:
            return
        object.__setattr__(self, "_descriptor", -1)
        try:
            os.close(descriptor)
        except OSError:
            pass


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
    parameters: tuple[tuple[str, int], ...] = ()


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
    source_roots: tuple[str, ...]
    source_lists: tuple[SourceList, ...]
    components: tuple[Component, ...]
    ports: tuple[Port, ...]
    protocol_endpoints: tuple[ProtocolEndpoint, ...]
    generated_candidate_count: int
    seeds: tuple[int, ...]
    cycle_budget: int
    raw_width: int
    coverage_metric: str
    clock_reset: ClockResetPolicy | None
    address_constraints: AddressConstraints | None
    protocol_width_parameters: tuple[tuple[str, int], ...]
    reference: ReferenceEvaluation | None
    document: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class DependencyPreflight:
    status: Literal["available", "dependency_unavailable"]
    sources: tuple[Path, ...]
    missing_paths: tuple[str, ...]
    resolved_roots: tuple[Path, ...] = ()
    capabilities: tuple[SourceCapability, ...] = ()

    def close(self) -> None:
        for capability in self.capabilities:
            capability.close()


_DIRECTIONS = frozenset(("input", "output", "inout"))
_SIDES = frozenset(("initiator", "target"))
_SUPPORTED_TOP_LEVEL_FIELDS = frozenset(
    (
        "schema_version",
        "target",
        "source_roots",
        "source_lists",
        "components",
        "ports",
        "protocol_endpoints",
        "generated_candidates",
        "seeds",
        "budget",
        "raw_width",
        "coverage",
        "harness_groups",
        "mutation",
        "build_concurrency",
        "clock_reset",
        "address_constraints",
        "protocol_width_parameters",
        "reference",
    )
)


@lru_cache(maxsize=1)
def _builtin_protocol_catalog() -> ProtocolCatalog:
    return load_protocol_catalog(Path(__file__).parents[1] / "protocols" / "plugins")


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


def _relative_path(value: object, label: str) -> str:
    text = _string(value, label)
    if "\x00" in text or "\\" in text:
        raise ExperimentConfigurationError(f"{label} must be a portable relative path")
    raw_parts = text.split("/")
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in raw_parts):
        raise ExperimentConfigurationError(f"{label} must be a portable relative path")
    return path.as_posix()


def _parse_source_roots(document: Mapping[str, object]) -> tuple[str, ...]:
    value = document.get("source_roots")
    if value is None:
        return ()
    roots = tuple(
        _relative_path(item, f"source_roots[{index}]")
        for index, item in enumerate(_array(value, "source_roots"))
    )
    if not roots or len(roots) != len(set(roots)):
        raise ExperimentConfigurationError("source_roots must be a non-empty unique list")
    return roots


def _unique_positive_ids(records: Sequence[object], label: str, key: str) -> set[int]:
    identifiers: set[int] = set()
    for index, value in enumerate(records):
        identifier = _positive_int(_object(value, f"{label}[{index}]").get(key), f"{label}[{index}].{key}")
        if identifier in identifiers:
            raise ExperimentConfigurationError(f"{label}.{key} values must be unique")
        identifiers.add(identifier)
    return identifiers


def _parse_source_lists(
    document: Mapping[str, object],
    source_roots: tuple[str, ...],
) -> tuple[SourceList, ...]:
    records = _array(document.get("source_lists"), "source_lists")
    _unique_positive_ids(records, "source_lists", "source_list_id")
    result: list[SourceList] = []
    for index, value in enumerate(records):
        record = _object(value, f"source_lists[{index}]")
        source_list_id = _positive_int(record.get("source_list_id"), f"source_lists[{index}].source_list_id")
        files = tuple(
            _relative_path(item, f"source_lists[{index}].files")
            for item in _array(record.get("files"), f"source_lists[{index}].files")
        )
        if not files or len(files) != len(set(files)):
            raise ExperimentConfigurationError("source_lists.files must be a non-empty unique list")
        if source_roots and any(
            not any(
                PurePosixPath(file).is_relative_to(PurePosixPath(root))
                for root in source_roots
            )
            for file in files
        ):
            raise ExperimentConfigurationError(
                "source_lists.files must stay below declared source_roots"
            )
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
        generated = record.get("generated", False)
        if not isinstance(generated, bool):
            raise ExperimentConfigurationError("components.generated must be bool")
        if generated and declared_sources:
            raise ExperimentConfigurationError(
                "generated components cannot declare source lists"
            )
        if (
            (not declared_sources and not generated)
            or len(declared_sources) != len(set(declared_sources))
            or not set(declared_sources) <= source_list_ids
        ):
            raise ExperimentConfigurationError("components.source_list_ids must resolve uniquely")
        result.append(Component(component_id, role, declared_sources, (), generated))
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


def _parse_protocol_endpoints(
    document: Mapping[str, object],
    component_ids: set[int],
    ports_by_id: Mapping[int, Port],
    address_constraints: AddressConstraints | None,
    protocol_width_parameters: Mapping[str, int],
) -> tuple[ProtocolEndpoint, ...]:
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
        protocol_id = _string(record.get("protocol_id"), f"protocol_endpoints[{index}].protocol_id")
        version = _string(record.get("version"), f"protocol_endpoints[{index}].version")
        try:
            plugin = _builtin_protocol_catalog().require(protocol_id, version)
        except ProtocolDefinitionError as error:
            raise ExperimentConfigurationError(str(error)) from error
        endpoint_parameters = _parse_width_parameters(
            record.get("parameters"),
            f"protocol_endpoints[{index}].parameters",
        )
        bindings: list[FieldBinding] = []
        field_roles: set[str] = set()
        for field_index, field_value in enumerate(_array(record.get("field_bindings"), f"protocol_endpoints[{index}].field_bindings")):
            field = _object(field_value, f"protocol_endpoints[{index}].field_bindings[{field_index}]")
            field_role = _string(field.get("field_role"), f"protocol_endpoints[{index}].field_bindings[{field_index}].field_role")
            port_id = _positive_int(field.get("port_id"), f"protocol_endpoints[{index}].field_bindings[{field_index}].port_id")
            if port_id not in ports_by_id or field_role in field_roles:
                raise ExperimentConfigurationError("protocol endpoint field bindings must resolve uniquely")
            if ports_by_id[port_id].component_id != component_id:
                raise ExperimentConfigurationError("field binding port must belong to endpoint component")
            field_roles.add(field_role)
            bindings.append(FieldBinding(field_role, port_id))
        if not bindings:
            raise ExperimentConfigurationError("protocol endpoint field bindings must not be empty")
        supported_field_roles = {field.field_id for field in plugin.fields}
        unsupported_field_roles = field_roles - supported_field_roles
        if unsupported_field_roles:
            raise ExperimentConfigurationError(
                "unsupported field role: " + ", ".join(sorted(unsupported_field_roles))
            )
        missing_field_roles = {field.field_id for field in plugin.fields if field.required} - field_roles
        if missing_field_roles:
            raise ExperimentConfigurationError(
                "missing required field roles: " + ", ".join(sorted(missing_field_roles))
            )
        fields_by_role = {field.field_id: field for field in plugin.fields}
        resolved_width_parameters = dict(protocol_width_parameters)
        resolved_width_parameters.update(endpoint_parameters)
        if address_constraints is not None:
            resolved_width_parameters["address_width"] = address_constraints.width
        for binding in bindings:
            field = fields_by_role[binding.field_role]
            port = ports_by_id[binding.port_id]
            expected_direction = (
                "output"
                if (field.direction == "host_to_device") == (side == "initiator")
                else "input"
            )
            if port.direction != expected_direction:
                raise ExperimentConfigurationError("protocol endpoint field direction is invalid")
            try:
                expected_width = compile_width_expression(
                    field.width_expression,
                    resolved_width_parameters,
                )
            except ProtocolWidthError as error:
                raise ExperimentConfigurationError(
                    "protocol endpoint field width cannot be resolved: "
                    f"{field.width_expression}"
                ) from error
            if port.width != expected_width:
                raise ExperimentConfigurationError("protocol endpoint field width is invalid")
        result.append(
            ProtocolEndpoint(
                endpoint_id,
                component_id,
                protocol_id,
                version,
                side,
                tuple(bindings),
                tuple(sorted(endpoint_parameters.items())),
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


def _parse_clock_reset(
    document: Mapping[str, object],
    component_ids: set[int],
    ports_by_id: Mapping[int, Port],
) -> ClockResetPolicy | None:
    value = document.get("clock_reset")
    if value is None:
        return None
    record = _object(value, "clock_reset")
    active_level = record.get("reset_active_level")
    synchronous = record.get("reset_synchronous")
    if (
        isinstance(active_level, bool)
        or not isinstance(active_level, int)
        or active_level not in (0, 1)
    ):
        raise ExperimentConfigurationError("clock_reset.reset_active_level must be 0 or 1")
    if not isinstance(synchronous, bool):
        raise ExperimentConfigurationError("clock_reset.reset_synchronous must be bool")
    declarations: list[ClockResetBinding] = []
    seen_ports: set[int] = set()
    for index, item in enumerate(_array(record.get("declarations", []), "clock_reset.declarations")):
        declaration = _object(item, f"clock_reset.declarations[{index}]")
        component_id = _positive_int(
            declaration.get("component_id"),
            f"clock_reset.declarations[{index}].component_id",
        )
        port_id = _positive_int(
            declaration.get("port_id"),
            f"clock_reset.declarations[{index}].port_id",
        )
        kind = _string(declaration.get("kind"), f"clock_reset.declarations[{index}].kind")
        if kind not in {"clock", "reset"}:
            raise ExperimentConfigurationError("clock_reset.declarations.kind must be clock or reset")
        domain_id = _positive_int(
            declaration.get("domain_id"),
            f"clock_reset.declarations[{index}].domain_id",
        )
        active_value = declaration.get(
            "active_level",
            active_level if kind == "reset" else 1,
        )
        if isinstance(active_value, bool) or not isinstance(active_value, int) or active_value not in (0, 1):
            raise ExperimentConfigurationError(
                "clock_reset.declarations.active_level must be 0 or 1"
            )
        synchronous_value = declaration.get("synchronous", synchronous)
        if not isinstance(synchronous_value, bool):
            raise ExperimentConfigurationError(
                "clock_reset.declarations.synchronous must be bool"
            )
        if component_id not in component_ids or port_id not in ports_by_id:
            raise ExperimentConfigurationError(
                "clock_reset.declarations must resolve component and port"
            )
        if ports_by_id[port_id].component_id != component_id or ports_by_id[port_id].role != kind:
            raise ExperimentConfigurationError(
                "clock_reset.declarations must match the declared port role"
            )
        if port_id in seen_ports:
            raise ExperimentConfigurationError("clock_reset.declarations ports must be unique")
        seen_ports.add(port_id)
        declarations.append(
            ClockResetBinding(
                component_id,
                port_id,
                kind,
                domain_id,
                active_value,
                synchronous_value,
            )
        )
    for port in ports_by_id.values():
        if port.role in {"clock", "reset"} and port.port_id not in seen_ports:
            raise ExperimentConfigurationError(
                "clock_reset.declarations must cover every clock/reset port"
            )
    policy = ClockResetPolicy(
        _string(record.get("clock_role"), "clock_reset.clock_role"),
        _string(record.get("reset_role"), "clock_reset.reset_role"),
        active_level,
        synchronous,
        tuple(sorted(declarations, key=lambda item: (item.component_id, item.port_id))),
    )
    if policy.clock_role == policy.reset_role:
        raise ExperimentConfigurationError("clock and reset roles must be distinct")
    return policy


def _parse_address_constraints(document: Mapping[str, object]) -> AddressConstraints | None:
    value = document.get("address_constraints")
    if value is None:
        return None
    record = _object(value, "address_constraints")
    width = _positive_int(record.get("width"), "address_constraints.width")
    alignment = _positive_int(
        record.get("alignment_bytes"),
        "address_constraints.alignment_bytes",
    )
    if width % 8 != 0:
        raise ExperimentConfigurationError("address_constraints.width must be byte aligned")
    if alignment & (alignment - 1):
        raise ExperimentConfigurationError(
            "address_constraints.alignment_bytes must be a power of two"
        )
    return AddressConstraints(width, alignment)


def _parse_width_parameters(value: object, label: str) -> dict[str, int]:
    if value is None:
        return {}
    try:
        return width_parameters(_object(value, label))
    except ProtocolWidthError as error:
        raise ExperimentConfigurationError(
            f"{label} must declare positive integer widths"
        ) from error


def load_experiment_config(path: str | Path) -> ExperimentConfig:
    """Load one validated experiment declaration from a JSON file."""
    source = Path(path)
    try:
        document = _object(json.loads(source.read_text(encoding="utf-8")), str(source))
    except (OSError, json.JSONDecodeError) as error:
        raise ExperimentConfigurationError(f"cannot load experiment configuration: {source}") from error
    unsupported_fields = set(document) - _SUPPORTED_TOP_LEVEL_FIELDS
    if unsupported_fields:
        raise ExperimentConfigurationError(
            "unsupported top-level fields: " + ", ".join(sorted(unsupported_fields))
        )
    if document.get("schema_version") != "experiment.v1":
        raise ExperimentConfigurationError("schema_version must be experiment.v1")
    target = _object(document.get("target"), "target")
    target_id = _positive_int(target.get("target_id"), "target.target_id")
    source_roots = _parse_source_roots(document)
    source_lists = _parse_source_lists(document, source_roots)
    components = _parse_components(document, {item.source_list_id for item in source_lists})
    ports = _parse_ports(document, {item.component_id for item in components})
    address_constraints = _parse_address_constraints(document)
    protocol_width_parameters = _parse_width_parameters(
        document.get("protocol_width_parameters"),
        "protocol_width_parameters",
    )
    components = tuple(
        Component(
            component.component_id,
            component.role,
            component.source_list_ids,
            tuple(port.port_id for port in ports if port.component_id == component.component_id),
            component.generated,
        )
        for component in components
    )
    if any(not component.port_ids for component in components):
        raise ExperimentConfigurationError("each component must declare at least one port")
    protocol_endpoints = _parse_protocol_endpoints(
        document,
        {item.component_id for item in components},
        {item.port_id: item for item in ports},
        address_constraints,
        protocol_width_parameters,
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
        source_roots,
        source_lists,
        components,
        ports,
        protocol_endpoints,
        generated_candidate_count,
        seeds,
        cycle_budget,
        raw_width,
        coverage_metric,
        _parse_clock_reset(
            document,
            {item.component_id for item in components},
            {item.port_id: item for item in ports},
        ),
        address_constraints,
        tuple(sorted(protocol_width_parameters.items())),
        _parse_reference(document),
        document,
    )


def load_experiment_configs(paths: Iterable[str | Path]) -> tuple[ExperimentConfig, ...]:
    """Load a caller-selected ordered set of independent experiment declarations."""
    return tuple(load_experiment_config(path) for path in paths)


def preflight_experiment_sources(
    config: ExperimentConfig,
    repo_root: Path,
) -> DependencyPreflight:
    """Resolve only declared source files and distinguish missing dependencies."""
    if not isinstance(config, ExperimentConfig):
        raise TypeError("config must be an ExperimentConfig")
    if not isinstance(repo_root, Path):
        raise TypeError("repo_root must be a pathlib.Path")
    try:
        root_metadata = repo_root.lstat()
    except OSError as error:
        raise ExperimentConfigurationError("cannot inspect repository root") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ExperimentConfigurationError("repo_root must be a real directory")

    def resolve_path(path: Path, label: str) -> Path:
        try:
            return path.resolve(strict=False)
        except (OSError, RuntimeError) as error:
            raise ExperimentConfigurationError(f"cannot resolve {label}") from error

    resolved_repo = resolve_path(repo_root, "repository root")

    resolved_roots: dict[str, Path] = {}
    for declared_root in config.source_roots:
        resolved = resolve_path(resolved_repo / declared_root, "declared source_root")
        if not resolved.is_relative_to(resolved_repo):
            raise ExperimentConfigurationError("declared source_root escapes repo_root")
        resolved_roots[declared_root] = resolved

    root_descriptors: dict[str, int | None] = {}
    repo_descriptor = -1
    sources: list[Path] = []
    missing: list[str] = []
    capabilities: list[SourceCapability] = []
    declared_file_lists: dict[str, set[int]] = {}
    for source_list in config.source_lists:
        for declared_file in source_list.files:
            declared_file_lists.setdefault(declared_file, set()).add(source_list.source_list_id)
    declared_files = sorted(declared_file_lists)
    try:
        try:
            repo_descriptor = os.open(
                resolved_repo,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise ExperimentConfigurationError("cannot open repository root") from error
        for declared_root in config.source_roots:
            descriptor = repo_descriptor
            try:
                for part in PurePosixPath(declared_root).parts:
                    next_descriptor = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=descriptor,
                    )
                    if descriptor != repo_descriptor:
                        os.close(descriptor)
                    descriptor = next_descriptor
            except FileNotFoundError:
                if descriptor != repo_descriptor:
                    os.close(descriptor)
                root_descriptors[declared_root] = None
            except OSError as error:
                if descriptor != repo_descriptor:
                    os.close(descriptor)
                raise ExperimentConfigurationError("cannot open declared source_root") from error
            else:
                root_descriptors[declared_root] = descriptor

        for declared_file in declared_files:
            matching_roots = tuple(
                root
                for root in config.source_roots
                if PurePosixPath(declared_file).is_relative_to(PurePosixPath(root))
            )
            if not matching_roots:
                raise ExperimentConfigurationError(
                    "source file is outside declared source_roots"
                )
            declared_root = max(matching_roots, key=len)
            candidate = resolved_repo / declared_file
            resolved_candidate = resolve_path(candidate, "source path")
            if not resolved_candidate.is_relative_to(resolved_roots[declared_root]):
                raise ExperimentConfigurationError("source path escapes declared source_root")
            root_descriptor = root_descriptors[declared_root]
            if root_descriptor is None:
                missing.append(declared_file)
                continue
            descriptor = -1
            directory_descriptor = -1
            try:
                directory_descriptor = os.dup(root_descriptor)
                relative_parts = PurePosixPath(declared_file).relative_to(PurePosixPath(declared_root)).parts
                for part in relative_parts[:-1]:
                    next_descriptor = os.open(
                        part,
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=directory_descriptor,
                    )
                    os.close(directory_descriptor)
                    directory_descriptor = next_descriptor
                descriptor = os.open(
                    relative_parts[-1],
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
                opened_metadata = os.fstat(descriptor)
            except OSError:
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                missing.append(declared_file)
                continue
            finally:
                if directory_descriptor >= 0:
                    os.close(directory_descriptor)
            if not stat.S_ISREG(opened_metadata.st_mode):
                os.close(descriptor)
                raise ExperimentConfigurationError("source must be a regular file")
            sources.append(resolved_candidate)
            capabilities.append(
                SourceCapability(
                    declared_file,
                    tuple(sorted(declared_file_lists[declared_file])),
                    descriptor,
                )
            )
        status = "available" if not missing else "dependency_unavailable"
        if missing:
            for capability in capabilities:
                capability.close()
            capabilities.clear()
        return DependencyPreflight(
            status,
            tuple(sources) if not missing else (),
            tuple(missing),
            tuple(resolved_roots[root] for root in config.source_roots),
            tuple(capabilities),
        )
    except BaseException:
        for capability in capabilities:
            capability.close()
        raise
    finally:
        for descriptor in root_descriptors.values():
            if descriptor is not None:
                os.close(descriptor)
        if repo_descriptor >= 0:
            os.close(repo_descriptor)
