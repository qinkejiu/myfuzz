"""Deterministic, catalog-backed CPU/peripheral composition planning."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType

from myfuzz.components import (
    ComponentCatalog,
    ComponentDefinitionError,
    PeripheralProfile,
    load_builtin_component_catalog,
)
from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.isa.constraints import IsaContract
from myfuzz.isa import CpuCatalog, CpuDefinitionError, CpuProfile, load_builtin_cpu_catalog
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import CompiledField, CompiledProtocol

from .endpoint_capabilities import (
    EndpointCapability,
    EndpointFieldFact,
    match_endpoint_pair,
    normalize_annotations,
)
from .ids import canonical_id
from .input_layout import InputLayout, build_input_layout, input_layout_document
from .interface_description import InterfaceDescription
from .ir import canonical_ir_document, canonical_ir_hash
from .source_crawler import annotate_interfaces


class AutoCompositionError(ValueError):
    """Raised when an auto-composition request or publication is unsafe."""


_RUNTIME_ADAPTERS = {
    ("apb", "4"): "apb4",
    ("axi4-lite", "1"): "axi4-lite",
    ("tl-ul", "1"): "tl-ul",
}
_MANIFEST_COMPONENT_TYPES = frozenset({"ram", "timer", "gpio", "uart", "spi"})
_MANIFEST_SIZES = frozenset({0x1000, 0x10000})
_IBEX_EXTERNAL_IRQ_MIN = 0
_IBEX_EXTERNAL_IRQ_MAX = 14
_DEFAULT_SEED = 7
_DEFAULT_DURATION_SECONDS = 3600
_DEFAULT_CHECKPOINT_SECONDS = 30


@dataclass(frozen=True, slots=True)
class AutoCompositionRequest:
    """The closed inputs to one deterministic composition plan."""

    cpu_id: str
    component_types: tuple[str, ...]
    protocol_preferences: tuple[tuple[str, str], ...]
    address_width: int = 32
    data_width: int = 32
    base_address: int = 0x80010000
    window_size: int = 0x1000
    irq_start: int = 1

    def __post_init__(self) -> None:
        try:
            component_types = tuple(self.component_types)
        except TypeError as error:
            raise AutoCompositionError("component_types:type") from error
        try:
            preferences = tuple(tuple(preference) for preference in self.protocol_preferences)
        except TypeError as error:
            raise AutoCompositionError("protocol_preferences:type") from error
        object.__setattr__(self, "component_types", component_types)
        object.__setattr__(self, "protocol_preferences", preferences)


@dataclass(frozen=True, slots=True)
class GenericCompositionRequest:
    """A source-annotated, CPU-name-independent composition request."""

    interface_description: InterfaceDescription
    component_types: tuple[str, ...]
    protocol_preferences: tuple[tuple[str, str], ...] = ()
    isa: IsaContract | None = None
    seed: int = _DEFAULT_SEED

    def __post_init__(self) -> None:
        if not isinstance(self.interface_description, InterfaceDescription):
            raise AutoCompositionError("generic:interface-description:type")
        if isinstance(self.component_types, str):
            raise AutoCompositionError("generic:component-types:type")
        try:
            component_types = tuple(self.component_types)
            preferences = tuple(tuple(item) for item in self.protocol_preferences)
        except TypeError as error:
            raise AutoCompositionError("generic:request:type") from error
        if any(not isinstance(item, str) or not item for item in component_types):
            raise AutoCompositionError("generic:component-types:invalid")
        if len(component_types) != len(set(component_types)):
            raise AutoCompositionError("generic:component-types:duplicate")
        if any(len(item) != 2 or not all(isinstance(value, str) and value for value in item) for item in preferences):
            raise AutoCompositionError("generic:protocol-preferences:invalid")
        if len(preferences) != len(set(preferences)):
            raise AutoCompositionError("generic:protocol-preferences:duplicate")
        if self.isa is not None and not isinstance(self.isa, IsaContract):
            raise AutoCompositionError("generic:isa:type")
        if not _integer(self.seed) or self.seed < 0:
            raise AutoCompositionError("generic:seed:invalid")
        object.__setattr__(self, "component_types", component_types)
        object.__setattr__(self, "protocol_preferences", preferences)


@dataclass(frozen=True, slots=True)
class GenericCompositionPlan:
    """Fully validated inputs for generic top-level publication."""

    interface_description: InterfaceDescription
    annotations: Mapping[str, object]
    capabilities: tuple[EndpointCapability, ...]
    components: tuple[Mapping[str, object], ...]
    matches: tuple[Mapping[str, object], ...]
    diagnostics: tuple[str, ...]
    layout: InputLayout
    ir: Mapping[str, object]
    interface_annotation_hash: str
    composition_ir_hash: str
    source_files: tuple[str, ...]
    complete: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "annotations", _freeze_nested(self.annotations))
        object.__setattr__(self, "components", tuple(_freeze_nested(item) for item in self.components))
        object.__setattr__(self, "matches", tuple(_freeze_nested(item) for item in self.matches))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "ir", _freeze_nested(self.ir))
        object.__setattr__(self, "source_files", tuple(self.source_files))


def _freeze_nested(value: object) -> object:
    """Copy mappings/sequences into recursively immutable equivalents."""
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_nested(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_nested(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class AutoCompositionPlan:
    """A portable plan and its deterministic semantic hash."""

    cpu: CpuProfile
    components: tuple[Mapping[str, object], ...]
    dependencies: tuple[tuple[str, str], ...]
    diagnostics: tuple[str, ...]
    complete: bool
    content_hash: str
    _cpu_source_paths: tuple[str, ...] = field(default=(), repr=False, compare=False)
    _component_source_paths: tuple[tuple[str, tuple[str, ...]], ...] = field(
        default=(), repr=False, compare=False
    )
    _source_root: str | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "components",
            tuple(_freeze_nested(component) for component in self.components),
        )
        object.__setattr__(
            self,
            "dependencies",
            tuple(tuple(edge) for edge in self.dependencies),
        )
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "_cpu_source_paths", tuple(self._cpu_source_paths))
        object.__setattr__(
            self,
            "_component_source_paths",
            tuple(
                (component_id, tuple(source_paths))
                for component_id, source_paths in self._component_source_paths
            ),
        )
        if self._source_root is not None:
            object.__setattr__(self, "_source_root", str(self._source_root))


def _plain(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _cpu_document(cpu: CpuProfile) -> dict[str, object]:
    return {
        "cpu_id": cpu.cpu_id,
        "vendor": cpu.vendor,
        "xlen": list(cpu.xlen),
        "extensions": list(cpu.extensions),
        "core_native_protocols": [list(pair) for pair in cpu.core_native_protocols],
        "integration_protocols": [list(pair) for pair in cpu.integration_protocols],
        "source_status": cpu.source_status,
        "source_paths": list(cpu.source_paths),
        "implemented": cpu.implemented,
    }


def _plan_hash_document(
    cpu: CpuProfile,
    components: tuple[Mapping[str, object], ...],
    dependencies: tuple[tuple[str, str], ...],
    diagnostics: tuple[str, ...],
    complete: bool,
    cpu_source_paths: tuple[str, ...],
    component_source_paths: tuple[tuple[str, tuple[str, ...]], ...],
) -> dict[str, object]:
    return {
        "schema_version": "auto_composition_plan.v1",
        "cpu": _cpu_document(cpu),
        "components": [_plain(component) for component in components],
        "dependencies": [list(edge) for edge in dependencies],
        "diagnostics": list(diagnostics),
        "complete": complete,
        "source_evidence": {
            "cpu": list(cpu_source_paths),
            "components": [
                {"component_id": component_id, "source_paths": list(paths)}
                for component_id, paths in component_source_paths
            ],
        },
    }


def _make_plan(
    cpu: CpuProfile,
    components: tuple[Mapping[str, object], ...],
    dependencies: tuple[tuple[str, str], ...],
    diagnostics: list[str],
    *,
    source_root: Path | None = None,
    cpu_source_paths: tuple[str, ...] = (),
    component_source_paths: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> AutoCompositionPlan:
    unique_diagnostics = tuple(dict.fromkeys(diagnostics))
    complete = not unique_diagnostics and bool(components)
    hash_document = _plan_hash_document(
        cpu,
        components,
        dependencies,
        unique_diagnostics,
        complete,
        cpu_source_paths,
        component_source_paths,
    )
    return AutoCompositionPlan(
        cpu=cpu,
        components=components,
        dependencies=dependencies,
        diagnostics=unique_diagnostics,
        complete=complete,
        content_hash=content_hash(hash_document),
        _cpu_source_paths=cpu_source_paths,
        _component_source_paths=component_source_paths,
        _source_root=None if source_root is None else str(source_root.resolve()),
    )


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _manifest_size_is_publishable(component_type: object, size: object) -> bool:
    if not isinstance(component_type, str) or not _integer(size):
        return False
    if size not in _MANIFEST_SIZES:
        return False
    if component_type == "ram":
        return size == 0x10000
    return size == 0x1000


def _relative_source(root: Path, source_path: object) -> tuple[bool, str]:
    if not isinstance(source_path, str) or not source_path:
        return False, "invalid-source-path"
    posix = PurePosixPath(source_path)
    windows = PureWindowsPath(source_path)
    if (
        "\x00" in source_path
        or posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or "\\" in source_path
        or any(part in {"", ".", ".."} for part in source_path.split("/"))
    ):
        return False, source_path
    root_resolved = root.resolve()
    candidate = (root / source_path).resolve(strict=False)
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return False, source_path
    return candidate.is_file(), source_path


def _safe_source_evidence_path(source_path: object) -> bool:
    """Validate the path form retained in a plan without resolving it."""
    if not isinstance(source_path, str) or not source_path or "\x00" in source_path:
        return False
    posix = PurePosixPath(source_path)
    windows = PureWindowsPath(source_path)
    return not (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or "\\" in source_path
        or any(part in {"", ".", ".."} for part in source_path.split("/"))
    )


def _check_sources(root: Path, source_paths: tuple[str, ...], owner: str) -> list[str]:
    diagnostics: list[str] = []
    if not source_paths:
        return [f"{owner}:source:missing"]
    for source_path in source_paths:
        exists, detail = _relative_source(root, source_path)
        if not exists:
            kind = "missing-source" if detail == source_path else "unsafe-source"
            diagnostics.append(f"{owner}:{kind}:{detail}")
    return diagnostics


def _validate_source_evidence(
    source_root: str | None,
    source_paths: tuple[str, ...],
    owner: str,
) -> None:
    """Revalidate retained source evidence immediately before publication."""
    if source_root is None:
        raise AutoCompositionError(f"plan:{owner}:source-root-missing")
    try:
        resolved_root = Path(source_root).resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise AutoCompositionError(f"plan:{owner}:source-root-invalid") from error
    if not resolved_root.is_dir():
        raise AutoCompositionError(f"plan:{owner}:source-root-missing")
    if not source_paths:
        raise AutoCompositionError(f"plan:{owner}:source-evidence-missing")

    for source_path in source_paths:
        if not _safe_source_evidence_path(source_path):
            raise AutoCompositionError(
                f"plan:{owner}:source-evidence-invalid:{source_path}"
            )
        try:
            resolved_source = (resolved_root / source_path).resolve(strict=False)
            resolved_source.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError) as error:
            raise AutoCompositionError(
                f"plan:{owner}:source-evidence-outside-root:{source_path}"
            ) from error
        if not resolved_source.exists():
            raise AutoCompositionError(
                f"plan:{owner}:source-evidence-missing:{source_path}"
            )
        if not resolved_source.is_file():
            raise AutoCompositionError(
                f"plan:{owner}:source-evidence-not-regular-file:{source_path}"
            )


def _parse_preferences(
    preferences: tuple[tuple[str, str], ...],
) -> tuple[tuple[tuple[str, str], ...], list[str]]:
    parsed: list[tuple[str, str]] = []
    diagnostics: list[str] = []
    for index, preference in enumerate(preferences):
        if (
            not isinstance(preference, tuple)
            or len(preference) != 2
            or not all(isinstance(item, str) and item for item in preference)
        ):
            diagnostics.append(f"protocol-preferences:invalid:{index}")
            continue
        if preference in parsed:
            diagnostics.append(
                f"protocol-preferences:duplicate:{preference[0]}@{preference[1]}"
            )
            continue
        parsed.append(preference)
    return tuple(parsed), diagnostics


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _default_parameters(profile: PeripheralProfile) -> dict[str, int]:
    limits = profile.parameter_limits
    parameters: dict[str, int] = {}
    for name, bounds in sorted(limits.items()):
        lower, upper = bounds
        if name == "WORDS":
            value = min(max(4096, lower), upper)
        else:
            value = lower
        parameters[name] = value
    return parameters


def _dependency_cycle(
    selected: Mapping[str, PeripheralProfile],
) -> tuple[str, ...] | None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(component_type: str, trail: tuple[str, ...]) -> tuple[str, ...] | None:
        if component_type in visiting:
            return trail + (component_type,)
        if component_type in visited:
            return None
        visiting.add(component_type)
        profile = selected[component_type]
        for dependency in profile.requires:
            if dependency not in selected:
                continue
            result = visit(dependency, trail + (component_type,))
            if result is not None:
                return result
        visiting.remove(component_type)
        visited.add(component_type)
        return None

    for component_type in sorted(selected):
        result = visit(component_type, ())
        if result is not None:
            return result
    return None


def plan_auto_composition(
    request: AutoCompositionRequest,
    *,
    cpu_catalog: CpuCatalog | None = None,
    component_catalog: ComponentCatalog | None = None,
    root: Path,
) -> AutoCompositionPlan:
    """Plan a closed CPU/peripheral composition without materializing files."""
    if not isinstance(request, AutoCompositionRequest):
        raise AutoCompositionError("request:type")
    try:
        checkout_root = Path(root)
    except (TypeError, ValueError) as error:
        raise AutoCompositionError("repository root:type") from error
    if not checkout_root.is_dir():
        raise AutoCompositionError(f"repository root does not exist: {checkout_root}")
    selected_cpu_catalog = cpu_catalog or load_builtin_cpu_catalog(root=checkout_root)
    selected_component_catalog = component_catalog or load_builtin_component_catalog()
    try:
        cpu = selected_cpu_catalog.require(request.cpu_id)
    except CpuDefinitionError:
        raise

    diagnostics: list[str] = []
    cpu_source_paths = tuple(cpu.source_paths)
    if cpu.source_status != "implemented" or not cpu.implemented:
        source_diagnostics = _check_sources(checkout_root, cpu_source_paths, "cpu")
        diagnostics.extend(source_diagnostics or ["cpu:unavailable-source"])
    else:
        diagnostics.extend(_check_sources(checkout_root, cpu_source_paths, "cpu"))

    if not request.component_types:
        diagnostics.append("components:empty")
    component_types = tuple(request.component_types)
    invalid_types = [
        str(value)
        for value in component_types
        if not isinstance(value, str) or not value
    ]
    if invalid_types:
        diagnostics.append("components:invalid-type")
    string_component_types = tuple(
        component_type for component_type in component_types if isinstance(component_type, str)
    )
    duplicates = sorted(
        component_type
        for component_type in set(string_component_types)
        if string_component_types.count(component_type) > 1
    )
    diagnostics.extend(f"components:duplicate:{component_type}" for component_type in duplicates)

    if not _integer(request.address_width) or request.address_width <= 0:
        diagnostics.append("width:address:invalid")
    elif request.address_width != 32:
        diagnostics.append(f"width:address:unsupported:{request.address_width}")
    if not _integer(request.data_width) or request.data_width <= 0:
        diagnostics.append("width:data:invalid")
    elif request.data_width != 32:
        diagnostics.append(f"width:data:unsupported:{request.data_width}")
    if _integer(request.data_width) and request.data_width not in cpu.xlen:
        diagnostics.append(f"width:data:cpu-mismatch:{request.data_width}")

    preferences, preference_diagnostics = _parse_preferences(request.protocol_preferences)
    diagnostics.extend(preference_diagnostics)
    if not preferences:
        diagnostics.append("protocol-preferences:missing")

    if not _integer(request.base_address) or request.base_address < 0:
        diagnostics.append("address:base:invalid")
    if not _integer(request.window_size) or request.window_size <= 0:
        diagnostics.append("address:window:invalid")
    elif request.window_size % 0x1000:
        diagnostics.append("address:window:not-4k-aligned")
    if (
        _integer(request.base_address)
        and _integer(request.window_size)
        and request.base_address >= 0
        and request.window_size > 0
        and request.base_address % 0x1000
    ):
        diagnostics.append("address:base:not-4k-aligned")
    if (
        not _integer(request.irq_start)
        or not _IBEX_EXTERNAL_IRQ_MIN <= request.irq_start <= _IBEX_EXTERNAL_IRQ_MAX
    ):
        diagnostics.append("irq:start:out-of-range")

    try:
        cpu_runtime_protocols = set(
            selected_cpu_catalog.compatible_protocols(request.cpu_id, runtime_only=True)
        )
    except CpuDefinitionError:
        raise
    cpu_integration_protocols = set(cpu.integration_protocols)
    if not cpu_runtime_protocols:
        diagnostics.append("cpu:unsupported-runtime-contract")

    if diagnostics:
        return _make_plan(
            cpu,
            (),
            (),
            diagnostics,
            source_root=checkout_root,
            cpu_source_paths=cpu_source_paths,
        )

    selected_profiles: dict[str, PeripheralProfile] = {}
    selected_protocols: dict[str, tuple[str, str]] = {}
    selection_diagnostics: list[str] = []
    for component_type in sorted(component_types):
        try:
            selected_component_catalog.require(component_type)
        except ComponentDefinitionError:
            selection_diagnostics.append(f"component:{component_type}:unknown")
            continue

        candidate_errors: list[str] = []
        for preference in preferences:
            if preference not in _RUNTIME_ADAPTERS:
                candidate_errors.append(
                    f"unsupported-runtime-adapter:{preference[0]}@{preference[1]}"
                )
                continue
            if preference not in cpu_runtime_protocols:
                candidate_errors.append(
                    f"unsupported-cpu-protocol:{preference[0]}@{preference[1]}"
                )
                continue
            if preference not in cpu_integration_protocols:
                candidate_errors.append(
                    f"unsupported-cpu-integration:{preference[0]}@{preference[1]}"
                )
                continue
            try:
                available_profile = selected_component_catalog.available(
                    component_type,
                    root=checkout_root,
                    protocol=preference,
                )
            except ComponentDefinitionError as error:
                message = str(error)
                if "reference-only" in message:
                    candidate_errors.append("reference-only")
                elif "missing component source" in message:
                    candidate_errors.append("missing-source")
                else:
                    candidate_errors.append(message)
                continue
            selected_profiles[component_type] = available_profile
            selected_protocols[component_type] = preference
            break
        else:
            selection_diagnostics.append(
                f"component:{component_type}:no-compatible-runtime-protocol"
            )
            selection_diagnostics.extend(
                f"component:{component_type}:{reason}"
                for reason in dict.fromkeys(candidate_errors)
                if reason in {"reference-only", "missing-source"}
            )

    if selection_diagnostics:
        return _make_plan(
            cpu,
            (),
            (),
            selection_diagnostics,
            source_root=checkout_root,
            cpu_source_paths=cpu_source_paths,
        )

    dependencies: list[tuple[str, str]] = []
    dependency_diagnostics: list[str] = []
    for component_type in sorted(selected_profiles):
        profile = selected_profiles[component_type]
        for dependency in sorted(profile.requires):
            if dependency not in selected_profiles:
                dependency_diagnostics.append(
                    f"dependency:{component_type}0:missing:{dependency}0"
                )
            else:
                dependencies.append((f"{component_type}0", f"{dependency}0"))
    cycle = _dependency_cycle(selected_profiles)
    if cycle is not None:
        dependency_diagnostics.append(f"dependency:cycle:{'->'.join(cycle)}")
    if dependency_diagnostics:
        return _make_plan(
            cpu,
            (),
            tuple(sorted(set(dependencies))),
            dependency_diagnostics,
            source_root=checkout_root,
            cpu_source_paths=cpu_source_paths,
        )

    components: list[Mapping[str, object]] = []
    component_source_paths: list[tuple[str, tuple[str, ...]]] = []
    address = request.base_address
    next_irq = request.irq_start
    address_diagnostics: list[str] = []
    for component_type in sorted(selected_profiles):
        profile = selected_profiles[component_type]
        alignment = max(0x1000, profile.address_alignment)
        size = max(request.window_size, profile.default_size)
        if request.window_size % profile.address_alignment:
            address_diagnostics.append(
                f"address:{component_type}0:window-not-aligned:{profile.address_alignment}"
            )
        if size % profile.address_alignment:
            address_diagnostics.append(f"address:{component_type}0:size-not-aligned")
        if (
            component_type in _MANIFEST_COMPONENT_TYPES
            and not _manifest_size_is_publishable(component_type, size)
        ):
            address_diagnostics.append(
                f"manifest-size:{component_type}0:unsupported:{size}"
            )
        base = _align_up(address, alignment)
        if base + size > (1 << request.address_width):
            address_diagnostics.append(f"address:{component_type}0:outside-width")
        irq: int | None = None
        if profile.irq_capable:
            if next_irq > _IBEX_EXTERNAL_IRQ_MAX:
                address_diagnostics.append(f"irq:{component_type}0:out-of-range")
            else:
                irq = next_irq
                next_irq += 1
        components.append(
            {
                "component_id": f"{component_type}0",
                "component_type": component_type,
                "protocol": {
                    "id": selected_protocols[component_type][0],
                    "version": selected_protocols[component_type][1],
                },
                "base": base,
                "size": size,
                "irq": irq,
                "parameters": _default_parameters(profile),
                "external_input": profile.irq_capable,
            }
        )
        component_source_paths.append((f"{component_type}0", tuple(profile.source_paths)))
        address = base + size

    if address_diagnostics:
        return _make_plan(
            cpu,
            (),
            tuple(sorted(set(dependencies))),
            address_diagnostics,
            source_root=checkout_root,
            cpu_source_paths=cpu_source_paths,
        )

    return _make_plan(
        cpu,
        tuple(components),
        tuple(sorted(set(dependencies))),
        [],
        source_root=checkout_root,
        cpu_source_paths=cpu_source_paths,
        component_source_paths=tuple(component_source_paths),
    )


def _manifest_component(component: Mapping[str, object], index: int) -> dict[str, object]:
    required = {
        "component_id",
        "component_type",
        "protocol",
        "base",
        "size",
        "irq",
        "parameters",
        "external_input",
    }
    if set(component) != required:
        raise AutoCompositionError(f"manifest:component[{index}]:fields")
    component_id = component["component_id"]
    component_type = component["component_type"]
    if not isinstance(component_type, str) or component_type not in _MANIFEST_COMPONENT_TYPES:
        raise AutoCompositionError(f"manifest:component[{index}]:type")
    if not isinstance(component_id, str) or component_id != f"{component_type}0":
        raise AutoCompositionError(f"manifest:component[{index}]:id")
    protocol = component["protocol"]
    if not isinstance(protocol, Mapping) or set(protocol) != {"id", "version"}:
        raise AutoCompositionError(f"manifest:component[{index}]:protocol")
    protocol_id = protocol["id"]
    protocol_version = protocol["version"]
    if (
        not isinstance(protocol_id, str)
        or not isinstance(protocol_version, str)
        or (protocol_id, protocol_version) not in _RUNTIME_ADAPTERS
    ):
        raise AutoCompositionError(f"manifest:component[{index}]:adapter")
    base = component["base"]
    size = component["size"]
    if (
        not _integer(base)
        or base < 0
        or base % 0x1000
        or not _integer(size)
        or not _manifest_size_is_publishable(component_type, size)
        or base + size > (1 << 32)
    ):
        raise AutoCompositionError(f"manifest:component[{index}]:address")
    irq = component["irq"]
    if irq is not None and (
        not _integer(irq)
        or not _IBEX_EXTERNAL_IRQ_MIN <= irq <= _IBEX_EXTERNAL_IRQ_MAX
    ):
        raise AutoCompositionError(f"manifest:component[{index}]:irq")
    parameters = component["parameters"]
    if not isinstance(parameters, Mapping) or any(
        not isinstance(name, str) or not name or not _integer(value)
        for name, value in parameters.items()
    ):
        raise AutoCompositionError(f"manifest:component[{index}]:parameters")
    external_input = component["external_input"]
    if not isinstance(external_input, bool):
        raise AutoCompositionError(f"manifest:component[{index}]:external-input")
    return {
        "component_id": component_id,
        "component_type": component_type,
        "protocol": {"id": protocol_id, "version": protocol_version},
        "base": base,
        "size": size,
        "irq": irq,
        "parameters": dict(sorted(parameters.items())),
        "external_input": external_input,
    }


def _manifest_document(plan: AutoCompositionPlan) -> dict[str, object]:
    if not isinstance(plan, AutoCompositionPlan):
        raise AutoCompositionError("plan:type")
    if not plan.complete:
        raise AutoCompositionError("plan:incomplete")
    if plan.cpu.source_status != "implemented" or not plan.cpu.implemented:
        raise AutoCompositionError("plan:cpu-source-unavailable")
    if not plan._cpu_source_paths:
        raise AutoCompositionError("plan:cpu-source-evidence-missing")
    if any(
        not _safe_source_evidence_path(source_path)
        for source_path in plan._cpu_source_paths
    ):
        raise AutoCompositionError("plan:cpu-source-evidence-invalid")
    _validate_source_evidence(plan._source_root, plan._cpu_source_paths, "cpu")
    records = tuple(
        _manifest_component(component, index)
        for index, component in enumerate(plan.components)
        if isinstance(component, Mapping)
    )
    if len(records) != len(plan.components) or not records:
        raise AutoCompositionError("manifest:components")
    component_ids = [str(record["component_id"]) for record in records]
    if len(component_ids) != len(set(component_ids)):
        raise AutoCompositionError("manifest:components:duplicate-id")
    regions: list[tuple[int, int, str]] = []
    for record in records:
        start = int(record["base"])
        end = start + int(record["size"])
        for existing_start, existing_end, existing_id in regions:
            if start < existing_end and existing_start < end:
                raise AutoCompositionError(
                    f"manifest:components:overlap:{record['component_id']}:{existing_id}"
                )
        regions.append((start, end, str(record["component_id"])))
    evidence = dict(plan._component_source_paths)
    if set(evidence) != set(component_ids):
        raise AutoCompositionError("plan:component-source-evidence-missing")
    for component_id, source_paths in evidence.items():
        if not source_paths or any(not _safe_source_evidence_path(path) for path in source_paths):
            raise AutoCompositionError(f"plan:{component_id}:source-evidence-invalid")
        _validate_source_evidence(plan._source_root, source_paths, component_id)
    irq_values = [record["irq"] for record in records if record["irq"] is not None]
    if len(irq_values) != len(set(irq_values)):
        raise AutoCompositionError("manifest:components:duplicate-irq")
    return {
        "schema_version": "protocol_composition.v1",
        "target": {
            "kind": "ibex_core",
            "base_config": "ibex_multicomponent_ip",
            "address_width": 32,
            "data_width": 32,
        },
        "components": sorted(records, key=lambda item: str(item["component_id"])),
        "runtime": {
            "seed": _DEFAULT_SEED,
            "duration_seconds": _DEFAULT_DURATION_SECONDS,
            "checkpoint_seconds": _DEFAULT_CHECKPOINT_SECONDS,
        },
    }


def write_auto_composition_manifest(plan: AutoCompositionPlan, path: Path) -> None:
    """Atomically publish one strict protocol-composition manifest."""
    document = _manifest_document(plan)
    destination = Path(path)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(document)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def _generic_source_path(base_dir: Path, source_path: str) -> Path:
    """Resolve one evidence path without allowing it to escape *base_dir*."""
    if not _safe_source_evidence_path(source_path):
        raise AutoCompositionError(f"generic:source-path:invalid:{source_path}")
    root = base_dir.resolve()
    candidate = (root / source_path).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise AutoCompositionError(f"generic:source-path:outside-base:{source_path}") from error
    if not candidate.is_file():
        raise AutoCompositionError(f"generic:source-path:missing:{source_path}")
    return candidate


def _generic_capability_document(capability: EndpointCapability) -> dict[str, object]:
    return {
        "endpoint_id": capability.endpoint_id,
        "function": capability.function,
        "side": capability.side,
        "protocol": None if capability.protocol is None else list(capability.protocol),
        "clock": capability.clock,
        "reset": capability.reset,
        "fields": [
            {
                "role": field.role,
                "port": field.port,
                "direction": field.direction,
                "width": field.width,
                "signed": field.signed,
                "source": None if field.source is None else {
                    "file_id": canonical_id("generic-source-file", field.source.file),
                    "line": field.source.line,
                    "column": field.source.column,
                },
                "evidence": list(field.evidence),
            }
            for field in capability.fields
        ],
        "evidence": list(capability.evidence),
    }


def _generic_ir_evidence(value: object) -> object:
    """Keep evidence in IR without embedding checkout-relative path spellings."""
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if key == "source" and isinstance(item, Mapping) and isinstance(item.get("file"), str):
                result[str(key)] = {
                    "file_id": canonical_id("generic-source-file", item["file"]),
                    "line": item.get("line"),
                    "column": item.get("column"),
                }
            elif key == "source_files" and isinstance(item, (tuple, list)):
                result[str(key)] = [canonical_id("generic-source-file", source) for source in item]
            else:
                result[str(key)] = _generic_ir_evidence(item)
        return result
    if isinstance(value, (tuple, list)):
        return [_generic_ir_evidence(item) for item in value]
    return value


def _generic_target_capability(
    component_type: str,
    protocol: tuple[str, str],
    source: EndpointCapability,
) -> EndpointCapability:
    """Use a checked source endpoint as a physical compatibility contract.

    Current component profiles declare protocol support but not a separate
    source-pinned component interface.  Mirroring the physical contract here
    is deliberately only a planner proof; rendering still exposes the source
    CPU ports rather than guessing peripheral port names.
    """
    reverse = {"input": "output", "output": "input"}
    if any(field.direction not in reverse for field in source.fields):
        raise AutoCompositionError(f"generic:component:{component_type}:inout-unsupported")
    return EndpointCapability(
        endpoint_id=f"component.{component_type}",
        function="protocol_target",
        side="target",
        protocol=protocol,
        fields=tuple(
            EndpointFieldFact(
                role=field.role,
                port=field.port,
                direction=reverse[field.direction],
                width=field.width,
                signed=field.signed,
                source=field.source,
                evidence=("profile_protocol_contract",),
            )
            for field in source.fields
        ),
        clock=source.clock,
        reset=source.reset,
        timing=source.timing,
        evidence=("profile_protocol_contract",),
    )


def _generic_compiled_protocols(
    source: EndpointCapability,
    target: EndpointCapability,
    catalog: ProtocolCatalog,
) -> dict[str, CompiledProtocol]:
    if source.protocol is None or target.protocol is None:
        raise AutoCompositionError("generic:protocol:ambiguous")
    plugin = catalog.require(*source.protocol)
    fields = {field.role: field for field in source.fields}
    target_fields = {field.role: field for field in target.fields}
    compiled: dict[str, CompiledProtocol] = {}
    for endpoint, records in ((source, fields), (target, target_fields)):
        compiled[endpoint.endpoint_id] = CompiledProtocol(
            endpoint.endpoint_id,
            source.protocol[0],
            source.protocol[1],
            tuple(
                CompiledField(spec.field_id, spec.direction, records[spec.field_id].width,
                              records[spec.field_id].port, spec.reset_value)
                for spec in plugin.fields
                if spec.field_id in records
            ),
        )
    return compiled


def _generic_dependencies(profiles: Mapping[str, PeripheralProfile]) -> tuple[tuple[str, str], ...]:
    edges: list[tuple[str, str]] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(component_type: str, trail: tuple[str, ...]) -> None:
        if component_type in visiting:
            raise AutoCompositionError("generic:dependency-cycle:" + "->".join((*trail, component_type)))
        if component_type in visited:
            return
        visiting.add(component_type)
        for dependency in sorted(profiles[component_type].requires):
            if dependency not in profiles:
                raise AutoCompositionError(f"generic:dependency:{component_type}:missing:{dependency}")
            edges.append((component_type, dependency))
            visit(dependency, (*trail, component_type))
        visiting.remove(component_type)
        visited.add(component_type)

    for component_type in sorted(profiles):
        visit(component_type, ())
    return tuple(sorted(set(edges)))


def _generic_address_width(capabilities: tuple[EndpointCapability, ...]) -> int:
    widths = {
        field.width
        for endpoint in capabilities
        for field in endpoint.fields
        if field.role in {"address", "addr"}
    }
    if len(widths) != 1:
        raise AutoCompositionError("generic:address-width:ambiguous")
    return widths.pop()


def _generic_irq_capacity(capabilities: tuple[EndpointCapability, ...]) -> int:
    """Return source-proven interrupt inputs available to selected devices."""
    return sum(
        field.width
        for endpoint in capabilities
        for field in endpoint.fields
        if endpoint.side == "initiator"
        and field.direction == "input"
        and field.role in {"irq", "interrupt", "interrupts"}
    )


def plan_generic_composition(
    request: GenericCompositionRequest,
    *,
    base_dir: Path,
    component_catalog: ComponentCatalog | None = None,
    protocol_catalog: ProtocolCatalog | None = None,
) -> GenericCompositionPlan:
    """Validate a source-backed composition before any file is published."""
    if not isinstance(request, GenericCompositionRequest):
        raise AutoCompositionError("generic:request:type")
    root = Path(base_dir)
    if not root.is_dir():
        raise AutoCompositionError("generic:base-dir:missing")
    selected_protocol_catalog = protocol_catalog
    if selected_protocol_catalog is None and any(endpoint.protocol for endpoint in request.interface_description.endpoints):
        # The built-in catalog is data, not a CPU or renderer selection table.
        from myfuzz.protocols.catalog import _builtin_catalog
        selected_protocol_catalog = _builtin_catalog()
    annotations = annotate_interfaces(
        request.interface_description,
        base_dir=root,
        protocol_catalog=selected_protocol_catalog,
    )
    capabilities = normalize_annotations(annotations, protocol_catalog=selected_protocol_catalog)
    if not capabilities:
        raise AutoCompositionError("generic:annotations:empty")
    layout = build_input_layout(annotations, isa=request.isa)

    source_prefix = request.interface_description.source.source_root.rstrip("/")
    source_files = tuple(
        sorted(
            f"{source_prefix}/{source_file}" if source_prefix else source_file
            for source_file in annotations["source"]["files"]  # type: ignore[index]
        )
    )
    for source_file in source_files:
        _generic_source_path(root, source_file)

    profiles: dict[str, PeripheralProfile] = {}
    component_records: list[dict[str, object]] = []
    matches: list[Mapping[str, object]] = []
    diagnostics: list[str] = []
    catalog = component_catalog or load_builtin_component_catalog()
    if request.component_types:
        address_width = _generic_address_width(capabilities)
        address = 0
        irq = 0
        for component_type in sorted(request.component_types):
            try:
                profile = catalog.require(component_type)
            except ComponentDefinitionError as error:
                raise AutoCompositionError(f"generic:component:{component_type}:unknown") from error
            if not profile.implemented or profile.source_status != "implemented":
                raise AutoCompositionError(f"generic:component:{component_type}:unavailable")
            for source_file in profile.source_paths:
                _generic_source_path(root, source_file)
            candidates = tuple(
                pair for pair in profile.protocols
                if not request.protocol_preferences or pair in request.protocol_preferences
            )
            if not candidates:
                raise AutoCompositionError(f"generic:component:{component_type}:protocol-preference")
            accepted: tuple[EndpointCapability, tuple[str, str], Mapping[str, object]] | None = None
            for protocol in sorted(candidates):
                sources = tuple(
                    endpoint for endpoint in capabilities
                    if endpoint.side == "initiator" and endpoint.protocol == protocol
                )
                if not sources:
                    diagnostics.append(f"rejected:{component_type}:{protocol[0]}@{protocol[1]}:no-source-endpoint")
                    continue
                for source in sources:
                    target = _generic_target_capability(component_type, protocol, source)
                    alternatives = match_endpoint_pair(
                        source,
                        target,
                        (),
                        protocol_catalog=selected_protocol_catalog,
                        compiled_protocols=_generic_compiled_protocols(source, target, selected_protocol_catalog),
                    )
                    matches.extend(alternatives)
                    selected = next((item for item in alternatives if item["accepted"]), None)
                    if selected is None:
                        diagnostics.extend(
                            f"rejected:{component_type}:{protocol[0]}@{protocol[1]}:{reason}"
                            for item in alternatives for reason in item["reasons"]  # type: ignore[index]
                        )
                        continue
                    accepted = (source, protocol, selected)
                    break
                if accepted is not None:
                    break
            if accepted is None:
                raise AutoCompositionError(f"generic:component:{component_type}:no-compatible-endpoint")
            alignment = profile.address_alignment
            if alignment <= 0 or alignment & (alignment - 1):
                raise AutoCompositionError(f"generic:component:{component_type}:invalid-alignment")
            size = profile.default_size
            if size <= 0 or size % alignment:
                raise AutoCompositionError(f"generic:component:{component_type}:invalid-size")
            base = _align_up(address, alignment)
            if base + size > 1 << address_width:
                raise AutoCompositionError(f"generic:component:{component_type}:address-outside-width")
            component_id = f"{component_type}0"
            if profile.irq_capable and irq >= _generic_irq_capacity(capabilities):
                raise AutoCompositionError(
                    f"generic:component:{component_type}:irq-endpoint-unavailable"
                )
            component_records.append({
                "component_id": component_id,
                "component_type": component_type,
                "module_name": profile.module_name,
                "protocol": {"id": accepted[1][0], "version": accepted[1][1]},
                "base": base,
                "size": size,
                "irq": irq if profile.irq_capable else None,
                "parameters": _default_parameters(profile),
                "source_files": list(profile.source_paths),
                "selected_endpoint": accepted[0].endpoint_id,
            })
            if profile.irq_capable:
                irq += 1
            address = base + size
            profiles[component_type] = profile
            source_files = tuple(sorted(set((*source_files, *profile.source_paths))))
        dependencies = _generic_dependencies(profiles)
    else:
        dependencies = ()

    annotation_hash = content_hash(annotations)
    ir = canonical_ir_document({
        "schema_version": "composition_ir.v1",
        "composition_kind": "generic_composition",
        "target": {"top_module": "generic_composition_top", "source_top_module": request.interface_description.source.top_module},
        "interface_annotation_hash": annotation_hash,
        "capabilities": [_generic_capability_document(item) for item in capabilities],
        "components": sorted(component_records, key=lambda item: str(item["component_id"])),
        "dependencies": [list(item) for item in dependencies],
        "runtime": {"seed": request.seed},
        "match_alternatives": _generic_ir_evidence(matches),
        "input_layout": {
            "schema_version": layout.schema_version,
            "raw_width": layout.raw_width,
            "layout_hash": layout.layout_hash,
            "fields": [
                {key: value for key, value in field.items() if key != "provenance"}
                for field in input_layout_document(layout)["fields"]
            ],
        },
        "source_file_ids": [canonical_id("generic-source-file", item) for item in source_files],
        "diagnostics": {"errors": [], "warnings": sorted(set(diagnostics))},
    })
    return GenericCompositionPlan(
        interface_description=request.interface_description,
        annotations=annotations,
        capabilities=capabilities,
        components=tuple(component_records),
        matches=tuple(matches),
        diagnostics=tuple(sorted(set(diagnostics))),
        layout=layout,
        ir=ir,
        interface_annotation_hash=annotation_hash,
        composition_ir_hash=canonical_ir_hash(ir),
        source_files=source_files,
    )


__all__ = [
    "AutoCompositionError",
    "AutoCompositionPlan",
    "AutoCompositionRequest",
    "GenericCompositionPlan",
    "GenericCompositionRequest",
    "plan_auto_composition",
    "plan_generic_composition",
    "write_auto_composition_manifest",
]
