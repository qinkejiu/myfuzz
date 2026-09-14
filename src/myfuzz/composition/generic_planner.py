"""Generic multi-component planning extracted from auto.py (P2).

This module owns the generic composition request/plan types and the generic
planner. auto.py re-imports every name below so the historical entry points
keep their original names and behaviour. Behaviour, hashes and target
selection are unchanged by the extraction.
"""
from __future__ import annotations
import ast
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import MappingProxyType
from myfuzz.components import (
    ComponentCatalog,
    ComponentDefinitionError,
    PeripheralProfile,
    load_builtin_component_catalog,
)
from myfuzz.contracts import content_hash
from myfuzz.isa.constraints import IsaContract
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import CompiledField, CompiledProtocol
from myfuzz.scripts.source_only_frontend import HDL_SUFFIXES, mask_comments_and_strings
from .endpoint_capabilities import (
    EndpointCapability,
    EndpointFieldFact,
    SourceReference,
    TimingFact,
    match_endpoint_pair,
    normalize_annotations,
)
from .ids import canonical_id
from .input_layout import InputLayout, build_input_layout, input_layout_document
from .interface_description import ElaborationSettings, InterfaceDescription
from .ir import canonical_ir_document, canonical_ir_hash
from .processor_boundary import build_processor_boundary
from .processor_execution import (
    ProcessorExecutionPlan,
    build_processor_execution,
    processor_execution_document,
)
from .source_crawler import annotate_interfaces
from .source_crawler import SourceCrawler, SourceCrawlError, source_tree_hash
from .interface_description import SourceLocator


class AutoCompositionError(ValueError):
    """Raised when an auto-composition request or publication is unsafe."""


_DEFAULT_SEED = 7


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
    processor_execution: ProcessorExecutionPlan | None
    ir: Mapping[str, object]
    interface_annotation_hash: str
    composition_ir_hash: str
    source_files: tuple[str, ...]
    source_include_roots: tuple[str, ...]
    source_defines: tuple[str, ...]
    source_evidence_hash: str
    request: GenericCompositionRequest
    component_catalog: ComponentCatalog
    protocol_catalog: ProtocolCatalog | None
    complete: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "annotations", _freeze_nested(self.annotations))
        object.__setattr__(self, "components", tuple(_freeze_nested(item) for item in self.components))
        object.__setattr__(self, "matches", tuple(_freeze_nested(item) for item in self.matches))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "ir", _freeze_nested(self.ir))
        object.__setattr__(self, "source_files", tuple(self.source_files))
        object.__setattr__(self, "source_include_roots", tuple(self.source_include_roots))
        object.__setattr__(self, "source_defines", tuple(self.source_defines))


def _freeze_nested(value: object) -> object:
    """Copy mappings/sequences into recursively immutable equivalents."""
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_nested(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_nested(item) for item in value)
    return value


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


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


@dataclass(frozen=True, slots=True)
class _GenericSourceListMetadata:
    """Normalized filelist context, preserving frontend declaration order."""

    include_roots: tuple[str, ...]
    defines: tuple[str, ...]
    filelists: tuple[str, ...]
    sources: tuple[str, ...]


def _generic_source_list_metadata(root: Path, locator: SourceLocator) -> _GenericSourceListMetadata:
    """Normalize source-list context without changing ordered frontend semantics.

    Include roots use first-declaration-wins de-duplication because repeated
    roots have no useful frontend effect. Macro definitions are deliberately
    not de-duplicated: a repeated definition is observable to the HDL frontend,
    so preserving filelist order is the only safe behavior.
    """
    source_root = (root.resolve() / locator.source_root).resolve()
    try:
        source_root.relative_to(root.resolve())
    except ValueError as error:
        raise AutoCompositionError("generic:source-root:outside-base") from error
    if not source_root.is_dir() or source_root.is_symlink():
        raise AutoCompositionError("generic:source-root:invalid")
    includes: list[Path] = []
    include_seen: set[Path] = set()
    defines: list[str] = []
    filelists: list[Path] = []
    sources: list[Path] = []
    source_seen: set[Path] = set()
    variables = dict(locator.filelist_variables)
    root_marker = "__MYFUZZ_SOURCE_ROOT__/"

    def child(parent: Path, raw: str) -> Path:
        if raw.startswith(root_marker):
            parent = source_root
            raw = raw[len(root_marker):]
        raw_path = Path(raw)
        if not raw or "\\" in raw or raw_path.is_absolute() or ".." in raw_path.parts:
            raise AutoCompositionError("generic:source-list:unsafe-path")
        candidate = (parent / raw_path).resolve()
        try:
            candidate.relative_to(source_root)
        except ValueError as error:
            raise AutoCompositionError("generic:source-list:unsafe-path") from error
        return candidate

    def add_include(parent: Path, raw: str) -> None:
        directory = child(parent, raw)
        if not directory.is_dir() or directory.is_symlink():
            raise AutoCompositionError("generic:source-list:include-root-invalid")
        if directory not in include_seen:
            include_seen.add(directory)
            includes.append(directory)

    def add_define(item: str) -> None:
        payload = item[len("+define+"):]
        if not payload or any(not part for part in payload.split("+")):
            raise AutoCompositionError("generic:source-list:invalid-define")
        defines.append(item)

    def add_source(parent: Path, raw: str) -> None:
        source = child(parent, raw)
        if not source.is_file() or source.is_symlink():
            raise AutoCompositionError("generic:source-list:source-missing")
        if source not in source_seen:
            source_seen.add(source)
            sources.append(source)

    def expand(path: Path, seen: set[Path]) -> None:
        if path in seen:
            return
        if not path.is_file() or path.is_symlink():
            raise AutoCompositionError("generic:source-list:filelist-missing")
        seen.add(path)
        filelists.append(path)
        try:
            text = path.read_text(encoding="utf-8")
            if root_marker in text:
                raise AutoCompositionError("generic:source-list:invalid-filelist-variable")
            text = "\n".join(
                "" if line.lstrip().startswith("//") else line
                for line in text.splitlines()
            )
            def expand_token(token: str) -> str:
                def substitute(match: re.Match[str]) -> str:
                    name = match.group(1)
                    if name not in variables:
                        raise AutoCompositionError("generic:source-list:undefined-filelist-variable")
                    anchored = (
                        match.start() == 0
                        or match.start() == 2 and token.startswith("-I")
                        or token[match.start() - 1] == "+"
                    )
                    return (root_marker if anchored else "") + variables[name]
                expanded = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", substitute, token)
                if "$" in expanded:
                    raise AutoCompositionError("generic:source-list:invalid-filelist-variable")
                return expanded
            tokens = iter(expand_token(token) for token in shlex.split(text, comments=True))
            for item in tokens:
                if item in ("-f", "-F"):
                    expand(child(path.parent if item == "-f" else source_root, next(tokens)), seen)
                elif item.startswith("+incdir+"):
                    for raw in item[len("+incdir+"):].split("+"):
                        add_include(path.parent, raw)
                elif item == "-I" or item.startswith("-I"):
                    add_include(path.parent, next(tokens) if item == "-I" else item[2:])
                elif item.startswith("+define+"):
                    add_define(item)
                elif item.startswith(("-", "+")):
                    raise AutoCompositionError("generic:source-list:unsupported-option")
                else:
                    add_source(path.parent, item)
        except (StopIteration, UnicodeDecodeError, ValueError) as error:
            raise AutoCompositionError("generic:source-list:invalid-filelist") from error

    for raw in locator.include_roots:
        add_include(source_root, raw)
    for raw in locator.files:
        add_source(source_root, raw)
    if locator.filelist is not None:
        expand(child(source_root, locator.filelist), set())
    return _GenericSourceListMetadata(
        include_roots=tuple(item.relative_to(root.resolve()).as_posix() for item in includes),
        defines=tuple(defines),
        filelists=tuple(item.relative_to(root.resolve()).as_posix() for item in filelists),
        sources=tuple(item.relative_to(root.resolve()).as_posix() for item in sources),
    )


def _generic_source_evidence_hash(
    base_dir: Path, source_files: tuple[str, ...], locator: SourceLocator,
) -> str:
    """Pin selected HDL and every declared include-root byte consumed by lint."""
    root = base_dir.resolve()
    paths = {_generic_source_path(root, source_file) for source_file in source_files}
    source_root = (root / locator.source_root).resolve()
    try:
        source_root.relative_to(root)
    except ValueError as error:
        raise AutoCompositionError("generic:source-root:outside-base") from error
    metadata = _generic_source_list_metadata(root, locator)
    for include_root in metadata.include_roots:
        include = (root / include_root).resolve()
        for candidate in include.rglob("*"):
            if candidate.is_symlink():
                raise AutoCompositionError("generic:include-root:symlink")
            if candidate.is_file():
                paths.add(candidate)
    for filelist in metadata.filelists:
        paths.add(_generic_source_path(root, filelist))
    return source_tree_hash(root, tuple(sorted(paths)))


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
                **({"member_path": list(field.member_path), "raw_lo": field.raw_lo,
                    "raw_hi": field.raw_hi, "container_width": field.container_width}
                   if field.member_path else {}),
            }
            for field in capability.fields
        ],
        "evidence": list(capability.evidence),
    }


_PROCESSOR_MEMORY_FUNCTIONS = frozenset({
    "processor_memory_master", "instruction_memory_master", "data_memory_master",
})


def _is_processor_memory_endpoint(
    endpoint: EndpointCapability, *, generic_processor_context: bool,
) -> bool:
    return endpoint.function in _PROCESSOR_MEMORY_FUNCTIONS or (
        endpoint.function == "memory_master"
        and (
            generic_processor_context
            or any(field.role == "instruction_identity" for field in endpoint.fields)
        )
    )


def _processor_source_records(
    root: Path, source_files: tuple[str, ...], annotations: Mapping[str, object],
    *, source_prefix: str,
) -> tuple[dict[str, int], list[int]]:
    """Identify all processor evidence files by normalized content, never path."""
    replacements: dict[str, str] = {}
    endpoints = annotations.get("endpoints", ())
    if isinstance(endpoints, (tuple, list)):
        for endpoint in endpoints:
            if not isinstance(endpoint, Mapping):
                continue
            module = endpoint.get("module")
            if isinstance(module, str):
                replacements[module] = "semantic_source_module"
            function = endpoint.get("function")
            fields = endpoint.get("fields", ())
            if isinstance(function, str) and isinstance(fields, (tuple, list)):
                for field in fields:
                    if not isinstance(field, Mapping):
                        continue
                    port, role = field.get("port"), field.get("role")
                    if isinstance(port, str) and isinstance(role, str):
                        replacements[port] = f"semantic_port_{function}_{role}"
    by_path: dict[str, int] = {}
    ids: list[int] = []
    source = annotations.get("source")
    declared_files = source.get("files", ()) if isinstance(source, Mapping) else ()
    # The verified closure includes package/header evidence that must have IDs
    # without being emitted as independent compilation units in sources.f.
    closure = tuple(
        f"{source_prefix}/{item}" if source_prefix else item
        for item in declared_files
    )
    for source_file in dict.fromkeys((*source_files, *closure)):
        path = _generic_source_path(root, source_file)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Include-root closure also binds non-HDL collateral. Its bytes
            # need provenance, not text normalization or standalone compilation.
            source_content = {"raw_source_hex": path.read_bytes().hex()}
        else:
            for name, replacement in sorted(
                replacements.items(), key=lambda item: (-len(item[0]), item[0])
            ):
                text = re.sub(rf"\b{re.escape(name)}\b", replacement, text)
            source_content = {"normalized_source": text}
        source_id = canonical_id(
            "generic-source-content", content_hash(source_content),
        )
        by_path[source_file] = source_id
        if source_prefix and source_file.startswith(source_prefix.rstrip("/") + "/"):
            by_path[source_file[len(source_prefix.rstrip("/")) + 1:]] = source_id
        ids.append(source_id)
    if isinstance(declared_files, (tuple, list)):
        for declared_file in declared_files:
            if not isinstance(declared_file, str):
                continue
            matches = [
                source_id for path, source_id in by_path.items()
                if path == declared_file or path.endswith("/" + declared_file)
            ]
            if len(set(matches)) == 1:
                by_path[declared_file] = matches[0]
    return by_path, sorted(ids)


def _processor_source_document(
    source: SourceReference | None, source_ids: Mapping[str, int], semantic_location: str,
) -> dict[str, object] | None:
    if source is None:
        return None
    return {
        "file_id": source_ids[source.file],
        "line": source.line,
        "semantic_location": semantic_location,
    }


def _processor_capability_documents(
    capabilities: tuple[EndpointCapability, ...], source_ids: Mapping[str, int],
) -> list[dict[str, object]]:
    clock_ports = {
        field.port: "clock" for endpoint in capabilities if endpoint.function == "clock"
        for field in endpoint.fields if field.role == "clock"
    }
    reset_ports = {
        field.port: "reset" for endpoint in capabilities if endpoint.function == "reset"
        for field in endpoint.fields if field.role == "reset"
    }

    def association(value: str | None, ports: Mapping[str, str]) -> str | None:
        if value is None:
            return None
        return ports.get(value, "unresolved")

    documents = []
    for capability in capabilities:
        documents.append({
            "function": capability.function,
            "side": capability.side,
            "protocol": None if capability.protocol is None else list(capability.protocol),
            "clock": association(capability.clock, clock_ports),
            "reset": association(capability.reset, reset_ports),
            "fields": [{
                "role": field.role,
                "direction": field.direction,
                "width": field.width,
                "signed": field.signed,
                "source": _processor_source_document(
                    field.source, source_ids, f"field:{field.role}",
                ),
                "evidence": list(field.evidence),
                **({
                    "member_role": field.role,
                    "raw_lo": field.raw_lo,
                    "raw_hi": field.raw_hi,
                    "container_width": field.container_width,
                } if field.member_path else {}),
            } for field in capability.fields],
            "timing": [{
                "kind": timing.kind,
                "fields": list(timing.fields),
                "clock": association(timing.clock, clock_ports),
                "max_latency": timing.max_latency,
                "source": _processor_source_document(
                    timing.source, source_ids,
                    f"timing:{timing.kind}:{','.join(timing.fields)}",
                ),
                "evidence": list(timing.evidence),
            } for timing in capability.timing],
            "evidence": list(capability.evidence),
        })
    return sorted(documents, key=lambda item: str(item["function"]))


def _processor_layout_fields(
    layout: InputLayout, capabilities: tuple[EndpointCapability, ...],
    source_ids: Mapping[str, int],
) -> list[dict[str, object]]:
    functions = {endpoint.endpoint_id: endpoint.function for endpoint in capabilities}

    def evidence(value: object) -> object:
        if isinstance(value, Mapping):
            normalized = {}
            for key, item in value.items():
                if key == "file" and isinstance(item, str) and item in source_ids:
                    normalized["file_id"] = source_ids[item]
                else:
                    normalized[str(key)] = evidence(item)
            return normalized
        if isinstance(value, (tuple, list)):
            return [evidence(item) for item in value]
        if isinstance(value, str):
            return functions.get(value, value)
        return value

    result = []
    for field in input_layout_document(layout)["fields"]:
        normalized = dict(field)
        owner = normalized.get("owner")
        function = functions.get(owner, owner)
        role = normalized.get("role")
        normalized["owner"] = function
        normalized["field_id"] = f"{function}:{role}"
        normalized["port"] = f"semantic_port:{function}:{role}"
        binding = normalized.get("binding")
        if isinstance(binding, Mapping):
            normalized["binding"] = {
                **binding, "port": f"semantic_port:{function}:{role}",
            }
        if "member_path" in normalized:
            normalized["member_path"] = [str(role)]
        if "provenance" in normalized:
            provenance = evidence(normalized["provenance"])
            if isinstance(provenance, dict):
                provenance.pop("column", None)
                provenance["semantic_location"] = f"field:{role}"
            normalized["provenance"] = provenance
        result.append(normalized)
    return result


def _generic_ir_evidence(
    value: object, source_ids: Mapping[str, int] | None = None,
) -> object:
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
                result[str(key)] = [
                    source_ids[source] if source_ids is not None and source in source_ids
                    else canonical_id("generic-source-file", source)
                    for source in item
                ]
            elif key == "adapter_sources" and isinstance(item, (tuple, list)):
                result["adapter_source_ids"] = [
                    source_ids[source] if source_ids is not None and source in source_ids
                    else canonical_id("generic-source-file", source)
                    for source in item
                ]
            elif key == "rtl_source" and isinstance(item, str):
                result["rtl_source_id"] = (
                    source_ids[item] if source_ids is not None and item in source_ids
                    else canonical_id("generic-source-file", item)
                )
            else:
                result[str(key)] = _generic_ir_evidence(item, source_ids)
        return result
    if isinstance(value, (tuple, list)):
        return [_generic_ir_evidence(item, source_ids) for item in value]
    return value


def _generic_target_capability(
    profile: PeripheralProfile,
    protocol: tuple[str, str],
    root: Path,
    catalog: ProtocolCatalog,
) -> EndpointCapability:
    """Derive a target binding from actual component source, or fail closed.

    A profile's protocol declaration is selection metadata, not evidence that
    its HDL has compatible pins.  The generic route therefore accepts only
    source ports named by the protocol's stable field IDs (or an eventual
    profile-provided mapping) and records their exact locations in the plan.
    """
    try:
        paths = tuple(_generic_source_path(root, item) for item in profile.source_paths)
        locator = SourceLocator(
            source_root=".",
            revision=source_tree_hash(root, paths),
            top_module=profile.module_name,
            files=profile.source_paths,
        )
        try:
            snapshot = SourceCrawler().crawl(locator, base_dir=root)
        except SourceCrawlError as error:
            # Real protocol bridges commonly use parameterized packed widths
            # (for example ``DATA_WIDTH/8``).  The source-only crawler must
            # remain fail-closed for unresolved component interfaces, but a
            # parameterized dependency can be proven safely by elaborating the
            # selected wrapper top.  Retry only for the narrow parser errors
            # that elaboration resolves; all other source failures propagate.
            if str(error) not in {
                "unsupported-port-width",
                "unsupported-port-type",
                "unsupported-unpacked-port",
            }:
                raise
            locator = replace(
                locator,
                elaboration=ElaborationSettings(
                    frontend="verilator-json",
                    warning_policy="recorded-nonfatal",
                ),
            )
            snapshot = SourceCrawler().crawl(locator, base_dir=root)
    except (SourceCrawlError, OSError, ValueError) as error:
        raise AutoCompositionError(f"generic:component:{profile.component_type}:target-binding:source") from error
    ports = [port for port in snapshot.ports if port.module == profile.module_name]
    if profile.module_name not in snapshot.modules:
        raise AutoCompositionError(f"generic:component:{profile.component_type}:target-binding:module:{profile.module_name}")
    plugin = catalog.require(*protocol)
    by_name: dict[str, object] = {}
    for port in ports:
        if port.name in by_name:
            raise AutoCompositionError(f"generic:component:{profile.component_type}:target-binding:ambiguous-port:{port.name}")
        by_name[port.name] = port
    fields: list[EndpointFieldFact] = []
    for spec in plugin.fields:
        port = by_name.get(spec.field_id)
        if port is None:
            if spec.required:
                raise AutoCompositionError(f"generic:component:{profile.component_type}:target-binding:required-field:{spec.field_id}")
            continue
        expected = "input" if spec.direction == "host_to_device" else "output"
        if port.direction != expected:
            raise AutoCompositionError(f"generic:component:{profile.component_type}:target-binding:direction:{spec.field_id}")
        fields.append(EndpointFieldFact(
            role=spec.field_id, port=port.name, direction=port.direction,
            width=port.width, signed=port.signed,
            source=SourceReference(port.source_file, port.line, port.column),
            evidence=("component_hdl_declaration", "protocol_field_id"),
        ))
    controls: dict[str, str] = {}
    for role in ("clock", "reset"):
        port = by_name.get(role)
        if port is None or getattr(port, "direction", None) != "input":
            raise AutoCompositionError(
                f"generic:component:{profile.component_type}:target-binding:control:{role}"
            )
        controls[role] = getattr(port, "name")
        fields.append(EndpointFieldFact(
            role=role, port=controls[role], direction="input", width=1, signed=False,
            source=SourceReference(port.source_file, port.line, port.column),
            evidence=("component_hdl_declaration", "control_port"),
        ))
    timing = tuple(
        TimingFact(
            observation.kind, observation.fields, observation.clock,
            source=SourceReference(observation.source_file, observation.line),
            evidence=("component_hdl_timing",),
        )
        for observation in snapshot.timing
        if observation.module == profile.module_name
    )
    capability = EndpointCapability(
        endpoint_id=f"component.{profile.component_type}", function="protocol_target",
        side="target", protocol=protocol, fields=tuple(fields), clock=controls["clock"],
        reset=controls["reset"], timing=timing, evidence=("component_profile", "component_hdl"),
    )
    return capability


def _generic_reset_contract(endpoint: EndpointCapability, root: Path) -> dict[str, str]:
    """Prove reset polarity and synchrony from declared pins plus HDL conditionals.

    An edge alone does not establish active polarity.  This deliberately
    recognizes only simple source forms where event control and reset branch
    agree, otherwise generic bridging is rejected before rendering.
    """
    fields = {field.role: field for field in endpoint.fields}
    clock, reset = fields.get("clock"), fields.get("reset")
    if (
        clock is None or reset is None or endpoint.clock != clock.port or endpoint.reset != reset.port
        or clock.direction != "input" or reset.direction != "input" or clock.width != 1 or reset.width != 1
        or clock.source is None or reset.source is None
    ):
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    module = next((item.removeprefix("source_module:") for item in endpoint.evidence if item.startswith("source_module:")), None)
    if module is None or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", module):
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    candidates: set[tuple[str, str]] = set()
    # Packed member declarations may live in packages/headers; reset semantics
    # are established only by the clock/reset pins and their module body.
    source_files = {clock.source.file, reset.source.file}
    for source_file in source_files:
        path = _generic_source_path(root, source_file)
        text = path.read_text(encoding="utf-8")
        masked = mask_comments_and_strings(text)
        modules = []
        for module_match in re.finditer(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b", masked):
            if module_match.group(1) != module:
                continue
            end_match = re.search(r"\bendmodule\b", masked[module_match.end():])
            if end_match is not None:
                modules.append(masked[module_match.start():module_match.end() + end_match.end()])
        if len(modules) != 1:
            raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
        event_re = re.compile(r"always(?:_ff)?\s*@\s*\(([^)]*)\)", re.S)
        for event in event_re.finditer(modules[0]):
            edges = re.findall(r"\b(posedge|negedge)\s+([A-Za-z_][A-Za-z0-9_$]*)", event.group(1))
            if ("posedge", clock.port) not in edges:
                continue
            reset_edges = [edge for edge in edges if edge[1] == reset.port]
            if len(reset_edges) > 1:
                continue
            # ``event`` offsets are relative to the selected module body;
            # consulting the original file here could borrow a conditional
            # from an unrelated module preceding this one.
            body = modules[0][event.end():event.end() + 512]
            conditional = re.match(r"\s*(?:begin\s*)?if\s*\(([^)]*)\)", body, re.S)
            if conditional is None:
                continue
            condition = re.sub(r"\s+", "", conditional.group(1))
            low = {
                f"!{reset.port}", f"~{reset.port}",
                f"{reset.port}==1'b0", f"1'b0=={reset.port}",
            }
            high = {reset.port, f"{reset.port}==1'b1", f"1'b1=={reset.port}"}
            polarity = "active_low" if condition in low else "active_high" if condition in high else None
            if polarity is None:
                continue
            if not reset_edges:
                synchrony = "synchronous"
            elif reset_edges[0][0] == ("negedge" if polarity == "active_low" else "posedge"):
                synchrony = "asynchronous"
            else:
                continue
            candidates.add((polarity, synchrony))
    if len(candidates) != 1:
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    polarity, synchrony = next(iter(candidates))
    return {"polarity": polarity, "synchrony": synchrony}


def _generic_with_reset_contract(endpoint: EndpointCapability, root: Path, module: str) -> EndpointCapability:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", module):
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    endpoint = replace(endpoint, evidence=tuple(sorted(set((*endpoint.evidence, f"source_module:{module}")))))
    contract = _generic_reset_contract(endpoint, root)
    marker = f"reset_contract:{contract['polarity']}:{contract['synchrony']}"
    return replace(endpoint, evidence=tuple(sorted(set((*endpoint.evidence, marker)))))


def _generic_endpoint_reset_contract(endpoint: EndpointCapability) -> dict[str, str]:
    contracts = [item.split(":", 2) for item in endpoint.evidence if item.startswith("reset_contract:")]
    if len(contracts) != 1 or len(contracts[0]) != 3:
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    _, polarity, synchrony = contracts[0]
    if polarity not in {"active_low", "active_high"} or synchrony not in {"synchronous", "asynchronous"}:
        raise AutoCompositionError(f"generic:endpoint:{endpoint.endpoint_id}:reset-semantics")
    return {"polarity": polarity, "synchrony": synchrony}


def _generic_transport_capability(
    endpoint: EndpointCapability, catalog: ProtocolCatalog,
) -> EndpointCapability:
    """Limit generic bridging to declared protocol fields, never port spellings."""
    if endpoint.protocol is None:
        raise AutoCompositionError("generic:protocol:ambiguous")
    roles = {spec.field_id for spec in catalog.require(*endpoint.protocol).fields}
    return EndpointCapability(
        endpoint.endpoint_id, endpoint.function, endpoint.side, endpoint.protocol,
        tuple(field for field in endpoint.fields if field.role in roles), None, None,
        (), endpoint.evidence,
    )


def _generic_adapter_contract(
    protocol: tuple[str, str], catalog: ProtocolCatalog,
) -> dict[str, object]:
    """Declare a source-independent bounded protocol implementation."""
    plugin = catalog.require(*protocol)
    if protocol == ("processor-memory-beat", "1"):
        limits = dict(plugin.capability_limits)
        return {
            "mode": "processor_memory_backend",
            "request_field_id": "req_valid",
            "response_field_id": "rsp_valid",
            "error_field_id": "error",
            "address_field_id": "addr",
            "request_fields": [
                field.field_id for field in plugin.fields
                if field.direction == "host_to_device"
            ],
            "response_fields": [
                field.field_id for field in plugin.fields
                if field.direction == "device_to_host"
            ],
            "max_wait_cycles": int(limits["max_wait_cycles"]),
        }
    from .generic_protocol_routes import native_contract
    try:
        native = native_contract(protocol, plugin)
    except ValueError as error:
        raise AutoCompositionError(f"generic:adapter:{protocol[0]}@{protocol[1]}:{error}") from error
    if native is not None:
        return native
    if protocol[0] in {"axi4", "axi4-lite", "apb", "wishbone", "obi"}:
        raise AutoCompositionError(f"generic:adapter:{protocol[0]}@{protocol[1]}:native-protocol-unsupported")
    limits = dict(plugin.capability_limits)
    relations = plugin.channel_relations
    gates = [
        action for action in plugin.projection_actions
        if action.kind == "gate" and action.category == "protocol_legality"
        and "valid" in action.field_ids and action.max_cycles is not None
        and isinstance(action.max_cycles, int) and not isinstance(action.max_cycles, bool)
        and 1 <= action.max_cycles <= 65_535
    ]
    required_limits = {
        "max_outstanding": 1,
        "bursts": False,
        "ids": False,
        "single_beat_only": True,
        "ordering": "in_order_single_id",
        "completion": "ack_or_err",
    }
    max_wait = limits.get("max_wait_cycles")
    if (
        len(relations) != 1
        or relations[0].kind not in {"request_response_handshake", "single_channel_request_response"}
        or not {"valid", "ready"}.issubset(relations[0].field_ids)
        or any(name not in limits or limits[name] != value for name, value in required_limits.items())
        or isinstance(max_wait, bool) or not isinstance(max_wait, int) or not 1 <= max_wait <= 65_535
        or len(gates) != 1
    ):
        raise AutoCompositionError(
            f"generic:adapter:{protocol[0]}@{protocol[1]}:single-channel-metadata"
        )
    directions = {field.field_id: field.direction for field in plugin.fields}
    required = {"valid": "host_to_device", "ready": "device_to_host", "error": "device_to_host"}
    if any(directions.get(name) != direction for name, direction in required.items()):
        raise AutoCompositionError(
            f"generic:adapter:{protocol[0]}@{protocol[1]}:single-channel-contract"
        )
    address_ids = _generic_address_field_ids(catalog, protocol)
    if len(address_ids) != 1:
        raise AutoCompositionError(
            f"generic:adapter:{protocol[0]}@{protocol[1]}:single-address-contract"
        )
    temporal_bounds = [int(gate.max_cycles) for gate in gates]
    temporal_bounds.extend(
        rule.max_cycles for rule in plugin.temporal_rules
        if rule.antecedent_field_id == "valid" and rule.consequent_field_id == "ready"
        and isinstance(rule.max_cycles, int) and not isinstance(rule.max_cycles, bool) and rule.max_cycles >= 1
    )
    bound = min(*temporal_bounds, max_wait)
    return {
        "mode": "single_target_single_channel",
        "request_field_id": "valid",
        "response_field_id": "ready",
        "error_field_id": "error",
        "address_field_id": address_ids[0],
        "request_fields": [field.field_id for field in plugin.fields if field.direction == "host_to_device"],
        "response_fields": [field.field_id for field in plugin.fields if field.direction == "device_to_host" and field.field_id != "irq"],
        "max_wait_cycles": bound,
    }


def _generic_control_binding(
    source: EndpointCapability, target: EndpointCapability, component_type: str, *,
    source_root: Path, target_root: Path, source_module: str, target_module: str,
) -> dict[str, dict[str, object]]:
    source_fields = {field.role: field for field in source.fields}
    target_fields = {field.role: field for field in target.fields}
    result: dict[str, dict[str, object]] = {}
    for role in ("clock", "reset"):
        source_field, target_field = source_fields.get(role), target_fields.get(role)
        if (
            source_field is None or target_field is None
            or source_field.direction != "input" or target_field.direction != "input"
            or source_field.width != 1 or target_field.width != 1
            or source_field.member_path or target_field.member_path
        ):
            raise AutoCompositionError(
                f"generic:component:{component_type}:control-binding:{role}"
            )
        result[role] = {"source_port": source_field.port, "target_port": target_field.port}
    if (
        source.clock != result["clock"]["source_port"]
        or target.clock != result["clock"]["target_port"]
    ):
        raise AutoCompositionError(
            f"generic:component:{component_type}:clock-semantics"
        )
    source_contract = _generic_endpoint_reset_contract(_generic_with_reset_contract(source, source_root, source_module))
    target_contract = _generic_endpoint_reset_contract(_generic_with_reset_contract(target, target_root, target_module))
    processor_backend = source.function == "processor_memory_backend"
    if source_contract != target_contract and not processor_backend:
        raise AutoCompositionError(
            f"generic:component:{component_type}:reset-semantics"
        )
    if processor_backend:
        result["source_reset_semantics"] = source_contract
    result["reset_semantics"] = target_contract
    return result


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


def _generic_address_width(
    capabilities: tuple[EndpointCapability, ...], catalog: ProtocolCatalog | None,
) -> int:
    widths: set[int] = set()
    for endpoint in capabilities:
        fields = {field.role: field for field in endpoint.fields}
        address_roles = {"address", "addr"}
        if catalog is not None and endpoint.protocol is not None:
            plugin = catalog.require(*endpoint.protocol)
            address_roles.update(
                spec.field_id for spec in plugin.fields
                if "address_width" in _generic_width_expression_names(spec.width_expression)
            )
        widths.update(field.width for role, field in fields.items() if role in address_roles)
    if len(widths) != 1:
        raise AutoCompositionError("generic:address-width:ambiguous")
    return widths.pop()


def _generic_width_expression_names(expression: str) -> frozenset[str]:
    """Return only stable parameter identifiers used by a protocol width."""
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, TypeError) as error:
        raise AutoCompositionError("generic:protocol:width-expression") from error
    return frozenset(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))


def _generic_address_field_ids(catalog: ProtocolCatalog, protocol: tuple[str, str]) -> tuple[str, ...]:
    return tuple(
        spec.field_id
        for spec in catalog.require(*protocol).fields
        if "address_width" in _generic_width_expression_names(spec.width_expression)
    )


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
    source_root = (root.resolve() / request.interface_description.source.source_root).resolve()
    capabilities = normalize_annotations(annotations, protocol_catalog=selected_protocol_catalog)
    if not capabilities:
        raise AutoCompositionError("generic:annotations:empty")
    endpoint_modules = {
        str(endpoint["endpoint_id"]): endpoint.get("module")
        for endpoint in annotations["endpoints"]  # type: ignore[index]
        if isinstance(endpoint, Mapping)
    }
    processor_execution = None
    processor_boundary = None
    processor_backend_source = None
    generic_processor_context = any(
        endpoint.function == "boot_control" for endpoint in capabilities
    )
    processor_candidate = any(
        _is_processor_memory_endpoint(
            endpoint, generic_processor_context=generic_processor_context,
        )
        for endpoint in capabilities
    )
    if processor_candidate:
        if selected_protocol_catalog is None:
            raise AutoCompositionError("generic:protocol-catalog-required")
        clock_endpoints = [item for item in capabilities if item.function == "clock"]
        reset_endpoints = [item for item in capabilities if item.function == "reset"]
        if len(clock_endpoints) != 1:
            raise AutoCompositionError("duplicate-clock" if clock_endpoints else "clock")
        if len(reset_endpoints) != 1:
            raise AutoCompositionError("duplicate-reset" if reset_endpoints else "reset")
        clock_endpoint, reset_endpoint = clock_endpoints[0], reset_endpoints[0]
        if len(clock_endpoint.fields) != 1 or len(reset_endpoint.fields) != 1:
            raise AutoCompositionError("generic:processor-control-fields")
        clock_port, reset_port = clock_endpoint.fields[0].port, reset_endpoint.fields[0].port
        memory_endpoints = [
            item for item in capabilities
            if _is_processor_memory_endpoint(
                item, generic_processor_context=generic_processor_context,
            )
        ]
        reset_contracts: set[tuple[str, str]] = set()
        associated: dict[str, EndpointCapability] = {}
        for memory_endpoint in memory_endpoints:
            reset_module = endpoint_modules.get(memory_endpoint.endpoint_id)
            if (
                not isinstance(reset_module, str) or not reset_module
                or endpoint_modules.get(clock_endpoint.endpoint_id) != reset_module
                or endpoint_modules.get(reset_endpoint.endpoint_id) != reset_module
            ):
                raise AutoCompositionError("generic:processor-reset-module")
            verification_view = replace(
                memory_endpoint,
                fields=(*memory_endpoint.fields, *clock_endpoint.fields, *reset_endpoint.fields),
                clock=clock_port, reset=reset_port,
            )
            try:
                verified_view = _generic_with_reset_contract(
                    verification_view, source_root, reset_module,
                )
            except AutoCompositionError as error:
                if memory_endpoint.clock != clock_port:
                    raise AutoCompositionError(
                        f"memory-clock:{memory_endpoint.endpoint_id}"
                    ) from error
                raise
            contract = _generic_endpoint_reset_contract(verified_view)
            reset_contracts.add((contract["polarity"], contract["synchrony"]))
            associated[memory_endpoint.endpoint_id] = replace(
                memory_endpoint, clock=clock_port, reset=reset_port,
            )
        if len(reset_contracts) != 1:
            raise AutoCompositionError("generic:processor-reset-semantics")
        polarity, synchrony = next(iter(reset_contracts))
        reset_markers = (f"reset_contract:{polarity}:{synchrony}",)
        verified_reset = replace(
            reset_endpoint,
            evidence=tuple(sorted(set((*reset_endpoint.evidence, *reset_markers)))),
        )
        capabilities = tuple(
            verified_reset if endpoint.endpoint_id == verified_reset.endpoint_id
            else associated.get(endpoint.endpoint_id, endpoint)
            for endpoint in capabilities
        )
        processor_boundary = build_processor_boundary(
            capabilities, protocol_catalog=selected_protocol_catalog,
            require_instruction_identity=False,
        )
        adapter_driven = {
            (memory.endpoint_id, field.role)
            for memory in processor_boundary.memories
            for field in memory.fields
            if field.direction == "input"
        }
        layout_annotations = {
            **annotations,
            "endpoints": [
                {
                    **endpoint,
                    "fields": [
                        field for field in endpoint["fields"]
                        if (endpoint["endpoint_id"], field["role"]) not in adapter_driven
                    ],
                }
                for endpoint in annotations["endpoints"]
            ],
        }
    else:
        layout_annotations = annotations
    layout = build_input_layout(layout_annotations, isa=request.isa)
    if processor_boundary is not None:
        assert selected_protocol_catalog is not None
        processor_execution = build_processor_execution(
            processor_boundary,
            protocol_catalog=selected_protocol_catalog,
            input_layout=layout,
        )
        execution_document = processor_execution_document(processor_execution)
        for route in execution_document["routes"]:
            contract = route.get("reset_contract")
            if contract != {"polarity": "active_low", "synchrony": "synchronous"}:
                raise AutoCompositionError("generic:processor:adapter-reset-contract")
        execution_route = processor_execution_document(processor_execution)["routes"][0]
        backend_fields = {
            item["field_id"]: item for item in execution_route["backend_contract"]["fields"]
        }
        backend_plugin = selected_protocol_catalog.require("processor-memory-beat", "1")
        evidence_source = processor_boundary.memories[0].fields[0].source
        virtual_fields = [
            EndpointFieldFact(
                role=spec.field_id,
                port=f"processor_backend_{spec.field_id}",
                direction="output" if spec.direction == "host_to_device" else "input",
                width=int(backend_fields[spec.field_id]["width"]),
                signed=False,
                source=evidence_source,
                evidence=("processor_execution_backend_contract",),
            )
            for spec in backend_plugin.fields
        ]
        virtual_fields.extend((*processor_boundary.clock.fields, *processor_boundary.reset.fields))
        processor_backend_source = EndpointCapability(
            endpoint_id="processor.execution.backend",
            function="processor_memory_backend",
            side="initiator",
            protocol=("processor-memory-beat", "1"),
            fields=tuple(virtual_fields),
            clock=processor_boundary.clock.fields[0].port,
            reset=processor_boundary.reset.fields[0].port,
            timing=(),
            evidence=("processor_execution.v1",),
        )
        endpoint_modules[processor_backend_source.endpoint_id] = endpoint_modules[
            processor_boundary.memories[0].endpoint_id
        ]

    source_prefix = request.interface_description.source.source_root.rstrip("/")
    declared_source_files = request.interface_description.source.files
    source_list_metadata = _generic_source_list_metadata(root, request.interface_description.source)
    source_file_records = source_list_metadata.sources or tuple(
        f"{source_prefix}/{source_file}" if source_prefix else str(source_file)
        for source_file in declared_source_files
    ) or annotations["source"]["files"]  # type: ignore[index]
    source_files = tuple(dict.fromkeys(
        str(source_file)
        for source_file in source_file_records
        if Path(str(source_file)).suffix in HDL_SUFFIXES
    ))
    for source_file in source_files:
        _generic_source_path(root, source_file)
    if processor_execution is not None:
        source_files = tuple(dict.fromkeys((*source_files, *processor_execution.adapter_sources)))
        for source_file in processor_execution.adapter_sources:
            _generic_source_path(root, source_file)
    source_include_roots = source_list_metadata.include_roots
    elaboration = request.interface_description.source.elaboration
    source_defines = source_list_metadata.defines + (
        tuple(f"+define+{name}={value}" for name, value in elaboration.defines)
        if elaboration is not None else ()
    )

    profiles: dict[str, PeripheralProfile] = {}
    component_records: list[dict[str, object]] = []
    matches: list[Mapping[str, object]] = []
    diagnostics: list[str] = []
    catalog = component_catalog or load_builtin_component_catalog()
    used_endpoints: set[str] = set()
    if request.component_types:
        if selected_protocol_catalog is None:
            raise AutoCompositionError("generic:protocol-catalog-required")
        address_width = _generic_address_width(capabilities, selected_protocol_catalog)
        address = 0
        irq = 0
        for component_type in request.component_types:
            try:
                profile = catalog.require(component_type)
            except ComponentDefinitionError as error:
                raise AutoCompositionError(f"generic:component:{component_type}:unknown") from error
            if not profile.implemented or profile.source_status != "implemented":
                raise AutoCompositionError(f"generic:component:{component_type}:unavailable")
            for source_file in profile.source_paths:
                _generic_source_path(root, source_file)
            candidates = (
                tuple(pair for pair in request.protocol_preferences if pair in profile.protocols)
                if request.protocol_preferences else profile.protocols
            )
            if not candidates:
                raise AutoCompositionError(f"generic:component:{component_type}:protocol-preference")
            accepted_candidates: list[tuple[EndpointCapability, EndpointCapability, tuple[str, str], Mapping[str, object]]] = []
            for protocol in candidates:
                sources = (
                    (processor_backend_source,)
                    if processor_backend_source is not None
                    and protocol == ("processor-memory-beat", "1")
                    else tuple(
                        endpoint for endpoint in capabilities
                        if endpoint.side == "initiator" and endpoint.protocol == protocol
                    )
                )
                if not sources:
                    diagnostics.append(f"rejected:{component_type}:{protocol[0]}@{protocol[1]}:no-source-endpoint")
                    continue
                target = _generic_target_capability(profile, protocol, root, selected_protocol_catalog)
                compatible: list[tuple[EndpointCapability, Mapping[str, object]]] = []
                for source in sources:
                    transport_source = _generic_transport_capability(source, selected_protocol_catalog)
                    transport_target = _generic_transport_capability(target, selected_protocol_catalog)
                    alternatives = match_endpoint_pair(
                        transport_source,
                        transport_target,
                        (),
                        protocol_catalog=selected_protocol_catalog,
                        compiled_protocols=_generic_compiled_protocols(source, target, selected_protocol_catalog),
                    )
                    matches.extend(
                        {**item, "component_type": component_type,
                         "source_endpoint_id": source.endpoint_id,
                         "target_endpoint_id": target.endpoint_id}
                        for item in alternatives
                    )
                    selected = next((item for item in alternatives if item["accepted"]), None)
                    if selected is None:
                        diagnostics.extend(
                            f"rejected:{component_type}:{protocol[0]}@{protocol[1]}:{reason}"
                            for item in alternatives for reason in item["reasons"]  # type: ignore[index]
                        )
                        continue
                    compatible.append((source, selected))
                if len(compatible) > 1:
                    endpoints = ",".join(sorted(source.endpoint_id for source, _ in compatible))
                    raise AutoCompositionError(
                        f"generic:component:{component_type}:ambiguous-source-endpoint:{endpoints}"
                    )
                if compatible:
                    source, selected = compatible[0]
                    accepted_candidates.append((source, target, protocol, selected))
            if not accepted_candidates:
                raise AutoCompositionError(f"generic:component:{component_type}:no-compatible-endpoint")
            if not request.protocol_preferences and len(accepted_candidates) > 1:
                choices = ",".join(f"{item[2][0]}@{item[2][1]}" for item in accepted_candidates)
                raise AutoCompositionError(f"generic:component:{component_type}:ambiguous-protocol:{choices}")
            accepted = accepted_candidates[0]
            if accepted[0].endpoint_id in used_endpoints and accepted[2] not in {
                ("apb", "3"), ("apb", "4"), ("wishbone", "classic"),
                ("processor-memory-beat", "1"),
            }:
                raise AutoCompositionError(
                    f"generic:adapter:single-target-source:{accepted[0].endpoint_id}"
                )
            control = _generic_control_binding(
                accepted[0], accepted[1], component_type,
                source_root=source_root, target_root=root,
                source_module=str(endpoint_modules.get(accepted[0].endpoint_id, "")),
                target_module=profile.module_name,
            )
            recovery_contract = None
            if accepted[2] == ("processor-memory-beat", "1"):
                features = profile.protocol_features.get(accepted[2], ())
                if "reset_flush" not in features:
                    raise AutoCompositionError(
                        f"generic:component:{component_type}:recovery-contract"
                    )
                recovery_contract = {
                    "mode": "reset_flush",
                    "scope": "all_accepted_requests",
                    "acknowledgment": "one_active_clock_edge",
                    "late_response_after_ack": "forbidden",
                    "reset_semantics": dict(control["reset_semantics"]),
                    "evidence": ["component_profile:reset_flush", "component_hdl:reset"],
                }
            for discarded in accepted_candidates[1:]:
                diagnostics.append(
                    f"rejected:{component_type}:{discarded[2][0]}@{discarded[2][1]}:lower-preference"
                )
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
            if profile.irq_capable:
                source_roles = {field.role for field in accepted[0].fields}
                target_roles = {field.role for field in accepted[1].fields}
                if "irq" not in source_roles or "irq" not in target_roles:
                    raise AutoCompositionError(
                        f"generic:component:{component_type}:irq-route-unavailable"
                    )
            component_records.append({
                "component_id": component_id,
                "component_type": component_type,
                "module_name": profile.module_name,
                "protocol": {"id": accepted[2][0], "version": accepted[2][1]},
                "base": base,
                "size": size,
                "irq": irq if profile.irq_capable else None,
                "parameters": _default_parameters(profile),
                "source_files": list(profile.source_paths),
                "selected_endpoint": accepted[0].endpoint_id,
                "target_binding": {
                    "endpoint_id": accepted[1].endpoint_id,
                    "module": profile.module_name,
                    "fields": [
                        {"role": field.role, "port": field.port, "direction": field.direction,
                         "width": field.width,
                         "source": None if field.source is None else {
                             "file": field.source.file, "line": field.source.line,
                             "column": field.source.column,
                         }}
                        for field in accepted[1].fields
                    ], "control": control,
                    **({"recovery": recovery_contract} if recovery_contract is not None else {}),
                },
            })
            used_endpoints.add(accepted[0].endpoint_id)
            if profile.irq_capable:
                irq += 1
            address = base + size
            profiles[component_type] = profile
            source_files = tuple(dict.fromkeys((*source_files, *profile.source_paths)))
        dependencies = _generic_dependencies(profiles)
        if dependencies:
            raise AutoCompositionError("generic:dependency:unbound-source-port")
    else:
        dependencies = ()

    annotation_hash = content_hash(annotations)
    instances = [
        {"instance_id": canonical_id("generic-component-instance", str(item["component_id"])),
         "component_id": item["component_id"], "module_name": item["module_name"],
         "parameters": item["parameters"], "role": item["component_type"]}
        for item in component_records
    ]
    adapters = [
        {"adapter_id": canonical_id("generic-adapter", str(item["component_id"])),
         "component_id": item["component_id"], "protocol": [item["protocol"]["id"], item["protocol"]["version"]],
         "source_endpoint_id": item["selected_endpoint"],
         "target_endpoint_id": item["target_binding"]["endpoint_id"],
         "max_wait_cycles": _generic_adapter_contract(
             (item["protocol"]["id"], item["protocol"]["version"]), selected_protocol_catalog,
         )["max_wait_cycles"], "kind": "generic_protocol_bridge",
         "contract": _generic_adapter_contract(
             (item["protocol"]["id"], item["protocol"]["version"]), selected_protocol_catalog,
         ),
         "address_field_ids": list(_generic_address_field_ids(
             selected_protocol_catalog, (item["protocol"]["id"], item["protocol"]["version"])
         )),
         "fields": [
             {"field_id": field["role"], "target_port": field["port"],
              "direction": field["direction"], "width": field["width"],
              "address": field["role"] in _generic_address_field_ids(
                  selected_protocol_catalog, (item["protocol"]["id"], item["protocol"]["version"])
              )}
             for field in item["target_binding"]["fields"]
             if field["role"] not in {"clock", "reset"}
         ]}
        for item in component_records
    ]
    bindings = [
        {"binding_id": canonical_id("generic-binding", str(item["component_id"])),
         "component_id": item["component_id"], "source_endpoint_id": item["selected_endpoint"],
         "target_endpoint_id": item["target_binding"]["endpoint_id"],
         "protocol": [item["protocol"]["id"], item["protocol"]["version"]],
         "target_binding": item["target_binding"], "control": item["target_binding"]["control"]}
        for item in component_records
    ]
    regions = [
        {"region_id": canonical_id("generic-address-region", str(item["component_id"])),
         "component_id": item["component_id"], "base": item["base"], "size": item["size"],
         "end": int(item["base"]) + int(item["size"]), "address_width": address_width}
        for item in component_records
    ] if request.component_types else []
    irq_routes = [
        {"route_id": canonical_id("generic-irq-route", str(item["component_id"])),
         "component_id": item["component_id"], "irq": item["irq"],
         "source_endpoint_id": item["selected_endpoint"],
         "field_id": "irq", "target_port": next(
             field["port"] for field in item["target_binding"]["fields"] if field["role"] == "irq"
         )}
        for item in component_records if item["irq"] is not None
    ]
    stable_processor_mode = processor_execution is not None
    if stable_processor_mode:
        processor_source_ids, stable_source_file_ids = _processor_source_records(
            root, source_files, annotations, source_prefix=source_prefix,
        )
        stable_component_records = _generic_ir_evidence(
            component_records, processor_source_ids,
        )
        stable_bindings = _generic_ir_evidence(bindings, processor_source_ids)
        stable_capabilities = _processor_capability_documents(
            capabilities, processor_source_ids,
        )
        stable_annotation_hash = content_hash({"capabilities": stable_capabilities})
        stable_layout_fields = _processor_layout_fields(
            layout, capabilities, processor_source_ids,
        )
    else:
        stable_component_records = component_records
        stable_bindings = bindings
        stable_source_file_ids = [
            canonical_id("generic-source-file", item) for item in source_files
        ]
        stable_capabilities = [
            _generic_capability_document(item) for item in capabilities
        ]
        stable_annotation_hash = annotation_hash
        stable_layout_fields = [
            {key: value for key, value in field.items() if key != "provenance"}
            for field in input_layout_document(layout)["fields"]
        ]
    stable_layout_hash = (
        canonical_ir_hash({
            "schema_version": layout.schema_version,
            "raw_width": layout.raw_width,
            "fields": stable_layout_fields,
        })
        if stable_processor_mode else layout.layout_hash
    )
    ir = canonical_ir_document({
        "schema_version": "composition_ir.v1",
        "composition_kind": "generic_composition",
        "target": {"top_module": "generic_composition_top", "source_top_module": (
                       "processor_source" if stable_processor_mode
                       else request.interface_description.source.top_module
                   ),
                   "address_width": address_width if request.component_types else None},
        "interface_annotation_hash": stable_annotation_hash,
        "capabilities": stable_capabilities,
        "components": stable_component_records,
        "instances": instances,
        "adapters": adapters,
        "endpoint_bindings": stable_bindings,
        "address_regions": regions,
        "irq_routes": irq_routes,
        "dependencies": [[f"{item[0]}0", f"{item[1]}0"] for item in dependencies],
        "runtime": {"seed": request.seed},
        "match_alternatives": _generic_ir_evidence(matches),
        "input_layout": {
            "schema_version": layout.schema_version,
            "raw_width": layout.raw_width,
            "layout_hash": stable_layout_hash,
            "fields": stable_layout_fields,
        },
        **({"processor_execution": _generic_ir_evidence(
                processor_execution_document(processor_execution), processor_source_ids,
            )}
           if processor_execution is not None else {}),
        "source_file_ids": stable_source_file_ids,
        "source_list": {
            "cwd": "output_dir",
            "path_basis": "output-relative",
            **({"compilation_unit_ids": [processor_source_ids[item] for item in source_files]}
               if stable_processor_mode else {}),
            "include_root_ids": [
                canonical_id("generic-include-root", item)
                for item in source_include_roots
            ],
            "defines": list(source_defines),
        },
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
        processor_execution=processor_execution,
        ir=ir,
        interface_annotation_hash=annotation_hash,
        composition_ir_hash=canonical_ir_hash(ir),
        source_files=source_files,
        source_include_roots=source_include_roots,
        source_defines=source_defines,
        source_evidence_hash=_generic_source_evidence_hash(
            root, source_files, request.interface_description.source,
        ),
        request=request,
        component_catalog=catalog,
        protocol_catalog=selected_protocol_catalog,
    )
