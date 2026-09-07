"""Semantic, source-pinned interface descriptions for later HDL analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from os import PathLike
from pathlib import Path

from myfuzz.contracts import validate_contract


@dataclass(frozen=True, slots=True)
class ElaborationSettings:
    frontend: str
    defines: tuple[tuple[str, str], ...] = ()
    parameters: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.frontend != "verilator-json":
            raise ValueError("unsupported-elaboration-frontend")
        identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
        patterns = (("define", self.defines, re.compile(r"[A-Za-z0-9_]+\Z")),
                    ("parameter", self.parameters, re.compile(r"-?(?:0|[1-9][0-9]*)\Z")))
        for kind, pairs, value_pattern in patterns:
            names: set[str] = set()
            normalized: list[tuple[str, str]] = []
            for pair in pairs:
                if not isinstance(pair, tuple) or len(pair) != 2:
                    raise ValueError(f"unsafe-elaboration-{kind}")
                name, value = pair
                if (not isinstance(name, str) or not isinstance(value, str)
                        or identifier.fullmatch(name) is None or value_pattern.fullmatch(value) is None):
                    raise ValueError(f"unsafe-elaboration-{kind}")
                if name in names:
                    raise ValueError(f"duplicate-elaboration-{kind}")
                names.add(name)
                normalized.append((name, value))
            object.__setattr__(self, kind + "s", tuple(sorted(normalized)))


@dataclass(frozen=True, slots=True)
class SourceLocator:
    source_root: str
    revision: str
    top_module: str
    files: tuple[str, ...] = ()
    filelist: str | None = None
    include_roots: tuple[str, ...] = ()
    elaboration: ElaborationSettings | None = None


@dataclass(frozen=True, slots=True)
class PhysicalSelector:
    port: str
    member_path: tuple[str, ...]

    def __post_init__(self) -> None:
        identifier = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
        if (not isinstance(self.member_path, (tuple, list))
                or not isinstance(self.port, str) or identifier.fullmatch(self.port) is None
                or not self.member_path or any(
            not isinstance(item, str) or identifier.fullmatch(item) is None for item in self.member_path
        )):
            raise ValueError("invalid-physical-selector")
        object.__setattr__(self, "member_path", tuple(self.member_path))


@dataclass(frozen=True, slots=True)
class FieldHint:
    role: str
    aliases: tuple[str, ...] = ()
    required: bool = True
    physical: PhysicalSelector | None = None

    def __post_init__(self) -> None:
        if self.physical is not None and self.aliases:
            raise ValueError("physical-aliases-mutually-exclusive")


@dataclass(frozen=True, slots=True)
class EndpointDescription:
    endpoint_id: str
    function: str
    required: bool = True
    module: str | None = None
    hierarchy: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    protocol: tuple[str, str] | None = None
    fields: tuple[FieldHint, ...] = ()


@dataclass(frozen=True, slots=True)
class InterfaceDescription:
    source: SourceLocator
    endpoints: tuple[EndpointDescription, ...]


def _document(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (str, PathLike)):
        with Path(value).open(encoding="utf-8") as source:
            loaded = json.load(source)
        if isinstance(loaded, Mapping):
            return loaded
    raise TypeError("document_or_path must be a mapping or JSON file path")


def _strings(value: object) -> tuple[str, ...]:
    assert isinstance(value, list)
    return tuple(value)  # type: ignore[arg-type]


def _field(value: Mapping[str, object]) -> FieldHint:
    physical_value = value.get("physical")
    physical = None
    if isinstance(physical_value, Mapping):
        physical = PhysicalSelector(
            physical_value["port"], tuple(physical_value["member_path"])  # type: ignore[arg-type]
        )
    return FieldHint(
        role=value["role"],  # type: ignore[arg-type]
        aliases=_strings(value.get("aliases", [])),
        required=value.get("required", True),  # type: ignore[arg-type]
        physical=physical,
    )


def _endpoint(value: Mapping[str, object]) -> EndpointDescription:
    protocol_value = value.get("protocol")
    protocol = None if protocol_value is None else tuple(protocol_value)  # type: ignore[arg-type]
    fields = value.get("fields", [])
    assert isinstance(fields, list)
    return EndpointDescription(
        endpoint_id=value["endpoint_id"],  # type: ignore[arg-type]
        function=value["function"],  # type: ignore[arg-type]
        required=value.get("required", True),  # type: ignore[arg-type]
        module=value.get("module"),  # type: ignore[arg-type]
        hierarchy=_strings(value.get("hierarchy", [])),
        aliases=_strings(value.get("aliases", [])),
        protocol=protocol,  # type: ignore[arg-type]
        fields=tuple(_field(field) for field in fields if isinstance(field, Mapping)),
    )


def load_interface_description(document_or_path: object) -> InterfaceDescription:
    """Load a source-pinned semantic interface description without HDL inference."""
    document = _document(document_or_path)
    validate_contract(document, "interface_description.v1")
    source_value = document["source"]
    endpoints_value = document["endpoints"]
    assert isinstance(source_value, Mapping)
    assert isinstance(endpoints_value, list)
    elaboration_value = source_value.get("elaboration")
    elaboration = None
    if isinstance(elaboration_value, Mapping):
        def pairs(name: str) -> tuple[tuple[str, str], ...]:
            values = elaboration_value.get(name, [])
            assert isinstance(values, list)
            return tuple((item["name"], item["value"]) for item in values if isinstance(item, Mapping))  # type: ignore[misc]
        elaboration = ElaborationSettings(
            frontend=elaboration_value["frontend"],  # type: ignore[arg-type]
            defines=pairs("defines"),
            parameters=pairs("parameters"),
        )
    source = SourceLocator(
        source_root=source_value["root"],  # type: ignore[arg-type]
        revision=source_value["revision"],  # type: ignore[arg-type]
        top_module=source_value["top_module"],  # type: ignore[arg-type]
        files=_strings(source_value.get("files", [])),
        filelist=source_value.get("filelist"),  # type: ignore[arg-type]
        include_roots=_strings(source_value.get("include_roots", [])),
        elaboration=elaboration,
    )
    return InterfaceDescription(
        source=source,
        endpoints=tuple(_endpoint(endpoint) for endpoint in endpoints_value if isinstance(endpoint, Mapping)),
    )


def _field_document(field: FieldHint) -> dict[str, object]:
    document: dict[str, object] = {"role": field.role}
    if field.aliases:
        document["aliases"] = sorted(field.aliases)
    if not field.required:
        document["required"] = False
    if field.physical is not None:
        document["physical"] = {"port": field.physical.port, "member_path": list(field.physical.member_path)}
    return document


def _endpoint_document(endpoint: EndpointDescription) -> dict[str, object]:
    document: dict[str, object] = {
        "endpoint_id": endpoint.endpoint_id,
        "function": endpoint.function,
    }
    if not endpoint.required:
        document["required"] = False
    if endpoint.module is not None:
        document["module"] = endpoint.module
    if endpoint.hierarchy:
        document["hierarchy"] = list(endpoint.hierarchy)
    if endpoint.aliases:
        document["aliases"] = sorted(endpoint.aliases)
    if endpoint.protocol is not None:
        document["protocol"] = list(endpoint.protocol)
    if endpoint.fields:
        document["fields"] = [
            _field_document(field) for field in sorted(endpoint.fields, key=lambda item: item.role)
        ]
    return document


def interface_description_document(value: InterfaceDescription) -> dict[str, object]:
    """Return the canonical JSON-compatible document for a semantic description."""
    source: dict[str, object] = {
        "root": value.source.source_root,
        "revision": value.source.revision,
        "top_module": value.source.top_module,
    }
    if value.source.files:
        source["files"] = list(value.source.files)
    if value.source.filelist is not None:
        source["filelist"] = value.source.filelist
    if value.source.include_roots:
        source["include_roots"] = list(value.source.include_roots)
    if value.source.elaboration is not None:
        settings = value.source.elaboration
        source["elaboration"] = {
            "frontend": settings.frontend,
            "defines": [
                {"name": name, "value": item_value}
                for name, item_value in sorted(settings.defines)
            ],
            "parameters": [
                {"name": name, "value": item_value}
                for name, item_value in sorted(settings.parameters)
            ],
        }
    return {
        "schema_version": "interface_description.v1",
        "source": source,
        "endpoints": [
            _endpoint_document(endpoint)
            for endpoint in sorted(value.endpoints, key=lambda item: item.endpoint_id)
        ],
    }
