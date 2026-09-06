"""Semantic, source-pinned interface descriptions for later HDL analysis."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from os import PathLike
from pathlib import Path

from myfuzz.contracts import validate_contract


@dataclass(frozen=True, slots=True)
class SourceLocator:
    source_root: str
    revision: str
    top_module: str
    files: tuple[str, ...] = ()
    filelist: str | None = None
    include_roots: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FieldHint:
    role: str
    aliases: tuple[str, ...] = ()
    required: bool = True


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
    return FieldHint(
        role=value["role"],  # type: ignore[arg-type]
        aliases=_strings(value.get("aliases", [])),
        required=value.get("required", True),  # type: ignore[arg-type]
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
    source = SourceLocator(
        source_root=source_value["root"],  # type: ignore[arg-type]
        revision=source_value["revision"],  # type: ignore[arg-type]
        top_module=source_value["top_module"],  # type: ignore[arg-type]
        files=_strings(source_value.get("files", [])),
        filelist=source_value.get("filelist"),  # type: ignore[arg-type]
        include_roots=_strings(source_value.get("include_roots", [])),
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
    return {
        "schema_version": "interface_description.v1",
        "source": source,
        "endpoints": [
            _endpoint_document(endpoint)
            for endpoint in sorted(value.endpoints, key=lambda item: item.endpoint_id)
        ],
    }
