"""Load protocol plugins by declared identifiers only."""

from __future__ import annotations

import json
from pathlib import Path

from .model import FieldSpec, ProtocolDefinitionError, ProtocolPlugin


class ProtocolCatalog:
    def __init__(self, plugins: tuple[ProtocolPlugin, ...]) -> None:
        self._plugins = plugins
        self._by_key = {(plugin.protocol_id, plugin.version): plugin for plugin in plugins}

    def require(self, protocol_id: str, version: str) -> ProtocolPlugin:
        try:
            return self._by_key[(protocol_id, version)]
        except KeyError as error:
            raise ProtocolDefinitionError(f"unsupported protocol version: {protocol_id}@{version}") from error

    @property
    def plugins(self) -> tuple[ProtocolPlugin, ...]:
        return self._plugins


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolDefinitionError(f"{label} must be a non-empty string")
    return value


def _parse_plugin(document: object, source: Path) -> ProtocolPlugin:
    if not isinstance(document, dict):
        raise ProtocolDefinitionError(f"{source}: plugin document must be an object")
    protocol_id = _require_string(document.get("protocol_id"), "protocol_id")
    version = _require_string(document.get("version"), "version")
    fields_raw = document.get("fields")
    if not isinstance(fields_raw, list) or not fields_raw:
        raise ProtocolDefinitionError(f"{source}: fields must be a non-empty list")
    fields: list[FieldSpec] = []
    seen: set[str] = set()
    for item in fields_raw:
        if not isinstance(item, dict):
            raise ProtocolDefinitionError(f"{source}: field must be an object")
        field_id = _require_string(item.get("field_id"), "field_id")
        if field_id in seen:
            raise ProtocolDefinitionError(f"{source}: duplicate field_id: {field_id}")
        seen.add(field_id)
        direction = item.get("direction")
        if direction not in {"host_to_device", "device_to_host"}:
            raise ProtocolDefinitionError(f"{source}: invalid direction for {field_id}")
        width_expression = _require_string(item.get("width"), f"width for {field_id}")
        required = item.get("required")
        if not isinstance(required, bool):
            raise ProtocolDefinitionError(f"{source}: required must be boolean for {field_id}")
        reset_value = item.get("reset_value")
        if isinstance(reset_value, bool) or not isinstance(reset_value, int):
            raise ProtocolDefinitionError(f"{source}: reset_value must be integer for {field_id}")
        fields.append(FieldSpec(field_id, direction, width_expression, required, reset_value))
    adapters_raw = document.get("legal_adapters", [])
    if not isinstance(adapters_raw, list) or not all(isinstance(adapter, str) and adapter for adapter in adapters_raw):
        raise ProtocolDefinitionError(f"{source}: legal_adapters must be a list of strings")
    return ProtocolPlugin(protocol_id, version, tuple(fields), tuple(adapters_raw))


def load_protocol_catalog(path: str | Path) -> ProtocolCatalog:
    directory = Path(path)
    if not directory.is_dir():
        raise ProtocolDefinitionError(f"plugin directory does not exist: {directory}")
    plugins = tuple(_parse_plugin(json.loads(source.read_text(encoding="utf-8")), source) for source in sorted(directory.glob("*.json")))
    keys = [(plugin.protocol_id, plugin.version) for plugin in plugins]
    if len(keys) != len(set(keys)):
        raise ProtocolDefinitionError("duplicate declared protocol_id and version")
    return ProtocolCatalog(plugins)
