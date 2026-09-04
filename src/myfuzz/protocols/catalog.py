"""Load protocol plugins by declared identifiers only."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .model import (
    FieldSpec,
    ProjectionActionSpec,
    ProtocolDefinitionError,
    ProtocolPlugin,
    TemporalRuleSpec,
)


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
        runtime_required = item.get("runtime_required", False)
        if not isinstance(runtime_required, bool):
            raise ProtocolDefinitionError(f"{source}: runtime_required must be boolean for {field_id}")
        reset_value = item.get("reset_value")
        if isinstance(reset_value, bool) or not isinstance(reset_value, int):
            raise ProtocolDefinitionError(f"{source}: reset_value must be integer for {field_id}")
        fields.append(FieldSpec(field_id, direction, width_expression, required, reset_value, runtime_required))
    adapters_raw = document.get("legal_adapters", [])
    if not isinstance(adapters_raw, list) or not all(isinstance(adapter, str) and adapter for adapter in adapters_raw):
        raise ProtocolDefinitionError(f"{source}: legal_adapters must be a list of strings")

    projection_actions: list[ProjectionActionSpec] = []
    action_ids: set[int] = set()
    actions_raw = document.get("projection_actions", [])
    if not isinstance(actions_raw, list):
        raise ProtocolDefinitionError(f"{source}: projection_actions must be a list")
    for index, item in enumerate(actions_raw):
        if not isinstance(item, dict):
            raise ProtocolDefinitionError(f"{source}: projection action must be an object")
        action_id = item.get("action_id")
        if isinstance(action_id, bool) or not isinstance(action_id, int) or action_id < 0:
            raise ProtocolDefinitionError(f"{source}: projection action ID is invalid")
        if action_id in action_ids:
            raise ProtocolDefinitionError(f"{source}: duplicate projection action ID")
        action_ids.add(action_id)
        field_ids_raw = item.get("field_ids")
        if (
            not isinstance(field_ids_raw, list)
            or not field_ids_raw
            or any(not isinstance(field_id, str) or field_id not in seen for field_id in field_ids_raw)
        ):
            raise ProtocolDefinitionError(f"{source}: projection action fields must reference declared fields")
        kind = _require_string(item.get("kind"), f"projection action {index}.kind")
        category = _require_string(item.get("category"), f"projection action {index}.category")
        max_cycles = item.get("max_cycles")
        if max_cycles is not None and (
            isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or not 1 <= max_cycles <= 65_535
        ):
            raise ProtocolDefinitionError(f"{source}: projection action max_cycles is invalid")
        if kind in {"gate", "delay_select"} and max_cycles is None:
            raise ProtocolDefinitionError(f"{source}: temporal projection action requires max_cycles")
        projection_actions.append(
            ProjectionActionSpec(action_id, tuple(field_ids_raw), kind, category, max_cycles)
        )

    temporal_rules: list[TemporalRuleSpec] = []
    rule_ids: set[int] = set()
    rules_raw = document.get("temporal_rules", [])
    if not isinstance(rules_raw, list):
        raise ProtocolDefinitionError(f"{source}: temporal_rules must be a list")
    for index, item in enumerate(rules_raw):
        if not isinstance(item, dict):
            raise ProtocolDefinitionError(f"{source}: temporal rule must be an object")
        rule_id = item.get("rule_id")
        if isinstance(rule_id, bool) or not isinstance(rule_id, int) or rule_id < 0 or rule_id in rule_ids:
            raise ProtocolDefinitionError(f"{source}: temporal rule ID is invalid")
        rule_ids.add(rule_id)
        antecedent = _require_string(item.get("antecedent_field_id"), f"temporal rule {index}.antecedent")
        consequent = _require_string(item.get("consequent_field_id"), f"temporal rule {index}.consequent")
        if antecedent not in seen or consequent not in seen:
            raise ProtocolDefinitionError(f"{source}: temporal rule references undeclared field")
        max_cycles = item.get("max_cycles")
        if isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or not 1 <= max_cycles <= 65_535:
            raise ProtocolDefinitionError(f"{source}: temporal rule max_cycles is invalid")
        temporal_rules.append(
            TemporalRuleSpec(
                rule_id,
                _require_string(item.get("kind"), f"temporal rule {index}.kind"),
                antecedent,
                consequent,
                max_cycles,
            )
        )
    return ProtocolPlugin(
        protocol_id,
        version,
        tuple(fields),
        tuple(adapters_raw),
        tuple(sorted(projection_actions, key=lambda action: action.action_id)),
        tuple(sorted(temporal_rules, key=lambda rule: rule.rule_id)),
    )


def load_protocol_catalog(path: str | Path) -> ProtocolCatalog:
    directory = Path(path)
    if not directory.is_dir():
        raise ProtocolDefinitionError(f"plugin directory does not exist: {directory}")
    plugins = tuple(_parse_plugin(json.loads(source.read_text(encoding="utf-8")), source) for source in sorted(directory.glob("*.json")))
    keys = [(plugin.protocol_id, plugin.version) for plugin in plugins]
    if len(keys) != len(set(keys)):
        raise ProtocolDefinitionError("duplicate declared protocol_id and version")
    return ProtocolCatalog(plugins)


@lru_cache(maxsize=1)
def _builtin_catalog() -> ProtocolCatalog:
    return load_protocol_catalog(Path(__file__).with_name("plugins"))


def load_builtin_protocol(protocol_id: str, version: str | None = None) -> ProtocolPlugin:
    """Load one bundled plugin by exact declared identity."""
    protocol_id = _require_string(protocol_id, "protocol_id")
    if version is not None:
        version = _require_string(version, "version")
        return _builtin_catalog().require(protocol_id, version)

    matches = tuple(
        plugin for plugin in _builtin_catalog().plugins if plugin.protocol_id == protocol_id
    )
    if not matches:
        raise ProtocolDefinitionError(f"unsupported protocol: {protocol_id}")
    if len(matches) != 1:
        versions = ", ".join(sorted(plugin.version for plugin in matches))
        raise ProtocolDefinitionError(
            f"protocol version is required for {protocol_id}; available versions: {versions}"
        )
    return matches[0]
