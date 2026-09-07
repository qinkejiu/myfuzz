"""Load protocol plugins by declared identifiers only."""

from __future__ import annotations

import ast
import json
from functools import lru_cache
from pathlib import Path

from .model import (
    CapabilityLimitValue,
    ChannelRelationSpec,
    FieldSpec,
    ProjectionActionSpec,
    ProtocolDefinitionError,
    ProtocolPlugin,
    TemporalRuleSpec,
)


_PROJECTION_KINDS = frozenset(("direct", "mask", "gate", "delay_select", "fold_xor", "constant"))
_PROJECTION_CATEGORIES = frozenset(
    ("direct", "protocol_legality", "progress", "dependency_consistency", "event_rarity", "address_validity")
)
_MAX_CAPABILITY_VALUE = 65_535
_MAX_WAIT_CYCLES = 16
_BOOLEAN_CAPABILITIES = frozenset(
    (
        "byte_enable",
        "partial_write",
        "single_beat_only",
        "splitter_required_for_bursts",
        "stall_supported",
        "source_id_reordering",
        "coherence",
    )
)
_POSITIVE_INTEGER_CAPABILITIES = frozenset(("max_outstanding", "max_wait_cycles"))
_NON_NEGATIVE_INTEGER_CAPABILITIES = frozenset(
    ("supported_burst_length", "supported_id_value")
)
_INTEGER_ARRAY_CAPABILITIES = frozenset(
    ("supported_burst_lengths", "supported_id_values")
)
_ENUM_CAPABILITIES = {
    "ordering": frozenset(("in_order_single_id",)),
    "completion": frozenset(("ack_or_err",)),
}
_BOOLEAN_OR_ENUM_CAPABILITIES = {
    "bursts": frozenset(("reject_non_single_beat",)),
    "ids": frozenset(("reject_nonzero",)),
}
_STRING_ARRAY_CAPABILITIES = {"completion_signals": ("ack", "err")}


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


def _validate_width_expression(expression: str, source: Path, field_id: str) -> None:
    """Reject malformed or non-arithmetic widths before accepting a plugin."""
    try:
        root = ast.parse(expression, mode="eval").body
    except SyntaxError as error:
        raise ProtocolDefinitionError(
            f"{source}: invalid width expression for {field_id}: {expression}"
        ) from error

    def validate(node: ast.AST) -> None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                return
        elif isinstance(node, ast.Name):
            return
        elif isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Div)
        ):
            if (
                isinstance(node.op, (ast.FloorDiv, ast.Div))
                and isinstance(node.right, ast.Constant)
                and node.right.value == 0
            ):
                raise ProtocolDefinitionError(
                    f"{source}: invalid width expression for {field_id}: {expression}"
                )
            validate(node.left)
            validate(node.right)
            return
        raise ProtocolDefinitionError(
            f"{source}: invalid width expression for {field_id}: {expression}"
        )

    validate(root)


def _parse_channel_relations(
    document: dict[object, object], source: Path, fields: set[str]
) -> tuple[ChannelRelationSpec, ...]:
    raw = document.get("channel_relations", [])
    if not isinstance(raw, list):
        raise ProtocolDefinitionError(f"{source}: channel_relations must be a list")
    relations: list[ChannelRelationSpec] = []
    seen_ids: set[int] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProtocolDefinitionError(f"{source}: channel relation must be an object")
        relation_id = item.get("relation_id")
        if (
            isinstance(relation_id, bool)
            or not isinstance(relation_id, int)
            or relation_id < 0
            or relation_id in seen_ids
        ):
            raise ProtocolDefinitionError(f"{source}: channel relation ID is invalid")
        seen_ids.add(relation_id)
        field_ids = item.get("field_ids")
        if (
            not isinstance(field_ids, list)
            or not field_ids
            or any(not isinstance(field_id, str) or field_id not in fields for field_id in field_ids)
            or len(field_ids) != len(set(field_ids))
        ):
            raise ProtocolDefinitionError(
                f"{source}: channel relation fields must reference distinct declared fields"
            )
        relations.append(
            ChannelRelationSpec(
                relation_id,
                _require_string(item.get("kind"), f"channel relation {index}.kind"),
                tuple(field_ids),
            )
        )
    return tuple(sorted(relations, key=lambda relation: relation.relation_id))


def _parse_capability_limits(
    document: dict[object, object], source: Path
) -> tuple[tuple[str, CapabilityLimitValue], ...]:
    raw = document.get("capability_limits", {})
    if not isinstance(raw, dict):
        raise ProtocolDefinitionError(f"{source}: capability_limits must be an object")
    limits: list[tuple[str, CapabilityLimitValue]] = []
    for key, value in raw.items():
        name = _require_string(key, "capability limit name")
        if name in _BOOLEAN_CAPABILITIES:
            if not isinstance(value, bool):
                raise ProtocolDefinitionError(f"{source}: capability limit {name} must be boolean")
            parsed: CapabilityLimitValue = value
        elif name in _POSITIVE_INTEGER_CAPABILITIES:
            maximum = _MAX_WAIT_CYCLES if name == "max_wait_cycles" else _MAX_CAPABILITY_VALUE
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be an integer in 1..{maximum}"
                )
            parsed = value
        elif name in _NON_NEGATIVE_INTEGER_CAPABILITIES:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_CAPABILITY_VALUE:
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be an integer in 0..{_MAX_CAPABILITY_VALUE}"
                )
            parsed = value
        elif name in _INTEGER_ARRAY_CAPABILITIES:
            maximum = 255 if name == "supported_burst_lengths" else _MAX_CAPABILITY_VALUE
            if (
                not isinstance(value, list)
                or not value
                or any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= maximum for item in value)
                or value != sorted(set(value))
            ):
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be a non-empty sorted unique integer array"
                )
            parsed = tuple(value)
        elif name in _ENUM_CAPABILITIES:
            if value not in _ENUM_CAPABILITIES[name]:
                values = ", ".join(sorted(_ENUM_CAPABILITIES[name]))
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be one of: {values}"
                )
            parsed = value
        elif name in _BOOLEAN_OR_ENUM_CAPABILITIES:
            if value is False:
                parsed = value
            elif value in _BOOLEAN_OR_ENUM_CAPABILITIES[name]:
                parsed = value
            else:
                values = ", ".join(sorted(_BOOLEAN_OR_ENUM_CAPABILITIES[name]))
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be false or one of: {values}"
                )
        elif name in _STRING_ARRAY_CAPABILITIES:
            expected = _STRING_ARRAY_CAPABILITIES[name]
            if not isinstance(value, list) or tuple(value) != expected:
                raise ProtocolDefinitionError(
                    f"{source}: capability limit {name} must be the ordered array {list(expected)}"
                )
            parsed = expected
        elif name.startswith("x-"):
            if isinstance(value, bool):
                parsed = value
            elif isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _MAX_CAPABILITY_VALUE:
                parsed = value
            elif isinstance(value, str) and value:
                parsed = value
            else:
                raise ProtocolDefinitionError(
                    f"{source}: extension capability limit {name} must be a bounded scalar"
                )
        else:
            raise ProtocolDefinitionError(
                f"{source}: unsupported capability limit: {name}"
            )
        limits.append((name, parsed))
    values = dict(limits)
    if values.get("partial_write") is True and values.get("byte_enable") is False:
        raise ProtocolDefinitionError(
            f"{source}: partial_write requires byte_enable capability"
        )
    return tuple(sorted(limits))


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
        _validate_width_expression(width_expression, source, field_id)
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
            or len(field_ids_raw) != len(set(field_ids_raw))
        ):
            raise ProtocolDefinitionError(
                f"{source}: projection action fields must reference distinct declared fields"
            )
        kind = _require_string(item.get("kind"), f"projection action {index}.kind")
        category = _require_string(item.get("category"), f"projection action {index}.category")
        if kind not in _PROJECTION_KINDS:
            raise ProtocolDefinitionError(f"{source}: unsupported projection action kind: {kind}")
        if category not in _PROJECTION_CATEGORIES:
            raise ProtocolDefinitionError(f"{source}: unsupported projection category: {category}")
        max_cycles = item.get("max_cycles")
        if max_cycles is not None and (
            isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or not 1 <= max_cycles <= 65_535
        ):
            raise ProtocolDefinitionError(f"{source}: projection action max_cycles is invalid")
        if kind in {"gate", "delay_select"} and max_cycles is None:
            raise ProtocolDefinitionError(f"{source}: temporal projection action requires max_cycles")
        constant_value = item.get("constant_value")
        if kind == "constant":
            if isinstance(constant_value, bool) or not isinstance(constant_value, int) or constant_value < 0:
                raise ProtocolDefinitionError(f"{source}: constant projection action requires a non-negative constant_value")
        elif constant_value is not None:
            raise ProtocolDefinitionError(f"{source}: only constant projection actions may declare constant_value")
        projection_actions.append(
            ProjectionActionSpec(
                action_id, tuple(field_ids_raw), kind, category, max_cycles, constant_value
            )
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
    channel_relations = _parse_channel_relations(document, source, seen)
    capability_limits = _parse_capability_limits(document, source)
    return ProtocolPlugin(
        protocol_id,
        version,
        tuple(fields),
        tuple(adapters_raw),
        tuple(sorted(projection_actions, key=lambda action: action.action_id)),
        tuple(sorted(temporal_rules, key=lambda rule: rule.rule_id)),
        channel_relations,
        capability_limits,
    )


def load_protocol_catalog(path: str | Path) -> ProtocolCatalog:
    directory = Path(path)
    if not directory.is_dir():
        raise ProtocolDefinitionError(f"plugin directory does not exist: {directory}")
    def reject_duplicate_keys(pairs: list[tuple[object, object]]) -> dict[object, object]:
        result: dict[object, object] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolDefinitionError(f"duplicate JSON object key: {key!r}")
            result[key] = value
        return result

    def load_document(source: Path) -> object:
        try:
            return json.loads(
                source.read_text(encoding="utf-8"),
                object_pairs_hook=reject_duplicate_keys,
            )
        except (json.JSONDecodeError, ProtocolDefinitionError) as error:
            raise ProtocolDefinitionError(f"{source}: invalid plugin JSON: {error}") from error

    plugins = tuple(_parse_plugin(load_document(source), source) for source in sorted(directory.glob("*.json")))
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
