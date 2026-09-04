"""Immutable records for explicitly declared protocol plugins."""

from __future__ import annotations

from dataclasses import dataclass


class ProtocolDefinitionError(ValueError):
    """Raised when a protocol declaration is inconsistent."""


@dataclass(frozen=True, slots=True)
class FieldSpec:
    field_id: str
    direction: str
    width_expression: str
    required: bool
    reset_value: int | None
    runtime_required: bool = False


@dataclass(frozen=True, slots=True)
class ProjectionActionSpec:
    """A declared bounded projection action, keyed only by plugin field IDs."""

    action_id: int
    field_ids: tuple[str, ...]
    kind: str
    category: str
    max_cycles: int | None


@dataclass(frozen=True, slots=True)
class TemporalRuleSpec:
    """Finite temporal relationship used to bound a projection action."""

    rule_id: int
    kind: str
    antecedent_field_id: str
    consequent_field_id: str
    max_cycles: int


@dataclass(frozen=True, slots=True)
class ProtocolPlugin:
    protocol_id: str
    version: str
    fields: tuple[FieldSpec, ...]
    legal_adapters: tuple[str, ...]
    projection_actions: tuple[ProjectionActionSpec, ...] = ()
    temporal_rules: tuple[TemporalRuleSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class CompiledField:
    field_id: str
    direction: str
    width: int
    port_id: str
    reset_value: int | None


@dataclass(frozen=True, slots=True)
class CompiledProtocol:
    binding_id: str
    protocol_id: str
    version: str
    fields: tuple[CompiledField, ...]

    def field_for(self, field_id: str) -> CompiledField:
        for field in self.fields:
            if field.field_id == field_id:
                return field
        raise KeyError(field_id)

    def port_for(self, field_id: str) -> str:
        return self.field_for(field_id).port_id
