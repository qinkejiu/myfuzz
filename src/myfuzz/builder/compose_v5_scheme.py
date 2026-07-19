"""Compose-v5 A/B/C/D bit-level scheme planning."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from .contracts import content_digest
from .contract_v5 import ContractV5SignalRef
from .input_model import InputValidationError
from .rawbits_v5 import RawBitsV5Field, RawBitsV5Layout
from .rtl_analysis import RTLModule
from .system_contract_discovery_v5 import ContractV5SystemDiscoveryReport


COMPOSE_V5_SCHEME_PLAN_SCHEMA = "myfuzz.compose-v5-scheme-plan/v1"

_PROTOCOL_CONTROL_ROLES = frozenset({
    "request_valid",
    "request_ready",
    "response_valid",
    "response_ready",
})
_PROTOCOL_PAYLOAD_ROLES = frozenset({
    "address",
    "write_data",
    "read_data",
    "byte_enable",
    "write_enable",
    "operation",
    "id",
    "error",
    "payload",
})


@dataclass(frozen=True)
class ComposeV5SchemePlan:
    manifest_digest: str
    layout_digest: str
    discovery_digest: str
    schemes: tuple[Mapping[str, object], ...]
    digest: str
    schema: str = COMPOSE_V5_SCHEME_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COMPOSE_V5_SCHEME_PLAN_SCHEMA:
            raise InputValidationError("compose-v5 scheme plan schema mismatch")
        for value, path in (
            (self.manifest_digest, "manifest_digest"),
            (self.layout_digest, "layout_digest"),
            (self.discovery_digest, "discovery_digest"),
        ):
            _digest(value, f"compose-v5 scheme plan {path}")
        if not isinstance(self.schemes, tuple) or len(self.schemes) != 4:
            raise InputValidationError("compose-v5 scheme plan requires exactly four schemes")
        identifiers = [str(item.get("id")) for item in self.schemes]
        if identifiers != ["A", "B", "C", "D"]:
            raise InputValidationError("compose-v5 scheme plan scheme order must be A, B, C, D")
        if self.digest and self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("compose-v5 scheme plan digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "manifest_digest": self.manifest_digest,
            "layout_digest": self.layout_digest,
            "discovery_digest": self.discovery_digest,
            "schemes": [dict(item) for item in self.schemes],
        }

    def to_dict(self) -> dict[str, object]:
        value = self.payload_dict()
        value["digest"] = self.digest
        return value


def build_compose_v5_abcd_scheme_plan(
    component_modules: Mapping[str, RTLModule],
    layout: RawBitsV5Layout,
    discovery: ContractV5SystemDiscoveryReport,
    *,
    manifest_digest: str,
    stall_inputs_before_escalation: int = 256,
) -> ComposeV5SchemePlan:
    """Build the auditable four-way compose-v5 experiment plan.

    All schemes are still bitstream-driven.  C/D constraints are recorded as
    bit-level projections over rawbits fields; this function does not introduce
    instruction fragments or fixed ROM behavior.
    """

    if not isinstance(layout, RawBitsV5Layout):
        raise InputValidationError("compose-v5 scheme plan requires a RawBitsV5Layout")
    if not isinstance(discovery, ContractV5SystemDiscoveryReport):
        raise InputValidationError("compose-v5 scheme plan requires a system discovery report")
    if not isinstance(component_modules, Mapping) or not component_modules:
        raise InputValidationError("compose-v5 scheme plan requires component modules")
    _digest(manifest_digest, "compose-v5 scheme plan manifest_digest")
    if isinstance(stall_inputs_before_escalation, bool) or not isinstance(stall_inputs_before_escalation, int) \
            or stall_inputs_before_escalation <= 0:
        raise InputValidationError("stall_inputs_before_escalation must be positive")

    fields = tuple(_field_use(field) for field in layout.fields)
    roles = _input_roles(component_modules, layout, discovery)
    safe_rules = tuple(_clock_reset_rules(layout.fields)) + tuple(_protocol_rules(roles))
    schemes = (
        _scheme(
            "A", "flat_rawbits",
            "scheme_a_flat_top",
            layout.record_width_bits,
            fields,
            (),
            (),
            "directly expose every declared component input and observe every output",
            requires_artifacts=("scheme_a_flat_top", "scheme_a_rawbits_harness"),
        ),
        _scheme(
            "B", "generated_soc_rawbits",
            "generated_soc_top",
            layout.record_width_bits,
            fields,
            (),
            (),
            "generated SoC structure with raw bit-level boundary drive and no protocol projection",
            requires_artifacts=("connection_graph", "address_map", "generated_bridge_rtl", "generated_soc_top"),
        ),
        _scheme(
            "C", "generated_soc_protocol_waveform_safe",
            "generated_soc_top",
            layout.record_width_bits,
            fields,
            safe_rules,
            (),
            "same generated SoC as B, with bit-level clock/reset/handshake waveform projection",
            requires_artifacts=("connection_graph", "address_map", "generated_bridge_rtl", "generated_soc_top"),
        ),
        _scheme(
            "D", "generated_soc_adaptive_perturbed",
            "generated_soc_top",
            layout.record_width_bits + 8,
            fields,
            safe_rules,
            _perturbation_fields(layout.record_width_bits),
            "same generated SoC as C, with bounded bit-level perturbation after coverage stalls",
            requires_artifacts=("connection_graph", "address_map", "generated_bridge_rtl", "generated_soc_top"),
            perturbation={
                "enabled": True,
                "trigger": "coverage_stall",
                "stall_inputs_before_escalation": stall_inputs_before_escalation,
                "strength_field": "perturb_strength",
                "mask_field": "perturb_mask",
                "policy": (
                    "increase bounded raw-bit bypass opportunities when branch coverage does not grow; "
                    "bypass is selected by fuzz bits, not by a transaction generator"
                ),
            },
        ),
    )
    payload = {
        "schema": COMPOSE_V5_SCHEME_PLAN_SCHEMA,
        "manifest_digest": manifest_digest,
        "layout_digest": layout.digest,
        "discovery_digest": discovery.digest,
        "schemes": [dict(item) for item in schemes],
    }
    return ComposeV5SchemePlan(
        manifest_digest=manifest_digest,
        layout_digest=layout.digest,
        discovery_digest=discovery.digest,
        schemes=schemes,
        digest=content_digest(payload),
    )


def _field_use(field: RawBitsV5Field) -> dict[str, object]:
    return {
        "owner": field.owner,
        "component": field.component,
        "name": field.name,
        "kind": field.kind,
        "width": field.width,
        "offset": field.offset,
        "source": "rawbits",
        "transform": "direct_bit_slice",
        "entropy_policy": "consumed",
    }


def _scheme(
    identifier: str,
    name: str,
    target_topology: str,
    record_width_bits: int,
    fields: tuple[Mapping[str, object], ...],
    constraints: tuple[Mapping[str, object], ...],
    synthetic_fields: tuple[Mapping[str, object], ...],
    summary: str,
    *,
    requires_artifacts: tuple[str, ...],
    perturbation: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    return {
        "id": identifier,
        "name": name,
        "target_topology": target_topology,
        "record_width_bits": record_width_bits,
        "input_stream_policy": {
            "encoding": "variable_length_lsb0_rawbits",
            "unit": "time_step",
            "length": "fuzzer_controlled",
        },
        "field_uses": [dict(item) for item in fields],
        "synthetic_fields": [dict(item) for item in synthetic_fields],
        "constraint_rules": [dict(item) for item in constraints],
        "requires_artifacts": list(requires_artifacts),
        "perturbation": dict(perturbation or {"enabled": False}),
        "summary": summary,
    }


def _clock_reset_rules(fields: tuple[RawBitsV5Field, ...]) -> tuple[Mapping[str, object], ...]:
    rules: list[dict[str, object]] = []
    for field in fields:
        if field.kind == "clock":
            rules.append(_rule(
                "clock_projector",
                field.owner,
                field.width,
                "clock",
                "raw bit controls a legal sampled clock edge/level projector",
            ))
        elif field.kind == "reset":
            rules.append(_rule(
                "reset_window_projector",
                field.owner,
                field.width,
                "reset",
                "raw bit controls bounded reset assertion/release windows instead of unbounded glitches",
            ))
    return tuple(rules)


def _protocol_rules(
    roles: Mapping[str, tuple[ContractV5SignalRef, ...]],
) -> tuple[Mapping[str, object], ...]:
    rules: list[dict[str, object]] = []
    for owner in sorted(roles):
        owner_roles = {signal.role for signal in roles[owner]}
        width = next(signal.width for signal in roles[owner])
        if owner_roles & _PROTOCOL_CONTROL_ROLES:
            role = sorted(owner_roles & _PROTOCOL_CONTROL_ROLES)[0]
            primitive = (
                "valid_hold_until_accept"
                if role in {"request_valid", "response_valid"}
                else "ready_sampled_backpressure"
            )
            rules.append(_rule(
                primitive,
                owner,
                width,
                role,
                "behavior-discovered one-bit handshake signal; projection is bit-level",
            ))
        if owner_roles & _PROTOCOL_PAYLOAD_ROLES:
            role = sorted(owner_roles & _PROTOCOL_PAYLOAD_ROLES)[0]
            rules.append(_rule(
                "payload_stable_while_unaccepted",
                owner,
                width,
                role,
                "behavior-discovered payload signal held stable only while its local accept event is pending",
            ))
    return tuple(rules)


def _rule(
    primitive: str,
    owner: str,
    width: int,
    role: str,
    reason: str,
) -> dict[str, object]:
    return {
        "id": f"{primitive}:{owner}",
        "target": owner,
        "scope": "bit_level",
        "primitive": primitive,
        "role": role,
        "width": width,
        "source": owner,
        "source_encoding": "rawbits_field",
        "reason": reason,
    }


def _perturbation_fields(offset: int) -> tuple[Mapping[str, object], ...]:
    return (
        {
            "name": "perturb_strength",
            "kind": "selector",
            "width": 3,
            "offset": offset,
            "purpose": "select bounded perturbation level after coverage stalls",
        },
        {
            "name": "perturb_mask",
            "kind": "selector",
            "width": 5,
            "offset": offset + 3,
            "purpose": "select which bit-level projector class may be bypassed",
        },
    )


def _input_roles(
    component_modules: Mapping[str, RTLModule],
    layout: RawBitsV5Layout,
    discovery: ContractV5SystemDiscoveryReport,
) -> dict[str, tuple[ContractV5SignalRef, ...]]:
    component_by_module_name: dict[str, str] = {}
    for component_id, module in component_modules.items():
        if not isinstance(component_id, str) or not component_id:
            raise InputValidationError("compose-v5 scheme plan component id must be non-empty")
        if not isinstance(module, RTLModule):
            raise InputValidationError("compose-v5 scheme plan requires RTLModule values")
        for name in {module.name, module.original_name}:
            if name in component_by_module_name and component_by_module_name[name] != component_id:
                raise InputValidationError(f"module name {name!r} maps to multiple components")
            component_by_module_name[name] = component_id

    field_owners = {field.owner for field in layout.fields}
    grouped: dict[str, list[ContractV5SignalRef]] = {}
    for report in discovery.module_reports:
        if report.ambiguity.status != "unique" or len(report.hypotheses) != 1:
            continue
        component_id = (
            component_by_module_name.get(report.module)
            or component_by_module_name.get(report.original_module)
        )
        if component_id is None:
            raise InputValidationError(
                f"compose-v5 discovery module {report.module!r} is absent from component modules"
            )
        for signal in report.hypotheses[0].signals:
            if signal.direction != "input":
                continue
            owner = f"{component_id}.{signal.port}"
            if owner not in field_owners:
                continue
            grouped.setdefault(owner, []).append(signal)
    return {owner: tuple(signals) for owner, signals in grouped.items()}


def _digest(value: object, path: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
