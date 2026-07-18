"""Total unknown-port policy mapping for the dual-mode RawBits harness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .constraint_engine import ConstraintPrimitive, build_constraint_ir
from .contracts import ConstraintIR
from .input_model import InputValidationError, PortDirection
from .rawbits import RawBitsLayout, build_rawbits_layout
from .unknown_ports import DecisionStatus, UnknownPortAction, UnknownPortDecision


@dataclass(frozen=True)
class UnknownPortModeMapping:
    qualified_port: str
    harness_target: str
    raw_behavior: str
    constrained_behavior: str
    boundary: str
    evidence: str


@dataclass(frozen=True)
class UnknownPortHarnessPlan:
    mappings: tuple[UnknownPortModeMapping, ...]
    layout: RawBitsLayout | None
    constraint_ir: ConstraintIR | None
    external_inputs: tuple[str, ...]
    observed_outputs: tuple[str, ...]


def map_unknown_ports_to_harness(
    decisions: Iterable[UnknownPortDecision],
    *,
    constrained_rules: Mapping[str, Mapping[str, Any]] | None = None,
) -> UnknownPortHarnessPlan:
    """Map every decision exactly once without inventing constraints from prose."""
    values = tuple(decisions)
    rules = constrained_rules or {}
    qualified = [f"{item.module}.{item.port}" for item in values]
    if len(set(qualified)) != len(qualified):
        raise InputValidationError("unknown-port decisions must be unique by module and port")

    layout_specs: list[dict[str, Any]] = []
    constraint_specs: list[dict[str, Any]] = []
    mappings: list[UnknownPortModeMapping] = []
    external_inputs: list[str] = []
    observed_outputs: list[str] = []
    consumed_rules: set[str] = set()

    for decision, qualified_port in zip(values, qualified):
        target = f"ext_{decision.module}_{decision.port}"
        if not target.isidentifier():
            raise InputValidationError(f"unknown port {qualified_port}: cannot form a Harness identifier")
        if decision.status is not DecisionStatus.PLANNED:
            raise InputValidationError(
                f"unknown port {qualified_port}: policy is {decision.status.value}, not planned"
            )
        evidence = f"{decision.evidence_source}: {decision.reason}"
        action = decision.action
        if action is UnknownPortAction.TIEOFF:
            if decision.direction is not PortDirection.INPUT or decision.fixed_value is None:
                raise InputValidationError(f"unknown port {qualified_port}: incomplete tieoff evidence")
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, f"fixed:{decision.fixed_value}",
                f"fixed:{decision.fixed_value}", "internal_constant", evidence,
            ))
        elif action is UnknownPortAction.RFUZZ_DRIVE:
            _require_input(decision, qualified_port)
            layout_specs.append({
                "target": target, "width": decision.width, "purpose": "direct_fuzz",
                "provenance": evidence,
            })
            constraint_specs.append({
                "target": target, "primitive": ConstraintPrimitive.DIRECT.value,
                "provenance": evidence,
            })
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, "DIRECT", "DIRECT", "rawbits", evidence,
            ))
        elif action is UnknownPortAction.CONSTRAINED_RANDOM:
            _require_input(decision, qualified_port)
            if qualified_port not in rules:
                raise InputValidationError(
                    f"unknown port {qualified_port}: constrained_fuzz requires a structured rule"
                )
            rule = dict(rules[qualified_port])
            consumed_rules.add(qualified_port)
            raw_width = rule.pop("raw_width", decision.width)
            purpose = rule.pop("purpose", "constrained_fuzz")
            rule.pop("target", None)
            rule.pop("provenance", None)
            primitive = rule.get("primitive")
            if primitive in (None, ConstraintPrimitive.TIEOFF.value):
                raise InputValidationError(
                    f"unknown port {qualified_port}: constrained_fuzz needs a non-TIEOFF primitive"
                )
            layout_specs.append({
                "target": target, "raw_width": raw_width, "value_width": decision.width,
                "purpose": purpose, "provenance": evidence,
            })
            constraint_specs.append({"target": target, "provenance": evidence, **rule})
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, "DIRECT", str(primitive), "rawbits", evidence,
            ))
        elif action is UnknownPortAction.EXTERNAL_INPUT:
            _require_input(decision, qualified_port)
            external_inputs.append(target)
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, "EXTERNAL", "EXTERNAL", "harness_input", evidence,
            ))
        elif action is UnknownPortAction.CONNECT:
            _require_input(decision, qualified_port)
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, "CONNECTED", "CONNECTED", "internal_connection", evidence,
            ))
        elif action is UnknownPortAction.OBSERVE:
            if decision.direction is not PortDirection.OUTPUT:
                raise InputValidationError(f"unknown port {qualified_port}: OBSERVE requires an output")
            observed_outputs.append(f"obs_{decision.module}_{decision.port}")
            mappings.append(UnknownPortModeMapping(
                qualified_port, target, "OBSERVE", "OBSERVE", "harness_output", evidence,
            ))
        else:
            raise InputValidationError(
                f"unknown port {qualified_port}: action {action.value} has no Harness mapping"
            )

    unused_rules = set(rules) - consumed_rules
    if unused_rules:
        raise InputValidationError("unused constrained rule(s): " + ", ".join(sorted(unused_rules)))
    if layout_specs:
        layout = build_rawbits_layout(layout_specs)
        by_target = {item["target"]: item for item in constraint_specs}
        ordered_constraints = [by_target[entry.target] for entry in layout.entries]
        constraint_ir = build_constraint_ir(layout, ordered_constraints)
    else:
        layout = None
        constraint_ir = None
    return UnknownPortHarnessPlan(
        tuple(mappings), layout, constraint_ir,
        tuple(sorted(external_inputs)), tuple(sorted(observed_outputs)),
    )


def _require_input(decision: UnknownPortDecision, qualified_port: str) -> None:
    if decision.direction is not PortDirection.INPUT:
        raise InputValidationError(f"unknown port {qualified_port}: action requires an input")
