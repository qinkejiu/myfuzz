"""Uniform, reportable policy decisions for ports without known semantics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping

from .input_model import InputValidationError, PortDirection


class UnknownPortAction(str, Enum):
    TIEOFF = "tieoff"
    CONSTRAINED_RANDOM = "constrained_random"
    RFUZZ_DRIVE = "rfuzz_drive"
    CONNECT = "connect"
    EXTERNAL_INPUT = "external_input"
    USER_REQUIRED = "user_required"
    OBSERVE = "observe"
    REJECT = "reject"


class DecisionStatus(str, Enum):
    PLANNED = "planned"
    NEEDS_USER = "needs_user"
    REJECTED = "rejected"


@dataclass(frozen=True)
class UnknownInputRequest:
    action: UnknownPortAction
    reason: str
    tieoff_value: int | None = None
    constraint: str | None = None
    reset_behavior: str | None = None
    connect_to: str | None = None


@dataclass(frozen=True)
class UnknownPortDecision:
    module: str
    port: str
    direction: PortDirection
    width: int
    action: UnknownPortAction
    status: DecisionStatus
    reason: str
    evidence_source: str
    resulting_action: str
    constraint: str | None = None
    reset_behavior: str | None = None
    fixed_value: int | None = None

    def to_report_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["direction"] = self.direction.value
        value["action"] = self.action.value
        value["status"] = self.status.value
        return value


def decide_unknown_port(
    *,
    module: str,
    port: str,
    direction: PortDirection | str,
    width: int,
    input_request: UnknownInputRequest | None = None,
) -> UnknownPortDecision:
    module = _string(module, "module")
    port = _string(port, "port")
    direction = _direction(direction)
    width = _width(width)

    if direction is PortDirection.OUTPUT:
        if input_request is not None:
            raise InputValidationError("input_request is invalid for an unknown output")
        return UnknownPortDecision(
            module=module,
            port=port,
            direction=direction,
            width=width,
            action=UnknownPortAction.OBSERVE,
            status=DecisionStatus.PLANNED,
            reason="unknown outputs are observed by default and are never driven",
            evidence_source="fallback",
            resulting_action=f"expose {module}.{port} as an observation",
        )

    if direction is PortDirection.INOUT:
        return UnknownPortDecision(
            module=module,
            port=port,
            direction=direction,
            width=width,
            action=UnknownPortAction.REJECT,
            status=DecisionStatus.REJECTED,
            reason="unknown inout requires a user annotation or protocol profile",
            evidence_source="fallback",
            resulting_action="stop generation and request port semantics",
        )

    if input_request is None:
        return UnknownPortDecision(
            module=module,
            port=port,
            direction=direction,
            width=width,
            action=UnknownPortAction.USER_REQUIRED,
            status=DecisionStatus.NEEDS_USER,
            reason="no safe driver or connection is known",
            evidence_source="fallback",
            resulting_action="leave undriven and request user policy",
        )
    return _decide_input(module, port, width, input_request)


def unknown_port_report(decisions: list[UnknownPortDecision] | tuple[UnknownPortDecision, ...]) -> dict[str, Any]:
    return {
        "unknown_ports": [decision.to_report_dict() for decision in decisions],
        "has_rejections": any(decision.status is DecisionStatus.REJECTED for decision in decisions),
        "needs_user_input": any(decision.status is DecisionStatus.NEEDS_USER for decision in decisions),
    }


def _decide_input(
    module: str, port: str, width: int, request: UnknownInputRequest
) -> UnknownPortDecision:
    reason = _string(request.reason, "input_request.reason")
    action = request.action
    if action is UnknownPortAction.TIEOFF:
        if request.tieoff_value not in (0, 1):
            raise InputValidationError("input_request.tieoff_value: expected 0 or 1")
        result = f"drive constant {request.tieoff_value}"
        constraint = f"value == {request.tieoff_value}"
    elif action is UnknownPortAction.CONSTRAINED_RANDOM:
        constraint = _string(request.constraint, "input_request.constraint")
        _string(request.reset_behavior, "input_request.reset_behavior")
        result = "drive from constrained fuzz source"
    elif action is UnknownPortAction.RFUZZ_DRIVE:
        constraint = request.constraint
        _string(request.reset_behavior, "input_request.reset_behavior")
        result = f"allocate {width} RFUZZ input bit(s)"
    elif action is UnknownPortAction.CONNECT:
        constraint = request.constraint
        result = f"connect to {_string(request.connect_to, 'input_request.connect_to')}"
    elif action is UnknownPortAction.EXTERNAL_INPUT:
        constraint = request.constraint
        result = f"expose {module}.{port} as an external input"
    else:
        raise InputValidationError(
            "input_request.action: inputs may explicitly use tieoff, constrained_random, "
            "rfuzz_drive, connect, or external_input"
        )
    return UnknownPortDecision(
        module=module,
        port=port,
        direction=PortDirection.INPUT,
        width=width,
        action=action,
        status=DecisionStatus.PLANNED,
        reason=reason,
        evidence_source="user",
        resulting_action=result,
        constraint=constraint,
        reset_behavior=request.reset_behavior,
        fixed_value=request.tieoff_value if action is UnknownPortAction.TIEOFF else None,
    )


def _direction(value: PortDirection | str) -> PortDirection:
    try:
        return PortDirection(value)
    except (TypeError, ValueError) as exc:
        raise InputValidationError("direction: expected input, output, or inout") from exc


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _width(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise InputValidationError("width: expected an integer greater than zero")
    return value
