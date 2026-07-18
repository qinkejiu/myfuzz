"""Validated ordered connection graph and explicit signal constraints."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .input_model import InputValidationError, PortDirection


class ConnectionKind(str, Enum):
    CLOCK_RESET = "clock_reset"
    PROTOCOL = "protocol"
    INTERRUPT = "interrupt"
    DATA = "data"
    UNKNOWN_POLICY = "unknown_policy"


class ConstraintKind(str, Enum):
    CONSTANT = "constant"
    RANGE = "range"
    ONEHOT = "onehot"
    HANDSHAKE = "handshake"
    EXPRESSION = "expression"


@dataclass(frozen=True, order=True)
class EndpointRef:
    module: str
    port: str

    def label(self) -> str:
        return f"{self.module}.{self.port}"


@dataclass(frozen=True)
class SignalEndpoint:
    ref: EndpointRef
    direction: PortDirection
    width: int
    semantic: str | None = None


@dataclass(frozen=True)
class ConnectionRequest:
    source: EndpointRef
    target: EndpointRef
    kind: ConnectionKind
    reason: str
    evidence_source: str
    confidence: str


@dataclass(frozen=True)
class ConnectionEdge:
    order: int
    source: EndpointRef
    target: EndpointRef
    width: int
    semantic: str | None
    kind: ConnectionKind
    reason: str
    evidence_source: str
    confidence: str


@dataclass(frozen=True)
class SignalConstraint:
    target: EndpointRef
    kind: ConstraintKind
    expression: str
    reason: str
    evidence_source: str
    confidence: str


@dataclass(frozen=True)
class SystemGraph:
    endpoints: tuple[SignalEndpoint, ...]
    connections: tuple[ConnectionEdge, ...]
    constraints: tuple[SignalConstraint, ...]


def build_system_graph(
    endpoints: Iterable[SignalEndpoint],
    connections: Iterable[ConnectionRequest],
    constraints: Iterable[SignalConstraint] = (),
) -> SystemGraph:
    endpoint_list = tuple(endpoints)
    by_ref: dict[EndpointRef, SignalEndpoint] = {}
    for endpoint in endpoint_list:
        _validate_endpoint(endpoint)
        if endpoint.ref in by_ref:
            raise InputValidationError(f"duplicate endpoint {endpoint.ref.label()}")
        by_ref[endpoint.ref] = endpoint

    requests = sorted(
        connections,
        key=lambda request: (
            _kind_order(request.kind),
            request.source.module,
            request.source.port,
            request.target.module,
            request.target.port,
        ),
    )
    driven: dict[EndpointRef, EndpointRef] = {}
    edges: list[ConnectionEdge] = []
    for order, request in enumerate(requests):
        source = _lookup(by_ref, request.source)
        target = _lookup(by_ref, request.target)
        if source.direction is not PortDirection.OUTPUT:
            raise InputValidationError(f"connection source {source.ref.label()} is not an output")
        if target.direction is not PortDirection.INPUT:
            raise InputValidationError(f"connection target {target.ref.label()} is not an input")
        if source.width != target.width:
            raise InputValidationError(
                f"connection width mismatch: {source.ref.label()} is {source.width} bit(s), "
                f"{target.ref.label()} is {target.width} bit(s)"
            )
        previous = driven.get(target.ref)
        if previous is not None:
            raise InputValidationError(
                f"multiple drivers for {target.ref.label()}: {previous.label()} and {source.ref.label()}"
            )
        if source.semantic and target.semantic and source.semantic != target.semantic:
            raise InputValidationError(
                f"connection semantic mismatch: {source.ref.label()} is {source.semantic!r}, "
                f"{target.ref.label()} is {target.semantic!r}"
            )
        driven[target.ref] = source.ref
        edges.append(
            ConnectionEdge(
                order=order,
                source=source.ref,
                target=target.ref,
                width=source.width,
                semantic=source.semantic or target.semantic,
                kind=request.kind,
                reason=_text(request.reason, "connection reason"),
                evidence_source=_text(request.evidence_source, "connection evidence_source"),
                confidence=_text(request.confidence, "connection confidence"),
            )
        )

    constraint_list = tuple(
        sorted(constraints, key=lambda item: (item.target.module, item.target.port, item.kind.value))
    )
    for constraint in constraint_list:
        endpoint = _lookup(by_ref, constraint.target)
        if endpoint.direction is not PortDirection.INPUT:
            raise InputValidationError(f"constraint target {endpoint.ref.label()} is not an input")
        if endpoint.ref in driven and constraint.kind is ConstraintKind.CONSTANT:
            raise InputValidationError(
                f"input {endpoint.ref.label()} cannot have both a connection and a constraint driver"
            )
        _text(constraint.expression, "constraint expression")
        _text(constraint.reason, "constraint reason")
        _text(constraint.evidence_source, "constraint evidence_source")
        _text(constraint.confidence, "constraint confidence")
    return SystemGraph(
        endpoints=tuple(sorted(endpoint_list, key=lambda item: item.ref)),
        connections=tuple(edges),
        constraints=constraint_list,
    )


def _validate_endpoint(endpoint: SignalEndpoint) -> None:
    _text(endpoint.ref.module, "endpoint module")
    _text(endpoint.ref.port, "endpoint port")
    if isinstance(endpoint.width, bool) or not isinstance(endpoint.width, int) or endpoint.width <= 0:
        raise InputValidationError(f"{endpoint.ref.label()}: width must be an integer greater than zero")
    if endpoint.semantic is not None:
        _text(endpoint.semantic, "endpoint semantic")


def _lookup(endpoints: dict[EndpointRef, SignalEndpoint], ref: EndpointRef) -> SignalEndpoint:
    try:
        return endpoints[ref]
    except KeyError as exc:
        raise InputValidationError(f"unknown endpoint {ref.label()}") from exc


def _kind_order(kind: ConnectionKind) -> int:
    try:
        return list(ConnectionKind).index(ConnectionKind(kind))
    except (TypeError, ValueError) as exc:
        raise InputValidationError(f"unknown connection kind {kind!r}") from exc


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{label}: expected a non-empty string")
    return value
