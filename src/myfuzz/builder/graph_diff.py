"""Fail-closed planned-versus-realized semantic graph comparison."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .contracts import SystemIR
from .graph import (
    ConnectionEdge, ConnectionKind, ConnectionRequest, EndpointRef, SignalEndpoint,
    SystemGraph, build_system_graph,
)
from .input_model import InputValidationError, PortDirection
from .rtl_analysis import RTLAnalysis


@dataclass(frozen=True)
class EdgeEquivalence:
    planned: tuple[EndpointRef, EndpointRef]
    realized: tuple[EndpointRef, EndpointRef]
    rule: str
    evidence: str


@dataclass(frozen=True)
class GraphDiff:
    equivalent: bool
    missing_edges: tuple[str, ...]
    unexpected_edges: tuple[str, ...]
    endpoint_mismatches: tuple[str, ...]
    evidence: tuple[EdgeEquivalence, ...]


def compare_planned_realized(
    planned: SystemGraph,
    realized: SystemGraph,
    equivalences: tuple[EdgeEquivalence, ...] = (),
) -> GraphDiff:
    """Compare canonical endpoint/edge semantics; no unlisted transformation is accepted."""
    planned_endpoints = {(item.ref, item.direction, item.width, item.semantic) for item in planned.endpoints}
    realized_endpoints = {(item.ref, item.direction, item.width, item.semantic) for item in realized.endpoints}
    endpoint_mismatches = set(planned_endpoints ^ realized_endpoints)
    planned_edges = {_edge_key(item) for item in planned.connections}
    realized_edges = {_edge_key(item) for item in realized.connections}
    mapped_planned: set[tuple[EndpointRef, EndpointRef, int, str | None, str]] = set()
    mapped_realized: set[tuple[EndpointRef, EndpointRef, int, str | None, str]] = set()
    evidence: list[EdgeEquivalence] = []
    for equivalence in equivalences:
        if not equivalence.rule.strip() or not equivalence.evidence.strip():
            raise InputValidationError("graph equivalence requires rule and evidence")
        source = next((edge for edge in planned_edges if edge[:2] == equivalence.planned), None)
        target = next((edge for edge in realized_edges if edge[:2] == equivalence.realized), None)
        if source is None or target is None:
            raise InputValidationError("graph equivalence references an absent planned or realized edge")
        if source[2:] != target[2:]:
            raise InputValidationError("graph equivalence changes width, semantic, or kind")
        mapped_planned.add(source)
        mapped_realized.add(target)
        endpoint_mismatches = {
            item for item in endpoint_mismatches
            if item[0] not in equivalence.planned and item[0] not in equivalence.realized
        }
        evidence.append(equivalence)
    missing = planned_edges - realized_edges - mapped_planned
    unexpected = realized_edges - planned_edges - mapped_realized
    return GraphDiff(
        not endpoint_mismatches and not missing and not unexpected,
        tuple(sorted(_edge_label(edge) for edge in missing)),
        tuple(sorted(_edge_label(edge) for edge in unexpected)),
        tuple(sorted(_endpoint_label(item) for item in endpoint_mismatches)),
        tuple(sorted(evidence, key=lambda item: (item.planned, item.realized))),
    )


def require_equivalent(planned: SystemGraph, realized: SystemGraph, equivalences: tuple[EdgeEquivalence, ...] = ()) -> GraphDiff:
    result = compare_planned_realized(planned, realized, equivalences)
    if not result.equivalent:
        details = list(result.endpoint_mismatches) + list(result.missing_edges) + list(result.unexpected_edges)
        raise InputValidationError("planned-versus-realized graph mismatch: " + "; ".join(details))
    return result


def graph_from_system_ir(ir: SystemIR) -> SystemGraph:
    """Build the planned graph exclusively from explicit SystemIR connection facts."""
    ports: dict[EndpointRef, SignalEndpoint] = {}
    for module_index, module in enumerate(ir.modules):
        logical_name = _identifier(module.get("name"), f"modules[{module_index}].name")
        raw_ports = module.get("ports")
        if not isinstance(raw_ports, (tuple, list)):
            raise InputValidationError(f"modules[{module_index}].ports: expected an array")
        for port_index, port in enumerate(raw_ports):
            if not isinstance(port, Mapping):
                raise InputValidationError(f"modules[{module_index}].ports[{port_index}]: expected an object")
            ref = EndpointRef(
                logical_name,
                _identifier(port.get("name"), f"modules[{module_index}].ports[{port_index}].name"),
            )
            if ref in ports:
                raise InputValidationError(f"duplicate endpoint {ref.label()}")
            try:
                direction = PortDirection(port.get("direction"))
            except ValueError as exc:
                raise InputValidationError(f"{ref.label()}: invalid direction") from exc
            width = port.get("width")
            if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
                raise InputValidationError(f"{ref.label()}: invalid width")
            semantic = port.get("semantic")
            if semantic is not None and (not isinstance(semantic, str) or not semantic.strip()):
                raise InputValidationError(f"{ref.label()}: invalid semantic")
            ports[ref] = SignalEndpoint(ref, direction, width, semantic)

    requests: list[ConnectionRequest] = []
    connected: set[EndpointRef] = set()
    for index, connection in enumerate(ir.connections):
        source = _endpoint(connection.get("source"), f"connections[{index}].source")
        target = _endpoint(connection.get("target"), f"connections[{index}].target")
        try:
            kind = ConnectionKind(connection.get("kind", ConnectionKind.DATA.value))
        except ValueError as exc:
            raise InputValidationError(f"connections[{index}].kind: invalid connection kind") from exc
        requests.append(ConnectionRequest(
            source, target, kind,
            str(connection.get("reason", "explicit SystemIR connection")),
            str(connection.get("evidence_source", "system_ir")),
            str(connection.get("confidence", "declared")),
        ))
        connected.update((source, target))
    return build_system_graph((ports[ref] for ref in connected), requests)


def realized_graph_from_analysis(
    planned: SystemGraph,
    analysis: RTLAnalysis,
    instance_names: Mapping[str, str],
) -> SystemGraph:
    """Reconstruct direct instance-to-instance edges from elaborated AST pin bindings."""
    top = next(
        (module for module in analysis.modules if module.top or module.name == analysis.top_module
         or module.original_name == analysis.top_module),
        None,
    )
    if top is None:
        raise InputValidationError(f"realized graph: analyzed top {analysis.top_module!r} is missing")
    by_ref = {endpoint.ref: endpoint for endpoint in planned.endpoints}
    bindings: dict[str, list[SignalEndpoint]] = {}
    seen: set[EndpointRef] = set()
    realized_instances = {instance.name for instance in top.instances}
    missing_instances = set(instance_names) - realized_instances
    if missing_instances:
        raise InputValidationError(
            "realized graph: missing instance(s): " + ", ".join(sorted(missing_instances))
        )
    for instance in top.instances:
        logical_name = instance_names.get(instance.name)
        if logical_name is None:
            raise InputValidationError(f"realized graph: unexpected top instance {instance.name!r}")
        for pin in instance.pins:
            ref = EndpointRef(logical_name, pin.port)
            expected = by_ref.get(ref)
            if expected is None:
                continue
            if pin.direction is not expected.direction or pin.width != expected.width:
                raise InputValidationError(
                    f"realized graph: pin fact mismatch for {ref.label()}"
                )
            if len(pin.signals) != 1 or pin.expression_kind not in {"VARREF", "VARXREF"}:
                raise InputValidationError(
                    f"realized graph: {ref.label()} requires an explicit equivalence for "
                    f"{pin.expression_kind} with {len(pin.signals)} signal(s)"
                )
            bindings.setdefault(pin.signals[0], []).append(expected)
            seen.add(ref)
    missing_endpoints = set(by_ref) - seen
    if missing_endpoints:
        raise InputValidationError(
            "realized graph: missing pin binding(s): "
            + ", ".join(sorted(ref.label() for ref in missing_endpoints))
        )

    planned_edges = {(edge.source, edge.target): edge for edge in planned.connections}
    requests: list[ConnectionRequest] = []
    realized_endpoints: set[SignalEndpoint] = set()
    for signal, endpoints in sorted(bindings.items()):
        sources = [item for item in endpoints if item.direction is PortDirection.OUTPUT]
        targets = [item for item in endpoints if item.direction is PortDirection.INPUT]
        if not sources or not targets:
            continue
        if len(sources) != 1:
            raise InputValidationError(f"realized graph: signal {signal!r} has {len(sources)} output drivers")
        source = sources[0]
        for target in targets:
            planned_edge = planned_edges.get((source.ref, target.ref))
            kind = planned_edge.kind if planned_edge else ConnectionKind.DATA
            requests.append(ConnectionRequest(
                source.ref, target.ref, kind,
                f"elaborated shared net {signal}", "verilator_ast", "proven",
            ))
            realized_endpoints.update((source, target))
    return build_system_graph(realized_endpoints, requests)


def verify_realized_system_ir(
    ir: SystemIR,
    analysis: RTLAnalysis,
    equivalences: tuple[EdgeEquivalence, ...] = (),
) -> GraphDiff:
    planned = graph_from_system_ir(ir)
    instance_names = {
        _identifier(module.get("instance"), f"modules[{index}].instance"):
        _identifier(module.get("name"), f"modules[{index}].name")
        for index, module in enumerate(ir.modules)
    }
    realized = realized_graph_from_analysis(planned, analysis, instance_names)
    return require_equivalent(planned, realized, equivalences)


def _edge_key(edge: ConnectionEdge) -> tuple[EndpointRef, EndpointRef, int, str | None, str]:
    return edge.source, edge.target, edge.width, edge.semantic, edge.kind.value


def _edge_label(edge: tuple[EndpointRef, EndpointRef, int, str | None, str]) -> str:
    return f"{edge[0].label()}->{edge[1].label()}:{edge[2]}:{edge[3] or '-'}:{edge[4]}"


def _endpoint_label(item: tuple[EndpointRef, object, int, str | None]) -> str:
    return f"{item[0].label()}:{getattr(item[1], 'value', item[1])}:{item[2]}:{item[3] or '-'}"


def _identifier(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.isidentifier():
        raise InputValidationError(f"{path}: expected an identifier")
    return value


def _endpoint(value: object, path: str) -> EndpointRef:
    if not isinstance(value, str) or value.count(".") != 1:
        raise InputValidationError(f"{path}: expected module.port")
    module, port = value.split(".")
    return EndpointRef(_identifier(module, path), _identifier(port, path))
