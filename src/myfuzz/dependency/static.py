"""Build a conservative dependency graph from explicit protocol and RTL facts."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from myfuzz.protocols.model import CompiledProtocol

from .graph import DependencyEdge, DependencyGraph


MAX_FIELD_GROUPS = 64


def _string_ids(value: object, label: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label} must be an array of non-empty explicit IDs")
    return frozenset(value)


def _edge_records(facts: Mapping[str, object], key: str, kind: str) -> Iterable[tuple[str, str, str, str]]:
    records = facts.get(key, [])
    if not isinstance(records, list):
        raise ValueError(f"{key} must be an array")
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValueError(f"{key}[{index}] must be an object")
        source, target = record.get("source_port_id"), record.get("target_port_id")
        if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
            raise ValueError(f"{key}[{index}] requires explicit source_port_id and target_port_id")
        evidence_id = record.get("evidence_id", f"{key}:{index:06d}")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError(f"{key}[{index}].evidence_id must be a non-empty ID")
        edge_kind = kind
        if key == "adapter_edges":
            adapter_id = record.get("adapter_id")
            if not isinstance(adapter_id, str) or not adapter_id:
                raise ValueError(f"{key}[{index}].adapter_id must be a non-empty explicit ID")
            edge_kind = f"adapter:{adapter_id}"
        yield source, target, edge_kind, evidence_id


def _field_groups(compiled_protocols: Iterable[CompiledProtocol]) -> list[tuple[str, str, str]]:
    fields: list[tuple[str, str, str]] = []
    for protocol in compiled_protocols:
        for field in protocol.fields:
            if field.direction == "host_to_device":
                fields.append((f"group:{protocol.binding_id}:{field.field_id}", field.port_id, field.field_id))
    return sorted(fields)


def _coalesce(groups: list[tuple[str, str, str]]) -> tuple[list[tuple[str, tuple[str, ...]]], tuple[str, ...]]:
    if len(groups) <= MAX_FIELD_GROUPS:
        return [(group_id, (port_id,)) for group_id, port_id, _ in groups], ()
    kept = [(group_id, (port_id,)) for group_id, port_id, _ in groups[: MAX_FIELD_GROUPS - 1]]
    coalesced_ports = tuple(port_id for _, port_id, _ in groups[MAX_FIELD_GROUPS - 1 :])
    kept.append(("group:coalesced:000", coalesced_ports))
    return kept, (f"coalesced dependency groups from {len(groups)} to {MAX_FIELD_GROUPS}",)


def build_static_graph(facts: object, compiled_protocols: Iterable[CompiledProtocol]) -> DependencyGraph:
    """Return all explicit structural dependencies, excluding declared non-data endpoints."""
    if not isinstance(facts, Mapping):
        raise ValueError("facts must be an object")
    excluded = (
        _string_ids(facts.get("clock_port_ids"), "clock_port_ids")
        | _string_ids(facts.get("reset_port_ids"), "reset_port_ids")
        | _string_ids(facts.get("external_endpoint_port_ids"), "external_endpoint_port_ids")
    )
    groups, diagnostics = _coalesce(_field_groups(compiled_protocols))
    nodes = {group_id for group_id, _ in groups}
    edges: list[DependencyEdge] = []
    for group_id, ports in groups:
        for port_id in ports:
            if port_id in excluded:
                continue
            nodes.add(f"port:{port_id}")
            edges.append(DependencyEdge(group_id, f"port:{port_id}", "declared_field", group_id))
    for key, kind in (("dataflow_edges", "rtl_dataflow"), ("control_edges", "rtl_control"), ("adapter_edges", "adapter")):
        for source, target, edge_kind, evidence_id in _edge_records(facts, key, kind):
            if source in excluded or target in excluded:
                continue
            nodes.add(f"port:{source}")
            nodes.add(f"port:{target}")
            edges.append(DependencyEdge(f"port:{source}", f"port:{target}", edge_kind, evidence_id))
    return DependencyGraph(
        node_ids=tuple(sorted(nodes)),
        group_ids=tuple(group_id for group_id, _ in groups),
        edges=tuple(sorted(edges, key=lambda edge: (edge.source_id, edge.target_id, edge.kind, edge.evidence_id))),
        diagnostics=diagnostics,
    )
