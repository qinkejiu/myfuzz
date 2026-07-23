"""Deterministic, memory-bounded composition candidate search."""

from __future__ import annotations

import heapq
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace

from myfuzz.contracts import canonical_bytes, content_hash

from .address import AddressAllocationError, AddressRegion, allocate_regions, extract_local_regions
from .constraints import ConstraintGraph, EdgeCandidate, Evidence, build_constraint_graph, candidate_edges, reject_hard_conflicts
from .declarations import DeclarationSet
from .facts import HdlFacts


@dataclass(frozen=True, slots=True)
class CompositionCandidate:
    candidate_id: str
    parent_input_hash: str
    graph_hash: str
    score_vector: tuple[int, ...]
    graph: ConstraintGraph
    declarations: DeclarationSet
    edges: tuple[EdgeCandidate, ...]
    address_regions: tuple[AddressRegion, ...]
    unresolved_optional_endpoint_ids: tuple[int, ...]
    evidence: tuple[Evidence, ...]
    assumptions: tuple[dict[str, object], ...]
    rejected_alternatives: tuple[dict[str, object], ...]


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def _edge_signature(edge: EdgeCandidate) -> tuple[object, ...]:
    return (
        edge.kind,
        edge.source_endpoint_id,
        edge.target_endpoint_id or 0,
        edge.adapter or "",
        tuple(sorted((field.role, field.source_port_id, field.target_port_id, field.source_width, field.target_width) for field in edge.fields)),
    )


def _graph_document(
    edges: tuple[EdgeCandidate, ...],
    regions: tuple[AddressRegion, ...],
    unresolved: tuple[int, ...],
) -> dict[str, object]:
    return {
        "connections": [
            {
                "source_endpoint_id": edge.source_endpoint_id,
                "target_endpoint_id": edge.target_endpoint_id,
                "adapter": edge.adapter,
                "fields": [
                    {
                        "source_port_id": field.source_port_id,
                        "target_port_id": field.target_port_id,
                        "source_width": field.source_width,
                        "target_width": field.target_width,
                        "role": field.role,
                    }
                    for field in sorted(edge.fields, key=lambda item: (item.role, item.source_port_id, item.target_port_id, item.source_width, item.target_width))
                ],
            }
            for edge in sorted(edges, key=_edge_signature)
            if edge.kind == "connection"
        ],
        "address_regions": [
            {
                "component_id": region.component_id,
                "port_id": region.port_id,
                "base": region.base,
                "size": region.size,
                "local_offset": region.local_offset,
                "provenance": region.provenance,
            }
            for region in sorted(regions, key=lambda item: (item.component_id, item.port_id, item.base, item.local_offset, item.size))
        ],
        "external_endpoint_ids": sorted(unresolved),
    }


def _parent_hash(graph: ConstraintGraph, declarations: DeclarationSet, regions: tuple[AddressRegion, ...]) -> str:
    document = {
        "ports": [(port.id, port.component_id, port.direction, port.width, port.signed, port.role, port.required) for port in graph.ports],
        "endpoints": [
            (
                endpoint.id,
                endpoint.component_id,
                endpoint.protocol_id,
                endpoint.side,
                [(field.role, field.port_id, field.protocol_direction, field.width) for field in endpoint.fields],
                endpoint.required,
                list(endpoint.clock_domain_ids),
                list(endpoint.reset_domain_ids),
            )
            for endpoint in graph.endpoints
        ],
        "components": [
            (
                component.id,
                component.module_id,
                component.role,
                [(port.port_id, port.role, port.required) for port in component.ports],
            )
            for component in declarations.components
        ],
        "protocols": [
            (
                protocol.protocol_id,
                list(protocol.endpoint_roles),
                [(field.role, field.direction, field.minimum_width, field.maximum_width, field.required) for field in protocol.fields],
                [(rule.kind, rule.source_protocol_id, rule.target_protocol_id, rule.allows_width_mismatch) for rule in protocol.legal_adapters],
            )
            for protocol in graph.protocols
        ],
        "address_regions": [(region.component_id, region.port_id, region.base, region.size, region.local_offset, region.provenance) for region in regions],
        "evidence": [(item.kind, item.ordinal, _json_value(item.record)) for item in graph.evidence],
    }
    return content_hash(document)


def _candidate_assumptions(
    graph: ConstraintGraph,
    edges: tuple[EdgeCandidate, ...],
    regions: tuple[AddressRegion, ...],
    unresolved: tuple[int, ...],
) -> tuple[dict[str, object], ...]:
    endpoint_by_id = {endpoint.id: endpoint for endpoint in graph.endpoints}
    result: list[dict[str, object]] = []
    for edge in edges:
        target_id = edge.target_endpoint_id
        if target_id is None:
            continue
        if not endpoint_by_id[edge.source_endpoint_id].required or not endpoint_by_id[target_id].required:
            result.append({"kind": "optional_endpoint_connection", "provenance": "assumed", "source_endpoint_id": edge.source_endpoint_id, "target_endpoint_id": target_id})
        else:
            result.append({"kind": "endpoint_connection", "provenance": "inferred", "source_endpoint_id": edge.source_endpoint_id, "target_endpoint_id": target_id})
    for endpoint_id in unresolved:
        result.append({"kind": "optional_endpoint_externalized", "provenance": "assumed", "endpoint_id": endpoint_id})
    for region in regions:
        if region.provenance == "inferred":
            result.append({"kind": "address_base", "provenance": "inferred", "component_id": region.component_id, "port_id": region.port_id, "base": region.base})
    return tuple(sorted(result, key=canonical_bytes))


def _record_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, tuple) and all(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str) for item in value):
        return dict(value)
    return None


def _unvalidated_clock_reset_associations(facts: HdlFacts, declarations: DeclarationSet) -> int:
    declared = {
        (component.id, item.port_id, item.kind, item.domain_id)
        for component in declarations.components
        for item in component.clock_reset
    }
    validated: set[tuple[int, int, str, int]] = set()
    for section, records in facts.structural_sections:
        if section != "clock_reset_checks":
            continue
        for record in records:
            item = _record_mapping(record)
            if item is None or item.get("structurally_validated") is not True:
                continue
            component_id = item.get("component_id")
            port_id = item.get("port_id")
            kind = item.get("kind")
            domain_id = item.get("domain_id")
            if not isinstance(component_id, int) or not isinstance(port_id, int) or kind not in ("clock", "reset") or not isinstance(domain_id, int):
                continue
            association = (component_id, port_id, kind, domain_id)
            if association in declared:
                validated.add(association)
    return len(declared - validated)


def _score(
    graph: ConstraintGraph,
    facts: HdlFacts,
    declarations: DeclarationSet,
    edges: tuple[EdgeCandidate, ...],
    regions: tuple[AddressRegion, ...],
    graph_hash: str,
) -> tuple[int, ...]:
    # Unsafe adapters never survive graph hard-constraint rejection. Declared
    # legal adapters therefore do not contribute to this score tier.
    unsafe_width_adapters = 0
    unvalidated_clock_reset_associations = _unvalidated_clock_reset_associations(facts, declarations)
    if regions:
        lowest = min(region.base for region in regions)
        highest = max(region.base + region.size for region in regions)
        address_waste = highest - lowest - sum(region.size for region in regions)
    else:
        address_waste = 0
    protocol_evidence = sum(len(edge.fields) for edge in edges)
    rtl_evidence = sum(len(edge.evidence) for edge in edges)
    return (0, 0, unsafe_width_adapters, unvalidated_clock_reset_associations, address_waste, -protocol_evidence, -rtl_evidence, int(graph_hash[7:], 16))


def _make_candidate(
    graph: ConstraintGraph,
    facts: HdlFacts,
    declarations: DeclarationSet,
    all_edges: tuple[EdgeCandidate, ...],
    selected: tuple[EdgeCandidate, ...],
    regions: tuple[AddressRegion, ...],
    parent_input_hash: str,
    address_evidence: tuple[Evidence, ...],
) -> CompositionCandidate:
    endpoint_by_id = {endpoint.id: endpoint for endpoint in graph.endpoints}
    connected = {endpoint_id for edge in selected for endpoint_id in (edge.source_endpoint_id, edge.target_endpoint_id) if endpoint_id is not None}
    unresolved = tuple(endpoint.id for endpoint in graph.endpoints if not endpoint.required and endpoint.id not in connected)
    graph_hash = content_hash(_graph_document(selected, regions, unresolved))
    selected_signatures = {_edge_signature(edge) for edge in selected}
    rejected = tuple(sorted((
        {
            "edge_id": edge.id,
            "source_endpoint_id": edge.source_endpoint_id,
            "target_endpoint_id": edge.target_endpoint_id,
            "reason": "not-selected",
            "provenance": "inferred",
        }
        for edge in all_edges
        if edge.kind == "connection" and _edge_signature(edge) not in selected_signatures
    ), key=canonical_bytes))
    evidence_by_key: dict[tuple[str, int, bytes], Evidence] = {
        (item.kind, item.ordinal, canonical_bytes(_json_value(item.record))): item
        for item in address_evidence
    }
    for edge in selected:
        for item in edge.evidence:
            key = (item.kind, item.ordinal, canonical_bytes(_json_value(item.record)))
            evidence_by_key[key] = item
    evidence = tuple(evidence_by_key[key] for key in sorted(evidence_by_key))
    assumptions = _candidate_assumptions(graph, selected, regions, unresolved)
    score = _score(graph, facts, declarations, selected, regions, graph_hash)
    return CompositionCandidate(
        "candidate-" + graph_hash[7:23],
        parent_input_hash,
        graph_hash,
        score,
        graph,
        declarations,
        selected,
        regions,
        unresolved,
        evidence,
        assumptions,
        rejected,
    )


def compose_topk(facts: HdlFacts, declarations: DeclarationSet, protocols: object, limit: int) -> Iterator[CompositionCandidate]:
    """Yield at most ``limit`` legal candidates in deterministic score order."""
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("limit:positive-integer-required")
    graph = build_constraint_graph(facts, declarations, protocols)
    if reject_hard_conflicts(graph):
        return

    try:
        local_regions = extract_local_regions(facts, declarations)
        allocated_regions = allocate_regions(local_regions, {})
    except AddressAllocationError:
        return
    regions = tuple(
        replace(
            region,
            provenance="inferred",
        )
        for region in allocated_regions
    )
    address_port_ids = {region.port_id for region in local_regions}
    address_evidence: list[Evidence] = []
    for section, records in facts.structural_sections:
        if section != "local_address_facts":
            continue
        for ordinal, record in enumerate(records):
            normalized = dict(record) if isinstance(record, tuple) else record
            if isinstance(normalized, Mapping) and any(normalized.get(key) in address_port_ids for key in ("address_field_port_id", "address_port_id")):
                address_evidence.append(Evidence(section, ordinal, record))

    normalized_edges: dict[tuple[object, ...], EdgeCandidate] = {}
    for edge in candidate_edges(graph):
        signature = _edge_signature(edge)
        previous = normalized_edges.get(signature)
        if previous is None or edge.id < previous.id:
            normalized_edges[signature] = edge
    all_edges = tuple(sorted(normalized_edges.values(), key=lambda edge: (edge.source_endpoint_id, edge.target_endpoint_id or 0, edge.id)))
    connection_edges = tuple(edge for edge in all_edges if edge.kind == "connection")
    by_source: dict[int, tuple[EdgeCandidate, ...]] = {}
    for endpoint in graph.endpoints:
        if endpoint.side == "initiator":
            by_source[endpoint.id] = tuple(edge for edge in connection_edges if edge.source_endpoint_id == endpoint.id)

    sources = tuple(endpoint for endpoint in graph.endpoints if endpoint.side == "initiator")
    required_targets = {endpoint.id for endpoint in graph.endpoints if endpoint.side == "target" and endpoint.required}
    parent_input_hash = _parent_hash(graph, declarations, regions)
    heap: list[tuple[tuple[int, ...], str, CompositionCandidate]] = []
    chosen: list[EdgeCandidate] = []
    used_targets: set[int] = set()

    def retain(candidate: CompositionCandidate) -> None:
        if any(item[2].graph_hash == candidate.graph_hash for item in heap):
            return
        reverse_score = tuple(-value for value in candidate.score_vector)
        item = (reverse_score, candidate.graph_hash, candidate)
        if len(heap) < limit:
            heapq.heappush(heap, item)
        elif candidate.score_vector < heap[0][2].score_vector:
            heapq.heapreplace(heap, item)

    def visit(position: int) -> None:
        if position == len(sources):
            if not required_targets.issubset(used_targets):
                return
            selected = tuple(chosen)
            retain(_make_candidate(graph, facts, declarations, all_edges, tuple(sorted(selected, key=_edge_signature)), regions, parent_input_hash, tuple(address_evidence)))
            return
        source = sources[position]
        for edge in by_source.get(source.id, ()):
            target_id = edge.target_endpoint_id
            if target_id is None or target_id in used_targets:
                continue
            chosen.append(edge)
            used_targets.add(target_id)
            visit(position + 1)
            used_targets.remove(target_id)
            chosen.pop()
        if not source.required:
            visit(position + 1)

    visit(0)
    for candidate in sorted((item[2] for item in heap), key=lambda item: item.score_vector):
        yield candidate


__all__ = ["CompositionCandidate", "compose_topk"]
