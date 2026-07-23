"""Serialization of composition candidates into composition_ir.v1."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .search import CompositionCandidate


def _json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def _net_id(source_port_id: int, target_port_id: int) -> int:
    digest = hashlib.sha256(f"net:{source_port_id}:{target_port_id}".encode("ascii")).digest()
    return max(1, int.from_bytes(digest[:8], "big"))


def composition_ir(candidate: CompositionCandidate) -> dict[str, object]:
    """Return a deterministic, path-free composition_ir.v1 document."""
    graph = candidate.graph
    declarations = candidate.declarations
    component_by_id = {component.id: component for component in declarations.components}
    unresolved = set(candidate.unresolved_optional_endpoint_ids)
    external_port_ids = {
        port.id
        for port in graph.ports
        if port.role in ("clock", "reset", "uninterpreted_external")
    }
    for endpoint in graph.endpoints:
        if endpoint.id in unresolved:
            external_port_ids.update(field.port_id for field in endpoint.fields)

    document: dict[str, object] = {
        "schema_version": "composition_ir.v1",
        "candidate_id": candidate.candidate_id,
        "parent_input_hash": candidate.parent_input_hash,
        "graph_hash": candidate.graph_hash,
        "components": [
            {"id": component.id, "module_id": component.module_id, "role": component.role}
            for component in declarations.components
        ],
        "instances": [],
        "nets": [
            {
                "id": _net_id(field.source_port_id, field.target_port_id),
                "source_port_id": field.source_port_id,
                "sink_port_ids": [field.target_port_id],
                "semantic_role": field.role,
            }
            for edge in candidate.edges
            for field in edge.fields
        ],
        "endpoint_bindings": [
            {
                "endpoint_id": endpoint.id,
                "component_id": endpoint.component_id,
                "protocol_id": endpoint.protocol_id,
                "side": endpoint.side,
                "fields": [{"field_role": field.role, "port_id": field.port_id} for field in endpoint.fields],
            }
            for endpoint in graph.endpoints
        ],
        "adapters": [
            {
                "edge_id": edge.id,
                "kind": edge.adapter,
                "source_endpoint_id": edge.source_endpoint_id,
                "target_endpoint_id": edge.target_endpoint_id,
            }
            for edge in candidate.edges
            if edge.adapter is not None
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
            for region in candidate.address_regions
        ],
        "clock_domains": [
            {
                "component_id": component.id,
                "port_id": item.port_id,
                "domain_id": item.domain_id,
                "active_level": item.active_level,
                "synchronous": item.synchronous,
            }
            for component in declarations.components
            for item in component.clock_reset
            if item.kind == "clock"
        ],
        "reset_domains": [
            {
                "component_id": component.id,
                "port_id": item.port_id,
                "domain_id": item.domain_id,
                "active_level": item.active_level,
                "synchronous": item.synchronous,
            }
            for component in declarations.components
            for item in component.clock_reset
            if item.kind == "reset"
        ],
        "external_ports": [
            {
                "port_id": port.id,
                "component_id": port.component_id,
                "direction": port.direction,
                "width": port.width,
                "semantic_role": port.role,
            }
            for port in graph.ports
            if port.id in external_port_ids
        ],
        "unresolved_optional_endpoints": list(candidate.unresolved_optional_endpoint_ids),
        "evidence": [
            {
                "kind": item.kind,
                "ordinal": item.ordinal,
                "record": _json_value(item.record),
                "provenance": "rtl",
            }
            for item in candidate.evidence
        ],
        "assumptions": [_json_value(item) for item in candidate.assumptions],
        "rejected_alternatives": [_json_value(item) for item in candidate.rejected_alternatives],
        "score_vector": list(candidate.score_vector),
        "diagnostics": {"errors": [], "warnings": []},
    }
    # This lookup checks that every graph component has a retained declaration
    # without exposing any source identifier text.
    if any(endpoint.component_id not in component_by_id for endpoint in graph.endpoints):
        raise ValueError("candidate:endpoint-component-unresolved")
    return document


__all__ = ["composition_ir"]
