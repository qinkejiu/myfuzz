"""Serialization of composition candidates into composition_ir.v1."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .search import CompositionCandidate
from .metadata import sanitize_metadata, semantic_content_hash


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


def _adapter_evidence_id(edge: object) -> str:
    evidence = getattr(edge, "evidence")
    document = [
        {
            "kind": item.kind,
            "ordinal": item.ordinal,
            "record": _json_value(item.record),
        }
        for item in evidence
    ]
    if not document:
        document = [
            {
                "kind": "declared-adapter",
                "edge_id": getattr(edge, "id"),
                "source_endpoint_id": getattr(edge, "source_endpoint_id"),
                "target_endpoint_id": getattr(edge, "target_endpoint_id"),
            }
        ]
    return semantic_content_hash(document, context="composition.adapter_evidence")


def canonical_ir_document(document: Mapping[str, object]) -> dict[str, object]:
    """Return a path-free, JSON-compatible composition IR document.

    The protocol-composition generator uses the same canonicalization boundary
    as the existing candidate serializer.  Keeping it here prevents the two IR
    producers from growing subtly different ordering and metadata rules.
    """
    normalized = sanitize_metadata(_json_value(document), context="composition_ir.metadata")
    if not isinstance(normalized, dict):
        raise TypeError("composition IR document must be an object")
    return normalized


def canonical_ir_hash(document: Mapping[str, object]) -> str:
    """Hash a canonical composition IR document after metadata validation."""
    return semantic_content_hash(canonical_ir_document(document), context="composition_ir.hash")


def composition_ir(candidate: CompositionCandidate) -> dict[str, object]:
    """Return a deterministic, path-free composition_ir.v1 document."""
    graph = candidate.graph
    declarations = candidate.declarations
    component_by_id = {component.id: component for component in declarations.components}
    port_by_id = {port.id: port for port in graph.ports}
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
            for component in sorted(declarations.components, key=lambda item: item.id)
        ],
        "instances": [
            {"id": component.id, "component_id": component.id, "module_id": component.module_id, "role": component.role}
            for component in sorted(declarations.components, key=lambda item: item.id)
        ],
        "nets": sorted((
            {
                "id": _net_id(field.source_port_id, field.target_port_id),
                "source_port_id": field.source_port_id,
                "sink_port_ids": [field.target_port_id],
                "semantic_role": field.role,
            }
            for edge in candidate.edges
            for field in edge.fields
        ), key=lambda item: (item["id"], item["source_port_id"], item["sink_port_ids"], item["semantic_role"])),
        "endpoint_bindings": sorted([
            {
                "endpoint_id": endpoint.id,
                "component_id": endpoint.component_id,
                "protocol_id": endpoint.protocol_id,
                "version": endpoint.version,
                "side": endpoint.side,
                "parameters": _json_value(dict(endpoint.parameters)),
                "fields": [
                    {
                        "field_role": field.role,
                        "port_id": field.port_id,
                        "direction": port_by_id[field.port_id].direction,
                        "width": port_by_id[field.port_id].width,
                        "signed": port_by_id[field.port_id].signed,
                    }
                    for field in sorted(endpoint.fields, key=lambda item: (item.role, item.port_id))
                ],
            }
            for endpoint in graph.endpoints
        ], key=lambda item: item["endpoint_id"]),
        "adapters": sorted(
            [
                {
                    "edge_id": edge.id,
                    "adapter_id": f"adapter-{edge.id}",
                    "kind": edge.adapter,
                    "source_endpoint_id": edge.source_endpoint_id,
                    "target_endpoint_id": edge.target_endpoint_id,
                    "source_port_id": edge.fields[0].source_port_id,
                    "target_port_id": edge.fields[0].target_port_id,
                    "evidence_id": _adapter_evidence_id(edge),
                    "port_bindings": [
                        {
                            "field_role": field.role,
                            "source_port_id": field.source_port_id,
                            "target_port_id": field.target_port_id,
                            "source_width": field.source_width,
                            "target_width": field.target_width,
                        }
                        for field in edge.fields
                    ],
                    "shape_status": "resolved" if len(edge.fields) == 1 else "irreducible",
                    **(
                        {}
                        if len(edge.fields) == 1
                        else {
                            "shape_conflict": {
                                "reason": "adapter-spans-multiple-field-connections",
                                "field_count": len(edge.fields),
                            }
                        }
                    ),
                }
                for edge in candidate.edges
                if edge.adapter is not None and edge.fields
            ],
            key=lambda item: (
                item["source_endpoint_id"],
                item["target_endpoint_id"],
                item["edge_id"],
            ),
        ),
        "address_regions": sorted([
            {
                "component_id": region.component_id,
                "port_id": region.port_id,
                "base": region.base,
                "size": region.size,
                "local_offset": region.local_offset,
                "provenance": region.provenance,
            }
            for region in candidate.address_regions
        ], key=lambda item: (item["component_id"], item["port_id"], item["base"], item["local_offset"])),
        "clock_domains": sorted([
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
        ], key=lambda item: (item["component_id"], item["port_id"], item["domain_id"])),
        "reset_domains": sorted([
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
        ], key=lambda item: (item["component_id"], item["port_id"], item["domain_id"])),
        "external_ports": sorted([
            {
                "port_id": port.id,
                "component_id": port.component_id,
                "direction": port.direction,
                "width": port.width,
                "signed": port.signed,
                "semantic_role": port.role,
            }
            for port in graph.ports
            if port.id in external_port_ids
        ], key=lambda item: item["port_id"]),
        "unresolved_optional_endpoints": sorted(candidate.unresolved_optional_endpoint_ids),
        "evidence": sorted([
            {
                "kind": item.kind,
                "ordinal": item.ordinal,
                "record": _json_value(item.record),
                "provenance": "rtl",
            }
            for item in candidate.evidence
        ], key=lambda item: (item["kind"], item["ordinal"])),
        "assumptions": sorted((_json_value(item) for item in candidate.assumptions), key=lambda item: repr(item)),
        "rejected_alternatives": sorted((_json_value(item) for item in candidate.rejected_alternatives), key=lambda item: repr(item)),
        "score_vector": list(candidate.score_vector),
        "diagnostics": {"errors": [], "warnings": []},
    }
    # This lookup checks that every graph component has a retained declaration
    # without exposing any source identifier text.
    if any(endpoint.component_id not in component_by_id for endpoint in graph.endpoints):
        raise ValueError("candidate:endpoint-component-unresolved")
    return canonical_ir_document(document)


__all__ = ["canonical_ir_document", "canonical_ir_hash", "composition_ir"]
