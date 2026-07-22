"""Deterministic compressed sparse row dependency graph representation."""

from __future__ import annotations

from dataclasses import dataclass

from .graph import DependencyGraph, DependencyNode


@dataclass(frozen=True, slots=True)
class CsrGraph:
    node_ids: tuple[DependencyNode, ...]
    group_ids: tuple[DependencyNode, ...]
    indptr: tuple[int, ...]
    indices: tuple[int, ...]
    edge_kinds: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    diagnostics: tuple[str, ...]


def to_csr(graph: DependencyGraph) -> CsrGraph:
    """Sort graph identifiers and adjacency without consulting identifier text."""
    node_ids = tuple(sorted(graph.node_ids))
    node_index = {node_id: index for index, node_id in enumerate(node_ids)}
    if len(node_index) != len(node_ids):
        raise ValueError("duplicate dependency node")
    ordered_edges = sorted(
        graph.edges,
        key=lambda edge: (edge.source_id, edge.target_id, edge.kind, edge.evidence_id),
    )
    for edge in ordered_edges:
        if edge.source_id not in node_index or edge.target_id not in node_index:
            raise ValueError(f"unknown dependency node in edge: {edge.source_id} -> {edge.target_id}")

    adjacency: list[list[tuple[int, str, str]]] = [[] for _ in node_ids]
    for edge in ordered_edges:
        adjacency[node_index[edge.source_id]].append(
            (node_index[edge.target_id], edge.kind, edge.evidence_id)
        )
    indptr = [0]
    indices: list[int] = []
    kinds: list[str] = []
    evidence: list[str] = []
    for entries in adjacency:
        for target, kind, evidence_id in entries:
            indices.append(target)
            kinds.append(kind)
            evidence.append(evidence_id)
        indptr.append(len(indices))
    return CsrGraph(
        node_ids=node_ids,
        group_ids=tuple(sorted(graph.group_ids)),
        indptr=tuple(indptr),
        indices=tuple(indices),
        edge_kinds=tuple(kinds),
        evidence_ids=tuple(evidence),
        diagnostics=tuple(sorted(graph.diagnostics)),
    )
