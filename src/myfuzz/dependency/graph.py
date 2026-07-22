"""Immutable dependency graph records built from explicit declarations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    source_id: str
    target_id: str
    kind: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    node_ids: tuple[str, ...]
    group_ids: tuple[str, ...]
    edges: tuple[DependencyEdge, ...]
    diagnostics: tuple[str, ...]

    def outgoing(self, node_id: str) -> tuple[DependencyEdge, ...]:
        return tuple(edge for edge in self.edges if edge.source_id == node_id)
