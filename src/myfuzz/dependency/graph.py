"""Immutable dependency graph records built from explicit declarations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class DependencyNode:
    """A structural graph identity, never a concatenation of user-declared IDs."""

    kind: str
    components: tuple[str, ...]


def field_group_node(binding_id: str, field_id: str) -> DependencyNode:
    return DependencyNode("field_group", (binding_id, field_id))


def coalesced_group_node(index: int) -> DependencyNode:
    return DependencyNode("coalesced_field_group", (str(index),))


def port_node(port_id: str) -> DependencyNode:
    return DependencyNode("port", (port_id,))


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    source_id: DependencyNode
    target_id: DependencyNode
    kind: str
    evidence_id: str


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    node_ids: tuple[DependencyNode, ...]
    group_ids: tuple[DependencyNode, ...]
    edges: tuple[DependencyEdge, ...]
    diagnostics: tuple[str, ...]

    def outgoing(self, node_id: DependencyNode) -> tuple[DependencyEdge, ...]:
        return tuple(edge for edge in self.edges if edge.source_id == node_id)
