"""Conservative bounded shrinking of static dependency groups."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Hashable, Protocol

from .csr import CsrGraph
from .graph import DependencyNode
from .replay import ReplayObservation, ReplayQueue


MAX_DYNAMIC_GROUPS = 64


class StaticGroupGraph(Protocol):
    group_ids: tuple[DependencyNode, ...]
    diagnostics: tuple[str, ...]


ReplayFunction = Callable[[int, tuple[DependencyNode, ...], int], ReplayObservation]


@dataclass(frozen=True, slots=True)
class ActiveDependencyView:
    """A bounded epoch view over edges that remain active in one CSR graph."""

    static_graph: CsrGraph
    active_edges: frozenset[tuple[int, int]]
    epoch: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.static_graph, CsrGraph):
            raise TypeError("static_graph must be a CsrGraph")
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 0:
            raise ValueError("epoch must be a non-negative integer")
        declared = frozenset(
            (source, self.static_graph.indices[offset])
            for source in range(len(self.static_graph.node_ids))
            for offset in range(
                self.static_graph.indptr[source],
                self.static_graph.indptr[source + 1],
            )
        )
        normalized = frozenset(self.active_edges)
        if any(
            isinstance(source, bool)
            or isinstance(target, bool)
            or not isinstance(source, int)
            or not isinstance(target, int)
            for source, target in normalized
        ):
            raise ValueError("active dependency edges must use integer CSR indices")
        if not normalized <= declared:
            raise ValueError("active dependency view references an unknown CSR edge")
        object.__setattr__(self, "active_edges", normalized)

    @classmethod
    def all_active(cls, static_graph: CsrGraph, *, epoch: int = 0) -> "ActiveDependencyView":
        edges = frozenset(
            (source, static_graph.indices[offset])
            for source in range(len(static_graph.node_ids))
            for offset in range(static_graph.indptr[source], static_graph.indptr[source + 1])
        )
        return cls(static_graph, edges, epoch)

    def is_active(self, source_index: int, target_index: int) -> bool:
        return (source_index, target_index) in self.active_edges


@dataclass(frozen=True, slots=True)
class ShrinkBudget:
    """Finite replay limits used by one dynamic shrink pass."""

    seed: int = 0
    cycles: int = 1
    repeat_count: int = 2
    max_replays: int = 256
    queue_capacity: int = 128
    diagnostic_capacity: int = 128
    required_liveness_predicates: frozenset[Hashable] = frozenset()

    def __post_init__(self) -> None:
        for name in ("cycles", "repeat_count", "max_replays", "queue_capacity", "diagnostic_capacity"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        object.__setattr__(self, "required_liveness_predicates", frozenset(self.required_liveness_predicates))

    @property
    def repeats(self) -> int:
        return self.repeat_count


ReplayBudget = ShrinkBudget


@dataclass(frozen=True, slots=True)
class ShrinkResult:
    """Active group view plus the immutable static fallback and bounded evidence."""

    static_graph: StaticGroupGraph
    static_groups: tuple[DependencyNode, ...]
    enabled_groups: tuple[DependencyNode, ...]
    removed_groups: tuple[DependencyNode, ...]
    replay_count: int
    observations: tuple[ReplayObservation, ...]
    diagnostics: tuple[str, ...]
    used_static_fallback: bool

    @property
    def retained_groups(self) -> tuple[DependencyNode, ...]:
        return self.enabled_groups

    @property
    def groups(self) -> tuple[DependencyNode, ...]:
        return self.enabled_groups

    @property
    def replay_log(self) -> tuple[ReplayObservation, ...]:
        return self.observations


class _BoundedDiagnostics:
    def __init__(self, capacity: int, initial: tuple[str, ...]) -> None:
        self._items: deque[str] = deque(maxlen=capacity)
        for item in sorted(initial):
            self._items.append(item)

    def append(self, message: str) -> None:
        self._items.append(message)

    def items(self) -> tuple[str, ...]:
        return tuple(self._items)


def _group_label(group: DependencyNode) -> str:
    return f"{group.kind}:{group.components!r}"


def _same_observations(observations: list[ReplayObservation]) -> bool:
    first = observations[0]
    return all(
        observation.coverage_signature == first.coverage_signature
        and observation.liveness_predicates == first.liveness_predicates
        for observation in observations[1:]
    )


def shrink_groups(
    static_graph: StaticGroupGraph,
    replay_fn: ReplayFunction,
    budget: ShrinkBudget | Mapping[str, object],
) -> ShrinkResult:
    """Remove groups only after repeatable same-seed replay preserves behavior."""
    if isinstance(budget, Mapping):
        budget = ShrinkBudget(**budget)
    if not isinstance(budget, ShrinkBudget):
        raise TypeError("budget must be a ShrinkBudget or mapping")
    static_groups = tuple(sorted(static_graph.group_ids))
    if len(set(static_groups)) != len(static_groups):
        raise ValueError("static dependency graph contains duplicate groups")
    if any(not isinstance(group, DependencyNode) for group in static_groups):
        raise ValueError("dynamic shrinking requires structured DependencyNode group identities")

    diagnostics = _BoundedDiagnostics(budget.diagnostic_capacity, tuple(static_graph.diagnostics))
    queue = ReplayQueue(budget.queue_capacity)
    replay_count = 0

    def result(
        enabled: tuple[DependencyNode, ...],
        removed: tuple[DependencyNode, ...],
        fallback: bool,
    ) -> ShrinkResult:
        return ShrinkResult(
            static_graph=static_graph,
            static_groups=static_groups,
            enabled_groups=enabled,
            removed_groups=removed,
            replay_count=replay_count,
            observations=queue.items,
            diagnostics=diagnostics.items(),
            used_static_fallback=fallback,
        )

    if len(static_groups) > MAX_DYNAMIC_GROUPS:
        diagnostics.append(
            f"dynamic shrink requires at most {MAX_DYNAMIC_GROUPS} groups; retaining static groups"
        )
        return result(static_groups, (), True)

    def replay(enabled: tuple[DependencyNode, ...]) -> ReplayObservation | None:
        nonlocal replay_count
        if replay_count >= budget.max_replays:
            return None
        replay_count += 1
        try:
            observation = replay_fn(budget.seed, enabled, budget.cycles)
            if not isinstance(observation, ReplayObservation):
                raise TypeError("replay function returned a non-ReplayObservation value")
        except Exception:
            observation = ReplayObservation(None, crashed=True)
        queue.append(observation)
        return observation

    baseline = [replay(static_groups) for _ in range(budget.repeat_count)]
    if any(observation is None for observation in baseline):
        diagnostics.append("baseline replay budget exhausted; retaining static groups")
        return result(static_groups, (), True)
    baseline_observations = [observation for observation in baseline if observation is not None]
    if any(not observation.conclusive for observation in baseline_observations):
        diagnostics.append("baseline replay inconclusive; retaining static groups")
        return result(static_groups, (), True)
    if not _same_observations(baseline_observations):
        diagnostics.append("baseline replay is not reproducible; retaining static groups")
        return result(static_groups, (), True)

    baseline_observation = baseline_observations[0]
    required_liveness = (
        budget.required_liveness_predicates
        if budget.required_liveness_predicates
        else baseline_observation.liveness_predicates
    )
    if not required_liveness <= baseline_observation.liveness_predicates:
        diagnostics.append("baseline replay misses required liveness predicates; retaining static groups")
        return result(static_groups, (), True)

    enabled = static_groups
    removed: list[DependencyNode] = []
    fallback = False
    for group in static_groups:
        candidate = tuple(item for item in enabled if item != group)
        attempts = [replay(candidate) for _ in range(budget.repeat_count)]
        if any(observation is None for observation in attempts):
            diagnostics.append("candidate replay budget exhausted; retaining remaining static groups")
            fallback = True
            break
        observations = [observation for observation in attempts if observation is not None]
        label = _group_label(group)
        if any(not observation.conclusive for observation in observations):
            diagnostics.append(f"group {label} replay inconclusive; group retained")
            fallback = True
            continue
        if not _same_observations(observations):
            diagnostics.append(f"group {label} replay is not reproducible; group retained")
            fallback = True
            continue
        if any(
            observation.coverage_signature != baseline_observation.coverage_signature
            for observation in observations
        ):
            diagnostics.append(f"group {label} coverage loss vetoed removal")
            continue
        if any(not required_liveness <= observation.liveness_predicates for observation in observations):
            diagnostics.append(f"group {label} liveness loss vetoed removal")
            continue
        enabled = candidate
        removed.append(group)

    return result(enabled, tuple(removed), fallback)
