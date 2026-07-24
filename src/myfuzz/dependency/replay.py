"""Bounded replay observation records for dynamic dependency analysis."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Hashable


@dataclass(frozen=True, slots=True)
class ReplayObservation:
    """One deterministic replay outcome for an explicit group selection."""

    coverage_signature: Hashable
    liveness_predicates: frozenset[Hashable] = frozenset()
    reset_stable: bool = True
    timed_out: bool = False
    crashed: bool = False
    reproducible: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "liveness_predicates", frozenset(self.liveness_predicates or ()))

    @property
    def conclusive(self) -> bool:
        return self.reproducible and self.reset_stable and not self.timed_out and not self.crashed

    @property
    def coverage(self) -> Hashable:
        return self.coverage_signature

    @property
    def liveness(self) -> frozenset[Hashable]:
        return self.liveness_predicates


class ReplayQueue:
    """A deterministic FIFO retaining only the newest replay observations."""

    def __init__(self, capacity: int) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("replay queue capacity must be a positive integer")
        self._items: deque[ReplayObservation] = deque(maxlen=capacity)

    @property
    def capacity(self) -> int:
        assert self._items.maxlen is not None
        return self._items.maxlen

    def append(self, observation: ReplayObservation) -> None:
        if not isinstance(observation, ReplayObservation):
            raise TypeError("replay queue accepts ReplayObservation values")
        self._items.append(observation)

    @property
    def items(self) -> tuple[ReplayObservation, ...]:
        return tuple(self._items)
