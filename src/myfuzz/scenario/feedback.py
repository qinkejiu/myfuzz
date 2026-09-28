"""Bounded semantic targets evaluated only from observed local RTL outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class CoverageTarget:
    target_id: str
    component: str
    port: str
    mask: int
    value: int

    def __post_init__(self) -> None:
        if not self.target_id or not self.component or not self.port:
            raise ValueError("coverage target identity is required")
        if (isinstance(self.mask, bool) or not isinstance(self.mask, int)
                or self.mask < 1 or isinstance(self.value, bool)
                or not isinstance(self.value, int) or self.value < 0
                or self.value & ~self.mask):
            raise ValueError("coverage target predicate is invalid")


def observed_targets(events: Iterable[Mapping],
                     targets: tuple[CoverageTarget, ...]) -> frozenset[str]:
    hits: set[str] = set()
    for event in events:
        outputs = event.get("outputs")
        if not isinstance(outputs, dict):
            continue
        for target in targets:
            if event.get("component") != target.component:
                continue
            actual = outputs.get(target.port)
            if isinstance(actual, int) and not isinstance(actual, bool) \
                    and actual & target.mask == target.value:
                hits.add(target.target_id)
    return frozenset(hits)
