"""Immutable search declarations and documentary observations, never authority."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Mapping


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def identifier(value):
    if type(value) is not str or not value or len(value) > 256 or value.strip() != value:
        raise ValueError("bounded nonempty identifier required")


def natural(value):
    if type(value) is not int or value < 0:
        raise ValueError("nonnegative integer required")


@dataclass(frozen=True)
class Observation:
    status: str
    value_class: str = "unknown"
    evidence_refs: tuple[str, ...] = ()
    epoch: int = 0
    reason: str = ""

    def __post_init__(self):
        if self.status not in ("satisfied", "refuted", "unknown"):
            raise ValueError("unknown observation status")
        identifier(self.value_class)
        natural(self.epoch)
        if type(self.evidence_refs) is not tuple or len(self.evidence_refs) > 128:
            raise ValueError("bounded evidence references required")
        for ref in self.evidence_refs:
            identifier(ref)
        if self.status != "unknown" and not self.evidence_refs:
            raise ValueError("known observation requires evidence")
        if type(self.reason) is not str or len(self.reason) > 1024:
            raise ValueError("bounded observation reason required")


@dataclass(frozen=True)
class Snapshot:
    epoch: int
    observations: Mapping[str, Observation]

    def __post_init__(self):
        natural(self.epoch)
        if not isinstance(self.observations, Mapping) or len(self.observations) > 128:
            raise ValueError("bounded observations required")
        for key, value in self.observations.items():
            identifier(key)
            if type(value) is not Observation:
                raise ValueError("documentary Observation required")
        object.__setattr__(self, "observations", MappingProxyType(dict(self.observations)))

    def get(self, key) -> Observation:
        value = self.observations.get(key)
        if value is None:
            return Observation("unknown", epoch=self.epoch, reason="unobserved")
        if value.epoch != self.epoch:
            return Observation("unknown", epoch=self.epoch, reason="epoch-mismatch")
        return value


@dataclass(frozen=True)
class Condition:
    id: str
    prerequisites: tuple[str, ...] = ()
    mode: str = "effect"

    def __post_init__(self):
        identifier(self.id)
        if type(self.prerequisites) is not tuple or len(self.prerequisites) > 128:
            raise ValueError("bounded prerequisite tuple required")
        for item in self.prerequisites:
            identifier(item)
        if len(set(self.prerequisites)) != len(self.prerequisites):
            raise ValueError("duplicate prerequisite")
        if self.mode not in ("effect", "all", "any") or (
                self.mode != "effect" and not self.prerequisites):
            raise ValueError("invalid condition mode")


@dataclass(frozen=True)
class Goal:
    id: str
    root: str
    conditions: tuple[Condition, ...]

    def __post_init__(self):
        identifier(self.id)
        identifier(self.root)
        if type(self.conditions) is not tuple or not 1 <= len(self.conditions) <= 128:
            raise ValueError("goal requires 1..128 conditions")
        if any(type(c) is not Condition for c in self.conditions):
            raise ValueError("Condition required")
        nodes = {c.id: c for c in self.conditions}
        if len(nodes) != len(self.conditions) or self.root not in nodes:
            raise ValueError("duplicate conditions or unknown root")
        done, active = set(), set()

        def visit(node):
            if node not in nodes or node in active:
                raise ValueError("unresolved prerequisite or dependency cycle")
            if node in done:
                return
            active.add(node)
            for child in nodes[node].prerequisites:
                visit(child)
            active.remove(node)
            done.add(node)

        for node in nodes:
            visit(node)

    @property
    def nodes(self):
        return {c.id: c for c in self.conditions}

    @property
    def identity(self):
        return sha256(canonical({"id": self.id, "root": self.root,
            "conditions": [{"id": c.id, "prerequisites": c.prerequisites,
                            "mode": c.mode} for c in self.conditions]})).hexdigest()
