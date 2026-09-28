"""Static AND/OR dependency paths from targets back to fuzzable sources."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import TYPE_CHECKING

from .genome import DIRECTIONS

if TYPE_CHECKING:
    from .genome import ScenarioGenome
    from .ownership import OwnershipMap


_RULE_KINDS = frozenset(("DATA_BINDING", "EVENT_ORDER",
                         "ENV_PRECONDITION", "PERSISTENT_STATE_RULE",
                         "BASELINE_GROUPING"))


@dataclass(frozen=True)
class FuzzableSource:
    source_id: str
    component: str
    port: str
    bit_offset: int
    width: int
    directions: tuple[str, ...]
    kind: str = "source"

    def __post_init__(self) -> None:
        if self.kind not in ("source", "memory_image"):
            raise ValueError("only fuzzable source nodes may be mutation sources")
        if not self.source_id or not self.component or not self.port:
            raise ValueError("source identity is required")
        if (isinstance(self.bit_offset, bool) or not isinstance(self.bit_offset, int)
                or self.bit_offset < 0 or isinstance(self.width, bool)
                or not isinstance(self.width, int) or self.width < 1):
            raise ValueError("source bit range is invalid")
        if not self.directions or any(item not in DIRECTIONS for item in self.directions):
            raise ValueError("source direction is invalid")


@dataclass(frozen=True)
class SourceBinding:
    """Profile-owned identity of one mutable graph source."""

    source_id: str
    kind: str
    component: str
    port: str
    bit_offset: int
    width: int
    owner_ref: str
    image_address: int | None = None

    def __post_init__(self) -> None:
        if not self.source_id or not self.component or not self.port or not self.owner_ref:
            raise ValueError("source binding identity is required")
        if self.kind not in ("source", "memory_image"):
            raise ValueError("source binding kind is invalid")
        if (type(self.bit_offset) is not int or self.bit_offset < 0
                or type(self.width) is not int or self.width < 1):
            raise ValueError("source binding range is invalid")
        if self.kind == "memory_image":
            if type(self.image_address) is not int or self.image_address < 0:
                raise ValueError("memory image binding address is required")
        elif self.image_address is not None:
            raise ValueError("input source binding cannot name image address")


@dataclass(frozen=True)
class SourceBindings:
    entries: tuple[SourceBinding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
                not isinstance(item, SourceBinding) for item in self.entries):
            raise ValueError("source bindings must be a tuple")
        if len({item.source_id for item in self.entries}) != len(self.entries):
            raise ValueError("duplicate source binding")

    def validate(self, graph: DependencyGraph, ownership: OwnershipMap,
                 genomes: tuple[ScenarioGenome, ...]) -> None:
        entries = {item.source_id: item for item in self.entries}
        if set(entries) != set(graph.sources):
            raise ValueError("graph source lacks trusted binding")
        occupied: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
        for source_id, source in graph.sources.items():
            entry = entries[source_id]
            if ((entry.kind, entry.component, entry.port, entry.bit_offset,
                 entry.width) !=
                    (source.kind, source.component, source.port,
                     source.bit_offset, source.width)):
                raise ValueError("graph source disagrees with trusted binding")
            if source.width > 8192:
                raise ValueError("source binding width exceeds decoder bound")
            if source.kind == "source":
                actual = ownership.mutation_source(
                    source.component, source.port, source.bit_offset,
                    source.width, direction=source.directions[0])
                if actual != entry.owner_ref:
                    raise ValueError("source binding owner does not match input owner")
            else:
                expected = f"initial_image:{source.component}:{source.port}"
                if entry.owner_ref != expected:
                    raise ValueError("memory image binding owner is invalid")
                for genome in genomes:
                    image = next((item for item in genome.initial_images
                                  if item.component == source.component
                                  and item.image_id == source.port), None)
                    if image is not None:
                        if image.address != entry.image_address:
                            raise ValueError("memory image binding address differs")
                        if source.bit_offset + source.width > len(image.data) * 8:
                            raise ValueError("memory image binding exceeds initial image")
                if not any(any(image.component == source.component
                               and image.image_id == source.port
                               for image in genome.initial_images)
                           for genome in genomes):
                    raise ValueError("memory image binding has no initial image")
            key = (source.kind, source.component, source.port)
            interval = (source.bit_offset, source.bit_offset + source.width)
            if any(interval[0] < end and start < interval[1]
                   for start, end in occupied.get(key, ())):
                raise ValueError("multiple graph source bindings own one bit")
            occupied.setdefault(key, []).append(interval)


@dataclass(frozen=True)
class DependencyRule:
    target: str
    prerequisites: tuple[str, ...]
    kind: str

    def __post_init__(self) -> None:
        if not self.target or not isinstance(self.prerequisites, tuple) \
                or not self.prerequisites or any(not item for item in self.prerequisites):
            raise ValueError("dependency rule needs a target and prerequisites")
        if self.kind not in _RULE_KINDS:
            raise ValueError("unknown dependency rule kind")


@dataclass(frozen=True)
class DependencyPath:
    target: str
    source_ids: tuple[str, ...]


class DependencyGraph:
    """Each rule is AND; multiple rules for the same target are OR alternatives."""

    def __init__(self, *, sources: tuple[FuzzableSource, ...],
                 rules: tuple[DependencyRule, ...]) -> None:
        if not isinstance(sources, tuple) or not isinstance(rules, tuple):
            raise ValueError("sources and rules must be tuples")
        if any(not isinstance(item, FuzzableSource) for item in sources) \
                or any(not isinstance(item, DependencyRule) for item in rules):
            raise ValueError("invalid source or dependency rule")
        self.sources = {item.source_id: item for item in sources}
        if len(self.sources) != len(sources):
            raise ValueError("duplicate source id")
        self.rules: dict[str, list[DependencyRule]] = {}
        for rule in rules:
            self.rules.setdefault(rule.target, []).append(rule)

    def paths_to(self, target: str, *, direction: str,
                 max_depth: int = 16, max_paths: int = 64) -> tuple[DependencyPath, ...]:
        if direction not in DIRECTIONS or not target or max_depth < 1 or max_paths < 1:
            raise ValueError("invalid dependency path request")

        def expand(node: str, seen: frozenset[str], depth: int) -> list[frozenset[str]]:
            source = self.sources.get(node)
            if source is not None:
                return [frozenset((node,))] if direction in source.directions else []
            if node in seen or depth >= max_depth:
                return []
            alternatives: list[frozenset[str]] = []
            for rule in self.rules.get(node, ()):
                child_choices = [expand(child, seen | {node}, depth + 1)
                                 for child in rule.prerequisites]
                if any(not choices for choices in child_choices):
                    continue
                for combination in product(*child_choices):
                    alternatives.append(frozenset().union(*combination))
                    if len(alternatives) >= max_paths * 4:
                        break
            return alternatives

        sets = sorted(set(expand(target, frozenset(), 0)),
                      key=lambda item: (len(item), tuple(sorted(item))))
        return tuple(DependencyPath(target, tuple(sorted(item)))
                     for item in sets[:max_paths])
