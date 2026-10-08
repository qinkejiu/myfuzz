"""Static AND/OR dependency paths from targets back to fuzzable sources."""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
import hashlib
import json
from itertools import product
from typing import TYPE_CHECKING

from .genome import DIRECTIONS

if TYPE_CHECKING:
    from .genome import ScenarioGenome
    from .ownership import OwnershipMap


_RULE_KINDS = frozenset(("DATA_BINDING", "EVENT_ORDER",
                         "ENV_PRECONDITION", "PERSISTENT_STATE_RULE",
                         "BASELINE_GROUPING"))
_EDGE_WORK_LIMIT = 1_000_000


def _edge_hash(document) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


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
class DependencyEdge:
    rule_index: int
    prerequisite_index: int
    prerequisite: str
    target: str
    kind: str

    def __post_init__(self) -> None:
        if (type(self.rule_index) is not int or self.rule_index < 0
                or type(self.prerequisite_index) is not int or self.prerequisite_index < 0
                or type(self.prerequisite) is not str or not self.prerequisite
                or type(self.target) is not str or not self.target
                or type(self.kind) is not str or self.kind not in _RULE_KINDS):
            raise ValueError('invalid dependency edge')

    def document(self):
        return {'rule_index': self.rule_index, 'prerequisite_index': self.prerequisite_index,
                'prerequisite': self.prerequisite, 'target': self.target, 'kind': self.kind}


@dataclass(frozen=True)
class DependencyPath:
    target: str
    source_ids: tuple[str, ...]
    edges: tuple[DependencyEdge, ...] = ()


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
        self._ordered_rules = rules
        indexed: dict[str, list[int]] = {}
        for index, rule in enumerate(rules):
            self.rules.setdefault(rule.target, []).append(rule)
            indexed.setdefault(rule.target, []).append(index)
        self._indexed_rules = {target: tuple(indices) for target, indices in indexed.items()}

    @property
    def ordered_rules(self) -> tuple[DependencyRule, ...]:
        return self._ordered_rules

    def edge_document(self) -> dict:
        """Ordered construction identity; sources include explicit online kinds.

        OnlineDependencyGraph intentionally supplies its source dictionary after
        the base constructor. Keep this boundary explicit rather than coercing
        instruction sources into memory-image sources.
        """
        expected = {}
        for rule in self._ordered_rules:
            if (type(rule.target) is not str or not rule.target
                    or any(type(child) is not str or not child for child in rule.prerequisites)):
                raise ValueError('invalid edge graph rule identity')
            expected.setdefault(rule.target, []).append(rule)
        if self.rules != expected:
            raise ValueError('edge graph rules changed after construction')
        sources = []
        for key, source in self.sources.items():
            if (key != source.source_id or type(key) is not str or not key
                    or type(source.component) is not str or not source.component
                    or type(source.port) is not str or type(source.kind) is not str or not source.kind
                    or type(source.bit_offset) is not int or source.bit_offset < 0
                    or type(source.width) is not int or source.width < 1
                    or not isinstance(source.directions, tuple) or not source.directions
                    or len(set(source.directions)) != len(source.directions)
                    or any(type(direction) is not str or direction not in DIRECTIONS
                           for direction in source.directions)):
                raise ValueError('invalid edge graph source identity')
            sources.append({'source_id': source.source_id, 'component': source.component,
                'port': source.port, 'bit_offset': source.bit_offset, 'width': source.width,
                'directions': list(source.directions), 'kind': source.kind})
        rules = [{'rule_index': index, 'target': rule.target,
                  'prerequisites': list(rule.prerequisites), 'kind': rule.kind}
                 for index, rule in enumerate(self._ordered_rules)]
        edges = [DependencyEdge(index, child_index, child, rule.target, rule.kind).document()
                 for index, rule in enumerate(self._ordered_rules)
                 for child_index, child in enumerate(rule.prerequisites)]
        return {'schema_version': 'dependency_edge_graph.v1',
                'sources': sources, 'rules': rules, 'edges': edges}

    @classmethod
    def from_edge_document(cls, document, *, source_factory=FuzzableSource):
        """Strict roundtrip; online sources require their explicit source factory."""
        if (type(document) is not dict or set(document) != {'schema_version', 'sources', 'rules', 'edges'}
                or document['schema_version'] != 'dependency_edge_graph.v1'
                or any(type(document[name]) is not list for name in ('sources', 'rules', 'edges'))):
            raise ValueError('invalid dependency edge graph document')
        try:
            sources = []
            for row in document['sources']:
                if type(row) is not dict or set(row) != {'source_id', 'component', 'port', 'bit_offset', 'width', 'directions', 'kind'} or type(row['directions']) is not list:
                    raise ValueError('invalid dependency edge source document')
                sources.append(source_factory(**{**row, 'directions': tuple(row['directions'])}))
            rules = []
            for index, row in enumerate(document['rules']):
                if (type(row) is not dict or set(row) != {'rule_index', 'target', 'prerequisites', 'kind'}
                        or type(row['rule_index']) is not int or row['rule_index'] != index
                        or type(row['prerequisites']) is not list):
                    raise ValueError('invalid dependency edge rule document')
                rules.append(DependencyRule(row['target'], tuple(row['prerequisites']), row['kind']))
            for row in document['edges']:
                if type(row) is not dict or set(row) != {'rule_index', 'prerequisite_index', 'prerequisite', 'target', 'kind'}:
                    raise ValueError('invalid dependency edge document')
                DependencyEdge(**row)
            graph = cls(sources=tuple(sources), rules=tuple(rules))
            if graph.edge_document() != document:
                raise ValueError('dependency edge graph roundtrip mismatch')
            return graph
        except (TypeError, AttributeError, KeyError) as error:
            raise ValueError('invalid dependency edge graph document') from error

    def edge_paths_to(self, target: str, *, direction: str,
                      max_depth: int = 16, max_paths: int = 64) -> tuple[DependencyPath, ...]:
        """Enumerate bounded proof DAGs with one consistent OR rule per node.

        Every AND prerequisite retains its edge, while shared subtree edges
        are deduplicated. This API deliberately leaves legacy paths_to intact.
        Paths and partial products are generated lazily with an explicit work
        budget. Exhaustion raises instead of silently hiding unexplored paths.
        """
        if (type(target) is not str or not target or type(direction) is not str
                or direction not in DIRECTIONS or type(max_depth) is not int
                or not 1 <= max_depth <= 128 or type(max_paths) is not int
                or not 1 <= max_paths <= 4096):
            raise ValueError('invalid dependency edge path request')
        remaining = min(_EDGE_WORK_LIMIT, max(4096, max_paths * max_depth * 128))

        def spend(amount=1):
            nonlocal remaining
            remaining -= amount
            if remaining < 0:
                raise ValueError('dependency edge path work limit exceeded')

        # Bound identity materialization too, before allocating its edge rows.
        # Direct document/identity calls remain linear in their supplied graph.
        spend(len(self.sources))
        for rule in self._ordered_rules:
            spend(1 + len(rule.prerequisites))
        self.edge_document()

        # Directional reachability cheaply discards unresolved prerequisites,
        # source-less cycles and dead AND branches before any product expansion.
        viable = {key for key, source in self.sources.items() if direction in source.directions}
        pending, reverse = {}, {}
        for index, rule in enumerate(self._ordered_rules):
            spend()
            if rule.target in self.sources:
                continue  # Source nodes remain terminal, matching legacy semantics.
            pending[index] = len(rule.prerequisites)
            for child in rule.prerequisites:
                spend()
                reverse.setdefault(child, []).append(index)
        queue = deque(viable)
        while queue:
            node = queue.popleft()
            spend()
            for index in reverse.get(node, ()):
                spend()
                pending[index] -= 1
                if pending[index] == 0:
                    reached = self._ordered_rules[index].target
                    if reached not in viable:
                        viable.add(reached)
                        queue.append(reached)

        def walk(node, seen, depth, choices):
            spend()
            if node not in viable:
                return
            if node in self.sources:
                yield frozenset((node,)), frozenset(), choices
                return
            if node in seen or depth >= max_depth:
                return
            for index in self._indexed_rules.get(node, ()):
                spend()
                if node in choices and choices[node] != index:
                    continue
                rule = self._ordered_rules[index]
                if any(child not in viable for child in rule.prerequisites):
                    continue
                selected = {**choices, node: index}
                active = seen | {node}
                stack = [(0, frozenset(), frozenset(),
                          iter(walk(rule.prerequisites[0], active, depth + 1, selected)))]
                while stack:
                    spend()
                    child_index, sources, edges, iterator = stack[-1]
                    try:
                        child_sources, child_edges, child_choices = next(iterator)
                    except StopIteration:
                        stack.pop()
                        continue
                    sources = sources | child_sources
                    edges = edges | child_edges | {DependencyEdge(index, child_index,
                        rule.prerequisites[child_index], rule.target, rule.kind)}
                    next_index = child_index + 1
                    if next_index == len(rule.prerequisites):
                        yield sources, edges, child_choices
                    else:
                        stack.append((next_index, sources, edges,
                            iter(walk(rule.prerequisites[next_index], active, depth + 1, child_choices))))

        paths, identities = [], set()
        for sources, edges, _ in walk(target, frozenset(), 0, {}):
            path = DependencyPath(target, tuple(sorted(sources)),
                tuple(sorted(edges, key=lambda edge: (edge.rule_index, edge.prerequisite_index))))
            if path not in identities:
                identities.add(path)
                paths.append(path)
                if len(paths) == max_paths:
                    break
        return tuple(paths)

    def path_identity(self, path: DependencyPath, *, direction: str) -> str:
        """Authenticate an entire selected proof DAG without enumerating paths."""
        graph_document = self.edge_document()
        if (not isinstance(path, DependencyPath) or type(path.target) is not str or not path.target
                or type(direction) is not str or direction not in DIRECTIONS
                or not isinstance(path.source_ids, tuple) or not path.source_ids
                or any(type(source) is not str or not source for source in path.source_ids)
                or path.source_ids != tuple(sorted(set(path.source_ids)))
                or not isinstance(path.edges, tuple)
                or any(not isinstance(edge, DependencyEdge) for edge in path.edges)):
            raise ValueError('invalid dependency edge path identity')
        canonical = tuple(sorted(set(path.edges), key=lambda edge: (edge.rule_index, edge.prerequisite_index)))
        if path.edges != canonical:
            raise ValueError('dependency edge path is not canonical')
        selected, by_key = {}, {}
        for edge in path.edges:
            if edge.rule_index >= len(self._ordered_rules):
                raise ValueError('dependency edge rule not in graph')
            rule = self._ordered_rules[edge.rule_index]
            if (edge.prerequisite_index >= len(rule.prerequisites)
                    or edge != DependencyEdge(edge.rule_index, edge.prerequisite_index,
                        rule.prerequisites[edge.prerequisite_index], rule.target, rule.kind)):
                raise ValueError('dependency edge differs from graph')
            previous = selected.setdefault(edge.target, edge.rule_index)
            if previous != edge.rule_index:
                raise ValueError('dependency path has inconsistent OR selections')
            by_key[(edge.rule_index, edge.prerequisite_index)] = edge
        visited, active, used, leaves = set(), set(), set(), set()
        stack = [(path.target, False)]
        while stack:
            node, exiting = stack.pop()
            if exiting:
                active.remove(node)
                visited.add(node)
                continue
            if node in active:
                raise ValueError('dependency selected path contains cycle')
            if node in visited:
                continue
            if node in self.sources:
                if direction not in self.sources[node].directions:
                    raise ValueError('dependency source direction differs')
                leaves.add(node)
                visited.add(node)
                continue
            index = selected.get(node)
            if index is None:
                raise ValueError('dependency path has unresolved prerequisite')
            active.add(node)
            stack.append((node, True))
            for child_index, child in reversed(tuple(enumerate(self._ordered_rules[index].prerequisites))):
                edge = by_key.get((index, child_index))
                if edge is None:
                    raise ValueError('dependency path omits AND prerequisite edge')
                used.add(edge)
                stack.append((child, False))
        if used != set(path.edges) or tuple(sorted(leaves)) != path.source_ids:
            raise ValueError('dependency path has disconnected edge or incorrect sources')
        return _edge_hash({'schema_version': 'dependency_edge_path_identity.v1',
            'graph': graph_document, 'target': path.target, 'direction': direction,
            'source_ids': list(path.source_ids), 'edges': [edge.document() for edge in path.edges]})

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
