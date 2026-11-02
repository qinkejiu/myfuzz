"""Finite public action domains and typed decisions; no DUT effects."""
from dataclasses import asdict, dataclass
from hashlib import sha256

from .model import Goal, Snapshot, canonical, identifier, natural


@dataclass(frozen=True)
class Action:
    id: str
    source_id: str
    operator: str
    produces: tuple[str, ...]
    requires: tuple[str, ...]
    values: tuple[int, ...]
    ownership: str = "source"

    def __post_init__(self):
        for field in (self.id, self.source_id, self.operator):
            identifier(field)
        if self.ownership != "source":
            raise ValueError("only declared source actions may be proposed")
        for group in (self.produces, self.requires):
            if type(group) is not tuple or len(group) > 128 or len(set(group)) != len(group):
                raise ValueError("bounded unique condition IDs required")
            for key in group:
                identifier(key)
        if not self.produces:
            raise ValueError("an intended effect must be declared")
        if (type(self.values) is not tuple or not 1 <= len(self.values) <= 64
                or any(type(v) is not int or not 0 <= v < 1 << 32 for v in self.values)
                or len(set(self.values)) != len(self.values)):
            raise ValueError("finite unique uint32 parameter domain required")


@dataclass(frozen=True)
class Catalog:
    actions: tuple[Action, ...]

    def __post_init__(self):
        if (type(self.actions) is not tuple or not 1 <= len(self.actions) <= 64
                or any(type(a) is not Action for a in self.actions)
                or len({a.id for a in self.actions}) != len(self.actions)):
            raise ValueError("1..64 distinct Action descriptions required")

    def eligible(self, snapshot: Snapshot) -> tuple[Action, ...]:
        return tuple(a for a in self.actions if all(
            snapshot.get(key).status == "satisfied" for key in a.requires))

    @property
    def identity(self):
        return sha256(canonical([asdict(a) for a in self.actions])).hexdigest()

    def get(self, key):
        for action in self.actions:
            if action.id == key:
                return action
        raise ValueError("undeclared action")


def context_key(goal: Goal, snapshot: Snapshot, frontier_ids, available_ids):
    # References and epochs remain in raw evidence, not in novelty keys.
    relevant = set()

    def visit(key):
        if key in relevant:
            return
        relevant.add(key)
        for child in goal.nodes[key].prerequisites:
            visit(child)

    visit(goal.root)
    document = {"goal": goal.identity, "frontier": sorted(frontier_ids),
                "available": sorted(available_ids), "observations": [
                    (key, snapshot.get(key).status, snapshot.get(key).value_class)
                    for key in sorted(relevant)]}
    return sha256(canonical(document)).hexdigest()


@dataclass(frozen=True)
class Decision:
    sequence: int
    goal_id: str
    context: str
    action_id: str
    value: int
    reason: str
    entropy: int

    def __post_init__(self):
        natural(self.sequence)
        for field in (self.goal_id, self.context, self.action_id, self.reason):
            identifier(field)
        if type(self.value) is not int or not 0 <= self.value < 1 << 32:
            raise ValueError("uint32 decision value required")
        if type(self.entropy) is not int or not 0 <= self.entropy < 1 << 128:
            raise ValueError("128-bit entropy required")

    @property
    def id(self):
        return sha256(canonical(asdict(self))).hexdigest()

    def document(self):
        return {"schema_version": "dependency_search_decision.v1", **asdict(self),
                "decision_id": self.id, "native_authority": False}
