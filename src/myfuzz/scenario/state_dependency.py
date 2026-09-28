"""Dynamic byte-version dependencies from actual memory commits and reads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .ledger import TransactionKey


@dataclass(frozen=True)
class StateEdge:
    kind: str
    source: str
    target: str
    memory_id: str
    generation: int
    byte_offset: int
    version: tuple[int, int] | None


class StateDependencyTracker:
    """Observe state evolution; it never supplies memory values or DUT results."""

    def __init__(self) -> None:
        self.edges: list[StateEdge] = []
        self._current: dict[tuple[str, int, int], tuple[str, tuple[int, int]]] = {}
        self._readers: dict[tuple[str, int, int], list[str]] = {}
        self._seen: set[tuple[str, str]] = set()

    @staticmethod
    def _transaction(record: Mapping) -> str:
        return str(TransactionKey(**record["transaction"]))

    def ingest(self, events: Iterable[Mapping]) -> None:
        for event in events:
            kind = event.get("kind")
            if kind not in ("memory_read", "memory_write"):
                continue
            identity = self._transaction(event)
            if (kind, identity) in self._seen:
                continue
            self._seen.add((kind, identity))
            memory_id = event["memory_id"]
            generation = event["generation"]
            base = event["byte_offset"]
            if kind == "memory_write":
                version = event["version"]
                if version is None:
                    continue
                version = tuple(version)
                for lane in range(event["width_bytes"]):
                    if not (event["byte_enable"] >> lane & 1):
                        continue
                    offset = base + lane
                    key = (memory_id, generation, offset)
                    previous = self._current.get(key)
                    if previous is not None and previous[0] != identity:
                        self.edges.append(StateEdge("WAW", previous[0], identity,
                                                    memory_id, generation, offset,
                                                    previous[1]))
                    for reader in self._readers.get(key, ()):
                        self.edges.append(StateEdge("WAR", reader, identity,
                                                    memory_id, generation, offset,
                                                    previous[1] if previous else None))
                    self._current[key] = (identity, version)
                    self._readers[key] = []
            else:
                for lane, (writer, version_value) in enumerate(
                        zip(event["writer_event_ids"], event["versions"])):
                    offset = base + lane
                    key = (memory_id, generation, offset)
                    version = tuple(version_value)
                    observed = self._current.get(key)
                    if observed is not None and observed != (writer, version):
                        raise ValueError("read snapshot conflicts with committed state history")
                    self._current[key] = (writer, version)
                    self.edges.append(StateEdge("RAW", writer, identity,
                                                memory_id, generation, offset, version))
                    self.edges.append(StateEdge("PERSIST", writer, identity,
                                                memory_id, generation, offset, version))
                    self._readers.setdefault(key, []).append(identity)

    def invalidate_generation(self, memory_id: str, generation: int,
                              reset_identity: str) -> tuple[StateEdge, ...]:
        """Record the explicit cold-reset boundary for observed byte versions."""
        created: list[StateEdge] = []
        for key, (writer, version) in tuple(self._current.items()):
            if key[:2] != (memory_id, generation):
                continue
            edge = StateEdge("INVALIDATE", writer, reset_identity,
                             memory_id, generation, key[2], version)
            created.append(edge)
            self.edges.append(edge)
            del self._current[key]
            self._readers.pop(key, None)
        return tuple(created)
