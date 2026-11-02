"""A bounded, deterministic corpus for the closed-loop in-process fuzzer.

The corpus holds the record texts the executor has already run, keyed by
``(flow, record_text)`` so the same input is stored once.  Every entry records
where it came from, its parent (for a mutation), how often it was chosen as a
parent and how many previously unseen features its run discovered.

Two policies keep the corpus useful:

* the queue is bounded, and an overflow evicts the entry with the *highest*
  pick count and the *fewest* discoveries -- an input that is popular but no
  longer productive -- never the entry just added;
* :meth:`Corpus.choose` draws uniformly from the least-picked quartile of the
  queue, so fresh inputs are reached before well-worn ones.

The module is pure apart from :meth:`Corpus.save` / :meth:`Corpus.load`; choice
is driven only by the ``random.Random`` the caller passes, and the saved
document carries no absolute path, timestamp or environment fact.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

__all__ = ['CORPUS_SCHEMA', 'MAX_ENTRIES', 'MIN_ENTRIES', 'ORIGINS', 'Corpus',
           'CorpusEntry']

#: Version tag of the saved corpus document.
CORPUS_SCHEMA = 'inprocess_fuzz_corpus.v1'

#: How an entry entered the corpus.
ORIGINS = ('seed', 'fresh', 'mutation')

#: The inclusive bounds of ``Corpus(max_entries=...)``.
MIN_ENTRIES = 1
MAX_ENTRIES = 4096

_DEFAULT_MAX_ENTRIES = 256


@dataclass(slots=True)
class CorpusEntry:
    """One record the executor has run, with its queue bookkeeping."""

    flow: str
    fields: tuple[int, ...]
    record_text: str
    #: ``'seed'`` (declared by the caller), ``'fresh'`` (newly generated) or
    #: ``'mutation'`` (derived from ``parent``).
    origin: str
    #: The record text this entry was mutated from, if any.
    parent: str | None
    #: How often this entry was chosen as a mutation parent.
    picks: int
    #: How many previously unseen features this entry's run discovered.
    discoveries: int

    def document(self) -> dict:
        """The entry as a JSON-serialisable dictionary."""
        return {
            'flow': self.flow,
            'fields': list(self.fields),
            'record_text': self.record_text,
            'origin': self.origin,
            'parent': self.parent,
            'picks': self.picks,
            'discoveries': self.discoveries,
        }


def _checked_limit(max_entries):
    if (type(max_entries) is not int
            or not MIN_ENTRIES <= max_entries <= MAX_ENTRIES):
        raise ValueError('corpus max_entries must be an integer in '
                         f'{MIN_ENTRIES}..{MAX_ENTRIES}: {max_entries!r}')
    return max_entries


def _checked_flow(flow):
    if type(flow) is not str or not flow:
        raise ValueError('corpus flow must be a non-empty string: '
                         + repr(flow))
    return flow


def _checked_fields(fields):
    if isinstance(fields, str) or not isinstance(fields, (tuple, list)):
        raise ValueError('corpus fields must be a tuple of integers: '
                         + repr(fields))
    checked = []
    for field in fields:
        if type(field) is not int:
            raise ValueError('corpus fields must be integers only: '
                             + repr(field))
        checked.append(field)
    return tuple(checked)


def _checked_record_text(record_text):
    if type(record_text) is not str or not record_text:
        raise ValueError('corpus record_text must be a non-empty string: '
                         + repr(record_text))
    return record_text


def _checked_parent(parent):
    if parent is not None and type(parent) is not str:
        raise ValueError('corpus parent must be a string or None: '
                         + repr(parent))
    return parent


def _checked_origin(origin):
    if origin not in ORIGINS:
        raise ValueError('unsupported corpus origin: ' + repr(origin))
    return origin


def _eviction_order(entry):
    """Highest picks first, then fewest discoveries, then a stable name.

    ``min()`` over this order evicts the most-worn and least-productive entry;
    the ``(flow, record_text)`` tail makes a tie reproducible.
    """
    return (-entry.picks, entry.discoveries, entry.flow, entry.record_text)


def _entry_order(entry):
    return (entry.flow, entry.record_text)


class Corpus:
    """A bounded set of unique ``(flow, record_text)`` entries."""

    def __init__(self, *, max_entries: int = _DEFAULT_MAX_ENTRIES) -> None:
        self._max_entries = _checked_limit(max_entries)
        self._entries: dict[tuple[str, str], CorpusEntry] = {}
        self._evicted = 0

    def seed(self, flow, fields, record_text) -> CorpusEntry:
        """Add a caller-declared seed record."""
        return self.add(flow, fields, record_text, origin='seed')

    def add(self, flow, fields, record_text, *, parent=None,
            origin='mutation') -> CorpusEntry:
        """Add one record, or return the entry already holding it.

        A duplicate is not stored twice and its pick/discovery counts are not
        reset.  Adding to a full corpus evicts one older entry first.
        """
        flow = _checked_flow(flow)
        fields = _checked_fields(fields)
        record_text = _checked_record_text(record_text)
        parent = _checked_parent(parent)
        origin = _checked_origin(origin)
        key = (flow, record_text)
        existing = self._entries.get(key)
        if existing is not None:
            return existing
        entry = CorpusEntry(flow=flow, fields=fields, record_text=record_text,
                            origin=origin, parent=parent, picks=0,
                            discoveries=0)
        self._insert(entry)
        return entry

    def choose(self, rng: random.Random) -> CorpusEntry | None:
        """Draw one entry, preferring the least-picked quartile.

        The candidates are every entry at or below the pick count of the
        lowest quartile boundary, so ties at the least-picked value are all
        reachable.  The draw is uniform among them and deterministic for a
        given ``rng`` state.
        """
        if not self._entries:
            return None
        ordered = sorted(self._entries.values(),
                         key=lambda entry: (entry.picks,) + _entry_order(entry))
        boundary = ordered[(len(ordered) - 1) // 4].picks
        candidates = [entry for entry in ordered if entry.picks <= boundary]
        return candidates[rng.randrange(len(candidates))]

    def mark_picked(self, entry: CorpusEntry) -> None:
        """Count one more use of ``entry`` as a mutation parent."""
        self._stored(entry).picks += 1

    def note_discovery(self, entry: CorpusEntry) -> None:
        """Count ``entry`` as the source of one more newly seen feature."""
        self._stored(entry).discoveries += 1

    def flow(self, name: str) -> tuple[CorpusEntry, ...]:
        """Every entry of one flow, in stable record order."""
        if type(name) is not str:
            raise ValueError('corpus flow name must be a string: ' + repr(name))
        return tuple(entry for entry in self.entries if entry.flow == name)

    @property
    def entries(self) -> tuple[CorpusEntry, ...]:
        """Every entry, ordered by ``(flow, record_text)``."""
        return tuple(sorted(self._entries.values(), key=_entry_order))

    def document(self) -> dict:
        """The corpus as a stable, JSON-serialisable dictionary."""
        ordered = self.entries
        by_flow: dict[str, int] = {}
        for entry in ordered:
            by_flow[entry.flow] = by_flow.get(entry.flow, 0) + 1
        return {
            'schema_version': CORPUS_SCHEMA,
            'entries': [entry.document() for entry in ordered],
            'by_flow': by_flow,
            'evicted': self._evicted,
        }

    def save(self, path) -> None:
        """Write :meth:`document` to ``path`` as UTF-8 JSON.

        The document is self-contained: it carries no absolute path, no
        timestamp and no other environment fact.
        """
        text = json.dumps(self.document(), indent=2, sort_keys=True,
                          ensure_ascii=True)
        Path(path).write_text(text + '\n', encoding='utf-8')

    @classmethod
    def load(cls, path, *, max_entries=_DEFAULT_MAX_ENTRIES) -> 'Corpus':
        """Read a corpus saved by :meth:`save`, refusing anything malformed."""
        corpus = cls(max_entries=max_entries)
        text = Path(path).read_text(encoding='utf-8')
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError('malformed corpus document: not JSON: '
                             + error.msg) from error
        if not isinstance(payload, dict):
            raise ValueError('malformed corpus document: expected a JSON object')
        version = payload.get('schema_version')
        if version != CORPUS_SCHEMA:
            raise ValueError('unsupported corpus schema version: ' + repr(version))
        rows = payload.get('entries')
        if not isinstance(rows, list):
            raise ValueError('malformed corpus document: entries must be a list')
        evicted = payload.get('evicted', 0)
        if type(evicted) is not int or evicted < 0:
            raise ValueError('malformed corpus document: evicted must be a '
                             'non-negative integer')
        loaded = []
        seen: set[tuple[str, str]] = set()
        for position, row in enumerate(rows):
            entry = _load_entry(row, position)
            key = (entry.flow, entry.record_text)
            if key in seen:
                raise ValueError(
                    f'malformed corpus entry at index {position}: duplicate '
                    f'entry for {entry.flow} {entry.record_text}')
            seen.add(key)
            loaded.append(entry)
        for entry in loaded:
            corpus._insert(entry)
        corpus._evicted += evicted
        return corpus

    # -- internals ---------------------------------------------------------
    def _insert(self, entry: CorpusEntry) -> None:
        if len(self._entries) >= self._max_entries:
            self._evict_one()
        self._entries[(entry.flow, entry.record_text)] = entry

    def _evict_one(self) -> None:
        victim = min(self._entries.values(), key=_eviction_order)
        del self._entries[(victim.flow, victim.record_text)]
        self._evicted += 1

    def _stored(self, entry: CorpusEntry) -> CorpusEntry:
        if not isinstance(entry, CorpusEntry):
            raise ValueError('corpus operation needs a CorpusEntry: '
                             + repr(entry))
        stored = self._entries.get((entry.flow, entry.record_text))
        if stored is None:
            raise ValueError('corpus entry is not in this corpus: '
                             + entry.flow + ' ' + entry.record_text)
        return stored


def _load_entry(row, position: int) -> CorpusEntry:
    """One saved entry, validated field by field."""
    where = f'malformed corpus entry at index {position}'
    if not isinstance(row, dict):
        raise ValueError(where + ': expected a JSON object')
    flow = row.get('flow')
    if type(flow) is not str or not flow:
        raise ValueError(where + ': flow must be a non-empty string')
    record_text = row.get('record_text')
    if type(record_text) is not str or not record_text:
        raise ValueError(where + ': record_text must be a non-empty string')
    raw_fields = row.get('fields')
    if not isinstance(raw_fields, (list, tuple)):
        raise ValueError(where + ': fields must be a list of integers')
    fields = []
    for value in raw_fields:
        if type(value) is not int:
            raise ValueError(where + ': fields must be integers only')
        fields.append(value)
    origin = row.get('origin')
    if origin not in ORIGINS:
        raise ValueError(where + ': unsupported origin: ' + repr(origin))
    parent = row.get('parent')
    if parent is not None and type(parent) is not str:
        raise ValueError(where + ': parent must be a string or null')
    picks = row.get('picks', 0)
    discoveries = row.get('discoveries', 0)
    for name, value in (('picks', picks), ('discoveries', discoveries)):
        if type(value) is not int or value < 0:
            raise ValueError(where + f': {name} must be a non-negative integer')
    return CorpusEntry(flow=flow, fields=tuple(fields),
                       record_text=record_text, origin=origin, parent=parent,
                       picks=picks, discoveries=discoveries)
