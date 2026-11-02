#!/usr/bin/env python3
"""Measure the ``EventJournal`` chunk-reload pathology and the bounded LRU fix.

The steady-state Runner step of the shared reference workload
(``F3,F1,F4,F5,F2,F6,F5,F6``: 2 727 steps, 38 421 journal events, ~14 events
drained per step) does two different kinds of journal read per step:

* ``Runner.events_since(cursor)`` -- the tail drain, which unpickles the newest
  spilled chunk (or reads the resident ``_current`` chunk);
* a handful of historical ``event_id`` reads through ``Runner._event_ref_by_id``
  -- ``f6_instruction_fetch_receipt`` issues 7-8 per F6 fetch completion and
  ``_route_observed_outputs`` issues one per binding, all of which land in older
  chunks.

With the single-chunk cache that ``EventJournal`` shipped before this change,
those two access families alternate every step, so every step pays at least two
``pickle.load`` calls of a 2 048-event chunk (measured 27.8 ms each in
``docs/reports/host-overhead-profile-20261030.md``).  This script measures that
pattern against the bounded LRU cache on identical journal contents, the same
step count and the same lookups.

What is measured
----------------
``tail``       the tail drain only (``events_since(cursor)``);
``adjacent3``  tail plus three historical ``event_id`` reads one and two chunks
               back (the F6 request/completion shape);
``wide3``      tail plus three historical reads 1/3k/8k events back, i.e. a
               three-to-five-chunk working set;
``f6x8``       supplementary: the recorded per-fetch-completion fan-out (eight
               historical reads spread over the last two cases).

``legacy`` is the *pre-change* ``_chunk`` body (one cached chunk) reproduced
verbatim in :class:`LegacyEventJournal`, so before/after run in one process over
the same event objects.  ``lruN`` is the shipped implementation with
``chunk_cache_size=N``.

The measurement window is the *deepest* part of the journal (the last
``steps x tail`` events), because that is where the reference workload's F6
cases sit and where the chunk working set is largest.

Correctness guard: every variant must read exactly the same records in the same
order (asserted), so a timing win can never come from reading less.

Usage
-----
::

    PYTHONPATH=src:. python3 scripts/bench_event_journal_cache.py
    PYTHONPATH=src:. python3 scripts/bench_event_journal_cache.py --steps 2727
    PYTHONPATH=src:. python3 scripts/bench_event_journal_cache.py --source \
      research/input-strategy-audit-20261027/runs/shared-performance-20261029/\
tail-v1/workload/original/prefix.json

Nothing is written to disk except the journal's own anonymous temp file: this
script never touches ``research/`` or ``runs/`` and never starts RTL.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import pickle
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if SRC.as_posix() not in sys.path:
    sys.path.insert(0, SRC.as_posix())

from myfuzz.scenario.event_journal import EventJournal  # noqa: E402

DEFAULT_EVENTS = 38_421
DEFAULT_STEPS = 2_727
DEFAULT_TAIL = 14          # recorded events drained per step (38 421 / 2 727)
CHUNK_SIZE = 2048


class LegacyEventJournal(EventJournal):
    """Pre-change journal: one resident read chunk, reload on every miss.

    Only the counter increment differs from the shipped-before ``_chunk``; the
    flush/seek/``pickle.load`` sequence and the single-slot cache are verbatim.
    """

    def __init__(self, *, chunk_size: int = CHUNK_SIZE) -> None:
        super().__init__(chunk_size=chunk_size, chunk_cache_size=1)
        self._legacy_index = -1
        self._legacy_chunk: list[dict] = []

    def _chunk(self, number: int) -> list[dict]:
        if number == len(self._offsets):
            return self._current
        if number != self._legacy_index:
            self._file.flush()
            self._file.seek(self._offsets[number])
            self._legacy_chunk = pickle.load(self._file)
            self._legacy_index = number
            self._chunk_loads += 1
        return self._legacy_chunk


def synthetic_events(count: int) -> list[dict]:
    """Build ``count`` independent events shaped like the recorded journal.

    The recorded ``actual_events`` section is 147 384 432 bytes of pretty JSON
    over 38 421 events (mean 3 836 B, median 1 104 B, max 69 962 B).  The
    template below reproduces the dominant record shape (``gpio_input_sample``
    with per-bit ``stages`` rows plus the standard ``provenance`` envelope) and
    is sized by its ``bits`` count to follow that distribution, so the pickled
    chunk size -- what a reload actually costs -- matches the real artifact.
    Every event is built from fresh objects; nothing is shared between events,
    which is what keeps ``pickle`` chunk sizes realistic.
    """
    plan = (4, 6, 8, 10, 4, 8, 6, 14, 4, 8, 22, 6, 8, 4, 10, 6)
    events = []
    for index in range(count):
        event_id = index + 1
        bits = plan[index % len(plan)]
        stages = {"padin_latch": [
            {"bit": bit, "component": "peripheral", "dependencies": [],
             "local_tick": index, "observation_event_id": event_id - 3,
             "origin_refs": [], "origin_status": "unknown",
             "register": "padin_latch", "reset_epoch": 0, "transaction": None,
             "value": bit & 1, "version": 65 + bit}
            for bit in range(bits)]}
        events.append({
            "address": 65664 + index % 4096, "component": "peripheral",
            "data_hex": "b703010093830320739053303713004013030300" * 2,
            "enabled_mask": 3840, "event_id": event_id, "image_id": "f6-initial-0",
            "kind": "gpio_input_sample", "local_tick": index,
            "observation_event_id": event_id - 3, "producer_event_id": event_id - 3,
            "proof_scope": "gpio_native_resource_observation", "reset_epoch": 0,
            "schema_version": "gpio_input_sample.v1", "stages": stages,
            "status": "observed", "status_resources": {},
            "provenance": {
                "edge_candidates": [], "invalid_origin_references": 0,
                "observed_case": {"case_id": "ibex-gpio-dma-shared-mixed:F5:7",
                                  "case_index": 7},
                "origin_admission_ids": [], "origin_status": "unknown",
                "proof_scope": "observation_only", "resource": None,
                "schema_version": "event_source_provenance.v1",
                "unknown_writer_ids": []}})
    return events


def recorded_events(path: Path, count: int) -> list[dict]:
    """Load the journal straight out of a recorded ``prefix.json``."""
    document = json.loads(Path(path).read_text())
    events = document.get("actual_events")
    if not isinstance(events, list) or len(events) != count:
        raise SystemExit(f"{path}: expected {count} actual_events, "
                         f"found {len(events) if isinstance(events, list) else None}")
    return events


def cursor_at(step: int, count: int, tail: int, steps: int) -> int:
    """Tail cursor of a step inside the last ``steps x tail`` events.

    Identical for every variant; the window ends at the end of the journal
    because that is where the reference workload's chunk pressure is.
    """
    return max(0, count - (steps - step) * tail)


def historical_ids(pattern: str, cursor: int, count: int) -> tuple[int, ...]:
    """Historical ``event_id`` reads for one step."""
    def at(distance: int) -> int:
        return max(1, min(count, cursor - distance))
    if pattern == "tail":
        return ()
    if pattern == "adjacent3":
        return (at(1), at(2049), at(4097))
    if pattern == "wide3":
        return (at(1), at(3000), at(8000))
    if pattern == "f6x8":
        return (at(1), at(24), at(141), at(160), at(620), at(700),
                at(2049), at(4097))
    raise SystemExit(f"unknown pattern {pattern!r}")


def build_journal(impl: str, capacity: int, events: list[dict]) -> EventJournal:
    if impl == "legacy":
        journal = LegacyEventJournal(chunk_size=CHUNK_SIZE)
    else:
        journal = EventJournal(chunk_size=CHUNK_SIZE, chunk_cache_size=capacity)
    for event in events:
        journal.append(event)
    return journal


def chunk_bytes(journal: EventJournal) -> int | None:
    """Median spilled-chunk pickle size, read for reporting only."""
    offsets = getattr(journal, "_offsets", None)
    if not offsets or len(offsets) < 2:
        return None
    sizes = sorted(offsets[index + 1] - offsets[index]
                   for index in range(len(offsets) - 1))
    return sizes[len(sizes) // 2]


def resident_measurement(journal: EventJournal, count: int, *,
                         probe: bool = False) -> dict:
    """Report the memory bound, and optionally measure resident bytes.

    ``chunk_pickle_bytes`` is exact (taken from the journal's own chunk
    offsets); ``resident_bound_bytes`` is ``resident_chunks`` times that.  The
    optional ``tracemalloc`` probe touches every spilled chunk and reports what
    remains allocated at the end, which is the live cache footprint.  It runs
    after the timed loops, so it cannot influence them.
    """
    spilled = count // CHUNK_SIZE
    resident_chunks = min(journal.chunk_cache_size, spilled)
    chunk_pickle = chunk_bytes(journal)
    result = {"spilled_chunks": spilled,
              "resident_chunks_bound": resident_chunks,
              "chunk_pickle_bytes": chunk_pickle,
              "resident_pickle_bytes_bound": (resident_chunks * chunk_pickle
                                              if chunk_pickle is not None else None)}
    if not probe:
        return result
    import tracemalloc
    tracemalloc.start()
    try:
        for index in range(spilled):
            journal[index * CHUNK_SIZE]
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    result.update(resident_probe_bytes=current, resident_probe_peak_bytes=peak)
    return result


def run_pattern(journal: EventJournal, pattern: str, steps: int, count: int,
                tail: int) -> dict:
    """Measure one access pattern and return timings plus what was read."""
    tail_ids: list[int] = []
    seen_history: list[int] = []
    loads_before = journal.chunk_loads
    started = time.perf_counter()
    for step in range(steps):
        cursor = cursor_at(step, count, tail, steps)
        # ``Runner.events_since(cursor)`` == deepcopy(tuple(journal[cursor:stop]))
        # for the recorded per-step drain width.
        drained = deepcopy(tuple(journal[cursor:cursor + tail]))
        for record in drained:
            tail_ids.append(record["event_id"])
        for event_id in historical_ids(pattern, cursor, count):
            # ``Runner._event_ref_by_id``: positional read plus an ID check.
            record = journal[event_id - 1]
            if record.get("event_id") != event_id:
                raise SystemExit("journal ID/order mismatch in benchmark")
            seen_history.append(record["event_id"])
    elapsed = time.perf_counter() - started
    return {"elapsed": elapsed, "steps": steps,
            "loads": journal.chunk_loads - loads_before,
            "tail_ids": tail_ids, "history_ids": seen_history}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--events", type=int, default=DEFAULT_EVENTS)
    parser.add_argument("--steps", type=int, default=DEFAULT_STEPS)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL,
                        help=f"events drained per step (default {DEFAULT_TAIL})")
    parser.add_argument("--source", type=Path, default=None,
                        help="recorded prefix.json to read actual_events from")
    parser.add_argument("--capacities", default="1,2,3,4,6,8",
                        help="LRU capacities to measure (default 1,2,3,4,6,8)")
    parser.add_argument("--patterns", default="tail,adjacent3,wide3",
                        help="comma separated access patterns")
    parser.add_argument("--no-legacy", dest="legacy", action="store_false",
                        help="skip the pre-change single-chunk baseline")
    parser.add_argument("--memory-probe", action="store_true",
                        help="tracemalloc-measure resident cache bytes per variant")
    parser.add_argument("--json", type=Path, default=None,
                        help="also write the result table here")
    args = parser.parse_args(argv)

    if args.events < CHUNK_SIZE:
        raise SystemExit("--events must cover at least one spilled chunk")
    if args.steps < 1 or args.tail < 1:
        raise SystemExit("--steps and --tail must be positive")
    if args.steps * args.tail > args.events:
        raise SystemExit("--steps x --tail must fit inside --events")
    patterns = [name for name in args.patterns.split(",") if name]
    capacities = [int(value) for value in args.capacities.split(",") if value]

    build_started = time.perf_counter()
    if args.source is not None:
        events = recorded_events(args.source, args.events)
        source = str(args.source)
    else:
        events = synthetic_events(args.events)
        source = "synthetic"
    build_seconds = time.perf_counter() - build_started
    count = len(events)

    variants = ([("legacy", 1)] if args.legacy else []) + [
        (f"lru{capacity}", capacity) for capacity in capacities]
    rows = []
    memory = {}
    reference: dict[str, tuple] = {}
    for impl, capacity in variants:
        journal = build_journal(impl, capacity, events)
        try:
            for pattern in patterns:
                result = run_pattern(journal, pattern, args.steps, count, args.tail)
                row = {"impl": impl, "capacity": journal.chunk_cache_size,
                       "pattern": pattern, "steps": result["steps"],
                       "seconds": round(result["elapsed"], 4),
                       "ms_per_step": round(
                           result["elapsed"] * 1000 / result["steps"], 3),
                       "chunk_loads": result["loads"],
                       "loads_per_step": round(result["loads"] / result["steps"], 3),
                       "tail_records": len(result["tail_ids"]),
                       "historical_records": len(result["history_ids"]),
                       "seconds_extrapolated_2727": round(
                           result["elapsed"] * 2727 / result["steps"], 2)}
                rows.append(row)
                # Every variant must observe exactly the same records, in the
                # same order: a timing win may never come from reading less.
                seen = (tuple(result["tail_ids"]), tuple(result["history_ids"]))
                if pattern in reference and reference[pattern] != seen:
                    raise SystemExit(f"semantic drift in {impl} ({pattern})")
                reference[pattern] = seen
                print(json.dumps(row), flush=True)
            # Whole-journal identity check, after all timed loops.
            identity = tuple(journal[index]["event_id"] for index in range(count))
            reference.setdefault("identity", identity)
            if reference["identity"] != identity:
                raise SystemExit(f"journal contents drifted in {impl}")
            memory[impl] = resident_measurement(
                journal, count, probe=args.memory_probe)
        finally:
            journal.close()

    summary = {"source": source, "events": count, "steps": args.steps,
               "tail_events": args.tail, "chunk_size": CHUNK_SIZE,
               "build_seconds": round(build_seconds, 2), "patterns": patterns,
               "variants": [name for name, _ in variants],
               "memory": memory, "rows": rows}
    text = json.dumps(summary, indent=2, sort_keys=True)
    if args.json is not None:
        args.json.write_text(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
