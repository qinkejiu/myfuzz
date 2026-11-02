"""Bounded-memory, ordered event storage for long online RTL sessions.

Only completed chunks are pickled to a private temporary file.  A small
current chunk and a bounded least-recently-used set of read chunks remain
resident.  The public snapshot reads detached event values, matching the old
Runner.events ownership contract.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator, Sequence
from copy import deepcopy
from dataclasses import fields, is_dataclass
from array import array
from bisect import bisect_right
import hashlib
import json
import os
from pathlib import Path
import pickle
import struct
import tempfile
import zlib

# Measured tradeoff (scripts/bench_event_journal_cache.py, recorded 38 421-event
# journal): the steady-state per-step path drains the tail chunk while a handful
# of historical ``event_id`` readers touch one to three older chunks, so a
# single-slot cache misses on every step (2.83 chunk loads/step, 71.5 ms/step).
# A three-slot cache still misses 0.042 loads/step; four slots miss 0.008 and
# cost 62 MB resident (measured with tracemalloc; one 2 048-event chunk of real
# events is 2 680 980 B pickled / ~15.4 MB live, so the bound is
# ``chunk_cache_size * chunk_size`` events, and it does not grow with the
# journal).  ``1`` reproduces the old single-chunk behaviour for an A/B.
_DEFAULT_CHUNK_CACHE_SIZE = 4
# Same-workload A/B switch for the lead: one value per process, read when the
# journal is created (a Runner creates exactly one).  ``1`` reproduces the
# pre-change single-chunk behaviour; the constructor keyword still wins.
_CHUNK_CACHE_ENV = "MYFUZZ_EVENT_JOURNAL_CHUNK_CACHE"


def _configured_chunk_cache_size() -> int:
    raw = os.environ.get(_CHUNK_CACHE_ENV, "").strip()
    if not raw:
        return _DEFAULT_CHUNK_CACHE_SIZE
    try:
        value = int(raw, 10)
    except ValueError:
        raise ValueError(f"{_CHUNK_CACHE_ENV} must be a positive integer") from None
    if value < 1:
        raise ValueError(f"{_CHUNK_CACHE_ENV} must be a positive integer")
    return value


class EventJournal(Sequence[dict]):
    def __init__(self, *, chunk_size: int = 2048,
                 chunk_cache_size: int | None = None) -> None:
        if type(chunk_size) is not int or chunk_size < 1:
            raise ValueError("event journal chunk_size must be positive")
        if chunk_cache_size is None:
            chunk_cache_size = _configured_chunk_cache_size()
        elif type(chunk_cache_size) is not int or chunk_cache_size < 1:
            raise ValueError("event journal chunk_cache_size must be positive")
        self._chunk_size = chunk_size
        self._chunk_cache_size = chunk_cache_size
        self._file = tempfile.TemporaryFile(mode="w+b", prefix="myfuzz-events-")
        self._offsets: list[int] = []
        self._current: list[dict] = []
        self._cache: OrderedDict[int, list[dict]] = OrderedDict()
        self._chunk_loads = 0
        self._count = 0

    def close(self) -> None:
        self._file.close()

    def __del__(self) -> None:
        file = getattr(self, "_file", None)
        if file is not None:
            file.close()

    def append(self, event: dict) -> None:
        self._current.append(event)
        self._count += 1
        if len(self._current) == self._chunk_size:
            self._file.seek(0, 2)
            self._offsets.append(self._file.tell())
            pickle.dump(self._current, self._file, protocol=pickle.HIGHEST_PROTOCOL)
            self._current = []

    def __len__(self) -> int:
        return self._count

    @property
    def chunk_loads(self) -> int:
        """Number of chunk unpickles so far; read-only measurement counter."""
        return self._chunk_loads

    @property
    def chunk_cache_size(self) -> int:
        """Resident read-chunk capacity; read-only measurement accessor."""
        return self._chunk_cache_size

    def _chunk(self, number: int) -> list[dict]:
        if number == len(self._offsets):
            return self._current
        cache = self._cache
        chunk = cache.get(number)
        if chunk is not None:
            cache.move_to_end(number)
            return chunk
        self._file.flush()
        self._file.seek(self._offsets[number])
        chunk = pickle.load(self._file)
        self._chunk_loads += 1
        cache[number] = chunk
        if len(cache) > self._chunk_cache_size:
            cache.popitem(last=False)
        return chunk

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[position] for position in range(*index.indices(self._count))]
        if type(index) is not int:
            raise TypeError("event index must be an integer or slice")
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError("event index out of range")
        chunk, offset = divmod(index, self._chunk_size)
        return self._chunk(chunk)[offset]

    def __iter__(self) -> Iterator[dict]:
        for index in range(len(self._offsets)):
            yield from self._chunk(index)
        yield from self._current

    def snapshot(self) -> EventJournalSnapshot:
        return EventJournalSnapshot(self, self._count)


class EventJournalSnapshot(Sequence[dict]):
    """Read-only prefix view that detaches each returned event."""

    def __init__(self, journal: EventJournal, count: int) -> None:
        self._journal = journal
        self._count = count

    def __len__(self) -> int:
        return self._count

    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple(deepcopy(self._journal[position]) for position in
                         range(*index.indices(self._count)))
        if type(index) is not int:
            raise TypeError("event index must be an integer or slice")
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError("event index out of range")
        return deepcopy(self._journal[index])

    def __iter__(self) -> Iterator[dict]:
        for index, event in enumerate(self._journal):
            if index >= self._count:
                break
            yield deepcopy(event)

    def _iter_borrowed(self) -> Iterator[dict]:
        """Read the fixed prefix for internal, non-mutating serialization."""
        for index, event in enumerate(self._journal):
            if index >= self._count:
                break
            yield event

    def __deepcopy__(self, memo):
        # An immutable snapshot can be shared without materializing its prefix.
        return self

    def __eq__(self, other):
        if not isinstance(other, Sequence) or len(self) != len(other):
            return False
        return all(left == right for left, right in zip(self, other))


def canonical_json_chunks(value) -> Iterator[str]:
    """Stream the same canonical JSON bytes as json.dumps(asdict(value))."""
    options = {"sort_keys": True, "separators": (",", ":"),
               "ensure_ascii": False, "allow_nan": False}
    if isinstance(value, EventJournalSnapshot):
        yield "["
        for index, event in enumerate(value):
            if index:
                yield ","
            yield json.dumps(event, **options)
        yield "]"
    elif is_dataclass(value) and not isinstance(value, type):
        yield from canonical_json_chunks({field.name: getattr(value, field.name)
                                         for field in fields(value)})
    elif isinstance(value, dict):
        yield "{"
        for index, key in enumerate(sorted(value)):
            if index:
                yield ","
            yield json.dumps(key, **options)
            yield ":"
            yield from canonical_json_chunks(value[key])
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from canonical_json_chunks(item)
        yield "]"
    else:
        yield json.dumps(value, **options)


class JsonlEventView(Sequence[dict]):
    """Indexed, lazy reader for a durable terminal JSONL event artifact."""

    def __init__(self, path: Path, expected_count: int) -> None:
        if type(expected_count) is not int or expected_count < 0:
            raise ValueError("invalid JSONL event count")
        self.path = Path(path)
        self._offsets = array("Q")
        with self.path.open("rb") as handle:
            while True:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    raise ValueError("unterminated JSONL event")
                self._offsets.append(offset)
        if len(self._offsets) != expected_count:
            raise ValueError("JSONL event count mismatch")

    def __len__(self) -> int:
        return len(self._offsets)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple(self[position] for position in
                         range(*index.indices(len(self))))
        if type(index) is not int:
            raise TypeError("event index must be an integer or slice")
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError("event index out of range")
        with self.path.open("rb") as handle:
            handle.seek(self._offsets[index])
            return json.loads(handle.readline())

    def __iter__(self) -> Iterator[dict]:
        with self.path.open("rb") as handle:
            for line in handle:
                yield json.loads(line)


_ZLIB_MAGIC = b"MFZ1"
_ZLIB_HEADER = struct.Struct("<IIII")
_ZLIB_MAX_RAW = 8 * 1024 * 1024
_ZLIB_MAX_COMPRESSED = _ZLIB_MAX_RAW + 65536


def write_zlib_chunk_events(path: Path, events, *, chunk_events: int = 256,
                            semantic_digest=None) -> int:
    """Write independently addressable, lossless JSONL zlib blocks."""
    if type(chunk_events) is not int or not 1 <= chunk_events <= 4096:
        raise ValueError("invalid compressed event chunk size")
    count = 0
    pending: list[bytes] = []
    pending_bytes = 0

    def flush(handle):
        nonlocal pending_bytes
        if not pending:
            return
        raw = b"".join(pending)
        encoded = zlib.compress(raw, level=1)
        handle.write(_ZLIB_HEADER.pack(len(encoded), len(raw), len(pending),
                                       zlib.crc32(raw)))
        handle.write(encoded)
        pending.clear()
        pending_bytes = 0

    with Path(path).open("wb") as handle:
        handle.write(_ZLIB_MAGIC)
        source = (events._iter_borrowed() if isinstance(events, EventJournalSnapshot)
                  else events)
        for event in source:
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
            line = encoded + b"\n"
            if len(line) > _ZLIB_MAX_RAW:
                raise ValueError("compressed event exceeds block size")
            if pending and (len(pending) >= chunk_events
                            or pending_bytes + len(line) > _ZLIB_MAX_RAW):
                flush(handle)
            if semantic_digest is not None:
                if count:
                    semantic_digest.update(b",")
                semantic_digest.update(encoded)
            pending.append(line)
            pending_bytes += len(line)
            count += 1
        flush(handle)
        handle.flush()
        import os
        os.fsync(handle.fileno())
    return count


class ZlibChunkEventView(Sequence[dict]):
    """Validated indexed compressed event view; each lookup inflates one block."""

    def __init__(self, path: Path, expected_count: int) -> None:
        if type(expected_count) is not int or expected_count < 0:
            raise ValueError("invalid compressed event count")
        self.path = Path(path)
        self._blocks: list[tuple[int, int, int, int, int]] = []
        self._starts: list[int] = []
        self._count = 0
        self._cache_index = -1
        self._cache_events: list[dict] = []
        self._semantic_digest = hashlib.sha256(b'{"events":[')
        with self.path.open("rb") as handle:
            if handle.read(4) != _ZLIB_MAGIC:
                raise ValueError("invalid compressed event magic")
            while True:
                header = handle.read(_ZLIB_HEADER.size)
                if not header:
                    break
                if len(header) != _ZLIB_HEADER.size:
                    raise ValueError("truncated compressed event header")
                comp_len, raw_len, block_count, crc = _ZLIB_HEADER.unpack(header)
                if (not 0 < comp_len <= _ZLIB_MAX_COMPRESSED
                        or not 0 < raw_len <= _ZLIB_MAX_RAW):
                    raise ValueError("invalid compressed event block size")
                if not 0 < block_count <= 4096:
                    raise ValueError("invalid compressed event block count")
                offset = handle.tell()
                compressed = handle.read(comp_len)
                if len(compressed) != comp_len:
                    raise ValueError("truncated compressed event block")
                decoded = self._decode(compressed, raw_len, block_count, crc)
                self._starts.append(self._count)
                for event in decoded:
                    if self._count:
                        self._semantic_digest.update(b",")
                    self._semantic_digest.update(json.dumps(
                        event, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False).encode("utf-8"))
                    self._count += 1
                self._blocks.append((offset, comp_len, raw_len, block_count, crc))
        if self._count != expected_count:
            raise ValueError("compressed event count mismatch")

    def verify_trace_semantic(self, *, status: str, local_ticks: dict,
                              expected_sha256: str) -> None:
        digest = self._semantic_digest.copy()
        digest.update(b'],"local_ticks":')
        digest.update(json.dumps(local_ticks, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8"))
        digest.update(b',"status":')
        digest.update(json.dumps(status, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8"))
        digest.update(b"}")
        if digest.hexdigest() != expected_sha256:
            raise ValueError("compressed trace semantic SHA mismatch")

    @staticmethod
    def _decode(data: bytes, raw_len: int, count: int, crc: int) -> list[dict]:
        try:
            decompressor = zlib.decompressobj()
            raw = decompressor.decompress(data, raw_len + 1)
            if (not decompressor.eof or decompressor.unused_data
                    or decompressor.unconsumed_tail or len(raw) != raw_len):
                raise ValueError("invalid compressed event payload")
            if zlib.crc32(raw) != crc:
                raise ValueError("compressed event CRC mismatch")
            if not raw.endswith(b"\n"):
                raise ValueError("unterminated compressed event")
            events = [json.loads(line) for line in raw.splitlines()]
            if len(events) != count or any(type(event) is not dict for event in events):
                raise ValueError("compressed event block count mismatch")
            return events
        except (zlib.error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid compressed event payload") from exc

    def _block(self, index: int) -> list[dict]:
        if index != self._cache_index:
            offset, comp_len, raw_len, count, crc = self._blocks[index]
            with self.path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(comp_len)
            self._cache_events = self._decode(data, raw_len, count, crc)
            self._cache_index = index
        return self._cache_events

    def __len__(self) -> int:
        return self._count

    def __getitem__(self, index):
        if isinstance(index, slice):
            return tuple(self[position] for position in range(*index.indices(len(self))))
        if type(index) is not int:
            raise TypeError("event index must be an integer or slice")
        if index < 0:
            index += self._count
        if not 0 <= index < self._count:
            raise IndexError("event index out of range")
        block = bisect_right(self._starts, index) - 1
        return self._block(block)[index - self._starts[block]]

    def __iter__(self) -> Iterator[dict]:
        for index in range(len(self._blocks)):
            yield from self._block(index)
