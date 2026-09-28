"""Authoritative byte memory for one continuously running testcase.

This is environment RAM/ROM. Device MMIO must be served by its real RTL.
Each instance starts at generation zero and is owned by exactly one testcase.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json


_MAX_ADDRESS = (1 << 64) - 1
_WIDTHS = frozenset((1, 2, 4, 8))


def _natural(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


@dataclass(frozen=True)
class MemoryRegion:
    memory_id: str
    base: int
    size: int
    aliases: tuple[int, ...] = ()
    readable: bool = True
    writable: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.memory_id, str) or not self.memory_id:
            raise ValueError("memory_id must be a nonempty string")
        _natural(self.base, "base")
        _natural(self.size, "size")
        if self.size == 0 or self.base > _MAX_ADDRESS - self.size + 1:
            raise ValueError("memory region exceeds address bounds")
        if not isinstance(self.aliases, tuple):
            raise ValueError("aliases must be a tuple")
        for alias in self.aliases:
            _natural(alias, "alias")
            if alias > _MAX_ADDRESS - self.size + 1:
                raise ValueError("memory alias exceeds address bounds")
        if not isinstance(self.readable, bool) or not isinstance(self.writable, bool):
            raise ValueError("memory permissions must be boolean")


@dataclass(frozen=True)
class ByteCell:
    value: int
    version: tuple[int, int]
    writer_kind: str
    writer_event_id: str


@dataclass(frozen=True)
class ReadSnapshot:
    transaction_id: str
    memory_id: str
    generation: int
    byte_offset: int
    data: bytes
    versions: tuple[tuple[int, int], ...]
    writer_event_ids: tuple[str, ...]
    materialized_offsets: tuple[int, ...] = ()

    @property
    def value(self) -> int:
        return int.from_bytes(self.data, "little")


class PersistentMemory:
    """A sparse, versioned memory with immutable read results."""

    def __init__(self, *, regions: tuple[MemoryRegion, ...],
                 initialization_seed: int, max_initialized_bytes: int) -> None:
        _natural(initialization_seed, "initialization_seed")
        _natural(max_initialized_bytes, "max_initialized_bytes")
        if not isinstance(regions, tuple) or not regions:
            raise ValueError("regions must be a nonempty tuple")
        self._regions = regions
        self._windows: list[tuple[int, int, MemoryRegion]] = []
        seen_ids: set[str] = set()
        for region in regions:
            if not isinstance(region, MemoryRegion):
                raise ValueError("regions must contain MemoryRegion entries")
            if region.memory_id in seen_ids:
                raise ValueError(f"duplicate memory_id {region.memory_id}")
            seen_ids.add(region.memory_id)
            for base in (region.base, *region.aliases):
                end = base + region.size
                if any(base < old_end and old_base < end
                       for old_base, old_end, _ in self._windows):
                    raise ValueError("overlapping memory windows")
                self._windows.append((base, end, region))
        self.initialization_seed = initialization_seed
        self.max_initialized_bytes = max_initialized_bytes
        self.generation = 0
        self.step_count = 0
        self._bytes: dict[tuple[str, int], ByteCell] = {}
        self._initial_images: dict[tuple[str, int], int] = {}
        self._commit_sequences = {region.memory_id: 0 for region in regions}

    @property
    def initialized_bytes(self) -> int:
        return len(self._bytes)

    @property
    def memory_ids(self) -> tuple[str, ...]:
        return tuple(region.memory_id for region in self._regions)

    def identity_document(self) -> dict:
        """Immutable memory configuration used to guard replay identity."""
        return {"regions": [asdict(region) for region in self._regions],
                "initialization_seed": self.initialization_seed,
                "initialization_algorithm": "memory-init-v1",
                "max_initialized_bytes": self.max_initialized_bytes}

    def state_summary(self) -> dict:
        """Digest every persistent byte, writer, and version without reading RAM."""
        digest = hashlib.sha256()
        for (memory_id, offset), cell in sorted(self._bytes.items()):
            record = [memory_id, offset, cell.value, cell.version,
                      cell.writer_kind, cell.writer_event_id]
            digest.update(json.dumps(record, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8") + b"\n")
        return {"generation": self.generation,
                "step_count": self.step_count,
                "initialized_bytes": self.initialized_bytes,
                "commit_sequences": dict(self._commit_sequences),
                "cells_sha256": digest.hexdigest()}

    def advance_step(self) -> None:
        self.step_count += 1

    def _resolve(self, address: int, width_bytes: int,
                 *, write: bool) -> tuple[MemoryRegion, int]:
        _natural(address, "address")
        if address > _MAX_ADDRESS:
            raise ValueError("address exceeds address bounds")
        if isinstance(width_bytes, bool) or width_bytes not in _WIDTHS:
            raise ValueError("unsupported access width")
        if address % width_bytes:
            raise ValueError("unaligned access")
        if width_bytes - 1 > _MAX_ADDRESS - address:
            raise ValueError("address span exceeds address bounds")
        for base, end, region in self._windows:
            if base <= address < end:
                if address + width_bytes > end:
                    raise ValueError("access crosses memory window")
                if write and not region.writable:
                    raise ValueError("read-only memory")
                if not write and not region.readable:
                    raise ValueError("write-only memory")
                return region, address - base
        raise ValueError("unmapped address; MMIO requires real IP response")

    def resolve_span(self, address: int, width_bytes: int, *,
                     write: bool = False) -> tuple[str, int, int]:
        """Return stable memory/generation/byte-offset identity for a valid span."""
        region, offset = self._resolve(address, width_bytes, write=write)
        return region.memory_id, self.generation, offset

    def _initial_byte(self, memory_id: str, offset: int) -> int:
        fields = ["memory-init-v1", self.initialization_seed,
                  memory_id, self.generation, offset]
        encoded = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).digest()[0]

    def _next_version(self, memory_id: str) -> tuple[int, int]:
        sequence = self._commit_sequences[memory_id] + 1
        self._commit_sequences[memory_id] = sequence
        return (self.generation, sequence)

    def _budget(self, additions: int) -> None:
        if self.initialized_bytes + additions > self.max_initialized_bytes:
            raise ValueError("initialized byte budget exceeded")

    def validate_read(self, address: int, width_bytes: int) -> None:
        """Reject a read with no state change before its transaction is accepted."""
        region, offset = self._resolve(address, width_bytes, write=False)
        missing = sum((region.memory_id, offset + index) not in self._bytes
                      for index in range(width_bytes))
        if missing and not region.writable:
            raise ValueError("uninitialized read-only memory")
        self._budget(missing)

    def validate_write(self, address: int, value: int, *, width_bytes: int,
                       byte_enable: int) -> None:
        """Check access shape and capacity without committing a byte."""
        region, offset = self._resolve(address, width_bytes, write=True)
        _natural(value, "value")
        if value >= 1 << (8 * width_bytes):
            raise ValueError("value exceeds access width")
        _natural(byte_enable, "byte_enable")
        if byte_enable >= 1 << width_bytes:
            raise ValueError("byte_enable exceeds access width")
        self._budget(sum((region.memory_id, offset + index) not in self._bytes
                         for index in range(width_bytes)
                         if byte_enable >> index & 1))

    def preload(self, address: int, data: bytes) -> None:
        if not isinstance(data, bytes) or not data:
            raise ValueError("preload data must be nonempty bytes")
        region, offset = self._resolve(address, 1, write=False)
        if offset + len(data) > region.size:
            raise ValueError("preload crosses memory window")
        keys = [(region.memory_id, offset + index) for index in range(len(data))]
        if any(key in self._bytes for key in keys):
            raise ValueError("preload would overwrite initialized bytes")
        self._budget(len(keys))
        for key, value in zip(keys, data):
            self._initial_images[key] = value
            self._bytes[key] = ByteCell(value, (self.generation, 0),
                                        "INITIAL_IMAGE", "initial-image")

    def read(self, address: int, width_bytes: int, *,
             transaction_id: str) -> ReadSnapshot:
        if not isinstance(transaction_id, str) or not transaction_id:
            raise ValueError("transaction_id must be nonempty")
        region, offset = self._resolve(address, width_bytes, write=False)
        keys = [(region.memory_id, offset + index) for index in range(width_bytes)]
        missing = [key for key in keys if key not in self._bytes]
        if missing and not region.writable:
            raise ValueError("uninitialized read-only memory")
        self._budget(len(missing))
        if missing:
            version = self._next_version(region.memory_id)
            for key in missing:
                self._bytes[key] = ByteCell(self._initial_byte(*key), version,
                                            "FIRST_READ", f"init:{region.memory_id}:{key[1]}")
        cells = tuple(self._bytes[key] for key in keys)
        return ReadSnapshot(transaction_id, region.memory_id, self.generation,
                            offset, bytes(cell.value for cell in cells),
                            tuple(cell.version for cell in cells),
                            tuple(cell.writer_event_id for cell in cells),
                            tuple(key[1] for key in missing))

    def write(self, address: int, value: int, *, width_bytes: int,
              byte_enable: int, writer_event_id: str) -> tuple[int, int] | None:
        if not isinstance(writer_event_id, str) or not writer_event_id:
            raise ValueError("writer_event_id must be nonempty")
        region, offset = self._resolve(address, width_bytes, write=True)
        _natural(value, "value")
        if value >= 1 << (8 * width_bytes):
            raise ValueError("value exceeds access width")
        _natural(byte_enable, "byte_enable")
        if byte_enable >= 1 << width_bytes:
            raise ValueError("byte_enable exceeds access width")
        enabled = [index for index in range(width_bytes) if byte_enable >> index & 1]
        self._budget(sum((region.memory_id, offset + index) not in self._bytes
                         for index in enabled))
        if not enabled:
            return None
        version = self._next_version(region.memory_id)
        for index in enabled:
            byte = value >> (8 * index) & 0xFF
            self._bytes[(region.memory_id, offset + index)] = ByteCell(
                byte, version, "STORE", writer_event_id)
        return version

    def warm_reset(self) -> None:
        """Keep committed memory and generation during a whole-scene warm reset."""

    def cold_reset(self) -> None:
        """Start a new generation and reapply only the declared initial image."""
        self.generation += 1
        self._bytes = {
            key: ByteCell(value, (self.generation, 0), "INITIAL_IMAGE", "initial-image")
            for key, value in self._initial_images.items()
        }
        self._commit_sequences = {region.memory_id: 0 for region in self._regions}
