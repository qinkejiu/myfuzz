"""Authoritative byte memory for one continuously running testcase.

This is environment RAM/ROM. Device MMIO must be served by its real RTL.
Each instance starts at generation zero and persists throughout one session.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import sys
from weakref import ref


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
    writer_kinds: tuple[str, ...] = ()

    @property
    def value(self) -> int:
        return int.from_bytes(self.data, "little")


@dataclass(frozen=True, slots=True)
class InstructionAcceptance:
    """Actual host instruction-byte write; no CPU transfer/source grant."""

    memory_id: str
    address: int
    byte_offset: int
    generation: int
    data: bytes
    source_event_id: str
    versions: tuple[tuple[int, int], ...]
    writer_event_ids: tuple[str, ...]
    writer_kinds: tuple[str, ...]


def _acceptance_material(receipt):
    if (type(receipt) is not InstructionAcceptance
            or type(receipt.memory_id) is not str or not receipt.memory_id
            or type(receipt.source_event_id) is not str or not receipt.source_event_id
            or any(type(v) is not int or v < 0 for v in
                   (receipt.address, receipt.byte_offset, receipt.generation))
            or type(receipt.data) is not bytes or not receipt.data or len(receipt.data) % 4
            or any(type(v) is not tuple or len(v) != len(receipt.data)
                   for v in (receipt.versions, receipt.writer_event_ids, receipt.writer_kinds))
            or any(type(v) is not tuple or len(v) != 2
                   or any(type(part) is not int or part < 0 for part in v)
                   for v in receipt.versions)
            or any(type(v) is not str for v in (*receipt.writer_event_ids, *receipt.writer_kinds))):
        raise ValueError('invalid instruction acceptance material')
    return (receipt.memory_id, receipt.address, receipt.byte_offset,
            receipt.generation, receipt.data, receipt.source_event_id,
            receipt.versions, receipt.writer_event_ids, receipt.writer_kinds)


def _instruction_acceptance_registry():
    issued = {}
    producer = None

    def bind(method):
        nonlocal producer
        if producer is not None or method is not PersistentMemory.accept_instructions:
            raise ValueError('instruction acceptance producer is already bound or foreign')
        producer = (method, method.__code__)

    def original_producer(owner):
        method, code = producer
        bound = getattr(owner, 'accept_instructions', None)
        if (PersistentMemory.accept_instructions is not method or method.__code__ is not code
                or 'accept_instructions' in vars(owner)
                or getattr(bound, '__self__', None) is not owner
                or getattr(bound, '__func__', None) is not method):
            raise ValueError('instruction acceptance producer was replaced')
        return method, code

    def owner_records(owner):
        row = issued.get(id(owner))
        return row[1] if row is not None and row[0]() is owner else None

    def register(owner, receipt):
        frame = sys._getframe(1)
        method, code = original_producer(owner)
        if (frame.f_code is not code or frame.f_globals is not globals()
                or frame.f_locals.get('self') is not owner
                or PersistentMemory.accept_instructions is not method
                or method.__code__ is not code):
            raise ValueError('instruction acceptance must originate in actual memory write')
        records = owner_records(owner)
        if records is None:
            owner_id = id(owner)

            def expired(reference):
                row = issued.get(owner_id)
                if row is not None and row[0] is reference:
                    issued.pop(owner_id)

            records = {}
            issued[owner_id] = (ref(owner, expired), records)
        records[id(receipt)] = (receipt, _acceptance_material(receipt))

    def validate(owner, receipt):
        original_producer(owner)
        records = owner_records(owner)
        row = records.get(id(receipt)) if records is not None else None
        if (row is None or row[0] is not receipt
                or _acceptance_material(receipt) != row[1]
                or receipt.generation != owner.generation):
            raise ValueError('instruction acceptance is not an unchanged actual issued result')
        return receipt

    def revoke(owner):
        if owner_records(owner) is not None:
            issued.pop(id(owner))

    def accept(owner, address, data, *, source_event_id):
        method, _ = original_producer(owner)
        # Invoke the captured actual write for this call, never an override
        # that can replay an earlier genuine result.
        return method(owner, address, data, source_event_id=source_event_id)

    return register, validate, revoke, bind, accept


(_REGISTER_INSTRUCTION_ACCEPTANCE, _VALIDATE_INSTRUCTION_ACCEPTANCE,
 _REVOKE_INSTRUCTION_ACCEPTANCES, _BIND_INSTRUCTION_ACCEPTANCE_PRODUCER,
 _ACCEPT_ISSUED_INSTRUCTIONS) = _instruction_acceptance_registry()


class InstructionNotReady(ValueError):
    """Declared online instruction bytes await their source."""


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
        self._instruction_slots: set[tuple[str, int]] = set()
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
                "max_initialized_bytes": self.max_initialized_bytes,
                "instruction_slots": sorted(self._instruction_slots)}

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

    def determined_bytes(self) -> tuple[tuple[str, int, int, str], ...]:
        """Every determined byte as ``(memory_id, offset, value, writer_kind)``.

        A read-only view of committed state without reading RAM: a byte a real
        read, Store or initial image already determined can never be presented
        to a caller as un-materialized.
        """
        return tuple(sorted((memory_id, offset, cell.value, cell.writer_kind)
                            for (memory_id, offset), cell in self._bytes.items()))

    def inspect_byte(self, memory_id: str, byte_offset: int) -> ByteCell | None:
        """Inspect one already determined cell without initializing or reading RAM."""
        if (type(memory_id) is not str or memory_id not in self.memory_ids
                or type(byte_offset) is not int or not 0 <= byte_offset < 1 << 64):
            raise ValueError('invalid memory byte inspection')
        cell = self._bytes.get((memory_id, byte_offset))
        return (ByteCell(cell.value, cell.version, cell.writer_kind, cell.writer_event_id)
                if cell is not None else None)

    def reserved_instruction_bytes(self) -> tuple[tuple[str, int], ...]:
        """Reserved instruction slots a real fetch still has to determine."""
        return tuple(sorted(key for key in self._instruction_slots
                            if key not in self._bytes))

    def instruction_slot_unmaterialized(self, address: int) -> bool:
        """Check one declared word against current cells without initializing it."""
        if type(address) is not int or address < 0 or address % 4:
            raise ValueError('invalid instruction slot inspection')
        memory_id, _, offset = self.resolve_span(address, 4)
        return all((memory_id, offset + lane) in self._instruction_slots
                   and (memory_id, offset + lane) not in self._bytes for lane in range(4))

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
        self._check_instruction_ready(region.memory_id, offset, width_bytes)
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
        if any(key in self._bytes or key in self._instruction_slots for key in keys):
            raise ValueError("preload would overwrite initialized or reserved instruction bytes")
        self._budget(len(keys))
        for key, value in zip(keys, data):
            self._initial_images[key] = value
            self._bytes[key] = ByteCell(value, (self.generation, 0),
                                        "INITIAL_IMAGE", "initial-image")

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        """Reserve empty aligned words without materializing RAM."""
        _natural(count, "count")
        if not count:
            raise ValueError("instruction slot count must be positive")
        region, offset = self._resolve(address, 4, write=False)
        if offset + count * 4 > region.size:
            raise ValueError("instruction slots cross memory window")
        keys = {(region.memory_id, offset + lane) for lane in range(count * 4)}
        if any(key in self._bytes for key in keys):
            raise ValueError("instruction slots contain determined bytes")
        self._instruction_slots.update(keys)

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str) -> InstructionAcceptance:
        """Fill reserved words once and record the input source for every byte."""
        from .rv32i_sources import validate_instruction_bytes
        validate_instruction_bytes(data)
        if not isinstance(source_event_id, str) or not source_event_id:
            raise ValueError("instruction source_event_id must be nonempty")
        region, offset = self._resolve(address, 4, write=False)
        if offset + len(data) > region.size:
            raise ValueError("instruction fragment crosses memory window")
        keys = [(region.memory_id, offset + lane) for lane in range(len(data))]
        if any(key not in self._instruction_slots for key in keys):
            raise ValueError("instruction bytes are outside declared online slots")
        if any(key in self._bytes for key in keys):
            raise ValueError("instruction admission would overwrite determined bytes")
        self._budget(len(keys))
        version = self._next_version(region.memory_id)
        for key, value in zip(keys, data):
            self._bytes[key] = ByteCell(value, version, "INSTRUCTION_SOURCE", source_event_id)
        cells = tuple(self._bytes[key] for key in keys)
        receipt = InstructionAcceptance(str(region.memory_id), int(address), offset,
            self.generation, bytes(data), str(source_event_id),
            tuple(cell.version for cell in cells),
            tuple(str(cell.writer_event_id) for cell in cells),
            tuple(str(cell.writer_kind) for cell in cells))
        _REGISTER_INSTRUCTION_ACCEPTANCE(self, receipt)
        return receipt

    def validate_instruction_acceptance(self, receipt: InstructionAcceptance) -> InstructionAcceptance:
        """Validate original issued identity/material, without reading memory."""
        return _VALIDATE_INSTRUCTION_ACCEPTANCE(self, receipt)

    def _check_instruction_ready(self, memory_id: str, offset: int, width_bytes: int) -> None:
        if any((memory_id, offset + lane) in self._instruction_slots
               and (memory_id, offset + lane) not in self._bytes for lane in range(width_bytes)):
            raise InstructionNotReady("online instruction slot awaits its source")

    def read(self, address: int, width_bytes: int, *,
             transaction_id: str) -> ReadSnapshot:
        if not isinstance(transaction_id, str) or not transaction_id:
            raise ValueError("transaction_id must be nonempty")
        region, offset = self._resolve(address, width_bytes, write=False)
        self._check_instruction_ready(region.memory_id, offset, width_bytes)
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
        snapshot = ReadSnapshot(transaction_id, region.memory_id, self.generation,
                                offset, bytes(cell.value for cell in cells),
                                tuple(cell.version for cell in cells),
                                tuple(cell.writer_event_id for cell in cells),
                                tuple(key[1] for key in missing),
                                writer_kinds=tuple(cell.writer_kind for cell in cells))
        return snapshot

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
        _REVOKE_INSTRUCTION_ACCEPTANCES(self)

    def cold_reset(self) -> None:
        """Start a new generation and reapply only the declared initial image."""
        _REVOKE_INSTRUCTION_ACCEPTANCES(self)
        self.generation += 1
        self._bytes = {
            key: ByteCell(value, (self.generation, 0), "INITIAL_IMAGE", "initial-image")
            for key, value in self._initial_images.items()
        }
        self._commit_sequences = {region.memory_id: 0 for region in self._regions}


_BIND_INSTRUCTION_ACCEPTANCE_PRODUCER(PersistentMemory.accept_instructions)


def _native_read_snapshot_anchor():
    """Call the original memory read for service issuance, rejecting overrides."""
    method = PersistentMemory.read
    code = method.__code__
    issued = {}

    def original_producer(owner):
        bound = getattr(owner, 'read', None)
        if (type(owner) is not PersistentMemory
                or PersistentMemory.read is not method or method.__code__ is not code
                or 'read' in vars(owner)
                or getattr(bound, '__self__', None) is not owner
                or getattr(bound, '__func__', None) is not method):
            raise ValueError('native read requires original memory producer')

    def register(owner, issuer, snapshot):
        frame = sys._getframe(1)
        original_producer(owner)
        if (frame.f_code is not read.__code__ or frame.f_globals is not globals()
                or frame.f_locals.get('owner') is not owner
                or frame.f_locals.get('issuer') is not issuer
                or frame.f_locals.get('snapshot') is not snapshot
                or type(snapshot) is not ReadSnapshot):
            raise ValueError('snapshot requires actual memory read')
        issuer_id = id(issuer)

        def expired(reference):
            row = issued.get(issuer_id)
            if row is not None and any(item is reference for item in row[:3]):
                issued.pop(issuer_id)

        issued[issuer_id] = (ref(owner, expired), ref(issuer, expired),
                             ref(snapshot, expired),
                             tuple(getattr(snapshot, name) for name in
                                   ReadSnapshot.__dataclass_fields__))

    def validate(owner, issuer, snapshot):
        original_producer(owner)
        row = issued.get(id(issuer))
        if (row is None or row[0]() is not owner or row[1]() is not issuer
                or row[2]() is not snapshot
                or tuple(getattr(snapshot, name) for name in
                         ReadSnapshot.__dataclass_fields__) != row[3]
                or snapshot.generation != owner.generation):
            raise ValueError('snapshot is not an unchanged actual memory read')
        return snapshot

    def revoke(owner, issuer, snapshot=None):
        row = issued.get(id(issuer))
        if (row is not None and row[0]() is owner and row[1]() is issuer
                and (snapshot is None or row[2]() is snapshot)):
            issued.pop(id(issuer))

    def read(owner, address, width_bytes, *, transaction_id, issuer):
        original_producer(owner)
        snapshot = method(owner, address, width_bytes, transaction_id=transaction_id)
        register(owner, issuer, snapshot)
        return snapshot

    return register, validate, revoke, read


(_REGISTER_ACTUAL_SNAPSHOT, _VALIDATE_ACTUAL_SNAPSHOT,
 _REVOKE_ACTUAL_SNAPSHOT, _READ_ACTUAL_SNAPSHOT) = _native_read_snapshot_anchor()


def _native_instruction_memory_anchor():
    pins = tuple((getattr(PersistentMemory, name), getattr(PersistentMemory, name).__code__)
                 for name in ('validate_instruction_acceptance', 'resolve_span'))
    return lambda: pins


_NATIVE_INSTRUCTION_MEMORY_PRODUCERS = _native_instruction_memory_anchor()
