"""Freeze RAM responses when the memory service commits a CPU request."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import OrderedDict
import hashlib
import json
from typing import ClassVar

from .ledger import TransactionKey, TransactionLedger
from .memory import PersistentMemory, ReadSnapshot


@dataclass(frozen=True)
class WriteReceipt:
    transaction_id: TransactionKey
    version: tuple[int, int] | None
    byte_enable: int
    # Keep the legacy three-field dataclass constructor, repr, equality and
    # asdict wire shape. Only the actual service callback attaches frozen bytes.
    _commit_json: ClassVar[bytes | None] = None

    def commit_document(self) -> dict:
        """Detached successful host-memory effect facts, not source authority.

        Stored bytes freeze the original callback outcome. Reading a receipt
        never reads/materializes RAM or substitutes a later equal-value store.
        Legacy manually constructed receipts have no measured commit document.
        """
        if self._commit_json is None:
            raise ValueError('write receipt has no measured commit document')
        return json.loads(self._commit_json)


class MemoryService:
    def __init__(self, memory: PersistentMemory,
                 ledger: TransactionLedger, *, include_writer_kinds: bool = False,
                 commit_stream_capacity: int | None = None) -> None:
        if type(include_writer_kinds) is not bool:
            raise ValueError("include_writer_kinds must be boolean")
        if commit_stream_capacity is not None and (type(commit_stream_capacity) is not int
                                                   or commit_stream_capacity < 1):
            raise ValueError('commit stream capacity must be a positive integer')
        self.memory = memory
        self.ledger = ledger
        self.include_writer_kinds = include_writer_kinds
        self.events: list[dict] = []
        self._commit_stream_capacity = commit_stream_capacity
        self._pending_commits = OrderedDict()
        self._issued_receipt_ids = {}
        self._service_commit_sequence = 0
        self._commit_reserved = 0

    @property
    def commit_stream_enabled(self) -> bool:
        return self._commit_stream_capacity is not None

    @property
    def pending_commit_count(self) -> int:
        return len(self._pending_commits)

    def lookup_pending_commit(self, commit_id: str) -> tuple[WriteReceipt, dict]:
        """Lookup only this service's unacknowledged actual callback issuance.

        The digest indexes existing issuance; it cannot enroll caller documents.
        Root must confirm the installed service before treating this as authority.
        """
        if type(commit_id) is not str or commit_id not in self._pending_commits:
            raise ValueError('commit was not issued or has been acknowledged')
        receipt, frozen, event = self._pending_commits[commit_id]
        entry = self.ledger._entries.get(receipt.transaction_id)
        if (entry is None or entry.status != 'complete' or entry.receipt is not receipt
                or type(receipt._commit_json) is not bytes or receipt._commit_json != frozen):
            raise RuntimeError('issued commit no longer matches the completed callback receipt')
        return receipt, json.loads(event)

    def lookup_issued_write_commit(self, receipt: WriteReceipt) -> dict:
        commit_id = self._issued_receipt_ids.get(id(receipt))
        if commit_id is None:
            raise ValueError('receipt was not issued or has been acknowledged')
        actual, event = self.lookup_pending_commit(commit_id)
        if actual is not receipt:
            raise ValueError('receipt is not the actual issued callback object')
        return event

    def drain_commit_events(self, max_events: int | None = None) -> tuple[dict, ...]:
        """Detached FIFO prefix; records remain live until explicit prefix ack."""
        if max_events is not None and (type(max_events) is not int or max_events < 1):
            raise ValueError('drain limit must be a positive integer')
        keys = tuple(self._pending_commits)
        if max_events is not None:
            keys = keys[:max_events]
        return tuple(self.lookup_pending_commit(key)[1] for key in keys)

    def ack_commit_events(self, commit_ids: tuple[str, ...]) -> None:
        """Release exact FIFO prefix; acknowledged issuance never resurrects."""
        if (type(commit_ids) is not tuple or any(type(key) is not str for key in commit_ids)
                or commit_ids != tuple(self._pending_commits)[:len(commit_ids)]):
            raise ValueError('ack must name the exact pending commit prefix')
        for key in commit_ids:
            receipt, _, _ = self._pending_commits.pop(key)
            del self._issued_receipt_ids[id(receipt)]

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str) -> None:
        self.memory.accept_instructions(address, data, source_event_id=source_event_id)
        self.events.append({"kind": "instruction_source", "address": address,
                            "data_hex": data.hex(), "source_event_id": source_event_id,
                            "generation": self.memory.generation})

    def read(self, key: TransactionKey, address: int, *,
             width_bytes: int) -> ReadSnapshot:
        payload = {"op": "read", "address": address, "width_bytes": width_bytes}
        self.memory.validate_read(address, width_bytes)
        def commit() -> ReadSnapshot:
            snapshot = self.memory.read(address, width_bytes,
                                        transaction_id=str(key))
            for byte_offset in snapshot.materialized_offsets:
                lane = byte_offset - snapshot.byte_offset
                self.events.append({"kind": "memory_initialization",
                                    "transaction": asdict(key),
                                    "memory_id": snapshot.memory_id,
                                    "generation": snapshot.generation,
                                    "byte_offset": byte_offset,
                                    "value": snapshot.data[lane],
                                    "version": snapshot.versions[lane],
                                    "writer_event_id": snapshot.writer_event_ids[lane]})
            record = {"kind": "memory_read", "transaction": asdict(key),
                                "address": address, "width_bytes": width_bytes,
                                "memory_id": snapshot.memory_id,
                                "generation": snapshot.generation,
                                "byte_offset": snapshot.byte_offset,
                                "value": snapshot.value,
                                "data_hex": snapshot.data.hex(),
                                "versions": snapshot.versions,
                                "writer_event_ids": snapshot.writer_event_ids}
            if self.include_writer_kinds:
                record["writer_kinds"] = snapshot.writer_kinds
            self.events.append(record)
            return snapshot

        return self.ledger.execute_once(key, payload, commit)

    def write(self, key: TransactionKey, address: int, value: int, *,
              width_bytes: int, byte_enable: int) -> WriteReceipt:
        if (type(key) is not TransactionKey
                or any(type(getattr(key, name)) is not str or not getattr(key, name)
                       for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or any(type(getattr(key, name)) is not int or not 0 <= getattr(key, name) < 1 << 64
                       for name in ('source_epoch', 'source_sequence'))):
            raise ValueError('write requires a complete typed transaction key')
        payload = {"op": "write", "address": address, "value": value,
                   "width_bytes": width_bytes, "byte_enable": byte_enable}
        self.memory.validate_write(address, value, width_bytes=width_bytes,
                                   byte_enable=byte_enable)
        if (self.commit_stream_enabled and key not in self.ledger._entries
                and len(self._pending_commits) + self._commit_reserved >= self._commit_stream_capacity):
            raise RuntimeError('memory commit stream capacity exceeded before effect')
        actual_callback = None
        reserved = False

        def commit() -> WriteReceipt:
            nonlocal actual_callback, reserved
            if self.commit_stream_enabled:
                if len(self._pending_commits) + self._commit_reserved >= self._commit_stream_capacity:
                    raise RuntimeError('memory commit stream capacity exceeded before effect')
                self._commit_reserved += 1
                reserved = True
            memory_id, generation, byte_offset = self.memory.resolve_span(
                address, width_bytes, write=True)
            version = self.memory.write(address, value, width_bytes=width_bytes,
                                        byte_enable=byte_enable,
                                        writer_event_id=str(key))
            actual_region, actual_offset = self.memory._resolve(address, width_bytes, write=True)
            if (type(memory_id) is not str or not memory_id
                    or type(generation) is not int or not 0 <= generation < 1 << 64
                    or type(byte_offset) is not int or not 0 <= byte_offset < 1 << 64
                    or memory_id != actual_region.memory_id or byte_offset != actual_offset
                    or type(self.memory.generation) is not int or generation != self.memory.generation):
                raise RuntimeError('host memory span identity conflicts with commit')
            def typed_version(candidate) -> bool:
                return (type(candidate) is tuple and len(candidate) == 2
                        and all(type(n) is int and 0 <= n < 1 << 64 for n in candidate))
            if (byte_enable == 0 and version is not None
                    or byte_enable != 0 and (not typed_version(version)
                        or type(generation) is not int or version[0] != generation
                        or type(self.memory._commit_sequences[memory_id]) is not int
                        or version[1] != self.memory._commit_sequences[memory_id]
                        or version[1] == 0)):
                raise RuntimeError('host memory write outcome conflicts with commit')
            cells = []
            for lane in range(width_bytes):
                if not byte_enable >> lane & 1:
                    continue
                cell = self.memory._bytes[(memory_id, byte_offset + lane)]
                if (not typed_version(cell.version) or cell.version != version
                        or type(cell.value) is not int or not 0 <= cell.value < 256
                        or type(cell.writer_kind) is not str or cell.writer_kind != 'STORE'
                        or cell.writer_event_id != str(key)
                        or cell.value != value >> (8 * lane) & 0xff):
                    raise RuntimeError('host memory write outcome conflicts with commit')
                cells.append(dict(byte_offset=byte_offset + lane, value=cell.value,
                    version=list(cell.version), writer_kind=cell.writer_kind,
                    writer_event_id=cell.writer_event_id))
            document = dict(schema_version='memory_write_commit_receipt.v1',
                fullkey=asdict(key), memory_kind='modeled_host_persistent_memory',
                memory_id=memory_id, generation=generation, byte_offset=byte_offset,
                width_bytes=width_bytes, byte_enable=byte_enable,
                version=list(version) if version is not None else None,
                payload_sha256=TransactionLedger._digest(payload),
                commit_status='complete', performed_effect=version is not None,
                enabled_byte_cells=cells)
            encoded = json.dumps(document, sort_keys=True, separators=(',', ':'),
                                 allow_nan=False).encode()
            document['commit_id'] = hashlib.sha256(encoded).hexdigest()
            receipt = WriteReceipt(key, version, byte_enable)
            object.__setattr__(receipt, '_commit_json',
                json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
            self.events.append({"kind": "memory_write", "transaction": asdict(key),
                                "address": address, "width_bytes": width_bytes,
                                "memory_id": memory_id,
                                "generation": generation,
                                "byte_offset": byte_offset,
                                "value": value, "byte_enable": byte_enable,
                                "version": version})
            actual_callback = (receipt, receipt._commit_json)
            return receipt

        try:
            result = self.ledger.execute_once(key, payload, commit)
            if self.commit_stream_enabled and actual_callback is not None:
                receipt, frozen = actual_callback
                entry = self.ledger._entries.get(key)
                if (entry is None or entry.status != 'complete' or entry.receipt is not receipt
                        or result is not receipt or receipt._commit_json != frozen):
                    raise RuntimeError('memory commit publication requires actual completed callback')
                document = json.loads(frozen)
                commit_id = document['commit_id']
                self._service_commit_sequence += 1
                event = dict(kind='memory_write_commit', schema_version='memory_write_commit.v1',
                    service_commit_sequence=self._service_commit_sequence, transaction=asdict(key),
                    commit_id=commit_id, commit_document=document)
                encoded = json.dumps(event, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
                self._pending_commits[commit_id] = (receipt, frozen, encoded)
                self._issued_receipt_ids[id(receipt)] = commit_id
            return result
        finally:
            if reserved:
                self._commit_reserved -= 1
