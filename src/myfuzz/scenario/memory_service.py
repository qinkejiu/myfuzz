"""Freeze RAM responses when the memory service commits a CPU request."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ledger import TransactionKey, TransactionLedger
from .memory import PersistentMemory, ReadSnapshot


@dataclass(frozen=True)
class WriteReceipt:
    transaction_id: TransactionKey
    version: tuple[int, int] | None
    byte_enable: int


class MemoryService:
    def __init__(self, memory: PersistentMemory,
                 ledger: TransactionLedger) -> None:
        self.memory = memory
        self.ledger = ledger
        self.events: list[dict] = []

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
            self.events.append({"kind": "memory_read", "transaction": asdict(key),
                                "address": address, "width_bytes": width_bytes,
                                "memory_id": snapshot.memory_id,
                                "generation": snapshot.generation,
                                "byte_offset": snapshot.byte_offset,
                                "value": snapshot.value,
                                "data_hex": snapshot.data.hex(),
                                "versions": snapshot.versions,
                                "writer_event_ids": snapshot.writer_event_ids})
            return snapshot

        return self.ledger.execute_once(key, payload, commit)

    def write(self, key: TransactionKey, address: int, value: int, *,
              width_bytes: int, byte_enable: int) -> WriteReceipt:
        payload = {"op": "write", "address": address, "value": value,
                   "width_bytes": width_bytes, "byte_enable": byte_enable}
        self.memory.validate_write(address, value, width_bytes=width_bytes,
                                   byte_enable=byte_enable)

        def commit() -> WriteReceipt:
            memory_id, generation, byte_offset = self.memory.resolve_span(
                address, width_bytes, write=True)
            version = self.memory.write(address, value, width_bytes=width_bytes,
                                        byte_enable=byte_enable,
                                        writer_event_id=str(key))
            self.events.append({"kind": "memory_write", "transaction": asdict(key),
                                "address": address, "width_bytes": width_bytes,
                                "memory_id": memory_id,
                                "generation": generation,
                                "byte_offset": byte_offset,
                                "value": value, "byte_enable": byte_enable,
                                "version": version})
            return WriteReceipt(key, version, byte_enable)

        return self.ledger.execute_once(key, payload, commit)
