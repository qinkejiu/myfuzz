"""Freeze RAM responses when the memory service commits a CPU request."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from collections import OrderedDict
import hashlib
import json
import sys
from typing import ClassVar
from weakref import ref

from .ledger import TransactionKey, TransactionLedger
from .memory import (InstructionAcceptance, PersistentMemory, ReadSnapshot,
                     _ACCEPT_ISSUED_INSTRUCTIONS, _READ_ACTUAL_SNAPSHOT,
                     _VALIDATE_ACTUAL_SNAPSHOT, _REVOKE_ACTUAL_SNAPSHOT)


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

    def accept_instructions(self, address: int, data: bytes, *, source_event_id: str) -> InstructionAcceptance:
        receipt = _ACCEPT_ISSUED_INSTRUCTIONS(self.memory, address, data,
                                            source_event_id=source_event_id)
        PersistentMemory.validate_instruction_acceptance(self.memory, receipt)
        self.events.append({"kind": "instruction_source", "address": address,
                            "data_hex": data.hex(), "source_event_id": source_event_id,
                            "generation": self.memory.generation})
        return receipt

    def read(self, key: TransactionKey, address: int, *,
             width_bytes: int) -> ReadSnapshot:
        payload = {"op": "read", "address": address, "width_bytes": width_bytes}
        had_armed_read = _HAS_ARMED_ISSUED_READ(self)
        f6_token = _f6_dma_read_arm(self, key)
        try:
            self.memory.validate_read(address, width_bytes)
            native_armed = _IS_ARMED_ISSUED_READ(self, key)
        except BaseException:
            if f6_token is not None:
                _revoke_f6_dma_read(self)
            if had_armed_read:
                _REVOKE_ISSUED_READ(self)
            raise
        committed_snapshot = None
        committed_event = None

        def commit() -> ReadSnapshot:
            nonlocal committed_snapshot, committed_event
            if native_armed or f6_token is not None:
                snapshot = _READ_ACTUAL_SNAPSHOT(self.memory, address, width_bytes,
                    transaction_id=str(key), issuer=f6_token if f6_token is not None else self)
            else:
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
            committed_snapshot = snapshot
            committed_event = record
            return snapshot

        try:
            result = self.ledger.execute_once(key, payload, commit)
            if f6_token is not None:
                _register_f6_dma_read(self, key, result, committed_event, payload)
            if native_armed:
                if committed_snapshot is None:
                    raise ValueError('armed native read was replayed without a callback')
                _REGISTER_ISSUED_READ(self, self.memory, key, result,
                                      committed_event, payload)
            return result
        except BaseException:
            if f6_token is not None:
                _revoke_f6_dma_read(self)
            if native_armed:
                _REVOKE_ISSUED_READ(self)
            raise

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


def _native_instruction_service_anchor():
    method = MemoryService.accept_instructions
    pin = (method, method.__code__)
    return lambda: pin


_NATIVE_INSTRUCTION_SERVICE_PRODUCER = _native_instruction_service_anchor()


def _issued_read_registry():
    """Keep opaque handles for completed original service reads only."""
    method = MemoryService.read
    code = method.__code__
    issued = {}

    def owner_records(service):
        row = issued.get(id(service))
        return row[1] if row is not None and row[0]() is service else None

    def original_producer(service):
        bound = getattr(service, 'read', None)
        if (type(service) is not MemoryService
                or MemoryService.read is not method or method.__code__ is not code
                or 'read' in vars(service)
                or getattr(bound, '__self__', None) is not service
                or getattr(bound, '__func__', None) is not method):
            raise ValueError('native read requires original service producer')

    def arm(service, key):
        original_producer(service)
        if type(key) is not TransactionKey:
            raise ValueError('native read requires typed transaction key')
        records = owner_records(service)
        if records is None:
            owner_id = id(service)

            def expired(reference):
                row = issued.get(owner_id)
                if row is not None and row[0] is reference:
                    issued.pop(owner_id)

            records = {}
            issued[owner_id] = (ref(service, expired), records)
        if records:
            raise ValueError('native read issuance already armed or pending')
        records['armed'] = key

    def has_arm(service):
        records = owner_records(service)
        return records is not None and 'armed' in records

    def is_armed(service, key):
        records = owner_records(service)
        if records is None or 'armed' not in records:
            return False
        if records['armed'] is not key:
            raise ValueError('native read key differs from armed transaction')
        return True

    def revoke(service):
        records = owner_records(service)
        if records is not None:
            row = records.get('issued')
            _REVOKE_ACTUAL_SNAPSHOT(row[3] if row is not None else service.memory,
                                    service)
            records.clear()

    def register(service, memory, key, snapshot, event, payload):
        frame = sys._getframe(1)
        original_producer(service)
        _VALIDATE_ACTUAL_SNAPSHOT(memory, service, snapshot)
        entry = service.ledger._entries.get(key)
        if (frame.f_code is not code or frame.f_globals is not globals()
                or frame.f_locals.get('self') is not service
                or frame.f_locals.get('committed_snapshot') is not snapshot
                or frame.f_locals.get('committed_event') is not event
                or type(memory) is not PersistentMemory or service.memory is not memory
                or type(key) is not TransactionKey or type(snapshot) is not ReadSnapshot
                or entry is None or entry.status != 'complete' or entry.receipt is not snapshot
                or entry.payload_digest != TransactionLedger._digest(payload)
                or not service.events or service.events[-1] is not event
                or type(event) is not dict or event.get('kind') != 'memory_read'
                or event.get('transaction') != asdict(key)
                or snapshot.transaction_id != str(key)):
            raise ValueError('native read requires actual completed service callback')
        expected_event = {"kind": "memory_read", "transaction": asdict(key),
                          "address": payload['address'],
                          "width_bytes": payload['width_bytes'],
                          "memory_id": snapshot.memory_id,
                          "generation": snapshot.generation,
                          "byte_offset": snapshot.byte_offset,
                          "value": snapshot.value,
                          "data_hex": snapshot.data.hex(),
                          "versions": snapshot.versions,
                          "writer_event_ids": snapshot.writer_event_ids}
        if service.include_writer_kinds:
            expected_event['writer_kinds'] = snapshot.writer_kinds
        if (event != expected_event
                or json.dumps(event, sort_keys=True, allow_nan=False)
                != json.dumps(expected_event, sort_keys=True, allow_nan=False)):
            raise ValueError('native read event differs from actual snapshot')
        records = owner_records(service)
        if records is None or records.get('armed') is not key:
            raise ValueError('native read was not armed for this transaction')
        handle = object()
        records.clear()
        records['issued'] = (handle, snapshot, key, memory, service.ledger,
                             entry, tuple(getattr(snapshot, name) for name in
                                          ReadSnapshot.__dataclass_fields__),
                             event,
                             json.dumps(event, sort_keys=True, allow_nan=False))

    def lookup(service, memory, key, snapshot):
        original_producer(service)
        _VALIDATE_ACTUAL_SNAPSHOT(memory, service, snapshot)
        records = owner_records(service)
        row = records.get('issued') if records is not None else None
        if (row is None or row[1] is not snapshot or row[2] is not key
                or row[3] is not memory or service.memory is not memory
                or row[4] is not service.ledger or type(key) is not TransactionKey
                or type(snapshot) is not ReadSnapshot
                or tuple(getattr(snapshot, name) for name in
                         ReadSnapshot.__dataclass_fields__) != row[6]
                or snapshot.generation != memory.generation
                or service.ledger._entries.get(key) is not row[5]
                or row[5].status != 'complete' or row[5].receipt is not snapshot
                # Runner journals a detached copy and deliberately clears
                # service.events. Keep validating the original callback event
                # object and its frozen material, not its transient list slot.
                or json.dumps(row[7], sort_keys=True, allow_nan=False) != row[8]):
            raise ValueError('native read is not an unchanged issued result')
        return row[0]

    def validate(service, memory, key, snapshot, handle):
        if lookup(service, memory, key, snapshot) is not handle:
            raise ValueError('native read handle does not match issuance')
        return snapshot

    return arm, has_arm, is_armed, revoke, register, lookup, validate


(_ARM_ISSUED_READ, _HAS_ARMED_ISSUED_READ, _IS_ARMED_ISSUED_READ,
 _REVOKE_ISSUED_READ,
 _REGISTER_ISSUED_READ, _LOOKUP_ISSUED_READ,
 _VALIDATE_ISSUED_READ) = _issued_read_registry()


class _F6ReadToken:
    """Weak-referenceable per-read issuer; separate from CPU instruction issuer."""


def _f6_dma_read_registry():
    from weakref import WeakKeyDictionary
    owners=WeakKeyDictionary()
    original=None
    read=MemoryService.read;read_code=read.__code__
    ledger_execute=TransactionLedger.execute_once;ledger_code=ledger_execute.__code__

    def seal(cls):
        nonlocal original
        if original is not None:raise ValueError('F6 DMA read provider already sealed')
        original=cls,cls.step_local,cls.step_local.__code__

    def typed(key):
        from .f6_ram_dma_policy import _key
        return _key(key)

    def original_service(service):
        if (type(service) is not MemoryService or MemoryService.read is not read
                or read.__code__ is not read_code or 'read' in vars(service)
                or type(service.ledger) is not TransactionLedger
                or TransactionLedger.execute_once is not ledger_execute
                or ledger_execute.__code__ is not ledger_code
                or 'execute_once' in vars(service.ledger)):
            raise ValueError('F6 read requires original service and ledger methods')

    def native_receipt(receipt,session):
        from myfuzz.local_harness.wire import DriverReceipt
        if (type(receipt) is not DriverReceipt or receipt.status!='result'
                or type(receipt.execution) is not str or receipt.execution!=session._execution
                or any(type(getattr(receipt,n)) is not int for n in ('sequence','tick_before','tick_after','new_ticks'))
                or not 0<receipt.sequence<2**64 or receipt.new_ticks!=1
                or not 0<=receipt.tick_before<receipt.tick_after<2**64
                or receipt.tick_after!=receipt.tick_before+1):
            raise ValueError('F6 read requires an actual complete typed native receipt')

    def check_session(session):
        from myfuzz.local_harness.wishbone_dma_session import (
            _f6_dma_session_instance_data_is_canonical,
            _f6_dma_session_type_allowlist)
        try:
            allowed = _f6_dma_session_type_allowlist()
        except (AttributeError, ImportError, TypeError, ValueError) as error:
            raise ValueError('F6 read requires original native DMA producer') from error
        base_session = allowed[0]
        if (not _f6_dma_session_instance_data_is_canonical(session)
                or original is None or original[0] is not base_session
                or type(session) not in allowed
                or base_session.step_local is not original[1]
                or original[1].__code__ is not original[2]
                or 'step_local' in vars(session)):
            raise ValueError('F6 read requires original native DMA producer')
        if type(session) is allowed[1]:
            # The scheduler class intentionally wraps one base native step.
            # Its class method and code are pinned by the shared exact class
            # allowlist; step_frame below still proves this receipt originated
            # inside the sealed base step_local implementation.
            return
        if type(session).step_local is not original[1]:
            raise ValueError('F6 read requires original native DMA producer')

    def step_frame(session,frame):
        check_session(session)
        if (frame.f_code is not original[2]
                or frame.f_globals is not original[1].__globals__
                or frame.f_locals.get('self') is not session):
            raise ValueError('F6 read requires actual native accepted-read/response callback')

    def arm(session,key):
        from .dma_route_admission import DmaMasterRouteAdmission
        from .f6_ram_dma_policy import F6RamDmaPolicy
        admission=session._dma_route_admission
        if (type(admission) is not DmaMasterRouteAdmission
                or type(admission._beat_policy) is not F6RamDmaPolicy):
            return False
        frame=sys._getframe(1);step_frame(session,frame);typed(key)
        original_service(session.memory_service)
        local=frame.f_locals;pre=local.get('pre',{})
        native_receipt(local.get('receipt'),session)
        if _HAS_ARMED_ISSUED_READ(session.memory_service):
            raise ValueError('F6 DMA service must not share an armed instruction issuer')
        if (local.get('key') is not key or local.get('admission') is not admission
                or local.get('target') is not None or local.get('invalid') is not False
                or local.get('selected_fault') is not False or pre.get('mwb_we') != 0
                or pre.get('mwb_cyc') != 1 or pre.get('mwb_stb') != 1
                or any(type(pre.get(n)) is not int or pre[n]!=0
                       for n in ('mwb_stall','mwb_ack','mwb_err'))
                or local.get('stall') != 0 or session._pending is not None
                or key.channel_id != 'dma-memory'
                or (key.execution_id,key.testcase_id,key.source_component,key.source_epoch,key.source_sequence)
                != (session._execution,session._case_id,session.source_component,session.reset_epoch,session._source_sequence)
                or not any(r['transaction']==asdict(key) for r in admission.route_matches)):
            raise ValueError('F6 read is not an admitted normal native RAM read')
        service=session.memory_service
        state=owners.setdefault(service,dict(session=ref(session),memory=service.memory,
            ledger=service.ledger,rows={},armed=None))
        if (state['session']() is not session or state['memory'] is not service.memory
                or state['ledger'] is not service.ledger or state['armed'] is not None
                or key in state['rows'] or len(state['rows'])>=64):
            raise ValueError('F6 read issuance owner/replay/capacity conflict')
        state['armed']=(key,_F6ReadToken(),local['address'],local['receipt'])
        return True

    def armed(service,key):
        state=owners.get(service)
        if state is None or state['armed'] is None:return None
        original_service(service);typed(key)
        if state['armed'][0] is not key:raise ValueError('F6 read differs from armed key')
        return state['armed'][1]

    def revoke(service):
        state=owners.get(service)
        if state is not None:state['armed']=None

    def register(service,key,snapshot,event,payload):
        frame=sys._getframe(1);original_service(service);typed(key)
        state=owners.get(service);arm=state['armed'] if state is not None else None
        if arm is None or arm[0] is not key:raise ValueError('F6 read has no native arm')
        _VALIDATE_ACTUAL_SNAPSHOT(service.memory,arm[1],snapshot)
        entry=service.ledger._entries.get(key)
        if (frame.f_code is not read_code or frame.f_globals is not globals()
                or frame.f_locals.get('self') is not service
                or frame.f_locals.get('committed_snapshot') is not snapshot
                or frame.f_locals.get('committed_event') is not event
                or type(snapshot) is not ReadSnapshot or snapshot.transaction_id != str(key)
                or payload != dict(op='read',address=arm[2],width_bytes=4)
                or entry is None or entry.status != 'complete' or entry.receipt is not snapshot
                or entry.payload_digest != TransactionLedger._digest(payload)
                or not service.events or service.events[-1] is not event):
            raise ValueError('F6 read requires original completed service callback')
        state['rows'][key]=dict(key=key,snapshot=snapshot,handle=object(),token=arm[1],entry=entry,
            snapshot_pin=repr(asdict(snapshot)),event=event,
            event_pin=json.dumps(event,sort_keys=True,allow_nan=False),
            scope=(key.execution_id,key.testcase_id,key.source_component,key.source_epoch),
            acceptance=(arm[3],json.dumps(asdict(arm[3]),sort_keys=True,allow_nan=False)),response=None)
        state['armed']=None

    def complete(session,pending,receipt):
        from .dma_route_admission import DmaMasterRouteAdmission
        from .f6_ram_dma_policy import F6RamDmaPolicy
        admission=session._dma_route_admission
        if type(admission) is not DmaMasterRouteAdmission or type(admission._beat_policy) is not F6RamDmaPolicy:return
        step_frame(session,sys._getframe(1))
        state=owners.get(session.memory_service)
        if state is None:return
        transaction=pending.get('transaction')
        matches=[row for row in state['rows'].values() if asdict(row['key'])==transaction]
        if not matches:return  # writes and sealed ERR never issued a read
        row,=matches
        native_receipt(receipt,session)
        pre=receipt.payload.get('pre_backend',{})
        if (type(pre.get('mwb_cyc')) is not int or pre['mwb_cyc']!=1
                or type(pre.get('mwb_ack')) is not int or pre['mwb_ack']!=1
                or type(pre.get('mwb_err')) is not int or pre['mwb_err']!=0
                or type(pre.get('mwb_stall')) is not int or pre['mwb_stall']!=1
                or pre.get('mwb_dat_r')!=row['snapshot'].value):
            raise ValueError('F6 native read response requires actual PRE CYC and ACK')
        if (row['response'] is not None or session._pending is not pending
                or sys._getframe(1).f_locals.get('deliver') is not True
                or receipt.status != 'result' or receipt.new_ticks != 1
                or receipt.execution != row['key'].execution_id
                or row['scope']!=(session._execution,session._case_id,session.source_component,session.reset_epoch)
                or receipt.sequence<=row['acceptance'][0].sequence
                or receipt.tick_after<=row['acceptance'][0].tick_after
                or type(pending.get('error')) is not int or pending['error']!=0
                or type(pending.get('rdata')) is not int or pending['rdata']!=row['snapshot'].value):
            raise ValueError('F6 native read response is duplicate or contradictory')
        row['response']=(receipt,json.dumps(pending,sort_keys=True,allow_nan=False),
                         json.dumps(asdict(receipt),sort_keys=True,allow_nan=False))

    def validate(session,service,key,snapshot,handle):
        check_session(session);original_service(service);typed(key)
        state=owners.get(service);row=state['rows'].get(key) if state is not None else None
        if (row is None or state['session']() is not session or session.memory_service is not service
                or state['memory'] is not service.memory or state['ledger'] is not service.ledger
                or row['key'] is not key or row['snapshot'] is not snapshot or row['handle'] is not handle
                or repr(asdict(snapshot)) != row['snapshot_pin']
                or snapshot.generation != service.memory.generation
                or row['scope'] != (session._execution,session._case_id,session.source_component,session.reset_epoch)
                or service.ledger._entries.get(key) is not row['entry']
                or row['entry'].status != 'complete' or row['entry'].receipt is not snapshot
                or json.dumps(row['event'],sort_keys=True,allow_nan=False) != row['event_pin']
                or json.dumps(asdict(row['acceptance'][0]),sort_keys=True,allow_nan=False)!=row['acceptance'][1]
                or row['response'] is None
                or json.dumps(asdict(row['response'][0]),sort_keys=True,allow_nan=False)!=row['response'][2]):
            raise ValueError('F6 read is not an unchanged issued native result and response')
        return json.loads(row['event_pin'])

    def results(session):
        check_session(session)
        state=owners.get(session.memory_service)
        if state is None:return ()
        if state['session']() is not session:raise ValueError('F6 read issuer owner mismatch')
        return tuple((row['key'],row['snapshot'],row['handle']) for row in state['rows'].values())

    return seal,arm,armed,revoke,register,complete,validate,results


(_seal_f6_dma_read_provider,_arm_f6_dma_read,_f6_dma_read_arm,_revoke_f6_dma_read,
 _register_f6_dma_read,_complete_f6_dma_read,_validate_f6_dma_read,
 _f6_dma_read_results)=_f6_dma_read_registry()
