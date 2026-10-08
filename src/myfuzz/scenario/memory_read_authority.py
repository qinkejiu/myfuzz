"""Bounded live invocation authority for modeled host memory reads.

The only issuance method calls the installed MemoryService.read itself. A
detached saved snapshot or completed ledger entry cannot be enrolled later.
"""
from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict
import json

from .ledger import TransactionKey, TransactionLedger
from .memory import PersistentMemory, ReadSnapshot
from .memory_service import MemoryService


def _uint(value, bits=64):
    return type(value) is int and 0 <= value < 1 << bits


class MemoryReadAuthority:
    def __init__(self, *, services, max_services=16, max_pending=256):
        if (type(max_services) is not int or max_services < 1
                or type(max_pending) is not int or max_pending < 1):
            raise ValueError('invalid memory read authority capacity')
        if (not isinstance(services, Mapping) or not services
                or len(services) > max_services):
            raise ValueError('bounded installed read services required')
        self._installed = {}
        seen = set()
        for component, service in services.items():
            if (type(component) is not str or not component
                    or type(service) is not MemoryService
                    or type(service.ledger) is not TransactionLedger
                    or type(service.memory) is not PersistentMemory
                    or not service.include_writer_kinds or id(service) in seen):
                raise ValueError('actual distinct writer-aware read service required')
            seen.add(id(service))
            self._installed[component] = (service, service.ledger, service.memory)
        self.max_pending = max_pending
        self._pending = OrderedDict()
        self._next_token = 1
        self._bad = False

    @property
    def pending_count(self):
        return len(self._pending)

    @property
    def degraded(self):
        return self._bad

    def read(self, component, service, key, address, *, width_bytes):
        """Perform one actual callback and pin its immutable result before reply."""
        installed = self._installed.get(component) if type(component) is str else None
        if (self._bad or installed is None or service is not installed[0]
                or service.ledger is not installed[1]
                or service.memory is not installed[2]
                or type(key) is not TransactionKey
                or key.source_component != component or key.channel_id != 'data'
                or any(type(getattr(key, n)) is not str or not getattr(key, n)
                       for n in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or not _uint(key.source_epoch) or not _uint(key.source_sequence)
                or key.source_sequence == 0
                or not _uint(address, 32) or width_bytes != 4
                or type(width_bytes) is not int):
            raise ValueError('invalid installed host memory read')
        if key in service.ledger._entries:
            raise ValueError('duplicate read is not a new issuance')
        if len(self._pending) >= self.max_pending:
            raise RuntimeError('memory read issuance capacity exceeded before effect')
        snapshot = service.read(key, address, width_bytes=width_bytes)
        entry = service.ledger._entries.get(key)
        event = service.events[-1] if service.events else None
        try:
            if (type(snapshot) is not ReadSnapshot or entry is None
                    or entry.status != 'complete' or entry.receipt is not snapshot
                    or entry.payload_digest != TransactionLedger._digest(
                        dict(op='read', address=address, width_bytes=width_bytes))
                    or type(event) is not dict or event.get('kind') != 'memory_read'
                    or event.get('transaction') != asdict(key)
                    or event.get('address') != address or event.get('width_bytes') != width_bytes
                    or snapshot.transaction_id != str(key)
                    or type(snapshot.memory_id) is not str
                    or snapshot.memory_id not in service.memory.memory_ids
                    or not _uint(snapshot.generation) or not _uint(snapshot.byte_offset)
                    or type(snapshot.data) is not bytes or len(snapshot.data) != 4
                    or type(snapshot.versions) is not tuple or len(snapshot.versions) != 4
                    or type(snapshot.writer_event_ids) is not tuple or len(snapshot.writer_event_ids) != 4
                    or type(snapshot.writer_kinds) is not tuple or len(snapshot.writer_kinds) != 4
                    or any(type(version) is not tuple or len(version) != 2
                           or not all(_uint(value) for value in version)
                           for version in snapshot.versions)
                    or any(type(ref) is not str or not ref for ref in snapshot.writer_event_ids)
                    or any(kind not in ('STORE', 'FIRST_READ', 'INITIAL_IMAGE', 'INSTRUCTION_SOURCE')
                           for kind in snapshot.writer_kinds)):
                raise RuntimeError('actual read callback receipt is inconsistent')
            memory_id, generation, offset = service.memory.resolve_span(address, 4)
            if (memory_id != snapshot.memory_id or generation != snapshot.generation
                    or offset != snapshot.byte_offset):
                raise RuntimeError('actual read callback span is inconsistent')
            record = dict(schema_version='memory_read_authority.v1',
                proof_scope='installed_host_memory_read_snapshot',
                memory_kind='modeled_host_persistent_memory',
                fullkey=asdict(key), address=address, width_bytes=4,
                memory_id=snapshot.memory_id, generation=snapshot.generation,
                byte_offset=snapshot.byte_offset, value=snapshot.value,
                data_hex=snapshot.data.hex(),
                versions=[list(version) for version in snapshot.versions],
                writer_event_ids=list(snapshot.writer_event_ids),
                writer_kinds=list(snapshot.writer_kinds))
            for name in ('memory_id', 'generation', 'byte_offset', 'value', 'data_hex',
                         'versions', 'writer_event_ids', 'writer_kinds'):
                if json.dumps(event.get(name), sort_keys=True) != json.dumps(record[name], sort_keys=True):
                    raise RuntimeError('actual read callback event is inconsistent')
            token = self._next_token
            self._next_token += 1
            self._pending[token] = record
            return snapshot
        except (RuntimeError, TypeError, ValueError):
            self._bad = True
            raise RuntimeError('actual read callback could not be authenticated')

    def drain(self):
        """Return detached pending descriptors with private one-shot tokens."""
        return tuple((token, deepcopy(record)) for token, record in self._pending.items())

    def resolve(self, token):
        if type(token) is not int or token < 1:
            return None
        record = self._pending.pop(token, None)
        # A later failed callback invalidates earlier pending proof. Still
        # consume its one-shot token so the runner cannot drain it again.
        return deepcopy(record) if record is not None and not self._bad else None
