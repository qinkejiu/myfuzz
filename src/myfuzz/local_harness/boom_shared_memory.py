"""Source-bound, uncached BOOM word service over one host memory object.

This is a bounded external A/D service. It does not grant PMP permissions,
cache coherence, ISA retirement, or generic memory source authority.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


_SOURCE_HASHES = {
    'configs/cpus/boom/component_profile.json':
        '344cfcebf31056311021f04cbecef0d1a8819f4befc40c71e380147293620a01',
    'configs/cpus/boom/generated/source_manifest.json':
        '0e3718bdc000dd2a8b965e20eb4e00b8071a786f7961d62372956f90a6bc6053',
    'configs/cpus/boom/generated/chipyard.TestHarness.SmallBoomConfig.top.v':
        '78bc69803c7b993cd1ddfcdb585d477bd27a83710bb1ce426e217aedbbdfaced',
    'configs/cpus/boom/evidence/derived-20261017/physical_ports.json':
        '80878201d383247fc8eba54d7b4caa710c6b9e96bd62b346fe322ed5e7559310',
    'src/myfuzz/local_harness/boom_cpu_driver.cpp':
        '63dcc4f0fc13bc997a9b93fa8dd78f852954698db30815b23be04868c06da466',
    'configs/cpus/boom/runtime/tl_ram.h':
        'c40e3b16f492f4f73857950e47604f60e29055f684f46204cdeb685867d095da',
}


def validate_boom_external_request(request, *, reset_epoch):
    """Check actual physical fields before any service or router effect."""
    fields = {'opcode': 3, 'param': 3, 'size': 4, 'source': 3,
              'address': 32, 'mask': 8, 'data': 64,
              'request_sequence': 64, 'reset_epoch': 64}
    if type(request) is not dict or request.get('channel') != 'A':
        raise ValueError('accepted BOOM A request required')
    for field, width in fields.items():
        value = request.get(field)
        if type(value) is not int or not 0 <= value < 1 << width:
            raise ValueError('invalid BOOM request field: ' + field)
    address = request['address']
    if (request['opcode'] not in (0, 1, 4) or request['param'] != 0
            or request['size'] != 2 or address % 4
            or request['mask'] != 15 << (address & 7)
            or request['request_sequence'] < 1
            or request['reset_epoch'] != reset_epoch):
        raise ValueError('unsupported BOOM external word transfer shape')


@dataclass(frozen=True)
class BoomSharedMemoryContract:
    external_range: tuple[int, int] = (0x4000, 0x5000)
    source_range: tuple[int, int] = (0x4100, 0x4110)
    destination_range: tuple[int, int] = (0x4200, 0x4210)
    result_range: tuple[int, int] = (0x4300, 0x4318)
    control_range: tuple[int, int] = (0x4400, 0x4410)

    def __post_init__(self):
        expected = ((0x4000, 0x5000), (0x4100, 0x4110),
                    (0x4200, 0x4210), (0x4300, 0x4318), (0x4400, 0x4410))
        for value, required in zip(asdict(self).values(), expected):
            if (type(value) is not tuple or len(value) != 2
                    or any(type(n) is not int for n in value) or value != required):
                raise ValueError('BOOM shared memory requires the exact pinned layout')

    @property
    def data_ranges(self):
        return (self.source_range, self.destination_range, self.result_range)

    def contains_data(self, address):
        return any(lo <= address and address + 4 <= hi for lo, hi in self.data_ranges)

    def identity_document(self):
        return dict(schema_version='boom_shared_memory_contract.v1', **asdict(self),
                    word_bytes=4, physical_beat_bytes=8,
                    pmp_permission='requires_actual_cpu_pmp',
                    source_hashes=dict(_SOURCE_HASHES))

    def authenticate_source(self, repo: Path):
        root = repo.resolve()
        for name, expected in _SOURCE_HASHES.items():
            path = root / name
            if (path.is_symlink() or path.resolve() != path or not path.is_file()
                    or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
                raise ValueError('BOOM shared memory source drift: ' + name)
        # These are the predicates of the exact source bytes above. Read/write
        # PMP inputs remain runtime CPU inputs, never permissions invented here.
        for lo, hi in (*self.data_ranges, self.control_range):
            for address in range(lo, hi):
                legal = ((address ^ 0x4000) & ~0xfff) == 0
                lsu_cached = (((address ^ 0x10000000) & 0x94010000) == 0
                              or ((address ^ 0x80000000) & 0x90000000) == 0)
                cache_cached = any(((address ^ base) & mask) == 0 for base, mask in
                    ((0x20000, 0x94030000), (0x10000000, 0x94030000),
                     (0x80000000, 0x90000000)))
                if not legal or lsu_cached or cache_cached or address & 0x8a130000:
                    raise ValueError('BOOM shared layout violates pinned PMA predicates')
        return dict(schema_version='boom_shared_memory_source.v1',
                    source_hashes=dict(_SOURCE_HASHES), legal_uncached_pma=True,
                    pmp_permission='requires_actual_cpu_pmp')


class BoomSharedMemoryService:
    """Issue one measured width4 operation per bound native acceptance key."""

    def __init__(self, memory: PersistentMemory, contract: BoomSharedMemoryContract):
        if type(memory) is not PersistentMemory or type(contract) is not BoomSharedMemoryContract:
            raise ValueError('actual PersistentMemory and exact BOOM contract required')
        regions = memory.identity_document()['regions']
        if (len(regions) != 3
                or sorted((r['base'], r['base'] + r['size']) for r in regions)
                    != sorted(contract.data_ranges)
                or any(r['aliases'] or r['readable'] is not True
                       or r['writable'] is not True for r in regions)):
            raise ValueError('BOOM memory must declare only the three exact read/write spans')
        self.memory, self.contract = memory, contract
        self.service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True)
        self._objects = (memory, contract, self.service)
        self._memory_identity = deepcopy(memory.identity_document())
        self._generation = memory.generation
        self._ledger = self.service.ledger
        self._binding = None
        self.records = []
        self.receipts = {}

    def identity_document(self):
        return dict(schema_version='boom_shared_memory_service.v1',
                    contract=self.contract.identity_document(),
                    memory=deepcopy(self._memory_identity),
                    memory_service='MemoryService', width_bytes=4, byte_enable=15,
                    reset_policy='fresh_sessions_and_fresh_shared_memory')

    def validate_binding(self):
        if (any(actual is not expected for actual, expected in zip(
                (self.memory, self.contract, self.service), self._objects))
                or self.service.memory is not self.memory or self.service.ledger is not self._ledger
                or self.memory.identity_document() != self._memory_identity
                or self.memory.generation != self._generation):
            raise ValueError('BOOM shared memory binding changed; fresh testcase required')

    def bind(self, *, execution_id, testcase_id, source_component, reset_epoch):
        self.validate_fresh()
        if (any(type(n) is not str or not n for n in
                       (execution_id, testcase_id, source_component))
                or type(reset_epoch) is not int or not 0 <= reset_epoch < 1 << 64):
            raise ValueError('BOOM shared service requires one fresh native binding')
        self._binding = (execution_id, testcase_id, source_component, reset_epoch)

    def validate_fresh(self):
        self.validate_binding()
        if self._binding is not None or self._ledger._entries or self.records or self.receipts:
            raise ValueError('BOOM shared service must be fresh before native startup')

    def execute(self, key: TransactionKey, request):
        self.validate_binding()
        if self._binding is None:
            raise ValueError('BOOM shared service has no native binding')
        validate_boom_external_request(request, reset_epoch=self._binding[3])
        if (type(key) is not TransactionKey
                or any(type(getattr(key, name)) is not str for name in
                       ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or (key.execution_id, key.testcase_id, key.source_component, key.source_epoch)
                    != self._binding
                or key.channel_id != 'coherent-A-uncached'
                or type(key.source_sequence) is not int
                or key.source_sequence != request['request_sequence']
                or key in self.receipts
                or not self.contract.contains_data(request['address'])):
            raise ValueError('BOOM memory key/span does not match actual accepted request')
        shift = 8 * (request['address'] & 7)
        if request['opcode'] == 4:
            receipt = self.service.read(key, request['address'], width_bytes=4)
            response = receipt.value << shift
            document = dict(transaction_id=receipt.transaction_id,
                memory_id=receipt.memory_id, generation=receipt.generation,
                byte_offset=receipt.byte_offset, data_hex=receipt.data.hex(),
                value=receipt.value, versions=receipt.versions,
                writer_event_ids=receipt.writer_event_ids,
                writer_kinds=receipt.writer_kinds,
                materialized_offsets=receipt.materialized_offsets)
        else:
            receipt = self.service.write(key, request['address'],
                (request['data'] >> shift) & 0xffffffff, width_bytes=4, byte_enable=15)
            response = 0
            document = receipt.commit_document()
        self.receipts[key] = receipt
        self.records.append(dict(schema_version='boom_shared_memory_operation.v1',
            source_transaction=asdict(key), native_request=deepcopy(request),
            operation='read' if request['opcode'] == 4 else 'write',
            service_receipt=document, response_data=response,
            status='service_complete_d_pending'))
        return response

    def finish(self, key, *, status):
        if status not in ('d_accepted', 'cancelled'):
            raise ValueError('invalid BOOM memory terminal status')
        for record in reversed(self.records):
            if record['source_transaction'] == asdict(key):
                if record['status'] != 'service_complete_d_pending':
                    raise RuntimeError('duplicate BOOM memory completion')
                record['status'] = status
                return
        raise ValueError('BOOM memory completion has no service receipt')
