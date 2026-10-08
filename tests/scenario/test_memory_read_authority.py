"""Actual installed MemoryService.read invocation, not detached snapshot labels."""
from dataclasses import asdict
from unittest.mock import patch
import pytest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory, ReadSnapshot
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.memory_read_authority import MemoryReadAuthority


def fixture(capacity=4):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0x20000, 4096),),
                              initialization_seed=7, max_initialized_bytes=4096)
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True)
    authority = MemoryReadAuthority(services={'cpu': service}, max_pending=capacity)
    return service, authority


def key(sequence=1, testcase='first'):
    return TransactionKey('execution', testcase, 'cpu', 0, 'data', sequence)


def test_actual_read_callback_issues_one_frozen_snapshot_once():
    service, authority = fixture()
    snapshot = authority.read('cpu', service, key(), 0x20000, width_bytes=4)
    issued = authority.drain()
    assert len(issued) == 1
    token, record = issued[0]
    assert record['fullkey'] == asdict(key())
    assert record['memory_id'] == 'ram' and record['byte_offset'] == 0
    assert record['value'] == snapshot.value and record['data_hex'] == snapshot.data.hex()
    assert record['versions'] == [list(v) for v in snapshot.versions]
    assert record['writer_event_ids'] == list(snapshot.writer_event_ids)
    assert record['writer_kinds'] == list(snapshot.writer_kinds)
    assert authority.resolve(token) == record
    assert authority.resolve(token) is None and authority.pending_count == 0


def test_persistent_read_after_store_preserves_precise_writer_version():
    service, authority = fixture()
    service.write(key(), 0x20000, 0x5a, width_bytes=4, byte_enable=15)
    snapshot = authority.read('cpu', service, key(2), 0x20000, width_bytes=4)
    token, issued = authority.drain()[0]
    assert issued['fullkey']['source_sequence'] == 2
    assert issued['versions'][0] == [0, 1]
    assert issued['writer_kinds'][0] == 'STORE'
    assert issued['writer_event_ids'][0] == str(key())
    service.write(key(3), 0x20000, 0x5a, width_bytes=4, byte_enable=15)
    assert authority.resolve(token)['versions'][0] == [0, 1]
    assert snapshot.value == 0x5a


def test_detached_snapshot_and_manual_ledger_entry_have_no_issue_api():
    service, authority = fixture()
    fake = ReadSnapshot(str(key()), 'ram', 0, 0, b'\x5a\x00\x00\x00',
                        ((0, 1),) * 4, ('fake',) * 4, (), ('STORE',) * 4)
    assert not hasattr(authority, 'stage')
    assert authority.drain() == ()
    service.ledger.execute_once(key(), {'op': 'read', 'address': 0x20000,
                                        'width_bytes': 4}, lambda: fake)
    with pytest.raises(ValueError, match='duplicate'):
        authority.read('cpu', service, key(), 0x20000, width_bytes=4)
    assert authority.drain() == ()


def test_capacity_rejects_before_second_read_effect_and_duplicate_cannot_reissue():
    service, authority = fixture(capacity=1)
    authority.read('cpu', service, key(), 0x20000, width_bytes=4)
    before = len(service.events)
    with pytest.raises(RuntimeError, match='capacity'):
        authority.read('cpu', service, key(2), 0x20000, width_bytes=4)
    assert len(service.events) == before and key(2) not in service.ledger._entries
    token, _ = authority.drain()[0]
    assert authority.resolve(token)
    with pytest.raises(ValueError, match='duplicate'):
        authority.read('cpu', service, key(), 0x20000, width_bytes=4)


def test_conflicting_post_read_result_fails_closed_without_issuance():
    service, authority = fixture()
    fake = ReadSnapshot(str(key()), 'ram', 0, 0, b'\x00\x00\x00\x00',
                        ((0, 1),) * 4, ('fake',) * 4, (), ('STORE',) * 4)
    with patch.object(service, 'read', return_value=fake):
        with pytest.raises(RuntimeError, match='actual read callback'):
            authority.read('cpu', service, key(), 0x20000, width_bytes=4)
    assert authority.degraded and authority.drain() == ()


def test_degraded_authority_discards_older_live_token_once_without_document():
    service, authority = fixture()
    authority.read('cpu', service, key(), 0x20000, width_bytes=4)
    token, _ = authority.drain()[0]
    fake = ReadSnapshot(str(key(2)), 'ram', 0, 0, b'\x00\x00\x00\x00',
                        ((0, 1),) * 4, ('fake',) * 4, (), ('STORE',) * 4)
    with patch.object(service, 'read', return_value=fake):
        with pytest.raises(RuntimeError, match='actual read callback'):
            authority.read('cpu', service, key(2), 0x20000, width_bytes=4)
    assert authority.degraded and authority.pending_count == 1
    assert authority.resolve(token) is None
    assert authority.pending_count == 0
    assert authority.drain() == ()
