"""The Runner passes an actual pending host write to the UART store join."""
from copy import deepcopy
from dataclasses import asdict
import pytest

from tests.scenario.test_uart_native_irq_runner import fixture as runner_fixture
from tests.scenario.test_uart_ram_commit_join import fixture as memory_fixture
from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
from myfuzz.scenario.uart_store_memory import UartStoreMemoryJoin
from myfuzz.scenario.ledger import TransactionKey


def wired():
    stream, store, service, receipt, _ = memory_fixture()
    runner, _, _ = runner_fixture()
    runner.sessions['cpu'].service = service
    runner.sessions['cpu'].memory_commit_receipts_enabled = True
    runner.sessions['cpu'].cpu_events = []
    authority = MemoryCommitAuthority(services={'cpu': service})
    runner._memory_commit_authority = authority
    runner._uart_store_memory_join = UartStoreMemoryJoin(
        memory_commit_authority=authority,
        admission_registry=stream.registry, ownership=stream.owner,
        edge_index=stream.index)
    return stream, store, service, receipt, runner


def test_actual_pending_callback_is_staged_before_ack_and_raw_use_joins():
    stream, store, service, receipt, runner = wired()
    staged = []
    stage = runner._memory_commit_authority.stage
    ack = service.ack_commit_events

    def record_stage(*args):
        assert service.lookup_pending_commit(receipt.commit_document()['commit_id'])[0] is receipt
        token = stage(*args)
        staged.append(token)
        return token

    def record_ack(ids):
        assert staged and type(staged[0]) is int
        return ack(ids)

    runner._memory_commit_authority.stage = record_stage
    service.ack_commit_events = record_ack
    runner._append_external_events('cpu', 1)
    assert service.pending_commit_count == 0
    assert len([e for e in runner.events if e.get('kind') == 'memory_write_commit']) == 1
    for raw in stream.events:
        runner._append_uart_store_memory_join(deepcopy(raw))
    proofs = [e for e in runner.events if e.get('kind') == 'uart_store_memory_match'
              and e.get('status') == 'accepted']
    assert len(proofs) == 1
    assert proofs[0]['store_fullkey'] == asdict(receipt.transaction_id)
    assert proofs[0]['store_retirement_event_id'] == store['event_id']
    assert proofs[0]['byte_value'] == 0
    assert runner._memory_commit_authority.pending_count == 0


def test_detached_service_event_does_not_gain_live_commit_token():
    stream, _, service, receipt, runner = wired()
    saved = service.drain_commit_events()[0]
    service.ack_commit_events((saved['commit_id'],))
    service.events.append(saved)
    runner._append_external_events('cpu', 1)
    for raw in stream.events:
        runner._append_uart_store_memory_join(deepcopy(raw))
    assert not [e for e in runner.events if e.get('kind') == 'uart_store_memory_match'
                and e.get('status') == 'accepted']


def test_no_effect_callback_is_logged_and_acknowledged_without_store_proof():
    stream, _, service, receipt, runner = wired()
    empty_key = TransactionKey(**dict(asdict(receipt.transaction_id), source_sequence=3))
    service.write(empty_key, 0x20004, 0, width_bytes=4, byte_enable=0)
    runner._append_external_events('cpu', 1)
    assert service.pending_commit_count == 0
    records = [e for e in runner.events if e.get('kind') == 'memory_write_commit']
    assert len(records) == 2
    assert records[1]['commit_document']['performed_effect'] is False
    for raw in stream.events:
        runner._append_uart_store_memory_join(deepcopy(raw))
    proofs = [e for e in runner.events if e.get('kind') == 'uart_store_memory_match'
              and e.get('status') == 'accepted']
    assert len(proofs) == 1
    assert proofs[0]['store_fullkey'] == asdict(receipt.transaction_id)


def test_typed_drain_change_does_not_advance_or_ack_callback():
    _, _, service, _, runner = wired()
    original = service.drain_commit_events

    def changed():
        event = deepcopy(original()[0])
        event['commit_document']['generation'] = False
        return (event,)

    service.drain_commit_events = changed
    with pytest.raises(RuntimeError, match='changed during drain'):
        runner._append_external_events('cpu', 1)
    assert service.pending_commit_count == 1
    assert runner._memory_commit_authority.pending_count == 0
