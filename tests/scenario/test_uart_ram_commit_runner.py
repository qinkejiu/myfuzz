"""Runner live callback handoff for restricted UART to host RAM proof."""
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace

from tests.scenario.test_uart_native_irq_runner import fixture as runner_fixture
from tests.scenario.test_uart_ram_commit_join import fixture as join_fixture
from myfuzz.scenario.ledger import TransactionKey


def wired_fixture():
    stream, store, service, receipt, join = join_fixture()
    runner, _, _ = runner_fixture()
    runner.sessions['cpu'].service = service
    runner.sessions['cpu'].memory_commit_receipts_enabled = True
    runner.sessions['cpu'].cpu_events = []
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ())
    runner._uart_ram_commit_join = join
    return stream, store, service, receipt, join, runner


def feed_raw(runner, stream):
    for raw in stream.events:
        runner._append_uart_ram_commit_join(deepcopy(raw))


def test_runner_pins_actual_callback_before_ack_and_feeds_raw_chain():
    stream, store, service, receipt, join, runner = wired_fixture()
    staged = []
    original_stage = join.stage_commit
    original_ack = service.ack_commit_events

    def stage(*args):
        assert service.lookup_pending_commit(receipt.commit_document()['commit_id'])[0] is receipt
        staged.append(True)
        return original_stage(*args)

    def ack(commit_ids):
        assert staged and commit_ids == (receipt.commit_document()['commit_id'],)
        return original_ack(commit_ids)

    join.stage_commit = stage
    service.ack_commit_events = ack
    runner._append_external_events('cpu', 1)
    assert service.pending_commit_count == 0
    commit_records = [e for e in runner.events if e.get('kind') == 'memory_write_commit']
    assert len(commit_records) == 1
    assert commit_records[0]['transaction'] == asdict(receipt.transaction_id)
    feed_raw(runner, stream)
    proofs = [e for e in runner.events if e.get('kind') == 'uart_ram_commit_join'
              and e.get('status') == 'accepted']
    assert len(proofs) == 1
    assert proofs[0]['operand_retirement_event_id'] == store['event_id']
    assert proofs[0]['byte_version'] == list(receipt.version)


def test_runner_forged_detached_commit_record_cannot_stage_or_certify():
    stream, _, service, receipt, _, runner = wired_fixture()
    service.ack_commit_events((receipt.commit_document()['commit_id'],))
    fake = dict(
        kind='memory_write_commit', schema_version='memory_write_commit.v1',
        transaction=asdict(receipt.transaction_id),
        commit_id=receipt.commit_document()['commit_id'],
        commit_document=receipt.commit_document())
    service.events.append(fake)
    runner._append_external_events('cpu', 1)
    feed_raw(runner, stream)
    assert not [e for e in runner.events if e.get('kind') == 'uart_ram_commit_join'
                and e.get('status') == 'accepted']


def test_runner_drains_each_commit_once_across_many_callback_batches():
    _, _, service, receipt, _, runner = wired_fixture()
    for sequence in range(2, 34):
        if sequence > 2:
            key = TransactionKey(**dict(asdict(receipt.transaction_id),
                                        source_sequence=sequence))
            service.write(key, 0x20000, sequence, width_bytes=4, byte_enable=15)
        runner._append_external_events('cpu', sequence)
        assert service.pending_commit_count == 0
    commits = [e for e in runner.events if e.get('kind') == 'memory_write_commit']
    assert len(commits) == 32
    assert [e['service_commit_sequence'] for e in commits] == list(range(1, 33))


def test_external_event_bridge_forwards_raw_cpu_and_uart_facts_in_stream_order():
    runner, _, _ = runner_fixture()
    seen = []
    runner._uart_ram_commit_join = SimpleNamespace(
        consume=lambda event: seen.append(deepcopy(event)) or ())
    runner._uart_retired_read_linker = SimpleNamespace(consume=lambda event: ())
    runner._uart_consumption_tracker = SimpleNamespace(consume=lambda event: ())
    runner.sessions['cpu'].cpu_events = [
        {'kind': 'instr_response', 'marker': 'fetch'},
        {'kind': 'data_accept', 'marker': 'accept'},
        {'kind': 'data_response', 'marker': 'response'}]
    runner.sessions['uart'].uart_events = [
        {'kind': 'uart_tick_observation', 'marker': 'tick'},
        {'kind': 'uart_frame_validation', 'marker': 'frame'}]
    runner._append_external_events('cpu', 1)
    runner._append_external_events('uart', 1)
    assert [e['marker'] for e in seen] == [
        'fetch', 'accept', 'response', 'tick', 'frame']
    assert all(type(e['event_id']) is int for e in seen)
    assert len(runner.sessions['cpu'].cpu_events) == 3
    assert len(runner.sessions['uart'].uart_events) == 2


def test_online_journal_releases_processed_local_streams_without_losing_event_identity():
    runner, _, _ = runner_fixture()
    runner.enable_event_journal(chunk_size=2)
    cpu = runner.sessions['cpu']
    cpu.cpu_events = []
    for sequence in range(5):
        cpu.cpu_events.append({'kind': 'cpu_probe', 'sequence': sequence})
        runner._append_external_events('cpu', 7)
        assert cpu.cpu_events == []
    observed = [event for event in runner.events if event.get('kind') == 'cpu_probe']
    assert [event['sequence'] for event in observed] == list(range(5))
    assert [event['event_id'] for event in observed] == list(range(1, 6))
    assert all(event['producer_event_id'] == 7 for event in observed)


def test_online_journal_keeps_router_acceptance_order_source_history():
    runner, _, _ = runner_fixture()
    runner.enable_event_journal(chunk_size=2)
    router = SimpleNamespace(acceptances=[{'kind': 'route_probe', 'acceptance_order': 1}],
                             deliveries=[])
    runner.sessions['cpu'].router = router
    runner._append_external_events('cpu', 7)
    assert router.acceptances == [{'kind': 'route_probe', 'acceptance_order': 1}]


def test_online_journal_releases_authenticated_memory_service_events_after_commit():
    _, _, service, receipt, _, runner = wired_fixture()
    runner.enable_event_journal(chunk_size=2)
    runner._append_external_events('cpu', 7)
    assert service.events == []
    commits = [event for event in runner.events
               if event.get('kind') == 'memory_write_commit']
    assert len(commits) == 1
    assert commits[0]['transaction'] == asdict(receipt.transaction_id)
    assert service.pending_commit_count == 0


def test_online_journal_local_stream_cursors_survive_warm_reset_and_other_component():
    runner, _, _ = runner_fixture()
    runner.enable_event_journal(chunk_size=2)
    cpu, uart = runner.sessions['cpu'], runner.sessions['uart']
    cpu.cpu_events = [{'kind': 'cpu_reset', 'source_component': 'cpu',
                       'execution_id': 'local-execution', 'source_epoch': 1,
                       'reset_epoch': 1}]
    uart.cpu_events = [{'kind': 'uart_side_probe', 'sequence': 1}]
    uart.uart_events = [{'kind': 'uart_reset', 'sequence': 1}]
    runner._append_external_events('cpu', 7)
    assert cpu.cpu_events == []
    assert len(uart.cpu_events) == 1
    cpu.cpu_events.append({'kind': 'cpu_probe', 'sequence': 2})
    runner._append_external_events('cpu', 8)
    runner._append_external_events('uart', 9)
    assert uart.cpu_events == []
    assert uart.uart_events == []
    uart.uart_events.append({'kind': 'uart_tick_observation', 'sequence': 2})
    runner._append_external_events('uart', 10)
    assert uart.uart_events == []
    assert [event['kind'] for event in runner.events] == [
        'cpu_reset', 'cpu_probe', 'uart_reset', 'uart_side_probe',
        'uart_tick_observation']
    assert [event['event_id'] for event in runner.events] == [1, 2, 3, 4, 5]


def test_online_journal_releases_uart_observations_after_synchronous_consumption():
    runner, _, _ = runner_fixture()
    runner.enable_event_journal(chunk_size=2)
    seen = []
    runner._uart_consumption_tracker = SimpleNamespace(
        consume=lambda event: seen.append(deepcopy(event)) or ())
    uart = runner.sessions['uart']
    uart.uart_events = []
    for sequence in range(5):
        uart.uart_events.append({'kind': 'uart_tick_observation', 'sequence': sequence})
        runner._append_external_events('uart', 17)
        assert uart.uart_events == []
    assert [event['sequence'] for event in seen] == list(range(5))
    observed = [event for event in runner.events
                if event.get('kind') == 'uart_tick_observation']
    assert [event['sequence'] for event in observed] == list(range(5))
    assert [event['event_id'] for event in observed] == list(range(1, 6))


def test_online_journal_keeps_uart_source_list_on_consumer_failure():
    runner, _, _ = runner_fixture()
    runner.enable_event_journal(chunk_size=2)
    uart = runner.sessions['uart']
    uart.uart_events = [{'kind': 'uart_tick_observation', 'sequence': 1}]

    def fail(_event):
        raise RuntimeError('consumer failed')

    runner._uart_consumption_tracker = SimpleNamespace(consume=fail)
    import pytest
    with pytest.raises(RuntimeError, match='consumer failed'):
        runner._append_external_events('uart', 17)
    assert len(uart.uart_events) == 1
    runner._uart_consumption_tracker = SimpleNamespace(consume=lambda event: ())
    runner._append_external_events('uart', 17)
    assert len([event for event in runner.events
                if event.get('kind') == 'uart_tick_observation']) == 1
    assert uart.uart_events == []
