"""Independent negatives: equal data and damaged native facts prove no origin."""
from copy import deepcopy

from myfuzz.local_harness.opentitan_uart_fifo_contract import (
    UART_FIFO_PROBES, uart_fifo_observation_contract)
from myfuzz.scenario.uart_consumption import UartConsumptionTracker


def tick(sequence=1):
    signals = {'probe_uart_' + key: 0 for key in UART_FIFO_PROBES}
    signals.update(probe_uart_idle=1, probe_uart_rx_in=1,
                   probe_uart_fifo_wready=1)
    return dict(kind='uart_tick_observation', component='uart', reset_epoch=0,
                local_tick=sequence, event_id=sequence,
                command_scope={'component': 'uart', 'reset_epoch': 0,
                               'command_sequence': sequence},
                receipt_id={'execution': 'fixture', 'sequence': sequence},
                observation_contract=uart_fifo_observation_contract(),
                pre=deepcopy(signals), post=deepcopy(signals))


def accepted(records):
    return [record for record in records
            if record.get('kind') == 'uart_consumption_match'
            and record.get('status') == 'accepted']


def test_deleted_or_boolean_probe_blocks_equal_byte_promotion():
    for damage in ('delete', 'boolean', 'overflow'):
        event = tick()
        if damage == 'delete':
            del event['pre']['probe_uart_sync_intq']
        elif damage == 'boolean':
            event['pre']['probe_uart_sync_intq'] = False
        else:
            event['pre']['probe_uart_fifo_depth'] = 128
        original = deepcopy(event)
        records = UartConsumptionTracker().consume(event)
        assert not accepted(records)
        assert any(record.get('status') == 'incomplete' for record in records)
        assert event == original


def test_empty_zero_read_never_consumes_same_edge_new_zero_entry():
    tracker = UartConsumptionTracker()
    event = tick()
    event['pre'].update(probe_uart_fifo_wvalid=1,
                        probe_uart_fifo_incr_wptr=1,
                        probe_uart_fifo_rdata_re=1)
    event['post'].update(probe_uart_fifo_depth=1,
                         probe_uart_fifo_wptr=1,
                         probe_uart_fifo_rvalid=1)
    records = tracker.consume(event)
    assert not any(record['kind'] == 'uart_fifo_pop' for record in records)
    assert not accepted(records)
    pushes = [record for record in records if record['kind'] == 'uart_fifo_push']
    assert len(pushes) == 1
    assert pushes[0]['origin_status'] == 'unknown'


def test_unknown_identical_entries_preserve_order_without_byte_realignment():
    tracker = UartConsumptionTracker()
    entries = []
    for index in range(2):
        event = tick(index + 1)
        event['pre'].update(probe_uart_fifo_depth=index,
            probe_uart_fifo_wptr=index, probe_uart_fifo_rvalid=int(index > 0),
            probe_uart_fifo_head=0x5a if index else 0,
            probe_uart_fifo_data=0x5a, probe_uart_rx_data=0x5a,
            probe_uart_fifo_wvalid=1,
            probe_uart_fifo_incr_wptr=1)
        event['post'].update(probe_uart_fifo_depth=index + 1,
            probe_uart_fifo_wptr=index + 1, probe_uart_fifo_rvalid=1,
            probe_uart_fifo_head=0x5a, probe_uart_fifo_data=0x5a,
            probe_uart_rx_data=0x5a)
        records = tracker.consume(event)
        pushes = [record for record in records if record['kind'] == 'uart_fifo_push']
        assert len(pushes) == 1
        entries.append(pushes[0]['entry_id'])
        assert pushes[0]['origin_status'] == 'unknown'
        assert not accepted(records)
    assert entries[0] != entries[1]
    event = tick(3)
    event['pre'].update(probe_uart_fifo_depth=2, probe_uart_fifo_wptr=2,
        probe_uart_fifo_rvalid=1, probe_uart_fifo_head=0x5a,
        probe_uart_fifo_rdata_re=1, probe_uart_fifo_incr_rptr=1)
    event['post'].update(probe_uart_fifo_depth=1, probe_uart_fifo_wptr=2,
        probe_uart_fifo_rptr=1, probe_uart_fifo_rvalid=1,
        probe_uart_fifo_head=0x5a)
    records = tracker.consume(event)
    pops = [record for record in records if record['kind'] == 'uart_fifo_pop']
    assert len(pops) == 1
    assert pops[0]['entry_id'] == entries[0]
    assert pops[0]['origin_status'] == 'unknown'
    assert not accepted(records)


def test_cancelled_partial_producer_frame_keeps_raw_prefix_and_no_validation():
    # Software receipt fixture only; it supplies no admitted source authority.
    from tests.local_harness.test_uart_fifo_source_receipts import fifo_session
    uart = fifo_session()
    uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8,
                            action_id='cancelled-original-action')
    uart.step_local({'uart_rx_byte': 0x5a})
    frame_start = uart._source_frames[0]['record']['start_tick']
    while uart.local_ticks < frame_start + 12:
        uart.step_local({'uart_rx_byte': 0x5a})
    prefix = deepcopy(uart.uart_events)
    uart._cancel_source_frames('review-cancellation')
    cancel = uart.source_events[-1]
    assert cancel['kind'] == 'uart_source_frame_cancel'
    assert cancel['action_id'] == 'cancelled-original-action'
    assert cancel['reason'] == 'review-cancellation'
    assert cancel['sample_count'] == 13
    assert uart.uart_events == prefix
    assert not any(e['kind'] == 'uart_frame_validation' for e in uart.uart_events)
    assert not uart._source_frames
    assert all(e['physical_rx_ref'] is None
               or e['physical_rx_ref']['admission_id'] is None for e in prefix)


def test_failed_routed_access_always_clears_transaction_and_native_context():
    import pytest
    from tests.local_harness.test_uart_fifo_source_receipts import fifo_session
    from myfuzz.scenario.ledger import TransactionKey
    uart = fifo_session()
    key = TransactionKey('review', 'original-case', 'cpu', 0, 'data', 1)
    def failed_command(operation, fields):
        raise RuntimeError('unit fixture transport failure')
    uart.command = failed_command
    with pytest.raises(RuntimeError, match='transport failure'):
        uart.routed_register_access(key, address=0x40000018, offset=24,
            write=False, value=0, be=15, delivery_context={})
    assert uart._routed_uart_transaction is None
    assert uart._active_uart_access is None
    assert not any(e['kind'] == 'uart_rdata_access' for e in uart.uart_events)
