from copy import deepcopy
from tests.scenario.test_uart_native_irq_versions import join, raw, update, retention, accepted


def delivery(resource, event_id=400, value=1):
    return dict(kind='native_irq_binding_delivery', schema_version='native_irq_binding_delivery.v1', event_id=event_id,
        source_component='uart', source_epoch=0, source_local_tick=1, source_phase='post',
        irq_class='rx_watermark', source_output_key=resource['source_output_key'],
        source_observation_event_id=resource['source_observation_event_id'],
        source_receipt_ref=resource['source_receipt_ref'], source_port='uart_rx_watermark',
        target_component='cpu', target_epoch=0, target_port='irq', width=1,
        source_bit_offset=0, target_bit_offset=0, value=value, dataflow_delivery_event_id=399)


def test_unknown_binding_schema_and_different_target_value_fail_closed():
    for field, value in (('schema_version', 'native_irq_binding_delivery.v2'), ('target_value', True)):
        tracker, resource = configured()
        event = delivery(resource); event[field] = value
        assert any(record.get('status') == 'incomplete' for record in tracker.consume(event))


def configured():
    tracker, admission = join()
    event = raw()
    tracker.consume(event); tracker.consume(update(event)); tracker.consume(retention(admission))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    return tracker, resource


def test_wrong_equal_valued_version_and_binding_bit_are_rejected():
    for field in ('source_output_key', 'source_observation_event_id', 'target_bit_offset', 'source_port'):
        tracker, resource = configured()
        event = delivery(resource)
        if field == 'source_output_key': event[field] = ['uart', 0, 'rx_watermark', 99]
        elif field == 'source_observation_event_id': event[field] += 1
        elif field == 'source_port': event[field] = 'uart_tx_watermark'
        else: event[field] = 1
        before = deepcopy(event)
        records = tracker.consume(event)
        assert any(record.get('status') == 'incomplete' for record in records)
        assert not accepted(records, 'cpu_external_irq_taken')
        assert event == before


def test_equal_level_new_delivery_overwrites_old_receipt_and_reset_cancels():
    from tests.scenario.test_uart_native_irq_taken import sample, taken
    tracker, resource = configured()
    tracker.consume(delivery(resource))
    tracker.consume(delivery(resource, event_id=401))
    assert any(record.get('status') == 'incomplete' for record in tracker.consume(sample()))
    assert not accepted(tracker.consume(taken()), 'cpu_external_irq_taken')
    tracker, resource = configured(); tracker.consume(delivery(resource))
    tracker.consume(dict(kind='cpu_reset', event_id=450, component='cpu', reset_epoch=1,
                         local_tick=1, physical_reset=True))
    assert not accepted(tracker.consume(sample()) + tracker.consume(taken()), 'cpu_external_irq_taken')
