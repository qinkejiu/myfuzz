"""Native delivery/sample/take scopes independent of UART source cause."""
from tests.scenario.test_uart_native_irq_versions import raw, update, authority
from tests.scenario.test_uart_native_irq_binding import delivery
from tests.scenario.test_uart_native_irq_taken import sample, taken


def test_native_join_has_opt_in_delivery_and_acceptance_scopes_without_cause_claim():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    registry, ownership, _ = authority()
    try:
        tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry,
                                   enable_boundary_evidence=True)
    except TypeError:
        tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry)
    tick = raw()
    tracker.consume(tick); tracker.consume(update(tick))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    tracker.consume(delivery(resource)); tracker.consume(sample()); tracker.consume(taken())
    drain = getattr(tracker, 'drain_boundary_evidence', None)
    assert drain is not None
    records = drain()
    assert [r['proof_scope'] for r in records] == ['irq_delivery', 'irq_acceptance']
    assert all(r['source_origin'] == 'unknown' for r in records)
    assert records[0]['sample_event_id'] == 500
    assert records[1]['take_event_id'] == 501
    assert drain() == ()


def test_native_boundary_export_is_default_off():
    from tests.scenario.test_uart_native_irq_binding import configured
    tracker, resource = configured()
    tracker.consume(delivery(resource)); tracker.consume(sample()); tracker.consume(taken())
    drain = getattr(tracker, 'drain_boundary_evidence', None)
    assert drain is not None and drain() == ()


def test_opt_in_boundary_queue_rejects_unbounded_receipt_text():
    from myfuzz.scenario.uart_irq_consumption import UartNativeIrqJoin
    registry, ownership, _ = authority()
    tracker = UartNativeIrqJoin(ownership=ownership, admission_registry=registry,
                               enable_boundary_evidence=True)
    tick = raw(); tracker.consume(tick); tracker.consume(update(tick))
    resource = tracker.output_at('uart', 0, 1, 'post', 'rx_watermark')
    tracker.consume(delivery(resource))
    measured = sample(); measured['receipt_id']['execution'] = 'x' * 10000
    tracker.consume(measured)
    assert tracker.drain_boundary_evidence() == ()
