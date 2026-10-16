"""Independent software boundaries for actual completed-access observation seals."""
import pytest
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.scenario.test_ordinary_apb_access_runner import installed, deliver


def write(runner, cpu, *, target='gpio_a', value=7):
    window = next(w for w in cpu.router.windows if w.device_id == target)
    cpu._pending_data = None
    cpu._serve('data', 1, window.base + 12, value, 15)
    runner._append_external_events('cpu', len(runner._events))
    runner._step_once(target)


def test_failed_later_callback_preserves_only_successful_historical_prefix(native_factory):
    runner, cpu = installed(native_factory)
    deliver(runner, cpu)
    observer = runner._ordinary_apb_access_evidence
    before = observer.completed_accesses()
    window = next(w for w in cpu.router.windows if w.device_id == 'gpio_a')
    cpu._pending_data = None
    cpu._serve('data', 0, window.base + 12, 0, 15)
    cpu.mmio_read_count = 'bad'
    runner._append_external_events('cpu', len(runner._events))
    with pytest.raises(TypeError):
        runner._step_once('gpio_a')
    assert observer.snapshot()['status'] == 'incomplete'
    assert observer.completed_accesses() == before
    assert len(observer.snapshot()['records']) == 2


def test_equal_value_actual_writes_remain_two_distinct_accesses(native_factory):
    runner, cpu = installed(native_factory)
    write(runner, cpu)
    write(runner, cpu)
    first, second = runner._ordinary_apb_access_evidence.completed_accesses()
    assert [first['ordinal'], second['ordinal']] == [1, 2]
    assert first['association']['access_id'] != second['association']['access_id']
    assert first['association']['source_transaction'] != second['association']['source_transaction']
    for row in (first, second):
        assert row['receipt']['delivery_context']['write'] is True
        assert row['receipt']['delivery_context']['value'] == 7
        assert row['cpu_response'] == [0, 0, row['association']['source_transaction']['source_sequence']]


def test_same_value_other_actual_target_preserves_instance_identity(native_factory):
    runner, cpu = installed(native_factory)
    write(runner, cpu, target='gpio_a')
    write(runner, cpu, target='gpio_b')
    first, second = runner._ordinary_apb_access_evidence.completed_accesses()
    assert [row['receipt']['target_instance'] for row in (first, second)] == ['gpio_a', 'gpio_b']
    assert first['association']['access_id'] != second['association']['access_id']
    assert first['receipt']['delivery_context']['address'] != second['receipt']['delivery_context']['address']


def test_nested_export_cannot_rewrite_original_seal(native_factory):
    runner, cpu = installed(native_factory)
    deliver(runner, cpu)
    observer = runner._ordinary_apb_access_evidence
    expected = observer.completed_accesses()
    changed = observer.completed_accesses()[0]
    changed['association']['raw_event_refs'].clear()
    changed['request_evidence'].clear()
    changed['delivery']['target_access_receipt']['sample_ticks'].clear()
    changed['cpu_response'][0] = 0x12345678
    assert observer.completed_accesses() == expected


def test_completed_history_export_checks_current_code_method_pin(native_factory, monkeypatch):
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    runner, cpu = installed(native_factory)
    deliver(runner, cpu)
    observer = runner._ordinary_apb_access_evidence
    monkeypatch.setattr(GeneratedCve2Session, '_serve', lambda *args: None)
    with pytest.raises(ValueError, match='cpu-serve-method-drift'):
        observer.completed_accesses()
    assert observer.snapshot()['status'] == 'incomplete'
