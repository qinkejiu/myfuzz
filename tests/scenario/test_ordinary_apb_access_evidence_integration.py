"""Root checks of the full actual-object journal binding, software transport only."""
import pytest
from tests.scenario.test_ordinary_apb_access_runner import native_factory, installed


def test_protocol_identity_drift_is_rejected_before_any_access_command(native_factory):
    runner, cpu = installed(native_factory)
    target = runner.sessions['gpio_a']
    window = next(row for row in cpu.router.windows if row.target is target)
    cpu._serve('data', 0, window.base + 12, 0, 15)
    runner._append_external_events('cpu', len(runner._events))
    normalizer = runner._ip_protocol_event_normalizers['gpio_a']
    normalizer.endpoint_id = 'foreign.endpoint'
    sequence = target._sequence
    with pytest.raises(ValueError):
        runner._step_once('gpio_a')
    assert target._sequence == sequence


def test_acceptance_reference_must_match_actual_target_and_payload(native_factory):
    runner, cpu = installed(native_factory)
    target = runner.sessions['gpio_a']
    window = next(row for row in cpu.router.windows if row.target is target)
    cpu._serve('data', 0, window.base + 12, 0, 15)
    cpu.router.acceptances[-1]['device_id'] = 'gpio_b'
    runner._append_external_events('cpu', len(runner._events))
    try:
        runner._step_once('gpio_a')
    except ValueError:
        pass
    records = runner.ordinary_apb_access_evidence_snapshot()['records']
    assert not any(row['status'] == 'cpu_delivery_confirmed' for row in records)


def test_replaced_noop_callback_cannot_claim_cpu_delivery(native_factory):
    runner, cpu = installed(native_factory)
    target = runner.sessions['gpio_a']
    window = next(row for row in cpu.router.windows if row.target is target)
    cpu._serve('data', 0, window.base + 12, 0, 15)
    pending = cpu.router._queued[0]
    cpu.router._queued[0] = (*pending[:-1], lambda response: None)
    runner._append_external_events('cpu', len(runner._events))
    try:
        runner._step_once('gpio_a')
    except ValueError:
        pass
    assert cpu._pending_data is None
    records = runner.ordinary_apb_access_evidence_snapshot()['records']
    assert not any(row['status'] == 'cpu_delivery_confirmed' for row in records)
