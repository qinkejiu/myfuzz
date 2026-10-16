"""Independent actual-object association boundaries; parsed software, no RTL."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from myfuzz.scenario.ledger import TransactionKey
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory, software_transport


def actual(native_factory):
    runner = native_factory()
    cpu = runner.sessions['cpu']
    target = runner.sessions['gpio_a']
    target.configure_ordinary_apb_access_receipts()
    calls = software_transport(target, rdata=7)
    cpu._case_id = 'stream'
    window = next(row for row in cpu.router.windows if row.device_id == 'gpio_a')
    return runner, cpu, target, calls, window


def confirmation(router, key):
    try:
        return router.ordinary_delivery_confirmation(key)
    except ValueError:
        return None


def test_synchronous_delivery_public_flag_cannot_create_actual_callback_pin(native_factory):
    _, cpu, target, calls, window = actual(native_factory)
    key = TransactionKey('execution', 'case', 'cpu', 0, 'data', 1)
    assert cpu.router.transact(cpu.service.ledger, key, address=window.base + 12,
        write=False, wdata=0, be=15, beat_bytes=4) == (7, 0)
    row = cpu.router.deliveries[-1]
    assert row['source_delivery_confirmed'] is False
    assert confirmation(cpu.router, key) is None
    row['source_delivery_confirmed'] = True
    row['target_access_receipt']['grants_verified'] = False
    assert confirmation(cpu.router, key) is None
    assert len(calls) == 1


def test_failed_actual_callback_public_delivery_cannot_create_pin(native_factory):
    _, cpu, target, calls, window = actual(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    key = cpu.router.acceptances[-1]['source_transaction']
    accepted = deepcopy(cpu.router.acceptances[-1])
    queued = cpu.router._queued[-1]
    def fail(response):
        raise RuntimeError('independent source callback refusal')
    cpu.router._queued[-1] = (*queued[:-1], fail)
    with pytest.raises(RuntimeError, match='independent source callback refusal'):
        cpu.router.drain_one('gpio_a')
    assert cpu.router.deliveries == []
    assert confirmation(cpu.router, key) is None
    observed = next(row for row in target.ordinary_apb_access_events
                    if row.get('schema_version') == 'ordinary_apb_target_receipt.v1')
    cpu.router.deliveries.append({**accepted, 'source_delivery_confirmed': True,
        'target_access_id': observed['access_id'], 'target_access_receipt': deepcopy(observed),
        'read_value': 7})
    assert confirmation(cpu.router, key) is None
    assert len(calls) == 1


def test_actual_callback_confirmation_is_detached_from_public_delivery(native_factory):
    _, cpu, target, calls, window = actual(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    key = cpu.router.acceptances[-1]['source_transaction']
    assert cpu.router.drain_one('gpio_a')
    confirmed = confirmation(cpu.router, key)
    assert confirmed is not None
    saved = deepcopy(confirmed)
    cpu.router.deliveries[-1]['target_access_receipt']['sample_ticks'].clear()
    cpu.router.deliveries[-1]['read_value'] = 999
    assert confirmation(cpu.router, key) == saved
    confirmed['target_access_receipt']['sample_ticks'].clear()
    assert confirmation(cpu.router, key) == saved
    assert len(calls) == 1


def test_tagged_raw_mutation_cannot_change_original_parsed_sample_digest(native_factory):
    import hashlib
    import json
    _, cpu, target, calls, window = actual(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    assert cpu.router.drain_one('gpio_a')
    receipt = cpu.router.deliveries[-1]['target_access_receipt']
    sample = target._samples[1]
    digest = target.ordinary_apb_sample_digest(receipt['access_id'], sample['local_tick'], 'pre')
    encoded = lambda state: json.dumps(state, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    assert digest == hashlib.sha256(encoded(sample['pre'])).hexdigest()
    sample['pre']['backend']['trace_prdata'] = 999
    assert hashlib.sha256(encoded(sample['pre'])).hexdigest() != digest
    assert target.ordinary_apb_sample_digest(receipt['access_id'], sample['local_tick'], 'pre') == digest
    with pytest.raises(ValueError):
        target.ordinary_apb_sample_digest(receipt['access_id'], sample['local_tick'] + 1000, 'pre')
    with pytest.raises(ValueError):
        target.ordinary_apb_sample_digest(receipt['access_id'], sample['local_tick'], 'unknown')
    assert len(calls) == 1


@pytest.mark.parametrize('changed', ('process_execution', 'target_epoch'))
def test_original_sample_digest_cannot_be_queried_as_current_after_lifecycle_change(native_factory, changed):
    _, cpu, target, calls, window = actual(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    assert cpu.router.drain_one('gpio_a')
    receipt = cpu.router.deliveries[-1]['target_access_receipt']
    tick = receipt['sample_ticks'][0]
    digest = target.ordinary_apb_sample_digest(receipt['access_id'], tick, 'pre')
    assert len(digest) == 64
    if changed == 'process_execution':
        target._execution = 'fedcba9876543210fedcba9876543210'
    else:
        target.reset_epoch += 1
    with pytest.raises(ValueError):
        target.ordinary_apb_sample_digest(receipt['access_id'], tick, 'pre')
    assert len(calls) == 1


def linked(native_factory):
    from tests.scenario.test_ordinary_apb_access_runner import installed
    runner, cpu = installed(native_factory)
    return runner, cpu, runner.sessions['gpio_a'], next(w for w in cpu.router.windows if w.device_id == 'gpio_a')


def assert_no_confirmed_association(runner):
    assert all(row['status'] != 'cpu_delivery_confirmed' for row in runner.events
               if row.get('kind') == 'ordinary_apb_access_association')


def test_direct_router_enqueue_with_cpu_shaped_key_and_noop_is_not_cpu_admission(native_factory):
    runner, cpu, target, window = linked(native_factory)
    key = cpu._key('data')
    assert cpu.router.enqueue(cpu.service.ledger, key, address=window.base + 12,
        write=False, wdata=0, be=15, beat_bytes=4, callback=lambda response: None)
    before = target._sequence
    with pytest.raises(ValueError):
        runner._ordinary_apb_access_evidence.preflight_access(cpu.router, target)
    assert target._sequence == before
    assert_no_confirmed_association(runner)


@pytest.mark.parametrize('replaced', ('noop', 'closure_key', 'closure_self', 'closure_write'))
def test_replaced_actual_completed_callback_cannot_confirm_cpu_delivery(native_factory, replaced):
    import types
    import copy
    runner, cpu, target, window = linked(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    queued = cpu.router._queued[-1]
    callback = queued[-1]
    if replaced == 'noop':
        replacement = lambda response: None
    else:
        cells = dict(zip(callback.__code__.co_freevars, callback.__closure__))
        def cell(value):
            return (lambda: value).__closure__[0]
        if replaced == 'closure_key':
            key = queued[1]
            cells['key'] = cell(TransactionKey(key.execution_id, key.testcase_id,
                key.source_component, key.source_epoch, key.channel_id, key.source_sequence + 1))
        elif replaced == 'closure_self':
            cells['self'] = cell(copy.copy(cpu))
        else:
            cells['write'] = cell(1)
        replacement = types.FunctionType(callback.__code__, callback.__globals__,
            callback.__name__, callback.__defaults__, tuple(cells[name] for name in callback.__code__.co_freevars))
    cpu.router._queued[-1] = (*queued[:-1], replacement)
    before = target._sequence
    with pytest.raises(ValueError):
        runner._ordinary_apb_access_evidence.preflight_access(cpu.router, target)
    assert target._sequence == before
    assert_no_confirmed_association(runner)


def test_callback_replaced_after_initial_preflight_is_rechecked_before_target_command(native_factory):
    runner, cpu, target, window = linked(native_factory)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    observer = runner._ordinary_apb_access_evidence
    observer.preflight_access(cpu.router, target)
    queued = cpu.router._queued[-1]
    cpu.router._queued[-1] = (*queued[:-1], lambda response: None)
    before = target._sequence
    with pytest.raises(ValueError):
        observer.preflight_access(cpu.router, target)
    assert target._sequence == before
    assert_no_confirmed_association(runner)


@pytest.mark.parametrize('changed_index,replacement', ((4, 1), (5, 99), (6, 16)))
def test_actual_queue_decoded_access_drift_refuses_before_command(native_factory, changed_index, replacement):
    runner, cpu, target, window = linked(native_factory)
    assert cpu._serve('data', 1, window.base + 12, 1, 15) is None
    queued = list(cpu.router._queued[-1])
    queued[changed_index] = replacement
    cpu.router._queued[-1] = tuple(queued)
    before = target._sequence
    with pytest.raises(ValueError):
        runner._ordinary_apb_access_evidence.preflight_access(cpu.router, target)
    assert target._sequence == before
    assert_no_confirmed_association(runner)


def test_missing_delivery_journal_row_cannot_be_a_complete_target_only_association(native_factory):
    from tests.scenario.test_ordinary_apb_access_evidence import installed
    runner, target = installed(native_factory)
    software_transport(target)
    cpu = runner.sessions['cpu']; cpu._case_id = 'stream'
    window = next(w for w in cpu.router.windows if w.target is target)
    assert cpu._serve('data', 0, window.base + 12, 0, 15) is None
    observer = runner._ordinary_apb_access_evidence
    observer.preflight_access(cpu.router, target)
    assert cpu.router.drain_one('gpio_a')
    cpu.router.deliveries.clear()
    runner._append_external_events('cpu', 1)
    runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a'] = target.local_ticks
    runner._drain_tick_samples(1)
    records = observer.finalize_pending(cpu.router, target)
    assert len(records) == 1 and records[0]['status'] == 'incomplete'
    assert observer.snapshot()['status'] == 'incomplete'
