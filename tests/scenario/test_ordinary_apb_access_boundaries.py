"""Independent ordinary receipt handoff boundaries; software targets, no RTL."""
from copy import deepcopy
from dataclasses import asdict

import pytest

from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.router import DataflowRouter, DeviceWindow


class ObservedTarget:
    ordinary_apb_access_receipts_enabled = True
    routed_register_access_enabled = False

    def __init__(self, name):
        self.name = name
        self.calls = []
        self.failed = []
        self.receipt = {'target_instance': name}

    def execute_observed_register_access(self, key, *, delivery_context):
        self.calls.append((key, deepcopy(delivery_context)))
        self.receipt.update(schema_version='ordinary_apb_target_receipt.v1',
            access_id='access:' + self.name, source_transaction=asdict(key),
            delivery_context=deepcopy(delivery_context), status='target_observed',
            error=0, rdata=7, grants_verified=False, grants_storage=False, grants_functional=False,
            endpoint_id='gpio.bus', target_reset_epoch=0,
            command_scope=dict(component=self.name,reset_epoch=0,command_sequence=1),
            driver_receipt=dict(execution_scope='parsed_driver_execution',process_scope='driver',sequence=1,tick_before=0,tick_after=2,new_ticks=2),
            sample_ticks=[1,2],proof_scope='actual_target_command_observation_only')
        return dict(rdata=7, target_access_id='access:' + self.name,
                    target_access_receipt=self.receipt)

    def ordinary_apb_access_receipt(self, access_id):
        assert access_id == 'access:' + self.name
        if getattr(self, 'lookup_missing', False):
            return None
        return deepcopy(self.receipt)

    def ordinary_apb_delivery_failed(self, key, access_id):
        self.failed.append((key, access_id))

    def read_register(self, *args, **kwargs):
        raise AssertionError('observed dispatch bypassed')

    def write_register(self, *args, **kwargs):
        raise AssertionError('observed dispatch bypassed')


def setup():
    a, b = ObservedTarget('a'), ObservedTarget('b')
    router = DataflowRouter((DeviceWindow('a', 0x40000000, 4096, a),
                             DeviceWindow('b', 0x40001000, 4096, b)))
    return a, b, router, TransactionLedger()


def enqueue(router, ledger, sequence, address, callback):
    key = TransactionKey('execution', 'case', 'cpu', 0, 'data', sequence)
    fresh = router.enqueue(ledger, key, address=address, write=False,
                           wdata=0, be=15, beat_bytes=4, callback=callback)
    return key, fresh


def test_two_equal_value_targets_keep_exact_window_and_key_handoff():
    a, b, router, ledger = setup()
    responses = []
    ka, _ = enqueue(router, ledger, 1, 0x40000004, responses.append)
    kb, _ = enqueue(router, ledger, 2, 0x40001004, responses.append)
    assert router.drain_one('a') and router.drain_one('b')
    assert responses == [(7, 0), (7, 0)]
    assert a.calls[0][0] == ka and b.calls[0][0] == kb
    for target, base in ((a, 0x40000000), (b, 0x40001000)):
        context = target.calls[0][1]
        assert context['device_id'] == target.name
        assert context['window_base'] == base and context['offset'] == 4
        assert context['address'] == base + 4
    assert [r['device_id'] for r in router.deliveries] == ['a', 'b']
    assert [r['target_access_id'] for r in router.deliveries] == ['access:a', 'access:b']


def test_completed_delivery_receipt_is_detached_from_target_return_value():
    a, _, router, ledger = setup()
    enqueue(router, ledger, 1, 0x40000004, lambda response: None)
    assert router.drain_one('a')
    saved = deepcopy(router.deliveries)
    a.receipt['sample_ticks'].append(999)
    a.receipt['target_instance'] = 'foreign'
    assert router.deliveries == saved


def test_callback_failure_replay_never_executes_target_or_publishes_delivery():
    a, _, router, ledger = setup()
    def refuse(response):
        assert response == (7, 0)
        raise RuntimeError('source callback refused')
    key, _ = enqueue(router, ledger, 1, 0x40000004, refuse)
    with pytest.raises(RuntimeError, match='source callback refused'):
        router.drain_one('a')
    assert router.deliveries == [] and a.failed == [(key, 'access:a')]
    _, fresh = enqueue(router, ledger, 1, 0x40000004, lambda response: None)
    assert fresh is False and router.drain_one('a') is False
    assert len(a.calls) == 1 and router.deliveries == []


@pytest.mark.parametrize('mutation', ('foreign_target', 'wrong_transaction',
    'wrong_context', 'wrong_return_value', 'saved_copy_only', 'grant_verified'))
def test_router_rejects_mismatched_or_unretained_target_receipt(mutation):
    a, _, router, ledger = setup()
    original = a.execute_observed_register_access
    def altered(key, *, delivery_context):
        result = original(key, delivery_context=delivery_context)
        if mutation == 'foreign_target':
            a.receipt['target_instance'] = 'b'
        elif mutation == 'wrong_transaction':
            a.receipt['source_transaction']['source_epoch'] = 1
        elif mutation == 'wrong_context':
            a.receipt['delivery_context']['window_base'] += 4096
        elif mutation == 'wrong_return_value':
            result['rdata'] = 8
        elif mutation == 'saved_copy_only':
            result['target_access_receipt'] = deepcopy(a.receipt)
            a.lookup_missing = True
        elif mutation == 'grant_verified':
            a.receipt['grants_verified'] = True
        return result
    a.execute_observed_register_access = altered
    enqueue(router, ledger, 1, 0x40000004, lambda response: None)
    with pytest.raises(ValueError):
        router.drain_one('a')
    assert router.deliveries == [] and len(a.calls) == 1
    assert ledger.uncertain_keys

# Real rendered artifact and strict wire parser; command is software only.
from tests.local_harness.test_ordinary_apb_access_receipts import (
    native_factory, configured, context, software_transport,
)


@pytest.mark.parametrize('mutation', ('epoch_during_command', 'extra_access',
    'read_data_disagrees', 'missing_setup'))
def test_actual_parsed_command_span_mutations_never_publish_observed_receipt(native_factory, mutation):
    from dataclasses import replace
    session = configured(native_factory)
    def mutate(receipt):
        if mutation == 'epoch_during_command':
            session.reset_epoch += 1
            return receipt
        payload = deepcopy(receipt.payload)
        if mutation == 'extra_access':
            for phase in ('pre', 'post'):
                payload['samples'][2][phase]['backend'].update(trace_psel=1, trace_penable=1)
        elif mutation == 'read_data_disagrees':
            for phase in ('pre', 'post'):
                payload['samples'][1][phase]['backend']['trace_prdata'] = 8
        elif mutation == 'missing_setup':
            for phase in ('pre', 'post'):
                payload['samples'][0][phase]['backend']['trace_psel'] = 0
        return replace(receipt, payload=payload)
    calls = software_transport(session, mutate=mutate)
    key, ctx = context()
    with pytest.raises(ValueError):
        session.execute_observed_register_access(key, delivery_context=ctx)
    assert len(calls) == 1
    with pytest.raises(ValueError):
        session.execute_observed_register_access(key, delivery_context=ctx)
    assert len(calls) == 1


@pytest.mark.parametrize('mutation', ('scope_epoch_bool', 'context_epoch_bool',
    'sample_tick_bool', 'execution_id_integer'))
def test_closed_receipt_rejects_equal_value_wrong_types(mutation):
    from myfuzz.local_harness.ordinary_apb_access_receipts import validate_ordinary_apb_target_receipt
    target = ObservedTarget('a')
    key = TransactionKey('execution', 'case', 'cpu', 0, 'data', 1)
    ctx = dict(source_transaction=asdict(key), device_id='a', window_base=0x40000000,
               window_size=4096, address=0x40000004, offset=4, write=False, value=0, be=15)
    doc = deepcopy(target.execute_observed_register_access(key, delivery_context=ctx)['target_access_receipt'])
    assert validate_ordinary_apb_target_receipt(doc) == doc
    if mutation == 'scope_epoch_bool':
        doc['command_scope']['reset_epoch'] = False
    elif mutation == 'context_epoch_bool':
        doc['delivery_context']['source_transaction']['source_epoch'] = False
    elif mutation == 'sample_tick_bool':
        doc['sample_ticks'][0] = True
    else:
        doc['source_transaction']['execution_id'] = 1
        doc['delivery_context']['source_transaction']['execution_id'] = 1
    with pytest.raises(ValueError):
        validate_ordinary_apb_target_receipt(doc)


def test_command_tick_base_change_cannot_publish_wrong_lifetime_sample_refs(native_factory):
    session = configured(native_factory)
    def shift(receipt):
        session._tick_base += 100
        return receipt
    calls = software_transport(session, mutate=shift)
    key, ctx = context()
    with pytest.raises(ValueError):
        session.execute_observed_register_access(key, delivery_context=ctx)
    assert len(calls) == 1


def test_new_driver_process_without_reset_cannot_overwrite_existing_access_identity(native_factory):
    """Mirror end_case/begin_case identity changes with parsed software receipts."""
    session = configured(native_factory)
    calls = software_transport(session)
    key, ctx = context()
    old = session.execute_observed_register_access(key, delivery_context=ctx)
    session.drain_tick_samples()
    # GeneratedLocalSession.begin_case changes execution and resets sequence,
    # retaining reset_epoch and lifetime local_ticks (no RTL process here).
    session._sequence = 0
    session._tick_base = session.local_ticks
    original = session.command
    session._execution = 'fedcba9876543210fedcba9876543210'
    next_key = TransactionKey('next-execution', 'next-case', 'cpu', 0, 'data', 1)
    next_ctx = {**ctx, 'source_transaction': asdict(next_key)}
    new = session.execute_observed_register_access(next_key, delivery_context=next_ctx)
    assert len(calls) == 2
    assert new['target_access_id'] != old['target_access_id']
    assert session.ordinary_apb_access_receipt(new['target_access_id']) == new['target_access_receipt']
