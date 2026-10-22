"""Contract tests for the keyed Caliptra SHA256 AHB target provider."""
from collections import deque
from copy import deepcopy
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.ahb_lite_register_session import (
    GeneratedAhbLiteRegisterSession,
)
from myfuzz.scenario.ledger import TransactionKey


BASE = 0x40002000
OFFSET = 0x10
ADDRESS = BASE + OFFSET
VALUE = 5
TRACE = {
    'haddr': 'trace_haddr', 'hwdata': 'trace_hwdata',
    'hsel': 'trace_hsel', 'hwrite': 'trace_hwrite',
    'hreadyin': 'trace_hreadyin', 'htrans': 'trace_htrans',
    'hsize': 'trace_hsize', 'hresp': 'trace_hresp',
    'hreadyout': 'trace_hreadyout', 'hrdata': 'trace_hrdata',
}


def _key(**changes):
    values = dict(execution_id='dma-exec', testcase_id='case-1',
        source_component='dma', source_epoch=0, channel_id='write_master',
        source_sequence=4)
    values.update(changes)
    return TransactionKey(**values)


def _phase(*, data=False, address=OFFSET, value=VALUE, hresp=0,
           accepted=True):
    pins = {
        'trace_haddr': address,
        'trace_hwdata': value if data else 0,
        'trace_hsel': 0 if data else int(accepted),
        'trace_hwrite': 1,
        'trace_hreadyin': 1,
        'trace_htrans': 0 if data else (2 if accepted else 0),
        'trace_hsize': 2,
        'trace_hresp': hresp,
        'trace_hreadyout': int(data),
        'trace_hrdata': 0,
    }
    return {'backend': pins}


def _session(*, phases=None, result=None, outputs=None):
    document = {
        'kind': 'ahb_lite_register_observe',
        'artifact_digest': 'a' * 64,
        'base_protocol_trace': {
            'schema_version': 'ip_protocol_trace.v1',
            'protocol': 'ahb-lite', 'endpoint_id': 'sha256.bus',
            'signals': dict(TRACE),
        },
    }
    session = GeneratedAhbLiteRegisterSession.__new__(
        GeneratedAhbLiteRegisterSession)
    session.artifact = SimpleNamespace(
        runtime_document=document,
        plan=SimpleNamespace(request=SimpleNamespace(instance_id='sha')))
    session._artifact_document = deepcopy(document)
    session._window = 0x1000
    session._execution = 'ahb-exec'
    session._sequence = 0
    session._case_id = 'case-1'
    session.reset_epoch = 0
    session.local_ticks = 0
    session._tick_base = 0
    session._process = SimpleNamespace(poll=lambda: None)
    session._samples = deque()
    session._outputs = dict(outputs or {})
    session._dma_target_events = []
    session._dma_target_poisoned = False
    session.command_calls = []
    actual_phases = phases if phases is not None else (
        _phase(), _phase(data=True))
    actual_result = result or {'rdata': 0, 'error': 0}

    def command(operation, fields):
        session.command_calls.append((operation, fields))
        session._sequence += 1
        for index, phase in enumerate(actual_phases, 1):
            tick = session.local_ticks + index
            session._samples.append({'local_tick': tick, 'pre': deepcopy(phase)})
        session.local_ticks += len(actual_phases)
        return object()

    session.command = command
    session._take = lambda _reply: dict(actual_result)
    return session


def _call(session, *, key=None, address=ADDRESS, offset=OFFSET, write=True,
          value=VALUE, byte_enable=15, delivery_context=None):
    transaction = key or _key()
    context = delivery_context or {
        'source_transaction': {
            'execution_id': transaction.execution_id,
            'testcase_id': transaction.testcase_id,
            'source_component': transaction.source_component,
            'source_epoch': transaction.source_epoch,
            'channel_id': transaction.channel_id,
            'source_sequence': transaction.source_sequence,
        },
        'device_id': 'sha', 'address': address, 'offset': offset,
        'write': write, 'value': value, 'be': byte_enable,
        'window_base': BASE, 'window_size': 0x1000,
    }
    return session.dma_master_target_access(
        transaction, address=address, offset=offset, write=write,
        value=value, byte_enable=byte_enable, delivery_context=context)


def test_provider_identity_is_closed_and_pins_ahb_ctrl_start():
    session = _session()

    identity = session.dma_master_target_provider_identity_document()

    assert identity == {
        'schema_version': 'caliptra_sha256_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
        'artifact_digest': 'a' * 64,
        'endpoint_id': 'sha256.bus',
        'operation': 'write', 'register': 'CTRL', 'offset': OFFSET,
        'value': VALUE, 'byte_enable': 15,
        'observation_contract_schema_version': 'ip_protocol_trace.v1',
    }


def test_provider_joins_real_address_phase_data_phase_and_dma_key():
    session = _session()

    receipt = _call(session)

    assert receipt['schema_version'] == 'dma_master_target_access.v1'
    assert receipt['status'] == 'observed'
    assert receipt['request'] == {
        'address': ADDRESS, 'offset': OFFSET, 'write': True,
        'value': VALUE, 'byte_enable': 15}
    assert receipt['response'] == {'rdata': 0, 'error': 0}
    assert receipt['source_transaction'] == {
        'execution_id': 'dma-exec', 'testcase_id': 'case-1',
        'source_component': 'dma', 'source_epoch': 0,
        'channel_id': 'write_master', 'source_sequence': 4}
    assert receipt['target_access']['status'] == 'observed'
    assert receipt['target_request']['backend']['haddr'] == OFFSET
    assert receipt['target_request']['backend']['hwrite'] == 1
    assert receipt['target_response']['backend']['hwdata'] == VALUE
    assert receipt['target_response']['backend']['hresp'] == 0
    assert receipt['target_effect']['accepted_value'] == VALUE
    assert receipt['target_effect']['register'] == 'CTRL'
    assert receipt['target_effect']['schema_version'] == (
        'caliptra_sha256_ctrl_ahb_write_completion.v1')
    assert receipt['target_effect']['effect'] == 'ctrl_write_transfer_completed'
    assert receipt['target_effect']['proof_scope'] == 'ahb_write_data_phase_completion'
    access_id = receipt['target_access_id']
    assert all(receipt[name]['access_id'] == access_id for name in (
        'target_access', 'target_request', 'target_response', 'target_effect'))
    assert len(session.command_calls) == 1
    assert session.command_calls[0] == ('ACCESS_AHB_REG', (1, OFFSET, VALUE, 15))


def test_provider_accepts_only_extra_results_declared_as_physical_outputs():
    session = _session(
        result={'rdata': 0, 'error': 0, 'error_intr': 0, 'notif_intr': 0},
        outputs={'error_intr': ('trace_error_intr', 1),
                 'notif_intr': ('trace_notif_intr', 1)})

    receipt = _call(session)

    assert receipt['response'] == {'rdata': 0, 'error': 0}


def test_provider_refuses_unknown_ahb_result_fields_after_command():
    session = _session(result={'rdata': 0, 'error': 0, 'unexpected': 0})

    with pytest.raises(RuntimeError, match='response was not successful'):
        _call(session)

    assert session._dma_target_poisoned is True
    assert session._dma_target_events[-1]['status'] == 'uncertain'


@pytest.mark.parametrize('changes', [
    {'address': ADDRESS + 4, 'offset': OFFSET + 4},
    {'offset': 0x80, 'address': BASE + 0x80},
    {'value': 4},
    {'write': False},
    {'byte_enable': 1},
])
def test_provider_refuses_non_ctrl_start_before_ahb_command(changes):
    session = _session()

    with pytest.raises(ValueError):
        _call(session, **changes)

    assert session.command_calls == []
    assert session._dma_target_poisoned is False


@pytest.mark.parametrize('phases,result', [
    ((_phase(accepted=False), _phase(data=True)), {'rdata': 0, 'error': 0}),
    ((_phase(), _phase(), _phase(data=True)), {'rdata': 0, 'error': 0}),
    ((_phase(address=OFFSET + 4), _phase(data=True)), {'rdata': 0, 'error': 0}),
    ((_phase(), _phase(data=True, value=4)), {'rdata': 0, 'error': 0}),
    ((_phase(), _phase(data=True, hresp=1)), {'rdata': 0, 'error': 0}),
    ((_phase(), _phase(data=True)), {'rdata': 0, 'error': 1}),
])
def test_provider_retains_uncertain_terminal_after_bad_native_evidence(phases, result):
    session = _session(phases=phases, result=result)

    with pytest.raises((RuntimeError, ValueError)):
        _call(session)

    assert len(session.command_calls) == 1
    assert session._dma_target_poisoned is True
    assert session._dma_target_events[-1]['status'] == 'uncertain'
    with pytest.raises(ValueError, match='poisoned'):
        _call(session, key=_key(source_sequence=5))
    assert len(session.command_calls) == 1
