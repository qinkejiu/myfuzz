"""Measured PULP PADOUT provider receipts for accepted DMA target writes."""
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_dma_session import dma_route_endpoint_identity_document
from myfuzz.local_harness.pulp_gpio_probe_contract import (
    PULP_GPIO_PROBES, pulp_gpio_observation_contract)
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.ledger import TransactionKey


ROOT = Path(__file__).resolve().parents[2]
GPIO_BASE = 0x40001000
GPIO_SIZE = 0x1000
OFFSET = 12
ADDRESS = GPIO_BASE + OFFSET
VALUE = 0xA55A3CC3


def _artifact():
    document = {
        'schema_version': 'local_runtime_artifact.v1',
        'driver_schema_version': 'local_driver_generation.v1',
        'status': 'driver_generated',
        'driver_status': 'generated',
        'kind': 'apb_gpio',
        'artifact_digest': 'a' * 64,
        'driver_reset': {'schema_version': 'generated_local_reset.v1',
                         'reset_assert_ticks': 8, 'reset_release_ticks': 4},
        'effective_max_wait_cycles': 8,
        'gpio_observation_contract': pulp_gpio_observation_contract(),
        'plan': {'instance_id': 'gpio'},
        'physical_exports': [
            {'physical_port': 'gpio_probe_' + name,
             'runtime_name': 'probe_gpio_' + name,
             'width': width, 'direction': 'output'}
            for name, (width, _) in PULP_GPIO_PROBES.items()
        ] + [{'physical_port': 'gpio_in', 'runtime_name': 'gpio_in',
              'width': 32, 'direction': 'input'}],
    }
    return SimpleNamespace(runtime_document=document)


def _snapshot(value, *, physical=None, backend=None):
    raw = {name: 0 for name in PULP_GPIO_PROBES}
    raw.update(physical or {})
    return {
        'gpio_out': raw['out'], 'gpio_dir': 0, 'gpio_in_sync': 0,
        'interrupt': 0, 'gpio_padcfg': '0' * 32,
        'physical': {'probe_gpio_' + name: actual for name, actual in raw.items()},
        'backend': backend or {},
    }


def _receipt(value=VALUE):
    request_backend = {
        'gpio_req_valid': 1, 'gpio_req_ready': 1,
        'gpio_req_addr': OFFSET, 'gpio_req_write': 1,
        'gpio_req_wdata': value, 'gpio_req_be': 15,
        'gpio_rsp_valid': 0, 'gpio_rsp_ready': 0,
        'gpio_rsp_rdata': 0, 'gpio_rsp_error': 0,
    }
    access_physical = {
        'psel': 1, 'penable': 1, 'apb_addr': OFFSET,
        'pwrite': 1, 'pwdata': value, 'pready': 1, 'pslverr': 0,
    }
    response_backend = {
        'gpio_req_valid': 0, 'gpio_req_ready': 1,
        'gpio_req_addr': OFFSET, 'gpio_req_write': 1,
        'gpio_req_wdata': value, 'gpio_req_be': 15,
        'gpio_rsp_valid': 1, 'gpio_rsp_ready': 1,
        'gpio_rsp_rdata': 0, 'gpio_rsp_error': 0,
    }
    samples = [
        {'local_tick': 1,
         'pre': _snapshot(value, backend=request_backend),
         'post': _snapshot(value, backend=request_backend)},
        {'local_tick': 2,
         'pre': _snapshot(value, physical=access_physical),
         'post': _snapshot(value, physical={'out': value})},
        {'local_tick': 3,
         'pre': _snapshot(value, backend=response_backend),
         'post': _snapshot(value, backend=response_backend)},
    ]
    return DriverReceipt('result', 'b' * 32, 1, 0, 3, 3,
        payload={'samples': samples,
                 'observations': {'gpio_out': value, 'gpio_dir': 0,
                     'gpio_in_sync': 0, 'interrupt': 0,
                     'gpio_padcfg': '0' * 32},
                 'rdata': 0, 'error': 0})


def _session(reply=None):
    session = GeneratedPulpGpioSession(_artifact(), base_dir=ROOT,
        cache_dir=Path('/tmp/pulp-gpio-dma-provider-test'))
    session.command = Mock(return_value=reply or _receipt())
    return session


def _key():
    return TransactionKey('dma-exec', 'dma-case', 'zipcpu-wbdmac', 0,
                          'dma-memory', 1)


def _context(key=None, *, address=ADDRESS, offset=OFFSET, write=True,
             value=VALUE, be=15):
    key = key or _key()
    return {'source_transaction': asdict(key), 'device_id': 'gpio',
            'window_base': GPIO_BASE, 'window_size': GPIO_SIZE,
            'address': address, 'offset': offset, 'write': write,
            'value': value, 'be': be}


def _access(session, *, key=None, address=ADDRESS, offset=OFFSET,
            write=True, value=VALUE, byte_enable=15, delivery_context=None):
    key = key or _key()
    return session.dma_master_target_access(
        key, address=address, offset=offset, write=write, value=value,
        byte_enable=byte_enable,
        delivery_context=delivery_context or _context(key, address=address,
            offset=offset, write=write, value=value, be=byte_enable))


def test_padout_provider_returns_keyed_apb_and_effect_receipt():
    session = _session()
    key = _key()

    result = _access(session, key=key)

    request = {'address': ADDRESS, 'offset': OFFSET, 'write': True,
               'value': VALUE, 'byte_enable': 15}
    assert result['schema_version'] == 'dma_master_target_access.v1'
    assert result['status'] == 'observed'
    assert result['source_transaction'] == asdict(key)
    assert result['request'] == request
    assert result['response'] == {'rdata': 0, 'error': 0}
    assert result['target_access_id']
    assert result['target_access']['status'] == 'observed'
    assert result['target_access']['source_transaction'] == asdict(key)
    assert result['target_request']['status'] == 'observed'
    assert result['target_request']['source_transaction'] == asdict(key)
    assert result['target_response']['status'] == 'observed'
    assert result['target_response']['source_transaction'] == asdict(key)
    effect = result['target_effect']
    assert effect == {
        'schema_version': 'pulp_gpio_padout_effect.v1',
        'status': 'observed', 'source_transaction': asdict(key),
        'request': request, 'register': 'PADOUT', 'offset': OFFSET,
        'accepted_value': VALUE, 'post_probe_value': VALUE,
        'access_id': result['target_access_id'], 'local_tick': 2,
    }
    assert session.command.call_count == 1
    assert session.command.call_args.args[0] == 'ACCESS_GPIO'
    assert session.command.call_args.args[1] == (0, 1, OFFSET, VALUE, 15)


def test_provider_identity_pins_api_implementation_and_observation_contract():
    identity = dma_route_endpoint_identity_document(_session())

    provider = identity['dma_master_target_provider']
    assert provider['schema_version'] == 'pulp_gpio_dma_target_provider.v1'
    assert provider['api_schema_version'] == 'dma_master_target_access.v1'
    assert provider['implementation_profile'] == 'pulp_gpio_padout_apb3.v1'
    assert provider['observation_contract'] == pulp_gpio_observation_contract()


@pytest.mark.parametrize('mutation,match', [
    ('request_address', 'target request'),
    ('missing_request', 'target request'),
    ('response', 'target response'),
    ('pslverr', 'APB error'),
    ('post_output', 'PADOUT effect'),
])
def test_unproven_apb_or_padout_effect_never_returns_provider_success(
        mutation, match):
    reply = _receipt()
    if mutation == 'request_address':
        reply.payload['samples'][0]['pre']['backend']['gpio_req_addr'] = OFFSET + 4
    elif mutation == 'missing_request':
        reply.payload['samples'][0]['pre']['backend']['gpio_req_valid'] = 0
    elif mutation == 'response':
        reply.payload['samples'][2]['pre']['backend']['gpio_rsp_rdata'] = 1
        reply.payload['samples'][2]['post']['backend']['gpio_rsp_rdata'] = 1
    elif mutation == 'pslverr':
        reply.payload['samples'][1]['pre']['physical']['probe_gpio_pslverr'] = 1
    else:
        reply.payload['samples'][1]['post']['physical']['probe_gpio_out'] = VALUE ^ 1
        reply.payload['samples'][1]['post']['gpio_out'] = VALUE ^ 1
    session = _session(reply)

    with pytest.raises((RuntimeError, ValueError), match=match):
        _access(session)

    assert session.command.call_count == 1
    assert any(event.get('status') == 'uncertain'
               for event in session.gpio_events)
    assert session.gpio_events[-1]['kind'] == 'gpio_dma_target_terminal'
    assert session.gpio_events[-1]['status'] == 'uncertain'


def test_nonzero_apb_error_never_returns_provider_success():
    reply = _receipt()
    reply.payload['error'] = 1
    reply.payload['samples'][2]['pre']['backend']['gpio_rsp_error'] = 1
    reply.payload['samples'][2]['post']['backend']['gpio_rsp_error'] = 1
    session = _session(reply)

    with pytest.raises(RuntimeError, match='APB access error'):
        _access(session)

    assert session.command.call_count == 1
    assert session.gpio_events[-1]['kind'] == 'gpio_dma_target_terminal'
    assert session.gpio_events[-1]['status'] == 'uncertain'


def test_missing_apb_response_witness_is_rejected_after_one_target_call():
    reply = _receipt()
    reply.payload['samples'][2]['pre']['backend']['gpio_rsp_valid'] = 0
    reply.payload['samples'][2]['post']['backend']['gpio_rsp_valid'] = 0
    session = _session(reply)

    with pytest.raises(ValueError, match='target response'):
        _access(session)

    assert session.command.call_count == 1


@pytest.mark.parametrize('kwargs,match', [
    ({'offset': 8, 'address': GPIO_BASE + 8}, 'PADOUT'),
    ({'write': False}, 'write'),
    ({'byte_enable': 1}, 'full-word'),
])
def test_unsupported_target_shape_is_rejected_before_apb(kwargs, match):
    session = _session()

    with pytest.raises(ValueError, match=match):
        _access(session, **kwargs)

    assert session.command.call_count == 0


def test_delivery_context_must_join_exact_transaction_key_before_apb():
    session = _session()
    wrong_key = TransactionKey('other-exec', 'dma-case', 'zipcpu-wbdmac', 0,
                               'dma-memory', 1)

    with pytest.raises(ValueError, match='context'):
        _access(session, delivery_context=_context(wrong_key))

    assert session.command.call_count == 0
