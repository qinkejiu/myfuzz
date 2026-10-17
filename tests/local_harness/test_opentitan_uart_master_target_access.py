"""Pure tests: DMA master UART reads carry a real DMA transaction identity (S4).

No RTL is started here.  ``master_target_access`` is exercised on a session
shell whose measured ``read_register`` is replaced by a synthetic measured
access; the DMA bridge is exercised through its declared module function.
"""
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.scenario.ledger import TransactionKey

UART_BASE = 0x50000000
ADDRESS = UART_BASE + 0x18
WINDOW = dict(source_transaction=None, device_id='uart', address=ADDRESS,
    offset=0x18, write=False, value=0, be=15, window_base=UART_BASE,
    window_size=0x1000)


def _session(*, access_factory=None):
    session = object.__new__(GeneratedOpentitanUartSession)
    session._artifact_document = {'plan': {'instance_id': 'uart'},
        'uart_fifo_observation_contract': {}}
    session._source_provenance = True
    session._started = True
    session._routed_uart_transaction = None
    session._routed_uart_context = None
    session._last_uart_access = None

    def read_register(offset):
        context = session._routed_uart_context
        transaction = session._routed_uart_transaction
        session._last_uart_access = (access_factory(context, transaction)
            if access_factory else dict(
                kind='uart_rdata_access', schema_version='uart_rdata_access.v1',
                component='uart', reset_epoch=0, source_epoch=0,
                command_scope={'component': 'uart', 'reset_epoch': 0,
                               'command_sequence': 3},
                local_tick=77, read_value=0x5A, error=0, status='observed',
                access_id='uart-access:uart:0:9', raw_offset=offset,
                source_transaction=transaction,
                route_context_mode=context['route_context_mode'],
                address=context['address'],
                window_base=context['window_base'],
                window_size=context['window_size'],
                delivery_context=context['delivery_context'],
                request_tick=71, response_tick=76,
                read_capture={'pre': {}, 'post': {}},
                response_capture={'pre': {}, 'post': {}}))
        return 0x5A

    session.read_register = read_register
    return session


def _key(**overrides):
    values = dict(execution_id='b' * 32, testcase_id='case-A',
        source_component='dma', source_epoch=0, channel_id='dma-memory',
        source_sequence=4)
    values.update(overrides)
    return TransactionKey(**values)


def _context(**overrides):
    key = _key()
    values = dict(WINDOW, source_transaction={k: getattr(key, k) for k in
        ('execution_id', 'testcase_id', 'source_component', 'source_epoch',
         'channel_id', 'source_sequence')})
    values.update(overrides)
    return values


def test_master_target_access_records_the_dma_master_route():
    session = _session()
    reply = session.master_target_access(_key(), address=ADDRESS, offset=0x18,
        write=False, value=0, be=15, delivery_context=_context())
    assert reply['rdata'] == 0x5A
    observed = reply['target_uart_access']
    assert observed['kind'] == 'uart_rdata_access'
    assert observed['status'] == 'observed'
    assert observed['route_context_mode'] == 'dma_master'
    assert observed['source_transaction']['channel_id'] == 'dma-memory'
    assert observed['source_transaction']['source_component'] == 'dma'
    assert observed['window_base'] == UART_BASE
    assert observed['window_size'] == 0x1000
    assert reply['target_access_id'] == observed['access_id']
    # The routed context is cleared after the measured access.
    assert session._routed_uart_transaction is None
    assert session._routed_uart_context is None


@pytest.mark.parametrize('kwargs', [
    dict(be=1),
    dict(be=4),
    dict(write=True),
    dict(value=1),
    dict(offset=0x14),
    dict(address=UART_BASE + 0x1C)])
def test_master_target_access_refuses_a_non_rdata_or_wrong_strobe(kwargs):
    session = _session()
    call = dict(address=ADDRESS, offset=0x18, write=False, value=0, be=15,
                delivery_context=_context())
    call.update(kwargs)
    with pytest.raises(ValueError):
        session.master_target_access(_key(), **call)
    assert session._routed_uart_transaction is None


@pytest.mark.parametrize('key_overrides', [
    dict(channel_id='data'),
    dict(source_sequence=0),
    dict(execution_id='')])
def test_master_target_access_refuses_a_non_dma_master_transaction(key_overrides):
    session = _session()
    with pytest.raises(ValueError, match='transaction identity'):
        session.master_target_access(_key(**key_overrides), address=ADDRESS,
            offset=0x18, write=False, value=0, be=15,
            delivery_context=_context())
    assert session._routed_uart_transaction is None


@pytest.mark.parametrize('context_change', [
    dict(offset=0x14),
    dict(device_id='gpio'),
    dict(be=1),
    dict(write=True),
    dict(value=7)])
def test_master_target_access_refuses_a_wrong_delivery_context(context_change):
    session = _session()
    with pytest.raises(ValueError, match='delivery context|window context'):
        session.master_target_access(_key(), address=ADDRESS, offset=0x18,
            write=False, value=0, be=15,
            delivery_context=_context(**context_change))
    assert session._routed_uart_transaction is None


def test_master_target_access_rejects_an_unobserved_read():
    def unobserved(context, transaction):
        return {'kind': 'uart_rdata_access', 'status': 'incomplete',
                'read_value': 0x5A, 'access_id': 'a',
                'route_context_mode': 'dma_master',
                'source_transaction': transaction}

    session = _session(access_factory=unobserved)
    with pytest.raises(RuntimeError, match='measured access'):
        session.master_target_access(_key(), address=ADDRESS, offset=0x18,
            write=False, value=0, be=15, delivery_context=_context())


class _Endpoint:
    def __init__(self, *, capable=True, provenance=True):
        self.local_ticks = 5
        self.uart_events = []
        self.calls = []
        self.source_provenance_enabled = provenance
        if capable:
            self.master_target_access = self._master

    def identity_document(self):
        return {'component': 'uart'}

    def read_register(self, offset):
        self.uart_events.append(dict(kind='uart_rdata_access', status='observed',
            read_value=0x5A, access_id='uart-access:uart:0:1',
            read_capture={'pre': {'probe_uart_fifo_rvalid': 1,
                'probe_uart_fifo_rdata_re': 1, 'probe_uart_fifo_under_rst': 0}}))
        return 0x5A

    def write_register(self, offset, value, *, be=15):
        pass

    def _master(self, key, **kwargs):
        self.calls.append((key, kwargs))
        self.uart_events.append(dict(kind='uart_rdata_access', status='observed',
            read_value=0x5A, access_id='uart-access:uart:0:2',
            route_context_mode='dma_master'))
        return {'rdata': 0x5A, 'target_uart_access': self.uart_events[-1],
                'target_access_id': 'uart-access:uart:0:2'}


def _window(endpoint):
    return MasterTargetWindow('uart', UART_BASE, 0x1000, endpoint,
        (0x1C,), range(256), readable_offsets=(0x18,))


def test_dma_delivery_uses_the_master_access_capability_when_present():
    endpoint = _Endpoint(capable=True)
    key = _key()
    rdata, receipt = GeneratedWishboneDmaSession._deliver_target(
        object(), key, _window(endpoint), ADDRESS, False, 0)
    assert rdata == 0x5A
    assert len(endpoint.calls) == 1
    _, kwargs = endpoint.calls[0]
    assert kwargs['delivery_context'] == dict(
        source_transaction={k: getattr(key, k) for k in
            ('execution_id', 'testcase_id', 'source_component', 'source_epoch',
             'channel_id', 'source_sequence')},
        device_id='uart', address=ADDRESS, offset=0x18, write=False, value=0,
        be=15, window_base=UART_BASE, window_size=0x1000)
    assert receipt['target_route_context_mode'] == 'dma_master'
    assert receipt['target_access_id'] == 'uart-access:uart:0:2'
    assert receipt['value'] == 0x5A


def test_dma_delivery_keeps_the_legacy_direct_read_for_other_endpoints():
    endpoint = _Endpoint(capable=False)
    rdata, receipt = GeneratedWishboneDmaSession._deliver_target(
        object(), _key(), _window(endpoint), ADDRESS, False, 0)
    assert rdata == 0x5A
    assert receipt['target_route_context_mode'] is None
    assert 'route_context_mode' not in receipt['target_uart_access']
    # A capable endpoint without enabled source provenance keeps the legacy
    # unauthenticated read, preserving the pre-S4 direct fixtures exactly.
    disabled = _Endpoint(capable=True, provenance=False)
    rdata, receipt = GeneratedWishboneDmaSession._deliver_target(
        object(), _key(), _window(disabled), ADDRESS, False, 0)
    assert rdata == 0x5A
    assert disabled.calls == []
    assert receipt['target_route_context_mode'] is None
