"""The CPU route admits only the UART WDATA low byte strobe."""

from dataclasses import asdict

import pytest

from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
from myfuzz.scenario.ledger import TransactionKey


def _bare_session():
    session = object.__new__(GeneratedOpentitanUartSession)
    session._artifact_document = {'plan': {'instance_id': 'uart'},
                                  'uart_fifo_observation_contract': {}}
    session._routed_uart_transaction = None
    session._routed_uart_context = None
    return session


def test_wdata_accepts_lane_zero_byte_write_only():
    session = _bare_session()
    writes = []
    session._access = lambda write, offset, value, be: writes.append(
        (write, offset, value, be))
    session.write_register(0x1c, 0xa6, be=1)
    assert writes == [(True, 0x1c, 0xa6, 1)]
    for be in (0, 2, 4, 8, 3):
        with pytest.raises(ValueError, match='unsupported UART register write'):
            session.write_register(0x1c, 0xa6, be=be)


def test_cpu_route_preserves_wdata_byte_enable_and_rejects_other_byte_writes():
    session = _bare_session()
    writes = []
    session.write_register = lambda offset, value, *, be: writes.append(
        (offset, value, be))
    key = TransactionKey('run', 'case', 'cpu', 0, 'data', 1)

    def route(offset, be):
        address = 0x40000000 + offset
        context = {'source_transaction': asdict(key), 'device_id': 'uart',
                   'address': address, 'offset': offset, 'write': True,
                   'value': 0xa6, 'be': be, 'window_base': 0x40000000,
                   'window_size': 0x1000}
        return session.routed_register_access(
            key, address=address, offset=offset, write=True,
            value=0xa6, be=be, delivery_context=context)

    assert route(0x1c, 1) == {'rdata': 0}
    assert writes == [(0x1c, 0xa6, 1)]
    for offset, be in ((0x1c, 2), (0x1c, 3), (0x10, 1)):
        with pytest.raises(ValueError, match='invalid routed UART register shape'):
            route(offset, be)
