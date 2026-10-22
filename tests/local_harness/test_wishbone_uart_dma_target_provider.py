"""Bounded ZipCPU wbuart TXREG DMA provider contract tests."""

from collections import deque
from copy import deepcopy
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.wishbone_uart_session import (
    GeneratedWishboneUartSession,
)
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.uart_peer import Uart8N1Peer


BASE = 0x40001000
OFFSET = 12
ADDRESS = BASE + OFFSET
VALUE = 0x41
BUS_WIDTHS = {
    'cyc': 1, 'stb': 1, 'we': 1, 'adr': 2,
    'dat_w': 32, 'sel': 4, 'ack': 1,
}
TRACE_ROLE_NAMES = {role: 'trace_' + role for role in BUS_WIDTHS}


def _key(**changes):
    values = dict(execution_id='dma-exec', testcase_id='case-1',
        source_component='dma', source_epoch=0, channel_id='write_master',
        source_sequence=4)
    values.update(changes)
    return TransactionKey(**values)


def _exports():
    return [{
        'endpoint_id': 'uart.pins', 'role': 'tx',
        'runtime_name': 'uart_tx_pin', 'physical_port': 'o_uart_tx',
        'direction': 'output', 'width': 1, 'disposition': 'external',
    }]


def _trace():
    return {
        'schema_version': 'ip_protocol_trace.v1',
        'protocol': 'wishbone',
        'endpoint_id': 'uart.bus',
        'signals': dict(TRACE_ROLE_NAMES),
        'signal_widths': dict(BUS_WIDTHS),
    }
    return rows


def _backend(**overrides):
    values = dict(cyc=0, stb=0, we=0, adr=0, dat_w=0, sel=0, ack=0)
    values.update(overrides)
    return {TRACE_ROLE_NAMES[role]: value for role, value in values.items()}


def _phase(**pins):
    backend = _backend(**pins)
    physical = {'uart_tx_pin': 1}
    return {
        'pre': {'physical': deepcopy(physical),
                'backend': {**deepcopy(backend), 'uart_target_stb': pins.get('stb', 0)}},
        'post': {'physical': deepcopy(physical),
                 'backend': {**deepcopy(backend), 'uart_target_stb': pins.get('stb', 0)},
                 'uart_tx': 1},
    }


def _native_phases(value=VALUE):
    return (
        _phase(cyc=1, stb=1, we=1, adr=3, dat_w=value, sel=15, ack=0),
        _phase(cyc=1, stb=0, we=1, adr=3, dat_w=value, sel=15, ack=0),
        _phase(cyc=1, stb=0, we=1, adr=3, dat_w=value, sel=15, ack=1),
    )


def _serial_wave(byte, *, frames=1):
    bits = []
    for frame in range(frames):
        bits.extend([0] * 25)
        bits.extend([((byte >> bit) & 1) for bit in range(8) for _ in range(25)])
        bits.extend([1] * 25)
    bits.extend([1] * 800)
    return deque(bits)


def _session(*, phases=None, response_error=0, serial_byte=VALUE,
             serial_frames=1, startup_writes=((0, 25, 15),), started=True):
    document = {
        'kind': 'wishbone_uart',
        'artifact_digest': 'a' * 64,
        'plan': {'instance_id': 'uart0'},
        'physical_exports': _exports(),
        'base_protocol_trace': _trace(),
    }
    profile = SimpleNamespace(
        address=SimpleNamespace(window_size=16),
        capabilities={
            'address_width': 2, 'data_width': 32, 'byte_enable': True,
            'partial_write': True, 'has_error': False,
            'has_address_port': True, 'address_units': 'word',
            'sel_implemented': True, 'wishbone_flavour': 'registered-ack',
            'ack_requires_cyc': True, 'max_outstanding': 1,
        },
    )
    session = GeneratedWishboneUartSession.__new__(GeneratedWishboneUartSession)
    session.artifact = SimpleNamespace(
        runtime_document=document,
        plan=SimpleNamespace(
            request=SimpleNamespace(instance_id='uart0'), profile=profile))
    session._artifact_document = deepcopy(document)
    session._execution = 'uart-exec'
    session._sequence = 0
    session._case_id = 'case-1'
    session.reset_epoch = 0
    session.local_ticks = 1
    session._tick_base = 0
    session._samples = deque()
    session._outputs = {}
    session._started = started
    session.startup_writes = startup_writes
    session.local_transactions = (
        [{'offset': 0, 'write_value': 25, 'byte_enable': 15}]
        if started and startup_writes == ((0, 25, 15),) else [])
    session.peer = Uart8N1Peer(b'', clocks_per_bit=25)
    session.source = b''
    session.source_mode = 'constructor'
    session.read_rx_after_source = False
    session.cpu_routed_mode = False
    session._rx_read = False
    session._rx_word = 0
    session._dma_target_events = []
    session._dma_target_poisoned = False
    session.max_local_ticks_per_register_access = 12
    session.command_calls = []
    session._test_phases = tuple(phases if phases is not None else _native_phases())
    session._test_response_error = response_error
    session._test_serial_wave = _serial_wave(serial_byte, frames=serial_frames)

    def command(operation, fields):
        session.command_calls.append((operation, fields))
        session._sequence += 1
        if operation == 'ACCESS_WB_UART':
            sample_rows = session._test_phases
            error = session._test_response_error
        elif operation == 'STEP_WB_UART':
            line = session._test_serial_wave.popleft() if session._test_serial_wave else 1
            backend = _backend()
            physical = {'uart_tx_pin': 1}
            sample_rows = ({
                'pre': {'physical': deepcopy(physical),
                        'backend': {**deepcopy(backend), 'uart_target_stb': 0}},
                'post': {'physical': {**physical, 'uart_tx_pin': line},
                         'backend': {**deepcopy(backend), 'uart_target_stb': 0},
                         'uart_tx': line},
            },)
            error = 0
        else:
            raise AssertionError('unexpected UART command: ' + operation)
        samples = []
        for row in sample_rows:
            tick = session.local_ticks + len(samples) + 1
            sample = {'local_tick': tick, **deepcopy(row)}
            samples.append(sample)
        session.local_ticks += len(samples)
        return DriverReceipt('result', session._execution, session._sequence,
            session.local_ticks - len(samples), session.local_ticks,
            len(samples), payload={
                'samples': samples, 'rdata': 0, 'error': error,
                'observations': {}, 'pre_backend': {},
            })

    session.command = command

    return session


def _context(key=None, **changes):
    transaction = key or _key()
    context = {
        'source_transaction': asdict(transaction), 'device_id': 'uart0',
        'address': ADDRESS, 'offset': OFFSET, 'write': True,
        'value': VALUE, 'be': 15, 'window_base': BASE, 'window_size': 16,
    }
    context.update(changes)
    return context


def _call(session, *, key=None, address=ADDRESS, offset=OFFSET, write=True,
          value=VALUE, byte_enable=15, delivery_context=None):
    transaction = key or _key()
    context_key = transaction if type(transaction) is TransactionKey else _key()
    return session.dma_master_target_access(
        transaction, address=address, offset=offset, write=write, value=value,
        byte_enable=byte_enable,
        delivery_context=delivery_context or _context(context_key))


def test_provider_identity_pins_artifact_instance_bus_txreg_and_serial_profile():
    session = _session()

    identity = session.dma_master_target_provider_identity_document()

    assert identity == {
        'schema_version': 'zipcpu_uart_dma_target_provider.v1',
        'api_schema_version': 'dma_master_target_access.v1',
        'implementation_profile': 'zipcpu_wbuart_txreg_wishbone_serial.v1',
        'artifact_digest': 'a' * 64,
        'instance_id': 'uart0',
        'endpoint_id': 'uart.bus',
        'txreg': {
            'operation': 'write', 'offset': 12,
            'accepted_write_values': {
                'kind': 'range', 'start': 0, 'stop': 256, 'step': 1,
            },
            'byte_enable': 15,
        },
        'startup_writes': [[0, 25, 15]],
        'serial': {
            'endpoint_id': 'uart.pins', 'role': 'tx', 'format': '8N1',
            'clocks_per_bit': 25, 'runtime_name': 'uart_tx_pin',
        },
        'wishbone_signals': {
            role: TRACE_ROLE_NAMES[role] for role in BUS_WIDTHS
        },
    }


def test_provider_joins_dma_key_native_wishbone_request_ack_and_one_tx_byte():
    session = _session()
    key = _key()

    receipt = _call(session, key=key)

    assert receipt['schema_version'] == 'dma_master_target_access.v1'
    assert receipt['status'] == 'observed'
    assert receipt['source_transaction'] == asdict(key)
    assert receipt['request'] == {
        'address': ADDRESS, 'offset': OFFSET, 'write': True,
        'value': VALUE, 'byte_enable': 15,
    }
    assert receipt['response'] == {'rdata': 0, 'error': 0}
    assert receipt['target_request']['status'] == 'observed'
    assert receipt['target_request']['source_transaction'] == asdict(key)
    assert receipt['target_request']['backend'] == {
        'cyc': 1, 'stb': 1, 'we': 1, 'adr': 3,
        'dat_w': VALUE, 'sel': 15, 'ack': 0,
    }
    assert receipt['target_response']['status'] == 'observed'
    assert receipt['target_response']['source_transaction'] == asdict(key)
    assert receipt['target_response']['backend']['ack'] == 1
    assert receipt['target_effect']['status'] == 'observed'
    assert receipt['target_effect']['source_transaction'] == asdict(key)
    assert receipt['target_effect']['request'] == receipt['request']
    assert receipt['target_effect']['serial_byte'] == VALUE
    assert receipt['target_effect']['clocks_per_bit'] == 25
    assert (receipt['target_effect']['serial_start_tick']
            < receipt['target_effect']['serial_end_tick'])
    assert receipt['target_effect']['serial_format'] == '8N1'
    access_id = receipt['target_access_id']
    assert all(receipt[name]['access_id'] == access_id for name in (
        'target_access', 'target_request', 'target_response', 'target_effect'))
    assert len(session.peer.captured) == 1
    assert session.peer.captured == [VALUE]
    assert len([row for row in session.command_calls
                if row[0] == 'ACCESS_WB_UART']) == 1
    assert len([row for row in session.command_calls
                if row[0] == 'STEP_WB_UART']) >= 250


@pytest.mark.parametrize('changes', [
    {'value': 0x100}, {'value': 0xffffffff},
    {'offset': 8, 'address': BASE + 8},
    {'write': False}, {'byte_enable': 1},
    {'address': ADDRESS + 4},
])
def test_provider_refuses_unsupported_request_before_issuing_native_command(changes):
    session = _session()

    with pytest.raises(ValueError):
        _call(session, **changes)

    assert session.command_calls == []
    assert session._dma_target_poisoned is False
    assert session._dma_target_events == []


@pytest.mark.parametrize('kwargs', [
    {'key': 'not-a-transaction-key'},
    {'delivery_context': {'source_transaction': {}, 'device_id': 'other'}},
    {'delivery_context': _context(value=0x42)},
    {'delivery_context': _context(window_size=32)},
])
def test_provider_refuses_invalid_transaction_or_context_before_command(kwargs):
    session = _session()

    with pytest.raises(ValueError):
        _call(session, **kwargs)

    assert session.command_calls == []
    assert session._dma_target_poisoned is False


def test_provider_requires_startup_setup_to_have_completed():
    session = _session(started=False)

    with pytest.raises(ValueError, match='initialized'):
        _call(session)

    assert session.command_calls == []


def _remove_startup_setup(session):
    session.startup_writes = ()


def _change_uart_clock(session):
    session.peer.clocks_per_bit = 24


@pytest.mark.parametrize('mutate', [_remove_startup_setup, _change_uart_clock])
def test_provider_identity_refuses_changed_setup_or_serial_clock(mutate):
    session = _session()
    mutate(session)

    with pytest.raises(ValueError):
        session.dma_master_target_provider_identity_document()


@pytest.mark.parametrize('mutate', [
    lambda trace: trace['signals'].pop('cyc'),
    lambda trace: trace['signals'].__setitem__('cyc', trace['signals']['ack']),
])
def test_provider_identity_rejects_ambiguous_or_incomplete_native_trace(mutate):
    session = _session()
    mutate(session._artifact_document['base_protocol_trace'])
    session.artifact.runtime_document = deepcopy(session._artifact_document)

    with pytest.raises(ValueError, match='invalid|ambiguous|reuses'):
        session.dma_master_target_provider_identity_document()


def test_provider_identity_pin_detects_instance_change_after_compilation():
    session = _session()
    session.dma_master_target_provider_identity_document()
    session.artifact.plan.request.instance_id = 'changed-uart'
    session._artifact_document['plan']['instance_id'] = 'changed-uart'
    session.artifact.runtime_document['plan']['instance_id'] = 'changed-uart'

    with pytest.raises(ValueError, match='identity changed'):
        session.dma_master_target_provider_identity_document()


def test_ordinary_register_write_keeps_its_existing_byte_enable_semantics():
    session = _session()

    session.write_register(12, VALUE, be=1)

    assert session.command_calls == [
        ('ACCESS_WB_UART', (1, 0, 1, 12, VALUE, 1))]
    assert session._dma_target_events == []
    with pytest.raises(ValueError, match='unsupported UART'):
        session.write_register(12, VALUE, be=15)


@pytest.mark.parametrize('phases,error', [
    ((_phase(cyc=1, stb=0, we=1, adr=3, dat_w=VALUE, sel=15, ack=1),), 0),
    (_native_phases() + (_phase(cyc=1, stb=1, we=1, adr=3, dat_w=VALUE, sel=15),), 0),
    ((_phase(cyc=1, stb=1, we=1, adr=2, dat_w=VALUE, sel=15),
      _phase(cyc=1, stb=0, we=1, adr=2, dat_w=VALUE, sel=15, ack=1)), 0),
    ((_phase(cyc=1, stb=1, we=1, adr=3, dat_w=VALUE + 1, sel=15),
      _phase(cyc=1, stb=0, we=1, adr=3, dat_w=VALUE + 1, sel=15, ack=1)), 0),
    ((_native_phases()[0], _native_phases()[1]), 0),
    ((_native_phases()[0], _native_phases()[2], _native_phases()[2]), 0),
    (_native_phases(), 1),
])
def test_post_command_native_uncertainty_poisons_and_records_terminal(phases, error):
    session = _session(phases=phases, response_error=error)

    with pytest.raises((RuntimeError, ValueError)):
        _call(session)

    assert len([row for row in session.command_calls if row[0] == 'ACCESS_WB_UART']) == 1
    assert session._dma_target_poisoned is True
    assert session._dma_target_events[-1]['status'] == 'uncertain'
    assert session._dma_target_events[-1]['source_transaction'] == asdict(_key())
    with pytest.raises(ValueError, match='poisoned'):
        _call(session, key=_key(source_sequence=5))
    assert len([row for row in session.command_calls if row[0] == 'ACCESS_WB_UART']) == 1


@pytest.mark.parametrize('serial_byte,serial_frames', [
    (0x42, 1), (VALUE, 2), (VALUE, 0),
])
def test_missing_matching_or_unique_serial_frame_poisons_provider(serial_byte, serial_frames):
    session = _session(serial_byte=serial_byte, serial_frames=serial_frames)

    with pytest.raises((RuntimeError, ValueError)):
        _call(session)

    assert session._dma_target_poisoned is True
    assert session._dma_target_events[-1]['status'] == 'uncertain'
