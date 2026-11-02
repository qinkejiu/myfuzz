"""Closed Wishbone SETUP storage row: exact bytes/profile, never authority."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.wishbone_storage_source_contract import (
    registered_wishbone_storage_source_contracts,
    select_wishbone_storage_source_contract,
    validate_wishbone_storage_source_contract,
    wishbone_setup_matches,
    wishbone_word_index,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'


@pytest.fixture
def uart():
    return load_component_profile(
        ROOT / 'configs/peripherals/zipcpu_uart_storage/component_profile.json')


def choose(profile, base_dir=ROOT, **selection):
    return select_wishbone_storage_source_contract(
        profile, base_dir=base_dir,
        selection={'contract_id': CONTRACT, 'register': 'SETUP', **selection})


def copy_sources(profile, tmp_path):
    for name in profile.source.files:
        path = tmp_path / profile.source.source_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / profile.source.source_root / name).read_bytes())


def test_exact_wbuart_setup_row_is_documentary(uart):
    import hashlib
    document = choose(uart)
    assert registered_wishbone_storage_source_contracts() == (CONTRACT,)
    assert document['scope'] == 'source_reviewed_wishbone_storage_row'
    assert all(document[key] is False for key in (
        'authority', 'source_authority', 'native_verified', 'hierarchy_verified',
        'reset_authority', 'version_authority'))
    assert document['source']['root'] == 'third_party/soc-zipcpu-wbuart'
    assert document['source']['revision'] == 'git:f43a6b83c3a70fb2ac0696a45c5545b233fb860b'
    assert document['source']['top_module'] == 'wbuart'
    assert document['parameters'] == {'HARDWARE_FLOW_CONTROL_PRESENT': 1,
                                      'INITIAL_SETUP': 25, 'LGFLEN': 4}
    assert hashlib.sha256(
        (ROOT / 'third_party/soc-zipcpu-wbuart/rtl/wbuart.v').read_bytes()
    ).hexdigest() == document['source']['files']['rtl/wbuart.v']
    assert document['register'] == dict(name='SETUP', canonical_offset=0,
        word_index=0, width=32, reset_value=25, read_mask=0x7fffffff,
        write_mask=0x7fffffff)
    assert document['clock'] == dict(port='i_clk', edge='posedge')
    assert document['reset']['port'] == 'i_reset'
    assert document['reset']['polarity'] == 'active_high'
    assert document['reset']['synchronous'] is True
    assert document['decode']['address_units'] == 'word'
    assert document['decode']['mask'] == 0x3 and document['decode']['value'] == 0
    assert document['decode']['canonical_word_index'] == 0
    assert document['storage_expression']['expression'] == '{1\'b0, u_component.u_dut.uart_setup}'
    assert document['writers']['complete_for_registered_source'] is True
    assert document['writers']['autonomous_ctrl_writers'] == []
    assert 'SETUP writes reset RX/TX state' in document['writers']['other_state']
    assert document['storage_scope']['kind'] == 'stable_word_value_only'
    assert 'not claimed' in document['storage_scope']['effect']
    assert set(document['storage_scope']['excluded']) == {
        'FIFO_STATUS', 'RXREG', 'TXREG', 'UART_RX', 'UART_TX', 'UART_RX_INT',
        'UART_TX_INT', 'UART_RXFIFO_INT', 'UART_TXFIFO_INT'}
    assert validate_wishbone_storage_source_contract(
        json.loads(json.dumps(document)), uart, base_dir=ROOT) == document
    assert choose(replace(uart, component_id='another_name')) == document
    mutated = copy.deepcopy(document)
    mutated['writers']['autonomous_ctrl_writers'].append('caller')
    assert choose(uart)['writers']['autonomous_ctrl_writers'] == []


def test_word_index_and_setup_alias(uart):
    document = choose(uart)
    assert [wishbone_word_index(value) for value in (0, 4, 8, 12)] == [0, 1, 2, 3]
    assert wishbone_setup_matches(document, 0) is True
    assert wishbone_setup_matches(document, 4) is False
    assert wishbone_setup_matches(document, 12) is False
    for bad in (True, -4, 16, 2, '0'):
        with pytest.raises(ValueError):
            wishbone_word_index(bad)


@pytest.mark.parametrize('selection', [
    {'contract_id': CONTRACT, 'register': 'FIFO_STATUS'},
    {'contract_id': CONTRACT, 'register': 'RXREG'},
    {'contract_id': CONTRACT, 'register': 'TXREG'},
    {'contract_id': CONTRACT, 'register': 'COUNT'},
    {'contract_id': 'unregistered', 'register': 'SETUP'},
    {'contract_id': CONTRACT, 'register': 'SETUP', 'evidence_ref': 'caller'},
])
def test_only_the_registered_setup_row_is_selectable(uart, selection):
    with pytest.raises(ValueError):
        select_wishbone_storage_source_contract(
            uart, base_dir=ROOT, selection=selection)


@pytest.mark.parametrize('change', [
    {'source_root': 'third_party/soc-zipcpu'},
    {'revision': 'git:' + '0' * 40},
    {'top_module': 'ziptimer'},
    {'files': ('rtl/wbuart.v',)},
    {'include_roots': ('extra',)},
    {'filelist': 'extra.f'},
])
def test_source_identity_drift_refused(uart, change):
    with pytest.raises(ValueError):
        choose(replace(uart, source=replace(uart.source, **change)))


@pytest.mark.parametrize('change', [
    {'parameters': (('HARDWARE_FLOW_CONTROL_PRESENT', '0'),
                    ('INITIAL_SETUP', '25'), ('LGFLEN', '4'))},
    {'parameters': (('HARDWARE_FLOW_CONTROL_PRESENT', '1'),
                    ('INITIAL_SETUP', '24'), ('LGFLEN', '4'))},
    {'parameters': (('HARDWARE_FLOW_CONTROL_PRESENT', '1'),
                    ('INITIAL_SETUP', '25'), ('LGFLEN', '4'), ('EXTRA', '0'))},
    {'frontend': 'other'}, {'defines': (('EXTRA', '1'),)},
    {'warning_policy': 'fatal'},
])
def test_elaboration_drift_refused(uart, change):
    with pytest.raises(ValueError):
        settings = replace(uart.source.elaboration, **change)
        choose(replace(uart, source=replace(uart.source, elaboration=settings)))


@pytest.mark.parametrize('which,change', [
    ('clock', {'port': 'fake_clk'}),
    ('reset', {'port': 'fake_reset'}),
    ('reset', {'polarity': 'active_low'}),
    ('reset', {'synchronous': False}),
    ('reset', {'synchronous': 0}),
    ('reset', {'sequence_after': ('other',)}),
])
def test_clock_reset_drift_refused(uart, which, change):
    if which == 'clock':
        profile = replace(uart, clocks=(replace(uart.clocks[0], **change),))
    else:
        profile = replace(uart, resets=(replace(uart.resets[0], **change),))
    with pytest.raises(ValueError):
        choose(profile)


@pytest.mark.parametrize('change', [
    {'function': 'mmio_master'}, {'protocol': ('wishbone', 'pipelined')},
    {'fields': ()},
])
def test_endpoint_drift_refused(uart, change):
    endpoints = tuple(replace(e, **change) if e.protocol is not None else e
                      for e in uart.endpoints)
    with pytest.raises(ValueError):
        choose(replace(uart, endpoints=endpoints))


@pytest.mark.parametrize('key,value', [
    ('data_width', 16), ('has_address_port', False), ('address_units', 'byte'),
    ('byte_enable', False), ('partial_write', False), ('has_error', True),
    ('wishbone_flavour', 'pipelined'), ('ack_requires_cyc', False),
])
def test_capability_drift_refused(uart, key, value):
    with pytest.raises(ValueError):
        choose(replace(uart, capabilities={**uart.capabilities, key: value}))


@pytest.mark.parametrize('change', [
    {'window_size': 4}, {'window_size': 8}, {'alignment': 8},
    {'window_size': True},
])
def test_window_drift_refused(uart, change):
    with pytest.raises(ValueError):
        choose(replace(uart, address=replace(uart.address, **change)))


@pytest.mark.parametrize('change', [
    {'offset': 4}, {'offset': False}, {'width': 16}, {'access': 'ro'},
    {'side_effect': 'none'}, {'side_effect': 'read_pops_rx_fifo'},
    {'reset_value': 0}, {'reset_value': False}, {'writable_bits': 1},
    {'clears_register': 'SETUP'},
])
def test_setup_register_fact_drift_refused(uart, change):
    rows = tuple(replace(row, **change) if row.name == 'SETUP' else row
                 for row in uart.address.registers)
    with pytest.raises(ValueError):
        choose(replace(uart, address=replace(uart.address, registers=rows)))


@pytest.mark.parametrize('mutate', [
    lambda d: d.update(authority=True),
    lambda d: d['register'].update(reset_value=False),
    lambda d: d['decode'].update(value=1),
    lambda d: d['decode'].update(mask=0xff),
    lambda d: d['storage_expression'].update(expression='uart_setup'),
    lambda d: d['storage_scope'].update(kind='uart_effect'),
    lambda d: d['source']['files'].update({'extra.sv': '0' * 64}),
    lambda d: d.update(digest='0' * 64),
])
def test_document_tampering_refused(uart, mutate):
    document = choose(uart)
    mutate(document)
    with pytest.raises(ValueError):
        validate_wishbone_storage_source_contract(document, uart, base_dir=ROOT)
    with pytest.raises(ValueError):
        wishbone_setup_matches(document, 0)


@pytest.mark.parametrize('relative', (
    'rtl/wbuart.v', 'rtl/ufifo.v', 'rtl/rxuart.v', 'rtl/txuart.v'))
def test_every_closure_byte_is_rechecked(uart, tmp_path, relative):
    copy_sources(uart, tmp_path)
    document = choose(uart, base_dir=tmp_path)
    path = tmp_path / uart.source.source_root / relative
    path.write_bytes(path.read_bytes() + b'\n// drift\n')
    with pytest.raises(ValueError, match='reviewed-source-bytes-changed'):
        choose(uart, base_dir=tmp_path)
    with pytest.raises(ValueError, match='reviewed-source-bytes-changed'):
        validate_wishbone_storage_source_contract(document, uart, base_dir=tmp_path)


def test_source_symlink_refused(uart, tmp_path):
    copy_sources(uart, tmp_path)
    choose(uart, base_dir=tmp_path)
    path = tmp_path / uart.source.source_root / 'rtl/wbuart.v'
    path.unlink()
    path.symlink_to(ROOT / uart.source.source_root / 'rtl/wbuart.v')
    with pytest.raises(ValueError, match='source-symlink'):
        choose(uart, base_dir=tmp_path)
