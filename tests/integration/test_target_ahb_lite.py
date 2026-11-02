"""Synthetic AHB-Lite target selection and address/data phase joins.

No Verilator or real RTL is started here.  The events are the same shape the
Runner journals for a routed CPU MMIO access: one acceptance, one delivery,
the target's own pre-edge tick samples and the dependent RAM store.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.integration.target_ahb_lite import (
    SIGNALS, WINDOW_SIZE, ahb_lite_mmio_bank_facts, observe_ahb_lite_mmio_bus,
    target_adapter)

ROOT = Path(__file__).resolve().parents[2]
BASE = 0x40000000
RESULT = 68672
NAMES = {role: 'trace_' + role for role in SIGNALS}


def _artifact():
    profile = load_component_profile(
        ROOT / 'configs/peripherals/caliptra_sha256/component_profile.json')
    runtime_sv = ''.join(f'assign {NAMES[role]} = wire_{role};\n' for role in SIGNALS)
    endpoint = SimpleNamespace(endpoint_id='sha256.bus',
        protocol=('ahb-lite', '1'), function='mmio_slave')
    tuning = SimpleNamespace(document=lambda: dict(endpoint_id='sha256.bus',
        template_id='target.ahb-lite', template_version='1',
        variant_id='full-word-single', max_outstanding=1))
    plan = SimpleNamespace(profile=profile,
        binding=SimpleNamespace(endpoints=[endpoint]),
        request=SimpleNamespace(tuning=SimpleNamespace(records=[tuning])))
    document = {'kind': 'ahb_lite_register_observe',
        'base_protocol_trace': {'schema_version': 'ip_protocol_trace.v1',
            'protocol': 'ahb-lite', 'endpoint_id': 'sha256.bus',
            'signals': dict(NAMES), 'signal_widths': dict(SIGNALS)},
        'storage_observation': None, 'dynamic_physical_inputs': [],
        'bound_physical_inputs': [],
        'runtime_sv_sha256': sha256(runtime_sv.encode()).hexdigest()}
    return SimpleNamespace(plan=plan, runtime_document=document, runtime_sv=runtime_sv)


def _request(*, template='target.ahb-lite', variant='full-word-single',
             base=BASE, size=WINDOW_SIZE):
    row = {'target_instance': 'sha', 'endpoint_id': 'sha256.bus',
           'template': template, 'variant_id': variant, 'base': base, 'size': size}
    return SimpleNamespace(wiring=SimpleNamespace(document={'windows': [row]}), base_dir=ROOT)


def _access(operation, *, register='NAME0', offset=0):
    return dict(schema_version='register_source_access.v1',
        source_component='processor', source_endpoint='processor.data',
        target_component='sha', target_endpoint='sha256.bus', device_id='sha',
        register=register, field='value', register_offset=offset,
        address=BASE + offset, window_base=BASE, window_size=WINDOW_SIZE,
        window_alignment=WINDOW_SIZE, access_alignment=4, width_bytes=4,
        byte_enable_domain='target_word_lanes', allowed_byte_enables=[15],
        operation=operation,
        value_origin=('cpu_transaction_wdata' if operation == 'write'
                      else 'bound_target_rdata'),
        register_origin='bound_target_register_commit', value_mask=0xffffffff)


def _key(sequence):
    return {'execution_id': 'exec', 'testcase_id': 'case',
            'source_component': 'processor', 'source_epoch': 0,
            'channel_id': 'data', 'source_sequence': sequence}


def _pins(*, offset, write, value, read_value, hsel, htrans, hreadyout=1,
          hresp=0, hsize=2, haddr=None):
    backend = {NAMES['haddr']: offset if haddr is None else haddr,
               NAMES['hwdata']: value, NAMES['hsel']: hsel,
               NAMES['hwrite']: int(write), NAMES['hreadyin']: hreadyout,
               NAMES['htrans']: htrans, NAMES['hsize']: hsize,
               NAMES['hresp']: hresp, NAMES['hreadyout']: hreadyout,
               NAMES['hrdata']: read_value}
    return {'backend': backend}


def _access_events(*, event_id, producer, sequence, offset, write, value,
                   read_value, ram_value):
    key = _key(sequence)
    address = BASE + offset
    events = [
        {'event_id': event_id, 'kind': 'mmio_acceptance', 'component': 'processor',
         'source_transaction': key, 'device_id': 'sha', 'address': address,
         'offset': offset, 'write': write, 'byte_enable': 15,
         'write_value': value if write else None, 'producer_event_id': producer},
        {'event_id': event_id + 1, 'kind': 'mmio_delivery', 'component': 'processor',
         'source_transaction': key, 'device_id': 'sha', 'address': address,
         'offset': offset, 'write': write, 'byte_enable': 15,
         'write_value': value if write else None,
         'read_value': read_value if not write else None,
         'producer_event_id': producer},
    ]
    phases = (
        _pins(offset=offset, write=write, value=value, read_value=read_value,
              hsel=0, htrans=0),
        _pins(offset=offset, write=write, value=value, read_value=read_value,
              hsel=1, htrans=2),
        _pins(offset=offset, write=write, value=value, read_value=read_value,
              hsel=0, htrans=0),
        _pins(offset=offset, write=write, value=value, read_value=read_value,
              hsel=0, htrans=0),
    )
    for index, outputs in enumerate(phases):
        events.append({'event_id': event_id + 2 + index,
                       'kind': 'local_tick_sample', 'component': 'sha',
                       'producer_event_id': producer, 'local_tick': index + 1,
                       'phase': 'pre', 'outputs': outputs})
    events.append({'event_id': event_id + 6, 'kind': 'memory_write',
                   'component': 'processor', 'address': RESULT,
                   'value': ram_value, 'byte_enable': 15})
    return events


def _read_events(read_value=0x61327368):
    return _access_events(event_id=1, producer=100, sequence=1, offset=0,
        write=False, value=0, read_value=read_value,
        ram_value=read_value ^ 0x5a5)


def _write_read_events(write_value=0x11223344, read_value=0):
    return (_access_events(event_id=1, producer=100, sequence=1, offset=0,
                           write=True, value=write_value, read_value=0,
                           ram_value=0)
            + _access_events(event_id=8, producer=200, sequence=2, offset=0,
                             write=False, value=0, read_value=read_value,
                             ram_value=read_value))


def _declaration(operation, *, value=0):
    access = _access(operation)
    return {'candidate': {'access': access, 'value': value},
            'xor_constant': 0x5a5, 'result_address': RESULT}


def _observe(events, *, flow='F2', operation='read', value=0, artifact=None):
    return observe_ahb_lite_mmio_bus(_declaration(operation, value=value),
        SimpleNamespace(events=events),
        target_artifact=artifact or _artifact(), flow=flow)


def test_target_adapter_selects_generated_ahb_session_and_bank():
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    protocol, session, bank, observer = target_adapter(_artifact(), _access('read'), _request())
    assert protocol == 'ahb-lite' and session is GeneratedAhbLiteRegisterSession
    assert observer is observe_ahb_lite_mmio_bus
    facts = bank.document()
    assert facts['protocol'] == ['ahb-lite', '1']
    assert facts['template'] == ['target.ahb-lite', '1', 'full-word-single']
    assert facts['window_size'] == facts['alignment'] == 4096
    assert facts['internal_storage_version'] == 'unknown'
    assert facts['cross_case_origin'] == 'unknown' and facts['reward_eligible'] is False
    assert [row['name'] for row in facts['registers']][:2] == ['NAME0', 'NAME1']
    assert ahb_lite_mmio_bank_facts(_artifact(), endpoint_id='sha256.bus').document() == facts


def test_target_adapter_refuses_wrong_template_window_or_kind():
    with pytest.raises(ValueError, match='template-mismatch'):
        target_adapter(_artifact(), _access('read'),
                       _request(variant='full-word'))
    with pytest.raises(ValueError, match='window-mismatch'):
        target_adapter(_artifact(), _access('read'), _request(size=2048))
    damaged = deepcopy(_artifact().runtime_document)
    damaged['kind'] = 'apb3_register_observe'
    artifact = SimpleNamespace(plan=_artifact().plan, runtime_document=damaged,
                               runtime_sv=_artifact().runtime_sv)
    with pytest.raises(ValueError, match='actual-static-AHB-Lite-MMIO-target-required'):
        target_adapter(artifact, _access('read'), _request())
    forged = _artifact()
    forged.runtime_document['base_protocol_trace']['signals']['hresp'] = 'forged_hresp'
    with pytest.raises(ValueError, match='trace-wiring-mismatch'):
        target_adapter(forged, _access('read'), _request())
    missing = _artifact()
    missing.runtime_document['base_protocol_trace']['signals'].pop('hresp')
    with pytest.raises(ValueError, match='actual-static-AHB-Lite-MMIO-target-required'):
        target_adapter(missing, _access('read'), _request())


def test_f2_read_joins_address_and_data_phase_to_dependent_ram():
    result = _observe(_read_events())
    assert result['read_value'] == 0x61327368
    assert result['result_value'] == 0x61327368 ^ 0x5a5
    assert result['RAM_event'] == 7
    assert len(result['joins']) == 1
    join = result['joins'][0]
    assert join['native_ahb_request_event'] == 4
    assert join['native_ahb_response_event'] == 5
    assert join['acceptance_event'] == 1 and join['delivery_event'] == 2
    assert join['write'] is False and join['value'] == 0x61327368


def test_f4_write_then_readback_keeps_write_acceptance_before_read():
    result = _observe(_write_read_events(write_value=0x11223344, read_value=0),
                      flow='F4', operation='write', value=0x11223344)
    assert [join['write'] for join in result['joins']] == [True, False]
    assert [join['value'] for join in result['joins']] == [0x11223344, 0]
    assert result['joins'][0]['delivery_event'] < result['joins'][1]['delivery_event']
    assert result['read_value'] == 0 and result['result_value'] == 0
    assert result['RAM_event'] == 14


def test_hresp_error_is_refused():
    events = _read_events()
    events[4]['outputs']['backend'][NAMES['hresp']] = 1
    with pytest.raises(ValueError, match='native-AHB-response-error'):
        _observe(events)


def test_missing_data_phase_sample_is_refused():
    events = [event for event in _read_events() if event['event_id'] != 5]
    with pytest.raises(ValueError, match='native-AHB-samples'):
        _observe(events)


@pytest.mark.parametrize('role,value,message', [
    ('hwrite', 0, 'native-AHB-address-mismatch'),
    ('hsize', 1, 'native-AHB-address-mismatch'),
    ('haddr', 4, 'native-AHB-address-mismatch'),
    ('hwdata', 0xdeadbeef, 'native-AHB-address-mismatch'),
])
def test_address_phase_field_mismatch_is_refused(role, value, message):
    events = _write_read_events(write_value=0x11223344, read_value=0)
    events[3]['outputs']['backend'][NAMES[role]] = value
    with pytest.raises(ValueError, match=message):
        _observe(events, flow='F4', operation='write', value=0x11223344)


def test_read_data_mismatch_and_missing_acceptance_are_refused():
    events = _read_events()
    events[4]['outputs']['backend'][NAMES['hrdata']] ^= 1
    with pytest.raises(ValueError, match='native-AHB-read-data'):
        _observe(events)
    with pytest.raises(ValueError, match='native-AHB-acceptance-join'):
        _observe([event for event in _read_events()
                  if event['kind'] != 'mmio_acceptance'])
