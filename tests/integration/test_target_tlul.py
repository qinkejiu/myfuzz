"""Synthetic TL-UL target selection and native A/D handshake joins.

No Verilator or real RTL is started here.  The artifact is the real generated
planning/rendering output for the pinned OpenTitan GPIO profile; the receipt
events are synthetic because the real pre-edge samples come from the remote
execution the main agent owns.
"""
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration.target_tlul import (
    TEMPLATE, observe_tlul_mmio_bus, target_adapter, tlul_mmio_bank_facts)
from myfuzz.local_harness.tlul_register_session import (
    GeneratedTlulRegisterSession)
from myfuzz.scenario.ip_protocol_checker import _REQUIRED_SIGNALS

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_gpio_local/component_profile.json'
ENDPOINT = 'opentitan_gpio.mmio'
INSTANCE = 'peripheral'
BASE = 0x40000000
OFFSET = 4
SIGNALS = tuple(_REQUIRED_SIGNALS['tl-ul'])
NAMES = {role: 'trace_' + role for role in SIGNALS}
ACCESS = {'schema_version': 'register_source_access.v1',
          'source_component': 'processor', 'source_endpoint': 'processor.data',
          'target_component': INSTANCE, 'target_endpoint': ENDPOINT,
          'device_id': INSTANCE, 'register': 'INTR_ENABLE', 'field': 'value',
          'register_offset': OFFSET, 'address': BASE + OFFSET,
          'window_base': BASE, 'window_size': 128, 'window_alignment': 128,
          'access_alignment': 4, 'width_bytes': 4,
          'byte_enable_domain': 'target_word_lanes',
          'allowed_byte_enables': [15], 'operation': 'read',
          'value_origin': 'bound_target_rdata',
          'register_origin': 'bound_target_register_commit',
          'value_mask': 0xffffffff}


@pytest.fixture(scope='module')
def artifact():
    from myfuzz.local_harness import (
        load_local_harness_request, plan_local_harness, render_local_driver,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id=INSTANCE, reset_assert_ticks=2, reset_release_ticks=3,
        max_wait_cycles=16, tuning={
            'endpoint_policies': [dict(
                endpoint_id=ENDPOINT, template_id='target.tl-ul',
                template_version='1', variant_id='user-integrity',
                max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='gpio.pins', role='in', value=0),
                             dict(endpoint_id='gpio.pins', role='strap_en',
                                  value=0)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT),
        base_dir=ROOT), base_dir=ROOT)


def _request(*, template='target.tl-ul', variant='user-integrity',
             endpoint=ENDPOINT, base=BASE, size=128):
    return SimpleNamespace(wiring=SimpleNamespace(document={'windows': [dict(
        target_instance=INSTANCE, endpoint_id=endpoint, template=template,
        variant_id=variant, base=base, size=size)]}), base_dir=ROOT)


def _access(operation, *, register='INTR_ENABLE', offset=OFFSET):
    return dict(ACCESS, operation=operation, register=register,
                register_offset=offset, address=BASE + offset)


def _key(sequence):
    return {'execution_id': 'exec', 'testcase_id': 'case',
            'source_component': 'processor', 'source_epoch': 0,
            'channel_id': 'data', 'source_sequence': sequence}


def _sample(event_id, producer, *, tick, **pins):
    backend = {name: 0 for name in NAMES.values()}
    backend.update({NAMES[role]: value for role, value in pins.items()})
    return dict(event_id=event_id, kind='local_tick_sample',
                component=INSTANCE, producer_event_id=producer,
                local_tick=tick, phase='pre', outputs={'backend': backend})


def _write_events(value, *, producer=10, event_id=1, result_address=0x10c00):
    key = _key(1)
    address = BASE + OFFSET
    return [
        dict(event_id=event_id, kind='mmio_acceptance', component='processor',
             source_transaction=key, device_id=INSTANCE, address=address,
             offset=OFFSET, write=True, byte_enable=15,
             write_value=value, producer_event_id=producer),
        dict(event_id=event_id + 1, kind='mmio_delivery', component='processor',
             source_transaction=key, device_id=INSTANCE, address=address,
             register_offset=OFFSET, offset=OFFSET, write=True,
             byte_enable=15, write_value=value, read_value=None,
             producer_event_id=producer),
        _sample(event_id + 2, producer, tick=event_id + 2,
                a_valid=1, a_ready=1, a_opcode=0, a_size=2,
                a_address=OFFSET, a_mask=15, a_data=value, a_source=0),
        _sample(event_id + 3, producer, tick=event_id + 3,
                d_valid=1, d_ready=1, d_opcode=0, d_size=2,
                d_source=0, d_error=0, d_data=0xffffffff),
        dict(event_id=event_id + 4, kind='memory_write', component='processor',
             address=result_address, value=0, byte_enable=15),
    ]


def _read_events(read_value, *, producer=20, event_id=1, flow='F2',
                 result_address=0x10c00):
    key = _key(2)
    address = BASE + OFFSET
    result = read_value ^ (0x5a5 if flow == 'F2' else 0)
    return [
        dict(event_id=event_id, kind='mmio_acceptance', component='processor',
             source_transaction=key, device_id=INSTANCE, address=address,
             offset=OFFSET, write=False, byte_enable=15,
             write_value=None, producer_event_id=producer),
        dict(event_id=event_id + 1, kind='mmio_delivery', component='processor',
             source_transaction=key, device_id=INSTANCE, address=address,
             register_offset=OFFSET, offset=OFFSET, write=False,
             byte_enable=15, write_value=None, read_value=read_value,
             producer_event_id=producer),
        _sample(event_id + 2, producer, tick=event_id + 2,
                a_valid=1, a_ready=1, a_opcode=4, a_size=2,
                a_address=OFFSET, a_mask=15, a_data=0, a_source=0),
        _sample(event_id + 3, producer, tick=event_id + 3,
                d_valid=1, d_ready=1, d_opcode=1, d_size=2,
                d_source=0, d_error=0, d_data=read_value),
        dict(event_id=event_id + 4, kind='memory_write', component='processor',
             address=result_address, value=result, byte_enable=15),
    ]


def _declaration(operation='read', *, value=0, result_address=0x10c00):
    return {'candidate': {'access': _access(operation), 'value': value},
            'xor_constant': 0x5a5, 'result_address': result_address}


def _receipt(events):
    return SimpleNamespace(events=events)


def _observe(events, *, artifact, flow='F2', operation='read', value=0):
    return observe_tlul_mmio_bus(_declaration(operation, value=value),
                                 _receipt(events),
                                 target_artifact=artifact, flow=flow)


def test_target_adapter_selects_generated_tlul_session_and_bank(artifact):
    protocol, session, bank, observer = target_adapter(
        artifact, _access('read'), _request())
    assert protocol == 'tl-ul'
    assert session is GeneratedTlulRegisterSession
    assert observer is observe_tlul_mmio_bus
    document = bank.document()
    assert document['protocol'] == ['tl-ul', '1']
    assert document['template'] == list(TEMPLATE)
    assert document['window_size'] == 128 and document['alignment'] == 128
    assert document['internal_storage_version'] == 'unknown'
    assert document['cross_case_origin'] == 'unknown'
    assert document['reward_eligible'] is False
    assert document['declaration_scope'] == (
        'configured_register_map_not_internal_RTL_storage_proof')
    register = [row for row in document['registers']
                if row['name'] == 'INTR_ENABLE']
    assert len(register) == 1 and register[0]['offset'] == OFFSET
    assert register[0]['access'] == 'rw'
    assert tlul_mmio_bank_facts(
        artifact, endpoint_id=ENDPOINT).document() == document


def test_extension_dispatch_selects_tlul(artifact):
    from myfuzz.integration.compiled_mmio import _target_adapter
    from myfuzz.integration.extension_plugins import target_adapter as plugin
    for dispatch in (plugin, _target_adapter):
        protocol, session, bank, observer = dispatch(
            artifact, _access('read'), _request())
        assert protocol == 'tl-ul'
        assert session is GeneratedTlulRegisterSession
        assert bank.document()['template'] == list(TEMPLATE)
        assert observer is observe_tlul_mmio_bus


@pytest.mark.parametrize('defect,match', [
    ('kind', 'actual-static-TL-UL-MMIO-target-required'),
    ('protocol', 'actual-static-TL-UL-MMIO-target-required'),
    ('signal', 'actual-static-TL-UL-MMIO-target-required'),
    ('width', 'actual-static-TL-UL-MMIO-target-required'),
    ('storage', 'actual-static-TL-UL-MMIO-target-required'),
    ('dynamic', 'actual-static-TL-UL-MMIO-target-required'),
    ('wire', 'trace-wiring-mismatch'),
])
def test_damaged_artifact_is_refused_by_name(artifact, defect, match):
    document = deepcopy(artifact.runtime_document)
    runtime_sv = artifact.runtime_sv
    trace = document['base_protocol_trace']
    if defect == 'kind':
        document['kind'] = 'apb3_register_observe'
    elif defect == 'protocol':
        trace['protocol'] = 'apb3'
    elif defect == 'signal':
        trace['signals'].pop('a_valid')
        trace['signal_widths'].pop('a_valid')
    elif defect == 'width':
        trace['signal_widths']['a_data'] = 16
    elif defect == 'storage':
        document['storage_observation'] = {'forged': True}
    elif defect == 'dynamic':
        document['dynamic_physical_inputs'] = [{'input_name': 'forged'}]
    else:
        runtime_sv = runtime_sv.replace('assign trace_a_valid =',
                                        'assign unrelated =', 1)
        document['runtime_sv_sha256'] = sha256(runtime_sv.encode()).hexdigest()
    with pytest.raises(ValueError, match=match):
        target_adapter(replace(artifact, runtime_document=document,
                               runtime_sv=runtime_sv),
                       _access('read'), _request())


def test_wrong_template_window_or_access_is_refused(artifact):
    with pytest.raises(ValueError, match='template-mismatch'):
        target_adapter(artifact, _access('read'),
                       _request(variant='full-word'))
    with pytest.raises(ValueError, match='window-mismatch'):
        target_adapter(artifact, _access('read'), _request(size=64))
    with pytest.raises(ValueError, match='one-declared-window-required'):
        target_adapter(artifact, _access('read'), SimpleNamespace(
            wiring=SimpleNamespace(document={'windows': []}), base_dir=ROOT))
    with pytest.raises(ValueError, match='target-instance-mismatch'):
        target_adapter(artifact, dict(_access('read'), target_component='other'),
                       _request())
    with pytest.raises(ValueError, match='register-required'):
        target_adapter(artifact, dict(_access('read'), register='NO_SUCH'),
                       _request())
    with pytest.raises(ValueError, match='register-write-access'):
        target_adapter(artifact, _access('write', register='DATA_IN',
                                         offset=16), _request())


def test_f2_read_joins_a_and_d_handshakes_to_dependent_ram(artifact):
    read_value = 0x61327368
    observed = _observe(_read_events(read_value), artifact=artifact)
    assert observed['read_value'] == read_value
    assert observed['result_value'] == read_value ^ 0x5a5
    assert observed['RAM_event'] == 5
    assert len(observed['joins']) == 1
    join = observed['joins'][0]
    assert join['native_tlul_a_event'] == 3
    assert join['native_tlul_d_event'] == 4
    assert join['native_tlul_request_event'] == 3
    assert join['native_tlul_response_event'] == 4
    assert join['native_tlul_a_opcode'] == 4
    assert join['native_tlul_a_address'] == OFFSET
    assert join['native_tlul_a_mask'] == 15
    assert join['native_tlul_d_opcode'] == 1
    assert join['acceptance_event'] == 1 and join['delivery_event'] == 2
    assert join['write'] is False and join['value'] == read_value


def test_f4_write_then_readback_keeps_order_and_values(artifact):
    value, read_value = 0x11223344, 0x00000055
    write = _write_events(value, event_id=1)
    read = _read_events(read_value, event_id=6, flow='F4', producer=20)
    observed = observe_tlul_mmio_bus(
        _declaration('write', value=value), _receipt(write + read),
        target_artifact=artifact, flow='F4')
    assert [join['write'] for join in observed['joins']] == [True, False]
    assert [join['value'] for join in observed['joins']] == [value, read_value]
    assert observed['joins'][0]['delivery_event'] < observed['joins'][1]['delivery_event']
    assert observed['joins'][0]['native_tlul_response_event'] == 4
    assert observed['joins'][1]['native_tlul_request_event'] == 8
    assert observed['read_value'] == read_value
    assert observed['result_value'] == read_value
    assert observed['RAM_event'] == 10


@pytest.mark.parametrize('defect,match', [
    ('d-error', 'response-error'),
    ('no-d', 'completion'),
    ('no-samples', 'samples'),
    ('no-a', 'request'),
    ('write-address', 'write-request'),
    ('write-mask', 'write-request'),
    ('write-data', 'write-request'),
    ('read-address', 'read-request'),
    ('read-mask', 'read-request'),
    ('read-data', 'read-data'),
    ('response-source', 'response-source'),
    ('response-opcode', 'response-opcode'),
    ('response-size', 'response-size'),
    ('no-acceptance', 'acceptance-join'),
    ('no-ram', 'dependent-RAM'),
    ('ram-value', 'dependent-RAM'),
])
def test_native_mismatch_is_refused(artifact, defect, match):
    read_value = 0x55667788
    flow, operation, value = 'F2', 'read', 0
    events = _read_events(read_value)
    if defect == 'd-error':
        events[3]['outputs']['backend'][NAMES['d_error']] = 1
    elif defect == 'no-d':
        events = [event for event in events if event['event_id'] != 4]
    elif defect == 'no-samples':
        events = [event for event in events
                  if event['kind'] != 'local_tick_sample']
    elif defect == 'no-a':
        events = [event for event in events if event['event_id'] != 3]
    elif defect == 'write-address':
        events = _write_events(0x12345678)
        events[2]['outputs']['backend'][NAMES['a_address']] = 0
        flow, operation, value = 'F4', 'write', 0x12345678
    elif defect == 'write-mask':
        events = _write_events(0x12345678)
        events[2]['outputs']['backend'][NAMES['a_mask']] = 3
        flow, operation, value = 'F4', 'write', 0x12345678
    elif defect == 'write-data':
        events = _write_events(0x12345678)
        events[2]['outputs']['backend'][NAMES['a_data']] = 0x12345679
        flow, operation, value = 'F4', 'write', 0x12345678
    elif defect == 'read-address':
        events[2]['outputs']['backend'][NAMES['a_address']] = 0
    elif defect == 'read-mask':
        events[2]['outputs']['backend'][NAMES['a_mask']] = 3
    elif defect == 'read-data':
        events[3]['outputs']['backend'][NAMES['d_data']] = read_value ^ 1
    elif defect == 'response-source':
        events[3]['outputs']['backend'][NAMES['d_source']] = 1
    elif defect == 'response-opcode':
        events[3]['outputs']['backend'][NAMES['d_opcode']] = 0
    elif defect == 'response-size':
        events[3]['outputs']['backend'][NAMES['d_size']] = 1
    elif defect == 'no-acceptance':
        events = [event for event in events
                  if event['kind'] != 'mmio_acceptance']
    elif defect == 'no-ram':
        events = [event for event in events
                  if event['kind'] != 'memory_write']
    elif defect == 'ram-value':
        events[-1]['value'] = (read_value ^ 0x5a5) ^ 1
    if flow == 'F4' and operation == 'write':
        events = events + _read_events(0, event_id=6, flow='F4', producer=20)
    with pytest.raises(ValueError, match=match):
        _observe(events, flow=flow, operation=operation, value=value,
                 artifact=artifact)


def test_transfer_count_and_ordering_are_refused(artifact):
    value = 0x0a0b0c0d
    write = _write_events(value)
    read = _read_events(value, event_id=6, flow='F4', producer=20)
    with pytest.raises(ValueError, match='MMIO-transfer-count'):
        observe_tlul_mmio_bus(
            _declaration('read', value=value), _receipt(write + read),
            target_artifact=artifact, flow='F2')
    with pytest.raises(ValueError, match='MMIO-transfer-count'):
        observe_tlul_mmio_bus(
            _declaration('write', value=value), _receipt(read),
            target_artifact=artifact, flow='F4')
    with pytest.raises(ValueError, match='write-value-or-order'):
        observe_tlul_mmio_bus(
            _declaration('write', value=value ^ 1), _receipt(write + read),
            target_artifact=artifact, flow='F4')
    late = [dict(event) for event in write]
    for event in late:
        event['event_id'] += 100
    with pytest.raises(ValueError, match='write-value-or-order'):
        observe_tlul_mmio_bus(
            _declaration('write', value=value), _receipt(late + read),
            target_artifact=artifact, flow='F4')
    early_read = _read_events(value, event_id=1, flow='F4', producer=5)
    late_write = _write_events(value, event_id=6)
    with pytest.raises(ValueError, match='write-value-or-order'):
        observe_tlul_mmio_bus(
            _declaration('write', value=value),
            _receipt(late_write + early_read),
            target_artifact=artifact, flow='F4')


def test_observer_requires_the_native_trace(artifact):
    document = deepcopy(artifact.runtime_document)
    document['base_protocol_trace']['protocol'] = 'apb3'
    damaged = replace(artifact, runtime_document=document)
    with pytest.raises(ValueError, match='native-TL-UL-trace-required'):
        observe_tlul_mmio_bus(
            _declaration('read'), _receipt([]),
            target_artifact=damaged, flow='F2')


def test_descriptor_is_self_contained_and_prepares_tlul_support():
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    import tempfile
    descriptor = load_descriptor(
        ROOT / 'configs/scenarios/compiled-f2-f4-obi-tlul-gpio'
        / 'generic_scenario.json', base_dir=ROOT)
    assert descriptor.flow_ids == ('F2', 'F4')
    assert descriptor.executors == {'F2': 'compiled_mmio',
                                    'F4': 'compiled_mmio'}
    assert descriptor.f2_records == ('04000040',)
    # The TL-UL F4 candidate layout keeps the ten declared target bus-input
    # slices (141 bits = 18 bytes); the compiled_mmio executor ignores their
    # values, so the declared records pad the 32-bit stream with zero pins.
    assert descriptor.f4_records == (
        '550000000000000000000000000000000000',
        'aa0000000000000000000000000000000000',
        '341200000000000000000000000000000000')
    with tempfile.TemporaryDirectory(prefix='tlul-gpio-test-') as directory:
        context = create_preparation(
            base_dir=ROOT, compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,),
            supplement_path=descriptor.supplement,
            generated_dir=Path(directory) / 'generated',
            flow_ids=descriptor.flow_ids)
        try:
            target = context.artifacts[INSTANCE]
            assert target.runtime_document['kind'] == 'tlul_register_observe'
            from myfuzz.integration.compiled_mmio import mmio_support
            for flow in ('F2', 'F4'):
                support = context.flow_support(flow)
                assert support['status'] == 'supported'
                assert support['execution_supported'] == 1
                assert support['executor'] == 'compiled_mmio'
                binding = support['producer_binding']
                assert binding['protocol'] == ['tl-ul', '1']
                assert binding['template'] == list(TEMPLATE)
                assert binding['internal_storage_version'] == 'unknown'
                assert binding['reward_eligible'] is False
                selected = mmio_support(artifacts=context.artifacts,
                                        compiled_inputs=context.compiled_inputs(),
                                        flow=flow)
                assert selected['status'] == 'supported'
                assert selected['executor'] == 'compiled_mmio'
                assert selected['producer_binding'] == binding
            protocol, session, bank, observer = target_adapter(
                target, dict(ACCESS, operation='read'), _request())
            assert protocol == 'tl-ul'
            assert session is GeneratedTlulRegisterSession
            assert observer is observe_tlul_mmio_bus
            assert bank.document()['endpoint_id'] == ENDPOINT
        finally:
            context.close()
