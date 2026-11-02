"""AXI4-Lite IP target adapter: selection, template gate and native joins.

The artifact is the real generated one (planning/rendering only, no Verilator
and no RTL run); the receipt events are synthetic because the real native
samples are produced by the remote execution the main agent owns.
"""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration.target_axi4lite import (
    TEMPLATE, axi4lite_mmio_bank_facts, observe_axi4lite_mmio_bus,
    target_adapter)
from myfuzz.local_harness.axi4lite_register_session import (
    GeneratedAxi4LiteRegisterSession)

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'
BASE = 0x40001000
OFFSET = 0
ACCESS = {'source_component': 'cpu', 'source_endpoint': 'processor.memory',
          'target_component': 'peripheral', 'target_endpoint': 'uart.bus',
          'device_id': 'peripheral', 'register': 'SETUP', 'field': 'value',
          'register_offset': OFFSET, 'address': BASE, 'window_base': BASE,
          'window_size': 16}
TRACE = {'awvalid': 1, 'awready': 1, 'awaddr': 4, 'awprot': 3,
         'wvalid': 1, 'wready': 1, 'wdata': 32, 'wstrb': 4,
         'bvalid': 1, 'bready': 1, 'bresp': 2,
         'arvalid': 1, 'arready': 1, 'araddr': 4, 'arprot': 3,
         'rvalid': 1, 'rready': 1, 'rdata': 32, 'rresp': 2}


@pytest.fixture(scope='module')
def artifact():
    from myfuzz.local_harness import (load_local_harness_request,
        plan_local_harness, render_local_driver, render_local_harness,
        render_local_runtime, verify_local_source_lock)
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=PROFILE,
        instance_id='peripheral', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16, tuning={
            'endpoint_policies': [dict(
                endpoint_id='uart.bus', template_id='target.axi4-lite',
                template_version='1', variant_id='single-outstanding-error-codes',
                max_outstanding=1)],
            'fixed_inputs': [dict(endpoint_id='uart.pins', role='rx', value=1),
                             dict(endpoint_id='uart.pins', role='cts_n', value=0)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT),
        base_dir=ROOT), base_dir=ROOT)


def _request(*, template='target.axi4-lite',
             variant='single-outstanding-error-codes', endpoint='uart.bus'):
    row = {'target_instance': 'peripheral', 'endpoint_id': endpoint,
           'template': template, 'variant_id': variant}
    return SimpleNamespace(wiring=SimpleNamespace(document={'windows': [row]}),
                           base_dir=ROOT)


def _sample(event_id, producer, **pins):
    backend = {name: 0 for name in
               (f'trace_{role}' for role in TRACE)}
    backend.update({f'trace_{role}': value for role, value in pins.items()})
    return dict(event_id=event_id, kind='local_tick_sample',
                component='peripheral', phase='pre',
                producer_event_id=producer, outputs={'backend': backend})


def _acceptance(event_id, transaction, write):
    return dict(event_id=event_id, kind='mmio_acceptance', component='cpu',
                device_id='peripheral', address=BASE,
                source_transaction=transaction, write=write)


def _delivery(event_id, transaction, *, producer, write, write_value=0,
              read_value=None):
    return dict(event_id=event_id, kind='mmio_delivery', component='cpu',
                device_id='peripheral', address=BASE, register_offset=OFFSET,
                source_transaction=transaction, producer_event_id=producer,
                write=write, byte_enable=15,
                write_value=write_value if write else None,
                read_value=None if write else read_value)


def _declaration(flow, *, value=0x12345678, read_value=0x1234, result_address=0x100):
    return dict(schema_version='generated_register_reader.v1',
                candidate=dict(access=deepcopy(ACCESS), value=value),
                result_address=result_address, xor_constant=0x5a5)


def _write_events(value, *, producer=10, bresp=0, awaddr=OFFSET,
                  wstrb=15, wdata=None):
    transaction = {'execution_id': 'e', 'testcase_id': 't',
                   'source_component': 'cpu', 'source_epoch': 0,
                   'channel_id': 'memory', 'source_sequence': 1}
    return [
        _acceptance(1, transaction, True),
        _delivery(2, transaction, producer=producer, write=True,
                  write_value=value),
        _sample(3, producer, awvalid=1, awready=1, awaddr=awaddr, awprot=0,
                wvalid=1, wready=1, wdata=value if wdata is None else wdata,
                wstrb=wstrb),
        _sample(4, producer, bvalid=1, bready=1, bresp=bresp),
    ]


def _read_events(read_value, *, producer=11, rresp=0, araddr=OFFSET,
                 rdata=None, flow='F4', result_address=0x100, value=0x12345678):
    transaction = {'execution_id': 'e', 'testcase_id': 't',
                   'source_component': 'cpu', 'source_epoch': 0,
                   'channel_id': 'memory', 'source_sequence': 2}
    result = (read_value ^ 0x5a5) if flow == 'F2' else read_value
    return [
        _acceptance(5, transaction, False),
        _delivery(6, transaction, producer=producer, write=False,
                  read_value=read_value),
        _sample(7, producer, arvalid=1, arready=1, araddr=araddr, arprot=0),
        _sample(8, producer, rvalid=1, rready=1,
                rdata=read_value if rdata is None else rdata, rresp=rresp),
        dict(event_id=9, kind='memory_write', component='cpu',
             address=result_address, value=result, byte_enable=15),
    ]


def _receipt(events):
    return SimpleNamespace(events=events)


# ---------------------------------------------------------------------------
# Selection, template gate and bank facts
# ---------------------------------------------------------------------------

def test_adapter_selects_the_real_axi4lite_register_target(artifact):
    protocol, session, bank, observer = target_adapter(
        artifact, ACCESS, _request())
    assert protocol == 'axi4-lite'
    assert session is GeneratedAxi4LiteRegisterSession
    assert observer is observe_axi4lite_mmio_bus
    document = bank.document()
    assert document['protocol'] == ['axi4-lite', '1']
    assert document['template'] == list(TEMPLATE)
    assert document['window_size'] == 16
    assert document['internal_storage_version'] == 'unknown'
    assert document['cross_case_origin'] == 'unknown'
    assert document['reward_eligible'] is False
    assert document['declaration_scope'] == (
        'configured_register_map_not_internal_RTL_storage_proof')
    assert [row['name'] for row in document['registers']] == [
        'SETUP', 'FIFO_STATUS', 'RXREG', 'TXREG']
    assert document['registers'][0]['access'] == 'rw'


def test_bank_facts_can_be_derived_without_the_access(artifact):
    bank = axi4lite_mmio_bank_facts(artifact, endpoint_id='uart.bus')
    assert bank.document()['endpoint_id'] == 'uart.bus'


@pytest.mark.parametrize('template,variant,match', [
    ('target.apb3', 'single-outstanding-error-codes', 'template-mismatch'),
    ('target.axi4-lite', 'full-word', 'template-mismatch'),
])
def test_unadmitted_template_is_refused_by_name(artifact, template, variant, match):
    with pytest.raises(ValueError, match=match):
        target_adapter(artifact, ACCESS, _request(template=template, variant=variant))


def test_missing_or_foreign_window_is_refused(artifact):
    with pytest.raises(ValueError, match='one-declared-window-required'):
        target_adapter(artifact, ACCESS, SimpleNamespace(
            wiring=SimpleNamespace(document={'windows': []}), base_dir=ROOT))
    with pytest.raises(ValueError, match='one-declared-window-required'):
        target_adapter(artifact, dict(ACCESS, target_endpoint='uart.other'),
                       _request(endpoint='uart.bus'))


def test_unknown_access_register_is_refused(artifact):
    with pytest.raises(ValueError, match='access-register-mismatch'):
        target_adapter(artifact, dict(ACCESS, register='TXREG'), _request())


@pytest.mark.parametrize('defect,match', [
    ('kind', 'native-AXI4-Lite-trace-required'),
    ('protocol', 'native-AXI4-Lite-trace-required'),
    ('signal', 'native-AXI4-Lite-trace-required'),
    ('width', 'native-AXI4-Lite-trace-required'),
    ('storage', 'native-AXI4-Lite-trace-required'),
])
def test_damaged_artifact_is_refused_by_name(artifact, defect, match):
    document = deepcopy(artifact.runtime_document)
    trace = document['base_protocol_trace']
    if defect == 'kind':
        document['kind'] = 'apb3_register_observe'
    elif defect == 'protocol':
        trace['protocol'] = 'apb3'
    elif defect == 'signal':
        trace['signals'].pop('awvalid')
    elif defect == 'width':
        trace['signal_widths']['rdata'] = 16
    else:
        document['storage_observation'] = {'forged': True}
    with pytest.raises(ValueError, match=match):
        target_adapter(replace(artifact, runtime_document=document), ACCESS, _request())


# ---------------------------------------------------------------------------
# Observer joins
# ---------------------------------------------------------------------------

def test_f4_write_then_readback_join_and_dependent_ram(artifact):
    value, read_value = 0x12345678, 0x12345678
    events = _write_events(value) + _read_events(read_value, flow='F4')
    observed = observe_axi4lite_mmio_bus(
        _declaration('F4', value=value, read_value=read_value),
        _receipt(events), target_artifact=artifact, flow='F4')
    assert observed['read_value'] == read_value
    assert observed['result_value'] == read_value
    assert observed['RAM_event'] == 9
    write, read = observed['joins']
    assert write['write'] is True and read['write'] is False
    assert write['value'] == value and read['value'] == read_value
    assert write['native_axi4lite_aw_event'] == 3
    assert write['native_axi4lite_w_event'] == 3
    assert write['native_axi4lite_b_event'] == 4
    assert write['native_axi4lite_request_event'] == 3
    assert write['native_axi4lite_response_event'] == 4
    assert write['acceptance_event'] == 1 and write['delivery_event'] == 2
    assert read['native_axi4lite_ar_event'] == 7
    assert read['native_axi4lite_r_event'] == 8
    assert read['native_axi4lite_response_event'] == 8
    assert read['acceptance_event'] == 5 and read['delivery_event'] == 6


def test_f2_read_xor_and_dependent_ram(artifact):
    read_value = 0x00000019
    events = _read_events(read_value, flow='F2')
    observed = observe_axi4lite_mmio_bus(
        _declaration('F2', read_value=read_value), _receipt(events),
        target_artifact=artifact, flow='F2')
    assert observed['read_value'] == read_value
    assert observed['result_value'] == read_value ^ 0x5a5
    assert len(observed['joins']) == 1
    join, = observed['joins']
    assert join['native_axi4lite_ar_event'] == 7
    assert join['native_axi4lite_r_event'] == 8


@pytest.mark.parametrize('defect,match', [
    ('bresp', 'bresp'),
    ('rresp', 'rresp'),
    ('no-sample', 'sample-missing'),
    ('no-w', 'request'),
    ('wstrb', 'write-data'),
    ('wdata', 'write-data'),
    ('awaddr', 'aw-address'),
    ('araddr', 'ar-address'),
    ('rdata', 'read-data'),
    ('no-ram', 'dependent-RAM'),
    ('ram-value', 'dependent-RAM'),
])
def test_observer_refuses_native_mismatch(artifact, defect, match):
    value, read_value = 0x11223344, 0x55667788
    if defect in ('bresp', 'no-w', 'wstrb', 'wdata', 'awaddr'):
        events = _write_events(value, **({'bresp': 2} if defect == 'bresp' else {}))
        if defect == 'no-w':
            events = [event for event in events if event['event_id'] != 3]
        elif defect == 'wstrb':
            events = _write_events(value, wstrb=3)
        elif defect == 'wdata':
            events = _write_events(value, wdata=value ^ 1)
        elif defect == 'awaddr':
            events = _write_events(value, awaddr=4)
        events = events + _read_events(read_value, flow='F4')
        flow, declaration = 'F4', _declaration('F4', value=value, read_value=read_value)
    elif defect == 'no-sample':
        events = _write_events(value) + [
            event for event in _read_events(read_value, flow='F4')
            if event['kind'] != 'local_tick_sample']
        flow, declaration = 'F4', _declaration('F4', value=value, read_value=read_value)
    else:
        events = _read_events(read_value, flow='F2',
                              **({'rresp': 3} if defect == 'rresp' else {}))
        if defect == 'araddr':
            events = _read_events(read_value, flow='F2', araddr=4)
        elif defect == 'rdata':
            events = _read_events(read_value, flow='F2', rdata=read_value ^ 1)
        elif defect == 'no-ram':
            events = [event for event in events if event['kind'] != 'memory_write']
        elif defect == 'ram-value':
            events[-1] = dict(events[-1], value=read_value ^ 0x5a5 ^ 1)
        flow, declaration = 'F2', _declaration('F2', read_value=read_value)
    with pytest.raises(ValueError, match=match):
        observe_axi4lite_mmio_bus(declaration, _receipt(events),
                                  target_artifact=artifact, flow=flow)


def test_observer_refuses_transfer_count_and_order(artifact):
    value = 0x0a0b0c0d
    write = _write_events(value)
    read = _read_events(value, flow='F4')
    with pytest.raises(ValueError, match='MMIO-transfer-count'):
        observe_axi4lite_mmio_bus(
            _declaration('F4', value=value, read_value=value),
            _receipt(read + [dict(event) for event in read if event['kind'] == 'mmio_delivery']),
            target_artifact=artifact, flow='F4')
    with pytest.raises(ValueError, match='MMIO-transfer-count'):
        observe_axi4lite_mmio_bus(
            _declaration('F2', read_value=value), _receipt(write + read),
            target_artifact=artifact, flow='F2')
    # The write must precede the read; renumbering the write after it fails.
    late_write = [dict(event) for event in write]
    for event in late_write:
        event['event_id'] += 100
    with pytest.raises(ValueError, match='write-value-or-order'):
        observe_axi4lite_mmio_bus(
            _declaration('F4', value=value, read_value=value),
            _receipt(late_write + read), target_artifact=artifact, flow='F4')


def test_observer_refuses_a_wrong_write_value_and_flow(artifact):
    value = 0x01020304
    with pytest.raises(ValueError, match='write-value-or-order'):
        observe_axi4lite_mmio_bus(
            _declaration('F4', value=value ^ 1, read_value=value),
            _receipt(_write_events(value) + _read_events(value, flow='F4')),
            target_artifact=artifact, flow='F4')
    with pytest.raises(ValueError, match='flow-unsupported'):
        observe_axi4lite_mmio_bus(
            _declaration('F2'), _receipt([]), target_artifact=artifact, flow='F3')


def test_observer_requires_the_native_trace(artifact):
    document = deepcopy(artifact.runtime_document)
    document['base_protocol_trace']['protocol'] = 'apb3'
    damaged = replace(artifact, runtime_document=document)
    with pytest.raises(ValueError, match='native-AXI4-Lite-trace-required'):
        observe_axi4lite_mmio_bus(
            _declaration('F2', read_value=0), _receipt([]),
            target_artifact=damaged, flow='F2')


# ---------------------------------------------------------------------------
# Static descriptor selection (no RTL, no Verilator)
# ---------------------------------------------------------------------------

def test_descriptor_is_self_contained_and_selects_the_axi4lite_target():
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    import tempfile
    path = (ROOT / 'configs/scenarios/compiled-f2-f4-axil-axiluart-picorv32'
            / 'generic_scenario.json')
    descriptor = load_descriptor(path, base_dir=ROOT)
    assert descriptor.flow_ids == ('F2', 'F4')
    assert descriptor.executors == {'F2': 'compiled_mmio', 'F4': 'compiled_mmio'}
    assert len(descriptor.f2_records) == 1
    assert all(len(row) == 8 for row in descriptor.f4_records)
    assert all(int(row, 16) < 0x80000000 for row in descriptor.f4_records)
    with tempfile.TemporaryDirectory(prefix='axil-axiluart-test-') as directory:
        context = create_preparation(
            base_dir=ROOT, compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,),
            supplement_path=descriptor.supplement,
            generated_dir=Path(directory) / 'generated',
            flow_ids=descriptor.flow_ids)
        try:
            assert (context.artifacts['peripheral'].runtime_document['kind']
                    == 'axi4lite_register_observe')
            assert (context.artifacts['cpu'].runtime_document['kind']
                    == 'axi4_lite_cpu')
            compiled = context.compiled_inputs()['compiled']
            paths = {row['flow_id']: row for row in compiled['paths']
                     if row['status'] == 'executable'}
            from myfuzz.integration.compiled_candidate_layout import (
                compile_candidate_layout)
            from myfuzz.integration.compiled_f2_layout import (
                compile_f2_candidate_layout)
            f4 = compile_candidate_layout(paths['F4'])
            for record in descriptor.f4_records:
                f4.decode(bytes.fromhex(record))
            f2 = compile_f2_candidate_layout(paths['F2'])
            for record in descriptor.f2_records:
                assert f2.classify(bytes.fromhex(record)).accepted
            for flow in ('F2', 'F4'):
                support = context.flow_support(flow)
                assert support['status'] == 'supported'
                assert support['execution_supported'] == 1
                assert support['executor'] == 'compiled_mmio'
                binding = support['producer_binding']
                assert binding['protocol'] == ['axi4-lite', '1']
                assert binding['template'] == list(TEMPLATE)
                assert binding['internal_storage_version'] == 'unknown'
                assert binding['reward_eligible'] is False
        finally:
            context.close()
