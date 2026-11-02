from types import SimpleNamespace
import pytest

from myfuzz.runtime.flows.mmio import capture_mmio


def _case(join):
    return dict(status='observed',flow_id='F2',internal_storage_version='unknown',
        cross_case_origin='unknown',reward_eligible=False,execution_binding_sha256='a'*64,
        joins=[dict(source_transaction=dict(execution_id='run',testcase_id='test',
            source_component='cpu',source_epoch=0,channel_id='data',source_sequence=1),
            delivery_event=5,**join)])


def test_capture_keeps_protocol_specific_actual_sample_references():
    context=SimpleNamespace(flow_id='F2',target_component='peripheral',cpu_component='cpu',
                            semantic_contract_sha256='b'*64)
    apb,=capture_mmio(context,_case({'native_APB_event':3}))
    wb,=capture_mmio(context,_case({'native_wishbone_request_event':2,'native_wishbone_response_event':4}))
    assert [ref.event_id for ref in apb.native_refs]==[3]
    assert [ref.event_id for ref in wb.native_refs]==[2,4]
    assert all(ref.component=='peripheral' and ref.kind=='local_tick_sample' for ref in wb.native_refs)
    assert wb.scope=='physical_protocol_sample'


@pytest.mark.parametrize('join',[
    {}, {'native_wishbone_request_event':2},
    {'native_APB_event':3,'native_wishbone_request_event':2,'native_wishbone_response_event':4},
])
def test_capture_rejects_missing_or_mixed_bus_sample_shape(join):
    context=SimpleNamespace(flow_id='F2',target_component='peripheral',cpu_component='cpu',
                            semantic_contract_sha256='b'*64)
    with pytest.raises(ValueError,match='protocol-sample-shape'):
        capture_mmio(context,_case(join))
