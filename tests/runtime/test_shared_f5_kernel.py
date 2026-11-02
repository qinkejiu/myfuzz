from types import SimpleNamespace
import pytest

from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.flows.mixed import MixedStorageKernel
from tests.runtime.test_storage_kernel import campaign_world, plan_shaped_path, raw_path


def test_mixed_kernel_accepts_explicit_declared_flows_without_f2():
    kernel=MixedStorageKernel(flow_ids=('F1','F3','F4','F5'))
    assert set(kernel._kernels)=={'F1','F3','F4','F5'}


def test_f5_kernel_lowers_only_declared_pin_raw8_and_never_certifies():
    from myfuzz.runtime.flows.irq import PinFlowKernel
    row={'path_id':'pin-path','flow_id':'F5','sources':[{'kind':'external_pin',
         'origin':'fuzzable','source_id':'pin','component':'target','port':'gpio_in','bit_offset':8,'width':1}]}
    bound=SimpleNamespace(plan_sha256='a'*64,plan=SimpleNamespace(document=lambda:{'paths':[row]}))
    kernel=PinFlowKernel();context=kernel.prepare(bound,'pin-path')
    case={'testcase_id':'case1','path_id':'pin-path','source_id':'pin','raw_records_hex':['0000000100000000']}
    lowered=kernel.lower(context,case)
    assert lowered.flow_id=='F5' and lowered.raw_records==(bytes.fromhex('0000000100000000'),)
    assert kernel.capture(context,{'schema_version':'compiled_shared_F5_case.v1','flow_id':'F5'})==()
    assert kernel.feedback(context,())==()
    for change in ({'source_id':'foreign'},{'raw_records_hex':['00000001']}):
        with pytest.raises(GenericRuntimeRefused):kernel.lower(context,{**case,**change})


def test_mixed_capture_refuses_known_but_undeclared_flow():
    from myfuzz.runtime.flows.mixed import MixedFlowContext
    with pytest.raises(GenericRuntimeRefused):
        MixedStorageKernel(flow_ids=('F4','F5')).capture(
            MixedFlowContext('a'*64,{'F4':object(),'F5':object()}),
            {'schema_version':'compiled_F2_chain.v1'})
