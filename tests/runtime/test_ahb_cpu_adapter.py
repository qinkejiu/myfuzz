"""Source/ABI preparation of the common AHB CPU adapter; no DUT process."""
from copy import deepcopy
from dataclasses import replace
import pytest


def test_registered_AHB_surface_keeps_real_34bit_ABI_and_no_retirement_or_IRQ():
    from myfuzz.runtime.registry import registrations
    row,=[r for r in registrations() if r.adapter_id=='ahb-lite.cpu.v1']
    assert row.protocol==('ahb-lite','1') and row.address_widths==(34,) and row.data_widths==(32,)
    assert row.templates==(('cpu.ahb-lite','1','cvw-external-bus'),)
    assert row.completion_kinds==('address_phase_then_ready_completion',)
    assert set(row.evidence_capabilities)=={'cross_component_consumption','cross_component_source','physical_protocol_sample'}


@pytest.fixture(scope='module')
def artifact():
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from tests.local_harness.test_ahb_lite_session import _artifact
    with elaboration_mode_scope('direct'),execution_validation_scope():
        return _artifact()


def test_actual_generated_AHB_surface_preserves_manager_domain_and_boot(artifact):
    from myfuzz.runtime.adapters.ahb_cpu import ahb_cpu_surface_document
    facts=ahb_cpu_surface_document(artifact)
    assert facts['address_width']==34 and facts['data_width']==32
    assert facts['boot_contract']==artifact.runtime_document['boot_contract']
    assert facts['trace_binding']['manager_domain']
    assert facts['instruction_retirement']=='unknown' and facts['native_IRQ']=='unsupported'


@pytest.mark.parametrize('change',['boot','trace','manager','width'])
def test_AHB_source_ABI_drift_is_not_relabelled(artifact,change):
    from myfuzz.runtime.adapters.ahb_cpu import ahb_cpu_surface_document
    document=deepcopy(artifact.runtime_document)
    changed=replace(artifact,runtime_document=document)
    if change=='boot':document['boot_contract']['configured_boot_base']+=1
    if change=='trace':document['base_protocol_traces']['traces'][0]['signals']['hready']='guessed-ready'
    if change=='manager':document.pop('manager_domain',None)
    if change=='width':
        profile=replace(artifact.plan.profile,capabilities={**artifact.plan.profile.capabilities,'address_width':32})
        changed=replace(changed,plan=replace(artifact.plan,profile=profile))
    with pytest.raises(ValueError):ahb_cpu_surface_document(changed)
