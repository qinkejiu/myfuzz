from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest

from tests.integration.test_shared_f5_runtime import prepared_irq

ROOT=Path(__file__).resolve().parents[2]


def test_actual_causal_gpio_companion_uses_bank_and_original_live_authority(prepared_irq,tmp_path):
    from myfuzz.integration.f6_storage_companion import companion_artifact_documents,validate_companion_sessions,validate_companion_build_documents
    from myfuzz.integration.f6_gpio_companion import create_gpio_companion,gpio_companion_authority
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    inputs=prepared_irq.compiled_inputs();contract={'cpu':{'instance_id':'processor'},'dma':{'instance_id':'dma'},
        'memory':{'resource':{'base':0x10000,'size':0x30000}}}
    docs=companion_artifact_documents(contract=contract,artifacts=prepared_irq.artifacts,request=inputs['request'],base_dir=ROOT)
    doc=docs['peripheral']
    assert doc['source_contract']['kind']=='gpio.register-bank.v1'
    assert doc['register']=='GPIOEN' and doc['read_register']=='PADIN' and doc['irq_source_port']=='interrupt'
    assert doc['source_contract']['read_register']['write_mask']==0
    target=create_gpio_companion(prepared_irq.artifacts['peripheral'],base_dir=ROOT,cache_dir=tmp_path)
    authority=gpio_companion_authority(target)
    assert target.process is None
    assert type(authority) is GpioRegisterVersionAuthority and authority.target is target
    assert gpio_companion_authority(target) is authority
    validate_companion_sessions(documents=docs,artifacts=prepared_irq.artifacts,sessions={'peripheral':target})
    validate_companion_build_documents(docs,artifacts=prepared_irq.artifacts,wiring=inputs['request'].wiring)
    bad=deepcopy(docs);bad['peripheral']['read_register']='GPIOEN'
    with pytest.raises(ValueError):validate_companion_sessions(documents=bad,artifacts=prepared_irq.artifacts,sessions={'peripheral':target})
    with pytest.raises(ValueError):validate_companion_build_documents(bad,artifacts=prepared_irq.artifacts,wiring=inputs['request'].wiring)
    with pytest.raises(ValueError):gpio_companion_authority(SimpleNamespace())


@pytest.fixture(scope='module')
def group_prepared(tmp_path_factory):
    from myfuzz.runtime.preparation import create_preparation
    config=ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared'
    context=create_preparation(base_dir=ROOT,compose_path=config/'compose.json',
        capability_paths=(ROOT/'configs/scenarios/compiled-f6-ibex-wbdmac-storage/dma.test_capability.json',
                          ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json'),
        supplement_path=config/'execution_supplement.json',generated_dir=tmp_path_factory.mktemp('gpio-dma-group')/'generated',
        flow_ids=('F1','F2','F3','F4','F6'))
    yield context
    context.close()


def test_actual_gpio_dma_group_keeps_one_cpu_memory_and_distinct_live_register_authority(group_prepared,tmp_path):
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly,shared_irq_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    inputs=group_prepared.compiled_inputs();artifacts=dict(group_prepared.artifacts)
    admission=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    contract=admission['execution_contract']
    owner=_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma')
    owner=shared_irq_ownership(owner,contract,artifacts,base_dir=ROOT)
    assembly=build_f6_assembly(contract=contract,artifacts=artifacts,request=inputs['request'],
        ownership=owner,base_dir=ROOT,cache_dir=tmp_path)
    assert set(assembly.runner.sessions)=={'cpu','dma','peripheral'}
    assert assembly.cpu.memory is assembly.dma.memory is assembly.memory
    assert assembly.cpu.irq_input_port=='irq_external_i'
    groups=[assembly.runner.irq_group_for(binding) for binding in assembly.runner.bindings]
    assert len(groups)==2 and groups[0] is groups[1] and groups[0].operation=='or'
    assert [(m.mode,m.pulse_width_ticks) for m in groups[0].members]==[('pulse',16),('pulse',4)]
    assert owner.binding_producer('cpu','irq_external_i',0,1)==groups[0].owner_ref
    assert all(local.process is None for local in assembly.runner.sessions.values())
    assert assembly.companion_authorities['peripheral'].target is assembly.companions['peripheral']


def test_dma_level_contract_uses_real_group_samples_with_or_without_gpio(group_prepared):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.zipdma_profile_session import verify_zipdma_profile
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.f6_dma_behavior import f6_dma_semantics_from_source
    from myfuzz.integration.shared_f6_assembly import shared_irq_group,shared_irq_ownership
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroupState

    inputs=group_prepared.compiled_inputs();artifacts=dict(group_prepared.artifacts)
    contract=deepcopy(admit_compiled_f6_runtime_path(artifacts=artifacts,
        compiled_inputs=inputs,base_dir=ROOT)['execution_contract'])
    profile=load_component_profile(ROOT/'configs/peripherals/zipdma_smoke/component_profile.json')
    source=verify_zipdma_profile(profile,base_dir=ROOT)
    csr,behavior=f6_dma_semantics_from_source(source)
    contract['dma'].update(source_contract=source,csr=csr,behavior=behavior)
    for with_gpio in (True,False):
        current=deepcopy(contract)
        if not with_gpio:current['program_contract'].pop('gpio_irq')
        group=shared_irq_group(current,artifacts,base_dir=ROOT)
        assert group.members[0].mode=='level'
        assert group.members[0].pulse_width_ticks is None
        assert len(group.members)==(2 if with_gpio else 1)
        owner=_f6_runner_ownership(inputs['ownership'],cpu_id='cpu',dma_id='dma')
        owner=shared_irq_ownership(owner,current,artifacts,base_dir=ROOT)
        assert owner.binding_producer('cpu',group.target_port,group.target_bit_offset,1)==group.owner_ref
        # Exercise the same reducer as the runner with native source references.
        class Pulse:
            def input_at(self,tick):return 0
            def state_document(self):return {}
        bindings=group.member_bindings()
        state=IrqDeliveryGroupState(group,{bindings[1]:Pulse()} if with_gpio else {})
        def observe(binding,value,event):
            state.observe(binding,value,dict(component=binding.source_component,event_id=event,
                reset_epoch=0,local_tick=event,phase='post'))
        if with_gpio:observe(bindings[1],0,1)
        observe(bindings[0],1,2)
        assert state.frame(100)['value']==1
        observe(bindings[0],1,3)
        assert state.frame(1000)['members'][0]['native_source']['event_id']==2
        observe(bindings[0],0,4)
        assert state.frame(1001)['value']==0


def test_real_F5_pin_path_joins_explicit_group_and_declares_fixed_support_without_F6_permission(group_prepared,tmp_path):
    from myfuzz.integration.shared_f5_slots import extend_shared_pin_path,declare_shared_pin
    from myfuzz.integration.shared_f6_assembly import shared_irq_group
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.scenario.dependency import DependencyGraph
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract,PreparedRuntimePathContract
    inputs=group_prepared.compiled_inputs();artifacts=dict(group_prepared.artifacts)
    admission=admit_compiled_f6_runtime_path(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
    group=shared_irq_group(admission['execution_contract'],artifacts,base_dir=ROOT)
    graph=DependencyGraph.from_edge_document(admission['runtime_graph']);contract=RuntimePathContract.from_document(admission['runtime_contract'])
    prepared=PreparedRuntimePathContract.from_document(admission['prepared_runtime_paths'])
    metadata=admission['shared_flow_paths']['F5']
    typed=contract
    assert metadata['support_flow_id']=='F1' and metadata['pin']['bit_offset']==8
    assert any(e.relation=='irq_delivery_group' and e.irq_group_sha256==group.identity_sha256 for e in typed.edges)
    assert metadata['path_id'] in prepared.path_ids
    assert len(prepared.path_ids)>1  # retain the actual DMA route selections
    modified=deepcopy(admission);modified['shared_flow_paths']['F5']=metadata
    layout=modified['execution_contract']['program_contract']['shared_slots']
    declaration=declare_shared_pin(inputs,layout,modified,raw=bytes.fromhex('0000000100000000'),slot_index=0)
    assert declaration['value']==1 and declaration['code_hex']=='13000000'*32
    assert declaration['support_path_id']==modified['shared_flow_paths']['F1']['path_id']
    with pytest.raises(ValueError):declare_shared_pin(inputs,layout,modified,raw=b'\0'*4,slot_index=0)
    wrong=deepcopy(group.document());wrong['members'][1]['source_port']='irq'
    with pytest.raises(ValueError):extend_shared_pin_path(graph,contract,inputs['compiled'],irq_group=wrong)
