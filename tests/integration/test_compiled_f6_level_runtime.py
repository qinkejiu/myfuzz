"""Software-only checks for source-backed level IRQ runtime state."""
from types import SimpleNamespace
from copy import deepcopy

import pytest

from myfuzz.integration.compiled_f6 import CompiledF6Runtime, _f6_actual_irq_binding
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember, IrqDeliveryGroupState


def level_world():
    group=IrqDeliveryGroup('f6-dma-irq','cpu','irq',(
        IrqDeliveryMember('dma','irq',mode='level'),))
    binding=group.member_bindings()[0]
    state=IrqDeliveryGroupState(group,{})
    runner=SimpleNamespace(bindings=(binding,),_irq_pulses={},
        _irq_group_states={group.group_id:state},irq_group_for=lambda b:group if b==binding else None)
    return group,binding,state,runner


def test_configuration_values_follow_dma_behavior():
    from myfuzz.integration.compiled_f6 import _f6_configuration_values
    contract={'program_contract':{'source_address':100,'destination_address':200},
        'dma':{'csr':{'start_word':0x0fed0004}}}
    assert _f6_configuration_values(contract)==[100,200,4,0x0fed0004]
    contract['dma'].update(csr={'start_word':0},behavior={'length_unit':'bytes'})
    assert _f6_configuration_values(contract)==[100,200,16,0]


def test_runtime_sets_level_group_ownership_without_gpio(tmp_path,monkeypatch):
    from myfuzz.integration import compiled_f6,compiled_f6_runtime_path,shared_f6_assembly
    class FoundGroupOwnership(Exception):pass
    contract={'program_contract':{},'irq':{'delivery_policy':'level'}}
    owner=object();artifacts={}
    request=SimpleNamespace(cpu=SimpleNamespace(instance_id='cpu'),
        wiring=SimpleNamespace(dma_master_routes=(SimpleNamespace(initiator_instance='dma'),)))
    monkeypatch.setattr(compiled_f6,'_f6_runner_ownership',lambda *a,**kw:owner)
    monkeypatch.setattr(compiled_f6_runtime_path,'admit_compiled_f6_runtime_path',
        lambda **kw:{'logical_path':{'execution_contract':contract}})
    def verify(actual_owner,actual_contract,actual_artifacts,*,base_dir):
        assert actual_owner is owner and actual_contract==contract and actual_artifacts is artifacts
        raise FoundGroupOwnership
    monkeypatch.setattr(shared_f6_assembly,'shared_irq_ownership',verify)
    with pytest.raises(FoundGroupOwnership):
        CompiledF6Runtime(artifacts=artifacts,compiled_inputs={'request':request,'ownership':owner},
            base_dir=tmp_path,cache_dir=tmp_path,max_cases=1)


def test_level_binding_requires_the_contract_and_real_group():
    group,binding,state,runner=level_world()
    contract=dict(delivery_policy='level',target_local_ticks=0,clear_policy='software_write')
    assert _f6_actual_irq_binding(runner,dma_id='dma',cpu_id='cpu',cpu_port='irq',irq_contract=contract)==binding
    with pytest.raises(ValueError):
        _f6_actual_irq_binding(runner,dma_id='dma',cpu_id='cpu',cpu_port='irq')
    runner.irq_group_for=lambda _:None
    with pytest.raises(ValueError):
        _f6_actual_irq_binding(runner,dma_id='dma',cpu_id='cpu',cpu_port='irq',irq_contract=contract)


def test_level_publisher_uses_onset_not_latest_high_and_context_tracks_real_level():
    group,binding,state,runner=level_world()
    def observe(value,tick):
        state.observe(binding,value,dict(component='dma',event_id=tick,reset_epoch=0,
            local_tick=tick,phase='post'))
    observe(0,1);observe(1,2);observe(1,3)
    class Cpu:
        local_ticks=10;reset_epoch=0;source_component='cpu';context=None
        def set_next_irq_input_context(self,value):self.context=value
    runtime=object.__new__(CompiledF6Runtime)
    runtime.contract=dict(cpu={'instance_id':'cpu'},dma={'instance_id':'dma'},
        irq=dict(delivery_policy='level',target_local_ticks=0,clear_policy='software_write',
            producer_port='irq_o',delivery_id='dma-to-cpu'))
    runtime.runner=runner;runtime._irq_binding=binding;runtime.cpu=Cpu()
    runtime.dma=SimpleNamespace(reset_epoch=0)
    runtime._f6_irq_runtime_name='irq_wire'
    runtime._validated_f6_irq_runtime_name=lambda:'irq_wire'
    runtime.observer_view=[dict(event_id=tick,kind='dma_edge',component='dma',tick=tick,reset_epoch=0,
        payload={'observations':{'physical':{'irq_wire':int(tick>1)}}}) for tick in (1,2,3)]
    runtime._observer_raw_event_ids={id(row):row['event_id'] for row in runtime.observer_view}
    runtime._active_f6_irq_delivery=None
    runtime._publish_f6_irq_delivery()
    delivery=runtime._active_f6_irq_delivery
    assert delivery['source_output_key']==['dma',0,'irq_o',2]
    assert delivery['start_local_tick']==11 and delivery.get('end_local_tick') is None
    runtime._arm_native_irq_context()
    assert runtime.cpu.context['source_output_key']==delivery['source_output_key']
    observe(1,4);runtime._arm_native_irq_context()
    assert runtime.cpu.context is not None
    observe(0,5);runtime._arm_native_irq_context()
    assert runtime.cpu.context is None


def test_level_stop_requires_real_clear_and_subsequent_native_low():
    from myfuzz.integration.compiled_f6 import _f6_level_clear_tick
    group,binding,state,runner=level_world()
    key=['dma',0,'irq_o',2]
    transaction={'source_component':'cpu','source_epoch':0,'testcase_id':'case',
        'execution_id':'local-execution','channel_id':'data','source_sequence':3}
    delivery={'event_id':9,'source_output_key':key}
    runtime=SimpleNamespace(runner=runner,_irq_binding=binding,
        cpu=SimpleNamespace(reset_epoch=0,_case_id='case'),dma=SimpleNamespace(reset_epoch=0,_irq_runtime_name='irq_wire'),
        cpu_id='cpu',dma_id='dma',contract={'control':{'base':4096,'device_id':'dma'},
            'dma':{'behavior':{'irq_clear':{'method':'write','offset':0,'value':128,'byte_enable':15}}}})
    runtime.observer_view=[
        dict(event_id=10,runner_event_id=1,kind='cpu_external_irq_taken',component='cpu',local_tick=11,
            reset_epoch=0,binding_delivery_event_id=9,source_output_key=key),
        dict(event_id=11,kind='data_accept',component='cpu',transaction=transaction,address=4096,write=1,wdata=128),
        dict(event_id=12,kind='mmio_delivery',component='cpu',source_transaction=transaction,
            device_id='dma',address=4096,write=True,
            dma_control_receipt=dict(source_transaction=transaction,address=4096,offset=0,
                write=True,value=128,byte_enable=15,edge_ticks=[8,9,10])),
        dict(event_id=13,kind='data_response',component='cpu',transaction=transaction,address=4096,write=1)]
    journal=[dict(event_id=1,kind='cpu_external_irq_taken',component='cpu',local_tick=11,reset_epoch=0),
        dict(event_id=2,kind='irq_group_delivery',group_id=group.group_id,
            group_sha256=group.identity_sha256,target_epoch=0,cpu_tick=11,
            unique_source='dma.irq',native_take_event_id=1),
        dict(event_id=3,kind='local_tick_sample',component='dma',local_tick=9,
        reset_epoch=0,phase='post',outputs={'irq':0,'physical':{'irq_wire':0}}),
        dict(event_id=4,kind='cpu_external_irq_sample',component='cpu',local_tick=18,
            reset_epoch=0,expected_input=0,actual_pre_input=0,actual_post_input=0),
        dict(event_id=5,kind='irq_group_delivery',group_id=group.group_id,
            group_sha256=group.identity_sha256,target_epoch=0,cpu_tick=18,value=0,native_sample_event_id=4,
            members=[dict(source_id='dma.irq',mode='level',value=0,
                latest_native_source=dict(event_id=3,component='dma',local_tick=9,
                    reset_epoch=0,phase='post',runtime_name='irq_wire'))])]
    assert _f6_level_clear_tick(runtime,delivery,journal,0)==18
    original=deepcopy(runtime.observer_view)
    for mutation in ('clear','low','cpu','take'):
        broken=deepcopy(runtime.observer_view);bad_journal=deepcopy(journal)
        if mutation=='clear':broken[2]['dma_control_receipt']['value']=129
        elif mutation=='low':bad_journal[2]['outputs']['physical']['irq_wire']=1
        elif mutation=='cpu':bad_journal[3]['actual_post_input']=1
        else:broken.pop(0)
        runtime.observer_view=broken
        assert _f6_level_clear_tick(runtime,delivery,bad_journal,0) is None
        # Restore the baseline before the next independent mutation.
        runtime.observer_view=deepcopy(original)
