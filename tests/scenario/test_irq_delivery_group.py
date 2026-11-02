"""OR groups authenticate real inputs without inventing a sole IRQ source."""
import pytest
from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup,IrqDeliveryMember,IrqDeliveryGroupState
from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
from myfuzz.scenario.runner import ScenarioRunner


def declared():
    return IrqDeliveryGroup('external','core','irq',(
        IrqDeliveryMember('dma','irq'),IrqDeliveryMember('gpio','interrupt')))


def test_generated_dma_irq_adapter_identity_tracks_verified_zipdma_profile():
    from pathlib import Path
    from types import SimpleNamespace
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.zipdma_profile_session import verify_zipdma_profile
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    from myfuzz.scenario.irq_delivery_group import verify_group_sessions
    root=Path(__file__).resolve().parents[2]
    profile=load_component_profile(root/'configs/peripherals/zipdma_smoke/component_profile.json')
    source=verify_zipdma_profile(profile,base_dir=root)
    export=dict(physical_port='o_interrupt',endpoint_id='dma.interrupt',role='irq',
        direction='output',bit_lo=0,bit_hi=0,width=1,disposition='functional',runtime_name='native_irq')
    artifact=SimpleNamespace(plan=SimpleNamespace(profile=profile),source_verification=source,
        runtime_document={'physical_exports':[export],'source_verification':source},
        structural=SimpleNamespace(abi_document={'ports':[export]}))
    cpu=object.__new__(GeneratedCve2Session);cpu._native_irq_receipts=True;cpu.irq_input_port='irq'
    dma=object.__new__(GeneratedWishboneDmaScenarioSession)
    dma.artifact=artifact;dma._irq_runtime_name='native_irq';dma.base_dir=root
    group=IrqDeliveryGroup('dma-level','cpu','irq',(IrqDeliveryMember('dma','irq',mode='level'),))
    mapping=verify_group_sessions(group,{'cpu':cpu,'dma':dma})
    assert mapping[group.member_bindings()[0]]['adapter_id']=='zipcpu.zipdma.native-irq.v1'
    artifact.runtime_document['source_verification']={'schema_version':'forged'}
    with pytest.raises(ValueError,match='source verification'):
        verify_group_sessions(group,{'cpu':cpu,'dma':dma})


def test_profile_declared_dma_irq_uses_its_actual_source_verifier():
    from pathlib import Path
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    from myfuzz.scenario.irq_delivery_group import verify_group_sessions
    root=Path(__file__).resolve().parents[2]
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        artifact=_artifact('configs/peripherals/unregistered_zipdma_profile/component_profile.json','dma')
        assert artifact.source_verification['schema_version']=='local_source_lock_verification.v1'
        cpu=object.__new__(GeneratedCve2Session);cpu._native_irq_receipts=True;cpu.irq_input_port='irq'
        dma=object.__new__(GeneratedWishboneDmaScenarioSession)
        dma.artifact=artifact;dma.base_dir=root
        dma._irq_runtime_name=next(e['runtime_name'] for e in artifact.runtime_document['physical_exports'] if e.get('role')=='irq')
        group=IrqDeliveryGroup('dma-level','cpu','irq',(IrqDeliveryMember('dma','irq',mode='level'),))
        mapping=verify_group_sessions(group,{'cpu':cpu,'dma':dma})
        assert mapping[group.member_bindings()[0]]['adapter_id']=='declared.wishbone-dma.native-irq.v1'
        # The generic selected-Wishbone artifact must also install the real
        # dual-endpoint checker using its own source manifest, not the ZipDMA
        # registry's profile identifier.
        from types import SimpleNamespace
        checker_runner=ScenarioRunner(sessions={'dma':SimpleNamespace(artifact=artifact,base_dir=root)},
            ownership=compile_ownership((),()),bindings=())
        checker=checker_runner.install_protocol_checker('dma')
        assert checker.report()['installed_endpoint_ids']==['dma.control','dma.memory']
        from unittest.mock import patch
        with patch.dict(artifact.runtime_document,source_verification={'schema_version':'forged'}):
            with pytest.raises(ValueError,match='source verification'):
                verify_group_sessions(group,{'cpu':cpu,'dma':dma})


def world():
    group=declared();pulses={b:IrqPulseDelivery(width_ticks=4) for b in group.member_bindings()}
    return group,IrqDeliveryGroupState(group,pulses),pulses


def native_source(component,event_id,value):
    return dict(event_id=event_id,component=component,reset_epoch=0,local_tick=1,phase='post',value=value)


def observe(state,pulses,binding,value,event_id):
    state.observe(binding,value,native_source(binding.source_component,event_id,value))
    pulses[binding].observe_source(value,source_tick=1,cpu_tick=0)


@pytest.mark.parametrize('values,active,status', [((0,0),[], 'unknown'),((1,0),['dma.irq'],'unique'),
    ((0,1),['gpio.interrupt'],'unique'),((1,1),['dma.irq','gpio.interrupt'],'joint')])
def test_group_or_and_actual_cpu_sample(values,active,status):
    group,state,pulses=world()
    for i,(b,v) in enumerate(zip(group.member_bindings(),values)):observe(state,pulses,b,v,i+1)
    state.begin_step(1)
    state.native(dict(kind='cpu_external_irq_sample',component='core',event_id=3,producer_event_id=2,
        reset_epoch=0,receipt_id={'execution':'native','sequence':1},local_tick=1,
        expected_input=int(any(values)),actual_pre_input=int(any(values)),actual_post_input=int(any(values))))
    row=state.finish_step(2)
    assert row['active_sources']==active and row['attribution_status']==status
    assert row['unique_source']==(active[0] if len(active)==1 else None)


def test_group_missing_sample_reset_and_wrong_actual_cpu_input_refuse():
    group,state,pulses=world()
    with pytest.raises(ValueError,match='native state'):state.frame(1)
    for i,b in enumerate(group.member_bindings()):observe(state,pulses,b,1,i+1)
    state.begin_step(1)
    with pytest.raises(ValueError,match='does not match OR'):
        state.native(dict(kind='cpu_external_irq_sample',component='core',local_tick=1,
            expected_input=1,actual_pre_input=0,actual_post_input=1))
    state.reset()
    with pytest.raises(ValueError,match='native state'):state.frame(1)


def test_group_owner_does_not_claim_one_member_is_the_direct_driver():
    group=declared()
    owners=compile_ownership((InputField('core','irq',1),),
        (InputOwner('core','irq',0,1,'bound',group.owner_ref),))
    assert owners.binding_producer('core','irq',0,1)=='irq-group:external'
    assert owners.irq_group_owner('core','irq',0,1)==group.group_id


def test_old_single_source_runner_does_not_accept_two_producers_without_explicit_group():
    group=declared()
    owners=compile_ownership((InputField('core','irq',1),),
        (InputOwner('core','irq',0,1,'bound',group.owner_ref),))
    with pytest.raises(ValueError,match='producer'):
        ScenarioRunner(sessions={'core':object(),'dma':object(),'gpio':object()},ownership=owners,
            bindings=group.member_bindings())


def test_runtime_group_edge_requires_exact_declared_group_hash(monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace
    from hashlib import sha256
    import json
    from myfuzz.scenario.dependency import DependencyGraph,DependencyRule,FuzzableSource
    from myfuzz.scenario.runtime_path_contract import RuntimeEdgeContract,RuntimeNode,RuntimePathContract,compile_runtime_path_contract
    group=declared()
    graph=DependencyGraph(sources=(FuzzableSource('pin','gpio','pin',0,1,('IP_TO_CPU',)),),
        rules=(DependencyRule('line',('pin',),'EVENT_ORDER'),DependencyRule('input',('line',),'EVENT_ORDER')))
    owner=compile_ownership((InputField('core','irq',1),InputField('gpio','pin',1)),(
        InputOwner('core','irq',0,1,'bound',group.owner_ref),InputOwner('gpio','pin',0,1,'source','pin')))
    monkeypatch.setattr('myfuzz.scenario.irq_delivery_group.verify_group_sessions',lambda group,sessions:{})
    runner=ScenarioRunner(sessions={name:SimpleNamespace() for name in ('core','gpio','dma')},
        ownership=owner,bindings=group.member_bindings(),irq_delivery_groups=(group,))
    edge=RuntimeEdgeContract(1,0,'irq_delivery_group',irq_group_id=group.group_id,irq_group_sha256=group.identity_sha256)
    contract=RuntimePathContract(sha256(json.dumps(graph.edge_document(),sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        (RuntimeNode('pin','gpio','physical','pin',0,1),RuntimeNode('line','gpio','physical','interrupt',0,1),
         RuntimeNode('input','core','physical','irq',0,1)),(edge,))
    assert RuntimePathContract.from_document(contract.document())==contract
    paths=(('IP_TO_CPU',graph.edge_paths_to('input',direction='IP_TO_CPU')[0]),)
    assert compile_runtime_path_contract(graph,contract,runner,paths=paths)
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
    prepared=PreparedRuntimePathContract(graph,contract,paths)
    compiled=prepared.bind(runner).document()
    compiled['declaration']=prepared.document()
    index=RuntimeEdgeIndex(compiled,contract.document())
    match=index.match_event(dict(kind='cpu_irq_taken',source=['gpio','interrupt'],target=['core','irq'],
        source_bit_offset=0,target_bit_offset=0,width=1))
    assert len(match)==1 and match[0]['scope']=='irq_group_member'
    assert match[0]['relation']=='irq_delivery_group'
    assert index.match_event(dict(kind='dataflow_delivery',source=['gpio','interrupt'],target=['core','irq'],
        source_bit_offset=0,target_bit_offset=0,width=1)) == ()
    with pytest.raises(ValueError,match='group identity'):
        compile_runtime_path_contract(graph,replace(contract,edges=(replace(edge,irq_group_sha256='0'*64),)),runner,paths=paths)
    with pytest.raises(ValueError,match='overlapping target'):
        compile_runtime_path_contract(graph,replace(contract,edges=(RuntimeEdgeContract(1,0,'direct_binding'),)),runner,paths=paths)


@pytest.mark.parametrize('values,expected_single', [((1,0),1),((0,1),1),((1,1),0)])
def test_real_runner_group_samples_acceptance_once_only_for_unique_active(monkeypatch,values,expected_single):
    from types import SimpleNamespace
    from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
    group=declared()
    class Session:
        reset_epoch=0
        local_ticks=0
        def begin_case(self,case_id):pass
        def end_case(self):pass
    class CPU(Session):
        def __init__(self):self.cpu_events=[]
        def step_local(self,inputs):
            self.local_ticks+=1
            scope=dict(component='core',reset_epoch=0,command_sequence=self.local_ticks)
            fields=dict(reset_epoch=0,local_tick=self.local_ticks,command_scope=scope,
                receipt_id={'execution':'wire','sequence':self.local_ticks},expected_input=inputs['irq'],
                actual_pre_input=inputs['irq'],actual_post_input=inputs['irq'],irq_taken_pre=1,
                observation_contract=ibex_irq_receipt_contract())
            self.cpu_events.extend((dict(fields,kind='cpu_external_irq_sample'),
                dict(fields,kind='cpu_external_irq_taken',sample_ref={'command_scope':scope,'local_tick':self.local_ticks},
                     take_key=['core',0,self.local_ticks])))
            return {'irq_taken_pre':1,'irq_masked_pre':0}
    monkeypatch.setattr('myfuzz.scenario.irq_delivery_group.verify_group_sessions',lambda group,sessions:{})
    ownership=compile_ownership((InputField('core','irq',1),),(InputOwner('core','irq',0,1,'bound',group.owner_ref),))
    runner=ScenarioRunner(sessions={'core':CPU(),'dma':Session(),'gpio':Session()},ownership=ownership,
        bindings=group.member_bindings(),irq_delivery_groups=(group,))
    runner.begin_test('group')
    state=runner._irq_group_states[group.group_id]
    for i,(binding,value) in enumerate(zip(group.member_bindings(),values)):
        observe(state,runner._irq_pulses,binding,value,i+1)
    runner.step('core')
    events=runner.events_since(0)
    assert len([e for e in events if e.get('kind')=='cpu_irq_taken'])==expected_single
    facts=[e for e in events if e.get('kind')=='irq_group_acceptance']
    assert len(facts)==1
    assert facts[0]['attribution_status']==('unique' if expected_single else 'joint')
    assert facts[0]['value']==1
    assert runner.irq_group_delivery(group.member_bindings()[0])['native_sample_event_id']>0
    first=runner.irq_group_delivery(group.member_bindings()[0],cpu_tick=1)
    runner.step('core')
    assert runner.irq_group_delivery(group.member_bindings()[0])['cpu_tick']==2
    assert runner.irq_group_delivery(group.member_bindings()[0],cpu_tick=1)==first
    first['members'][0]['value']=99
    assert runner.irq_group_delivery(group.member_bindings()[0],cpu_tick=1)['members'][0]['value']!=99
    runner.sessions['gpio'].reset_epoch=1
    with pytest.raises(ValueError,match='epoch changed'):runner._effective_inputs('core')


def test_native_level_member_is_not_replaced_by_a_pulse_or_last_writer():
    group=IrqDeliveryGroup('level-or','core','irq',(
        IrqDeliveryMember('dma','irq',mode='level'),IrqDeliveryMember('gpio','interrupt')))
    bindings=group.member_bindings();pulses={bindings[1]:IrqPulseDelivery(width_ticks=4)}
    state=IrqDeliveryGroupState(group,pulses)
    state.observe(bindings[0],1,native_source('dma',1,1))
    observe(state,pulses,bindings[1],0,2)
    assert state.frame(100)['value']==1
    state.observe(bindings[0],0,native_source('dma',3,0))
    assert state.frame(100)['value']==0


def test_level_keeps_assertion_source_until_native_low_and_next_assertion():
    group = IrqDeliveryGroup('level', 'core', 'irq', (IrqDeliveryMember('dma', 'irq', mode='level'),))
    binding, = group.member_bindings()
    state = IrqDeliveryGroupState(group, {})
    def sample(event_id, tick, value):
        state.observe(binding, value, dict(event_id=event_id, component='dma',
            reset_epoch=0, local_tick=tick, phase='post'))
    sample(1, 1, 0)
    sample(2, 2, 1)
    sample(3, 3, 1)
    row = state.frame(10)['members'][0]
    assert row['value'] == 1 and row['native_source']['event_id'] == 2
    assert row['latest_native_source']['event_id'] == 3
    sample(4, 4, 0)
    row = state.frame(11)['members'][0]
    assert row['value'] == 0 and row['native_source']['event_id'] == 4
    sample(5, 5, 1)
    row = state.frame(12)['members'][0]
    assert row['value'] == 1 and row['native_source']['event_id'] == 5
    state.reset()
    with pytest.raises(ValueError, match='native state unavailable'):
        state.frame(13)


def test_level_repeated_high_keeps_cpu_context_until_actual_low():
    from types import SimpleNamespace
    group = IrqDeliveryGroup('level', 'core', 'irq', (IrqDeliveryMember('dma', 'irq', mode='level'),))
    binding, = group.member_bindings()
    state = IrqDeliveryGroupState(group, {})
    def sample(event_id, value):
        state.observe(binding, value, dict(event_id=event_id, component='dma',
            reset_epoch=0, local_tick=event_id, phase='post'))
    sample(1, 0)
    sample(2, 1)
    sample(3, 1)
    state.begin_step(5)
    runner = object.__new__(ScenarioRunner)
    runner._irq_group_states = {group.group_id: state}
    runner._irq_group_adapters = {binding: {'physical_port': 'o_interrupt'}}
    cpu = SimpleNamespace(_next_irq_input_context={'source_output_key': ['dma', 0, 'o_interrupt', 2]})
    cpu.set_next_irq_input_context = lambda value: setattr(cpu, '_next_irq_input_context', value)
    runner._guard_irq_group_input_context('core', cpu)
    assert cpu._next_irq_input_context is not None
    state.active_frame = None
    sample(4, 0)
    state.begin_step(6)
    runner._guard_irq_group_input_context('core', cpu)
    assert cpu._next_irq_input_context is None


def test_runner_refuses_a_fake_actual_cpu_input_for_an_installed_group(monkeypatch):
    group=declared()
    ownership=compile_ownership((InputField('core','irq',1),),(InputOwner('core','irq',0,1,'bound',group.owner_ref),))
    with pytest.raises(ValueError,match='actual native CPU'):
        ScenarioRunner(sessions={'core':object(),'dma':object(),'gpio':object()},ownership=ownership,
            bindings=group.member_bindings(),irq_delivery_groups=(group,))


@pytest.mark.parametrize('values,key,retained',[
    ((1,0),['dma',0,'o_interrupt',1],True),
    ((1,1),['dma',0,'o_interrupt',1],False),
    ((0,1),['dma',0,'o_interrupt',1],False),
    ((1,0),['dma',0,'guessed-port',1],False),
    ((1,0),['dma',1,'o_interrupt',1],False),
])
def test_actual_or_frame_clears_preplanned_nonunique_or_wrong_source_context(values,key,retained):
    from types import SimpleNamespace
    group,state,pulses=world()
    for i,(binding,value) in enumerate(zip(group.member_bindings(),values)):
        observe(state,pulses,binding,value,i+1)
    state.begin_step(1)
    runner=object.__new__(ScenarioRunner)
    runner._irq_group_states={group.group_id:state}
    runner._irq_group_adapters={group.member_bindings()[0]:{'physical_port':'o_interrupt'},
        group.member_bindings()[1]:{'physical_port':'interrupt'}}
    cpu=SimpleNamespace(_next_irq_input_context={'source_output_key':key})
    cpu.set_next_irq_input_context=lambda value:setattr(cpu,'_next_irq_input_context',value)
    runner._guard_irq_group_input_context('core',cpu)
    assert (cpu._next_irq_input_context is not None) is retained
