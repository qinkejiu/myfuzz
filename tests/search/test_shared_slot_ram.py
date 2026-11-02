"""Shared-slot RAM current-version and finite shared catalog contracts."""
import pytest
from myfuzz.search.shared_slot_ram import install_shared_slot_ram_consumer, match_current_read
from myfuzz.search.shared_slot_ram_adapter import SharedSlotSelector, shared_slot_records
from tests.search.test_ram_search import field, relation

ROWS=['F3:55000000','F1:03200000','F4:0001000000','F5:0000000100000000','F2:08100040','F6:0110c00008000000']


def test_pin_feedback_requires_a_declared_f5_pin():
    from myfuzz.search.shared_slot_ram_adapter import _pin_feedback_applicable
    f2 = {'execution_contract': {'register': 'PADIN', 'target_component': 'peripheral'}}
    assert _pin_feedback_applicable(f2, {'pin': {'component': 'peripheral'}})
    assert not _pin_feedback_applicable(f2, {'component': 'timer', 'direction': 'CPU_TO_IP'})
    assert not _pin_feedback_applicable(f2, {'pin': {'component': 'different'}})
    assert not _pin_feedback_applicable({'execution_contract': {'register': 'PRESCALER',
        'target_component': 'peripheral'}}, {'pin': {'component': 'peripheral'}})


def test_catalog_accepts_full_word_apb_target_record():
    rows=['F3:55000000','F1:03200000','F4:55000000','F5:0000000100000000',
          'F2:04300040','F6:0110c00008000000']
    assert shared_slot_records(rows)
    selector=SharedSlotSelector(None,flow='mixed',records=rows,policy='state',seed=7,cases=8)
    assert {a.operator for a in selector.catalog.actions} == {f'F{i}' for i in range(1,7)}
    selector._pin_mode = False
    goal, snapshot = selector.view({'status':'unknown'}, {'status':'unknown'})
    assert goal.root == 'ram:consumed'
    assert snapshot.get('ram:consumed').status == 'unknown'

def test_saved_or_duck_runtime_cannot_install():
    with pytest.raises(ValueError,match='actual_shared_slot'):
        install_shared_slot_ram_consumer(type('Fake',(),{})())

def test_same_version_exact_four_bytes_required():
    current=field()
    observation={'byte_relations':[dict(byte_offset=r['byte_offset'],byte_version=r['version'],value=r['value'],write_event_id=r['observation_event_id']) for r in current['byte_resources']]}
    assert match_current_read(current,observation)
    observation['byte_relations'][0]['byte_version']=[0,2]
    assert not match_current_read(current,observation)
    observation['byte_relations']=[]
    assert not match_current_read(current,observation)

def test_whole_catalog_is_preserved_and_one_and_goal():
    assert shared_slot_records(ROWS)
    selector=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='state',seed=7,cases=8)
    assert len(selector.catalog.actions)==len(ROWS)
    assert {a.operator for a in selector.catalog.actions}=={f'F{i}' for i in range(1,7)}
    goal,snapshot=selector.view({'status':'unknown'},{'status':'unknown'})
    assert goal.nodes[goal.root].mode=='all'
    assert set(goal.nodes[goal.root].prerequisites)=={'ram:consumed','pin:consumed:1'}
    assert snapshot.get('ram:written').status=='unknown'
    assert snapshot.get('pin:enabled').status=='unknown'
    assert not shared_slot_records(['F3:55000000','F1:03200000','F9:00000000'])

def test_non_ram_overwrite_censors_old_writer_without_settling_current_twice():
    selector=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='state',seed=7,cases=8)
    goal,snapshot=selector.view({'status':'unknown'},{'status':'unknown'})
    decision=selector.scheduler.choose(goal,snapshot,selector.catalog)
    old=field()
    selector.credit.pending[decision.id]={'case_id':'writer','resource':__import__('myfuzz.search.ram_actions',fromlist=['ram_identity']).ram_identity(old)}
    selector.credit.writers[decision.id]=dict(selector.credit.pending[decision.id])
    selector.credit.costs[decision.id]=10
    rows=selector.invalidate_ram(field(version=2))
    assert len(rows)==1 and rows[0]['reward'] in (None,0)
    assert not selector.credit.pending and not selector.credit.writers


def test_actual_installed_tracker_same_value_overwrite_reset_without_host_read(monkeypatch):
    from myfuzz.search.shared_slot_ram import _current
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    from tests.scenario.test_classified_feedback import memory
    runner,cpu=memory()
    tracker=LiveMemoryEffectTracker(consumer=runner._memory_dependency_consumer)
    s=dict(tracker=tracker,address=0x20000,image={'port':'ram','range':[0x20000,0x20fff]},
        runtime=type('Context',(),{'cpu_id':'cpu'})(),cpu=cpu,memory=cpu.memory)
    monkeypatch.setattr('myfuzz.search.shared_slot_ram._attribution',
        lambda state,rows,needed:{i:{'case_id':'writer'} for i in needed})
    rows=[dict(case_id='writer',flow='F3',status='passed')]
    cpu._serve('data',1,0x20000,85,15);runner._append_external_events('cpu',1)
    event_id=tracker.retained_ram_witnesses('ram',0)[0].event_id
    rows[0]['certificate']=dict(status='certified',case_id='writer',flow_id='F3',ram_address=0x20000,memory_store_observation={'memory_write_event':event_id})
    first=_current(s,rows)
    # Callback-only fixture has no native OBI store/response certificate.
    assert first['status']=='observed' and first['value']==85
    assert first['writer_attributed'] is False
    count=len(cpu.service.ledger._entries)
    assert _current(s,rows)==first
    assert len(cpu.service.ledger._entries)==count
    cpu._serve('data',1,0x20000,85,15);runner._append_external_events('cpu',1)
    second=_current(s,rows)
    assert second['value']==first['value']
    assert second['byte_resources']!=first['byte_resources']
    tracker.reset(event_id=runner.event_count)
    assert _current(s,rows)['status']=='unknown'


def test_unaligned_component_epoch_is_not_relabelled():
    selector=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='state',seed=7,cases=8)
    ram=field();pin=dict(status='observed',reset_epoch=1,enabled=True,writer_attributed=True,value=1)
    _,snapshot=selector.view(ram,pin)
    assert snapshot.get('ram:written').status=='unknown'
    assert snapshot.get('pin:written:1').status=='satisfied'


def test_attribution_uses_actual_session_metadata_and_selected_events_only():
    from tests.scenario.test_session_runtime_paths import configured,case
    from myfuzz.search.shared_slot_ram import _attribution
    from myfuzz.search.gpio_relations import _bind_case_session
    from myfuzz.scenario.runner import ScenarioRunner
    session=configured();session.begin();submitted=case(session)
    try:
        session.submit_case(submitted)
        receipt=session.case_receipt(submitted.case_id)
        state=dict(session=session,runner=session.runner,case_session=_bind_case_session(session,session.runner),
            methods=(ScenarioRunner._event_refs_since,ScenarioRunner.event_by_id))
        rows=[dict(case_id=submitted.case_id,session_case_index=0)]
        event_id=receipt.events[0]['event_id']
        assert _attribution(state,rows,{event_id})=={event_id:{'case_id':submitted.case_id,'case_index':0}}
        with pytest.raises(ValueError,match='sealed_case_drift'):
            _attribution(state,[dict(rows[0],case_id='forged')],{event_id})
    finally:session.finish()


def test_ram_credit_same_version_relation_deduplicates_across_new_versions():
    from myfuzz.search.ram_actions import RamCredit,RamActionSpace,ram_view
    from myfuzz.search.policy import Policy
    space=RamActionSpace(values=(85,),write_source='F3',read_source='F1')
    policy=Policy(seed=7,mode='state',max_decisions=4,epsilon=0)
    credit=RamCredit(policy);accepted=[]
    for index in range(2):
        current=field(version=index+1,writer='writer'+str(index))
        g,s=ram_view({'status':'unknown'},{'relations':[]},values=space.values)
        writer=policy.choose(g,s,space.catalog)
        assert writer.action_id.startswith('ram:write:')
        credit.observe(writer,'writer'+str(index),current,{'relations':[]},10)
        g,s=ram_view(current,{'relations':[]},values=space.values)
        reader=policy.choose(g,s,space.catalog)
        assert reader.action_id=='ram:read'
        answer=credit.observe(reader,'reader'+str(index),current,{'relations':[relation(current,'reader'+str(index))]},20)
        accepted.append(answer['credited_relations'])
    assert len(accepted[0])==1 and accepted[1]==[]


def test_shared_family_routing_settles_once_and_fresh_costs_do_not_replace_measurements(monkeypatch):
    from types import SimpleNamespace
    from myfuzz.search import shared_slot_ram_adapter as module
    rows=[];selector=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='uniform',seed=7,cases=32)
    # This is a lifecycle wiring test, not an authority fixture. Both live
    # observers explicitly return no evidence; no relation can earn a reward.
    handle=SimpleNamespace(current_state=lambda:{'status':'unknown'},
        observe_case=lambda case_id:dict(status='unknown',relations=[]))
    pin=SimpleNamespace(current_state=lambda:{'status':'unknown'},
        observe_case=lambda case_id:dict(status='unknown',relations=[],writer=None,read_case_id=case_id))
    selector._handle=handle;selector._pin_handle=pin;selector._runtime=object()
    selector.pin_credit.authenticator=lambda h,r:r
    monkeypatch.setattr('myfuzz.integration.shared_f6_slots.flow_records',lambda r:rows)
    seen={'RAM':[],'PIN':[]}
    ram_observe=selector.credit.observe;pin_observe=selector.pin_credit.observe
    def ram(*args):seen['RAM'].append(args[1]);return ram_observe(*args)
    def padin(*args):seen['PIN'].append(args[2]);return pin_observe(*args)
    monkeypatch.setattr(selector.credit,'observe',ram)
    monkeypatch.setattr(selector.pin_credit,'observe',padin)
    selector.replay_costs([dict(settlement_cost_ns=11,policy_cost_ns=22)]*32)
    selector.start_search_clock(lambda:float(len(rows)),0)
    for i in range(32):
        row=selector.choose();case_id=f'case:{i}'
        rows.append(dict(status='passed',flow=row[:2],raw_hex=row[3:],case_id=case_id))
        selector.settle(row)
    selector.finish_search_clock()
    assert set(r[:2] for r in selector.sequence)=={f'F{i}' for i in range(1,7)}
    assert set(seen['RAM'])=={r['case_id'] for r in rows if r['flow'] in ('F1','F3')}
    assert set(seen['PIN'])=={r['case_id'] for r in rows if r['flow'] in ('F2','F5')}
    assert all(not t['credited_relations'] for t in selector.transitions)
    assert all(t['policy_cost_ns']==22 and t['settlement_cost_ns']==11 for t in selector.transitions)
    measurements=selector.measurements(mode='fresh')
    assert measurements['certified_events']==[] and measurements['search_seconds']==32
    assert measurements['measured_action_cost_ns']!=[22]*32
    assert len(selector.scheduler._settled)==32


def test_pin_consumed_frontier_requires_current_writer_version_not_historical_value():
    selector=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='state',seed=7,cases=8)
    pin=dict(status='observed',component='gpio',pin=8,reset_epoch=0,enabled=True,
        writer_attributed=True,value=1,writer_case_id='writer',resource_identity='version-A')
    relation=dict(status='verified',reward_eligible=True,component='gpio',pin=8,reset_epoch=0,
        value=1,writer_case_id='writer',resource_identity='version-A')
    selector._completed_values.add(1)  # historical semantic coverage is separate
    selector._pin_relations=[relation]
    # Use one declared pin value so this test inspects its consumed condition,
    # rather than pin_view advancing to the other value's exploration goal.
    selector.values=(1,)
    def status(current):return selector.view({'status':'unknown'},current)[1].get('pin:consumed:1').status
    assert status(pin)=='satisfied'
    for changed in ({'resource_identity':'version-B'}, {'writer_case_id':'new-writer'},
            {'reset_epoch':1}, {'value':0}, {'component':'other'}, {'pin':9},
            {'status':'unknown'}, {'enabled':False}, {'writer_attributed':False}):
        assert status(dict(pin,**changed))=='unknown'
    assert selector._completed_values=={1}
    fresh=SharedSlotSelector(None,flow='mixed',records=ROWS,policy='state',seed=7,cases=8)
    fresh.values=(1,)
    assert fresh.view({'status':'unknown'},pin)[1].get('pin:consumed:1').status=='unknown'


def test_installed_bounded_feedback_horizon_retains_adjacent_read_gap_then_expires():
    from tests.scenario.test_memory_dependency_runner import wired
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    runner,cpu=wired()
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64,max_event_gap=8192)
    tracker=LiveMemoryEffectTracker(consumer=runner._memory_dependency_consumer)
    cpu._serve('data',1,0x20000,85,15);runner._append_external_events('cpu',1)
    writer=tracker.retained_ram_witnesses('ram',0)[0]
    def advance_to_gap(gap):
        while runner.event_count<writer.event_id+gap:
            runner._events.append({'event_id':runner.event_count+1,'kind':'idle'})
        tracker.consume_event({'kind':'idle'})
    advance_to_gap(4662)  # genuine shared RAMv2 store-to-settlement gap
    assert tracker.retained_ram_witnesses('ram',0)[0].version==writer.version
    advance_to_gap(8193)
    assert tracker.retained_ram_witnesses('ram',0)==()
