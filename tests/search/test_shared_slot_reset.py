"""Shared provider reset fences using a real runner and simulated processes."""
from types import SimpleNamespace

import pytest

from tests.scenario.test_native_reset_recovery import _runner


def runtime():
    runner, sessions, memory = _runner()
    r = SimpleNamespace(runner=runner, memory=memory,cpu_id='cpu',
        _native_processes={name: session.process for name,session in sessions.items()})
    return r,runner,sessions,memory


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_rebind_checks_measured_barrier_and_new_processes(policy):
    from myfuzz.search.shared_slot_reset import capture_epoch, rebind_epoch
    r,runner,sessions,memory=runtime()
    previous=capture_epoch(r)
    before=memory.generation
    runner.reset_all(policy)
    barrier=next(event for event in runner.events_since(0) if event['kind']=='reset_barrier')
    r._native_processes={name: session.process for name,session in sessions.items()}
    actual=rebind_epoch(r,previous,barrier_event_id=barrier['event_id'])
    assert actual['command_epoch']==previous['command_epoch']+1
    assert all(value==1 for value in actual['epochs'].values())
    assert actual['memory_generation']==before+(policy=='cold_all')
    assert actual['barrier_event_id']==barrier['event_id']
    with pytest.raises(ValueError):
        rebind_epoch(r,actual,barrier_event_id=barrier['event_id'])


def test_rebind_rejects_unmeasured_reset_and_unbound_process():
    from myfuzz.search.shared_slot_reset import capture_epoch, rebind_epoch
    r,runner,sessions,_=runtime()
    previous=capture_epoch(r)
    with pytest.raises(ValueError):
        rebind_epoch(r,previous,barrier_event_id=1)
    runner.reset_all('warm_all')
    barrier=next(event for event in runner.events_since(0) if event['kind']=='reset_barrier')
    with pytest.raises(ValueError):
        rebind_epoch(r,previous,barrier_event_id=barrier['event_id'])


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_rebinding_installed_providers_drops_old_writer_scope(policy):
    from myfuzz.search.shared_slot_reset import capture_epoch
    from myfuzz.search import shared_slot_ram,shared_slot_pin_read
    r,runner,sessions,_=runtime()
    previous=capture_epoch(r)
    class Tracker:
        def __init__(self): self.floor=0
        def reset(self,*,event_id): self.floor=event_id
    tracker=Tracker()
    ram=shared_slot_ram._Installation()
    pin=shared_slot_pin_read._Installation()
    shared_slot_ram._INSTALLATIONS[ram]=dict(runtime=r,tracker=tracker,cursor=0,
                                               reset_scope=previous)
    shared_slot_pin_read._INSTALLATIONS[pin]=dict(runtime=r,writers={'old':1},
                                                   reset_scope=previous)
    runner.reset_all(policy)
    barrier=next(event for event in runner.events_since(0) if event['kind']=='reset_barrier')
    r._native_processes={name:session.process for name,session in sessions.items()}
    ram.rebind_after_reset(barrier_event_id=barrier['event_id'])
    pin.rebind_after_reset(barrier_event_id=barrier['event_id'])
    assert tracker.floor==barrier['event_id']
    assert shared_slot_ram._INSTALLATIONS[ram]['cursor']==barrier['event_id']
    assert shared_slot_pin_read._INSTALLATIONS[pin]['writers']=={}
    assert shared_slot_pin_read._INSTALLATIONS[pin]['epoch_start_event']==barrier['event_id']


@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_ram_tracker_accepts_new_writes_but_never_old_writes_after_reset(policy):
    from myfuzz.search import shared_slot_ram
    from myfuzz.search.shared_slot_reset import capture_epoch
    from myfuzz.scenario.live_memory_prerequisites import LiveMemoryEffectTracker
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.runner import ScenarioRunner
    from tests.scenario.test_memory_dependency_runner import wired
    from tests.scenario.test_native_reset_recovery import _Process
    _,cpu=wired()
    cpu.router=DataflowRouter(())
    runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
    runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
    runner._status='running'
    cpu._process=_Process();cpu._execution='old-execution'
    r=SimpleNamespace(runner=runner,memory=cpu.memory,cpu_id='cpu',
                      _native_processes={'cpu':cpu.process})
    tracker=LiveMemoryEffectTracker(consumer=runner._memory_dependency_consumer)
    cpu._serve('data',1,0x20000,85,15);runner._append_external_events('cpu',1)
    old=tracker.retained_ram_witnesses('ram',0)[0]
    handle=shared_slot_ram._Installation()
    shared_slot_ram._INSTALLATIONS[handle]=dict(runtime=r,tracker=tracker,cursor=runner.event_count,
                                                reset_scope=capture_epoch(r))
    def reset_local():
        cpu.reset_epoch+=1;cpu._process=_Process();cpu._execution='new-execution'
        cpu._sequences={'instr':0,'data':0}
        return {'cancelled_responses':0}
    cpu.reset_local=reset_local
    runner.reset_all(policy)
    barrier=next(event for event in runner.events_since(0) if event['kind']=='reset_barrier')
    r._native_processes={'cpu':cpu.process}
    handle.rebind_after_reset(barrier_event_id=barrier['event_id'])
    assert tracker.retained_ram_witnesses('ram',0)==()
    cpu._serve('data',1,0x20000,85,15);runner._append_external_events('cpu',1)
    cpu._serve('data',0,0x20000,0,15);runner._append_external_events('cpu',1)
    # The reset event may be drained lazily after the consumer has already
    # authenticated the later write. Its fence is the reset event, not now.
    tracker.consume_event({'kind':'cpu_reset','event_id':barrier['event_id']+1})
    fresh=tracker.retained_ram_witnesses('ram',0)
    assert len(fresh)==1 and fresh[0].event_id>barrier['event_id']
    assert fresh[0].event_id!=old.event_id
    assert runner.memory_dependency_evidence_report()['counts']['verified']>=4


def test_pin_case_reading_excludes_pre_barrier_cases_and_keeps_new_cases(monkeypatch):
    from myfuzz.search import shared_slot_pin_read as pin
    old=SimpleNamespace(case_id='old');new=SimpleNamespace(case_id='new')
    receipts={'old':SimpleNamespace(event_start=0), 'new':SimpleNamespace(event_start=8)}
    session=SimpleNamespace(cases=(old,new),case_receipt=lambda case_id:receipts[case_id],
        _receipts={name:(case,receipts[name]) for name,case in [('old',old),('new',new)]})
    state={'session':session,'epoch_start_event':8}
    monkeypatch.setattr(pin,'_validate_writer_receipt',lambda *args:None)
    def row(case_id,index):
        return dict(case_id=case_id,session_case_index=index,status='passed',flow='F5',
            certificate=dict(status='certified',case_id=case_id,flow_id='F5'))
    with pytest.raises(ValueError,match='pre_reset_case'):
        pin._case(state,row('old',0))
    assert pin._case(state,row('new',1))[0] is new
    # The old writer is skipped before dereferencing its previous source or receipt.
    pin._refresh_writers(state,[row('old',0)])
