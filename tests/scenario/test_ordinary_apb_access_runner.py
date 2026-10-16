"""Ordinary association hooks, software-only native artifact fixtures."""
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory

def test_runner_exposes_explicit_before_begin_install(native_factory):
    runner=native_factory()
    assert callable(getattr(runner,'install_ordinary_apb_access_evidence',None))

def test_default_identity_and_trace_have_no_ordinary_channel(native_factory):
    runner=native_factory()
    assert 'ordinary_apb_access_evidence' not in runner.identity_document()
    assert runner.events==()

import pytest

def physical_transport(target):
    def complete(receipt):
        exports=target.artifact.runtime_document['physical_exports']
        for sample in receipt.payload['samples']:
            for phase in ('pre','post'):
                sample[phase]['physical']={row['runtime_name']:0 for row in exports}
        return receipt
    return software_transport(target,mutate=complete)

from tests.local_harness.test_ordinary_apb_access_receipts import software_transport

def installed(native_factory,*,max_records=8):
    runner=native_factory()
    for name in ('gpio_a','gpio_b'):
        target=runner.sessions[name]
        target.configure_ordinary_apb_access_receipts()
        physical_transport(target)
        target.step_local=lambda inputs:{}
    runner.install_ordinary_apb_access_evidence(max_records=max_records)
    runner.enable_event_journal()
    cpu=runner.sessions['cpu'];cpu._case_id='runner-software-case'
    runner._status='running'
    runner._events.append(dict(event_id=1,kind='software_fixture_start',component='cpu'))
    return runner,cpu

def deliver(runner,cpu,*,target='gpio_a',offset=12):
    window=next(w for w in cpu.router.windows if w.device_id==target)
    # Software-only fixture models consumption of the preceding CPU response.
    cpu._pending_data=None
    cpu._serve('data',0,window.base+offset,0,15)
    runner._append_external_events('cpu',len(runner._events))
    runner._step_once(target)
    return [row for row in runner.events if row.get('kind')=='ordinary_apb_access_association']

def test_actual_cpu_router_raw_base_journal_refs_are_independently_associated(native_factory):
    runner,cpu=installed(native_factory)
    records=deliver(runner,cpu)
    assert len(records)==1
    association=records[0]
    assert association['status']=='cpu_delivery_confirmed'
    raw=[row for row in runner.events if row.get('kind')=='local_tick_sample' and 'ordinary_apb_access_ref' in row]
    assert len(raw)==6
    protocol=[row for row in runner.events if row.get('event_type') in ('transaction_request','transaction_accept','transaction_response')]
    assert len(protocol)==3
    assert all(row['transaction_key'] is None for row in protocol)
    assert set(association['raw_event_refs'])=={row['event_id'] for row in raw}
    assert association['base_event_refs']==[row['event_id'] for row in protocol]
    assert runner.event_by_id(association['target_receipt_event_id'])['kind']=='ordinary_apb_target_receipt'
    assert runner.event_by_id(association['acceptance_event_id'])['kind']=='mmio_acceptance'
    assert runner.event_by_id(association['delivery_event_id'])['kind']=='mmio_delivery'
    assert not any(association[name] for name in ('grants_verified','grants_storage','grants_functional'))
    assert runner.ordinary_apb_access_evidence_snapshot() is not None
    assert 'ordinary_apb_access_evidence' in runner.identity_document()

def test_install_rejects_unconfigured_target_before_effect(native_factory):
    runner=native_factory()
    with pytest.raises(ValueError):runner.install_ordinary_apb_access_evidence()
    assert runner._ordinary_apb_access_evidence is None
    assert all(session.process is None for session in runner.sessions.values())

def test_second_same_value_target_keeps_separate_association(native_factory):
    runner,cpu=installed(native_factory)
    deliver(runner,cpu,target='gpio_a');records=deliver(runner,cpu,target='gpio_b')
    assert len(records)==2
    assert records[0]['access_id']!=records[1]['access_id']

def test_callback_failure_emits_incomplete_not_confirmed(native_factory):
    runner,cpu=installed(native_factory)
    window=next(w for w in cpu.router.windows if w.device_id=='gpio_a')
    cpu._serve('data',0,window.base+12,0,15)
    # Keep the actual CPU completed closure; fail its real counter update.
    cpu.mmio_read_count='bad'
    runner._append_external_events('cpu',len(runner._events))
    with pytest.raises(TypeError):runner._step_once('gpio_a')
    associations=[row for row in runner.events if row.get('kind')=='ordinary_apb_access_association']
    assert associations and all(row['status']=='incomplete' for row in associations)
    assert not cpu.router.deliveries
    key=cpu.router.acceptances[-1]['source_transaction']
    with pytest.raises(ValueError):cpu.router.ordinary_delivery_confirmation(key)

def test_capacity_preflight_rejects_second_target_command(native_factory):
    runner,cpu=installed(native_factory,max_records=1)
    deliver(runner,cpu)
    target=runner.sessions['gpio_a'];sequence=target._sequence
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._pending_data=None  # Model preceding response consumption before a new beat.
    cpu._serve('data',0,window.base+12,0,15)
    with pytest.raises(ValueError,match='ordinary-evidence-capacity'):
        runner._step_once('gpio_a')
    assert target._sequence==sequence

def test_capacity_guard_runs_before_native_target_step_command(native_factory):
    runner=native_factory();target=runner.sessions['gpio_a']
    calls=physical_transport(target)
    def step(inputs):
        target._take(target.command('STEP_GPIO',(0,0,0,0,15)))
        return {}
    target.step_local=step
    class RejectingObserver:
        def validate(self):pass
        def observe_event(self,record):pass
        def finalize_pending(self,*args,**kwargs):return ()
        def preflight_access(self,router,actual_target):raise ValueError('capacity full')
    runner._ordinary_apb_access_evidence=RejectingObserver()
    runner._status='running'
    cpu=runner.sessions['cpu'];cpu._case_id='software-source'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    with pytest.raises(ValueError,match='capacity full'):runner._step_once('gpio_a')
    assert calls==[]
    assert target._sequence==0

@pytest.mark.parametrize('policy',['warm_all','cold_all'])
def test_clean_software_reset_then_access_uses_new_epochs_and_generation(native_factory,policy):
    runner,cpu=installed(native_factory)
    previous=deliver(runner,cpu)[0]
    for session in runner.sessions.values():
        def reset(session=session):
            session.reset_epoch+=1
            if session is cpu:
                session._pending_data=None;session._queued_mmio=False
                session._sequences={channel:0 for channel in session._sequences}
            return {'cancelled_responses':0}
        session.reset_local=reset
    runner.reset_all(policy)
    latest=deliver(runner,cpu)[-1]
    assert latest['status']=='cpu_delivery_confirmed'
    assert latest['target_reset_epoch']==previous['target_reset_epoch']+1
    assert latest['memory_generation']==cpu.memory.generation
    assert latest['memory_generation']==previous['memory_generation']+(policy=='cold_all')
    assert latest['source_transaction']['source_epoch']==1
