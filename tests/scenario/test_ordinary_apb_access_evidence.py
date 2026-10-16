"""Actual-object collector exercised with parsed software transport, no RTL."""
import pytest
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory, software_transport


def installed(native_factory, max_records=2):
    runner=native_factory();target=runner.sessions['gpio_a']
    target.configure_ordinary_apb_access_receipts(max_records=max_records)
    runner.install_ordinary_apb_access_evidence(max_records=max_records)
    return runner,target


def test_collector_requires_actual_runner():
    from myfuzz.scenario.ordinary_apb_access_evidence import OrdinaryApbAccessEvidence
    with pytest.raises(ValueError):OrdinaryApbAccessEvidence(object())


def test_actual_queued_access_joins_private_command_and_callback(native_factory):
    runner,target=installed(native_factory);software_transport(target,rdata=17)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence
    observer.preflight_access(cpu.router,target)
    cpu.router.drain_one('gpio_a')
    runner._append_external_events('cpu',1)
    runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a']=target.local_ticks
    runner._drain_tick_samples(1)
    rows=observer.finalize_pending(cpu.router,target)
    assert len(rows)==1
    assert rows[0]['status']=='cpu_delivery_confirmed'
    assert len(rows[0]['raw_event_refs'])==6
    assert len(rows[0]['base_event_refs'])==3
    assert all(rows[0][name] is False for name in ('grants_verified','grants_storage','grants_functional'))
    assert observer.finalize_pending(cpu.router,target)==()
    detached=observer.snapshot();detached['records'].clear()
    assert len(observer.snapshot()['records'])==1


def test_detached_journal_document_cannot_register_evidence(native_factory):
    runner,target=installed(native_factory)
    observer=runner._ordinary_apb_access_evidence
    with pytest.raises(ValueError):observer.observe_event({'event_id':1,'kind':'local_tick_sample'})
    assert observer.snapshot()['status']=='incomplete'


@pytest.mark.parametrize('mutation',['content','drop','duplicate'])
def test_raw_span_corruption_never_confirms_delivery(native_factory,mutation):
    runner,target=installed(native_factory);software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    cpu.router.drain_one('gpio_a');runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
    if mutation=='content':target._samples[0]['pre']['backend']['trace_prdata']=1
    elif mutation=='drop':target._samples.pop()
    else:target._samples.append(target._samples[-1].copy())
    runner.local_ticks['gpio_a']=target.local_ticks
    try:runner._drain_tick_samples(1)
    except ValueError:pass
    rows=observer.finalize_pending(cpu.router,target,failure='drain_failed' if mutation=='duplicate' else None)
    assert rows[0]['status']=='incomplete'
    assert observer.snapshot()['status']=='incomplete'


def test_registry_replacement_is_refused_before_command(native_factory):
    runner,target=installed(native_factory)
    helper=target._ordinary_apb_receipts
    helper._records=dict(helper._records)
    with pytest.raises(ValueError):runner._ordinary_apb_access_evidence.validate()


def test_capacity_preflight_does_not_consume_second_command(native_factory):
    runner,target=installed(native_factory,max_records=1);calls=software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    cpu.router.drain_one('gpio_a');runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
    observer.finalize_pending(cpu.router,target)
    cpu._serve('data',0,window.base+12,0,15)
    with pytest.raises(ValueError):observer.preflight_access(cpu.router,target)
    assert len(calls)==1


def test_conflicting_callback_confirmation_is_incomplete_not_target_success(native_factory):
    runner,target=installed(native_factory);software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    key=cpu.router._queued[0][1];cpu.router.drain_one('gpio_a')
    runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
    cpu.router._ordinary_delivery_confirmations[key]['read_value']=99
    assert observer.finalize_pending(cpu.router,target)[0]['status']=='incomplete'


def test_projector_metadata_drift_refuses_before_command(native_factory):
    runner,target=installed(native_factory)
    runner._ip_protocol_event_normalizers['gpio_a'].endpoint_id='foreign.endpoint'
    with pytest.raises(ValueError):runner._ordinary_apb_access_evidence.validate()


def test_repeated_preflight_revalidates_actual_queued_payload(native_factory):
    runner,target=installed(native_factory);software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    cpu.router._queued[0][2]['address']+=4
    with pytest.raises(ValueError):observer.preflight_access(cpu.router,target)


def test_replaced_noop_cpu_callback_refuses_before_target_command(native_factory):
    runner,target=installed(native_factory);calls=software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    queued=cpu.router._queued[0]
    cpu.router._queued[0]=(*queued[:-1],lambda _:None)
    with pytest.raises(ValueError):runner._ordinary_apb_access_evidence.preflight_access(cpu.router,target)
    assert calls==[] and cpu._pending_data is None


def test_queued_cpu_can_advance_waiting_ticks_without_changing_request(native_factory):
    runner,target=installed(native_factory);software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    cpu.local_ticks+=3
    observer.preflight_access(cpu.router,target)
    cpu.router.drain_one('gpio_a');runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
    assert observer.finalize_pending(cpu.router,target)[0]['status']=='cpu_delivery_confirmed'


def test_missing_queued_delivery_journal_ref_is_incomplete(native_factory):
    runner,target=installed(native_factory);software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    observer=runner._ordinary_apb_access_evidence;observer.preflight_access(cpu.router,target)
    cpu.router.drain_one('gpio_a')
    cpu.router.deliveries.clear()
    runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
    runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
    assert observer.finalize_pending(cpu.router,target)[0]['status']=='incomplete'
    assert observer.snapshot()['status']=='incomplete'


@pytest.mark.parametrize('index,value',[(4,1),(5,0xdeadbeef),(6,16)])
def test_preflight_recomputes_queued_bus_lane_values(native_factory,index,value):
    runner,target=installed(native_factory);calls=software_transport(target)
    cpu=runner.sessions['cpu'];cpu._case_id='stream'
    window=next(w for w in cpu.router.windows if w.target is target)
    cpu._serve('data',0,window.base+12,0,15)
    row=list(cpu.router._queued[0]);row[index]=value;cpu.router._queued[0]=tuple(row)
    with pytest.raises(ValueError):runner._ordinary_apb_access_evidence.preflight_access(cpu.router,target)
    assert calls==[]
