"""Actual completed-access seals are detached observations, never certificates."""
import pytest
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.scenario.test_ordinary_apb_access_runner import installed, deliver


def test_only_actual_finalized_accesses_are_exposed(native_factory):
    runner,cpu=installed(native_factory)
    observer=runner._ordinary_apb_access_evidence
    assert observer.completed_accesses()==()
    association=deliver(runner,cpu)[0]
    row,=observer.completed_accesses()
    assert row['association']=={k:v for k,v in association.items() if k not in ('kind','component','event_id','producer_event_id')}
    assert row['receipt']['access_id']==association['access_id']
    assert row['delivery']['source_delivery_confirmed'] is True
    assert row['cpu_response']==[row['receipt']['rdata'],0,association['source_transaction']['source_sequence']]
    assert row['ordinal']==1
    assert all(row[name] is False for name in ('grants_verified','grants_storage','grants_functional'))


def test_returned_and_public_journal_mutations_do_not_rewrite_sealed_access(native_factory):
    runner,cpu=installed(native_factory)
    deliver(runner,cpu)
    observer=runner._ordinary_apb_access_evidence
    original=observer.completed_accesses()
    changed=observer.completed_accesses();changed[0]['receipt']['rdata']=999
    observer._records[0]['status']='forged'
    event=runner._event_ref_by_id(original[0]['association']['delivery_event_id'])
    event['read_value']=999
    assert observer.completed_accesses()==original


def test_failed_callback_never_creates_completed_access_seal(native_factory):
    runner,cpu=installed(native_factory)
    target=runner.sessions['gpio_a']
    window=next(w for w in cpu.router.windows if w.device_id=='gpio_a')
    cpu._serve('data',0,window.base+12,0,15);cpu.mmio_read_count='bad'
    runner._append_external_events('cpu',len(runner._events))
    with pytest.raises(TypeError):runner._step_once('gpio_a')
    assert runner._ordinary_apb_access_evidence.completed_accesses()==()


def test_completed_access_export_still_rejects_actual_configuration_drift(native_factory):
    runner,cpu=installed(native_factory);deliver(runner,cpu)
    cpu.memory.initialization_seed+=1
    with pytest.raises(ValueError,match='memory-configuration-drift'):
        runner._ordinary_apb_access_evidence.completed_accesses()
