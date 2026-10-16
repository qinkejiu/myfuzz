"""Closed Session opt-in and fresh reconstruction, pure rendered software fixtures."""
import json
import pytest
from tests.scenario.test_register_program_replay import actual_factory, adapter
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session
from myfuzz.scenario.genome import ScenarioGenome


def session(actual_factory):
    result=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    result.declare_instruction_slots('cpu',0x11000,32)
    return result


@pytest.mark.parametrize('adapter_first',[False,True])
def test_prebegin_hook_is_optin_and_works_either_side_of_adapter(actual_factory,adapter_first):
    result=session(actual_factory)
    if adapter_first:adapter(result)
    config=result.configure_ordinary_apb_access_evidence(max_records=2)
    if not adapter_first:adapter(result)
    assert config['max_records']==2
    assert all(result.runner.sessions[name].ordinary_apb_access_receipts_enabled for name in ('gpio_a','gpio_b'))
    result.begin();trace=result.finish();doc=json.loads(result.encode_plan())
    ordinary=doc['register_programs']['ordinary_apb_access_evidence']
    assert ordinary['schema_version']=='ordinary_apb_access_session.v1'
    assert ordinary['configuration']==config
    assert ordinary['state']['records']==[]
    assert result._manifest_document['ordinary_apb_access_evidence_configuration']==config
    def install(fresh):
        fresh.configure_ordinary_apb_access_evidence(max_records=2)
        return adapter(fresh)
    assert replay_online_session(result.encode_plan(),actual_factory,trace,register_runtime_factory=install).matches


def test_default_off_keeps_plan_and_manifest_fields_absent(actual_factory):
    result=session(actual_factory);adapter(result);result.begin();result.finish()
    assert 'ordinary_apb_access_evidence' not in json.loads(result.encode_plan())['register_programs']
    assert 'ordinary_apb_access_evidence_configuration' not in result._manifest_document


def test_hook_rejects_late_or_boolean_capacity_without_partial_install(actual_factory):
    result=session(actual_factory)
    with pytest.raises(ValueError):result.configure_ordinary_apb_access_evidence(max_records=True)
    assert result.runner._ordinary_apb_access_evidence is None
    assert all(result.runner.sessions[n]._ordinary_apb_receipts is None for n in ('gpio_a','gpio_b'))
    result.begin()
    with pytest.raises(ValueError):result.configure_ordinary_apb_access_evidence()


def observed_factory(actual_factory, *, callback_failure=False):
    from tests.local_harness.test_ordinary_apb_access_receipts import software_transport
    def factory():
        runner=actual_factory();begin=runner.begin_test
        def start(case_id):
            begin(case_id);software_transport(runner.sessions['gpio_a'],rdata=17)
        runner.begin_test=start
        def step(order):
            cpu=runner.sessions['cpu'];target=runner.sessions['gpio_a']
            window=next(w for w in cpu.router.windows if w.target is target)
            if callback_failure:cpu.mmio_read_count='bad'
            cpu._serve('data',0,window.base+12,0,15)
            observer=runner._ordinary_apb_access_evidence
            observer.preflight_access(cpu.router,target)
            failure=None
            try:cpu.router.drain_one('gpio_a')
            except BaseException as error:
                failure=type(error).__name__;raise
            finally:
                runner._append_external_events('cpu',1);runner._drain_ordinary_apb_events(1)
                runner.local_ticks['gpio_a']=target.local_ticks;runner._drain_tick_samples(1)
                runner._finalize_ordinary_apb_access(cpu.router,target,failure=failure)
        runner.step_batch=step
        return runner
    return factory


def test_saved_nonempty_state_is_fresh_recomputed_not_restored(actual_factory):
    from tests.scenario.test_register_program_runtime import request
    factory=observed_factory(actual_factory);result=session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=2);runtime=adapter(result)
    result.begin();runtime.submit(request(target_instance='gpio_a'));trace=result.finish();plan=result.encode_plan()
    saved=json.loads(plan)['register_programs']['ordinary_apb_access_evidence']
    assert saved['state']['counts']['cpu_delivery_confirmed']==1
    assert len(saved['state']['records'][0]['raw_event_refs'])==6
    def install(fresh):
        fresh.configure_ordinary_apb_access_evidence(max_records=2);return adapter(fresh)
    assert replay_online_session(plan,factory,trace,register_runtime_factory=install).matches
    document=json.loads(plan)
    record=document['register_programs']['ordinary_apb_access_evidence']['state']['records'][0]
    record['raw_event_refs']=[ref+1000 for ref in record['raw_event_refs']]
    from dataclasses import replace
    import hashlib
    from myfuzz.scenario.session_runtime import _canonical
    changed=_canonical(document)
    comparison=replay_online_session(changed,factory,replace(trace,genome_sha256=hashlib.sha256(changed).hexdigest()),register_runtime_factory=install)
    assert not comparison.matches
    assert comparison.difference_context['register_program_state_match'] is False


@pytest.mark.parametrize('mutation',['unknown','bool_capacity','state_hash','grant','slot_bool'])
def test_closed_saved_ordinary_data_rejected_before_factory(actual_factory,mutation):
    from myfuzz.scenario.session_runtime import validate_register_program_plan
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=2);adapter(result)
    document=json.loads(result.encode_plan());saved=document['register_programs']['ordinary_apb_access_evidence']
    if mutation=='unknown':saved['authority']={}
    elif mutation=='bool_capacity':saved['configuration']['max_records']=True
    elif mutation=='state_hash':saved['state']['configuration_sha256']='f'*64
    elif mutation=='grant':saved['configuration']['grants_verified']=True
    else:saved['configuration']['bindings'][0]['memory']['instruction_slots'][0][1]=True
    with pytest.raises(ValueError):validate_register_program_plan(document)


def test_failed_installation_rolls_back_all_target_modes(actual_factory,monkeypatch):
    result=session(actual_factory)
    def failure(**kwargs):raise ValueError('collector installation interrupted')
    monkeypatch.setattr(result.runner,'install_ordinary_apb_access_evidence',failure)
    with pytest.raises(ValueError):result.configure_ordinary_apb_access_evidence(max_records=2)
    assert result.runner._ordinary_apb_access_evidence is None
    assert all(result.runner.sessions[n]._ordinary_apb_receipts is None for n in ('gpio_a','gpio_b'))


def test_configuration_and_sources_are_checked_before_begin(actual_factory,monkeypatch):
    import myfuzz.scenario.session_runtime as module
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=2);adapter(result)
    source=module._ordinary_apb_access_source_files
    def drift(paths=None):
        rows=source(paths);rows[0]['sha256']='f'*64;return rows
    monkeypatch.setattr(module,'_ordinary_apb_access_source_files',drift)
    with pytest.raises(ValueError):result.begin()
    assert not result._begun and result.runner._status=='created'


def test_schema17_retains_real_incomplete_callback_prefix_and_fresh_replays(actual_factory):
    from tests.scenario.test_register_program_runtime import request
    factory=observed_factory(actual_factory,callback_failure=True);result=session(factory)
    result.configure_ordinary_apb_access_evidence(max_records=2);runtime=adapter(result)
    result.begin()
    with pytest.raises(TypeError):runtime.submit(request(target_instance='gpio_a'))
    trace=result.finish();plan=result.encode_plan();doc=json.loads(plan)
    assert doc['schema_version']==17
    state=doc['register_programs']['ordinary_apb_access_evidence']['state']
    assert state['status']=='incomplete'
    assert state['records'][0]['status']=='incomplete'
    assert state['records'][0]['delivery_event_id'] is None
    def install(fresh):
        fresh.configure_ordinary_apb_access_evidence(max_records=2);return adapter(fresh)
    assert replay_online_session(plan,factory,trace,register_runtime_factory=install).matches


def test_saved_complete_state_cannot_contain_incomplete_record(actual_factory):
    from tests.scenario.test_register_program_runtime import request
    from myfuzz.scenario.session_runtime import validate_register_program_plan
    result=session(observed_factory(actual_factory));result.configure_ordinary_apb_access_evidence(max_records=2)
    runtime=adapter(result);result.begin();runtime.submit(request(target_instance='gpio_a'));result.finish()
    doc=json.loads(result.encode_plan());record=doc['register_programs']['ordinary_apb_access_evidence']['state']['records'][0]
    record['status']='incomplete';record['reason']='missing_actual_queued_delivery'
    doc['register_programs']['ordinary_apb_access_evidence']['state']['counts']['cpu_delivery_confirmed']=0
    with pytest.raises(ValueError):validate_register_program_plan(doc)


@pytest.mark.parametrize('operation',['advance','reset'])
def test_afterbegin_source_drift_refuses_session_command_without_effects(actual_factory,monkeypatch,operation):
    import myfuzz.scenario.session_runtime as module
    from tests.scenario.test_register_program_runtime import request
    result=session(actual_factory);result.configure_ordinary_apb_access_evidence(max_records=2);runtime=adapter(result)
    result.begin()
    if operation=='reset':runtime.submit(request(target_instance='gpio_a'))
    calls=[]
    result.runner.step_batch=lambda order:calls.append(('step',order))
    result.runner.reset_all=lambda policy:calls.append(('reset',policy))
    source=module._ordinary_apb_access_source_files
    def drift(paths=None):
        rows=source(paths)
        next(row for row in rows if row['path']=='src/myfuzz/local_harness/wire.py')['sha256']='f'*64
        return rows
    monkeypatch.setattr(module,'_ordinary_apb_access_source_files',drift)
    with pytest.raises(ValueError,match='ordinary-apb-session-source-drift'):
        result.advance_initial(('cpu',)) if operation=='advance' else result.reset('warm_all')
    assert calls==[]
    assert result._warmup_advances==[] and result._reset_operations==[]


def test_real_bootstrap_byte_slot_count_uses_actual_region_capacity(actual_factory):
    result=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),actual_factory())
    result.declare_instruction_slots('cpu',0x11000,31616)
    result.configure_ordinary_apb_access_evidence(max_records=2);adapter(result)
    doc=json.loads(result.encode_plan())['register_programs']['ordinary_apb_access_evidence']
    slots=doc['configuration']['bindings'][0]['memory']['instruction_slots']
    assert len(slots)==126464
    assert slots[0]==['ram',4096] and slots[-1]==['ram',130559]


def test_saved_cross_kind_event_ref_reuse_is_rejected(actual_factory):
    from tests.scenario.test_register_program_runtime import request
    from myfuzz.scenario.session_runtime import validate_register_program_plan
    result=session(observed_factory(actual_factory));result.configure_ordinary_apb_access_evidence(max_records=2)
    runtime=adapter(result);result.begin();runtime.submit(request(target_instance='gpio_a'));result.finish()
    doc=json.loads(result.encode_plan());record=doc['register_programs']['ordinary_apb_access_evidence']['state']['records'][0]
    record['delivery_event_id']=record['target_receipt_event_id']
    with pytest.raises(ValueError):validate_register_program_plan(doc)


def test_command_guard_does_not_copy_full_observation_configuration(actual_factory, monkeypatch):
    result=session(actual_factory)
    result.configure_ordinary_apb_access_evidence(max_records=2)
    observer=result._ordinary_apb_observer
    monkeypatch.setattr(observer,'snapshot',lambda:pytest.fail('command guard copied full snapshot'))
    result._register_capability_preflight()
