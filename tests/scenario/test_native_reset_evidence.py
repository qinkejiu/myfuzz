"""Actual Runner/Task1 software wire mechanics; never native eligibility."""
from pathlib import Path
import inspect
import json
import pytest
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.local_harness.test_native_reset_observation import wire_local


def configured_runner(native_factory,tmp_path,*,lifecycles=8,commands=32):
    runner=native_factory()
    for name in ('gpio_a','gpio_b'):
        target=runner.sessions[name];directory=tmp_path/name;directory.mkdir()
        local=wire_local(lambda:type('WireFixtureSelection',(),{'sessions':{'gpio_a':target}})(),directory)
        physical={r['runtime_name']:0 for r in target.artifact.runtime_document['physical_exports']}
        worker=target._binary;worker.write_text(worker.read_text().replace('physical={}',f'physical={physical!r}'))
        assert local is target
        target.configure_native_reset_observation(max_lifecycles=lifecycles,max_commands=commands)
    cpu=runner.sessions['cpu'];digest,asserted,released,_=cpu._expected_ready()
    binary=tmp_path/'cpu-worker.py';binary.write_text('#!/usr/bin/env python3\nimport sys\nprint('+repr(f'READY local_driver.v1 {digest} {asserted:x} {released:x}')+',flush=True)\nfor line in sys.stdin:\n if line.strip()=="END":break\n');binary.chmod(0o700);cpu._binary=binary
    return runner


def test_actual_runner_requires_explicit_private_install_api(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path)
    assert runner.events==()
    assert all(t._native_reset_observation._issuer is None for name,t in runner.sessions.items() if name.startswith('gpio'))
    runner.install_native_reset_evidence(max_records=8,max_commands=32)


def test_mechanical_begin_prepare_stub_is_not_native_authority(native_factory,tmp_path):
    """Structural fixture control: producer pins forbid the proposed prepare stub."""
    runner=configured_runner(native_factory,tmp_path)
    for target in runner.sessions.values():target.prepare_local=lambda:None
    with pytest.raises(ValueError,match='producer method drift:prepare_local'):
        runner.begin_test('mechanical')
    assert all(target.process is None for target in runner.sessions.values())


def test_install_second_target_gap_is_atomic(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path)
    first=runner.sessions['gpio_a']._native_reset_observation
    runner.sessions['gpio_b']._native_reset_observation=None
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert first._issuer is None and runner._native_reset_evidence is None


def test_producer_capacity_alignment_before_issuer_registration(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path,commands=32)
    with pytest.raises(ValueError,match='capacity'):runner.install_native_reset_evidence(max_commands=31)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_real_provider_facts_are_once_consumed_repeated_export_is_not_authority(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        target.write_register(24,17)
        first=runner.native_reset_evidence_snapshot()
        assert [r['kind'] for r in first['facts']]==['lifecycle','command_pending','command_parsed']
        assert first['counts']['commands']==1
        helper=target._native_reset_observation;consumed=len(helper._consumed)
        first['facts'][0]['document']['native_eligible']=True
        second=runner.native_reset_evidence_snapshot()
        assert len(helper._consumed)==consumed==3
        assert second['facts'][0]['document']['native_eligible'] is False
        assert runner._native_reset_evidence.completed_intervals()==()
        assert 'Popen' not in str(second)
        assert all(not ({'execution','execution_nonce','pid','private_process'} & set(row['document'])) for row in second['facts'])
        target.reset_local();unbound=runner.native_reset_evidence_snapshot()
        assert helper._logical_process==2
        assert unbound['status']=='incomplete'
        assert any(r['kind']=='lifecycle' and r['document']['kind']=='explicit_reset' for r in unbound['facts'])
        assert runner.native_reset_evidence_snapshot()['status']=='incomplete'
        from myfuzz.scenario.runner import guard_native_reset_evidence
        with pytest.raises(ValueError,match='incomplete'):guard_native_reset_evidence(runner,new_operation=True)
        with pytest.raises(ValueError,match='incomplete'):runner._native_reset_evidence.completed_intervals()
    finally:target.end_case()
    assert runner.native_reset_evidence_snapshot()['status']=='incomplete'


def test_duplicate_or_public_fact_cannot_authorize_consumer(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        runner.native_reset_evidence_snapshot();helper=target._native_reset_observation;evidence=runner._native_reset_evidence
        with pytest.raises(ValueError):helper._resolve_fact(helper._facts[0][0],issuer=evidence)
        with pytest.raises(ValueError):helper._resolve_fact(helper.lifecycles()[0],issuer=evidence)
        assert evidence.snapshot()['counts']['facts']==1
    finally:target.end_case()


@pytest.mark.parametrize('variant',['memory','target','consumer_code','actual_ref'])
def test_consumer_binding_and_cached_journal_drift_permanently_refuse(native_factory,tmp_path,monkeypatch,variant):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    evidence=runner._native_reset_evidence
    try:
        state=evidence.snapshot()
        if variant=='memory':
            cpu=runner.sessions['cpu'];old=cpu.memory;cpu.memory=object()
        elif variant=='target':
            old=runner.sessions['gpio_a'];runner.sessions['gpio_a']=runner.sessions['gpio_b']
        elif variant=='consumer_code':
            from myfuzz.scenario.native_reset_evidence import NativeResetEvidence
            old=NativeResetEvidence._domains.__code__;NativeResetEvidence._domains.__code__=(lambda self,name:{}).__code__
        else:
            ref=runner._event_ref_by_id(state['facts'][0]['event_id']);old=ref['document']['kind'];ref['document']['kind']='forged'
        with pytest.raises(ValueError):evidence.validate()
        if variant=='memory':cpu.memory=old
        elif variant=='target':runner.sessions['gpio_a']=old
        elif variant=='consumer_code':NativeResetEvidence._domains.__code__=old
        else:ref['document']['kind']=old
        with pytest.raises(ValueError,match='incomplete'):evidence.validate()
    finally:target.end_case()


def test_append_failure_never_reconsumes_token_or_heals(native_factory,tmp_path,monkeypatch):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical');evidence=runner._native_reset_evidence
    original=runner._events.append
    def fail(record,**kwargs):raise RuntimeError('controlled journal failure')
    monkeypatch.setattr(runner._events,'append',fail)
    try:
        with pytest.raises(RuntimeError):evidence.snapshot()
        assert evidence._cursor['gpio_a']==0 and len(target._native_reset_observation._consumed)==1
        monkeypatch.setattr(runner._events,'append',original)
        with pytest.raises(ValueError,match='incomplete'):evidence.validate()
        assert len(target._native_reset_observation._consumed)==1
    finally:target.end_case()


def test_actual_cpu_process_execution_is_separately_pinned(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    cpu=runner.sessions['cpu'];cpu.begin_case('mechanical')
    evidence=runner._native_reset_evidence
    try:
        evidence.validate()
        domains=evidence._domains('gpio_a')
        assert domains['cpu_logical_process']==1
        original=cpu._execution;cpu._execution='foreign-execution'
        with pytest.raises(ValueError,match='CPU process'):evidence.validate()
        cpu._execution=original
        with pytest.raises(ValueError,match='incomplete'):evidence.validate()
    finally:cpu.end_case()


def test_actual_provenance_decoration_preserves_authoritative_stored_ref(native_factory,tmp_path):
    from tests.scenario.test_runner_source_provenance import configured_runner as provenance_runner
    runner=configured_runner(native_factory,tmp_path)
    declared,_,_=provenance_runner()
    # This is an actual append-time decorator fixture, not causal/reset authority.
    runner.configure_provenance(declared._provenance.edge_index)
    runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        state=runner.native_reset_evidence_snapshot()
        actual=runner._event_ref_by_id(state['facts'][0]['event_id'])
        assert actual['kind']=='native_reset_private_fact'
        assert actual['document']['native_eligible'] is False
        assert actual['provenance']['proof_scope']=='observation_only'
        runner._native_reset_evidence.validate()
    finally:target.end_case()


def test_journal_capacity_refuses_before_one_use_token_resolution(native_factory,tmp_path):
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.runner import ScenarioBudgetExhausted
    runner=configured_runner(native_factory,tmp_path)
    runner.set_resource_budget(ResourceBudget(max_semantic_records=1))
    runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        with pytest.raises(ScenarioBudgetExhausted):runner.native_reset_evidence_snapshot()
        assert not target._native_reset_observation._consumed
        assert runner._native_reset_evidence._cursor['gpio_a']==0
        assert runner._native_reset_evidence._status=='incomplete'
    finally:target.end_case()


def test_fixed_native_guard_is_available_before_any_command(native_factory,tmp_path):
    from myfuzz.scenario.runner import guard_native_reset_evidence
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    guard_native_reset_evidence(runner)
    cpu=runner.sessions['cpu'];old=cpu.memory;cpu.memory=object()
    with pytest.raises(ValueError):guard_native_reset_evidence(runner)
    cpu.memory=old


def test_reset_interval_cannot_be_minted_by_calling_consumer_hook(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    evidence=runner._native_reset_evidence
    with pytest.raises(ValueError,match='actual Runner'):evidence._after_begin()
    assert evidence.snapshot()['counts']['intervals']==0


def test_reserved_journal_capacity_blocks_effect_and_all_token_resolution(native_factory,tmp_path):
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.runner import ScenarioBudgetExhausted
    runner=configured_runner(native_factory,tmp_path)
    runner.set_resource_budget(ResourceBudget(max_semantic_records=3))
    runner.install_native_reset_evidence(max_commands=32)
    with pytest.raises(ScenarioBudgetExhausted):runner._native_reset_evidence._reserve_capacity(2)
    assert all(t.process is None and not t._native_reset_observation._consumed
               for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_private_command_index_cannot_restore_saved_or_foreign_facts(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    evidence=runner._native_reset_evidence
    try:
        evidence.snapshot();evidence._commands['gpio_a'][1]={'status':'parsed_complete'}
        with pytest.raises(ValueError,match='index drift'):evidence.validate()
    finally:target.end_case()


def test_incomplete_ordinary_channel_still_exports_guarded_reset_history(native_factory,tmp_path):
    runner=configured_runner(native_factory,tmp_path)
    for n in ('gpio_a','gpio_b'):runner.sessions[n].configure_ordinary_apb_access_receipts()
    runner.install_ordinary_apb_access_evidence()
    runner.install_native_reset_evidence(max_commands=32)
    runner._ordinary_apb_access_evidence._fail('controlled_callback_failure')
    assert runner.native_reset_evidence_snapshot()['status']=='incomplete'
    with pytest.raises(ValueError,match='incomplete'):runner._native_reset_evidence.validate()


def test_actual_postappend_meter_failure_retains_consumed_attempt_reference(native_factory,tmp_path):
    from myfuzz.scenario.contracts import ResourceBudget
    from myfuzz.scenario.runner import ScenarioEvidenceRecordViolation
    runner=configured_runner(native_factory,tmp_path)
    runner.set_resource_budget(ResourceBudget())
    runner.install_native_reset_evidence(max_commands=32)
    runner.arm_evidence_meter(0,{},max_evidence_record_bytes=1)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        with pytest.raises(ScenarioEvidenceRecordViolation):runner.native_reset_evidence_snapshot()
        state=runner.native_reset_evidence_snapshot()
        assert state['status']=='incomplete' and state['counts']['facts']==0
        assert state['failed_attempts'][0]['actual_event_id']==1
        assert state['failed_attempts'][0]['fact_ordinal']==1
        assert runner._event_ref_by_id(1)['fact_kind']=='lifecycle'
        assert len(target._native_reset_observation._consumed)==1
        assert runner._native_reset_evidence._cursor['gpio_a']==0
    finally:target.end_case()


def test_admission_guard_cannot_bypass_native_channel_via_replaced_dispatch(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import runner as runner_module
    actual=runner_module.guard_register_program_verifier
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    monkeypatch.setattr(runner_module,'guard_native_reset_evidence',lambda *args,**kwargs:None)
    with pytest.raises(ValueError,match='guard drift'):actual(runner,new_operation=True)


@pytest.mark.parametrize('name',['_CACHE','_CPU_STATES','_ATTEMPTS','_QUALIFICATIONS'])
def test_same_contents_foreign_private_registry_is_rejected(native_factory,tmp_path,monkeypatch,name):
    from weakref import WeakKeyDictionary
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    monkeypatch.setattr(module,name,WeakKeyDictionary(getattr(module,name)))
    with pytest.raises(ValueError,match='ownership drift'):runner._native_reset_evidence.validate()


@pytest.mark.parametrize('name',['_json','_natural'])
def test_equivalent_global_helper_alias_is_rejected(native_factory,tmp_path,monkeypatch,name):
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    original=getattr(module,name)
    monkeypatch.setattr(module,name,lambda value:original(value))
    with pytest.raises(ValueError,match='ownership drift'):runner._native_reset_evidence.validate()


@pytest.mark.parametrize('name',['_event_ref_by_id','_ensure_semantic_capacity','_step_once'])
def test_preinstall_class_method_replacement_is_not_a_trusted_baseline(native_factory,tmp_path,monkeypatch,name):
    from myfuzz.scenario.runner import ScenarioRunner
    runner=configured_runner(native_factory,tmp_path)
    monkeypatch.setattr(ScenarioRunner,name,lambda *args,**kwargs:None)
    with pytest.raises(ValueError,match='Runner method drift'):
        runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None
               for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_preinstall_baseline_accessor_alias_is_rejected(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import runner as module
    runner=configured_runner(native_factory,tmp_path)
    original=module._native_reset_runner_method_table
    monkeypatch.setattr(module,'_native_reset_runner_method_table',lambda:original())
    with pytest.raises(ValueError,match='method table drift'):
        runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


@pytest.mark.parametrize('name',['_CACHE','_CPU_STATES','_ATTEMPTS','_QUALIFICATIONS','_json','_natural',
                               'Path.read_bytes','hashlib.sha256',
                               'guard_register_program_verifier','guard_native_reset_evidence'])
def test_preinstall_implementation_aliases_are_not_trusted_baselines(native_factory,tmp_path,monkeypatch,name):
    from weakref import WeakKeyDictionary
    from myfuzz.scenario import native_reset_evidence as module
    from myfuzz.scenario import runner as runner_module
    runner=configured_runner(native_factory,tmp_path)
    if name in ('_CACHE','_CPU_STATES','_ATTEMPTS','_QUALIFICATIONS'):
        monkeypatch.setattr(module,name,WeakKeyDictionary(getattr(module,name)))
    elif name in ('_json','_natural'):
        original=getattr(module,name);monkeypatch.setattr(module,name,lambda value:original(value))
    elif name=='Path.read_bytes':
        original=module.Path.read_bytes;monkeypatch.setattr(module.Path,'read_bytes',lambda path:original(path))
    elif name=='hashlib.sha256':
        original=module.hashlib.sha256;monkeypatch.setattr(module.hashlib,'sha256',lambda *a,**k:original(*a,**k))
    else:
        original=getattr(runner_module,name);monkeypatch.setattr(runner_module,name,lambda *a,**k:original(*a,**k))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


@pytest.mark.parametrize('fail',[False,True])
@pytest.mark.parametrize('dependency',[False,True])
def test_reset_default_commit_hook_gets_real_independent_token_before_ack(fail,dependency):
    """Real modeled-host callback issuance; probe records ordering and grants nothing."""
    from tests.scenario.test_memory_dependency_runner import wired
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    runner,cpu=wired()
    if dependency:
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
        authority=runner._memory_commit_authority
    else:authority=MemoryCommitAuthority(services={'cpu':cpu.service})
    authority.register_consumer('register_reset_default_verifier')
    runner._memory_commit_authority=authority
    received=[]
    class Probe:
        def _consume_actual_commit(self,logged,token):
            receipt,pending=cpu.service.lookup_pending_commit(logged['commit_id'])
            issued=authority.resolve(token,consumer='register_reset_default_verifier')
            assert issued is not None and issued['commit_id']==logged['commit_id']
            assert runner._event_ref_by_id(logged['event_id']) is logged
            received.append((logged['commit_id'],receipt,issued))
            if fail:raise RuntimeError('controlled reset consumer failure')
    runner._register_reset_default_verifier=Probe()
    cpu._serve('data',1,0x20000,0x11223344,15)
    if fail:
        with pytest.raises(RuntimeError,match='controlled reset consumer failure'):
            runner._append_external_events('cpu',0)
    else:runner._append_external_events('cpu',0)
    assert len(received)==1
    commit_id,receipt,issued=received[0]
    assert authority.pending_count==0
    if fail:
        assert cpu.service.lookup_pending_commit(commit_id)[0] is receipt
        assert runner._status=='failed' and runner.failure_status=='uncertain_effect'
    else:
        with pytest.raises(ValueError,match='acknowledged'):cpu.service.lookup_pending_commit(commit_id)
    if dependency:
        report=runner.memory_dependency_evidence_report()
        assert report['journal_integrity'] is True
        assert report['counts']['verified']==0  # A write alone creates no writer/readback pair.
    assert not any('token' in key for event in runner.events for key in event)


@pytest.mark.parametrize('name',['_check_import_time_baselines','inspect.currentframe','_METHODS'])
def test_preinstall_checker_inspection_and_method_table_are_code_owned(native_factory,tmp_path,monkeypatch,name):
    from types import MappingProxyType
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    if name=='_check_import_time_baselines':monkeypatch.setattr(module,name,lambda:None)
    elif name=='_METHODS':monkeypatch.setattr(module,name,MappingProxyType(dict(module._METHODS)))
    else:
        original=module.inspect.currentframe;monkeypatch.setattr(module.inspect,'currentframe',lambda:original())
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_native_install_freezes_absent_authority_before_late_configuration(native_factory,tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    base=tmp_path/'no-authority';base.mkdir()
    no_authority_factory=make_ibex_pulp_dual_source_factory(
        base/'cache',physical_observations=True,memory_commit_receipts=True)
    runner=configured_runner(no_authority_factory,base)
    assert runner._memory_commit_authority is None
    runner.install_native_reset_evidence(max_commands=32)
    with pytest.raises(ValueError,match='authority.*before native'):
        runner.configure_memory_dependency_evidence(runtime_contract_sha256='a'*64)
    assert runner._memory_commit_authority is None
    assert runner._memory_dependency_consumer is None


@pytest.mark.parametrize('phase',['journal','program','uart'])
def test_real_commit_callback_failure_is_terminal_before_ack(native_factory,tmp_path,monkeypatch,phase):
    from types import SimpleNamespace
    runner=configured_runner(native_factory,tmp_path)
    assert runner._memory_dependency_consumer is not None
    authority=runner._memory_commit_authority
    runner.install_native_reset_evidence(max_commands=32)
    cpu=runner.sessions['cpu'];cpu.begin_case('mechanical')
    calls=[]
    if phase=='journal':
        original=runner._memory_dependency_consumer.consume
        def fail(event,*,commit_token=None,read_token=None):
            result=original(event,commit_token=commit_token,read_token=read_token)
            if commit_token is not None:calls.append(commit_token);raise RuntimeError('controlled actual commit failure')
            return result
        monkeypatch.setattr(runner._memory_dependency_consumer,'consume',fail)
    elif phase=='program':
        def fail(logged,token):calls.append(token);raise RuntimeError('controlled actual commit failure')
        runner._register_program_verifier=SimpleNamespace(_consume_actual_commit=fail)
    else:
        def fail(logged,*,commit_token=None,read_token=None):
            if commit_token is not None:calls.append(commit_token);raise RuntimeError('controlled actual commit failure')
            return ()
        runner._uart_store_memory_join=SimpleNamespace(consume=fail)
    try:
        cpu._serve('data',1,0x10004,0x12345678,15)
        actual=cpu.service.drain_commit_events()[0];commit_id=actual['commit_id']
        with pytest.raises(RuntimeError,match='controlled actual commit failure'):runner._append_external_events('cpu',0)
        assert len(calls)==1 and type(calls[0]) is int
        assert cpu.service.lookup_pending_commit(commit_id)[1]==actual
        assert runner._status=='failed' and runner.failure_status=='uncertain_effect'
        assert runner.native_reset_evidence_snapshot()['status']=='incomplete'
        assert authority.pending_count==0
        runner._append_external_events('cpu',0)
        assert len(calls)==1 and cpu.service.lookup_pending_commit(commit_id)[1]==actual
        with pytest.raises(ValueError,match='incomplete'):runner._native_reset_evidence.validate()
    finally:cpu.end_case()


def test_preinstall_checker_and_its_dispatch_table_cannot_both_be_replaced(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    replacement=lambda:None
    monkeypatch.setattr(module,'_check_import_time_baselines',replacement)
    monkeypatch.setattr(module,'_IMPORT_CHECK',(replacement,replacement.__code__))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_preinstall_checker_defaults_cannot_enroll_foreign_method_table(native_factory,tmp_path,monkeypatch):
    from types import MappingProxyType
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    table=MappingProxyType(dict(module._METHODS));defaults=list(module._check_import_time_baselines.__defaults__)
    defaults[4]=table
    monkeypatch.setattr(module,'_METHODS',table)
    monkeypatch.setattr(module._check_import_time_baselines,'__defaults__',tuple(defaults))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_preinstall_inspect_sys_cannot_forge_runner_caller(native_factory,tmp_path,monkeypatch):
    from types import SimpleNamespace
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    forged=SimpleNamespace(f_code=type(runner).begin_test.__code__,f_locals={'self':runner})
    forged.f_back=SimpleNamespace(f_back=forged)
    from types import ModuleType
    fake=ModuleType('fake_inspect_sys');fake.__dict__.update(module.inspect.sys.__dict__);fake._getframe=lambda depth:forged
    rejected=False
    with monkeypatch.context() as patch:
        patch.setattr(module.inspect,'sys',fake)
        try:runner.install_native_reset_evidence(max_commands=32)
        except ValueError:rejected=True
    assert rejected
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_actual_commit_lookup_failure_is_terminal_without_ack_or_retry(native_factory,tmp_path,monkeypatch):
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    cpu=runner.sessions['cpu'];cpu.begin_case('mechanical')
    original=cpu.service.lookup_pending_commit;calls=[]
    try:
        cpu._serve('data',1,0x10004,0x23456789,15)
        issued=cpu.service.drain_commit_events()[0];commit_id=issued['commit_id']
        def fail(key):calls.append(key);raise RuntimeError('controlled issued receipt lookup failure')
        monkeypatch.setattr(cpu.service,'lookup_pending_commit',fail)
        with pytest.raises(RuntimeError,match='controlled issued receipt lookup failure'):runner._append_external_events('cpu',0)
        assert original(commit_id)[1]==issued
        assert runner._status=='failed' and runner.failure_status=='uncertain_effect'
        assert runner.native_reset_evidence_snapshot()['status']=='incomplete'
        monkeypatch.setattr(cpu.service,'lookup_pending_commit',original)
        runner._append_external_events('cpu',0)
        assert len(calls)==1 and original(commit_id)[1]==issued
        with pytest.raises(ValueError,match='incomplete'):runner._native_reset_evidence.validate()
    finally:cpu.end_case()


def test_preinstall_consumer_class_method_drift_has_no_registered_issuers(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    monkeypatch.setattr(module.NativeResetEvidence,'_drain',lambda self:None)
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_last_target_observer_method_drift_is_rejected_before_any_issuer(native_factory,tmp_path,monkeypatch):
    runner=configured_runner(native_factory,tmp_path)
    observer=runner.sessions['gpio_b']._native_reset_observation
    monkeypatch.setattr(observer,'_private_state',lambda **kwargs:None)
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_preinstall_task1_producer_check_tuple_is_not_a_trusted_baseline(native_factory,tmp_path,monkeypatch):
    from myfuzz.local_harness import session as module
    runner=configured_runner(native_factory,tmp_path)
    replacement=lambda owner:None
    monkeypatch.setattr(module,'_NATIVE_RESET_CHECK_PRODUCERS',(replacement,replacement.__code__))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


@pytest.mark.parametrize('replace_table',[False,True])
def test_import_guard_replacement_cannot_enroll_changed_consumer(native_factory,tmp_path,monkeypatch,replace_table):
    from types import MappingProxyType
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    monkeypatch.setattr(module,'_IMPORT_BASELINE_GUARD',lambda:None)
    monkeypatch.setattr(module.NativeResetEvidence,'_drain',lambda self:None)
    if replace_table:
        table=dict(module._METHODS)
        table['_drain']=(module.NativeResetEvidence._drain,module.NativeResetEvidence._drain.__code__)
        monkeypatch.setattr(module,'_METHODS',MappingProxyType(table))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


@pytest.mark.parametrize('installed',[False,True])
def test_guard_alias_alone_is_detected_by_fixed_entries(native_factory,tmp_path,monkeypatch,installed):
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    if installed:runner.install_native_reset_evidence(max_commands=32)
    monkeypatch.setattr(module,'_IMPORT_BASELINE_GUARD',lambda:None)
    with pytest.raises(ValueError):
        if installed:runner._native_reset_evidence.validate()
        else:runner.install_native_reset_evidence(max_commands=32)
    if not installed:
        assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_replaced_constructor_wrapper_is_rejected_before_any_issuer(native_factory,tmp_path,monkeypatch):
    from types import MappingProxyType
    from inspect import getclosurevars
    from myfuzz.scenario import native_reset_evidence as module
    runner=configured_runner(native_factory,tmp_path)
    original=getclosurevars(module.NativeResetEvidence.__init__).nonlocals['original_init']
    def replacement(self,*args,**kwargs):return original(self,*args,**kwargs)
    monkeypatch.setattr(module.NativeResetEvidence,'__init__',replacement)
    methods=dict(module._METHODS);methods['__init__']=(replacement,replacement.__code__)
    monkeypatch.setattr(module,'_METHODS',MappingProxyType(methods))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_replaced_runner_anchor_pair_and_constructor_reject_before_issuers(native_factory,tmp_path,monkeypatch):
    from types import MappingProxyType
    from inspect import getclosurevars
    from myfuzz.scenario import native_reset_evidence as module
    from myfuzz.scenario import runner as runner_module
    runner=configured_runner(native_factory,tmp_path)
    original=getclosurevars(module.NativeResetEvidence.__init__).nonlocals['original_init']
    def replacement(self,*args,**kwargs):return original(self,*args,**kwargs)
    noop=lambda:None
    monkeypatch.setattr(runner_module,'_native_reset_preconstruction_check',noop)
    monkeypatch.setattr(runner_module,'_NATIVE_RESET_PRECONSTRUCTION_GUARD',(noop,noop.__code__))
    monkeypatch.setattr(module.NativeResetEvidence,'__init__',replacement)
    methods=dict(module._METHODS);methods['__init__']=(replacement,replacement.__code__)
    monkeypatch.setattr(module,'_METHODS',MappingProxyType(methods))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_replaced_anchor_registration_alias_is_rejected_before_issuers(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import runner as module
    runner=configured_runner(native_factory,tmp_path)
    monkeypatch.setattr(module,'_register_native_reset_import_anchor',lambda *args:None)
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


def test_first_consumer_import_registration_replacement_is_rejected(tmp_path):
    import os
    import subprocess
    import sys
    script='''
import sys
from pathlib import Path
from tests.scenario.test_native_reset_evidence import configured_runner
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from myfuzz.scenario import runner as module
assert 'myfuzz.scenario.native_reset_evidence' not in sys.modules
class TempFactory:
    def mktemp(self,name):
        path=Path(sys.argv[1])/name;path.mkdir();return path
runner=configured_runner(native_factory.__wrapped__(TempFactory()),Path(sys.argv[1]))
assert 'myfuzz.scenario.native_reset_evidence' not in sys.modules
module._register_native_reset_import_anchor=lambda *args:None
try:runner.install_native_reset_evidence(max_commands=32)
except ValueError:pass
else:raise AssertionError('replaced first-import registration accepted')
assert 'myfuzz.scenario.native_reset_evidence' not in sys.modules
assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))
'''
    result=subprocess.run([sys.executable,'-c',script,str(tmp_path)],capture_output=True,text=True,env=os.environ.copy())
    assert result.returncode==0,result.stdout+result.stderr


@pytest.mark.parametrize('method_name',['_ensure_semantic_capacity','_event_ref_by_id'])
def test_replaced_runner_accessor_pair_cannot_admit_changed_methods(native_factory,tmp_path,monkeypatch,method_name):
    from types import MappingProxyType
    from myfuzz.scenario import runner as module
    runner=configured_runner(native_factory,tmp_path)
    monkeypatch.setattr(module.ScenarioRunner,method_name,lambda self,*args,**kwargs:None)
    table=MappingProxyType({name:(method,method.__code__) for name,method in vars(module.ScenarioRunner).items()
                            if callable(method) and hasattr(method,'__code__')})
    fake=lambda:table
    monkeypatch.setattr(module,'_native_reset_runner_method_table',fake)
    monkeypatch.setattr(module,'_NATIVE_RESET_RUNNER_TABLE_ACCESSOR',(fake,fake.__code__))
    with pytest.raises(ValueError):runner.install_native_reset_evidence(max_commands=32)
    assert runner._native_reset_evidence is None
    assert runner._native_reset_evidence_failed_install is False
    assert all(t._native_reset_observation._issuer is None for n,t in runner.sessions.items() if n.startswith('gpio'))


# --- Lifecycle-scoped native build qualification memoization (Task2b) -------------------------
#
# The re-qualification clause in NativeResetEvidence._validate is guarded by the committed
# lifecycle fact's `native_eligible` flag, which only an actual native build issuance can set.
# No software fixture may fabricate that issuance, so these cases drive the branch with a
# counting test double for the frozen Task1 qualification callable.  The double substitutes both
# session-module symbols together (the frozen producer pin compares the two globals to each
# other), records every invocation and makes no native claim: the lifecycle documents it seals
# are mechanical software lifecycles, they grant nothing, and no certificate is produced or
# inspected.  What is measured is the guard's invocation count, which is the defect under test.

def native_qualification_stand_in(monkeypatch,*,digest='a'*64,eligible=True):
    from myfuzz.local_harness import session as module
    state=dict(digest=digest,eligible=eligible,calls=[])
    def qualification(owner):
        state['calls'].append(owner)
        return state['eligible'],state['digest']
    monkeypatch.setattr(module,'_native_reset_native_eligible',qualification)
    monkeypatch.setattr(module,'_NATIVE_RESET_NATIVE_ELIGIBLE',(qualification,qualification.__code__))
    return state


def close_targets(targets):
    for target in targets:
        if target.process is not None:target.end_case()


def eligible_channel(native_factory,tmp_path,monkeypatch):
    state=native_qualification_stand_in(monkeypatch)
    runner=configured_runner(native_factory,tmp_path)
    runner.install_native_reset_evidence(max_commands=32)
    targets=[runner.sessions['gpio_a'],runner.sessions['gpio_b']]
    for target in targets:target.begin_case('mechanical')
    evidence=runner._native_reset_evidence
    evidence.snapshot()
    assert all(evidence._lifecycle[name]['native_eligible'] is True for name in ('gpio_a','gpio_b'))
    return runner,evidence,targets,state


def test_repeated_validate_requalifies_once_per_committed_lifecycle(native_factory,tmp_path,monkeypatch):
    """RED: ten unchanged validates must not requalify each target ten times."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        state['calls'].clear()
        for _ in range(10):evidence.validate()
        assert len(state['calls'])<=2,f'requalifications across 10 validates: {len(state["calls"])}'
        assert {entry[0] for entry in evidence._native_qualifications}=={'gpio_a','gpio_b'}
    finally:close_targets(targets)


def test_new_committed_lifecycle_ordinal_forces_requalification(native_factory,tmp_path,monkeypatch):
    """A new committed lifecycle, and only that target, requalifies exactly once."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        state['calls'].clear()
        evidence.validate()
        assert state['calls']==[],'unchanged committed lifecycle must not requalify'
        target=targets[0];target.reset_local()
        state['calls'].clear()
        evidence.snapshot()  # Commits the explicit_reset lifecycle, then requalifies the new ordinal.
        assert [owner is target for owner in state['calls']]==[True],'new lifecycle must requalify once'
        assert evidence._status=='incomplete' and 'explicit_target_reset_outside_global_barrier' in evidence._reason
    finally:close_targets(targets)


def test_lifecycle_change_with_mismatched_build_digest_is_refused(native_factory,tmp_path,monkeypatch):
    """Drift is still refused at the cycle boundary: a requalified target fails closed."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        target=targets[0];target.reset_local()  # Seals the next lifecycle with the recorded digest.
        state['digest']='b'*64                  # Live qualification now differs from the record.
        with pytest.raises(ValueError,match='current native build qualification drift'):
            evidence.snapshot()
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


@pytest.mark.parametrize('variant',['instance_rebind','registry_rebind','registry_replace'])
def test_poisoned_qualification_memo_is_refused_fail_closed(native_factory,tmp_path,monkeypatch,variant):
    from weakref import WeakKeyDictionary
    from myfuzz.scenario import native_reset_evidence as module
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        key=tuple(evidence._native_qualifications)
        if variant=='instance_rebind':evidence._native_qualifications=key+(('gpio_a',99,'b'*64),)
        elif variant=='registry_rebind':module._QUALIFICATIONS[evidence]=key+(('gpio_a',99,'b'*64),)
        else:monkeypatch.setattr(module,'_QUALIFICATIONS',WeakKeyDictionary(module._QUALIFICATIONS))
        with pytest.raises(ValueError,match='ownership drift'):evidence.validate()
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


def test_qualification_callable_pair_replacement_is_refused(native_factory,tmp_path,monkeypatch):
    from myfuzz.local_harness import session as module
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        forged=lambda owner:(True,'b'*64)
        with monkeypatch.context() as patch:
            patch.setattr(module,'_NATIVE_RESET_NATIVE_ELIGIBLE',(forged,forged.__code__))
            with pytest.raises(ValueError,match='producer pin drift'):runner._native_reset_evidence.validate()
        assert runner._native_reset_evidence._status=='incomplete'
    finally:close_targets([target])


@pytest.mark.parametrize('shadow',['instance_validate','instance_qualifier','class_qualifier'])
def test_qualification_memo_entry_points_cannot_be_shadowed(native_factory,tmp_path,monkeypatch,shadow):
    from myfuzz.scenario.native_reset_evidence import NativeResetEvidence
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        if shadow=='instance_validate':evidence.validate=lambda *args,**kwargs:None
        elif shadow=='instance_qualifier':evidence._native_build_qualified=lambda name,life:True
        else:monkeypatch.setattr(NativeResetEvidence,'_native_build_qualified',lambda self,name,life:True)
        with pytest.raises(ValueError,match='consumer method drift'):NativeResetEvidence.validate(evidence)
    finally:close_targets(targets)


def test_qualification_memo_is_private_and_never_exported(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.native_reset_evidence import NativeResetEvidence
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        before=json.dumps(evidence.snapshot(),sort_keys=True)
        for _ in range(3):evidence.validate()
        after=json.dumps(evidence.snapshot(),sort_keys=True)
        assert before==after
        assert '_native_qualifications' not in after and '_native_build_qualified' not in after
        assert str(inspect.signature(NativeResetEvidence.__init__)).endswith(
            '(self, runner, *, max_records=256, max_commands=4096)')
        assert {name for name,value in vars(NativeResetEvidence).items()
                if callable(value) and not name.startswith('_')}=={
                'validate','configuration','completed_intervals','snapshot'}
    finally:close_targets(targets)


def test_ineligible_lifecycle_skips_qualification_exactly_as_before(native_factory,tmp_path,monkeypatch):
    state=native_qualification_stand_in(monkeypatch,digest=None,eligible=False)
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        evidence=runner._native_reset_evidence;evidence.snapshot();state['calls'].clear()
        for _ in range(10):evidence.validate()
        assert state['calls']==[] and evidence._native_qualifications==()
        assert evidence._lifecycle['gpio_a']['native_eligible'] is False
        assert evidence.completed_intervals()==() and evidence._status=='complete'
    finally:close_targets([target])


# --- Incremental repeat validation (Task2c) ----------------------------------------------------
#
# The defect under test is measured, not asserted by argument.  The frozen `_validate` re-derives
# the whole committed prefix on every call -- parsing every cached command document and
# re-serialising every cached journal event -- and `advance_initial` reaches `_validate` about 19
# times per component step.  Measured on the gate's own exported state (1106 cached facts, 1.80 MB
# of fact documents, runs/stage2-e2-register-reset-default-warm-20261012-v1/native-reset-evidence.json)
# the committed-prefix reconstruction alone costs 11.4 ms per call and the journal tie 14.4 ms.
#
# The tests below count the reconstruction's own expense -- `json.loads` of a cached fact document
# executed from inside a `_validate` frame -- which is exactly the work the fix makes incremental.
# The live journal tie deliberately still runs on every call (a live record mutated in place cannot
# be detected without reading it), so it is not what these bounds measure.

def _loads_from_validate_counter():
    """Counter for `json.loads` calls reached from a NativeResetEidence._validate frame."""
    import sys
    from myfuzz.scenario import native_reset_evidence as module
    state=dict(loads=0)
    codes=set()
    sealed=module._TYPE.__dict__['_validate']
    codes.add(sealed.__code__)
    for cell in (sealed.__closure__ or ()):
        code=getattr(cell.cell_contents,'__code__',None)
        if code is not None:codes.add(code)
    loads_code=json.loads.__code__
    def profiler(frame,event,arg):
        # Only loads issued *directly* from the validator's own frame are the reconstruction's;
        # callees such as the observer's `configuration()` have their own frame in between and are
        # ordinary per-call guards, not the leg under test.
        if event=='call' and frame.f_code is loads_code and frame.f_back is not None \
                and frame.f_back.f_code in codes:
            state['loads']+=1
        return None
    return state,profiler


def _counted(counter,action):
    import sys
    state,profiler=counter
    state['loads']=0
    sys.setprofile(profiler)
    try:action()
    finally:sys.setprofile(None)
    return state['loads']


def test_repeat_validate_is_bounded_and_independent_of_cached_fact_count(native_factory,tmp_path,monkeypatch):
    """RED: unchanged repeats must not re-derive the committed prefix over and over."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        counter=_loads_from_validate_counter()
        for index in range(12):
            targets[index%2].write_register(24,17)
            evidence._drain()
        facts=len(evidence._cache)
        assert facts>=20,f'fixture must accumulate facts to measure the redundancy: {facts}'
        # `_drain` already re-derived the prefix at its own trailing validate, so ten further
        # unchanged validates must need no reconstruction at all.
        after=_counted(counter,lambda:[evidence.validate() for _ in range(10)])
        assert after<=4,(f'ten unchanged validates re-derived the committed prefix {after} times over '
                         f'{facts} cached facts; incremental repeats must be bounded')
    finally:close_targets(targets)


def test_incremental_repeat_validate_still_detects_in_place_cached_event_mutation(native_factory,tmp_path,monkeypatch):
    """(a) Fail-closed: mutating an already-verified cached journal event is still detected."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for index in range(6):
            targets[index%2].write_register(24,17)
            evidence._drain()
        evidence.validate()
        for _ in range(5):evidence.validate()
        ref=runner._event_ref_by_id(evidence._cache[0][5])
        assert ref is not None
        original=ref['document']['kind']
        ref['document']['kind']='forged'
        try:
            with pytest.raises(ValueError,match='journal ref drift'):evidence.validate()
        finally:
            ref['document']['kind']=original
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


def test_incremental_live_index_mutation_is_still_detected_after_repeats(native_factory,tmp_path,monkeypatch):
    """(a') Fail-closed: mutating live state the validation reads is still detected."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for index in range(6):
            targets[index%2].write_register(24,17)
            evidence._drain()
        evidence.validate()
        for _ in range(5):evidence.validate()
        rows=evidence._commands['gpio_a']
        assert rows,f'fixture must have committed a command index: {rows}'
        ordinal=min(rows)
        rows[ordinal]={'command_ordinal':ordinal,'status':'forged'}
        with pytest.raises(ValueError,match='committed index drift'):evidence.validate()
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


def test_incremental_new_lifecycle_boundary_still_reverifies_and_can_refuse(native_factory,tmp_path,monkeypatch):
    """(b) A new committed lifecycle still forces re-verification and can still refuse on drift."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        evidence.validate()
        for _ in range(3):evidence.validate()
        targets[0].reset_local()
        state['digest']='c'*64
        with pytest.raises(ValueError,match='current native build qualification drift'):
            evidence.snapshot()
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


def test_incremental_requalifies_exactly_once_after_new_lifecycle(native_factory,tmp_path,monkeypatch):
    """(b') The boundary check still runs exactly once and only for the changed target."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for _ in range(4):evidence.validate()
        targets[0].reset_local()
        state['calls'].clear()
        evidence.snapshot()
        assert [owner is targets[0] for owner in state['calls']]==[True],state['calls']
    finally:close_targets(targets)


def test_incremental_cursor_drift_still_raises_after_repeats(native_factory,tmp_path,monkeypatch):
    """(c) Cursor drift still raises after repeated unchanged validates."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for index in range(4):
            targets[index%2].write_register(24,17)
            evidence._drain()
        for _ in range(5):evidence.validate()
        original=evidence._cursor['gpio_a']
        evidence._cursor['gpio_a']=original+1
        try:
            with pytest.raises(ValueError,match='cursor drift'):evidence.validate()
        finally:
            evidence._cursor['gpio_a']=original
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


@pytest.mark.parametrize('rebind',['registry','qualification_callable','method_table'])
def test_incremental_pinned_identities_are_still_refused_after_repeats(native_factory,tmp_path,monkeypatch,rebind):
    """(d) Registry / qualification-callable / method-table rebinding is still refused."""
    from weakref import WeakKeyDictionary
    from myfuzz.local_harness import session as session_module
    from myfuzz.scenario import native_reset_evidence as module
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for _ in range(3):evidence.validate()
        with monkeypatch.context() as patch:
            if rebind=='registry':
                patch.setattr(module,'_QUALIFICATIONS',WeakKeyDictionary(module._QUALIFICATIONS))
                match='ownership drift'
            elif rebind=='qualification_callable':
                forged=lambda owner:(True,'b'*64)
                patch.setattr(session_module,'_NATIVE_RESET_NATIVE_ELIGIBLE',(forged,forged.__code__))
                match='producer pin drift'
            else:
                patch.setattr(module._TYPE,'_native_build_qualified',lambda self,name,life:True)
                match='consumer method drift'
            with pytest.raises(ValueError,match=match):module._TYPE.validate(evidence)
        assert evidence._status=='incomplete'
    finally:close_targets(targets)


def test_incremental_incomplete_target_is_still_reported_incomplete(native_factory,tmp_path,monkeypatch):
    """(e) An incomplete target is still reported incomplete across repeated validates."""
    runner=configured_runner(native_factory,tmp_path);runner.install_native_reset_evidence(max_commands=32)
    target=runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        evidence=runner._native_reset_evidence
        evidence.snapshot()
        for _ in range(5):evidence.validate(allow_incomplete=True)
        evidence._fail('target_incomplete:gpio_a')
        for _ in range(3):evidence.validate(allow_incomplete=True)
        with pytest.raises(ValueError,match='native reset evidence incomplete'):
            evidence.validate()
        assert evidence._status=='incomplete'
    finally:close_targets([target])


def test_incremental_export_is_byte_identical_to_the_non_incremental_path(native_factory,tmp_path,monkeypatch):
    """(f) Incremental repeats change no observable export."""
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        for index in range(6):
            targets[index%2].write_register(24,17)
            evidence._drain()
        first=json.dumps(evidence.snapshot(),sort_keys=True)
        for _ in range(8):evidence.validate()
        second=json.dumps(evidence.snapshot(),sort_keys=True)
        assert first==second
        assert '_revision' not in second and '_CONTENTS' not in second
    finally:close_targets(targets)


@pytest.mark.parametrize('variant',['registry_rebind','wrong_shape','projection_poison'])
def test_incremental_memo_is_registry_pinned_and_fail_closed(native_factory,tmp_path,monkeypatch,variant):
    """(g) The incremental memo is registry-pinned; a poisoned projection is refused."""
    from weakref import WeakKeyDictionary
    from myfuzz.scenario import native_reset_evidence as module
    runner,evidence,targets,state=eligible_channel(native_factory,tmp_path,monkeypatch)
    try:
        evidence.validate()
        original=module._CONTENTS[evidence]
        assert type(original) is tuple and len(original)==6
        if variant=='registry_rebind':
            monkeypatch.setattr(module,'_CONTENTS',WeakKeyDictionary(module._CONTENTS))
            match='ownership drift'
        elif variant=='wrong_shape':
            module._CONTENTS[evidence]=()
            match='ownership drift'
        else:
            # A revision that cannot match only ever forces the reconstruction -- it is not
            # authority -- so the meaningful poison is of a stored projection, which is refused.
            poisoned=dict(original[1]);poisoned['gpio_a']=0
            module._CONTENTS[evidence]=(original[0],poisoned,original[2],original[3],original[4],original[5])
            match='committed index drift'
        try:
            with pytest.raises(ValueError,match=match):module._TYPE.validate(evidence)
        finally:
            module._CONTENTS[evidence]=original
        assert evidence._status=='incomplete'
    finally:close_targets(targets)
