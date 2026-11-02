"""Software controls for live pin provenance; saved reports are never authority."""
from types import SimpleNamespace
import pytest


def test_saved_document_cannot_install_or_authenticate_pin_proof():
    from myfuzz.search.pin_read import install_pin_consumer, authenticated_report
    with pytest.raises(ValueError):install_pin_consumer(SimpleNamespace())
    with pytest.raises(ValueError):authenticated_report(object(),{'status':'verified','relations':[{}]})


def test_pin_catalog_excludes_other_domains():
    from myfuzz.search.pin_case_adapter import pin_records
    assert pin_records(['F4:0001000000','F5:0000000100000000','F5:0000000000000000','F2:08100040'])
    assert not pin_records(['F3:55000000','F1:03200000'])
    assert not pin_records(['F4:0001000000','F2:08100040'])


def test_pin_semantic_novelty_excludes_versions_events_and_case_ids():
    from myfuzz.search.pin_case_adapter import semantic_relation
    row=dict(component='gpio',pin=8,value=1,writer_case_id='old',read_case_id='reader',sample_version=1)
    assert semantic_relation(row)==semantic_relation({**row,'writer_case_id':'new','read_case_id':'new-read','sample_version':999})


def test_writer_receipt_accepts_actual_detached_configured_session_receipt():
    from copy import deepcopy
    from dataclasses import replace
    from tests.scenario.test_session_runtime_paths import configured,case
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.search.pin_read import _validate_writer_receipt
    session=configured();session.begin();submitted=case(session)
    try:
        receipt=session.submit_case(submitted)
        detached=session.case_receipt(submitted.case_id)
        assert detached is not receipt and detached==receipt
        state={'session':session,'runner':session.runner,'events_since':ScenarioRunner.events_since}
        _validate_writer_receipt(state,submitted,detached)
        with pytest.raises(ValueError):_validate_writer_receipt(state,deepcopy(submitted),detached)
        with pytest.raises(ValueError):_validate_writer_receipt(state,submitted,replace(detached,status='failed'))
        detached.local_ticks_after['a']+=1
        with pytest.raises(ValueError):_validate_writer_receipt(state,submitted,detached)
    finally:session.finish()


@pytest.mark.parametrize('field,enabled,written',[
    ({'status':'observed','enabled':False,'writer_attributed':False},'refuted','unknown'),
    ({'status':'observed','enabled':True,'writer_attributed':True,'value':1},'satisfied','refuted'),
    ({'status':'unknown'},'unknown','unknown'),
])
def test_pin_selector_three_valued_current_state(field,enabled,written):
    from myfuzz.search.pin_case_adapter import PinRecordSelector
    selector=PinRecordSelector(None,flow='mixed',records=['F4:0001000000','F5:0000000000000000','F2:08100040'],policy='state',seed=1,cases=8)
    selector._handle=SimpleNamespace(current_state=lambda:field)
    class Scheduler:
        def choose(self,goal,snapshot,catalog):
            assert snapshot.observations['pin:enabled'].status==enabled
            assert snapshot.observations['pin:written:0'].status==written
            return SimpleNamespace(value=0)
    selector.scheduler=Scheduler()
    selector.choose()


def test_pin_settlement_authenticates_one_opaque_report(monkeypatch):
    from myfuzz.search import pin_case_adapter as module
    selector=module.PinRecordSelector(None,flow='mixed',records=['F5:0000000000000000','F2:08100040'],policy='uniform',seed=1,cases=2)
    report=object();calls=[]
    monkeypatch.setattr(module,'authenticated_report',lambda handle,value:(calls.append(value) or dict(status='unattributed',relations=[],writer=None,read_case_id='read')))
    selector._handle=SimpleNamespace(current_state=lambda:dict(status='unknown'),observe_case=lambda case:report)
    selector._runtime=SimpleNamespace(records=[dict(certificate=dict(case_id='read'))])
    selector.start_search_clock(lambda:1.0,0.0)
    row=selector.choose();selector.settle(row)
    assert calls==[report]
    assert selector.transitions[0]['relation_status']=='unattributed'


def test_pin_query_retains_dynamic_gates_without_full_execution_validation(monkeypatch):
    from myfuzz.search import pin_read as module
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    from myfuzz.integration.shared_f5_runtime import submit_shared_f5
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.source_provenance import AdmissionRegistry
    from myfuzz.scenario.gpio_register_version import _AUTHORITIES
    class Target:pass
    target=Target();cpu=Target();authority=object();registry=AdmissionRegistry()
    process=SimpleNamespace(poll=lambda:None)
    target.process=process;cpu.process=process
    runner=SimpleNamespace(sessions={'cpu':cpu,'gpio':target},_provenance=SimpleNamespace(registry=registry),_status='running')
    runtime=SimpleNamespace(runner=runner,session=object(),authority=authority,target_id='gpio',cpu_id='cpu',_begun=True,_native_processes={'cpu':process,'gpio':process})
    def forbidden_full_validation(self):raise AssertionError('observation repeated execution validation')
    monkeypatch.setattr(CompiledF4Runtime,'_stable',forbidden_full_validation)
    handle=module._Installation()
    module._INSTALLATIONS[handle]=dict(runtime=runtime,runner=runner,session=runtime.session,authority=authority,target=target,cpu=cpu,registry=registry,
        registry_get=AdmissionRegistry.get,events_since=ScenarioRunner.events_since,event_by_id=ScenarioRunner.event_by_id,
        event_refs_since=ScenarioRunner._event_refs_since,event_refs_code=ScenarioRunner._event_refs_since.__code__,
        stable=CompiledF4Runtime._stable,source_submit=submit_shared_f5,exact=check_f2_exact_hops,processes=None)
    _AUTHORITIES[target]=authority
    try:
        assert module._live(handle)['runtime'] is runtime
        runner._event_refs_since=lambda index:()
        with pytest.raises(ValueError,match='scope_changed'):module._live(handle)
        del runner._event_refs_since
        def replacement(self,index,*,stop=None):return ()
        with monkeypatch.context() as drift:
            drift.setattr(ScenarioRunner._event_refs_since,'__code__',replacement.__code__)
            with pytest.raises(ValueError,match='scope_changed'):module._live(handle)
        with monkeypatch.context() as drift:
            drift.setattr(ScenarioRunner,'_event_refs_since',replacement)
            with pytest.raises(ValueError,match='scope_changed'):module._live(handle)
        runtime._native_processes['gpio']=object()
        with pytest.raises(ValueError,match='process_identity'):module._live(handle)
        runtime._native_processes['gpio']=process
        runner._provenance.registry=AdmissionRegistry()
        with pytest.raises(ValueError,match='scope_changed'):module._live(handle)
    finally:
        del _AUTHORITIES[target]


def test_pin_exact_borrows_synchronously_and_detaches_checker_output():
    from myfuzz.search.pin_read import _check_exact
    event={'versions':[{'version':1}]};runner=object();calls=[]
    def borrow(actual,index):
        assert actual is runner and index==0
        return (event,)
    def checker(*,events,marker):
        assert events[0] is event and marker=='actual'
        calls.append(True)
        return {'versions':events[0]['versions']}
    result=_check_exact({'event_refs_since':borrow,'exact':checker},runner,marker='actual')
    result['versions'][0]['version']=99
    assert event['versions'][0]['version']==1 and calls==[True]
