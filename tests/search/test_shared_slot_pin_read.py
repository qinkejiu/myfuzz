"""Shared-slot pin observer cannot import authority from saved records."""
from types import SimpleNamespace
import pytest


def test_shared_provider_rejects_documents_and_other_runtime_classes():
    from myfuzz.search.shared_slot_pin_read import install_shared_slot_pin_consumer, authenticated_report
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    for value in ({'shared_flow_paths': {'F2': {}, 'F5': {}}}, SimpleNamespace(), object.__new__(CompiledF4Runtime)):
        with pytest.raises(ValueError):
            install_shared_slot_pin_consumer(value)
    with pytest.raises(ValueError): authenticated_report(object(), {'status':'verified'})


def test_shared_writer_origin_requires_registered_actual_admission_and_epoch():
    from myfuzz.search.shared_slot_pin_read import _origin_writer
    origin=dict(kind='native_pin_sample',pin=8,value=1,source_context={'segments':[
        dict(bit_lo=8,width=1,value=1,origin=dict(kind='source_admission',action_id='f5'))]})
    state={'pin':8,'writers':{}}
    assert _origin_writer(state,origin,0) is None
    assert _origin_writer(state,dict(origin,kind='host_value'),0) is None


@pytest.mark.parametrize('change',[{}, {'epoch':1}, {'value':0}, {'role':'fixed_support'}, {'path_id':'F4-path'}])
def test_writer_identity_uses_actual_registry_entry_and_physical_owner(change):
    from myfuzz.search.shared_slot_pin_read import _origin_writer
    from myfuzz.scenario.source_provenance import AdmissionRegistry,SourceAdmission
    registry=AdmissionRegistry()
    admission=SourceAdmission.create(case_id='f5-case',case_index=0,source_id='pin-source',path_id=change.get('path_id','F5-path'),
        direction='IP_TO_CPU',component='gpio',action_id='f5',role=change.get('role','fuzz_source'),
        input_kind='source_event',input_sha256='0'*64)
    registry.register(admission)
    runner=SimpleNamespace(ownership=SimpleNamespace(mutation_source=lambda *args,**kwargs:'owner'),
        _provenance=SimpleNamespace(edge_index=SimpleNamespace(source_owner_ref=lambda *args:'owner')))
    writer=dict(admission=admission,epoch=change.get('epoch',0),value=change.get('value',1))
    state=dict(pin=8,writers={'f5':writer},methods=(None,)*5+(AdmissionRegistry.get,),registry=registry,
        paths={'F5':{'path_id':'F5-path'}},target_id='gpio',runner=runner)
    origin=dict(kind='native_pin_sample',pin=8,value=1,source_context={'segments':[
        dict(bit_lo=8,width=1,value=1,origin=dict(kind='source_admission',action_id='f5'))]})
    assert (_origin_writer(state,origin,0) is writer)==(not change)
    runner.ownership.mutation_source=lambda *args,**kwargs:'different-owner'
    assert _origin_writer(state,origin,0) is None


def test_F4_and_unsealed_F5_cannot_register_a_pin_writer():
    from myfuzz.search.shared_slot_pin_read import _refresh_writers
    state={'writers':{}}
    _refresh_writers(state,[dict(flow='F4',status='passed'),dict(flow='F5',status='reserved')])
    assert state['writers']=={}


def test_shared_exact_lookup_uses_original_native_checker_and_borrowed_reader():
    from myfuzz.search import shared_slot_pin_read as module
    # The actual exact checker is shared, not a documentary certificate test.
    from myfuzz.integration.native_obi_hops import check_f2_exact_hops
    assert module._methods()[2] is check_f2_exact_hops
    from myfuzz.scenario.runner import ScenarioRunner
    assert module._methods()[4] is ScenarioRunner._event_refs_since


def test_sealed_mapping_joins_actual_detached_session_receipt():
    from tests.scenario.test_session_runtime_paths import configured,case
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.search.shared_slot_pin_read import _case
    session=configured();session.begin();submitted=case(session)
    try:
        session.submit_case(submitted)
        state=dict(session=session,runner=session.runner,events_since=ScenarioRunner.events_since)
        row=dict(case_id=submitted.case_id,session_case_index=0,status='passed',flow='F5',
            certificate=dict(case_id=submitted.case_id,status='certified',flow_id='F5'))
        actual,receipt=_case(state,row)
        assert actual is submitted and receipt==session.case_receipt(submitted.case_id)
        with pytest.raises(ValueError,match='sealed_shared_pin_case_required'):
            _case(state,{**row,'session_case_index':1})
        with pytest.raises(ValueError,match='sealed_shared_pin_certificate_required'):
            _case(state,{**row,'certificate':{**row['certificate'],'case_id':'other'}})
    finally:session.finish()


def test_shared_pin_credit_authenticator_is_explicit_and_called_once():
    from myfuzz.search.pin_case_adapter import PinCredit
    from types import SimpleNamespace
    calls=[]
    token=object();handle=object()
    def authenticate(actual_handle,report):
        assert actual_handle is handle and report is token
        calls.append(report)
        return dict(read_case_id='read',status='unknown',relations=[],writer=None)
    class Policy:
        def settle(self,*args,**kwargs):return {'settled':args[0]}
    credit=PinCredit(Policy(),authenticator=authenticate)
    document,result=credit.observe(handle,SimpleNamespace(id='decision'),'read',token,1)
    assert calls==[token] and document['relations']==[] and result['settlements']==[{'settled':'decision'}]


def test_pin_view_can_join_RAM_goal_without_claiming_IRQ_or_unknown_writer():
    from myfuzz.search.pin_case_adapter import pin_view
    goal,snapshot=pin_view(dict(status='observed',enabled=False,value=1,writer_attributed=False,reset_epoch=2),values=(0,1),completed_values=set())
    assert goal.root=='pin:consumed:0'
    assert snapshot.observations['pin:enabled'].status=='refuted'
    assert snapshot.observations['pin:written:0'].status=='unknown'
    goal,snapshot=pin_view(dict(status='observed',enabled=True,value=1,writer_attributed=True,reset_epoch=2),values=(0,1),completed_values={0})
    assert goal.root=='pin:consumed:1'
    assert snapshot.observations['pin:written:1'].status=='satisfied'
    assert all('irq' not in key for key in snapshot.observations)
