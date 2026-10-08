"""Compile-derived logical GPIO source to exact physical owner authority."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from myfuzz.scenario.dependency import DependencyGraph,DependencyRule,FuzzableSource
from myfuzz.scenario.ownership import InputField,InputOwner,compile_ownership
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract,RuntimeNode,RuntimePathContract,_digest
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex


def alias_fixture(width=1,source_id='gpio_b.external_pin8',owner='external_b.pin8'):
    graph=DependencyGraph(sources=(FuzzableSource(source_id,'gpio','gpio_in',8,width,('IP_TO_CPU',)),),
        rules=(DependencyRule('sampled',(source_id,),'EVENT_ORDER'),))
    nodes=(RuntimeNode(source_id,'gpio','physical','gpio_in',8,width),RuntimeNode('sampled','gpio','logical'))
    contract=RuntimePathContract(_digest(graph.edge_document()),nodes,())
    path=graph.edge_paths_to('sampled',direction='IP_TO_CPU')[0]
    prepared=PreparedRuntimePathContract(graph,contract,(('IP_TO_CPU',path),))
    ownership=compile_ownership((InputField('gpio','gpio_in',32),),
        (InputOwner('gpio','gpio_in',0,8,'fixed','zero'),InputOwner('gpio','gpio_in',8,width,'source',owner),InputOwner('gpio','gpio_in',8+width,24-width,'fixed','zero')))
    runner=SimpleNamespace(sessions={'gpio':SimpleNamespace()},ownership=ownership,bindings=())
    compiled=prepared.bind(runner).document();compiled['declaration']=prepared.document()
    return RuntimeEdgeIndex(compiled,contract.document()),compiled,contract.document(),ownership,prepared.path_ids[0]


def query(path,**changes):
    return dict(source_id='gpio_b.external_pin8',path_id=path,direction='IP_TO_CPU',component='gpio',port='gpio_in',bit_lo=8,width=1,**changes)


def test_selected_alias_returns_actual_owner_and_wide_source_containment():
    index,_,_,_,path=alias_fixture(width=2)
    assert index.source_owner_ref(**query(path))=='external_b.pin8'
    q=query(path);q.update(bit_lo=9);assert index.source_owner_ref(**q)=='external_b.pin8'
    q.update(width=2);assert index.source_owner_ref(**q) is None
    q.update(bit_lo=7,width=2);assert index.source_owner_ref(**q) is None


def test_lookup_is_total_and_does_not_authorize_wrong_scope():
    index,_,_,_,path=alias_fixture()
    for name,value in [('source_id','other'),('path_id','other'),('direction','IP_TO_IP'),('component','other'),('port','pin'),('bit_lo',7),('bit_lo',True),('width',False),('width',2),('source_id',[]),('path_id',{}),('bit_lo',None)]:
        q=query(path);q[name]=value
        assert index.source_owner_ref(**q) is None


def test_constructor_and_public_document_are_detached_authority_snapshots():
    index,compiled,contract,_,path=alias_fixture()
    old=index.identity_sha256
    compiled['topology']['ownership_inputs'][0]['owners'][8]['producer_ref']='forged'
    compiled['declaration']['graph']['sources'][0]['source_id']='forged'
    contract['nodes'][0]['component']='forged'
    document=index.document();document['source_owner_refs'][0]['producer_ref']='forged'
    assert index.source_owner_ref(**query(path))=='external_b.pin8'
    assert index.identity_sha256==old
    with pytest.raises(TypeError):index._source_owners[('forged',)]='forged'


def test_tracker_alias_requires_compile_authority_and_current_owner():
    from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
    from myfuzz.scenario.source_provenance import AdmissionRegistry,SourceAdmission
    index,_,_,ownership,path=alias_fixture()
    a=SourceAdmission.create(case_id='case',case_index=0,source_id='gpio_b.external_pin8',path_id=path,direction='IP_TO_CPU',component='gpio',action_id='pin',role='fuzz_source',input_kind='source_event',input_sha256='a'*64)
    registry=AdmissionRegistry();registry.register(a)
    event=dict(kind='gpio_input_applied',event_id=2,actual_receipt_event_id=3,actual_input_value=256,component='gpio',reset_epoch=0,local_tick=1,port='gpio_in',value=1,bit_lo=8,width=1,origin=dict(kind='source_admission',action_id='pin'))
    t=GpioConsumptionTracker(ownership=ownership,admission_registry=registry,edge_index=index)
    assert t.consume(event)[0]['origin_status']=='known'
    t=GpioConsumptionTracker(ownership=ownership,admission_registry=registry)
    assert t.consume(event)[0]['origin_status']=='unknown'
    ownership._bits[('gpio','gpio_in')]=tuple(InputOwner('gpio','gpio_in',0,32,'source','forged') for _ in range(32))
    t=GpioConsumptionTracker(ownership=ownership,admission_registry=registry,edge_index=index)
    assert t.consume(event)[0]['origin_status']=='unknown'
