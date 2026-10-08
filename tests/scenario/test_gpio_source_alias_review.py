"""Independent selected-path source alias authority negatives; no RTL build."""
import hashlib
import json
from types import SimpleNamespace
import pytest
from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract, PreparedRuntimePathContract
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
from tests.scenario.test_gpio_consumption_versions import tick,probes


def authority(width=2):
    source='gpio_b.external_pin8'
    graph=DependencyGraph(sources=(FuzzableSource(source,'gpio_b','gpio_in',8,width,('IP_TO_CPU',)),),
                          rules=(DependencyRule('native_irq',(source,),'EVENT_ORDER'),))
    digest=hashlib.sha256(json.dumps(graph.edge_document(),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    contract=RuntimePathContract(digest,(RuntimeNode(source,'gpio_b','physical','gpio_in',8,width),
                                       RuntimeNode('native_irq','gpio_b','physical','irq',0,1)),())
    ownership=compile_ownership((InputField('gpio_b','gpio_in',32),),
        (InputOwner('gpio_b','gpio_in',0,8,'fixed','zero'),
         InputOwner('gpio_b','gpio_in',8,width,'source','external_b.pin8'),
         InputOwner('gpio_b','gpio_in',8+width,24-width,'fixed','zero')))
    runner=SimpleNamespace(sessions={'gpio_b':SimpleNamespace()},bindings=(),ownership=ownership)
    paths=tuple(('IP_TO_CPU',p) for p in graph.edge_paths_to('native_irq',direction='IP_TO_CPU'))
    prepared=PreparedRuntimePathContract(graph,contract,paths)
    compiled=prepared.bind(runner).document();compiled['declaration']=prepared.document()
    return RuntimeEdgeIndex(compiled,contract.document()),ownership,prepared.path_ids[0],compiled,contract.document()


def admission(path,role='fuzz_source',kind='source_event'):
    return SourceAdmission.create(case_id='source-case',case_index=0,source_id='gpio_b.external_pin8',
        path_id=path,direction='IP_TO_CPU',component='gpio_b',action_id='pin-action',
        role=role,input_kind=kind,input_sha256='a'*64)


def marker(action='pin-action'):
    return dict(kind='gpio_input_applied',event_id=2,actual_receipt_event_id=3,
        component='gpio_b',reset_epoch=0,source_epoch=0,local_tick=1,port='gpio_in',
        bit_lo=8,width=1,value=1,actual_input_value=256,
        origin={'kind':'source_admission','action_id':action})


def test_alias_authority_contains_bits_and_rejects_nonselected_scope():
    index,_,path,_,_=authority()
    args=['gpio_b.external_pin8',path,'IP_TO_CPU','gpio_b','gpio_in',8,1]
    assert index.source_owner_ref(*args)=='external_b.pin8'
    assert index.source_owner_ref(*args[:-2],9,1)=='external_b.pin8'
    for field,value in [(0,'external_b.pin8'),(1,'unselected'),(2,'CPU_TO_IP'),(3,'other'),
                        (4,'other'),(5,7),(5,10),(5,True),(6,3),(6,False),(0,[])]:
        changed=list(args);changed[field]=value
        assert index.source_owner_ref(*changed) is None


def test_alias_index_is_detached_from_constructor_documents():
    index,_,path,compiled,contract=authority()
    before=index.document();before_hash=index.identity_sha256
    compiled['topology']['ownership_inputs'][0]['owners'][8]['producer_ref']='forged'
    contract['nodes'][0]['port']='forged'
    assert index.source_owner_ref('gpio_b.external_pin8',path,'IP_TO_CPU','gpio_b','gpio_in',8,1)=='external_b.pin8'
    assert index.document()==before and index.identity_sha256==before_hash


@pytest.mark.parametrize('scope_fault',('no_index','wrong_path','wrong_kind','forged_marker_owner'))
def test_direct_marker_alias_never_overrides_authorized_scope(scope_fault):
    index,ownership,path,_,_=authority()
    registry=AdmissionRegistry()
    a=admission('other-path' if scope_fault=='wrong_path' else path,
                kind='instruction' if scope_fault=='wrong_kind' else 'source_event')
    registry.register(a)
    tracker=GpioConsumptionTracker(admission_registry=registry,ownership=ownership,
        edge_index=None if scope_fault in ('no_index','forged_marker_owner') else index)
    event=marker()
    if scope_fault=='forged_marker_owner':event['origin'].update(source_owner_ref='external_b.pin8',producer_ref='external_b.pin8')
    result=tracker.consume(event)
    assert result[-1]['origin_status']=='unknown'


def test_authorized_fixed_support_alias_preserves_role_and_actual_receipt():
    index,ownership,path,_,_=authority()
    registry=AdmissionRegistry();a=admission(path,role='fixed_support');registry.register(a)
    tracker=GpioConsumptionTracker(admission_registry=registry,ownership=ownership,edge_index=index)
    event=marker();event['origin']['role']='fuzz_source'
    records=tracker.consume(event)
    assert records[-1]['bit_resources'][0]['origin_refs'][0]['role']=='fixed_support'
    pre=probes(gpioen=256,input_clock_enable=4);pre['gpio_in']=256
    post=probes(gpioen=256,input_clock_enable=4,sync0=256);post['gpio_in']=256
    actual=tick(1,pre,post,component='gpio_b');actual['event_id']=3
    sampled=tracker.consume(actual)
    assert not any(e['kind']=='gpio_consumption_match' and e.get('status')=='accepted' for e in list(records)+list(sampled))
    resource=next(e for e in sampled if e['kind']=='gpio_input_sample')['stages']['sync0'][8]
    assert resource['origin_status']=='known' and resource['origin_refs'][0]['role']=='fixed_support'


def test_callable_fake_alias_provider_is_not_a_typed_authority():
    _,ownership,_,_,_=authority()
    fake=SimpleNamespace(source_owner_ref=lambda *args:'external_b.pin8')
    with pytest.raises(ValueError,match='RuntimeEdgeIndex'):
        GpioConsumptionTracker(ownership=ownership,edge_index=fake)

def test_current_owner_must_match_the_selected_compiled_owner():
    index,_,path,_,_=authority()
    changed=compile_ownership((InputField('gpio_b','gpio_in',32),),
        (InputOwner('gpio_b','gpio_in',0,8,'fixed','zero'),
         InputOwner('gpio_b','gpio_in',8,2,'source','gpio_b.external_pin8'),
         InputOwner('gpio_b','gpio_in',10,22,'fixed','zero')))
    registry=AdmissionRegistry();registry.register(admission(path))
    tracker=GpioConsumptionTracker(admission_registry=registry,ownership=changed,edge_index=index)
    assert tracker.consume(marker())[-1]['origin_status']=='unknown'
