"""Independent review of immutable compiled physical-source alias authority."""
import hashlib
import json
from types import SimpleNamespace

from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract, RuntimeNode, RuntimePathContract
from myfuzz.scenario.runtime_edge_index import RuntimeEdgeIndex
from myfuzz.scenario.gpio_consumption import GpioConsumptionTracker
from myfuzz.scenario.source_provenance import AdmissionRegistry, SourceAdmission
from tests.scenario.test_gpio_consumption_versions import applied


def authority(source_id='logical.pin8', physical_owner='external.pin8'):
    graph=DependencyGraph(sources=(FuzzableSource(source_id,'gpio_b','gpio_in',8,1,('IP_TO_CPU',),'source'),),
                          rules=(DependencyRule('sink',(source_id,),'EVENT_ORDER'),))
    digest=hashlib.sha256(json.dumps(graph.edge_document(),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    contract=RuntimePathContract(digest,(RuntimeNode(source_id,'gpio_b','physical','gpio_in',8,1),
                                        RuntimeNode('sink','gpio_b','logical')),())
    ownership=compile_ownership((InputField('gpio_b','gpio_in',32),),(
        InputOwner('gpio_b','gpio_in',0,8,'fixed','zero'),
        InputOwner('gpio_b','gpio_in',8,1,'source',physical_owner),
        InputOwner('gpio_b','gpio_in',9,23,'fixed','zero')))
    runner=SimpleNamespace(sessions={'gpio_b':SimpleNamespace()},ownership=ownership,bindings=())
    path=graph.edge_paths_to('sink',direction='IP_TO_CPU')[0]
    prepared=PreparedRuntimePathContract(graph,contract,(('IP_TO_CPU',path),))
    compiled={**prepared.bind(runner).document(),'declaration':prepared.document()}
    index=RuntimeEdgeIndex(compiled,contract.document())
    key=dict(source_id=source_id,path_id=prepared.path_ids[0],direction='IP_TO_CPU',
             component='gpio_b',port='gpio_in',bit_lo=8,width=1)
    return index,compiled,ownership,key


def test_query_is_exact_selected_source_path_direction_component_port_and_bits():
    index,_,_,key=authority()
    assert callable(getattr(index,'source_owner_ref',None)), 'compiled source authority helper missing'
    assert index.source_owner_ref(**key)=='external.pin8'
    for field,bad in (('source_id','external.pin8'),('path_id','other-path'),('direction','CPU_TO_IP'),
                      ('component','gpio_a'),('port','other'),('bit_lo',9),('width',2),
                      ('bit_lo',True),('width',True),('source_id',[]),('path_id',{})):
        assert index.source_owner_ref(**{**key,field:bad}) is None,(field,bad)


def test_authority_does_not_follow_mutated_caller_snapshot_or_returned_document():
    index,compiled,_,key=authority()
    assert callable(getattr(index,'source_owner_ref',None)), 'compiled source authority helper missing'
    compiled['topology']['ownership_inputs'][0]['owners'][8]['producer_ref']='forged'
    document=index.document();document['path_ids'].clear()
    assert index.source_owner_ref(**key)=='external.pin8'


def tracker_input(index,ownership,key,**admission_changes):
    registry=AdmissionRegistry()
    material=dict(case_id='original-case',case_index=0,source_id=key['source_id'],path_id=key['path_id'],
        direction=key['direction'],component=key['component'],action_id='original-action',
        role='fuzz_source',input_kind='source_event',input_sha256='a'*64)
    material.update(admission_changes)
    registry.register(SourceAdmission.create(**material))
    tracker=GpioConsumptionTracker(admission_registry=registry,ownership=ownership,edge_index=index)
    event=applied(1);event.update(component='gpio_b',origin={'kind':'source_admission','action_id':'original-action'})
    return tracker.consume(event)[-1]


def test_strict_authority_accepts_alias_but_rejects_wrong_admitted_path():
    index,_,ownership,key=authority()
    assert tracker_input(index,ownership,key)['origin_status']=='known'
    assert tracker_input(index,ownership,key,path_id='other-path')['origin_status']=='unknown'
    assert tracker_input(index,ownership,key,direction='CPU_TO_IP')['origin_status']=='unknown'


def test_matching_id_cannot_bypass_strict_authority_for_wrong_path():
    index,_,ownership,key=authority(source_id='physical.pin8',physical_owner='physical.pin8')
    assert tracker_input(index,ownership,key,path_id='other-path')['origin_status']=='unknown'


def test_changed_actual_ownership_cannot_borrow_compiled_alias_ref():
    index,_,_,key=authority()
    changed=compile_ownership((InputField('gpio_b','gpio_in',32),),(
        InputOwner('gpio_b','gpio_in',0,8,'fixed','zero'),
        InputOwner('gpio_b','gpio_in',8,1,'source','forged.pin8'),
        InputOwner('gpio_b','gpio_in',9,23,'fixed','zero')))
    assert tracker_input(index,changed,key)['origin_status']=='unknown'
