import copy
import hashlib
import json
import pytest
from myfuzz.scenario.compiled_assertion_results import build_assertion_results, validate_assertion_results

IDS = ['protocol_checker.receipt_violations', 'cross_component.declared_edge_hops']
PATH = {'path_id': 'p', 'assertions': [{'expectation_id': x} for x in IDS]}

def inputs():
    kw = dict(compiled_document_sha256='a'*64, binding_sha256='b'*64, path=copy.deepcopy(PATH), run_id='r', cases=[])
    scope = {k:kw[k] for k in ('compiled_document_sha256','binding_sha256','run_id')}
    scope.update(path_sha256=hashlib.sha256(json.dumps(PATH,sort_keys=True,separators=(',',':')).encode()).hexdigest(),case_id='c')
    inventory = {str(i):dict(kind=x,outcome='passed',scope=dict(scope,expectation_id=x),details={}) for i,x in enumerate(IDS)}
    kw['cases']=[dict(case_id='c', observations={x:dict(status='passed',reason='observed',evidence_refs=[str(i)]) for i,x in enumerate(IDS)},evidence_inventory=inventory)]
    return kw

def test_pass_and_strict_saved_validation():
    kw=inputs(); doc=build_assertion_results(**kw)
    assert [x['status'] for x in doc['cases'][0]['assertions']]==['passed','passed']
    validate_assertion_results(doc,**kw)
    doc['cases'][0]['assertions'].pop()
    with pytest.raises(ValueError): validate_assertion_results(doc,**kw)

def test_absent_observations_are_missing():
    kw=inputs(); kw['cases'][0]['observations']={}; kw['cases'][0]['evidence_inventory']={}
    assert [x['status'] for x in build_assertion_results(**kw)['cases'][0]['assertions']]==['missing','missing']

@pytest.mark.parametrize('mutation', ['bad_scope','contradiction','no_refs','bad_kind','unknown','duplicate_case','bool_hash','nan','bad_status'])
def test_refuses_invalid_claims(mutation):
    kw=inputs(); case=kw['cases'][0]; item=case['evidence_inventory']['0']
    if mutation=='bad_scope': item['scope']['case_id']='other'
    if mutation=='contradiction': item['outcome']='failed'
    if mutation=='no_refs': case['observations'][IDS[0]]['evidence_refs']=[]
    if mutation=='bad_kind': item['kind']='anything'
    if mutation=='unknown': case['observations']['unknown']={}
    if mutation=='duplicate_case': kw['cases'].append(copy.deepcopy(case))
    if mutation=='bool_hash': kw['binding_sha256']=True
    if mutation=='nan': item['details']['value']=float('nan')
    if mutation=='bad_status': case['observations'][IDS[0]]['status']='ok'
    with pytest.raises(ValueError): build_assertion_results(**kw)

def test_failed_requires_contradiction_and_missing_cannot_hide_one():
    kw=inputs(); case=kw['cases'][0]; obs=case['observations'][IDS[0]]
    obs['status']='failed'
    with pytest.raises(ValueError): build_assertion_results(**kw)
    case['evidence_inventory']['0']['outcome']='failed'
    assert build_assertion_results(**kw)['cases'][0]['assertions'][0]['status']=='failed'
    del case['observations'][IDS[0]]
    assert build_assertion_results(**kw)['cases'][0]['assertions'][0]['status']=='failed'

def test_selectively_omitted_contradiction_cannot_pass():
    kw=inputs(); inventory=kw['cases'][0]['evidence_inventory']
    inventory['hidden']=copy.deepcopy(inventory['0']); inventory['hidden']['outcome']='failed'
    with pytest.raises(ValueError): build_assertion_results(**kw)

@pytest.mark.parametrize('change', ['binding','path','run','case','extra','duplicate','bool','missing_ref'])
def test_saved_identity_and_rows_cannot_be_coherently_relabelled(change):
    kw=inputs(); doc=build_assertion_results(**kw)
    if change=='binding': doc['binding_sha256']='c'*64
    if change=='path': kw['path']['other']='different full path'
    if change=='run': doc['run_id']='other'
    if change=='case': doc['cases'][0]['case_id']='other'
    if change=='extra': doc['anything']=True
    if change=='duplicate': doc['cases'][0]['assertions'].append(copy.deepcopy(doc['cases'][0]['assertions'][0]))
    if change=='bool': doc['cases'][0]['assertions'][0]['status']=True
    if change=='missing_ref': doc['cases'][0]['assertions'][0]['evidence_refs']=['unknown']
    with pytest.raises(ValueError): validate_assertion_results(doc,**kw)
