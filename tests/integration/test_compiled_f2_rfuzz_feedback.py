"""Synthetic exact-hop observations exercise projection, granting no native authority."""
from copy import deepcopy
from hashlib import sha256
from types import SimpleNamespace
import importlib.util
import pytest
from tests.integration.test_compiled_f2_decoder import inputs
from tests.integration.test_compiled_f2_read_response import generated, _journal, _check
from myfuzz.integration.compiled_f2 import CompiledF2Runtime, derive_f2_execution_binding
from tests.integration.test_compiled_f4_storage_producer import ROOT


def module():
    assert importlib.util.find_spec('myfuzz.integration.compiled_f2_feedback'), 'F2 feedback missing'
    from myfuzz.integration import compiled_f2_feedback
    return compiled_f2_feedback


def observed(generated):
    artifacts, inputs = generated
    context = _journal(generated); exact = _check(context); parts = context['parts']
    binding = derive_f2_execution_binding(artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    path = parts['row']; cid = 'synthetic:0'
    expectations = [dict(expectation_id='protocol_checker.receipt_violations', status='passed', evidence={'violations': []}),
        dict(expectation_id='cross_component.declared_edge_hops', status='passed', evidence=dict(
            edge_ids=[[e['rule_index'],e['prerequisite_index']] for e in exact['edges']],
            roles=[e['role'] for e in exact['edges']], endpoints=[[e['source_component'],e['target_component']] for e in exact['edges']],
            transaction=deepcopy(context['route']), instruction_source_id=parts['image']['source_id'],
            native_read_APB_event=exact['data_hops'][0]['native_APB_event'],
            native_read_OBI_events=[exact['data_hops'][0]['native_acceptance_event'],exact['data_hops'][0]['native_response_event']],
            dependent_RAM_write_event=exact['ram_write_hop']['memory_write_event']))]
    candidate = SimpleNamespace(case=SimpleNamespace(case_id=cid), declaration=parts['declaration'], candidate_bytes=parts['access']['address'].to_bytes(4,'little'))
    certificate = dict(schema_version='compiled_F2_chain.v1',status='certified',case_id=cid,path_id=path['path_id'],
        source_id=path['execution_contract']['load_source_id'],execution_binding_sha256=binding.digest,
        instruction_source_id=parts['image']['source_id'],instruction_address=parts['cursor'],
        instruction_sha256=sha256(bytes.fromhex(parts['declaration']['code_hex'])).hexdigest(),exact_hops=exact,assertions=expectations)
    runtime = SimpleNamespace(path=path,inputs=inputs,execution_binding=binding,run_id='synthetic',
        compiled_digest=binding.document()['compiled_document_sha256'], declared_edges=parts['edges'],
        records=[dict(raw=candidate.candidate_bytes.hex(),certificate=deepcopy(certificate))],
        attempts=[dict(case_id=cid,receipt={'status':'running','violations':[]},assertions={a['expectation_id']:dict(status=a['status'],reason='synthetic exact observation',evidence=deepcopy(a['evidence'])) for a in expectations})])
    runtime.assertion_case_evidence=lambda:CompiledF2Runtime.assertion_case_evidence(runtime)
    runtime.assertion_results=lambda:CompiledF2Runtime.assertion_results(runtime)
    return runtime,candidate,certificate


def test_targets_are_six_f2_observation_predicates(inputs):
    path=next(p for p in inputs['compiled']['paths'] if p['flow_id']=='F2' and p['status']=='executable')
    targets=module().f2_observation_targets(path)
    assert len(targets)==6
    assert [t.mask for t in targets]==[1,2,4,8,16,32]
    assert all(t.value==t.mask and t.port=='compiled_F2_case_facts' and t.target_id.startswith('compiled_f2.'+path['path_id']+'.') for t in targets)


def test_exact_synthetic_observations_hit_six_and_detach(generated):
    runtime,candidate,certificate=observed(generated)
    hits,evidence=module().f2_observation_hits(runtime=runtime,candidates=(candidate,),certificates=(certificate,))
    assert hits==frozenset(t.target_id for t in module().f2_observation_targets(runtime.path))
    assert evidence['cases'][0]['case_id']==candidate.case.case_id
    evidence['cases'].clear()
    assert runtime.assertion_case_evidence()


@pytest.mark.parametrize('change',['fabricated','binding','case','transaction','unknown_edge','missing_ram','missing_typed','missing_ref','no_receipt'])
def test_invalid_or_unwitnessed_projection_never_hits(generated,change):
    runtime,candidate,certificate=observed(generated)
    if change=='fabricated': certificate={'status':'certified'}
    elif change=='binding': certificate['execution_binding_sha256']='0'*64
    elif change=='case':certificate['case_id']='borrowed'
    elif change=='transaction': certificate['exact_hops']['data_hops'][0]['source_transaction']['source_sequence']=99
    elif change=='unknown_edge':certificate['exact_hops']['edges'][1]['rule_index']=999
    elif change=='missing_ram':certificate['exact_hops'].pop('ram_write_hop')
    elif change=='missing_typed':
        document=runtime.assertion_results();document['cases'][0]['assertions'].pop();runtime.assertion_results=lambda:document
    elif change=='missing_ref':
        document=runtime.assertion_results();document['cases'][0]['assertions'][0]['evidence_refs']=[];runtime.assertion_results=lambda:document
    else: runtime.attempts[0].pop('receipt')
    try: hits,_=module().f2_observation_hits(runtime=runtime,candidates=(candidate,),certificates=(certificate,))
    except ValueError:return
    assert hits==frozenset()


def test_empty_or_partial_test_has_zero_hits(generated):
    runtime,candidate,certificate=observed(generated)
    assert module().f2_observation_hits(runtime=runtime,candidates=(),certificates=())[0]==frozenset()
    assert module().f2_observation_hits(runtime=runtime,candidates=(candidate,),certificates=())[0]==frozenset()


@pytest.mark.parametrize('change',['unknown_edge','missing_ram','transaction'])
def test_coherent_certificate_record_substitution_still_checks_actual_facts(generated,change):
    runtime,candidate,certificate=observed(generated)
    if change=='unknown_edge':certificate['exact_hops']['edges'][1]['target_component']='borrowed'
    elif change=='missing_ram':certificate['exact_hops'].pop('ram_write_hop')
    else:certificate['exact_hops']['data_hops'][0]['source_transaction']['source_sequence']=99
    runtime.records[0]['certificate']=deepcopy(certificate)
    with pytest.raises(ValueError):
        module().f2_observation_hits(runtime=runtime,candidates=(candidate,),certificates=(certificate,))


def test_failed_attempt_makes_complete_test_vector_zero(generated):
    runtime,candidate,certificate=observed(generated)
    attempt=runtime.attempts[0]
    attempt['assertions']['cross_component.declared_edge_hops'].update(status='missing',evidence={})
    hits,diagnostics=module().f2_observation_hits(runtime=runtime,candidates=(candidate,),certificates=(certificate,))
    assert hits==frozenset() and not diagnostics['complete']
    assert diagnostics['cases'][0]['observations']['cross_component.declared_edge_hops']['status']=='missing'
