"""Final F2 report material keeps source evidence independent of result JSON."""
import importlib
import importlib.util
from copy import deepcopy
from types import SimpleNamespace
import pytest


def module():
    name='myfuzz.integration.compiled_runtime_report'
    assert importlib.util.find_spec(name) is not None,'F2 runtime report integration missing'
    return importlib.import_module(name)


def test_report_requires_actual_full_fresh_comparison_before_projection():
    called=[]
    runtime=SimpleNamespace(assertion_results=lambda:called.append('assertions'))
    with pytest.raises(ValueError,match='full-fresh'):
        module().capture_f2_report_material(compiled={},runtime=runtime,harness_set={},
            fresh_verification={'matches':False,'first_difference':'data','verification_scope':'full'})
    assert called==[]


def test_report_rejects_exported_assertions_that_change_between_reads(monkeypatch):
    mod=module();calls=[]
    document={'schema_version':'compiled_assertion_results.v1','cases':[]}
    runtime=SimpleNamespace(path={'path_id':'F2:ram.image'},run_id='run',
        execution_binding=SimpleNamespace(document=lambda:{'schema_version':'compiled_F2_execution_binding.v1'}),
        assertion_results=lambda:deepcopy(document),assertion_case_evidence=lambda:[])
    def build(compiled,**kwargs):
        calls.append(kwargs)
        document['cases'].append('changed')
        return {'schema_version':'capability_report.v1'}
    monkeypatch.setattr(mod,'build_capability_report',build)
    with pytest.raises(ValueError,match='report-input-drift'):
        mod.capture_f2_report_material(compiled={},runtime=runtime,harness_set={},
            fresh_verification={'matches':True,'first_difference':None,'verification_scope':'full'})
    assert calls[0]['assertion_evidence']['cases']==[]
    assert calls[0]['assertion_results']['cases']==[]


def test_report_uses_independent_live_cases_and_preserves_copies(monkeypatch):
    mod=module();seen=[]
    assertions={'schema_version':'compiled_assertion_results.v1','cases':[]}
    cases=[]
    runtime=SimpleNamespace(path={'path_id':'F2:ram.image'},run_id='run',
        execution_binding=SimpleNamespace(document=lambda:{'schema_version':'compiled_F2_execution_binding.v1'}),
        assertion_results=lambda:deepcopy(assertions),assertion_case_evidence=lambda:deepcopy(cases))
    def build(compiled,**kwargs):
        seen.append(kwargs)
        return {'schema_version':'capability_report.v1','assertion_results':[]}
    monkeypatch.setattr(mod,'build_capability_report',build)
    material=mod.capture_f2_report_material(compiled={},runtime=runtime,harness_set={},
        fresh_verification={'matches':True,'first_difference':None,'verification_scope':'full'})
    assert seen[0]['assertion_evidence']['path_id']=='F2:ram.image'
    assert seen[0]['assertion_results']==assertions
    assert material['assertion_evidence']['cases']==cases
    assert material['capability_report']['schema_version']=='capability_report.v1'
    material['assertions']['cases'].append('mutation')
    assert assertions['cases']==[]


from tests.scenario.test_capability_compiled_assertions import admitted, inputs as assertion_inputs


def runtime_from_evidence(kwargs):
    evidence=kwargs['assertion_evidence']
    return SimpleNamespace(path={'path_id':evidence['path_id']},run_id=evidence['run_id'],
        execution_binding=SimpleNamespace(document=lambda:deepcopy(evidence['execution_binding'])),
        assertion_results=lambda:deepcopy(kwargs['assertion_results']),
        assertion_case_evidence=lambda:deepcopy(evidence['cases']))


def test_real_capability_report_receives_joined_runtime_inputs(admitted):
    mod=module();compiled,kwargs=assertion_inputs(admitted)
    material=mod.capture_f2_report_material(compiled=compiled,
        runtime=runtime_from_evidence(kwargs),harness_set=None,
        fresh_verification={'matches':True,'first_difference':None,'verification_scope':'full'})
    report=material['capability_report']
    assert len(report['assertion_results'])==2
    assert all(row['status']=='passed' for row in report['assertion_results'])
    path=next(p for p in report['paths'] if p['path_id']==kwargs['assertion_evidence']['path_id'])
    assert not any(t['claimed'] for t in path['tiers'] if t['tier']!='Catalog')


@pytest.mark.parametrize('mutation',['omit_assertion','scope','binding','inventory'])
def test_report_refuses_unjoined_live_material(admitted,mutation):
    mod=module();compiled,kwargs=assertion_inputs(admitted)
    if mutation=='omit_assertion':kwargs['assertion_results']['cases'][0]['assertions'].pop()
    elif mutation=='scope':kwargs['assertion_evidence']['run_id']='borrowed-run'
    elif mutation=='binding':kwargs['assertion_evidence']['execution_binding']['binding_sha256']='a'*64
    else:kwargs['assertion_evidence']['cases'][0]['evidence_inventory'].clear()
    with pytest.raises(ValueError):
        mod.capture_f2_report_material(compiled=compiled,runtime=runtime_from_evidence(kwargs),
            harness_set=None,fresh_verification={'matches':True,'first_difference':None,'verification_scope':'full'})
