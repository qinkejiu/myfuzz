"""Archived native facts are offline proofs, never restored runtime authority."""
from copy import deepcopy
from pathlib import Path
import json
import pytest
from tests.integration.test_compiled_f6_contract import ROOT


@pytest.fixture(scope='module')
def archive():
    directory = ROOT/'research/input-strategy-audit-20261027/runs/shared-full-20261028/dynamic-f4-f6-v1/original'
    path = directory/'partial_prefix.json'
    if not path.exists():
        pytest.skip('first mixed native archive unavailable')
    prefix = json.loads(path.read_text())
    attempt = prefix['attempts'][0]
    local = {}
    def visit(value):
        if isinstance(value,dict):
            if {'runner_event_id','component','event_id'} <= value.keys():
                local[(value['component'],value['event_id'])] = value
            for item in value.values(): visit(item)
        elif isinstance(value,list):
            for item in value: visit(item)
    visit(attempt['case_material'])
    return dict(prefix=prefix, attempt=attempt, directory=directory, local=local,
        contract=prefix['runtime_path_admission']['execution_contract'],
        context=dict(online_plan=prefix['online_plan'],flow_records=prefix['flow_records'],
            binding=prefix['execution_binding']))


def test_original_failed_label_does_not_hide_actual_configuration_and_words(archive):
    from myfuzz.integration.compiled_f6_saved_semantics import project_saved_cpu_configuration,project_saved_word_transfer
    assert archive['attempt']['status_kind'] == 'failed'
    kwargs = dict(attempt=archive['attempt'],contract=archive['contract'],
        events=archive['prefix']['actual_events'], local_by_id=archive['local'], shared_context=archive['context'])
    assert project_saved_cpu_configuration(**kwargs)['outcome'] == 'passed'
    assert project_saved_word_transfer(**kwargs,binding=archive['prefix']['execution_binding'])['outcome'] == 'passed'


@pytest.mark.parametrize('mutation',['no_context','slot','session','flow','plan_address','admission'])
def test_archived_map_requires_independent_plan_ledger_and_actual_admission(archive,mutation):
    from myfuzz.integration.f6_saved_slot_mapping import saved_slot_mapping
    args = deepcopy(archive)
    if mutation == 'no_context': args['context'] = None
    elif mutation in ('slot','session'):
        args['attempt'][mutation+'_index' if mutation == 'slot' else 'session_case_index'] = 0
    elif mutation == 'flow': args['context']['flow_records'][0]['flow'] = 'F6'
    elif mutation == 'plan_address': args['context']['online_plan']['cases'][1]['source']['address'] -= 256
    else:
        event = next(row for row in args['prefix']['actual_events'] if row.get('kind')=='source_admission'
            and row['admission']['case_id']==args['attempt']['case_id'])
        event['admission']['case_index'] = 0
    with pytest.raises(ValueError, match='saved-shared-slot'):
        saved_slot_mapping(args['attempt'],args['contract'],args['prefix']['actual_events'],args['context'])


def test_first_F6_fetch_handover_is_previous_actual_F4(archive):
    from myfuzz.integration.f6_saved_slot_mapping import saved_slot_mapping
    row = saved_slot_mapping(archive['attempt'],archive['contract'],archive['prefix']['actual_events'],archive['context'])
    assert row == dict(slot_index=1,session_case_index=1,
        previous_case=dict(case_id=archive['context']['flow_records'][0]['case_id'],case_index=0))


def test_saved_mapping_accepts_declared_irq_instruction_before_f6(archive,monkeypatch):
    """Synthetic F5 metadata tests mapping; it is not Timer RTL evidence."""
    from myfuzz.integration.f6_saved_slot_mapping import saved_slot_mapping
    from hashlib import sha256
    digest=lambda value:sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    ctx=deepcopy(archive['context']); contract=deepcopy(archive['contract'])
    events=deepcopy([e for e in archive['prefix']['actual_events'] if e.get('kind')=='source_admission'])
    binding=ctx['binding']; admission=binding['runtime_path_admission']
    program=contract['program_contract'];program['declared_irq']={'synthetic':True}
    admission['execution_contract']=contract
    admission['execution_contract_sha256']=digest(contract)
    admission['shared_flow_paths']={'F5':deepcopy(admission['shared_storage_path']),
        'F6':dict(path_id=admission['runtime_path_ids'][1],source_id=contract['instruction_source_id'])}
    monkeypatch.setattr('myfuzz.integration.shared_slot_paths.validate_shared_flow_admission',lambda *_:None)
    row=ctx['flow_records'][0]; case=ctx['online_plan']['cases'][0]
    old=row['case_id']; new=old.replace(':F4:',':F5:')
    row.update(flow='F5',case_id=new,raw_hex='0000000100000000')
    case['case_id']=new; case['source']['action_id']=new+':source'
    data=case['source']['data_hex']
    monkeypatch.setattr('myfuzz.integration.shared_declared_irq.compile_declared_irq_slot',
        lambda declaration,index:{'code_hex':data})
    from types import SimpleNamespace
    monkeypatch.setattr('myfuzz.integration.compiled_f6_firmware.build_f6_firmware',
        lambda *_args,**_kwargs:SimpleNamespace(validate_prefix=lambda *_a,**_k:None))
    event=next(e['admission'] for e in events if e['admission']['case_id']==old)
    event['case_id']=new;event['action_id']=case['source']['action_id']
    material={k:v for k,v in case['source'].items() if k not in ('kind','scheduled_local_tick')}
    material['kind']='instruction';event['input_sha256']=digest(material)
    admission['admission_sha256']=digest({k:v for k,v in admission.items() if k!='admission_sha256'})
    binding['binding_sha256']=digest({k:v for k,v in binding.items() if k!='binding_sha256'})
    result=saved_slot_mapping(archive['attempt'],contract,events,ctx)
    assert result['previous_case']==dict(case_id=new,case_index=0)
    case['source']['data_hex']='13' * 128
    with pytest.raises(ValueError,match='typed-declared-irq-source'):
        saved_slot_mapping(archive['attempt'],contract,events,ctx)


def test_declared_union_requires_exact_storage_route(archive):
    from myfuzz.integration.f6_saved_slot_mapping import saved_shared_union
    binding = deepcopy(archive['context']['binding'])
    assert len(saved_shared_union(archive['contract'],binding)['edges']) == 2
    binding['runtime_path_admission']['runtime_contract']['edges'][5]['base'] += 4
    with pytest.raises(ValueError,match='union-route'):
        saved_shared_union(archive['contract'],binding)


def test_independent_cross_projection_accepts_actual_union_and_physical_fetch(archive):
    from myfuzz.local_harness import load_local_harness_request,plan_local_harness
    from myfuzz.local_harness.renderer import render_local_harness
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.compiled_f6_saved_semantics import project_saved_cross_component_edges
    directory = archive['directory']/'generated'/'cpu'
    request = load_local_harness_request(json.loads((directory/'request.json').read_text()))
    with elaboration_mode_scope('direct'):
        plan = plan_local_harness(request,base_dir=ROOT)
        structural = render_local_harness(plan)
    assert structural.wrapper_sv == (directory/'wrapper.sv').read_text()
    artifact = LocalRuntimeArtifact(plan,structural,json.loads((directory/'source_verification.json').read_text()),
        (directory/'runtime.sv').read_text(),(directory/'driver.cpp').read_text(),
        json.loads((directory/'artifact.json').read_text()))
    result = project_saved_cross_component_edges(attempt=archive['attempt'],contract=archive['contract'],
        binding=archive['context']['binding'],events=archive['prefix']['actual_events'],
        local_by_id=archive['local'],cpu_artifact=artifact,shared_context=archive['context'])
    assert result['outcome'] == 'passed', result['details']['issues']
    assert [row['outcome'] for row in result['details']['edges']] == ['passed']*4
