from myfuzz.local_harness.compiled_execution_projection import assess_compiled_execution
from tests.integration.test_generated_dual_runtime_loaded_real import _loaded
from myfuzz.integration.cv32e40p_pulp_online import describe_generated_execution


def test_real_cv32e40p_paths_are_downgraded_without_claiming_retirement(tmp_path):
    artifacts,inputs=_loaded(tmp_path)
    report=assess_compiled_execution(artifacts=artifacts,compiled_inputs=inputs,
        runtime_declaration=describe_generated_execution())
    assert report['capability_executable']==4
    assert report['execution_supported']==0
    assert not report['runtime_admitted']
    paths={p['flow_id']:p for p in report['paths']}
    assert paths['F1']['status']=='unsupported'
    assert 'authenticated-retirement-observation-missing' in {r['code'] for r in paths['F1']['refusals']}
    f4=paths['F4']
    assert 'compiled-register-outside-runtime-candidate-windows' in {r['code'] for r in f4['refusals']}
    target=f4['register_targets'][0]
    assert target['address']==0x40001004
    assert target['offset']==4
    assert target['producer_component']=='gpio_a'
    assert target['physical_bus_outputs']
    assert target['artifact_digest']==artifacts['gpio_a'].runtime_document['artifact_digest']


def test_familiar_names_or_forged_handler_tables_never_grant_execution(tmp_path):
    import copy
    artifacts,inputs=_loaded(tmp_path)
    declaration=describe_generated_execution()
    for field in ('source_projection','bound_projection','compiled_prerequisite_handlers',
                  'compiled_assertion_handlers','compiled_seed_projection'):
        declaration[field]={'invented':'caller says implemented'}
    declaration['authenticated_retirement_contract']={'caller_says':'rvfi'}
    report=assess_compiled_execution(artifacts=artifacts,compiled_inputs=inputs,
        runtime_declaration=declaration)
    assert not report['runtime_admitted']
    assert all(r['status']=='unsupported' for r in report['paths'])
    changed=copy.deepcopy(inputs['compiled'])
    changed['paths'][0]['constraints']['source_constraints'][0]['mask']^=1
    report=assess_compiled_execution(artifacts=artifacts,compiled_inputs={**inputs,'compiled':changed},
        runtime_declaration=declaration)
    assert report['status']=='input_refused'
    assert report['paths']==[]


def test_cli_persists_downgrade_and_refuses_before_real_start(tmp_path):
    import json
    from tests.integration.test_auto_harness_test import (run_cli,driver_arguments,
        CV32E40P_COMPOSE,CV32E40P_CPU)
    client=tmp_path/'client';client.write_bytes(b'never executed')
    cache=tmp_path/'cache';cache.mkdir()
    output=tmp_path/'out'
    result,summary=run_cli(*driver_arguments(output,CV32E40P_COMPOSE,CV32E40P_CPU,
        '--runtime','cv32e40p-pulp-dual-source','--client-binary',client,
        '--cache-dir',cache,'--max-tests',1,'--budget-seconds',1))
    assert result.returncode!=0
    projection=json.loads((output/'execution_projection.v1.json').read_text())
    assert projection['capability_executable']==4
    assert projection['execution_supported']==0
    assert projection['runtime_admitted'] is False
    assert summary['stages']['execution_projection']['execution_status']=='unsupported'
    refusal=json.loads((output/'session-refusal.json').read_text())
    assert refusal['code']=='compiled-runtime-input-refused'
    assert not (output/'session').exists()
