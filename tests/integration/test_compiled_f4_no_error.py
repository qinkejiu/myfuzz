"""Success-only no-error ABI policy, without launching native processes."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import pytest
from tests.integration import test_compiled_f4 as fixture


@pytest.fixture(scope='module')
def admitted(tmp_path_factory):
    original=fixture.CONFIG
    try:
        fixture.CONFIG=fixture.ROOT/'configs/scenarios/compiled-f4-obi-apb'
        return fixture.loaded(tmp_path_factory.mktemp('no-error'))
    finally:fixture.CONFIG=original


def sources(inputs):
    path=next(p for p in inputs['compiled']['paths'] if p['flow_id']=='F4')
    return path,next(s for s in path['sources'] if s['kind']=='instruction_image'),next(s for s in path['sources'] if s['kind']=='cpu_mmio_stream')


def test_original_no_error_fixture_is_success_only_positive(admitted):
    from myfuzz.integration.compiled_f4 import admit_f4,_cpu_error_policy
    artifacts,inputs=admitted;path,image,stream=sources(inputs)
    with patch('subprocess.Popen',side_effect=AssertionError('pure admission')):
        assert admit_f4(artifacts=artifacts,compiled_inputs=inputs)==path
        policy=_cpu_error_policy(artifacts['processor'],image,stream)
    assert policy['mode']=='fail_stop_no_error_pin'
    assert policy['native_error_observation'] is False
    assert {r['contract']['variant_id'] for r in policy['selected_contracts']}=={'read-only-no-error-pins','read-write-no-error-pins'}


@pytest.mark.parametrize('corruption',['wrong_variant','false_fact','fake_tap','missing_adapter','adapter_digest','missing_failstop'])
def test_contradictory_no_error_artifact_refused(admitted,corruption):
    from myfuzz.integration.compiled_f4 import _cpu_error_policy
    artifacts,inputs=admitted;_,image,stream=sources(inputs);artifact=artifacts['processor']
    doc=deepcopy(artifact.runtime_document);runtime=artifact.runtime_sv
    if corruption=='wrong_variant':doc['selected_template']['executor']['protocol_templates'][0]['contract']['variant_id']='read-write'
    if corruption=='false_fact':doc['selected_template']['executor']['binding']['declared_profile_facts']['error_response']=True
    if corruption=='fake_tap':doc['base_protocol_traces']['traces'][0]['signals']['error']='constant_zero'
    if corruption=='missing_adapter':doc['adapter_sources']=[]
    if corruption=='adapter_digest':doc['adapter_sources'][0]['sha256']='0'*64
    if corruption=='missing_failstop':runtime=runtime.replace('.HAS_ERROR(0)','.HAS_ERROR(1)')
    with pytest.raises(ValueError):_cpu_error_policy(replace(artifact,runtime_document=doc,runtime_sv=runtime),image,stream)


def test_no_error_native_error_assertion_is_unsupported(admitted):
    from myfuzz.integration.compiled_f4 import _cpu_error_policy,_check_error_assertions
    artifacts,inputs=admitted;path,image,stream=sources(inputs)
    policy=_cpu_error_policy(artifacts['processor'],image,stream)
    path=deepcopy(path);path['assertions'].append({'expectation_id':'protocol_checker.native_error_response'})
    with pytest.raises(ValueError,match='native-error-observation-unsupported'):_check_error_assertions(path,policy)


def test_no_error_exact_hops_emit_null_not_fake_zero():
    from tests.integration.test_compiled_execution_files import exact_hop_fixture
    from myfuzz.integration.compiled_f4 import check_f4_exact_hops
    arguments=exact_hop_fixture()
    for signals in arguments['traces'].values():signals.pop('error')
    policy=dict(mode='fail_stop_no_error_pin',native_error_observation=False)
    result=check_f4_exact_hops(**arguments,error_policy=policy)
    assert result['cpu_error_policy']==policy
    assert all(row['error'] is None for row in result['instruction_hops']+[hop['native_obi'] for hop in result['data_hops']])
    with pytest.raises(ValueError,match='native-CPU-response-error'):
        check_f4_exact_hops(**arguments)


def test_unreviewed_adapter_source_cannot_supply_failstop_policy(admitted):
    from myfuzz.integration.compiled_f4 import _cpu_error_policy
    artifacts,inputs=admitted;_,image,stream=sources(inputs)
    with patch('pathlib.Path.read_bytes',return_value=b'// fail-stop removed'):
        with pytest.raises(ValueError,match='adapter-closure'):
            _cpu_error_policy(artifacts['processor'],image,stream)


def test_no_error_policy_cannot_ignore_exposed_native_error_role():
    from tests.integration.test_compiled_execution_files import exact_hop_fixture
    from myfuzz.integration.compiled_f4 import check_f4_exact_hops
    with pytest.raises(ValueError,match='policy-trace-contradiction'):
        check_f4_exact_hops(**exact_hop_fixture(),
            error_policy=dict(mode='fail_stop_no_error_pin',native_error_observation=False))
