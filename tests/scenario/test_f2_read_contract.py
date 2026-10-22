from copy import deepcopy
import pytest
from tests.integration.test_compiled_f4_storage_producer import timer_loaded

@pytest.fixture(scope='module')
def inputs(tmp_path_factory):
    return timer_loaded(tmp_path_factory.mktemp('f2-contract'))[1]

def f2(inputs):
    return next(p for p in inputs['compiled']['paths'] if p['flow_id']=='F2')

def test_f2_is_real_three_edge_read_contract(inputs):
    row=f2(inputs)
    assert 'execution_contract' in row
    from myfuzz.scenario.f2_read_contract import validate_f2_read_contract
    contract=validate_f2_read_contract(row)
    assert contract['schema_version']=='compiled_F2_read_contract.v1'
    assert len(row['runtime_path_identity']['edges'])==3
    assert row['prerequisites'][0]['kind']=='ip_register_version'
    source=next(s for s in row['sources'] if s['kind']=='cpu_load_stream')
    assert (source['width'],source['bit_offset'],source['mask'])==(32,0,0xffffffff)

@pytest.mark.parametrize('key', ['address','nodes','response_mask','expectation_ids','version_selector'])
def test_marker_cannot_disagree_with_path(inputs,key):
    from myfuzz.scenario.f2_read_contract import validate_f2_read_contract
    row=deepcopy(f2(inputs));row['execution_contract'][key]=None
    with pytest.raises(ValueError):validate_f2_read_contract(row)

def test_marker_is_exact_reconstruction_with_distinct_route_endpoints(inputs):
    from myfuzz.scenario.f2_read_contract import build_f2_read_contract
    row=f2(inputs);marker=row['execution_contract']
    assert build_f2_read_contract(row)==marker
    assert set(marker)==set('schema_version instruction_source_id load_source_id source_component source_endpoint target_component target_endpoint device_id window address register field response_mask width_bytes allowed_byte_enables version_selector nodes consumption_mode expectation_ids'.split())
    nodes={n['node_id']:n for n in inputs['compiled']['runtime_path_contract']['nodes']}
    assert [nodes[marker['nodes'][key]]['component'] for key in ('image','request','response','consumed')]==[marker['source_component'],marker['source_component'],marker['target_component'],marker['source_component']]
    assert marker['version_selector']==dict(kind='ip_register_version',component=marker['target_component'],register=marker['register'],epoch_policy='current_live_epoch')
    assert marker['expectation_ids']==sorted(a['expectation_id'] for a in row['assertions'])

def test_built_marker_does_not_alias_source_access(inputs):
    from myfuzz.scenario.f2_read_contract import build_f2_read_contract
    row=deepcopy(f2(inputs));built=build_f2_read_contract(row)
    built['allowed_byte_enables'].clear()
    assert next(s for s in row['sources'] if s['kind']=='cpu_load_stream')['register_access']['allowed_byte_enables']==[15]
