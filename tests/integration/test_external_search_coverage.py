from copy import deepcopy

from scripts.compare_external_search_coverage import compare_search_runs, load_external_verilator


def run(covered, *, commands=10):
    return {'coverage_kind':'verilator-line-block', 'cache_verified':True,
            'dut_sources':['dut.v'], 'dut_source_sha256':{'dut.v':'a'*64},
            'dut_points':{'point-1':int(covered), 'point-2':0},
            'commands':{'count':commands, 'local_ticks':commands}}


def metadata(tool):
    return {'tool':tool, 'version':'1', 'budget_seconds':60,
            'elapsed_seconds':60, 'seed':7, 'end_reason':'budget_exhausted'}


def test_different_search_traces_same_budget_and_points_can_be_compared():
    result=compare_search_runs(run(True),run(False,commands=25),metadata('ours'),metadata('external'))
    assert result['status']=='comparable'
    assert result['coverage']=={'left_covered':1,'right_covered':0,'total':2,
                                'right_minus_left':-1,'left_only':1,'right_only':0}
    assert result['search_budget_evidence']=='self_reported'
    assert result['runs'][0]['commands']!=result['runs'][1]['commands']


def test_mismatched_inputs_and_short_run_cannot_claim_comparable():
    left=run(True);right=deepcopy(left);right['dut_source_sha256']['dut.v']='b'*64
    result=compare_search_runs(left,right,metadata('ours'),metadata('other'))
    assert result['status']=='not_comparable' and 'dut_sources_mismatch' in result['reasons']
    result=compare_search_runs(left,left,metadata('ours'),{**metadata('other'),'budget_seconds':30})
    assert result['status']=='not_comparable' and 'search_budget_mismatch' in result['reasons']
    result=compare_search_runs(left,left,metadata('ours'),{**metadata('other'),'elapsed_seconds':5})
    assert result['status']=='not_comparable' and 'search_budget_not_exhausted' in result['reasons']


def test_unknown_points_or_unverified_cache_are_not_comparable():
    left=run(True);right=run(False);right['dut_points']={'other':1}
    right['cache_verified']=False
    result=compare_search_runs(left,right,metadata('ours'),metadata('other'))
    assert result['status']=='not_comparable'
    assert {'point_set_mismatch','cache_unverified'}<=set(result['reasons'])


def test_external_verilator_data_is_compared_without_local_cache(tmp_path):
    import hashlib
    import json

    source = tmp_path / 'dut.v'
    source.write_text('module dut; endmodule\n')
    fields = {'f': str(source), 'l': '1', 'n': '1', 't': 'line',
              'page': 'v_line/dut', 'o': 'dut', 'h': 'TOP.dut'}
    record = ''.join('\x01' + k + '\x02' + v for k, v in fields.items())
    data = tmp_path / 'coverage.dat'
    data.write_text("# SystemC::Coverage-3\nC '" + record + "' 3\n")
    relative_fields = {**fields, 'f': 'dut.v'}
    point = json.dumps(relative_fields, sort_keys=True, separators=(',', ':'))
    left = run(True)
    left['dut_points'] = {point: 0}
    left['dut_source_sha256'] = {'dut.v': hashlib.sha256(source.read_bytes()).hexdigest()}
    external = load_external_verilator(data, source_root=tmp_path, dut_sources=left['dut_sources'],
                                      verilator_version='5.0', build_description='verilator --coverage-line')
    result = compare_search_runs(left, external, metadata('ours'), metadata('other'))
    assert result['status'] == 'comparable'
    assert result['coverage']['right_covered'] == 1
    assert result['runs'][1]['commands'] is None
    assert result['runs'][1]['coverage_provenance'] == 'external_self_reported_build'
    source.write_text('changed\n')
    changed = load_external_verilator(data, source_root=tmp_path, dut_sources=left['dut_sources'],
                                     verilator_version='5.0', build_description='verilator --coverage-line')
    assert 'dut_sources_mismatch' in compare_search_runs(left, changed, metadata('ours'), metadata('other'))['reasons']
    left['dut_points'] = {'different-point': 0}
    assert 'point_set_mismatch' in compare_search_runs(left, external, metadata('ours'), metadata('other'))['reasons']
