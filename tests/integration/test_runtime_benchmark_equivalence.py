from copy import deepcopy
import pytest
from myfuzz.integration.runtime_benchmark_equivalence import compare_benchmarks


def inputs():
    prefix={'flow_records':[{'flow':'F1','raw_hex':'00','status':'passed'}],
            'actual_events':[{'kind':'tick','value':7}], 'trace_local_ticks':{'cpu':1}}
    report={'status':'complete','fresh_matches':True,'native_eval_timers_enabled':True,
            'fetch_scan_mode':'legacy','native_eval':{phase:{'cpu':{'status':'observed',
                'runtime_eval_count':4,'startup_eval_count':2,'runtime_eval_ns':99}}
                for phase in ('original','fresh')},'wall_seconds':10}
    candidate=deepcopy(report);candidate.update(fetch_scan_mode='snapshot',wall_seconds=8)
    return report,candidate,prefix,deepcopy(prefix)


def test_full_prefix_and_eval_counts_required_but_elapsed_may_differ():
    a,b,p,q=inputs()
    result=compare_benchmarks(a,b,p,q,normalize=lambda x:x)
    assert result['equivalent'] and result['wall_ratio_candidate_over_baseline']==.8
    assert result['authority'] is False


@pytest.mark.parametrize('change',('event','eval','incomplete','mode'))
def test_mismatch_never_authorizes_timing_comparison(change):
    a,b,p,q=inputs()
    if change=='event':q['actual_events'][0]['value']=8
    if change=='eval':b['native_eval']['fresh']['cpu']['runtime_eval_count']=5
    if change=='incomplete':b['fresh_matches']=False
    if change=='mode':b['fetch_scan_mode']='legacy'
    result=compare_benchmarks(a,b,p,q,normalize=lambda x:x)
    assert not result['equivalent']
    assert 'wall_ratio_candidate_over_baseline' not in result


def test_topology_ab_holds_fetch_snapshot_fixed():
    a,b,p,q=inputs()
    a.update(fetch_scan_mode='snapshot',topology_validation_mode='legacy')
    b.update(topology_validation_mode='boundary')
    result=compare_benchmarks(a,b,p,q,normalize=lambda x:x,varying_axis='topology_validation')
    assert result['equivalent'] and result['varying_axis']=='topology_validation'
    assert result['wall_ratio_candidate_over_baseline']==.8


@pytest.mark.parametrize('axis',['fetch_scan','topology_validation'])
def test_two_changed_axes_never_authorize_comparison(axis):
    a,b,p,q=inputs()
    a['topology_validation_mode']='legacy';b['topology_validation_mode']='boundary'
    result=compare_benchmarks(a,b,p,q,normalize=lambda x:x,varying_axis=axis)
    assert not result['equivalent'] and not result['checks']['single_varying_axis']
    assert 'wall_ratio_candidate_over_baseline' not in result


def test_fetch_ab_accepts_same_explicit_topology_mode():
    a,b,p,q=inputs()
    a['topology_validation_mode']=b['topology_validation_mode']='boundary'
    assert compare_benchmarks(a,b,p,q,normalize=lambda x:x)['equivalent']


@pytest.mark.parametrize('change',['missing_topology','missing_fixed_mode','legacy_fetch'])
def test_topology_ab_requires_both_declarations_and_snapshot_fetch(change):
    a,b,p,q=inputs()
    a.update(fetch_scan_mode='snapshot',topology_validation_mode='legacy')
    b.update(topology_validation_mode='boundary')
    if change=='missing_topology':a.pop('topology_validation_mode')
    if change=='missing_fixed_mode':b.pop('fetch_scan_mode')
    if change=='legacy_fetch':a['fetch_scan_mode']=b['fetch_scan_mode']='legacy'
    assert not compare_benchmarks(a,b,p,q,normalize=lambda x:x,varying_axis='topology_validation')['equivalent']
