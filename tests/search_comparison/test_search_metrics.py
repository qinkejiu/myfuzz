import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]

def module():
    path = ROOT / 'src/myfuzz/runtime/search_metrics.py'
    assert path.exists(), 'comparison metrics implementation missing'
    spec = importlib.util.spec_from_file_location('search_metrics', path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

def test_curve_is_semantically_deduplicated_and_censored():
    result = module().interaction_metrics([
        {'seconds': 2, 'semantic_key': 'a'},
        {'seconds': 3, 'semantic_key': 'a'},
        {'seconds': 7, 'semantic_key': 'b'},
    ], 10, [{'seconds': 1, 'case_id': str(i)} for i in range(4)])
    assert result['auc_count_seconds'] == 11
    assert result['first_hit_seconds'] == 2
    assert result['unique_certified_interactions'] == 2
    assert result['useful_cases_per_second'] == .4

def test_comparison_refuses_missing_or_different_denominator():
    m = module()
    row = {'identity': {'target':'gpio', 'source':'digest', 'profile':'p',
                       'catalog_sha256':'catalog', 'coverage_metric':'certified-interaction.v1'},
           'budget': {'cases':8,'seconds':10}, 'seed':1,
           'coverage': {'status':'unavailable'}}
    assert m.comparability(row, row)['coverage_comparable'] is False
    other = {**row, 'budget': {'cases':9,'seconds':10}}
    assert m.comparability(row, other)['status'] == 'incomparable'
    with pytest.raises(ValueError):
        m.interaction_metrics([{'seconds':-1,'semantic_key':'x'}], 10, [])

def test_summarize_preserves_missing_coverage_and_overhead():
    row = {'budget': {'seconds': 10}, 'metrics': {'certified_events': [],
        'useful_cases': 0, 'decision_seconds': [.1,.2], 'fresh': {'status':'not-run'}},
        'coverage': {'status':'unavailable','reason':'no instrumentation'}}
    result = module().summarize(row)
    assert result['first_hit_seconds'] is None
    assert result['first_hit_censored']
    assert result['coverage']['status'] == 'unavailable'
    assert result['decision_overhead_seconds'] == pytest.approx(.3)

def test_available_coverage_rejects_impossible_counts():
    row = {'budget': {'seconds': 10}, 'metrics': {'certified_events': [], 'useful_cases': 0},
        'coverage': {'status':'available','metric':'line','denominator_sha256':'x','total':4,'covered':5}}
    with pytest.raises(ValueError, match='coverage'):
        module().summarize(row)

def test_useful_rate_excludes_late_consumers_and_deduplicates_cases():
    row = {'budget': {'seconds': 10}, 'metrics': {'certified_events': [], 'useful_cases': 99,
        'useful_case_events': [{'seconds':2,'case_id':'a'}, {'seconds':3,'case_id':'a'},
                               {'seconds':10,'case_id':'b'}, {'seconds':11,'case_id':'c'}]}}
    result = module().summarize(row)
    assert result['useful_cases_per_second'] == .2
    assert result['useful_cases_within_budget'] == 2

def test_untimed_useful_aggregate_is_unavailable():
    result = module().summarize({'budget': {'seconds': 10},
        'metrics': {'certified_events': [], 'useful_cases': 99}})
    assert result['useful_cases_per_second'] is None
    assert result['useful_cases_status'] == 'unavailable-no-timed-case-events'


def unknown_row():
    return {'seed':1,'identity':{'target':'f5','source':'s','profile':'p',
        'catalog_sha256':'c','coverage_metric':None}, 'budget':{'cases':2,'seconds':1},
        'metrics':{'certified_events':None,'useful_case_events':None},
        'coverage':{'status':'unavailable'}}


def test_unknown_interaction_is_unavailable_not_zero():
    result = module().summarize(unknown_row())
    assert result['interaction_status'] == 'unavailable'
    for key in ('auc_count_seconds','auc_mean_count','first_hit_seconds',
                'first_hit_censored','unique_certified_interactions','useful_cases_per_second'):
        assert result[key] is None


def test_unknown_primary_can_compare_attested_coverage_only():
    m = module()
    row = unknown_row()
    row['coverage'] = {'status':'available','metric':'line','denominator_sha256':'a'*64,
        'total':4,'covered':2,'attestation':'recorded-prefix-replay.v1'}
    comparison = m.comparability(row,row)
    assert comparison['status'] == 'incomparable'
    assert comparison['execution_status'] == 'comparable'
    assert comparison['coverage_comparable'] is True
    other = {**row,'identity':{**row['identity'],'source':'other'}}
    assert m.comparability(row,other)['coverage_comparable'] is False
    other = {**row,'budget':{'cases':3,'seconds':1}}
    assert m.comparability(row,other)['coverage_comparable'] is False
    other = {**row,'coverage':{**row['coverage'],'attestation':None}}
    assert m.comparability(row,other)['coverage_comparable'] is False


def test_unknown_identity_missing_source_is_not_observed_comparable():
    row = unknown_row()
    row['identity']['source'] = None
    comparison = module().comparability(row,row)
    assert comparison['execution_status'] == 'incomparable'
    assert 'identity.source' in comparison['execution_reasons']
    assert comparison['coverage_comparable'] is False


def test_explicit_execution_modes_are_part_of_fairness():
    m = module()
    row = {'identity': {'target': 'gpio', 'source': 's', 'profile': 'p',
                       'catalog_sha256': 'c', 'coverage_metric': 'certified-interaction.v1'},
           'budget': {'cases': 1, 'seconds': 1}, 'seed': 1,
           'metrics': {'certified_events': []}, 'execution_mode': 'search'}
    assert m.comparability(row, {**row, 'execution_mode': 'acceptance'})['execution_reasons'] == ['execution_mode']
    legacy = dict(row)
    legacy.pop('execution_mode')
    assert m.comparability(row, legacy)['execution_status'] == 'comparable'


def test_actual_timed_evidence_without_fixed_budget_keeps_counts_not_auc():
    m = module()
    row = unknown_row()
    row['budget']['seconds'] = None
    row['identity']['coverage_metric'] = 'certified-ram-dut-read.v1'
    row['metrics'] = dict(certified_events=[{'seconds':2,'semantic_key':'ram:a'},
        {'seconds':3,'semantic_key':'ram:a'}], useful_case_events=[{'seconds':2,'case_id':'read'}])
    result = m.summarize(row)
    assert result['unique_certified_interactions'] == 1
    assert result['first_hit_seconds'] == 2
    assert result['auc_mean_count'] is None
    assert result['auc_count_seconds'] is None
    assert result['useful_cases_per_second'] is None
    comparison = m.comparability(row,row)
    assert comparison['execution_status'] == 'comparable'
    assert comparison['primary_status'] == 'incomparable'
    assert 'no-fixed-time-budget' in comparison['reasons']


def test_no_fixed_budget_does_not_skip_evidence_validation():
    with pytest.raises(ValueError, match='certified-event'):
        module().interaction_metrics([{'seconds':float('nan'),'semantic_key':'ram:a'}], None, [])
