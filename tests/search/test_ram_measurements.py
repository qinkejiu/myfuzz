"""Measured RAM interaction times never come from replay policy costs."""
from types import SimpleNamespace
from myfuzz.search.ram_case_adapter import RamRecordSelector
from tests.search.test_ram_search import field, relation


def test_live_measured_events_use_campaign_clock_and_semantic_relation_set(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr('myfuzz.search.ram_case_adapter.perf_counter_ns', lambda: int(clock[0] * 1e9))
    selector = RamRecordSelector(None, flow='mixed', records=['F3:55000000','F1:03200000'],
                                 policy='state', seed=7, cases=2)
    selector.start_search_clock(lambda: clock[0], 10.0)
    current = field()
    selector._handle = SimpleNamespace(current_state=lambda: current,
        observe_case=lambda case_id: {'relations':[relation(current, reader=case_id)]})
    selector._runtime = SimpleNamespace(records=[{'certificate': {'case_id':'reader'}}])
    selector._replay_costs = [(999_000_000_000, 999_000_000_000)]
    row = selector.choose()
    clock[0] = 13.0
    selector.settle(row)
    selector.finish_search_clock()
    measured = selector.measurements(mode='fresh')
    assert measured['certified_events'][0]['seconds'] == 3
    assert measured['search_seconds'] == 3
    assert measured['fresh']['status'] == 'verified'
    assert measured['certified_events'][0]['semantic_key'].startswith('ram-write-read:')
    assert measured['useful_case_events'] == [{'seconds':3.0,'case_id':'reader'}]
    assert selector.document()['transitions'][0]['policy_cost_ns'] == 999_000_000_000
    assert measured['timing_scope'] == 'campaign_execution_clock'


def test_empty_actual_search_has_available_empty_measurement_not_admission_credit():
    selector = RamRecordSelector(None, flow='mixed', records=['F3:55000000','F1:03200000'],
                                 policy='state', seed=7, cases=1)
    selector.start_search_clock(lambda: 17.0, 17.0)
    selector.finish_search_clock()
    measured = selector.measurements(mode='original')
    assert measured['certified_events'] == []
    assert measured['useful_case_events'] == []
    assert measured['search_seconds'] == 0


def test_measured_ram_rows_enter_standard_comparator_without_policy_time(monkeypatch):
    from myfuzz.runtime.search_metrics import summarize, comparability
    clock = [0.0]
    monkeypatch.setattr('myfuzz.search.ram_case_adapter.perf_counter_ns', lambda: int(clock[0]*1e9))
    selector = RamRecordSelector(None, flow='mixed', records=['F3:55000000','F1:03200000'],
                                 policy='state', seed=7, cases=1)
    selector.start_search_clock(lambda: clock[0], 0)
    current = field()
    selector._handle = SimpleNamespace(current_state=lambda: current,
        observe_case=lambda case_id: {'relations':[relation(current, reader=case_id)]})
    selector._runtime = SimpleNamespace(records=[{'certificate':{'case_id':'reader'}}])
    row = selector.choose()
    clock[0] = 2
    selector.settle(row)
    clock[0] = 3
    selector.finish_search_clock()
    summary = dict(seed=7, budget={'cases':1,'seconds':10},
        identity=dict(target='ram',source='s',profile='p',catalog_sha256=selector.catalog.identity,
                      coverage_metric='certified-ram-dut-read.v1'),
        metrics=selector.measurements(mode='original'))
    result = summarize(summary)
    assert result['unique_certified_interactions'] == 1
    assert result['auc_count_seconds'] == 8
    assert result['first_hit_seconds'] == 2
    assert result['search_seconds'] == 3
    assert comparability(summary,summary)['primary_status'] == 'comparable'
