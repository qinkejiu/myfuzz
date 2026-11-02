from contextlib import contextmanager
import sys
import pytest
from myfuzz.integration.runtime_benchmark import RuntimeTimings

@contextmanager
def noop(observer):yield
CONTEXTS=(noop,noop)


def test_nested_inclusive_spans_are_separate_and_code_is_unchanged():
    def inner():return 7
    def outer():return inner()
    code=inner.__code__;ticks=iter((0.,1.,3.,4.));timing=RuntimeTimings(clock=lambda:next(ticks))
    available=[sys.monitoring.get_tool(i) for i in range(6)]
    with timing.observe({'outer':outer,'inner':inner},observer_contexts=CONTEXTS):
        assert inner.__code__ is code and outer()==7
    assert inner.__code__ is code
    assert [sys.monitoring.get_tool(i) for i in range(6)]==available
    doc=timing.document(wall_seconds=4)
    assert [(r['phase'],r['seconds']) for r in doc['calls']]==[('inner',2.),('outer',4.)]
    assert doc['timing_semantics']=='inclusive_not_additive' and 'total_inclusive_seconds' not in doc


def test_unwind_and_fresh_case_scope():
    def submit():raise RuntimeError('actual failure')
    def replay():return submit()
    ticks=iter((0.,1.,2.,3.));timing=RuntimeTimings(clock=lambda:next(ticks))
    with timing.observe({'fresh_replay':replay,'submit':submit},observer_contexts=CONTEXTS):
        with pytest.raises(RuntimeError,match='actual failure'):replay()
    rows=timing.document(wall_seconds=3)['calls']
    assert rows[0]['case_index']==0 and rows[0]['invocation']=='fresh'
    assert all(r['status']=='error' for r in rows)


def test_observer_contexts_reuse_callbacks_and_assign_current_case():
    callbacks={}
    @contextmanager
    def runtime(observer):callbacks['runtime']=observer;yield
    @contextmanager
    def command(observer):callbacks['command']=observer;yield
    def submit():
        callbacks['runtime']('runner_step',.7)
        callbacks['runtime']('scheduler_batch',.9)
        callbacks['command']('STEP_CPU',.2)
    timing=RuntimeTimings()
    with timing.observe({'submit':submit},observer_contexts=(runtime,command)):submit()
    doc=timing.document(wall_seconds=1)
    assert [r['seconds'] for r in doc['runtime_inclusive']]==[.7,.9]
    assert all(r['case_index']==0 for r in doc['runtime_inclusive']+doc['command_roundtrips'])
    assert doc['command_roundtrips'][0]['count']==1


def test_failed_scope_restores_other_monitoring_tools():
    def submit():raise ValueError('expected')
    timing=RuntimeTimings();before=[sys.monitoring.get_tool(i) for i in range(6)]
    with pytest.raises(ValueError,match='expected'):
        with timing.observe({'submit':submit},observer_contexts=CONTEXTS):submit()
    assert [sys.monitoring.get_tool(i) for i in range(6)]==before
    assert timing.document(wall_seconds=1)['calls'][0]['status']=='error'


def test_workload_identity_keeps_auxiliary_cases_ticks_and_events():
    from myfuzz.integration.runtime_benchmark import workload_identity
    prefix=dict(flow_records=[dict(flow='F4',raw_hex='0001000000',status='passed')],
        actual_events=[dict(kind='cpu_retire'),dict(kind='gpio_irq_trigger')],trace_local_ticks={'cpu':3,'gpio':4},
        online_plan={'cases':[{},{}]})
    identity=workload_identity(prefix)
    assert identity['main_case_count']==1 and identity['session_case_count']==2
    assert identity['event_count']==2 and identity['local_ticks']=={'cpu':3,'gpio':4}
    changed={**prefix,'flow_records':[dict(flow='F4',raw_hex='0101000000',status='passed')]}
    assert workload_identity(changed)['records_sha256']!=identity['records_sha256']
    with pytest.raises(ValueError,match='completed workload'):
        workload_identity({**prefix,'flow_records':[dict(flow='F4',raw_hex='0001000000',status='reserved')]})
