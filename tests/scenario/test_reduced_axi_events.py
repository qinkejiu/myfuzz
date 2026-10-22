"""Offline replay of pinned native receipts and adversarial channel controls."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import pytest
from myfuzz.local_harness.vexii_axi_fields import SHAPES
import importlib

ROOT = Path(__file__).resolve().parents[2]
SHA = {
 'first':'892c2a50dbf730a2ae5f81bd7835020e816f18139479cb57c388ecd9172e1b63',
 'fresh':'fd3fd5642f3a815ef0d58a9d13ea4e3acae36c59ad493c85628e026834445dd4',
 'fault':'0dbefcea97ebccf0f71f06ee3a26581b9f6bd6f7049e862373a213fb13228963',
 'mmio-first':'5e31249cbae9f4bffecc8c08ca2796554c5628493cc238665a87f6b3370b8112',
 'mmio-fresh':'4dc89f1e50881293cea55984bf37a5b97231bfc3cbe47932e368c77575169171',
 'mmio-fault':'a5b20a745882ac21adf39d288e7fe9bb0bcfe74ec39480490786ee00ad2bc889'}
def saved(name):
 p=ROOT/'configs/cpus/vexiiriscv/evidence'/f'{name}-20261017.json.gz'
 assert hashlib.sha256(p.read_bytes()).hexdigest()==SHA[name]
 return json.loads(gzip.decompress(p.read_bytes()))
def observer(**kw):
 try:
  axi=importlib.import_module('myfuzz.scenario.reduced_axi_events')
 except ModuleNotFoundError:
  pytest.fail('receipt-bound reduced AXI observer is missing')
 return axi.ReducedAxiObserver(component_id='renamed-source', **kw)
def replay(name):
 d=saved(name);o=observer();o.begin_scope(execution_id=d['execution'],testcase_id='case',reset_epoch=0)
 for sample in d['samples']:o.observe(sample)
 return o
def edge(tick=1, **signals):
 row={p+'_'+r:0 for p,s in SHAPES.items() for r in s};row.update(signals)
 return {'local_tick':tick,'pre':{'backend':row},'post':{'backend':copy.deepcopy(row)}}
def run(*edges,**kw):
 o=observer(**kw);o.begin_scope(execution_id='exec',testcase_id='case',reset_epoch=0)
 for e in edges:o.observe(e)
 return o

@pytest.mark.parametrize('name',SHA)
def test_saved_native_prefix(name):
 o=replay(name)
 assert not [e for e in o.events if e['kind']=='reduced_axi_violation']
 assert sum(e['kind']=='reduced_axi_raw' for e in o.events)==len(saved(name)['samples'])
 assert o.contract['absent_roles']['arlen']=='not_exposed'
 assert all(e['authority']=='observation_only' and e['runtime_accepted'] is False and e['semantic_accepted'] is False for e in o.events)
 if name in ('first','fresh','fault'):
  assert o.accepted=={'i_ar':11,'i_r':10,'d_aw':2,'d_w':2,'d_b':2,'d_ar':1,'d_r':1}
  assert o.pending=={'i':{'read':True,'aw':False,'w':False,'write':False},'d':{'read':False,'aw':False,'w':False,'write':False}}

def test_full_prefix_fresh_equivalence_only_execution_scope_differs():
 a,b=replay('first'),replay('fresh')
 def normalize(events):
  events=copy.deepcopy(events)
  for event in events:event['scope']['execution_id']='NORMALIZED_EXECUTION'
  return events
 assert normalize(a.events)==normalize(b.events)
 assert saved('fault')['samples']!=saved('first')['samples']

@pytest.mark.parametrize('field,value,reason',[('i_rid',0,'response_id'),('i_rlast',0,'last'),('i_rresp',1,'exclusive_response_unsupported')])
def test_real_response_mutation_keeps_failure_edge(field,value,reason):
 samples=copy.deepcopy(saved('first')['samples']);i=next(i for i,s in enumerate(samples) if s['pre']['backend']['i_rvalid'] and s['pre']['backend']['i_rready'] and s['pre']['backend']['i_rid']==1)
 samples[i]['pre']['backend'][field]=value
 o=observer();o.begin_scope(execution_id='x',testcase_id='c',reset_epoch=0)
 with pytest.raises(ValueError,match=reason):
  for s in samples[:i+1]:o.observe(s)
 assert o.events[-1]['kind']=='reduced_axi_violation'
 assert o.events[-2]['raw_sample']==samples[i]

@pytest.mark.parametrize('resp',[0,2,3])
def test_response_status_is_preserved(resp):
 o=run(edge(i_arvalid=1,i_arready=1,i_arid=1,i_arsize=2),edge(2,i_rvalid=1,i_rready=1,i_rid=1,i_rlast=1,i_rresp=resp))
 assert o.events[-1]['payload']['rresp']==resp
 assert not o.pending['i']['read']

def test_w_before_aw_overlapping_read_and_independent_source():
 o=run(edge(d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15,d_arvalid=1,d_arready=1,d_arid=1,d_arsize=2,i_arvalid=1,i_arready=1,i_arsize=2),edge(2,d_awvalid=1,d_awready=1,d_awid=1,d_awsize=2),edge(3,d_bvalid=1,d_bready=1,d_bid=1,d_rvalid=1,d_rready=1,d_rid=1,d_rlast=1,i_rvalid=1,i_rready=1,i_rlast=1))
 assert not any(any(s.values()) for s in o.pending.values())
 assert next(e for e in o.events if e['kind']=='reduced_axi_write_join')['aw_w_order']=='w_before_aw'

@pytest.mark.parametrize('signals,reason', [({'d_bvalid':1,'d_bready':1},'orphan_b'),({'i_rvalid':1,'i_rready':1,'i_rlast':1},'orphan_r'),({'d_wvalid':1,'d_wready':1},'last'),({'i_arvalid':1,'i_arready':1,'i_arsize':3},'size_alignment')])
def test_orphan_and_shape_controls(signals,reason):
 with pytest.raises(ValueError,match=reason):run(edge(**signals))

def test_hold_checks_post_and_next_pre_without_double_accept():
 e=edge(i_arvalid=1,i_arsize=2);e['post']['backend']['i_araddr']=4
 with pytest.raises(ValueError,match='hold'):run(e)
 e=edge(i_arvalid=1,i_arsize=2)
 with pytest.raises(ValueError,match='hold'):run(e,edge(2,i_arvalid=1,i_arready=1,i_araddr=4,i_arsize=2))
 o=run(edge(i_arvalid=1,i_arready=1,i_arsize=2));assert o.accepted['i_ar']==1

def test_reset_cancels_pending_immediately_preserving_list():
 o=run(edge(i_arvalid=1,i_arready=1,i_arsize=2,d_wvalid=1,d_wready=1,d_wlast=1))
 stream=o.events;o.begin_scope(execution_id='new',testcase_id='case',reset_epoch=1)
 assert o.events is stream and not any(any(s.values()) for s in o.pending.values())
 assert o.events[-1]['kind']=='reduced_axi_reset' and o.events[-1]['cancelled']['i']['read']
 with pytest.raises(ValueError,match='orphan_r'):o.observe(edge(i_rvalid=1,i_rready=1,i_rlast=1))

def test_budget_and_tick_fail_closed_and_keep_raw():
 o=run(edge(),max_edges=1)
 with pytest.raises(ValueError,match='budget'):o.observe(edge(2))
 assert o.events[-2]['kind']=='reduced_axi_raw'
 with pytest.raises(ValueError,match='tick'):run(edge(),edge())

def test_missing_post_and_fabricated_len_rejected():
 e=edge();del e['post']
 with pytest.raises(ValueError,match='shape'):run(e)
 with pytest.raises(ValueError,match='shape'):run(edge(i_arlen=0))


def test_outstanding_lanes_width_and_byte_budget_controls():
 with pytest.raises(ValueError,match='outstanding_budget'):
  run(edge(i_arvalid=1,i_arready=1,i_arsize=2),edge(2,i_arvalid=1,i_arready=1,i_arsize=2))
 with pytest.raises(ValueError,match='strobe_lanes'):
  run(edge(d_awvalid=1,d_awready=1,d_awsize=0,d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15))
 with pytest.raises(ValueError,match='shape'):run(edge(i_arid=2))
 with pytest.raises(ValueError,match='budget'):run(edge(),max_bytes=1)


def test_stalled_response_payload_and_native_id_reuse():
 request=edge(i_arvalid=1,i_arready=1,i_arid=1,i_arsize=2)
 response=edge(2,i_rvalid=1,i_rid=1,i_rlast=1,i_rdata=27)
 changed=edge(3,i_rvalid=1,i_rready=1,i_rid=1,i_rlast=1,i_rdata=28)
 with pytest.raises(ValueError,match='hold'):run(request,response,changed)
 # An old response and a new request may handshake on the same edge.
 o=run(request,edge(2,i_rvalid=1,i_rready=1,i_rid=1,i_rlast=1,
                    i_arvalid=1,i_arready=1,i_arid=0,i_arsize=2),
       edge(3,i_rvalid=1,i_rready=1,i_rid=0,i_rlast=1))
 assert o.accepted['i_ar']==o.accepted['i_r']==2


def test_runner_imports_runtime_stream_once_and_retains_raw_refs():
 from types import SimpleNamespace
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 o=replay('first')
 session=SimpleNamespace(runtime_events=o.events)
 runner=ScenarioRunner(sessions={'renamed':session}, ownership=compile_ownership((),()), bindings=())
 runner._append_external_events('renamed',99)
 assert len(runner._events)==len(o.events)
 assert runner._events[0]['raw_sample']==o.events[0]['raw_sample']
 assert runner._events[0]['producer_event_id']==99
 runner._append_external_events('renamed',100)
 assert len(runner._events)==len(o.events)
 o.end_scope()
 runner._append_external_events('renamed',101)
 assert runner._events[-1]['kind']=='reduced_axi_reset'
 assert runner._events[-1]['cancelled']['i']['read']


def _journal_runner(o):
    from types import SimpleNamespace
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.ownership import compile_ownership

    runner = ScenarioRunner(
        sessions={'renamed': SimpleNamespace(runtime_events=o.events)},
        ownership=compile_ownership((), ()), bindings=())
    runner._events.enable_journal(chunk_size=2)
    return runner


def _drain_observer(runner, o, expected):
    expected.extend(copy.deepcopy(o.events))
    # Scheduler/other component records use the journal's separate ID space.
    runner._events.append({'event_id': len(runner._events) + 1,
                           'kind': 'test_interleaved_boundary'})
    runner._append_external_events('renamed', len(runner._events))
    assert o.events == []
    count = len(runner._events)
    runner._append_external_events('renamed', count)
    assert len(runner._events) == count


def _assert_journal_observer_references(runner, expected):
    events = list(runner._events)
    assert [row['event_id'] for row in events] == list(range(1, len(events) + 1))
    observed = [row for row in events
                if row.get('schema_version') == 'reduced_axi_observation.v1']
    detached = [{key: value for key, value in row.items()
                 if key not in ('event_id', 'producer_event_id', 'component')}
                for row in observed]
    assert detached == expected
    raw = {}
    last_ref = 0
    for row in observed:
        scope = tuple(sorted(row['scope'].items()))
        if row['kind'] == 'reduced_axi_raw':
            ref = row['raw_event_ref']
            assert type(ref) is int and ref > last_ref
            last_ref = ref
            assert ref not in raw
            raw[ref] = row
            # Interleaved journal records make local refs distinct from IDs.
            assert ref != row['event_id']
        refs = list(row.get('raw_event_refs', ()))
        refs.extend(row.get('request_refs', ()))
        for state in row.get('pending_request_refs', {}).values():
            for pending in state.values():
                if pending is not None:
                    refs.extend(pending['refs'])
        for ref in refs:
            source = raw[ref]
            assert source['event_id'] < row['event_id']
            assert tuple(sorted(source['scope'].items())) == scope
            assert source['component_id'] == row['component_id']
        assert row['authority'] == 'observation_only'
        assert row['runtime_accepted'] is row['semantic_accepted'] is False
    return observed


@pytest.mark.parametrize('order', ['aw_before_w', 'w_before_aw', 'same_edge'])
def test_event_journal_drain_preserves_outstanding_read_and_write_refs(order):
    aw = dict(d_awvalid=1, d_awready=1, d_awid=1, d_awsize=2)
    w = dict(d_wvalid=1, d_wready=1, d_wlast=1, d_wstrb=15)
    first = aw if order == 'aw_before_w' else w
    second = w if order == 'aw_before_w' else aw
    samples = [edge(i_arvalid=1, i_arready=1, i_arid=1, i_arsize=2,
                    **({**aw, **w} if order == 'same_edge' else first)),
               edge(2, i_rvalid=1, i_rready=1, i_rid=1, i_rlast=1,
                    **({} if order == 'same_edge' else second)),
               edge(3, d_bvalid=1, d_bready=1, d_bid=1)]
    o = observer()
    o.begin_scope(execution_id='exec', testcase_id='case', reset_epoch=0)
    runner, expected = _journal_runner(o), []
    try:
        for sample in samples:
            o.observe(sample)
            _drain_observer(runner, o, expected)
        records = _assert_journal_observer_references(runner, expected)
        assert next(row for row in records
                    if row['kind'] == 'reduced_axi_write_join')['aw_w_order'] == order
        assert sum(row['kind'] == 'reduced_axi_complete' for row in records) == 2
        assert not any(any(state.values()) for state in o.pending.values())
    finally:
        runner._events._records.close()


def test_event_journal_drain_keeps_reset_cancellation_refs_and_lifetime_numbering():
    o = run(edge(i_arvalid=1, i_arready=1, i_arsize=2,
                 d_wvalid=1, d_wready=1, d_wlast=1))
    runner, expected = _journal_runner(o), []
    try:
        _drain_observer(runner, o, expected)
        o.begin_scope(execution_id='exec', testcase_id='next', reset_epoch=1)
        _drain_observer(runner, o, expected)
        with pytest.raises(ValueError, match='orphan_r'):
            o.observe(edge(i_rvalid=1, i_rready=1, i_rlast=1))
        _drain_observer(runner, o, expected)
        records = _assert_journal_observer_references(runner, expected)
        reset = next(row for row in records if row['kind'] == 'reduced_axi_reset')
        assert reset['cancelled']['i']['read'] and reset['cancelled']['d']['w']
        assert records[-1]['kind'] == 'reduced_axi_violation'
        assert records[-1]['scope']['reset_epoch'] == 1
    finally:
        runner._events._records.close()


@pytest.mark.parametrize('name', SHA)
def test_saved_native_observer_prefix_matches_with_per_sample_event_journal_drain(name):
    document = saved(name)
    o = observer()
    o.begin_scope(execution_id=document['execution'], testcase_id='case', reset_epoch=0)
    runner, expected = _journal_runner(o), []
    try:
        for sample in document['samples']:
            o.observe(sample)
            _drain_observer(runner, o, expected)
        # Compare to a separate observer without any producer-list draining.
        buffered = replay(name)
        assert expected == buffered.events
        _assert_journal_observer_references(runner, expected)
    finally:
        runner._events._records.close()


def test_scope_budget_bounds_reset_only_stream():
 o=observer(max_scopes=1)
 o.begin_scope(execution_id='one',testcase_id='case',reset_epoch=0)
 o.end_scope()
 with pytest.raises(ValueError,match='scope_budget'):
  o.begin_scope(execution_id='two',testcase_id='case',reset_epoch=1)


def test_global_stream_budget_cannot_be_reopened_by_reset():
 o=run(edge(),max_edges=1)
 with pytest.raises(ValueError,match='budget'):o.observe(edge(2))
 o.end_scope()
 with pytest.raises(ValueError,match='budget'):
  o.begin_scope(execution_id='new',testcase_id='case',reset_epoch=1)


def test_actual_host_source_closure_pins_observer_and_physical_shapes():
 from myfuzz.local_harness.build import _discover_host_sources
 closure=_discover_host_sources()
 for path in ('src/myfuzz/scenario/reduced_axi_events.py',
              'src/myfuzz/local_harness/vexii_axi_fields.py',
              'src/myfuzz/local_harness/vexii_axi_session.py'):
  assert closure[path]==(ROOT/path).read_bytes()
