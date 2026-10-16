"""Constructed software AHB edge controls; never native evidence."""
import copy
import pytest
from myfuzz.scenario.ahb_cpu_events import AhbCpuObserver, SHAPE


def observer(**kw):
 o=AhbCpuObserver(component_id='opaque',endpoint_id='bus',**kw)
 o.begin_scope(execution_id='exec',testcase_id='case',reset_epoch=0)
 return o


def edge(o,post=None,**kw):
 row={k:0 for k in SHAPE};row.update(hready=1);row.update(kw)
 after=copy.deepcopy(row) if post is None else {**row,**post}
 return o.observe({'local_tick':o.tick+1,'pre':row,'post':after})


def test_old_completion_and_new_address_same_edge():
 o=observer();edge(o,hsel=1,htrans=2,haddr=(1<<33)+4)
 edge(o,hsel=1,htrans=3,haddr=8,hrdata=123)
 assert o.counts['accepted']==2 and o.counts['completed']==1
 complete=[e for e in o.events if e['kind']=='ahb_complete'][0]
 assert complete['address']==(1<<33)+4 and complete['rdata']==123
 assert complete['native_transaction_key'] is None
 assert o.pending['address']==8


def test_write_data_is_following_phase_and_zero_strobes_preserved():
 o=observer();edge(o,hsel=1,htrans=2,hwrite=1,haddr=8,hwdata=111,hwstrb=15)
 edge(o,hready=0,hwdata=222,hwstrb=0)
 edge(o,hready=0,hwdata=222,hwstrb=0)
 edge(o,hwdata=222,hwstrb=0,hresp=1)
 e=[e for e in o.events if e['kind']=='ahb_complete'][0]
 assert (e['wdata'],e['wstrb'],e['hresp'])==(222,0,1)
 assert e['write_data_ref']!=e['address_ref'] and o.counts['errors']==1
 assert e['authority']=='observation_only' and not e['runtime_accepted']


def test_write_stall_payload_change_poison():
 o=observer();edge(o,hsel=1,htrans=2,hwrite=1);edge(o,hready=0,hwdata=1)
 with pytest.raises(ValueError,match='write_hold'):edge(o,hready=0,hwdata=2)
 with pytest.raises(ValueError,match='not_active'):edge(o)
 assert o.events[-1]['possible_effects'] is True


def test_address_wait_stability_and_error_release():
 o=observer();edge(o,hready=0,hsel=1,htrans=2,haddr=4)
 with pytest.raises(ValueError,match='address_hold'):edge(o,hready=0,hsel=1,htrans=2,haddr=8)
 p=observer();edge(p,hready=0,hsel=1,htrans=2,haddr=4)
 edge(p,hready=0,hresp=1);edge(p,hresp=1)
 assert p.counts['accepted']==0


def test_post_does_not_accept_and_read_data_can_change_during_wait():
 o=observer();edge(o,post={'hsel':1,'htrans':2,'haddr':12})
 assert o.counts['accepted']==0
 edge(o,hsel=1,htrans=2,haddr=12);edge(o,hready=0,hrdata=1)
 edge(o,hready=0,hrdata=2);edge(o,hrdata=3)
 assert o.counts['completed']==1 and [e for e in o.events if e['kind']=='ahb_complete'][-1]['rdata']==3


@pytest.mark.parametrize('trans',[0,1])
def test_idle_busy_not_addresses(trans):
 o=observer();edge(o,hsel=1,htrans=trans);assert o.pending is None


@pytest.mark.parametrize('bad',[None,{}, {'pre':None}, {'local_tick':1,'pre':{'haddr':0},'post':{}}])
def test_malformed_retains_raw_and_poison(bad):
 o=observer()
 with pytest.raises(ValueError):o.observe(bad)
 assert o.events[-2]['raw_sample']==bad and o.events[-1]['trusted_projection'] is False


def test_width_and_tick_reject():
 for kw in ({'haddr':1<<34},{'hready':True}):
  o=observer()
  with pytest.raises(ValueError,match='shape'):edge(o,**kw)
 o=observer();edge(o)
 with pytest.raises(ValueError,match='tick'):o.observe(next(e['raw_sample'] for e in o.events if e['kind']=='ahb_raw'))


@pytest.mark.parametrize('budget', [{'max_edges':1},{'max_bytes':1},{'max_events':2},{'max_scopes':1}])
def test_global_budget_does_not_renew(budget):
 o=observer(**budget)
 try:
  edge(o);edge(o);o.end_scope();o.begin_scope(execution_id='next',testcase_id='case',reset_epoch=1)
 except ValueError:pass
 with pytest.raises(ValueError):o.require_active()


def test_reset_cancels_and_keeps_long_lived_events():
 o=observer();stream=o.events;edge(o,hsel=1,htrans=2,haddr=16)
 o.end_scope();assert stream[-1]['cancelled']['address']==16
 o.begin_scope(execution_id='new',testcase_id='case',reset_epoch=1)
 edge(o);assert o.events is stream and o.pending is None
 assert stream[0]['scope']['execution_id']=='exec'


def test_independent_sources_not_shared():
 a=observer();b=observer();edge(a,hsel=1,htrans=2);edge(b)
 assert a.pending is not None and b.pending is None


def test_controls_preserved_without_claiming_semantics():
 o=observer();edge(o,hsel=1,htrans=3,hsize=7,hburst=7,hprot=15,hmastlock=1)
 assert o.pending['controls']['hsize']==7
 assert o.contract['semantics']=='beat_phase_observation_only'


def test_completion_references_write_data_edge():
 o=observer();edge(o,hsel=1,htrans=2,hwrite=1)
 edge(o,hready=0,hwdata=42,hwstrb=3);edge(o,hwdata=42,hwstrb=3)
 complete=[e for e in o.events if e['kind']=='ahb_complete'][0]
 assert complete['write_data_ref']['raw_event'] in complete['raw_event_refs']


def test_first_measured_ready_is_explicitly_prefix_unknown():
 o=observer();edge(o)
 assert any(e['kind']=='ahb_prefix_unknown' for e in o.events)
 assert o.contract['startup_prefix']=='unknown_before_ready_measurement'
