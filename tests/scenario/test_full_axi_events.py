"""Software model controls for a pinned 64-bit single-master AXI variant.

These samples are constructed software inputs, not CVA6 native observations.
"""
import copy
import importlib
import pytest
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE


def observer(**kw):
 try: module=importlib.import_module('myfuzz.scenario.full_axi_events')
 except ModuleNotFoundError: pytest.fail('full AXI observer is missing')
 return module.BoundedFullAxiObserver(component_id='renamed',**kw)
def edge(tick=1, **values):
 row={'axi_'+r:0 for r in CVA6_AXI_SHAPE};row.update({'axi_'+k:v for k,v in values.items()})
 return dict(local_tick=tick,pre=dict(backend=row),post=dict(backend=copy.deepcopy(row)))
def run(*edges,**kw):
 o=observer(**kw);o.begin_scope(execution_id='exec',testcase_id='case',reset_epoch=0)
 for sample in edges:o.observe(sample)
 return o
def ar(**kw):return dict(arvalid=1,arready=1,arsize=3,arburst=1)|kw
def aw(**kw):return dict(awvalid=1,awready=1,awsize=3,awburst=1)|kw
def w(**kw):return dict(wvalid=1,wready=1,wstrb=255)|kw

@pytest.mark.parametrize('identifier',range(16))
@pytest.mark.parametrize('resp',[0,2,3])
def test_64bit_payload_id_user_and_status_preserved(identifier,resp):
 o=run(edge(**ar(arid=identifier,araddr=0x100000000,aruser=2**63)),edge(2,rvalid=1,rready=1,rid=identifier,rlast=1,rresp=resp,rdata=2**63+5,ruser=2**63+1))
 assert o.events[-1]['payload']['rdata']==2**63+5
 assert o.events[-1]['payload']['ruser']==2**63+1
 assert o.events[-1]['request_refs']==[1]
 assert o.pending=={'read_beats_remaining':0,'write_beats_remaining':0,'buffered_wbeats':0,'b_pending':False}
 assert all(e['authority']=='observation_only' and e['runtime_accepted'] is False and e['semantic_accepted'] is False for e in o.events)

@pytest.mark.parametrize('burst,start,length,addresses',[(0,0x100,3,[0x100]*3),(1,0x100,3,[0x100,0x108,0x110]),(2,0x118,4,[0x118,0x100,0x108,0x110])])
def test_burst_read_addresses_and_last(burst,start,length,addresses):
 request=ar(araddr=start,arlen=length-1);request['arburst']=burst
 o=run(edge(**request),*[edge(i+2,rvalid=1,rready=1,rlast=int(i==length-1)) for i in range(length)])
 assert [e['address'] for e in o.events if e['kind']=='full_axi_read_beat']==addresses
 assert [e['beat_index'] for e in o.events if e['kind']=='full_axi_read_beat']==list(range(length))


def test_w_before_aw_preserves_unaddressed_payload_then_binds_exact_refs():
 o=run(edge(**w(wdata=2**63,wuser=99,wlast=0)),edge(2,**w(wdata=27,wuser=101,wlast=1)),edge(3,**aw(awaddr=0x100,awlen=1,awid=7,awuser=23)),edge(4,bvalid=1,bready=1,bid=7,bresp=2,buser=29))
 accepts=[e for e in o.events if e['kind']=='full_axi_accept' and e['channel']=='w']
 assert 'address' not in accepts[0]
 joins=[e for e in o.events if e['kind']=='full_axi_write_beats']
 assert [b['address'] for b in joins[0]['beats']]==[0x100,0x108]
 assert [b['payload']['wuser'] for b in joins[0]['beats']]==[99,101]
 assert joins[0]['aw_w_order']=='w_before_aw'
 assert o.events[-1]['request_refs']==joins[0]['request_refs']
 assert len(set(o.events[-1]['request_refs']))==3


def test_256_beats_and_read_write_overlap():
 o=observer();o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 for i in range(256):o.observe(edge(i+1,**w(wlast=int(i==255),wdata=i)))
 o.observe(edge(257,**aw(awlen=255,awaddr=0x1000),**ar(arlen=1,arid=15,araddr=0x3000)))
 assert o.pending['b_pending'] and o.pending['read_beats_remaining']==2
 o.observe(edge(258,bvalid=1,bready=1,rvalid=1,rready=1,rid=15))
 o.observe(edge(259,rvalid=1,rready=1,rid=15,rlast=1))
 assert o.accepted=={'aw':1,'w':256,'b':1,'ar':1,'r':2}
 assert len(next(e for e in o.events if e['kind']=='full_axi_write_beats')['beats'])==256

@pytest.mark.parametrize('size',range(4))
def test_narrow_lane_zero_strobe_and_size_encoded_distinct_from_bytes(size):
 address=0x100+(8-(1<<size));a=aw(awaddr=address);a['awsize']=size
 o=run(edge(**a,**w(wlast=1,wstrb=0)),edge(2,bvalid=1,bready=1))
 beat=next(e for e in o.events if e['kind']=='full_axi_write_beats')['beats'][0]
 assert beat['encoded_size']==size and beat['beat_bytes']==1<<size

@pytest.mark.parametrize('values,reason,category',[
 (ar(arlock=1),'exclusive','unsupported'),
 (aw(awatop=1),'atomic','unsupported'),
 ({**ar(),'arsize':4},'size_alignment','unsupported'),
 ({**ar(),'arburst':3},'burst_reserved','protocol_violation'),
 ({**ar(),'arburst':2,'arlen':2},'wrap_length','protocol_violation'),
 (ar(araddr=0xff8,arlen=1),'boundary','protocol_violation'),
 (ar(araddr=2**64-8,arlen=1),'boundary','protocol_violation'),
 ({'rvalid':1,'rready':1,'rlast':1},'orphan_r','protocol_violation'),
 ({'bvalid':1,'bready':1},'orphan_b','protocol_violation')])
def test_invalid_requests_distinguish_unsupported(values,reason,category):
 o=observer();o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 with pytest.raises(ValueError,match=reason):o.observe(edge(**values))
 assert o.events[-1]['category']==category and o.events[-2]['raw_sample']==edge(**values)

@pytest.mark.parametrize('values,reason',[(dict(rid=1,rlast=1),'response_id'),(dict(rlast=0),'last'),(dict(rlast=1,rresp=1),'exclusive_response')])
def test_response_negative_controls(values,reason):
 with pytest.raises(ValueError,match=reason):run(edge(**ar()),edge(2,rvalid=1,rready=1,**values))


def test_wlast_lanes_extra_and_early_b_controls():
 for a,b,reason in [(aw(awlen=1),w(wlast=1),'last'),(aw(),w(wlast=0),'last'),({**aw(),'awsize':0},w(wlast=1),'strobe')]:
  with pytest.raises(ValueError,match=reason):run(edge(**a,**b))
 with pytest.raises(ValueError,match='orphan_b'):run(edge(**aw()),edge(2,bvalid=1,bready=1,**w(wlast=1)))
 with pytest.raises(ValueError,match='outstanding'):run(edge(**ar()),edge(2,**ar()))


def test_hold_reset_poison_scope_ticks_and_budgets():
 held=edge(**ar(aruser=7));held['pre']['backend']['axi_arready']=0;held['post']['backend']['axi_arready']=0
 changed=copy.deepcopy(held);changed['post']['backend']['axi_aruser']=8
 with pytest.raises(ValueError,match='hold'):run(changed)
 changed=edge(2,**ar(aruser=8))
 with pytest.raises(ValueError,match='hold'):run(held,changed)
 o=run(edge(**ar(),**w(wlast=1)));stream=o.events;o.end_scope()
 assert o.events is stream and o.events[-1]['cancelled']['read_beats_remaining']==1
 o.begin_scope(execution_id='new',testcase_id='c',reset_epoch=1)
 with pytest.raises(ValueError,match='orphan_r'):o.observe(edge(rvalid=1,rready=1,rlast=1))
 with pytest.raises(ValueError,match='not_active'):o.require_active()
 with pytest.raises(ValueError,match='tick'):run(edge(),edge())
 with pytest.raises(ValueError,match='budget'):run(edge(),max_bytes=1)
 o=run(edge(),max_edges=1)
 with pytest.raises(ValueError,match='budget'):o.observe(edge(2))
 o.end_scope()
 with pytest.raises(ValueError,match='budget'):o.begin_scope(execution_id='another',testcase_id='c',reset_epoch=2)


def test_exact_shape_and_post_validation():
 sample=edge();sample['post']['backend']['axi_awid']=16
 with pytest.raises(ValueError,match='shape'):run(sample)
 sample=edge();del sample['post']
 with pytest.raises(ValueError,match='shape'):run(sample)
 assert len(run(edge()).contract['signal_shapes'])==45


def test_fixed_burst_protocol_limit():
 with pytest.raises(ValueError,match='fixed_length'):
  run(edge(**ar(arburst=0,arlen=16)))


def test_partial_read_chain():
 o=run(edge(**ar(arlen=2)),edge(2,rvalid=1,rready=1),edge(3,rvalid=1,rready=1))
 beats=[e for e in o.events if e['kind']=='full_axi_read_beat']
 assert beats[1]['prior_beat_refs']==beats[0]['raw_event_refs']
 assert o.pending['read_beats_remaining']==1


def test_diagnostic_reset_record_budget_is_bounded():
 o=observer(max_edges=1,max_scopes=20)
 for i in range(20):
  o.begin_scope(execution_id=str(i),testcase_id='c',reset_epoch=i)
  o.poison('no measured edge');o.end_scope()
 assert len(o.events)<=o.contract['budgets']['max_records']


def test_w_buffer_overflow_id_b_last_and_read_hold_controls():
 o=observer();o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 for i in range(256):o.observe(edge(i+1,**w(wlast=0)))
 with pytest.raises(ValueError,match='buffer_budget'):o.observe(edge(257,**w(wlast=1)))
 with pytest.raises(ValueError,match='response_id'):
  run(edge(**aw(awid=9),**w(wlast=1)),edge(2,bvalid=1,bready=1,bid=8))
 with pytest.raises(ValueError,match='extra_w'):
  run(edge(**w(wlast=1)),edge(2,**w(wlast=1)),edge(3,**aw()))
 response=edge(2,rvalid=1,rlast=1,rdata=7,ruser=1)
 changed=edge(3,rvalid=1,rready=1,rlast=1,rdata=7,ruser=2)
 with pytest.raises(ValueError,match='hold'):run(edge(**ar()),response,changed)


def test_host_identity_closure_and_existing_runner_import():
 from pathlib import Path
 from types import SimpleNamespace
 from myfuzz.local_harness.build import _discover_host_sources
 from myfuzz.scenario.runner import ScenarioRunner
 from myfuzz.scenario.ownership import compile_ownership
 root=Path(__file__).resolve().parents[2];closure=_discover_host_sources()
 for path in ('src/myfuzz/scenario/full_axi_events.py','src/myfuzz/local_harness/cva6_axi4_fields.py','src/myfuzz/local_harness/cva6_axi4_session.py'):
  assert closure[path]==(root/path).read_bytes()
 o=run(edge(**ar()))
 runner=ScenarioRunner(sessions={'renamed':SimpleNamespace(runtime_events=o.events)},ownership=compile_ownership((),()),bindings=())
 runner._append_external_events('renamed',10);count=len(runner._events)
 runner._append_external_events('renamed',11)
 assert len(runner._events)==count==len(o.events)
 o.end_scope();runner._append_external_events('renamed',12)
 assert runner._events[-1]['cancelled']['read_beats_remaining']==1


def test_saved_software_model_full_prefix_scope_only_equivalence():
 import json
 from pathlib import Path
 directory=Path(__file__).resolve().parents[2]/'docs/reports/evidence/full-axi-observer-20261017'
 model=json.loads((directory/'software-model.json').read_text())
 assert model['provenance']=='constructed_software_model_not_native'
 a=run(*model['samples']);b=observer();b.begin_scope(execution_id='fresh',testcase_id='case',reset_epoch=0)
 for sample in model['samples']:b.observe(sample)
 events=copy.deepcopy(b.events)
 for event in events:event['scope']['execution_id']='exec'
 assert events==a.events
 assert a.accepted=={'aw':1,'w':4,'b':1,'ar':1,'r':2}
 assert json.loads((directory/'software-model-events.json').read_text())==a.events


def test_diagnostic_cannot_emit_outside_active_scope():
 o=observer(max_edges=1,max_scopes=1)
 for _ in range(20):o.end_scope();o.poison('outside scope')
 assert o.events==[]


def test_transaction_aw_w_order_stays_first_w_order_across_batches():
 o=run(edge(**w(wlast=0)),edge(2,**aw(awlen=1)),edge(3,**w(wlast=1)))
 batches=[e for e in o.events if e['kind']=='full_axi_write_beats']
 assert [e['aw_w_order'] for e in batches]==['w_before_aw','w_before_aw']
 assert [b['accepted_tick'] for e in batches for b in e['beats']]==[1,3]


def test_diagnostic_receipt_counts_global_byte_budget():
 o=observer(max_bytes=1);o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 o.poison('untrusted receipt',diagnostic_receipt={'payload':'large'})
 assert o.events[-1]['diagnostic_receipt']=={'payload':'large'}
 o.end_scope()
 with pytest.raises(ValueError,match='budget'):
  o.begin_scope(execution_id='another',testcase_id='c',reset_epoch=1)


@pytest.mark.parametrize('kind',['protocol','shape'])
def test_failure_states_possible_effects_and_projection_trust(kind):
 o=observer();o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 sample=edge(bvalid=1,bready=1) if kind=='protocol' else edge()
 if kind=='shape':sample['post']=None
 with pytest.raises(ValueError):o.observe(sample)
 failure=o.events[-1]
 assert failure['possible_effects'] is True
 assert failure['trusted_projection'] is (kind=='protocol')


@pytest.mark.parametrize('post_ready',[0,1])
def test_post_new_offer_is_held_until_next_measured_pre(post_ready):
 first=edge(arready=post_ready)
 first['post']['backend'].update(axi_arvalid=1,axi_araddr=0x100,axi_arsize=3,axi_arburst=1)
 o=run(first);assert o.accepted['ar']==0
 with pytest.raises(ValueError,match='hold'):o.observe(edge(2,**ar(araddr=0x108)))
 o=run(first,edge(2,**ar(araddr=0x100)))
 assert o.accepted['ar']==1


def test_accepted_master_post_offer_held_but_consumed_injected_response_can_drop():
 first=edge(**ar(araddr=0x100));first['post']['backend'].update(axi_araddr=0x108)
 with pytest.raises(ValueError,match='hold'):
  run(first,edge(2,rvalid=1,rready=1,rlast=1))
 # Injected RVALID remains high in post for the response consumed at pre;
 # next service command may legally remove it before the next edge.
 o=run(edge(**ar()),edge(2,rvalid=1,rready=1,rlast=1),edge(3))
 assert o.accepted['r']==1


def test_prevalidation_budget_failure_does_not_claim_trusted_shape():
 o=observer(max_bytes=1);o.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 sample=edge();sample['post']=None
 with pytest.raises(ValueError,match='budget'):o.observe(sample)
 assert o.events[-1]['category']=='unsupported'
 assert o.events[-1]['trusted_projection'] is False
