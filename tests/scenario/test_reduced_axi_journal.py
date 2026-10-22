"""Software Source/real wire parser fixtures; no native acceptance evidence."""
import copy
import hashlib
import importlib
import importlib.util
import json
from dataclasses import asdict

import pytest
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS, STEP_MAXIMA
from myfuzz.local_harness.wire import parse_driver_receipt
from myfuzz.scenario.reduced_axi_events import ReducedAxiObserver
from myfuzz.scenario.reduced_axi_stream_source import ReducedAxiStreamExport, DEFAULT_LIMITS
from myfuzz.local_harness.renderer import _sha


def api():
    assert importlib.util.find_spec('myfuzz.scenario.reduced_axi_journal') is not None, 'journal consumer capability missing'
    return importlib.import_module('myfuzz.scenario.reduced_axi_journal')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


class Recording:
    def __init__(self, irq=False, stream="stream"):
        self.runtime = {'schema_version':'local_runtime_artifact.v1',
            'kind':'reduced_dual_axi_irq_cpu' if irq else 'reduced_dual_axi_cpu'}
        self.runtime['artifact_digest'] = _sha(self.runtime)
        self.observer = ReducedAxiObserver(component_id='physical')
        self.export = ReducedAxiStreamExport(self.observer, session_id='session',
            observer_stream_id=stream, source_component='physical',
            artifact_digest=self.runtime['artifact_digest'])
        self.binding = self.export.source.identity_document()
        self.tick = self.total = self.sequence = self.base = 0
        self.irq = irq
        self.begin()

    def begin(self, execution='a'*32, epoch=0):
        self.execution = execution
        self.base = self.total
        self.tick = self.sequence = 0
        self.export.begin(dict(execution_id=execution,testcase_id='case',reset_epoch=epoch))

    def edge(self, **signals):
        row = {p+'_'+r:0 for p,s in SHAPES.items() for r in s}
        row.update(signals)
        sample = dict(local_tick=self.tick+1, pre={'backend':row}, post={'backend':copy.deepcopy(row)})
        payload = dict(schema_version='local_driver_result.v1',kind=self.runtime['kind'],
            samples=[sample],pre_backend=row,observations={},rdata=0,error=0)
        self.sequence += 1
        wire = f'RESULT {self.execution} {self.sequence:x} {self.tick:x} {self.tick+1:x} {canonical(payload).hex()}\n'
        receipt = parse_driver_receipt(wire.strip(), execution=self.execution,
            sequence=self.sequence,current_tick=self.tick,kind=self.runtime['kind'])
        self.tick += 1
        self.total += 1
        fields = ([1] if self.irq else []) + [row[n] for n in STEP_PORTS]
        operation = 'STEP_REDUCED_AXI_IRQ' if self.irq else 'STEP_REDUCED_AXI'
        command = f'CMD {self.execution} {self.sequence:x} {operation} ' + ' '.join(f'{v:x}' for v in fields) + '\n'
        try:
            self.export.receipt(receipt,operation=operation,fields=fields,wire_command=command,
                wire_reply=wire,cumulative_after=self.total,tick_base=self.base,artifact_kind=self.runtime['kind'])
        except ValueError:
            assert self.observer._failed

    def operations(self, seal=True):
        if seal and self.export.source.state != 'sealed': self.export.seal()
        return [self.export.source.lookup(t) for t in self.export.source.pending()]


def journal(recording, *, operations=None, interleave=True):
    m=api(); events=[dict(event_id=1,kind='scheduler_start',component='scheduler')]; raw={}
    def put(row):
        row=copy.deepcopy(row); row['event_id']=len(events)+1; row['producer_event_id']=1
        events.append(row); return row
    binding=put(dict(kind='reduced_axi_stream_binding',schema_version='reduced_axi_stream_binding.v1',
        component='alias',binding=recording.binding,limits=DEFAULT_LIMITS))
    for operation in recording.operations() if operations is None else operations:
        op=put(dict(kind='reduced_axi_source_operation',schema_version='reduced_axi_source_operation.v1',
            component='alias',stream_binding_event_id=binding['event_id'],operation=operation))
        for index, row in enumerate(operation['observations'],operation['first_record_index']):
            original=put(dict(row,component='alias'))
            if interleave: put(dict(kind='scheduler_tick',component='scheduler'))
            side=m.build_reduced_axi_journal_sidecar(original,stream_binding_event_id=binding['event_id'],
                operation_event_id=op['event_id'],record_index=index,raw_mappings=raw)
            put(side)
            if row['kind']=='reduced_axi_raw':
                raw[row['raw_event_ref']]={'event_id':original['event_id'],'scope':copy.deepcopy(row['scope'])}
    return events


def consume(recording, events=None, **limits):
    c=api().ReducedAxiJournalConsumer(recording.binding,runner_component='alias',runtime_document=recording.runtime,limits=limits)
    for event in journal(recording) if events is None else events: c.consume(event)
    return c


@pytest.mark.parametrize('irq',[False,True])
def test_full_journal_and_empty_lifecycle_operations(irq):
    r=Recording(irq); r.edge(); r.export.end(); r.export.end()
    c=consume(r)
    result=c.finalize()
    assert result['status']=='complete' and result['recording_integrity']=='complete'
    assert result['authority']=='observation_only'
    assert result['runtime_accepted'] is result['semantic_accepted'] is False
    assert result==c.finalize()==c.report()
    assert not c.observer.events


@pytest.mark.parametrize('order',['same_edge','aw_before_w','w_before_aw'])
@pytest.mark.parametrize('response',[0,2,3])
def test_write_orders_error_status_and_duplicate_same_edge_refs(order,response):
    r=Recording()
    aw=dict(d_awvalid=1,d_awready=1,d_awsize=2,d_awaddr=16,d_awid=1)
    w=dict(d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15)
    if order=='same_edge': r.edge(**aw,**w)
    elif order=='aw_before_w': r.edge(**aw); r.edge(**w)
    else: r.edge(**w); r.edge(**aw)
    r.edge(d_bvalid=1,d_bready=1,d_bid=1,d_bresp=response)
    result=consume(r).finalize()
    assert result['status']=='complete'
    complete=result['boundary_observations'][0]
    assert complete['response_status']==response
    assert complete['outcome']==('okay' if response==0 else 'error')
    assert complete['aw_w_order']==order
    assert len(complete['request_event_ids'])==2
    if order=='same_edge': assert complete['request_event_ids'][0]==complete['request_event_ids'][1]


def test_read_and_restart_native_and_cumulative_ticks():
    r=Recording()
    for index in range(2):
        r.edge(i_arvalid=1,i_arready=1,i_arid=1,i_araddr=12,i_arsize=2)
        r.edge(i_rvalid=1,i_rready=1,i_rid=1,i_rlast=1,i_rresp=2)
        r.export.end()
        if not index: r.begin('b'*32,1)
    result=consume(r).finalize()
    assert result['status']=='complete'
    assert len(result['boundary_observations'])==2


@pytest.mark.parametrize('slot',['read','aw','w','write'])
def test_old_scope_pending_reset_contexts(slot):
    r=Recording()
    if slot=='read': r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    if slot in ('aw','write'): r.edge(d_awvalid=1,d_awready=1,d_awsize=2)
    if slot in ('w','write'): r.edge(d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15)
    r.export.end(); r.begin('b'*32,1); r.edge()
    assert consume(r).finalize()['status']=='complete'


def test_legitimate_pending_seal_and_unsealed_prefix():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    prefix=consume(r,journal(r,operations=r.operations(False)))
    assert prefix.report()['status']=='prefix'
    assert prefix.finalize()['reason']=='missing_seal'
    result=consume(r).finalize()
    assert result['status']=='complete' and result['pending']['i']['read']


@pytest.mark.parametrize('signal',[{'i_rvalid':1,'i_rlast':1},{'i_arvalid':1,'i_arready':1,'i_arsize':3}])
def test_authentic_violation_is_failure_evidence(signal):
    r=Recording(); r.edge(**signal)
    result=consume(r).finalize()
    assert result['status']=='complete' and result['outcome']=='observed_protocol_failure'
    assert result['boundary_observations']==[]


@pytest.mark.parametrize('target',['reduced_axi_raw','reduced_axi_write_join','reduced_axi_journal_binding','reduced_axi_source_operation'])
def test_missing_tail_original_or_sidecar_or_seal(target):
    r=Recording(); r.edge(d_awvalid=1,d_awready=1,d_awsize=2,d_wvalid=1,d_wready=1,d_wlast=1)
    events=journal(r)
    index=max(i for i,e in enumerate(events) if e['kind']==target)
    events=events[:index]
    result=consume(r,events).finalize()
    assert result['status']=='failed'


@pytest.mark.parametrize('field,value',[('event_id',True),('event_id',2),('component_id','fake'),('raw_event_ref',True),('authority','trusted'),('runtime_accepted',True)])
def test_original_and_global_envelope_tampering(field,value):
    r=Recording(); r.edge(); events=journal(r)
    raw=next(e for e in events if e['kind']=='reduced_axi_raw'); raw[field]=value
    c=consume(r,events)
    assert c.finalize()['status']=='failed'
    reason=c.report()['reason']; c.consume({'event_id':999,'kind':'reset_barrier'})
    assert c.report()['reason']==reason


def test_rehashed_forged_projection_contradicted_by_wire_receipt():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    ops=r.operations()
    for row in ops[1]['observations']:
        if row['kind']=='reduced_axi_raw':
            row['raw_sample']['pre']['backend']['i_araddr']=4
            row['raw_sample']['post']['backend']['i_araddr']=4
        else: row['payload']['araddr']=4
    ops[1]['content_digest']=digest({k:v for k,v in ops[1].items() if k!='content_digest'})
    assert consume(r,journal(r,operations=ops)).finalize()['reason']=='projection_mismatch'


def rehash(op):
    op['content_digest']=digest({k:v for k,v in op.items() if k!='content_digest'})


@pytest.mark.parametrize('change,reason',[
    ('index','operation_index_mismatch'),('first','record_index_mismatch'),('count','operation_span_mismatch'),
    ('digest','operation_digest_mismatch'),('command','wire_command_mismatch'),
    ('receipt','wire_receipt_mismatch'),('base','cumulative_tick_mismatch'),
    ('sequence','wire_receipt_mismatch'),('fields','command_fields_invalid'),
    ('seal_count','seal_prefix_mismatch'),('seal_chain','seal_prefix_mismatch'),
    ('seal_kinds','seal_prefix_mismatch'),('seal_pending','seal_prefix_mismatch'),
])
def test_issued_envelope_and_wire_tampering(change,reason):
    r=Recording(); r.edge(); events=journal(r)
    operation=next(e['operation'] for e in events if e['kind']=='reduced_axi_source_operation' and e['operation']['kind']=='receipt')
    seal=events[-1]['operation']
    if change=='index': operation['operation_index']=True
    if change=='first': operation['first_record_index']+=1
    if change=='count': operation['record_count']+=1
    if change=='digest': operation['content_digest']='0'*64
    if change=='command': operation['payload']['wire_command']=operation['payload']['wire_command'].replace(' 1 STEP',' 2 STEP')
    if change=='receipt': operation['payload']['receipt']['new_ticks']=True
    if change=='base': operation['payload']['tick_base']=True
    if change=='sequence': operation['payload']['receipt']['sequence']=True
    if change=='fields': operation['payload']['command_fields'][0]=True
    if change=='seal_count': seal['payload']['prior_record_count']+=1
    if change=='seal_chain': seal['payload']['prior_operation_chain_sha256']='0'*64
    if change=='seal_kinds': seal['payload']['prior_kind_counts']['begin_scope']=True
    if change=='seal_pending': seal['payload']['pending']['i']['read']=True
    if change!='digest': rehash(operation)
    rehash(seal)
    assert consume(r,events).finalize()['reason']==reason


@pytest.mark.parametrize('change',['target_sidecar','wrong_role','lost_repeat','wrong_binding','wrong_operation','forward','hash','float'])
def test_sidecar_role_order_and_mapping_tampering(change):
    r=Recording(); r.edge(d_awvalid=1,d_awready=1,d_awsize=2,d_wvalid=1,d_wready=1,d_wlast=1)
    events=journal(r)
    side=next(e for e in events if e['kind']=='reduced_axi_journal_binding' and any(x['role']=='raw_event_refs' and len(x['event_ids'])==2 for x in e['resolved_refs']))
    if change=='target_sidecar': side['resolved_refs'][0]['event_ids'][0]=side['event_id']
    if change=='wrong_role': side['resolved_refs'][0]['role']='request_refs'
    if change=='lost_repeat': side['resolved_refs'][0]['event_ids'].pop()
    if change=='wrong_binding': side['stream_binding_event_id']+=1
    if change=='wrong_operation': side['operation_event_id']+=1
    if change=='forward': side['resolved_refs'][0]['event_ids'][0]=999
    if change=='hash': side['observation_sha256']='0'*64
    if change=='float': side['record_index']=float(side['record_index'])
    assert consume(r,events).finalize()['reason']=='sidecar_mismatch'


def test_boundary_keeps_actual_raw_refs_native_payload_and_ids():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arid=1,i_arsize=2,i_araddr=16)
    r.edge(i_rvalid=1,i_rready=1,i_rid=1,i_rlast=1,i_rdata=123)
    row=consume(r).finalize()['boundary_observations'][0]
    assert row['request_raw_refs']==[1]
    assert row['response_raw_refs']==[3]
    assert row['native_id']==1 and row['payload']['rdata']==123 and row['local_tick']==2
    assert row['request_event_ids'][0]<row['response_event_ids'][0]<row['observation_event_id']


def test_exclusive_response_is_authentic_violation():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    r.edge(i_rvalid=1,i_rready=1,i_rlast=1,i_rresp=1)
    result=consume(r).finalize()
    assert result['status']=='complete' and result['outcome']=='observed_protocol_failure'
    assert result['boundary_observations']==[]


def test_old_b_before_new_write_and_new_read_same_edge():
    r=Recording()
    aw=dict(d_awvalid=1,d_awready=1,d_awsize=2)
    w=dict(d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15)
    r.edge(**aw,**w)
    r.edge(d_bvalid=1,d_bready=1,**aw,**w)
    r.edge(d_bvalid=1,d_bready=1)
    result=consume(r).finalize()
    assert result['status']=='complete' and len(result['boundary_observations'])==2


def test_two_aliases_cannot_supply_each_others_raw_rows():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    r.edge(i_rvalid=1,i_rready=1,i_rlast=1)
    original=journal(r); other=copy.deepcopy(original)
    for e in other: e['component']='other-alias'
    combined=[]
    for a,b in zip(original,other):
        # Use unrelated stream's original IDs only as opaque content. Its records
        # retain native/source/local identities equal to this stream intentionally.
        b['event_id']=len(combined)+1; combined.append(b)
        a['event_id']=len(combined)+1; combined.append(a)
    # Own IDs changed without repairing joins => must reject, never resolve other.
    assert consume(r,combined).finalize()['status']=='failed'
    # Interleaving unrelated complete records without changing own ID assignment
    # is already exercised in every fixture; another alias cannot define own raws.
    events=journal(r)
    raw=next(e for e in events if e['kind']=='reduced_axi_raw'); raw['component']='other-alias'
    assert consume(r,events).finalize()['status']=='failed'


@pytest.mark.parametrize('limit',['max_scopes','max_raw_mappings','max_pending','max_expected_records','max_retained_records','max_events','max_event_gap'])
@pytest.mark.parametrize('delta',[-1,0,1])
def test_count_limits_at_n_minus_one_n_n_plus_one(limit,delta):
    r=Recording()
    if limit=='max_scopes': r.export.end(); r.begin('b'*32,1); required=2
    elif limit=='max_pending':
        r.edge(i_arvalid=1,i_arready=1,i_arsize=2,d_awvalid=1,d_awready=1,d_awsize=2)
        required=2
    elif limit=='max_expected_records':
        r.edge(d_awvalid=1,d_awready=1,d_awsize=2,d_wvalid=1,d_wready=1,d_wlast=1); required=4
    elif limit=='max_retained_records':
        for _ in range(2):
            r.edge(i_arvalid=1,i_arready=1,i_arsize=2); r.edge(i_rvalid=1,i_rready=1,i_rlast=1)
        required=2
    else: r.edge(); r.edge(); required=2
    events=journal(r)
    if limit=='max_events': required=len(events)
    if limit=='max_event_gap':
        events.insert(2,{'kind':'scheduler_tick','component':'scheduler'})
        events.insert(2,{'kind':'scheduler_tick','component':'scheduler'})
        # Repair all references consistently after shifting IDs.
        for e in events:
            for key in ('event_id','producer_event_id','stream_binding_event_id','operation_event_id','observation_event_id'):
                if key in e and e[key]>2: e[key]+=2
            for role in e.get('resolved_refs',[]): role['event_ids']=[x+2 if x>1 else x for x in role['event_ids']]
        for i,e in enumerate(events,1): e['event_id']=i
    result=consume(r,events,**{limit:required+delta}).finalize()
    assert result['status']==('failed' if delta==-1 else 'complete'), result


@pytest.mark.parametrize('value',[0,-1,True,1.0,'1',None])
@pytest.mark.parametrize('limit',list(__import__('itertools').chain(['max_streams','max_scopes','max_raw_mappings','max_pending','max_expected_records','max_retained_records','max_input_bytes','max_total_input_bytes','max_events','max_event_gap'])))
def test_limits_exact_positive_integer(limit,value):
    r=Recording()
    with pytest.raises(ValueError,match='invalid_limits'):
        api().ReducedAxiJournalConsumer(r.binding,runner_component='alias',runtime_document=r.runtime,limits={limit:value})


@pytest.mark.parametrize('change',['runtime','contract','binding_type','runtime_kind'])
def test_constructor_validates_actual_runtime_and_fresh_observer_contract(change):
    r=Recording()
    if change=='runtime': r.runtime['extra']='changed'
    if change=='runtime_kind':
        r.runtime['kind']='another_protocol'; r.runtime['artifact_digest']=_sha({k:v for k,v in r.runtime.items() if k!='artifact_digest'})
        r.binding['artifact_digest']=r.runtime['artifact_digest']
    if change=='contract': r.binding['observer_contract']['budgets']['read_per_face']=True
    if change=='binding_type': r.binding['extra']='not-six-fields'
    with pytest.raises(ValueError):
        api().ReducedAxiJournalConsumer(r.binding,runner_component='alias',runtime_document=r.runtime)


def test_unrelated_rows_after_terminal_seal_and_empty_stream_refusal():
    r=Recording(); events=journal(r)
    events.append({'event_id':len(events)+1,'kind':'scheduler_tick','component':'scheduler'})
    assert consume(r,events).finalize()['status']=='complete'
    assert consume(r,[]).finalize()['reason']=='missing_stream_binding'


def test_helper_does_not_mutate_inputs_and_refuses_duplicate_definition():
    r=Recording(); r.edge(); events=journal(r)
    raw=next(e for e in events if e['kind']=='reduced_axi_raw'); before=copy.deepcopy(raw)
    kwargs=dict(stream_binding_event_id=next(e['event_id'] for e in events if e['kind']=='reduced_axi_stream_binding'),operation_event_id=3,record_index=1)
    # operation ID depends on zero-span lifecycle rows, not command sequence.
    kwargs['operation_event_id']=next(e['event_id'] for e in events if e['kind']=='reduced_axi_source_operation' and e['operation']['kind']=='receipt')
    api().build_reduced_axi_journal_sidecar(raw,raw_mappings={},**kwargs)
    assert raw==before
    with pytest.raises(ValueError,match='duplicate_raw_definition'):
        api().build_reduced_axi_journal_sidecar(raw,raw_mappings={1:{'event_id':raw['event_id'],'scope':raw['scope']}},**kwargs)


def test_two_independently_bound_streams_with_same_native_local_and_source_ids():
    a=Recording(stream='one'); b=Recording(stream='two')
    for r in (a,b):
        r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
        r.edge(i_rvalid=1,i_rready=1,i_rlast=1)
    aa,bb=journal(a),journal(b)
    for event in bb: event['component']='second-alias'
    ordered=[]; maps=[{},{}]
    from itertools import zip_longest
    for pair in zip_longest(aa,bb):
        for stream,event in enumerate(pair):
            if event is not None:
                maps[stream][event['event_id']]=len(ordered)+1
                ordered.append((stream,event))
    events=[]
    for stream,event in ordered:
        mapping=maps[stream]
        for field in ('event_id','producer_event_id','stream_binding_event_id','operation_event_id','observation_event_id'):
            if field in event: event[field]=mapping[event[field]]
        for role in event.get('resolved_refs',[]): role['event_ids']=[mapping[n] for n in role['event_ids']]
        events.append(event)
    ca=consume(a,events)
    cb=api().ReducedAxiJournalConsumer(b.binding,runner_component='second-alias',runtime_document=b.runtime)
    for event in events: cb.consume(event)
    assert ca.finalize()['status']==cb.finalize()['status']=='complete'
    first=ca.report()['boundary_observations'][0]
    second=cb.report()['boundary_observations'][0]
    assert first['request_raw_refs']==second['request_raw_refs']
    assert first['request_event_ids']!=second['request_event_ids']


@pytest.mark.parametrize('limit',['max_input_bytes','max_total_input_bytes'])
@pytest.mark.parametrize('delta',[-1,0,1])
def test_canonical_byte_limits_n_minus_one_n_n_plus_one(limit,delta):
    r=Recording(); r.edge(); events=journal(r)
    required=(max(len(canonical(e)) for e in events) if limit=='max_input_bytes'
        else sum(len(canonical(e)) for e in events))
    result=consume(r,events,**{limit:required+delta}).finalize()
    assert result['status']==('failed' if delta<0 else 'complete'),result


@pytest.mark.parametrize('slot',['read','aw','w','write'])
@pytest.mark.parametrize('change',['metadata','scope','cancelled','refs','next_scope'])
def test_rehashed_reset_nested_context_metadata_is_not_a_lifecycle_oracle(slot,change):
    r=Recording()
    if slot=='read': r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    if slot in ('aw','write'): r.edge(d_awvalid=1,d_awready=1,d_awsize=2)
    if slot in ('w','write'): r.edge(d_wvalid=1,d_wready=1,d_wlast=1,d_wstrb=15)
    r.export.end(); r.begin('b'*32,1)
    ops=r.operations(); end=next(o for o in ops if o['kind']=='end_scope'); row=end['observations'][0]
    endpoint='i' if slot=='read' else 'd'
    if change=='metadata': row['pending_request_refs'][endpoint][slot]['tick']+=1
    if change=='scope': row['scope']['reset_epoch']=9
    if change=='cancelled': row['cancelled'][endpoint][slot]=False
    if change=='refs': row['pending_request_refs'][endpoint][slot]['refs']=[999]
    if change=='next_scope': row['next_scope']=dict(row['scope'])
    rehash(end)
    # Build authentic sidecars first, then replace the issued span and original.
    # This deliberately bypasses helper refusal so the consumer must check replay.
    events=journal(r)
    op_event=next(e for e in events if e['kind']=='reduced_axi_source_operation' and e['operation']['kind']=='end_scope')
    op_event['operation']=end
    assert consume(r,events).finalize()['reason']=='projection_mismatch'


@pytest.mark.parametrize('change',['remove','duplicate','reorder','extra','scope_reuse','receipt_without_scope'])
def test_operation_stream_omissions_and_reordering(change):
    r=Recording(); r.edge(); r.export.end(); r.begin('b'*32,1); r.edge()
    ops=r.operations()
    if change=='remove': ops.pop(1)
    if change=='duplicate':
        events=journal(r)
        row=next(e for e in events if e['kind']=='reduced_axi_source_operation' and e['operation']['kind']=='receipt')
        events.insert(events.index(row)+1,copy.deepcopy(row))
        assert consume(r,events).finalize()['status']=='failed'
        return
    if change=='reorder': ops[1],ops[2]=ops[2],ops[1]
    if change=='extra': ops.append(copy.deepcopy(ops[-1]))
    if change=='scope_reuse':
        ops[3]['payload']['scope']=copy.deepcopy(ops[0]['payload']['scope']); rehash(ops[3])
    if change=='receipt_without_scope':
        ops[3]['payload']['scope']=dict(execution_id='b'*32,testcase_id='another',reset_epoch=1)
        rehash(ops[3])
    assert consume(r,journal(r,operations=ops)).finalize()['status']=='failed'


@pytest.mark.parametrize('phase',['pre','post'])
def test_post_only_requests_and_hold_are_replayed_from_wire(phase):
    r=Recording()
    # Construct another actual parsed source receipt with a post-only offer, or
    # an illegal held offer. This cannot be synthesized from journal originals.
    row={p+'_'+n:0 for p,s in SHAPES.items() for n in s}
    other=copy.deepcopy(row)
    row['i_arvalid']=1 if phase=='pre' else 0
    other['i_arvalid']=1
    if phase=='pre': other['i_araddr']=4  # stalled PRE changed in POST
    sample=dict(local_tick=1,pre={'backend':row},post={'backend':other})
    payload=dict(schema_version='local_driver_result.v1',kind=r.runtime['kind'],samples=[sample],pre_backend=row,observations={},rdata=0,error=0)
    line=f'RESULT {r.execution} 1 0 1 {canonical(payload).hex()}\n'
    receipt=parse_driver_receipt(line[:-1],execution=r.execution,sequence=1,current_tick=0,kind=r.runtime['kind'])
    fields=[row[n] for n in STEP_PORTS]
    command=f'CMD {r.execution} 1 STEP_REDUCED_AXI '+' '.join(f'{v:x}' for v in fields)+'\n'
    try:
        r.export.receipt(receipt,operation='STEP_REDUCED_AXI',fields=fields,wire_command=command,wire_reply=line,cumulative_after=1,tick_base=0,artifact_kind=r.runtime['kind'])
    except ValueError: assert phase=='pre'
    result=consume(r).finalize()
    assert result['status']=='complete'
    assert result['outcome']==('observed_protocol_failure' if phase=='pre' else None)
    assert result['boundary_observations']==[]


def test_bound_runtime_clock_schedule_reparsed():
    r=Recording()
    # Alter admitted runtime and export binding before issuing any operations.
    runtime=dict(schema_version='local_runtime_artifact.v1',kind='reduced_dual_axi_cpu',
        clock_schedule={'schema_version':'local_clock_schedule.v1','startup_fast_ticks':0,
            'clocks':[{'domain':'fast','ratio':1,'first_rising_fast_tick':1},
                      {'domain':'slow','ratio':2,'first_rising_fast_tick':1}]})
    runtime['artifact_digest']=_sha(runtime)
    observer=ReducedAxiObserver(component_id='physical')
    export=ReducedAxiStreamExport(observer,session_id='session',observer_stream_id='clocked',source_component='physical',artifact_digest=runtime['artifact_digest'])
    export.begin(dict(execution_id='a'*32,testcase_id='case',reset_epoch=0))
    r.runtime=runtime; r.observer=observer; r.export=export; r.binding=export.source.identity_document()
    row={p+'_'+n:0 for p,s in SHAPES.items() for n in s}
    sample=dict(local_tick=1,pre={'backend':row},post={'backend':copy.deepcopy(row)},clock_edges={'fast':1,'slow':1})
    payload=dict(schema_version='local_driver_result.v1',kind=runtime['kind'],samples=[sample],pre_backend=row,observations={},rdata=0,error=0)
    line=f'RESULT {r.execution} 1 0 1 {canonical(payload).hex()}\n'
    receipt=parse_driver_receipt(line[:-1],execution=r.execution,sequence=1,current_tick=0,kind=runtime['kind'],clock_schedule=runtime['clock_schedule'])
    fields=[0]*len(STEP_PORTS)
    command=f'CMD {r.execution} 1 STEP_REDUCED_AXI '+' '.join(f'{v:x}' for v in fields)+'\n'
    export.receipt(receipt,operation='STEP_REDUCED_AXI',fields=fields,wire_command=command,wire_reply=line,cumulative_after=1,tick_base=0,artifact_kind=runtime['kind'])
    assert consume(r).finalize()['status']=='complete'
    events=journal(r)
    op=next(e['operation'] for e in events if e['kind']=='reduced_axi_source_operation' and e['operation']['kind']=='receipt')
    op['payload']['wire_reply']=op['payload']['wire_reply'].replace(canonical(payload).hex(),canonical(dict(payload,samples=[dict(sample,clock_edges={'fast':2,'slow':1})])).hex())
    rehash(op)
    assert consume(r,events).finalize()['reason']=='driver-clock-edge-count-mismatch'


def test_consume_has_constant_size_return_and_never_builds_a_report():
    r=Recording(); r.edge(); c=api().ReducedAxiJournalConsumer(r.binding,runner_component='alias',runtime_document=r.runtime)
    def forbidden_report(): raise AssertionError('consume copied accumulated report')
    c.report=forbidden_report
    for event in journal(r): assert c.consume(event) is None


def test_consumed_original_cannot_be_mutated_before_sidecar_into_a_false_boundary():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    r.edge(i_rvalid=1,i_rready=1,i_rlast=1,i_rdata=123)
    events=journal(r)
    c=api().ReducedAxiJournalConsumer(r.binding,runner_component='alias',runtime_document=r.runtime)
    for event in events:
        c.consume(event)
        if event['kind']=='reduced_axi_complete': event['payload']['rdata']=999
    result=c.finalize()
    assert result['status']=='complete'
    assert result['boundary_observations'][0]['payload']['rdata']==123


def test_returned_report_is_detached_from_consumer_state():
    r=Recording(); r.edge(i_arvalid=1,i_arready=1,i_arsize=2)
    r.edge(i_rvalid=1,i_rready=1,i_rlast=1,i_rdata=123)
    c=consume(r); original=c.report(); mutated=c.report()
    mutated['boundary_observations'][0]['payload']['rdata']=999
    mutated['pending']['i']['read']=True
    assert c.report()==original


def test_protocol_failure_has_one_bounded_role_preserving_witness():
    r=Recording(); r.edge(i_rvalid=1,i_rlast=1)
    result=consume(r).finalize()
    failure=result['protocol_failure']
    assert failure['reason']=='orphan_r'
    assert failure['raw_event_refs']==[1]
    assert failure['raw_event_ids'][0]<failure['observation_event_id']
    assert failure['authority']=='observation_only'


def test_gap_budget_counts_unrelated_events_from_the_registered_alias():
    r=Recording(); events=journal(r)
    base=len(events)
    events.extend({'event_id':base+i,'kind':'scheduler_tick','component':'alias'} for i in range(1,4))
    assert consume(r,events,max_event_gap=2).finalize()['reason']=='event_gap_limit'


@pytest.mark.parametrize('kind,schema',[('unknown_observation','reduced_axi_observation.v1'),('reduced_axi_invented','invented.v1')])
def test_unknown_own_protocol_record_is_not_an_unrelated_event(kind,schema):
    r=Recording(); events=journal(r)
    events.append(dict(event_id=len(events)+1,producer_event_id=1000,component='alias',kind=kind,schema_version=schema))
    assert consume(r,events).finalize()['reason']=='unknown_stream_record_kind'


def test_operation_ready_is_exact_and_waits_for_every_original_and_sidecar():
    r=Recording(); r.edge(d_awvalid=1,d_awready=1,d_awsize=2,d_wvalid=1,d_wready=1,d_wlast=1)
    events=journal(r); c=api().ReducedAxiJournalConsumer(r.binding,runner_component='alias',runtime_document=r.runtime)
    assert not c.operation_ready(1)
    current=0
    for index,event in enumerate(events):
        c.consume(event)
        if event['kind']=='reduced_axi_source_operation': current=event['operation']['operation_index']
        if current:
            remaining=next((e for e in events[index+1:] if e.get('component')=='alias' and e['kind']!='scheduler_tick'),None)
            ready=remaining is None or remaining['kind']=='reduced_axi_source_operation'
            assert c.operation_ready(current)==ready
            if current>1: assert not c.operation_ready(current-1)
    for bad in (True,1.0,0,'1'):
        with pytest.raises(ValueError,match='journal_index_type'): c.operation_ready(bad)
    c.consume(dict(event_id=len(events)+1,producer_event_id=1000,component='alias',kind='reduced_axi_invented'))
    assert not c.operation_ready(current)


@pytest.mark.parametrize('requested',['wrong','',True,1,{'case':'case'}])
def test_requested_testcase_id_must_match_actual_issued_scope(requested):
    r=Recording(); ops=r.operations(); ops[0]['payload']['requested_testcase_id']=requested; rehash(ops[0])
    assert consume(r,journal(r,operations=ops)).finalize()['reason']=='requested_testcase_mismatch'


@pytest.mark.parametrize('parent',[0,True,1.0,999])
def test_own_rows_require_existing_prior_producer(parent):
    r=Recording(); events=journal(r); events[1]['producer_event_id']=parent
    reason='producer_index_type' if type(parent) is not int or parent<=0 else 'producer_event_not_prior'
    assert consume(r,events).finalize()['reason']==reason


def test_real_session_post_receipt_service_failure_seal_is_recording_complete(monkeypatch):
    from tests.scenario.test_reduced_axi_stream_source import cpu
    from myfuzz.local_harness.session import GeneratedLocalSession
    from types import SimpleNamespace
    c=cpu(monkeypatch)
    runtime={'schema_version':'local_runtime_artifact.v1','kind':c.artifact_kind}
    runtime['artifact_digest']=_sha(runtime); c._artifact_document=runtime
    source=c.admit_observation_stream(session_id='session',observer_stream_id='failed-host-service')
    def actual_parsed_command(self, operation, fields):
        row={p+'_'+n:0 for p,s in SHAPES.items() for n in s}; row.update(zip(STEP_PORTS,fields))
        payload=dict(schema_version='local_driver_result.v1',kind=self.artifact_kind,
            samples=[dict(local_tick=1,pre={'backend':row},post={'backend':copy.deepcopy(row)})],
            pre_backend=row,observations={'physical':{}},rdata=0,error=0)
        wire=f'RESULT {self._execution} 1 0 1 {canonical(payload).hex()}\n'
        receipt=parse_driver_receipt(wire[:-1],execution=self._execution,sequence=1,current_tick=0,kind=self.artifact_kind)
        self._last_wire_reply=wire; self._sequence=self.local_ticks=1
        return receipt
    monkeypatch.setattr(GeneratedLocalSession,'command',actual_parsed_command)
    def service_failure(): raise RuntimeError('actual software host service failed')
    c.memory=SimpleNamespace(advance_step=service_failure)
    c.begin_case('case')
    with pytest.raises(RuntimeError,match='host service failed'): c.step_local({})
    assert source.state=='active' and c._observation_export.outcome=='observed_session_failure'
    c.seal_observation_stream()
    r=SimpleNamespace(binding=source.identity_document(),runtime=runtime,
        operations=lambda:[source.lookup(t) for t in source.pending()])
    result=consume(r).finalize()
    assert result['status']=='complete' and result['recording_integrity']=='complete'
    assert result['outcome']==result['producer_declared_outcome']=='observed_session_failure'
    assert result['protocol_outcome'] is None and result['protocol_failure'] is None
    assert result['runtime_accepted'] is result['semantic_accepted'] is False
