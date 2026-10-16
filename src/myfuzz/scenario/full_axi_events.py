"""Receipt-bound bounded full AXI observation for a pinned packed64 ABI.

No native coverage is implied by this software contract. Only pre accepts;
post validates stalled offers. The single master has no ISA channel identity.
"""
from __future__ import annotations
import copy
import json
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE as PACKED_SHAPE

SCHEMA = 'bounded_full_axi_observation.v1'


class BoundedFullAxiObserver:
    def __init__(self, *, component_id, max_edges=100000,
                 max_bytes=64*1024*1024, max_scopes=1024):
        if type(component_id) is not str or not component_id:
            raise ValueError('full_axi_component_required')
        if any(type(v) is not int or v < 1 for v in (max_edges,max_bytes,max_scopes)):
            raise ValueError('full_axi_budget_invalid')
        self.component_id=component_id
        self.max_edges,self.max_bytes,self.max_scopes=max_edges,max_bytes,max_scopes
        self.events=[]
        self.scope=None
        self._edges=self._bytes=self._scopes=0
        # Runner may drain this list in place into its EventJournal.
        # References identify the lifetime stream, not current buffer offsets.
        self._record_count=0
        self._budget_exhausted=False
        self.contract={
            'schema_version':SCHEMA,'variant':'packed64_id4_user64_single_master.v1',
            'endpoint_id':'axi','signal_prefix':'axi_',
            'signal_shapes':{r:{'direction':d,'width':w} for r,(d,w) in PACKED_SHAPE.items()},
            'sampling':'pre_acceptance_post_hold_only',
            'post_offer_hold':'new_or_changed_offer_until_next_pre',
            'raw_reference_namespace':'observer_stream_local_record_index',
            'native_observed_bins':'unknown_no_saved_generated_journal',
            'budgets':{'max_edges':max_edges,'max_raw_bytes':max_bytes,
                       'max_scopes':max_scopes,'max_events_per_edge':9,
                       'max_records':max_edges*9+max_scopes*2+2,
                       'read_bursts':1,'write_contexts':1,
                       'max_burst_beats':256,'max_w_before_aw':256},
            'supported_bursts':{'fixed_max_beats':16,'incrementing_max_beats':256,
                                'wrapping_lengths':[2,4,8,16]},
            'exclusive_and_atomic':'unsupported',
            'response_status':{'0':'okay','1':'exclusive_response_unsupported',
                               '2':'slave_error','3':'decode_error'},
            'authority':'observation_only'}
        self._clear()

    def _clear(self):
        self._read=self._write=self._b=None
        self._wbeats=[]
        self._holds={}
        self._tick=0
        self._failed=False
        self.accepted={c:0 for c in ('aw','w','b','ar','r')}

    @property
    def pending(self):
        return {'read_beats_remaining':0 if self._read is None else self._read['length']-self._read['index'],
                'write_beats_remaining':0 if self._write is None else self._write['length']-self._write['index'],
                'buffered_wbeats':len(self._wbeats),'b_pending':self._b is not None}

    def _emit(self,kind,**fields):
        event={'schema_version':SCHEMA,'kind':kind,'component_id':self.component_id,
               'endpoint_id':'axi','scope':copy.deepcopy(self.scope),
               'authority':'observation_only','runtime_accepted':False,
               'semantic_accepted':False,**copy.deepcopy(fields)}
        self.events.append(event)
        self._record_count+=1
        return event

    def end_scope(self):
        if self.scope is not None:
            self._emit('full_axi_reset',cancelled=self.pending,
                       pending_request_refs={'read':self._read,'write':self._write,
                                             'wbeats':self._wbeats,'b':self._b})
        self.scope=None
        self._clear()

    def begin_scope(self,*,execution_id,testcase_id,reset_epoch):
        if (not all(type(v) is str and v for v in (execution_id,testcase_id))
                or type(reset_epoch) is not int or reset_epoch<0):
            raise ValueError('full_axi_scope_invalid')
        if self._budget_exhausted or self._scopes>=self.max_scopes:
            raise ValueError('full_axi_scope_budget')
        scope=dict(execution_id=execution_id,testcase_id=testcase_id,
                   reset_epoch=reset_epoch,source_component=self.component_id)
        if scope==self.scope:raise ValueError('full_axi_scope_reuse')
        if self.scope is not None:self.end_scope()
        self.scope=scope
        self._scopes+=1
        self._clear()

    def require_active(self):
        if self.scope is None or self._failed or self._budget_exhausted:
            raise ValueError('full_axi_scope_not_active')

    def poison(self,reason,*,diagnostic_receipt=None):
        """Record a service/receipt failure without projecting untrusted signals."""
        if self.scope is None or self._failed:return
        self._failed=True
        try:
            self._bytes+=len(json.dumps(diagnostic_receipt,sort_keys=True,allow_nan=False).encode())
            if self._bytes>self.max_bytes:self._budget_exhausted=True
        except (TypeError,ValueError):
            self._budget_exhausted=True
        self._emit('full_axi_failure',category='diagnostic_unknown',reason=reason,
                   trusted_projection=False,possible_effects=True,
                   diagnostic_receipt=diagnostic_receipt,
                   pending=self.pending)

    def _fail(self,reason,ref,category='protocol_violation',*,trusted_projection=None):
        self._failed=True
        if reason=='budget':self._budget_exhausted=True
        self._emit('full_axi_failure',reason=reason,category=category,
                   raw_event_refs=[ref],local_tick=self._tick,pending=self.pending,
                   possible_effects=True,trusted_projection=(category!='diagnostic_unknown'
                       if trusted_projection is None else trusted_projection))
        raise ValueError('full_axi_'+reason)

    @staticmethod
    def _address(context,index):
        start,size,burst,length=(context[k] for k in ('address','size','burst','length'))
        if burst==0:return start
        if burst==1:return start+index*(1<<size)
        span=(1<<size)*length
        base=start&~(span-1)
        return base+(start-base+index*(1<<size))%span

    def _request(self,row,c,ref):
        start,size,length,burst=(row[c+s] for s in ('addr','size','len','burst'))
        length+=1
        if size>3 or start%(1<<size):self._fail('size_alignment',ref,'unsupported')
        if row[c+'lock']:self._fail('exclusive',ref,'unsupported')
        if c=='aw' and row['awatop']:self._fail('atomic',ref,'unsupported')
        if burst==3:self._fail('burst_reserved',ref)
        if burst==0 and length>16:self._fail('fixed_length',ref)
        if burst==2 and length not in (2,4,8,16):self._fail('wrap_length',ref)
        context=dict(address=start,size=size,length=length,burst=burst,
                     id=row[c+'id'],index=0,refs=[ref],beat_refs=[],tick=self._tick,
                     payload={r:v for r,v in row.items() if r.startswith(c)})
        if any((a:=self._address(context,i))>=1<<64 or a>>12!=start>>12 for i in range(length)):
            self._fail('boundary',ref)
        return context

    def observe(self,sample):
        self.require_active()
        ref=self._record_count+1
        self._emit('full_axi_raw',raw_event_ref=ref,raw_sample=sample)
        self._edges+=1
        try:self._bytes+=len(json.dumps(sample,sort_keys=True,allow_nan=False).encode())
        except (TypeError,ValueError):self._fail('shape',ref,'diagnostic_unknown')
        if self._edges>self.max_edges or self._bytes>self.max_bytes:
            self._fail('budget',ref,'unsupported',trusted_projection=False)
        if not isinstance(sample,dict):self._fail('shape',ref,'diagnostic_unknown')
        tick=sample.get('local_tick')
        if type(tick) is not int or tick<=self._tick:self._fail('tick',ref,'diagnostic_unknown')
        self._tick=tick
        rows={}
        for phase in ('pre','post'):
            group=sample.get(phase)
            row=group.get('backend') if isinstance(group,dict) else None
            if (not isinstance(row,dict) or set(row)!={'axi_'+r for r in PACKED_SHAPE}
                    or any(type(row['axi_'+r]) is not int or not 0<=row['axi_'+r]<1<<w
                           for r,(_,w) in PACKED_SHAPE.items())):
                self._fail('shape',ref,'diagnostic_unknown')
            rows[phase]={r:row['axi_'+r] for r in PACKED_SHAPE}
        for c in ('aw','w','b','ar','r'):
            roles=[r for r in PACKED_SHAPE if r.startswith(c) and r!=c+'ready']
            before={r:rows['pre'][r] for r in roles}
            after={r:rows['post'][r] for r in roles}
            held=self._holds.pop(c,None)
            if held is not None and held!=before:self._fail('hold',ref)
            if before[c+'valid'] and not rows['pre'][c+'ready']:
                if before!=after:self._fail('hold',ref)
                self._holds[c]=after
            # A newly asserted or changed post offer has not transferred.
            # Equal residual VALID/payload after an accepted pre is ambiguous:
            # injected R/B inputs retain the consumed response until the next
            # command. Do not project a second transfer or invent a new offer.
            if after[c+'valid'] and (not before[c+'valid'] or
                    rows['pre'][c+'ready'] and after!=before):
                self._holds[c]=after
        row=rows['pre']
        hit=lambda c:bool(row[c+'valid'] and row[c+'ready'])
        # Complete prior contexts before accepting a new request on this edge.
        if row['bvalid']:
            if self._b is None:self._fail('orphan_b',ref)
            if row['bid']!=self._b['id']:self._fail('response_id',ref)
            if row['bresp']==1:self._fail('exclusive_response',ref,'unsupported')
            if hit('b'):
                self.accepted['b']+=1
                self._emit('full_axi_complete',channel='b',payload=row,local_tick=tick,
                           raw_event_refs=[ref],request_refs=self._b['refs'])
                self._b=None
        if row['rvalid']:
            read=self._read
            if read is None:self._fail('orphan_r',ref)
            if row['rid']!=read['id']:self._fail('response_id',ref)
            if row['rlast']!=int(read['index']==read['length']-1):self._fail('last',ref)
            if row['rresp']==1:self._fail('exclusive_response',ref,'unsupported')
            if hit('r'):
                self.accepted['r']+=1
                self._emit('full_axi_read_beat',payload=row,local_tick=tick,
                           beat_index=read['index'],address=self._address(read,read['index']),
                           encoded_size=read['size'],beat_bytes=1<<read['size'],
                           raw_event_refs=[ref],request_refs=read['refs'],
                           prior_beat_refs=read['beat_refs'])
                read['beat_refs'].append(ref)
                read['index']+=1
                if read['index']==read['length']:self._read=None
        for c in ('ar','aw','w'):
            if not hit(c):continue
            payload={r:v for r,v in row.items() if r.startswith(c)}
            if c=='ar':
                if self._read is not None:self._fail('outstanding_read',ref,'unsupported')
                self._read=self._request(row,c,ref)
            elif c=='aw':
                if self._write is not None or self._b is not None:self._fail('outstanding_write',ref,'unsupported')
                self._write=self._request(row,c,ref)
            else:
                if self._b is not None:self._fail('outstanding_write',ref,'unsupported')
                if len(self._wbeats)>=256:self._fail('w_buffer_budget',ref,'unsupported')
                self._wbeats.append(dict(payload=payload,ref=ref,tick=tick))
            self.accepted[c]+=1
            self._emit('full_axi_accept',channel=c,local_tick=tick,
                       payload=payload,raw_event_refs=[ref])
        write=self._write
        if write is not None and self._wbeats:
            beats=[]
            for beat in self._wbeats:
                index=write['index']
                if index>=write['length']:self._fail('extra_w',ref)
                payload=beat['payload']
                if payload['wlast']!=int(index==write['length']-1):self._fail('last',ref)
                address=self._address(write,index)
                allowed=((1<<(1<<write['size']))-1)<<(address&7)
                if payload['wstrb']&~allowed:self._fail('strobe',ref)
                beats.append(dict(beat_index=index,address=address,encoded_size=write['size'],
                                  beat_bytes=1<<write['size'],payload=payload,
                                  raw_event_refs=[beat['ref']],aw_ref=write['refs'][0],
                                  accepted_tick=beat['tick']))
                write['refs'].append(beat['ref'])
                write['index']+=1
            if 'first_w_tick' not in write:
                write['first_w_tick']=self._wbeats[0]['tick']
            first_tick=write['first_w_tick']
            order=('same_edge' if first_tick==write['tick'] else
                   'w_before_aw' if first_tick<write['tick'] else 'aw_before_w')
            self._emit('full_axi_write_beats',local_tick=tick,beats=beats,
                       aw_w_order=order,request_refs=write['refs'],raw_event_refs=[ref])
            self._wbeats=[]
            if write['index']==write['length']:
                self._b=write
                self._write=None
