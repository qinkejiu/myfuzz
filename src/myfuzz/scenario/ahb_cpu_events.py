"""Bounded CPU AHB beat/phase observation, with no transaction authority.

The declared subset observes address and data phases, not burst/lock execution.
Only pre is an edge; post is raw evidence and limited wait continuity evidence.
"""
from __future__ import annotations
import copy
import json

SCHEMA='bounded_cpu_ahb_observation.v1'
SHAPE={'haddr':34,'hwdata':32,'hrdata':32,'hwstrb':4,'htrans':2,
       'hsize':3,'hburst':3,'hprot':4,'hwrite':1,'hmastlock':1,
       'hsel':1,'hready':1,'hresp':1}
ADDRESS=('hsel','htrans','haddr','hwrite','hsize','hburst','hprot','hmastlock')


class AhbCpuObserver:
    def __init__(self,*,component_id,endpoint_id,max_edges=100000,
                 max_bytes=64*1024*1024,max_events=1000000,max_scopes=256):
        if not all(isinstance(x,str) and x for x in (component_id,endpoint_id)):
            raise ValueError('ahb_identity')
        limits=(max_edges,max_bytes,max_events,max_scopes)
        if any(type(x) is not int or x<1 for x in limits):raise ValueError('ahb_budget')
        self.component_id=component_id;self.endpoint_id=endpoint_id
        self.events=[];self.scope=None;self._failed=False;self._exhausted=False
        self._edges=self._bytes=self._scopes=self._records=0
        self._limits=limits;self.tick=0;self.pending=None;self._address_hold=None
        self.counts=dict(accepted=0,completed=0,writes=0,reads=0,stalls=0,errors=0)
        self.contract={'schema_version':SCHEMA,'observer_version':1,
            'signal_widths':dict(SHAPE),'sampling':'pre_edge_post_continuity',
            'semantics':'beat_phase_observation_only','native_transaction_key':None,
            'startup_prefix':'unknown_before_ready_measurement',
            'not_claimed':['burst_execution','lock_execution','size_execution','retirement'],
            'budgets':dict(zip(('max_edges','max_raw_bytes','max_events','max_scopes'),limits)),
            'raw_reference_namespace':'observer_record_index_zero_based_global',
            'authority':'observation_only'}

    def _emit(self,kind,**fields):
        if kind != 'ahb_failure' and self._records >= self._limits[2]:
            self._exhausted = True
            self.poison('event_budget')
            raise ValueError('ahb_event_budget')
        row=dict(schema_version=SCHEMA,kind=kind,component_id=self.component_id,
            endpoint_id=self.endpoint_id,scope=copy.deepcopy(self.scope),
            observer_record_index=self._records,
            authority='observation_only',runtime_accepted=False,semantic_accepted=False,
            native_transaction_key=None,**copy.deepcopy(fields))
        self.events.append(row);self._records+=1;return self._records-1

    def require_active(self):
        if self._failed or self._exhausted or self.scope is None:
            raise ValueError('ahb_not_active')

    def poison(self,reason,*,diagnostic_receipt=None,trusted_projection=False,possible_effects=True):
        if self._failed:return
        self._failed=True
        self._emit('ahb_failure',reason=str(reason),category='diagnostic_unknown',
            trusted_projection=trusted_projection,possible_effects=possible_effects,
            diagnostic_receipt=diagnostic_receipt,pending=self.pending)

    def _fail(self,reason,ref,*,trusted=False):
        if reason=='budget':self._exhausted=True
        self.poison(reason,trusted_projection=trusted)
        self.events[-1]['raw_event_refs']=[ref]
        raise ValueError('ahb_'+reason)

    def begin_scope(self,*,execution_id,testcase_id,reset_epoch):
        if not all(isinstance(v,str) and v for v in (execution_id,testcase_id)) or type(reset_epoch) is not int or reset_epoch<0:
            raise ValueError('ahb_scope')
        if self._failed or self._exhausted:raise ValueError('ahb_not_active')
        if self._records >= self._limits[2]:
            self._exhausted=True;self.poison('event_budget');raise ValueError('ahb_event_budget')
        if self.scope is not None:self.end_scope()
        if self._scopes>=self._limits[3]:
            self._exhausted=True;self.poison('scope_budget');raise ValueError('ahb_scope_budget')
        self._scopes+=1;self.tick=0;self.pending=None;self._address_hold=None
        self.scope=dict(execution_id=execution_id,testcase_id=testcase_id,
            reset_epoch=reset_epoch,source_component=self.component_id,endpoint_id=self.endpoint_id)

    def end_scope(self):
        if self.scope is not None:
            self._emit('ahb_reset',cancelled=self.pending,counts=self.counts)
        self.scope=None;self.pending=None;self._address_hold=None;self.tick=0

    def observe(self,sample,*,rows=None):
        self.require_active()
        ref=self._emit('ahb_raw',raw_sample=sample)
        self._edges+=1
        try:self._bytes+=len(json.dumps(sample,sort_keys=True,allow_nan=False).encode())
        except (TypeError,ValueError):self._fail('shape',ref)
        if self._edges>self._limits[0] or self._bytes>self._limits[1] or self._records+5>self._limits[2]:
            self._fail('budget',ref)
        if not isinstance(sample,dict):self._fail('shape',ref)
        tick=sample.get('local_tick')
        if type(tick) is not int or tick<=self.tick:self._fail('tick',ref)
        values=sample if rows is None else rows
        if not isinstance(values,dict):self._fail('shape',ref)
        for phase in ('pre','post'):
            row=values.get(phase)
            if not isinstance(row,dict) or set(row)!=set(SHAPE) or any(type(row[k]) is not int or not 0<=row[k]<1<<w for k,w in SHAPE.items()):self._fail('shape',ref)
        p=values['pre'];post=values['post']
        if self.tick == 0:
            self._emit('ahb_prefix_unknown',local_tick=tick,raw_event_refs=[ref],
                reason='address/data phases before the measured READY boundary are unavailable')
        self.tick=tick
        address={k:p[k] for k in ADDRESS}
        # ERROR may release/cancel an address offer; no AXI VALID rule is applied.
        if self._address_hold is not None and not p['hresp'] and address!=self._address_hold:
            self._fail('address_hold',ref,trusted=True)
        self._address_hold=None
        if not p['hready']:
            self.counts['stalls']+=1
            if p['hsel'] and p['htrans']&2 and not p['hresp']:
                if not post['hresp'] and {k:post[k] for k in ADDRESS}!=address:
                    self._fail('address_hold',ref,trusted=True)
                if not post['hresp']:self._address_hold=address
        old=self.pending
        if old is not None:
            if old['write']:
                data={'wdata':p['hwdata'],'wstrb':p['hwstrb']}
                if old['write_data_ref'] is None:
                    old.update(**data,write_data_ref={'raw_event':ref,'phase':'pre'})
                elif any(old[k]!=v for k,v in data.items()):
                    self._fail('write_hold',ref,trusted=True)
                if not p['hready'] and not p['hresp'] and not post['hresp'] and (post['hwdata'],post['hwstrb'])!=(p['hwdata'],p['hwstrb']):
                    self._fail('write_hold',ref,trusted=True)
            if p['hready']:
                self.counts['completed']+=1;self.counts['errors']+=p['hresp']
                self._emit('ahb_complete',**old,local_tick=tick,hresp=p['hresp'],
                    rdata=p['hrdata'],raw_event_refs=list(dict.fromkeys([old['address_ref']['raw_event'],
                        *([old['write_data_ref']['raw_event']] if old['write_data_ref'] else []),ref])),
                    completion_ref={'raw_event':ref,'phase':'pre'})
                self.pending=None
        if p['hready'] and p['hsel'] and p['htrans']&2:
            self.counts['accepted']+=1;self.counts['writes' if p['hwrite'] else 'reads']+=1
            self.pending={'observation_id':self.counts['accepted'],'address':p['haddr'],
                'write':p['hwrite'],'controls':address,'address_ref':{'raw_event':ref,'phase':'pre'},
                'write_data_ref':None,'wdata':None,'wstrb':None}
            self._emit('ahb_address',**self.pending,local_tick=tick,raw_event_refs=[ref])


def bind_ahb_trace(document):
    """Authenticate the role map against the generated structural ABI facts."""
    group=document.get('base_protocol_traces',{})
    traces=group.get('traces',[])
    if group.get('sample_group')!='protocol_taps' or group.get('sampling')!='pre_post' or len(traces)!=1:
        raise ValueError('ahb_trace_missing')
    trace=traces[0];endpoint=trace.get('endpoint_id');signals=trace.get('signals')
    if (trace.get('protocol')!='ahb-lite' or trace.get('boundary')!='cpu_physical_abi'
        or trace.get('sample_group')!='protocol_taps' or trace.get('signal_widths')!=SHAPE
        or not isinstance(endpoint,str) or not endpoint or not isinstance(signals,dict)
        or set(signals)!=set(SHAPE) or len(set(signals.values()))!=len(SHAPE)):
        raise ValueError('ahb_trace_shape')
    taps=document.get('protocol_tap_ports',[]);abi=document.get('structural_abi',{}).get('ports',[])
    if len(taps)!=len(SHAPE):raise ValueError('ahb_tap_shape')
    for role,width in SHAPE.items():
        matches=[r for r in taps if r.get('name')==signals[role] and r.get('role')==role and r.get('endpoint_id')==endpoint]
        owners=[r for r in abi if r.get('role')==role and r.get('endpoint_id')==endpoint]
        if len(matches)!=1 or len(owners)!=1:raise ValueError('ahb_tap_binding')
        tap=matches[0];owner=owners[0]
        direction='input' if role in ('hready','hrdata','hresp') else 'output'
        if (tap.get('direction'),tap.get('width'),tap.get('source_wire'),owner.get('direction'),owner.get('width'))!=('output',width,'link_'+owner['wrapper_name'],direction,width):
            raise ValueError('ahb_tap_binding')
    return endpoint,copy.deepcopy(signals),copy.deepcopy(trace)
