"""Bounded CPU AHB beat/phase observation, with no transaction authority.

The declared subset observes address and data phases, not burst/lock execution.
Only pre is an edge; post is raw evidence and limited wait continuity evidence.

Manager-domain correction
    The thirteen protocol roles are the *external* boundary: ``hready`` is
    ``HREADYEXT``, the external subordinate's return.  Manager acceptance is the
    separate measured ``manager_ready`` output (aggregate ``HREADY``) and the
    actual bus reset is the measured ``bus_reset_n`` output (``HRESETn``).  Both
    arrive as explicit PRE/POST domain rows, authenticated by
    :func:`bind_ahb_trace` against the versioned manager-domain contract.  There
    is no fallback to the external ready role and no reset inversion.
"""
from __future__ import annotations
import copy
import json

SCHEMA='bounded_cpu_ahb_observation.v1'
SHAPE={'haddr':34,'hwdata':32,'hrdata':32,'hwstrb':4,'htrans':2,
       'hsize':3,'hburst':3,'hprot':4,'hwrite':1,'hmastlock':1,
       'hsel':1,'hready':1,'hresp':1}
ADDRESS=('hsel','htrans','haddr','hwrite','hsize','hburst','hprot','hmastlock')
BINDING_SCHEMA='bounded_cpu_ahb_trace_binding.v1'


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
        self._limits=limits;self.tick=0;self.pending=None
        self._stall_offer=None
        self._startup_contract=None;self._domain=None
        self._startup_seen=0;self._startup_finished=False
        self._bus_state='unknown';self._bus_assert_tick=None;self._bus_release_tick=None
        self._bus_domain_prefix=False;self._domain_unknown_emitted=False
        self._measurement_offset=0;self.measured_reset_to_command_prefix=False
        from myfuzz.local_harness.ahb_manager_domain import OBSERVER_VERSION,SAMPLING_DOMAIN
        self.counts=dict(accepted=0,completed=0,writes=0,reads=0,stalls=0,errors=0)
        self.contract={'schema_version':SCHEMA,'observer_version':OBSERVER_VERSION,
            'signal_widths':dict(SHAPE),'sampling':'pre_edge_post_continuity',
            'semantics':'beat_phase_observation_only','native_transaction_key':None,
            'startup_prefix':'observed_bus_reset_assertion_then_release',
            'sampling_domain':SAMPLING_DOMAIN,'domain_contract':None,
            'not_claimed':['burst_execution','lock_execution','size_execution','retirement',
                'aggregate_hresp','aggregate_hrdata','other_slave_response_semantics',
                'reset_synchronizer_latency'],
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

    def require_begin_capacity(self, startup_edges=0):
        if self._failed or self._exhausted:
            raise ValueError('ahb_not_active')
        if (self._scopes>=self._limits[3] or self._records>=self._limits[2]
                or self._edges+startup_edges>self._limits[0]):
            self._exhausted=True
            self.poison('scope_or_startup_budget',possible_effects=False)
            raise ValueError('ahb_scope_or_startup_budget')

    def begin_scope(self,*,execution_id,testcase_id,reset_epoch):
        if not all(isinstance(v,str) and v for v in (execution_id,testcase_id)) or type(reset_epoch) is not int or reset_epoch<0:
            raise ValueError('ahb_scope')
        if self._failed or self._exhausted:raise ValueError('ahb_not_active')
        if self._records >= self._limits[2]:
            self._exhausted=True;self.poison('event_budget');raise ValueError('ahb_event_budget')
        if self.scope is not None:self.end_scope()
        if self._scopes>=self._limits[3]:
            self._exhausted=True;self.poison('scope_budget');raise ValueError('ahb_scope_budget')
        self._scopes+=1;self.tick=0;self.pending=None;self._stall_offer=None
        self._startup_contract=None;self._startup_seen=0;self._startup_finished=False
        self._bus_state='unknown';self._bus_assert_tick=None;self._bus_release_tick=None
        self._bus_domain_prefix=False;self._domain_unknown_emitted=False
        self._measurement_offset=0;self.measured_reset_to_command_prefix=False
        self.scope=dict(execution_id=execution_id,testcase_id=testcase_id,
            reset_epoch=reset_epoch,source_component=self.component_id,endpoint_id=self.endpoint_id)

    def end_scope(self):
        if self.scope is not None:
            self._emit('ahb_reset',cancelled=self.pending,counts=self.counts,
                       bus_reset_state=self._bus_state)
        self.scope=None;self.pending=None;self._stall_offer=None;self.tick=0

    def declare_manager_domain(self, contract):
        """Install the authenticated measured-domain contract for this scope."""
        from myfuzz.local_harness.ahb_manager_domain import (
            OBSERVER_VERSION, SAMPLING_DOMAIN, validate_manager_domain_contract)
        domain=validate_manager_domain_contract(contract)
        if domain['protocol_endpoint_id'] != self.endpoint_id:
            raise ValueError('ahb_manager_domain_endpoint')
        configured=self.contract.get('domain_contract')
        if configured is not None and json.dumps(configured,sort_keys=True)!=json.dumps(domain,sort_keys=True):
            raise ValueError('ahb_manager_domain_substitution')
        self._domain=copy.deepcopy(domain)
        self.contract['domain_contract']=copy.deepcopy(domain)
        self.contract['sampling_domain']=SAMPLING_DOMAIN
        self.contract['observer_version']=OBSERVER_VERSION
        return copy.deepcopy(domain)

    def record_startup_receipt(self, receipt):
        self.require_active()
        ref=self._emit('ahb_startup_receipt',raw_receipt=receipt,
            trusted_projection=False,possible_effects=True)
        self._bytes+=len(json.dumps(receipt,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
        if self._bytes>self._limits[1] or self._records+5>self._limits[2]:
            self._fail('budget',ref)

    def begin_startup(self, contract):
        self.require_active()
        if self.tick or self._startup_contract is not None:
            raise ValueError('ahb_startup_state')
        from myfuzz.local_harness.ahb_startup import validate_startup_contract
        domain = contract.get('manager_domain') if isinstance(contract, dict) else None
        self._startup_contract=validate_startup_contract(contract)
        if domain is None:
            configured=self.contract.get('domain_contract')
            if configured is None:
                raise ValueError('ahb_manager_domain_missing')
            domain=configured
        self.declare_manager_domain(domain)

    def observe_startup(self, record, *, rows):
        self.require_active()
        index=self._startup_seen+1
        reset=int(index<=self._startup_contract['assert_ticks'])
        if (not isinstance(record,dict) or index>self._startup_contract['total_ticks'] or
            not isinstance(record.get('sample'),dict) or
            type(record['sample'].get('local_tick')) is not int or record['sample']['local_tick']!=index or
            any(type(record.get(k)) is not int or record[k]!=v for k,v in
                [('startup_edge_index',index),('reset_pre',reset),('reset_post',reset)])):
            self.poison('startup_record_identity',diagnostic_receipt=record)
            raise ValueError('ahb_startup_record_identity')
        self._observe(record['sample'],rows=rows,tick_namespace='startup',
            reset_asserted=reset,metadata={k:v for k,v in record.items() if k!='sample'})
        self._startup_seen=index

    def finish_startup(self):
        self.require_active()
        if self._startup_contract is None or self._startup_finished or self._startup_seen!=self._startup_contract['total_ticks']:
            raise ValueError('ahb_startup_incomplete')
        if (self._bus_assert_tick is None or self._bus_release_tick is None
                or not self._bus_domain_prefix or self._bus_state!='released'):
            self.poison('bus_reset_prefix_unmeasured',possible_effects=False)
            raise ValueError('ahb_bus_reset_prefix_unmeasured')
        self._startup_finished=True;self._measurement_offset=self._startup_seen
        self._emit('ahb_startup_complete',startup_ticks=self._startup_seen,
            measured_reset_to_command_prefix=False,
            bus_reset_assert_measurement_tick=self._bus_assert_tick,
            bus_reset_release_measurement_tick=self._bus_release_tick,
            domain_sampling='pre_only',synchronizer_latency='not_claimed')

    def observe(self,sample,*,rows=None):
        if self._startup_contract is not None and not self._startup_finished:
            raise ValueError('ahb_startup_incomplete')
        return self._observe(sample,rows=rows)

    def _values(self, sample, rows):
        if rows is not None:
            return rows
        if not isinstance(sample, dict):
            return sample
        return {'pre': sample.get('pre'), 'post': sample.get('post'),
                'domain': sample.get('domain')}

    def _observe(self,sample,*,rows=None,tick_namespace='command',reset_asserted=0,metadata=None):
        from myfuzz.local_harness.ahb_manager_domain import validate_domain_rows
        self.require_active()
        values=self._values(sample,rows)
        try:
            measured=validate_domain_rows(values.get('domain')) if isinstance(values,dict) else None
        except ValueError:
            measured=None
        ref=self._emit('ahb_raw',raw_sample=sample,tick_namespace=tick_namespace,
                       startup_metadata=metadata,
                       measured_domain=copy.deepcopy(measured))
        self._edges+=1
        try:self._bytes+=len(json.dumps([sample,metadata],sort_keys=True,allow_nan=False).encode())
        except (TypeError,ValueError):self._fail('shape',ref)
        if self._edges>self._limits[0] or self._bytes>self._limits[1] or self._records+5>self._limits[2]:
            self._fail('budget',ref)
        if not isinstance(sample,dict):self._fail('shape',ref)
        tick=sample.get('local_tick')
        measurement_tick=(tick+self._measurement_offset if type(tick) is int else None)
        if (type(tick) is not int or tick<1 or measurement_tick<=self.tick
                or self._startup_finished and measurement_tick!=self.tick+1):
            self._fail('tick',ref)
        if not isinstance(values,dict):self._fail('shape',ref)
        if measured is None:self._fail('domain_row',ref)
        for phase in ('pre','post'):
            row=values.get(phase)
            if not isinstance(row,dict) or set(row)!=set(SHAPE) or any(type(row[k]) is not int or not 0<=row[k]<1<<w for k,w in SHAPE.items()):self._fail('shape',ref)
        self.tick=measurement_tick
        if self._domain is None:self._fail('manager_domain_missing',ref)
        pre=values['pre'];post=values['post']
        manager_ready=measured['pre']['manager_ready']
        bus_reset_n=measured['pre']['bus_reset_n']
        external_ready=pre['hready']
        selected=bool(pre['hsel'] and pre['htrans']&2)

        # Actual bus reset is only the measured PRE output; post is raw evidence.
        if bus_reset_n==0:
            if self._bus_state!='asserted':
                cancelled=self.pending
                prior=self._bus_state
                self.pending=None;self._stall_offer=None
                self._bus_state='asserted';self._bus_assert_tick=measurement_tick
                self._bus_release_tick=None;self._bus_domain_prefix=False
                self._emit('ahb_bus_reset',asserted=True,released=False,bus_reset_n=0,
                    measured_phase='pre',local_tick=tick,measurement_tick=measurement_tick,
                    tick_namespace=tick_namespace,prior_state=prior,cancelled=cancelled,
                    bus_domain_prefix=False,raw_event_refs=[ref])
            return
        if self._bus_state=='asserted':
            self._bus_state='released';self._bus_release_tick=measurement_tick
            self._bus_domain_prefix=True
            self._emit('ahb_bus_reset',asserted=False,released=True,bus_reset_n=1,
                measured_phase='pre',local_tick=tick,measurement_tick=measurement_tick,
                tick_namespace=tick_namespace,prior_state='asserted',cancelled=None,
                bus_domain_prefix=True,
                assert_measurement_tick=self._bus_assert_tick,raw_event_refs=[ref])
        elif self._bus_state=='unknown':
            # Before the first actually observed assertion the domain is unknown;
            # no address, data or reset release is projected from external timing.
            if not self._domain_unknown_emitted:
                self._domain_unknown_emitted=True
                self._emit('ahb_domain_unknown',local_tick=tick,
                    measurement_tick=measurement_tick,tick_namespace=tick_namespace,
                    domain_state='unknown_before_first_measured_bus_reset_assertion',
                    raw_event_refs=[ref])
            return

        if tick_namespace=='command' and self._startup_finished and not self.measured_reset_to_command_prefix:
            self.measured_reset_to_command_prefix=True
            self._emit('ahb_prefix_complete',local_tick=tick,measurement_tick=measurement_tick,
                measured_reset_to_command_prefix=True,
                bus_reset_assert_measurement_tick=self._bus_assert_tick,
                bus_reset_release_measurement_tick=self._bus_release_tick,
                raw_event_refs=[ref])

        old=self.pending
        if old is not None and old['write']:
            data={'wdata':pre['hwdata'],'wstrb':pre['hwstrb']}
            if old['write_data_ref'] is None:
                old.update(**data,write_data_ref={'raw_event':ref,'phase':'pre'})
            elif any(old[k]!=v for k,v in data.items()):
                self._fail('write_hold',ref,trusted=True)
            if not manager_ready and not pre['hresp'] and not post['hresp'] and (post['hwdata'],post['hwstrb'])!=(pre['hwdata'],pre['hwstrb']):
                self._fail('write_hold',ref,trusted=True)
        if old is not None and manager_ready:
            # The accepted transfer is an owned external selected data phase.  Its
            # completion must agree with the external return; aggregate HRESP/HRDATA
            # are not exported, so no other-slave response is claimed.
            if not old.get('external_selected'):
                self._fail('completion_context',ref,trusted=False)
            if not external_ready:
                self._fail('external_completion',ref,trusted=True)
            self.counts['completed']+=1;self.counts['errors']+=pre['hresp']
            self._emit('ahb_complete',**old,local_tick=tick,measurement_tick=measurement_tick,
                tick_namespace=tick_namespace,hresp=pre['hresp'],
                rdata=pre['hrdata'],response_context='external_selected_data_phase',
                aggregate_hresp_exported=False,aggregate_hrdata_exported=False,
                external_ready=external_ready,
                raw_event_refs=list(dict.fromkeys([old['address_ref']['raw_event'],
                    *([old['write_data_ref']['raw_event']] if old['write_data_ref'] else []),ref])),
                completion_ref={'raw_event':ref,'phase':'pre'})
            self.pending=None

        address={k:pre[k] for k in ADDRESS}
        if not manager_ready:
            if self._stall_offer is not None and not pre['hresp'] and address!=self._stall_offer:
                self._fail('address_hold',ref,trusted=True)
            if selected and not pre['hresp']:
                if not post['hresp'] and {k:post[k] for k in ADDRESS}!=address:
                    self._fail('address_hold',ref,trusted=True)
                self._stall_offer=address
                self.counts['stalls']+=1
            else:
                self._stall_offer=None
        else:
            self._stall_offer=None
            if selected:
                self.counts['accepted']+=1;self.counts['writes' if pre['hwrite'] else 'reads']+=1
                self.pending={'observation_id':self.counts['accepted'],'address':pre['haddr'],
                    'write':pre['hwrite'],'controls':address,
                    'address_ref':{'raw_event':ref,'phase':'pre'},'write_data_ref':None,
                    'wdata':None,'wstrb':None,'external_selected':True,
                    'acceptance_ready':'manager_ready','external_ready_at_accept':external_ready}
                self._emit('ahb_address',**self.pending,local_tick=tick,
                    measurement_tick=measurement_tick,tick_namespace=tick_namespace,
                    raw_event_refs=[ref])
            elif pre['htrans']&2:
                self._emit('ahb_unvalidated',local_tick=tick,measurement_tick=measurement_tick,
                    tick_namespace=tick_namespace,
                    context='non_external_selected_address_phase',
                    reason='aggregate internal slave response/data are not exported',
                    raw_event_refs=[ref])


def bind_ahb_trace(document):
    """Authenticate the external role map and the measured manager-domain contract."""
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
    from myfuzz.local_harness.ahb_manager_domain import authenticate_manager_domain
    domain=authenticate_manager_domain(document)
    binding={'schema_version':BINDING_SCHEMA,
             'protocol_trace':copy.deepcopy(trace),
             'manager_domain':copy.deepcopy(domain)}
    return endpoint,copy.deepcopy(signals),binding
