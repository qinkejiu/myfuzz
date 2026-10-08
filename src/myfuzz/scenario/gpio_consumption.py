"""Bounded factual PULP GPIO register, synchronizer and native IRQ resources.

Only authenticated measured pre/post probes update resource metadata. Input
origin requires an exact applied-drive receipt; admission alone has no effect.
This module does not infer CPU operands, interrupt entry or pulse mappings.
"""
from copy import deepcopy
from .cpu_retirement import _uint
from .retirement_delivery import _key
from .source_provenance import AdmissionRegistry, SourceAdmission
from .ownership import OwnershipMap
from .runtime_edge_index import RuntimeEdgeIndex
from myfuzz.local_harness.pulp_gpio_probe_contract import (
    PULP_GPIO_PROBES, pulp_gpio_observation_contract)

_REGS = {'out':32, 'dir':32, 'gpioen':32, 'inten':32, 'inttype':64,
         'status':32, 'sync0':32, 'sync1':32, 'padin_latch':32}
_WRITE = {0:('dir','overwrite'), 4:('gpioen','overwrite'),
          12:('out','overwrite'),16:('out','set'),20:('out','clear'),
          24:('inten','overwrite'),28:('inttype','low'),32:('inttype','high')}
_READ = {0:'dir',4:'gpioen',8:'padin_latch',12:'out',24:'inten',
         28:'inttype',32:'inttype',36:'status'}


def _event_ref(value):
    return _uint(value,64) or type(value) is str and bool(value.strip())


def _ref(resource):
    return {n:deepcopy(resource.get(n)) for n in
        ('component','reset_epoch','register','bit','version','value','observation_event_id','local_tick','trigger_id','phase')}


def _value(p,name):
    return p['gpio_probe_'+name]


def _physical(p):
    return (isinstance(p,dict) and _uint(p.get('gpio_in'),32)
            and all(_uint(p.get('gpio_probe_'+n),width)
                    for n,(width,_) in PULP_GPIO_PROBES.items()))


def _derived(p):
    rise=_value(p,'sync1') & ~_value(p,'padin_latch') & 0xffffffff
    fall=~_value(p,'sync1') & _value(p,'padin_latch') & 0xffffffff
    selected=0
    for pin in range(32):
        mode=(_value(p,'inttype') >> (2*pin)) & 3
        edge=fall if mode==0 else rise if mode==1 else rise|fall if mode==2 else 0
        selected |= edge & (1 << pin)
    mask=selected & _value(p,'gpioen') & _value(p,'inten')
    enables=sum(bool(_value(p,'gpioen') & (15 << (4*g))) << g for g in range(8))
    word=(_value(p,'apb_addr')>>2)&31
    active=_value(p,'psel') & _value(p,'penable') & _value(p,'pwrite')
    masks={'write_out':0,'write_gpioen':0,'write_inten':0,'write_inttype':0}
    if active:
        if word in (3,4,5):masks['write_out']=0xffffffff
        elif word in (17,18,19):masks['write_out']=0xffffffff<<32
        if word==1:masks['write_gpioen']=0xffffffff
        elif word==15:masks['write_gpioen']=0xffffffff<<32
        if word==6:masks['write_inten']=0xffffffff
        elif word==20:masks['write_inten']=0xffffffff<<32
        if word in (7,8,21,22):masks['write_inttype']=0xffff << ({7:0,8:16,21:32,22:48}[word])
    return (_value(p,'decoded_word')==word and _value(p,'write')==active
            and all(_value(p,name)==value for name,value in masks.items())
            and _value(p,'rise')==rise and _value(p,'fall')==fall
            and _value(p,'irq_trigger_mask')==mask
            and _value(p,'native_irq')==int(bool(mask))
            and _value(p,'input_clock_enable')==enables)


def _edge(pre,post):
    enabled=sum(15 << (4*g) for g in range(8) if _value(pre,'input_clock_enable') & (1<<g))
    for name,source in (('sync0',pre['gpio_in']),('sync1',_value(pre,'sync0')),('padin_latch',_value(pre,'sync1'))):
        if _value(post,name)!=((_value(pre,name)&~enabled)|(source&enabled)):
            return False
    status=(_value(pre,'status')|_value(pre,'irq_trigger_mask') if _value(pre,'native_irq') else
        0 if _value(pre,'psel') and _value(pre,'penable') and not _value(pre,'pwrite')
            and _value(pre,'decoded_word')==9 else _value(pre,'status'))
    if _value(post,'status')!=status:return False
    selected=(_WRITE.get(_value(pre,'decoded_word')<<2) if _value(pre,'write') else None)
    for name in ('out','dir','gpioen','inten','inttype'):
        if selected is None or name!=selected[0]:
            if _value(pre,name)!=_value(post,name):return False
    if selected is not None:
        name,operation=selected;before=_value(pre,name);data=_value(pre,'pwdata')
        expected=(data if operation=='overwrite' else before|data if operation=='set'
            else before&~data if operation=='clear' else
            (before&~0xffffffff)|data if operation=='low' else (before&0xffffffff)|(data<<32))
        if _value(post,name)!=(expected&((1<<_REGS[name])-1)):return False
    return True


def is_authenticated_gpio_tick(event):
    """Pure shape/contract validation before admitting a receipt's input refs."""
    return (isinstance(event,dict) and event.get('kind')=='gpio_tick_observation'
        and type(event.get('component')) is str and bool(event['component'].strip())
        and _uint(event.get('reset_epoch'),64) and _uint(event.get('local_tick'),64)
        and ('source_epoch' not in event or type(event['source_epoch']) is int
             and event['source_epoch']==event['reset_epoch'])
        and ('event_id' not in event or _event_ref(event['event_id']))
        and event.get('observation_contract')==pulp_gpio_observation_contract()
        and _physical(event.get('pre')) and _physical(event.get('post'))
        and _derived(event['pre']) and _derived(event['post']) and _edge(event['pre'],event['post']))


class GpioConsumptionTracker:
    def __init__(self, *, max_components=16, max_completed_accesses=256,
                 admission_registry=None, ownership=None, edge_index=None):
        if any(type(n) is not int or n<1 for n in (max_components,max_completed_accesses)):
            raise ValueError('capacities must be positive')
        if admission_registry is not None and not isinstance(admission_registry,AdmissionRegistry):
            raise ValueError('admission_registry must be AdmissionRegistry')
        if ownership is not None and not isinstance(ownership,OwnershipMap):
            raise ValueError('ownership must be OwnershipMap')
        if edge_index is not None and type(edge_index) is not RuntimeEdgeIndex:
            raise ValueError('edge_index must be a compiled RuntimeEdgeIndex')
        self.edge_index=edge_index
        self.ownership=ownership
        self.max_components=max_components
        self.max_completed_accesses=max_completed_accesses
        self.admission_registry=admission_registry
        self._states={};self._accesses={};self._commits={};self._links={};self._applied={};self._output_cache={};self._output_views={};self._status_views={};self._capacity_loss=False
        self._global_barrier=False;self._scope_overflow=False

    def _record(self,event,kind,**fields):
        return deepcopy(dict(schema_version=kind+'.v1',kind=kind,
            component=event.get('component'),reset_epoch=event.get('reset_epoch'),
            local_tick=event.get('local_tick'),observation_event_id=event.get('event_id',event.get('observation_event_id')),
            proof_scope='gpio_native_resource_observation',**fields))

    def _fail(self,event,reason,status='incomplete'):
        component=event.get('component')
        if type(component) is str and component in self._states:self._states[component]['degraded']=True
        else:
            self._global_barrier=True
            for state in self._states.values():state['degraded']=True
        return (self._record(event,'gpio_consumption_match',status=status,reason=reason),)

    def _state(self,event):
        component=event['component'];epoch=event['reset_epoch']
        if component not in self._states:
            if len(self._states)>=self.max_components:
                self._states.pop(next(iter(self._states)))
                self._global_barrier=True;self._scope_overflow=True
                for s in self._states.values():s['degraded']=True
            self._states[component]=dict(epoch=epoch,version=0,registers={},
                inputs=[None]*32,stages={},last_tick=None,last_sample=None,
                last_access_tick=None,trigger_id=None,trigger_sequence=0,
                output_current=None,irq_high=None,degraded=self._global_barrier)
        return self._states[component]

    def _resource(self,event,state,register,bit,value,*,origin_status='unknown',
                  origin_refs=(),dependencies=(),transaction=None):
        state['version']+=1
        return dict(component=event['component'],reset_epoch=state['epoch'],
            register=register,bit=bit,version=state['version'],value=value,
            observation_event_id=event['event_id'],local_tick=event.get('local_tick'),
            origin_status=origin_status,origin_refs=deepcopy(list(origin_refs)),
            dependencies=[_ref(r) for r in dependencies],transaction=deepcopy(transaction))

    def _baseline(self,event,state,name,value):
        old=state['registers'].get(name)
        if old is not None and sum(r['value'] << i for i,r in enumerate(old))==value:
            return old
        refs=[self._resource(event,state,name,i,(value>>i)&1) for i in range(_REGS[name])]
        state['registers'][name]=refs
        return refs

    def _bounded(self,mapping,key,value,state):
        mapping[key]=value
        if len(mapping)>self.max_completed_accesses:
            mapping.pop(next(iter(mapping)));state['degraded']=True
            self._global_barrier=True;self._capacity_loss=True
            for affected in self._states.values():affected['degraded']=True

    def output_resources_at(self,component,reset_epoch,local_tick,phase='post'):
        if (type(component) is not str or not _uint(reset_epoch,64)
                or not _uint(local_tick,64) or phase not in ('pre','post')):
            return []
        return deepcopy(self._output_cache.get((component,reset_epoch,local_tick,phase),[]))

    def consume(self,event):
        self._capacity_loss=False
        reports=self._consume(event)
        if self._capacity_loss:
            reports+=self._fail(event if isinstance(event,dict) else {},'gpio_evidence_capacity_exceeded')
        return reports

    def _consume(self,event):
        if not isinstance(event,dict):return self._fail({},'malformed_gpio_event','rejected')
        event=deepcopy(event);kind=event.get('kind')
        if kind not in ('gpio_apb_access','gpio_tick_observation','gpio_input_applied',
                        'gpio_reset','gpio_access_terminal','cpu_retired_transaction_target_delivery'):
            return ()
        if kind=='cpu_retired_transaction_target_delivery':return self._link(event)
        if (type(event.get('component')) is not str or not event['component'].strip()
                or not _uint(event.get('reset_epoch'),64) or not _event_ref(event.get('event_id'))
                or 'source_epoch' in event and (type(event['source_epoch']) is not int or event['source_epoch']!=event['reset_epoch'])):
            return self._fail(event,'malformed_gpio_identity','rejected')
        if kind=='gpio_reset':return self._reset(event)
        if kind=='gpio_access_terminal':return self._fail(event,'uncertain_actual_target_access')
        state=self._state(event)
        if event['reset_epoch']!=state['epoch']:
            return self._fail(event,'epoch_without_advanced_reset','rejected')
        if not _uint(event.get('local_tick'),64):return self._fail(event,'missing_actual_tick','rejected')
        if kind=='gpio_input_applied':return self._input(event,state)
        if (event.get('observation_contract')!=pulp_gpio_observation_contract()
                or not _physical(event.get('pre')) or not _physical(event.get('post'))
                or not _derived(event['pre']) or not _derived(event['post'])
                or not _edge(event['pre'],event['post'])):
            return self._fail(event,'invalid_authenticated_probe_observation','rejected')
        if kind=='gpio_apb_access':return self._access(event,state)
        return self._sample(event,state)

    def _status_update(self,event,state,previous,pre,post,current_samples):
        mask=_value(pre,'irq_trigger_mask') if _value(pre,'native_irq') else 0
        clearing=(not mask and _value(pre,'psel') and _value(pre,'penable')
            and not _value(pre,'pwrite') and _value(pre,'decoded_word')==9)
        resources=list(previous)
        for pin,old in enumerate(previous):
            if mask & (1<<pin):
                sample=current_samples[pin]
                refs=deepcopy(sample['origin_refs'])
                if old['value']:
                    for ref in old['origin_refs']:
                        if ref not in refs:refs.append(deepcopy(ref))
                known=(not state['degraded'] and state['trigger_id'] is not None
                    and sample['origin_status']=='known'
                    and (not old['value'] or old['origin_status']=='known'))
                if len(refs)>self.max_completed_accesses:
                    refs=[];known=False;state['degraded']=True;self._capacity_loss=True
                trigger=dict(component=event['component'],reset_epoch=state['epoch'],
                    register='native_trigger',bit=pin,version=state['trigger_sequence'],value=1,
                    observation_event_id=event['event_id'],local_tick=event['local_tick'],
                    phase='pre',trigger_id=state['trigger_id'])
                resources[pin]=self._resource(event,state,'status',pin,1,
                    origin_status='known' if known else 'unknown',origin_refs=refs,
                    dependencies=[old,sample,trigger])
            elif clearing:
                resources[pin]=self._resource(event,state,'status',pin,0,dependencies=[old],
                    transaction=event.get('source_transaction'))
        state['registers']['status']=resources
        return resources

    def _access(self,event,state):
        key=_key(event.get('source_transaction'));pre=event['pre'];post=event['post']
        identity=(event['component'],state['epoch'],event.get('access_id'))
        scope=event.get('command_scope');raw=event.get('raw_offset')
        response=event.get('target_response')
        if (key is None or type(event.get('access_id')) is not str or not event['access_id']
                or not isinstance(scope,dict) or set(scope)!={'component','reset_epoch','command_sequence'}
                or scope['component']!=event['component'] or not _uint(scope['reset_epoch'],64) or scope['reset_epoch']!=state['epoch']
                or not _uint(scope['command_sequence'],64) or scope['command_sequence']==0
                or event.get('status')!='observed' or event.get('phase')!='pre'
                or not _uint(raw,12) or raw&3 or not _uint(event.get('decoded_offset'),7) or event.get('decoded_offset')!=((raw>>2)&31)<<2
                or _value(pre,'apb_addr')!=raw or _value(pre,'decoded_word')!=(raw>>2)&31
                or _value(pre,'psel')!=1 or _value(pre,'penable')!=1
                or _value(pre,'pready')!=1 or _value(pre,'pslverr')!=0
                or type(event.get('write')) is not bool or int(event['write'])!=_value(pre,'pwrite')
                or not isinstance(response,dict) or not _uint(response.get('rdata'),32)
                or not _uint(response.get('error'),1) or response['error']!=0):
            return self._fail(event,'invalid_actual_apb_access','rejected')
        old=self._accesses.get(identity)
        if old is not None:
            return () if old==event else self._fail(event,'conflicting_access_identity','ambiguous')
        if state['last_access_tick'] is not None and event['local_tick']<=state['last_access_tick']:
            return self._fail(event,'nonmonotonic_access_tick','ambiguous')
        state['last_access_tick']=event['local_tick']
        self._bounded(self._accesses,identity,event,state)
        offset=event['decoded_offset'];transaction=event['source_transaction']
        if event['write']:
            if not _uint(event.get('wdata'),32) or event['wdata']!=_value(pre,'pwdata'):
                return self._fail(event,'write_payload_conflict','rejected')
            if offset not in _WRITE:
                return (self._record(event,'gpio_register_commit',status='unknown',
                    reason='unsupported_or_upper_bank_offset',fullkey=transaction,
                    raw_offset=raw,decoded_offset=offset,bit_resources=[]),)
            name,operation=_WRITE[offset];before=_value(pre,name);after=_value(post,name)
            data=event['wdata']
            expected=(data if operation=='overwrite' else before|data if operation=='set'
                      else before & ~data if operation=='clear' else
                      (before & ~0xffffffff)|data if operation=='low' else
                      (before & 0xffffffff)|(data<<32))
            expected &= (1 << _REGS[name])-1
            if after!=expected:return self._fail(event,'register_post_state_conflict','rejected')
            previous=self._baseline(event,state,name,before);new=[]
            for bit,old_resource in enumerate(previous):
                touched=(operation=='overwrite' or operation in ('set','clear') and bool(data&(1<<bit))
                         or operation=='low' and bit<32 or operation=='high' and bit>=32)
                new.append(self._resource(event,state,name,bit,(after>>bit)&1,
                    dependencies=[old_resource] if operation in ('set','clear') else [],
                    transaction=transaction) if touched else old_resource)
            state['registers'][name]=new
            if name=='out':self._bounded(self._output_views,(event['component'],state['epoch'],event['local_tick']),(previous,new),state)
            record=self._record(event,'gpio_register_commit',status='observed',reason='actual_apb_register_write',
                fullkey=transaction,access_id=event['access_id'],register=name,operation=operation,
                raw_offset=raw,decoded_offset=offset,write_value=data,pre_value=before,post_value=after,
                changed_mask=before^after,bit_resources=new)
            self._bounded(self._commits,key,record,state)
            reports=[record]
            if key in self._links:reports.extend(self._join(record,self._links[key]))
            return tuple(reports)
        name=_READ.get(offset)
        if name is None:return (self._record(event,'gpio_register_read',status='unknown',reason='unmodeled_read_register',fullkey=transaction),)
        before=_value(pre,name);after=_value(post,name)
        returned=(before & 0xffffffff if offset!=32 else before>>32)
        if not _uint(event.get('read_rdata'),32) or event.get('read_rdata')!=returned or _value(pre,'prdata')!=returned or response['rdata']!=returned:
            return self._fail(event,'read_pre_value_conflict','rejected')
        refs=self._baseline(event,state,name,before)
        outcome='unchanged';post_refs=refs
        if name=='status':
            expected=before|_value(pre,'irq_trigger_mask') if _value(pre,'native_irq') else 0
            if after!=expected:return self._fail(event,'status_priority_conflict','rejected')
            outcome='new_event_priority' if _value(pre,'native_irq') else 'cleared'
            samples=self._baseline(event,state,'sync1',_value(pre,'sync1'))
            post_refs=self._status_update(event,state,refs,pre,post,samples)
            self._bounded(self._status_views,(event['component'],state['epoch'],event['local_tick']),(refs,post_refs),state)
        return (self._record(event,'gpio_register_read',status='observed',reason='actual_pre_edge_read',
            fullkey=transaction,access_id=event['access_id'],register=name,read_value=returned,
            pre_value=before,post_value=after,status_outcome=outcome,bit_resources=refs,post_bit_resources=post_refs),)

    def _sample(self,event,state):
        n=event['local_tick'];pre=event['pre'];post=event['post']
        if state['last_tick'] is not None:
            if n==state['last_tick']:
                return () if state['last_sample']==event else self._fail(event,'conflicting_tick_identity','ambiguous')
            if n!=state['last_tick']+1:return self._fail(event,'missing_or_nonmonotonic_tick','ambiguous')
            if any(_value(pre,name)!=_value(state['last_sample']['post'],name) for name in _REGS):
                return self._fail(event,'unobserved_register_transition','ambiguous')
        state['last_tick']=n;state['last_sample']=event
        status_expected=(_value(pre,'status')|_value(pre,'irq_trigger_mask') if _value(pre,'native_irq')
            else 0 if _value(pre,'psel') and _value(pre,'penable') and not _value(pre,'pwrite')
                and _value(pre,'decoded_word')==9 else _value(pre,'status'))
        if _value(post,'status')!=status_expected:
            return self._fail(event,'status_priority_conflict','rejected')
        enabled=sum(15<<(4*g) for g in range(8) if _value(pre,'input_clock_enable')&(1<<g))
        receipt_mismatch=False
        for pin,input_ref in enumerate(state['inputs']):
            if input_ref is None or 'actual_input_value' not in input_ref:continue
            if (input_ref['local_tick']==n
                    and input_ref['actual_receipt_event_id']==event['event_id']
                    and input_ref['actual_input_value']==pre['gpio_in']==post['gpio_in']):
                input_ref['receipt_verified']=True
            elif not input_ref.get('receipt_verified') and input_ref['local_tick']<=n:
                state['inputs'][pin]=self._resource(event,state,'input',pin,(pre['gpio_in']>>pin)&1)
                receipt_mismatch=True
        if receipt_mismatch:state['degraded']=True
        stages={name:self._baseline(event,state,name,_value(pre,name)) for name in ('sync0','sync1','padin_latch')}
        for name,source in (('sync0',pre['gpio_in']),('sync1',_value(pre,'sync0')),('padin_latch',_value(pre,'sync1'))):
            expected=(_value(pre,name)&~enabled)|(source&enabled)
            if _value(post,name)!=expected:
                return self._fail(event,'synchronizer_stage_conflict','rejected')
        new={name:list(refs) for name,refs in stages.items()}
        for pin in range(32):
            if not enabled&(1<<pin):continue
            input_ref=state['inputs'][pin]
            if (input_ref is None or input_ref['local_tick']>n
                    or input_ref['value']!=((pre['gpio_in']>>pin)&1)
                    or input_ref['local_tick']==n and input_ref.get('actual_input_value',pre['gpio_in'])!=pre['gpio_in']):
                input_ref=self._resource(event,state,'input',pin,(pre['gpio_in']>>pin)&1)
                state['inputs'][pin]=input_ref
            for name,source_ref in (('sync0',input_ref),('sync1',stages['sync0'][pin]),('padin_latch',stages['sync1'][pin])):
                new[name][pin]=self._resource(event,state,name,pin,(_value(post,name)>>pin)&1,
                    origin_status=source_ref['origin_status'] if not state['degraded'] else 'unknown',
                    origin_refs=source_ref['origin_refs'] if not state['degraded'] else (),dependencies=[source_ref])
        for name,refs in new.items():state['registers'][name]=refs
        status_view=self._status_views.get((event['component'],state['epoch'],n))
        previous_status=status_view[0] if status_view is not None else self._baseline(event,state,'status',_value(pre,'status'))
        view=self._output_views.get((event['component'],state['epoch'],n))
        prior=state['output_current']
        if view is not None:
            pre_output,post_output=view
        else:
            pre_value=_value(pre,'out');post_value=_value(post,'out')
            pre_output=(prior if prior is not None and sum(r['value']<<i for i,r in enumerate(prior))==pre_value
                else [self._resource(event,state,'out',i,(pre_value>>i)&1) for i in range(32)])
            post_output=(pre_output if pre_value==post_value else
                [self._resource(event,state,'out',i,(post_value>>i)&1,dependencies=[pre_output[i]]) for i in range(32)])
        state['output_current']=post_output
        for phase,refs in (('pre',pre_output),('post',post_output)):
            self._bounded(self._output_cache,(event['component'],state['epoch'],n,phase),refs,state)
        reports=[self._record(event,'gpio_input_sample',status='incomplete' if state['degraded'] else 'observed',enabled_mask=enabled,stages=new)]
        if receipt_mismatch:reports.append(self._record(event,'gpio_consumption_match',status='incomplete',reason='actual_input_receipt_not_verified'))
        for phase,p,resources in (('pre',pre,stages),('post',post,new)):
            mask=_value(p,'irq_trigger_mask');high=bool(mask)
            if high and state['irq_high'] is None:
                reports.append(self._record(event,'gpio_irq_observation',status='incomplete',phase=phase,
                    trigger_id=None,mask=mask,reason='unknown_previous_native_irq'))
            elif high and not state['irq_high']:
                state['trigger_sequence']+=1
                state['trigger_id']=f"{event['component']}:{state['epoch']}:trigger:{state['trigger_sequence']}"
                causes=[]
                for pin in range(32):
                    if mask&(1<<pin):
                        config={name:self._baseline(event,state,name,_value(p,name))[pin if name!='inttype' else 2*pin:pin+1 if name!='inttype' else 2*pin+2] for name in ('gpioen','inten','inttype')}
                        causes.append(dict(pin=pin,prior_sample=resources['padin_latch'][pin],
                            current_sample=resources['sync1'][pin],configuration=config))
                reports.append(self._record(event,'gpio_irq_trigger',status='observed',phase=phase,
                    trigger_id=state['trigger_id'],mask=mask,causes=causes,
                    origin_status='known' if not state['degraded'] and all(c['current_sample']['origin_status']=='known' for c in causes) else 'unknown',
                    status_pre=_value(pre,'status'),status_post=_value(post,'status')))
            elif high:
                reports.append(self._record(event,'gpio_irq_observation',status='observed',phase=phase,
                    trigger_id=state['trigger_id'],mask=mask,causes=[dict(pin=pin,prior_sample=resources['padin_latch'][pin],current_sample=resources['sync1'][pin]) for pin in range(32) if mask&(1<<pin)]))
            state['irq_high']=high
        status_resources=(status_view[1] if status_view is not None else
            self._status_update(event,state,previous_status,pre,post,stages['sync1']))
        state['registers']['status']=status_resources
        reports[0]['status_resources']=deepcopy(status_resources)
        return tuple(reports)

    def _input(self,event,state):
        width=event.get('width');lo=event.get('bit_lo');value=event.get('value');origin=event.get('origin')
        if (not _event_ref(event.get('actual_receipt_event_id'))
                or not _uint(event.get('actual_input_value'),32)
                or event.get('port')!='gpio_in' or type(width) is not int or width<1
                or type(lo) is not int or lo<0 or lo+width>32 or not _uint(value,width)
                or not isinstance(origin,dict)
                or ((event['actual_input_value']>>lo)&((1<<width)-1))!=value):
            return self._fail(event,'malformed_input_applied_receipt','rejected')
        receipt_key=(event['component'],state['epoch'],event['actual_receipt_event_id'],lo,width)
        previous=self._applied.get(receipt_key)
        if previous is not None:
            return () if previous==event else self._fail(event,'conflicting_input_receipt_identity','ambiguous')
        self._bounded(self._applied,receipt_key,event,state)
        known=False;refs=[]
        if origin.get('kind')=='source_admission' and self.admission_registry is not None:
            try:a=self.admission_registry.get(origin.get('action_id'))
            except ValueError:a=None
            owner=None
            if a is not None and self.ownership is not None:
                try:owner=self.ownership.mutation_source(event['component'],'gpio_in',lo,width,direction=a.direction)
                except ValueError:pass
            authority=(a.source_id if a is not None and self.edge_index is None else
                self.edge_index.source_owner_ref(a.source_id,a.path_id,a.direction,
                    event['component'],'gpio_in',lo,width)
                if a is not None else None)
            if a is not None and owner is not None and owner==authority and a.component==event['component'] and a.input_kind=='source_event':
                known=True;refs=[a.document()]
        elif origin.get('kind')=='binding':
            supplied=origin.get('producer_resource_refs');source=self._states.get(origin.get('source_component')) if type(origin.get('source_component')) is str else None
            source_lo=origin.get('source_bit_lo')
            if (source is not None and source['epoch']==origin.get('producer_reset_epoch') and origin.get('source_port')=='gpio_out'
                    and type(source_lo) is int and 0<=source_lo<=32-width
                    and _event_ref(origin.get('delivery_event_id'))
                    and isinstance(supplied,list) and len(supplied)==width):
                actual=self.output_resources_at(origin['source_component'],origin.get('producer_reset_epoch'),origin.get('producer_local_tick'),origin.get('producer_phase'))[source_lo:source_lo+width]
                owner=None
                if self.ownership is not None:
                    try:owner=self.ownership.binding_producer(event['component'],'gpio_in',lo,width)
                    except ValueError:pass
                if owner==origin['source_component']+'.gpio_out' and supplied==actual and len(actual)==width and value==sum(r['value']<<i for i,r in enumerate(actual)):
                    known=True;refs=[_ref(r) for r in actual]
        reports=[]
        for offset in range(width):
            pin=lo+offset;previous=state['inputs'][pin]
            if previous is not None and previous['local_tick']==event['local_tick']:
                reports.append(self._record(event,'gpio_consumption_match',status='incomplete',
                    reason='superseded_before_sample',superseded_resource=previous))
            state['inputs'][pin]=self._resource(event,state,'input',pin,(value>>offset)&1,
                origin_status='known' if known and not state['degraded'] else 'unknown',
                origin_refs=[refs[offset]] if known and origin.get('kind')=='binding' else refs)
            state['inputs'][pin]['actual_input_value']=event['actual_input_value']
            state['inputs'][pin]['actual_receipt_event_id']=event['actual_receipt_event_id']
            state['inputs'][pin]['receipt_verified']=False
        reports.append(self._record(event,'gpio_input_applied_resource',status='observed',
            bit_resources=state['inputs'][lo:lo+width],origin_status='known' if known and not state['degraded'] else 'unknown'))
        return tuple(reports)

    def _reset(self,event):
        old=self._states.get(event['component'])
        if old is not None and event['reset_epoch']<=old['epoch'] or old is None and self._scope_overflow:
            return self._fail(event,'reset_epoch_did_not_advance','rejected')
        reports=[]
        if old is not None:
            pending=[r for r in old['inputs'] if r is not None
                and (old['last_tick'] is None or r['local_tick']>old['last_tick'])]
            if pending:reports.append(self._record(event,'gpio_consumption_match',status='incomplete',
                reason='reset_cancelled_input_drive',bit_resources=pending))
        self._states.pop(event['component'],None)
        state=self._state(event);state['degraded']=False
        reports.append(self._record(event,'gpio_reset_resource',status='observed',reason='advanced_hardware_reset'))
        return tuple(reports)

    def _link(self,event):
        key=_key(event.get('fullkey'))
        if key is None:return self._fail(event,'malformed_retirement_delivery_identity','rejected')
        consumer=event.get('consumer_resource')
        if not isinstance(consumer,dict) or type(consumer.get('device_id')) is not str or consumer.get('device_id') not in self._states:
            return self._fail(event,'missing_target_resource_scope')
        state=self._states[consumer['device_id']]
        if key in self._links:
            return () if self._links[key]==event else self._fail({'component':consumer['device_id']},'conflicting_retirement_delivery','ambiguous')
        self._bounded(self._links,key,event,state)
        return self._join(self._commits[key],event) if key in self._commits else ()

    def finalize(self):
        reports=[]
        for component,state in self._states.items():
            pending=[r for r in state['inputs'] if r is not None
                and (state['last_tick'] is None or r['local_tick']>state['last_tick'])]
            if pending:
                reports.append(self._record(dict(component=component,reset_epoch=state['epoch']),
                    'gpio_consumption_match',status='incomplete',reason='input_drive_not_sampled',bit_resources=pending))
                state['degraded']=True
                for i,r in enumerate(state['inputs']):
                    if r in pending:state['inputs'][i]=None
        for key,link in self._links.items():
            if key not in self._commits:
                reports.append(self._record(link,'gpio_consumption_match',status='incomplete',
                    reason='missing_actual_register_commit',fullkey=link['fullkey']))
        if reports:
            self._global_barrier=True
            for state in self._states.values():state['degraded']=True
        self._links.clear()
        return tuple(reports)

    def _join(self,commit,link):
        consumer=link['consumer_resource'];access=consumer.get('target_apb_access')
        matched=(consumer.get('target_access_id')==commit['access_id']
            and consumer.get('device_id')==commit['component'] and link.get('status')=='linked_raw'
            and link.get('proof_scope')=='retired_instruction_transaction_delivery'
            and _event_ref(link.get('event_id')) and consumer.get('write') is True
            and consumer.get('write_value')==commit['write_value']
            and consumer.get('offset')==commit['raw_offset']
            and isinstance(access,dict) and access.get('access_id')==commit['access_id']
            and access.get('source_transaction')==commit['fullkey']
            and access.get('reset_epoch')==commit['reset_epoch'])
        known=False
        try:
            docs=link.get('registered_origins',[])
            admissions=[SourceAdmission.from_document(d) for d in docs]
            refs=link.get('source_refs',[])
            known=(matched and not self._states.get(commit['component'],{}).get('degraded',True)
                and self._states.get(commit['component'],{}).get('epoch')==commit['reset_epoch']
                and link.get('known_fuzz_origin') is True
                and self.admission_registry is not None and bool(refs)
                and set(refs)=={a.action_id for a in admissions}
                and all(self.admission_registry.get(a.action_id)==a
                    and a.input_kind=='instruction' and a.role=='fuzz_source'
                    and a.component==commit['fullkey']['source_component'] for a in admissions))
        except (ValueError,TypeError,AttributeError):pass
        return (self._record(commit,'gpio_consumption_match',
            status='accepted' if known else 'unknown' if matched else 'rejected',
            reason='exact_retired_register_commit' if matched else 'retired_commit_identity_conflict',
            proof_resource=commit['bit_resources'],fullkey=commit['fullkey'],
            retirement_delivery_event_id=link.get('event_id'),registered_origins=link.get('registered_origins',[])),)
