"""Bounded UART receiver/FIFO facts; unknown evidence never becomes byte matching."""
from copy import deepcopy
import json
import hashlib
import re


def _equal(left,right):
    return json.dumps(left,sort_keys=True,allow_nan=False)==json.dumps(right,sort_keys=True,allow_nan=False)


class UartConsumptionTracker:
    def __init__(self, *, max_components=16, max_pending=256,
                 admission_registry=None, ownership=None, edge_index=None):
        from .source_provenance import AdmissionRegistry
        from .ownership import OwnershipMap
        from .runtime_edge_index import RuntimeEdgeIndex
        for n in (max_components, max_pending):
            if type(n) is not int or n < 1:
                raise ValueError('capacities must be positive')
        for value, cls in ((admission_registry, AdmissionRegistry),
                           (ownership, OwnershipMap), (edge_index, RuntimeEdgeIndex)):
            if value is not None and not isinstance(value, cls):
                raise ValueError('invalid authority')
        self.max_components = max_components
        self.max_pending = max_pending
        self.admission_registry = admission_registry
        self.ownership = ownership
        self.edge_index = edge_index
        self._states = {}
        self._barrier = False

    def _record(self, event, kind, **fields):
        return deepcopy(dict(kind=kind, schema_version=kind+'.v1',
                             component=event.get('component'),
                             reset_epoch=event.get('reset_epoch'),
                             local_tick=event.get('local_tick'),
                             observation_event_id=event.get('event_id'), **fields))

    def _fail(self, event, reason):
        state = self._states.get(event.get('component')) if type(event.get('component')) is str else None
        if state is not None:
            state['degraded'] = True
        else:
            self._barrier = True
            for affected in self._states.values():affected['degraded']=True
        return (self._record(event, 'uart_consumption_match',
                             status='incomplete', reason=reason),)

    def _state(self, e):
        c=e['component']
        if c not in self._states:
            if len(self._states)>=self.max_components:
                self._barrier=True
                self._states.pop(next(iter(self._states)))
                for s in self._states.values():s['degraded']=True
            self._states[c]=dict(epoch=e['reset_epoch'],tick=None,queue=[],generation=0,
                sequence=0,receiver=None,completed=None,stages=[None,None],frames={},
                pending={},irq_snapshots={},execution=None,command_sequence=None,access_ticks={},active_access_scope=None,closed_access_floor=-1,closed_access_hash=None,frame_sequence_highwater=0,degraded=self._barrier)
        return self._states[c]

    def consume(self,e):
        reports=self._consume(e)
        component=e.get('component') if isinstance(e,dict) else None
        if type(component) is str and component in self._states:
            self._reclaim(self._states[component])
        return reports

    def _consume(self,e):
        if not isinstance(e,dict):return self._fail({},'malformed_uart_event')
        try:e=json.loads(json.dumps(e,allow_nan=False))
        except (TypeError,ValueError,RecursionError):return self._fail({},'malformed_uart_event')
        if (type(e.get('component')) is not str or not e['component']
            or type(e.get('reset_epoch')) is not int or not 0<=e['reset_epoch']<(1<<64)
            or type(e.get('local_tick')) is not int or not 0<=e['local_tick']<(1<<64)
            or not (type(e.get('event_id')) is str and bool(e['event_id'].strip())
                    or type(e.get('event_id')) is int and e['event_id']>=0)
            or not e.get('command_scope')):
            return self._fail(e,'malformed_uart_scope')
        if 'source_epoch' in e and (type(e['source_epoch']) is not int or e['source_epoch']!=e['reset_epoch']):
            return self._fail(e,'uart_source_epoch_mismatch')
        if 'schema_version' in e and (type(e.get('kind')) is not str or e['schema_version']!=e['kind']+'.v1'):
            return self._fail(e,'unknown_uart_event_version')
        scope=e['command_scope']
        if (type(scope) is not dict or set(scope)!={'component','reset_epoch','command_sequence'}
            or scope['component']!=e['component'] or type(scope['reset_epoch']) is not int
            or scope['reset_epoch']!=e['reset_epoch'] or type(scope['command_sequence']) is not int
            or scope['command_sequence']<0):return self._fail(e,'malformed_uart_command_scope')
        fresh=e['component'] not in self._states
        s=self._state(e)
        if e.get('kind')=='uart_reset':
            if (e.get('physical_reset') is not True or (fresh and self._barrier)
                or (not fresh and e['reset_epoch']<=s['epoch'])):
                return self._fail(e,'unproven_uart_reset')
            s.update(epoch=e['reset_epoch'],tick=None,queue=[],receiver=None,
                     completed=None,stages=[None,None],frames={},pending={},
                     generation=s['generation']+1,irq_snapshots={},last_event=None,execution=None,command_sequence=None,access_ticks={},active_access_scope=None,closed_access_floor=-1,closed_access_hash=None,frame_sequence_highwater=0,degraded=False)
            return (self._record(e,'uart_fifo_reset',fifo_generation=s['generation']),)
        if e['reset_epoch']!=s['epoch']:return self._fail(e,'uart_epoch_mismatch')
        if e.get('kind')=='uart_rdata_access':
            event_hash=hashlib.sha256(json.dumps(e,sort_keys=True,allow_nan=False).encode()).hexdigest()
            if e['command_scope']['command_sequence']<=s['closed_access_floor']:
                if e['command_scope']['command_sequence']==s['closed_access_floor'] and event_hash==s['closed_access_hash']:return ()
                return self._fail(e,'uart_closed_access_receipt_reused')
            reports=self._access(e,s)
            if s['active_access_scope']==e['command_scope']:
                s['closed_access_floor']=max(s['closed_access_floor'],e['command_scope']['command_sequence'])
                s['access_ticks'].clear();s['active_access_scope']=None;s['closed_access_hash']=event_hash
            return reports
        if e.get('kind')=='uart_frame_validation':return self._validate_frame(e,s)
        if e.get('kind')!='uart_tick_observation':return ()
        receipt=e.get('receipt_id')
        if (type(receipt) is not dict or set(receipt)!={'execution','sequence'}
            or type(receipt['execution']) is not str or not receipt['execution']
            or type(receipt['sequence']) is not int or receipt['sequence']!=scope['command_sequence']):
            return self._fail(e,'uart_command_receipt_mismatch')
        if s['execution'] is not None and s['execution']!=receipt['execution']:
            return self._fail(e,'uart_process_receipt_scope_changed')
        if s['command_sequence'] is not None and receipt['sequence']<s['command_sequence']:
            return self._fail(e,'uart_command_receipt_regressed')
        s['execution']=receipt['execution'];s['command_sequence']=receipt['sequence']
        from myfuzz.local_harness.opentitan_uart_fifo_contract import UART_FIFO_PROBES, uart_fifo_observation_contract
        try:
            contract_ok=json.dumps(e.get('observation_contract'),sort_keys=True,allow_nan=False)==json.dumps(uart_fifo_observation_contract(),sort_keys=True,allow_nan=False)
        except (TypeError,ValueError):contract_ok=False
        if not contract_ok:
            return self._fail(e,'unauthenticated_uart_tick')
        a,b=e.get('pre'),e.get('post')
        if not isinstance(a,dict) or not isinstance(b,dict):return self._fail(e,'missing_uart_samples')
        if any(type(p.get('probe_uart_'+k)) is not int or not 0<=p['probe_uart_'+k]<(1<<width)
               for p in (a,b) for k,(width,_) in UART_FIFO_PROBES.items()):
            return self._fail(e,'malformed_uart_probe_width')
        a={k.removeprefix('probe_uart_'):v for k,v in a.items()}
        b={k.removeprefix('probe_uart_'):v for k,v in b.items()}
        fields=('fifo_wvalid','fifo_wready','fifo_rvalid','fifo_rdata_re','fifo_data',
                'fifo_head','fifo_depth','fifo_wptr','fifo_rptr','fifo_under_rst',
                'fifo_clear','fifo_incr_wptr','fifo_incr_rptr')
        if any(type(p.get(k)) is not int or p[k]<0 for p in (a,b) for k in fields):
            return self._fail(e,'malformed_uart_fifo_sample')
        if s['tick'] is not None and e['local_tick']!=s['tick']+1:
            return self._fail(e,'uart_tick_discontinuity')
        s['tick']=e['local_tick']
        if a['rx_data']!=a['fifo_data']:
            return self._fail(e,'uart_receiver_fifo_data_mismatch')
        push=bool(a['fifo_wvalid'] and a['fifo_wready'] and not a['fifo_under_rst'])
        pop=bool(a['fifo_rvalid'] and a['fifo_rdata_re'] and not a['fifo_under_rst'])
        clear=bool(a['fifo_clear'] or a['fifo_under_rst'])
        valid=(0<=a['fifo_depth']<=64 and 0<=b['fifo_depth']<=64
            and b['fifo_depth']==(0 if clear else a['fifo_depth']+push-pop)
            and a['fifo_rvalid']==int(a['fifo_depth']>0)
            and a['fifo_wready']==int(a['fifo_depth']<64 and not a['fifo_under_rst'])
            and a['fifo_incr_wptr']==int(push) and a['fifo_incr_rptr']==int(pop)
            and b['fifo_wptr']==(0 if clear else (a['fifo_wptr']+push)%64)
            and b['fifo_rptr']==(0 if clear else (a['fifo_rptr']+pop)%64)
            and len(s['queue'])==a['fifo_depth'])
        if s['queue'] and s['queue'][0]['value']!=a['fifo_head']:valid=False
        if not valid:return self._fail(e,'uart_fifo_transition_mismatch')
        out=self._receiver(e,s,a,b)
        out.extend(self._irq(e,s,a,b))
        popped_entry=None
        if pop:
            head=s['queue'].pop(0);popped_entry=deepcopy(head)
            pending=s['pending'].get(tuple(head['entry_id']))
            if pending is not None:pending['pop']=dict(event_id=e['event_id'],access=deepcopy(e.get('access')),
                local_tick=e['local_tick'],command_scope=deepcopy(e['command_scope']),pre=deepcopy(e['pre']),post=deepcopy(e['post']))
            out.append(self._record(e,'uart_fifo_pop',entry_id=head['entry_id'],
                value=a['fifo_head'],origin_status='unknown',access=e.get('access'),clear=clear))
        if push:
            token=s['completed'] if a['rx_valid'] and not a['frame_err'] and not a['parity_err'] else None
            if token is not None and (token.get('completion_tick')!=e['local_tick']-1 or token['value']!=a['fifo_data']):token=None
            s['sequence']+=1
            entry=dict(entry_id=[e['component'],s['epoch'],s['generation'],s['sequence']],
                       value=a['fifo_data'],origin_status='unknown',
                       frame_id=token['input_ref']['frame_id'] if token and token.get('input_ref') else None,receiver_id=token['receiver_id'] if token else None,
                       completion_event=token['completion_event'] if token else None)
            out.append(self._record(e,'uart_fifo_push',**entry,retained=not clear))
            if not clear:
                s['queue'].append(entry)
                if token is not None and token['candidate']:
                    pending=dict(entry=deepcopy(entry),token=deepcopy(token),push_event=e['event_id'],pop=None)
                    s['pending'][tuple(entry['entry_id'])]=pending
                    if len(s['pending'])>self.max_pending:
                        s['pending'].clear();s['degraded']=True
                    else:out.extend(self._promote(e,s,pending))
        if a['rx_valid']:s['completed']=None
        if clear:
            for pending in s['pending'].values():
                if pending.get('pop') is None:pending['clear_event']=e['event_id']
            s['queue']=[];s['generation']+=1
            out.append(self._record(e,'uart_fifo_clear',fifo_generation=s['generation']))
        if s['degraded']:out.extend(self._fail(e,'uart_generation_untrusted'))
        context=e.get('access')
        if isinstance(context,dict) and context.get('write') is False and context.get('raw_offset')==24:
            if e['command_scope']['command_sequence']<=s['closed_access_floor']:
                out.extend(self._fail(e,'uart_closed_access_receipt_reused'))
            elif s['active_access_scope'] not in (None,e['command_scope']):
                out.extend(self._fail(e,'uart_unclosed_access_scope_replaced'))
            else:
                s['active_access_scope']=deepcopy(e['command_scope'])
                cache_key=(e['command_scope']['command_sequence'],e['local_tick'])
                s['access_ticks'][cache_key]=deepcopy(e)
                s['access_ticks'][cache_key]['fifo_pop_entry']=popped_entry
                if len(s['access_ticks'])>self.max_pending:
                    s['access_ticks'].clear();out.extend(self._fail(e,'uart_access_snapshot_capacity_exceeded'))
        s['last_event']=deepcopy(e)
        return tuple(out)

    def _receiver(self,e,s,a,b):
        required=('idle','rx_in','rx_enable','bit_cnt','tick_baud','sreg','rx_valid',
                  'rx_data','frame_err','parity_err','nco','rxnf_enable',
                  'sys_loopback','line_loopback','parity_en','parity_odd')
        if any(type(p.get(k)) is not int for p in (a,b) for k in required):
            return list(self._fail(e,'missing_receiver_samples'))
        config=tuple(a[k] for k in ('rx_enable','nco','rxnf_enable','sys_loopback',
                                   'line_loopback','parity_en','parity_odd'))
        out=[]
        input_ref=s['stages'][1]
        supported=not any(a[k] for k in ('rxnf_enable','sys_loopback','line_loopback','parity_en'))
        if not supported or a['rx_in']!=a['rx_sync']:
            input_ref=None
        if input_ref is not None and input_ref['bit_value']!=a['rx_in']:
            input_ref=None
        drive=e.get('physical_rx_ref')
        if (not self._drive_ref(drive,e) or e.get('physical_rx_value')!=drive['bit_value']
            or drive.get('receipt_id',drive.get('receipt'))!=e.get('receipt_id')
            or a['sync_input']!=drive['bit_value'] or b['sync_input']!=drive['bit_value']):
            drive=None
        if drive is not None and drive['frame_id'] not in s['frames'] and drive['frame_id'].startswith('uart-frame:'):
            sequence=self._frame_sequence(drive['frame_id'],s['epoch'])
            if sequence is None or sequence<=s['frame_sequence_highwater']:
                out.extend(self._fail(e,'stale_or_invalid_uart_frame_identity'));drive=None
            else:s['frame_sequence_highwater']=sequence
        if drive is not None:
            frame=s['frames'].setdefault(drive['frame_id'],dict(refs=[],validated=False,validation_event=None))
            if len(s['frames'])>self.max_pending or len(frame['refs'])>=4096:
                s['degraded']=True;s['frames'].clear();drive=None
            elif frame['refs'] and drive['drive_tick']!=frame['refs'][-1]['drive_tick']+1:
                s['degraded']=True;drive=None
            else:frame['refs'].append(deepcopy(drive))
        first=s['stages'][0]
        s['stages']=[deepcopy(drive) if drive is not None and b['sync_intq']==drive['bit_value'] else None,
                     deepcopy(first) if first is not None and b['rx_sync']==a['sync_intq']==first['bit_value'] else None]
        if a['rx_enable'] and a['idle'] and not a['rx_in']:
            if b['idle']!=0 or b['bit_cnt']!=(11 if a['parity_en'] else 10) or b['sreg']!=0 or b['baud_div']!=8 or b['tick_baud']!=0:
                return list(self._fail(e,'receiver_start_transition_mismatch'))
            s['sequence']+=1
            s['receiver']=dict(receiver_id=[e['component'],s['epoch'],s['sequence']],
                config=config,samples=[],origin_status='unknown',start_event=e['event_id'],input_ref=deepcopy(input_ref),candidate=input_ref is not None and self._authority(e,input_ref) is not None,shift=0)
            out.append(self._record(e,'uart_rx_receiver_start',
                receiver_id=s['receiver']['receiver_id'],origin_status='unknown',config=list(config),input_ref=input_ref))
        elif s['receiver'] is not None:
            r=s['receiver']
            if config!=r['config'] or not a['rx_enable']:
                out.append(self._record(e,'uart_rx_receiver_terminal',receiver_id=r['receiver_id'],
                                        reason='configuration_changed'))
                s['receiver']=None
            elif not a['idle'] and a['tick_baud']:
                if a['bit_cnt']==(11 if a['parity_en'] else 10) and a['rx_in']:
                    if b['idle']!=1 or b['bit_cnt']!=0:
                        return list(self._fail(e,'receiver_abort_transition_mismatch'))
                    out.append(self._record(e,'uart_rx_receiver_terminal',
                        receiver_id=r['receiver_id'],reason='false_start'))
                    s['receiver']=None
                else:
                    expected=(a['rx_in']<<10)|(a['sreg']>>1)
                    if (a['sreg']!=r['shift'] or b['sreg']!=expected or b['bit_cnt']!=a['bit_cnt']-1
                        or a['bit_cnt']!=(11 if a['parity_en'] else 10)-len(r['samples'])):
                        return list(self._fail(e,'receiver_sample_transition_mismatch'))
                    ref=dict(event_id=e['event_id'],bit_cnt=a['bit_cnt'],value=a['rx_in'],input_ref=deepcopy(input_ref))
                    start=r['input_ref']
                    if (input_ref is None or start is None or input_ref['frame_id']!=start['frame_id']
                        or input_ref['action_id']!=start['action_id'] or input_ref['admission_id']!=start['admission_id']
                        or input_ref['bit_index']!=10-a['bit_cnt']):r['candidate']=False
                    r['shift']=expected
                    r['samples'].append(ref)
                    out.append(self._record(e,'uart_rx_bit_sample',receiver_id=r['receiver_id'],**ref))
                    if a['bit_cnt']==1:
                        if b['rx_valid']!=1 or b['rx_data']!=((expected>>(1 if b['parity_en'] else 2))&255):
                            return list(self._fail(e,'receiver_valid_missing'))
                        s['completed']=deepcopy(r)
                        s['completed']['completion_event']=e['event_id']
                        s['completed']['completion_tick']=e['local_tick']
                        s['completed']['value']=b['rx_data']
                        if b['frame_err'] or b['parity_err'] or len(r['samples'])!=10:s['completed']['candidate']=False
                        if tuple(b[k] for k in ('rx_enable','nco','rxnf_enable','sys_loopback','line_loopback','parity_en','parity_odd'))!=r['config']:s['completed']['candidate']=False
                        s['receiver']=None
                        out.append(self._record(e,'uart_rx_receiver_complete',
                            receiver_id=r['receiver_id'],sample_refs=r['samples'],
                            value=b['rx_data'],frame_error=b['frame_err'],
                            parity_error=b['parity_err'],origin_status='unknown'))
        return out

    @staticmethod
    def _drive_ref(ref,e):
        return (isinstance(ref,dict) and all(type(ref.get(k)) is str and bool(ref[k])
                for k in ('frame_id','action_id'))
                and 'admission_id' in ref and (ref['admission_id'] is None
                    or type(ref['admission_id']) is str and bool(ref['admission_id']))
                and type(ref.get('bit_index')) is int and 0<=ref['bit_index']<10
                and type(ref.get('bit_value')) is int and ref['bit_value'] in (0,1)
                and type(ref.get('drive_tick')) is int and ref['drive_tick']==e['local_tick']
                and isinstance(ref.get('receipt_id',ref.get('receipt')),dict)
                and type(ref.get('receipt_id',ref.get('receipt')).get('execution')) is str
                and bool(ref.get('receipt_id',ref.get('receipt'))['execution'])
                and type(ref.get('receipt_id',ref.get('receipt')).get('sequence')) is int
                and ref.get('receipt_id',ref.get('receipt'))['sequence']>=0)

    def _irq(self,e,s,a,b):
        out=[]
        for role in ('rx_watermark','rx_overflow','rx_frame_err','rx_parity_err',
                     'rx_break_err','rx_timeout'):
            enable=a['intr_enable_'+role]
            state=a['intr_state_'+role]
            test=a['intr_test_'+role]
            qe=a['intr_test_qe_'+role]
            event=a['event_'+role]
            expected=int(bool((event or a['watermark_test']) and enable)) if role=='rx_watermark' else int(bool(state and enable))
            if b['irq_'+role]!=expected:
                out.extend(self._fail(e,'uart_irq_flop_transition_mismatch'))
                continue
            fingerprint=(event,state,b['intr_state_'+role],enable,test,qe,a['irq_'+role],
                b['irq_'+role],a['watermark_threshold'],a['watermark_test'],
                a['hw_state_de_'+role],a['hw_state_d_'+role],a['intr_state_we'],a['intr_enable_we'],
                a['intr_test_we'],a['reg_wdata'],a['reg_be'],b['watermark_test'],
                tuple(tuple(x['entry_id']) for x in s['queue']))
            if s['irq_snapshots'].get(role)==fingerprint:continue
            s['irq_snapshots'][role]=fingerprint
            out.append(self._record(e,'uart_irq_update',irq_class=role,
                pre_event=event,pre_state=state,post_state=b['intr_state_'+role],
                pre_enable=enable,pre_test=test,pre_test_qe=qe,
                pre_hw_state_de=a['hw_state_de_'+role],pre_hw_state_d=a['hw_state_d_'+role],
                pre_intr_state_we=a['intr_state_we'],pre_intr_enable_we=a['intr_enable_we'],
                pre_intr_test_we=a['intr_test_we'],pre_reg_wdata=a['reg_wdata'],pre_reg_be=a['reg_be'],
                pre_watermark_test=a['watermark_test'],post_watermark_test=b['watermark_test'],
                watermark_level=a['watermark_level'],
                timeout_config=[a['timeout_enable'],a['timeout_limit'],a['timeout_count']] if role=='rx_timeout' else None,
                pre_output=a['irq_'+role],post_output=b['irq_'+role],
                watermark_threshold=a['watermark_threshold'] if role=='rx_watermark' else None,
                pre_depth=a['fifo_depth'],pre_entry_ids=[x['entry_id'] for x in s['queue']],
                origin_status='unknown',proof_scope='native_irq_cause_observation'))
        return out

    def _validate_frame(self,e,s):
        frame=s['frames'].get(e.get('frame_id')) if type(e.get('frame_id')) is str else None
        refs=e.get('source_drive_refs')
        anchor=(frame['refs'][0] if frame is not None and frame['refs'] else
                dict(action_id=e.get('action_id'),admission_id=e.get('admission_id')))
        unknown=(self.admission_registry is None or self.ownership is None
                 or type(anchor['action_id']) is not str or not anchor['action_id'].strip()
                 or self._authority(e,anchor) is None)
        if unknown:
            if frame is not None:frame.update(finalized_unknown=True,validation_event=e['event_id'])
            return (self._record(e,'uart_consumption_match',status='incomplete',
                reason='unproven_uart_source_authority',proof_scope='uart_pin_drive',frame_id=e.get('frame_id')),)
        if frame is not None and frame.get('finalized_unknown'):
            return (self._record(e,'uart_consumption_match',status='incomplete',
                reason='unproven_uart_source_authority',proof_scope='uart_pin_drive',frame_id=e['frame_id']),)
        if (frame is None or not frame['refs'] or e.get('waveform_matched') is not True
            or type(refs) is not list or not _equal(refs,frame['refs'])):
            return self._fail(e,'missing_exact_frame_drive_witness')
        slots=[r['bit_index'] for r in refs]
        counts=[slots.count(i) for i in range(10)]
        if (slots!=sorted(slots) or not counts[0] or len(set(counts))!=1
            or refs[0]['bit_value']!=0 or refs[-1]['bit_value']!=1
            or any(len({r['bit_value'] for r in refs if r['bit_index']==i})!=1 for i in range(10))):
            return self._fail(e,'incomplete_8n1_drive_witness')
        if any(r['frame_id']!=e['frame_id'] or r['action_id']!=e.get('action_id')
               or r['admission_id']!=e.get('admission_id') for r in refs):
            return self._fail(e,'frame_identity_mismatch')
        admission=self._authority(e,refs[0])
        if admission is None:
            frame.update(finalized_unknown=True,validation_event=e['event_id'])
            return (self._record(e,'uart_consumption_match',status='incomplete',
                reason='unproven_uart_source_authority',proof_scope='uart_pin_drive',frame_id=e['frame_id']),)
        byte=sum(next(r['bit_value'] for r in refs if r['bit_index']==i+1)<<i for i in range(8))
        if not any(hashlib.sha256(json.dumps(dict(action_id=admission.action_id,component=e['component'],
            port='uart_rx_byte',value=byte,bit_offset=0,width=width,kind='source_event'),
            sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()==admission.input_sha256
            for width in (8,None)):
            return self._fail(e,'uart_source_action_bytes_mismatch')
        frame.update(validated=True,validation_event=e['event_id'],admission=admission.document())
        out=[]
        for pending in s['pending'].values():out.extend(self._promote(e,s,pending))
        return tuple(out)

    def _authority(self,e,ref):
        if self.admission_registry is None or self.ownership is None:return None
        admission=self.admission_registry.get(ref['action_id'])
        if (admission is None or admission.admission_id!=ref['admission_id']
            or admission.component!=e['component'] or admission.input_kind!='source_event'):return None
        try:
            owner=self.ownership.mutation_source(e['component'],'uart_rx_byte',0,8,direction=admission.direction)
        except ValueError:return None
        selected=(admission.source_id if self.edge_index is None else
            self.edge_index.source_owner_ref(admission.source_id,admission.path_id,
                admission.direction,e['component'],'uart_rx_byte',0,8))
        return admission if selected is not None and owner==selected else None

    def _promote(self,e,s,pending):
        token=pending['token'];ref=token['input_ref']
        frame=s['frames'].get(ref['frame_id'])
        if s['degraded'] or frame is None or not frame['validated']:return []
        if ref not in frame['refs'] or any(sample['input_ref'] not in frame['refs'] for sample in token['samples']):return []
        common=dict(entry_id=pending['entry']['entry_id'],receiver_id=token['receiver_id'],
            frame_id=ref['frame_id'],source_admission=frame['admission'],sample_refs=token['samples'],
            graph_path_certified=self.edge_index is not None,
            path_id=frame['admission']['path_id'] if self.edge_index is not None else None,
            receiver_start_event=token['start_event'],completion_event=token['completion_event'],
            push_event=pending['push_event'],validation_event=frame['validation_event'],
            retained_at_push=True,live_at_proof_time=any(x['entry_id']==pending['entry']['entry_id'] for x in s['queue']),
            disposition='popped' if pending.get('pop') else 'cleared' if pending.get('clear_event') else 'retained',
            clear_event=pending.get('clear_event'))
        out=[]
        if not pending.get('retention_proven'):
            pending['retention_proven']=True
            out.append(self._record(e,'uart_consumption_match',status='accepted',
                       proof_scope='uart_fifo_retention',**common))
        if pending.get('read') and not pending.get('read_proven'):
            pending['read_proven']=True
            out.append(self._record(e,'uart_consumption_match',status='accepted',
                proof_scope='uart_fifo_read_consumption',
                **dict(common,graph_path_certified=self.edge_index is not None and pending['read']['route_context_mode']=='router',
                       path_id=common['path_id'] if pending['read']['route_context_mode']=='router' else None),**pending['read']))
        return out



    def _access(self,e,s):
        from .retirement_delivery import _key
        if e.get('source_transaction') is None:
            return (self._record(e,'uart_consumption_match',status='incomplete',
                                reason='unrouted_uart_access',proof_scope='uart_fifo_read_consumption'),)
        if any(type(e.get(k)) is not int for k in ('raw_offset','byte_enable','request_tick','response_tick','read_value','error')):
            return self._fail(e,'malformed_uart_rdata_access')
        key=_key(e.get('source_transaction'))
        if key is None or e.get('write') is not False or e.get('raw_offset')!=24 or e.get('byte_enable')!=15:
            return self._fail(e,'unproven_uart_routed_access')
        request,response=e.get('read_capture'),e.get('response_capture')
        if not isinstance(request,dict) or not isinstance(response,dict):
            return self._fail(e,'missing_uart_access_capture')
        pending=next((p for p in s['pending'].values() if p.get('pop')
            and p['pop']['local_tick']==e.get('request_tick')
            and _equal(p['pop']['event_id'],e.get('actual_request_event_id'))),None)
        response_ref=response.get('actual_receipt_ref')
        last=(s['access_ticks'].get((e['command_scope']['command_sequence'],e.get('response_tick')))
              if isinstance(response_ref,dict) and _equal(response_ref.get('command_scope'),e['command_scope']) else None)
        measured_request=s['access_ticks'].get((e['command_scope']['command_sequence'],e['request_tick']))
        if (measured_request is None or not _equal(measured_request['event_id'],e.get('actual_request_event_id'))
            or last is None or not _equal(last['event_id'],e.get('actual_response_event_id'))
            or last['local_tick']!=e.get('response_tick') or e['local_tick']<last['local_tick']
            or (e['command_scope']['command_sequence'],e['local_tick']) not in s['access_ticks']
            or e['command_scope']!=last['command_scope']):
            return self._fail(e,'missing_exact_uart_access_ticks')
        pop=measured_request;context=pop['access']
        if not _equal(pop['command_scope'],e['command_scope']):
            return self._fail(e,'uart_request_response_command_scope_mismatch')
        fields=('access_id','source_transaction','raw_offset','write','byte_enable',
                'address','window_base','window_size','route_context_mode','delivery_context')
        if (not isinstance(context,dict) or any(not _equal(context.get(k),e.get(k)) for k in fields)
            or not _equal(request.get('pre'),pop['pre']) or not _equal(request.get('post'),pop['post'])
            or not _equal(response.get('pre'),last['pre']) or not _equal(response.get('post'),last['post'])
            or not _equal(request.get('actual_receipt_ref'),dict(command_scope=pop['command_scope'],local_tick=pop['local_tick']))
            or not _equal(response.get('actual_receipt_ref'),dict(command_scope=last['command_scope'],local_tick=last['local_tick']))):
            return self._fail(e,'uart_access_receipt_mismatch')
        if any(not isinstance(tick.get('access'),dict)
               or any(not _equal(tick['access'].get(k),e.get(k)) for k in fields)
               for tick in s['access_ticks'].values()):
            return self._fail(e,'uart_active_access_context_mismatch')
        mode=e.get('route_context_mode');address=e.get('address');base=e.get('window_base');size=e.get('window_size')
        delivery=e.get('delivery_context')
        if (type(address) is not int or type(base) is not int or not 0<=base<=address<(1<<64)
            or base!=address-24 or base%0x1000 or not isinstance(delivery,dict)
            or mode not in ('router','direct')):
            return self._fail(e,'unproven_uart_router_window')
        if mode=='direct':
            if size is not None or delivery:return self._fail(e,'unproven_uart_router_window')
        else:
            if (type(size) is not int or size<28 or size%4 or base+size>(1<<64)
                or type(delivery.get('value')) is not int or not 0<=delivery['value']<(1<<32)
                or not _equal(delivery,dict(source_transaction=e['source_transaction'],device_id=e['component'],
                    address=address,offset=24,write=False,value=delivery.get('value'),be=15,
                    window_base=base,window_size=size))):
                return self._fail(e,'unproven_uart_router_window')
        a={k.removeprefix('probe_uart_'):v for k,v in pop['pre'].items()}
        b={k.removeprefix('probe_uart_'):v for k,v in pop['post'].items()}
        d={k.removeprefix('probe_uart_'):v for k,v in last['pre'].items()}
        value=a['fifo_head']
        if (a['a_accept']!=1 or a['tl_a_valid']!=1 or a['tl_a_ready']!=1
            or a['tl_a_opcode']!=4 or a['tl_a_address']!=24 or a['tl_a_mask']!=15
            or a['reg_addr']!=24 or a['reg_re']!=1 or a['reg_rdata_re']!=1
            or a['reg_error'] or a['access_internal_error']
            or a['fifo_head']!=value or a['reg_rdata']!=value
            or b['captured_rdata']!=value or b['captured_source']!=a['tl_a_source'] or b['captured_error']
            or d['d_accept']!=1 or d['tl_d_valid']!=1 or d['tl_d_ready']!=1
            or d['tl_d_opcode']!=1 or d['tl_d_source']!=a['tl_a_source']
            or d['tl_d_data']!=value or d['tl_d_error'] or e.get('error')!=0 or e.get('read_value')!=value):
            return self._fail(e,'uart_rdata_native_access_mismatch')
        entry=measured_request.get('fifo_pop_entry')
        if pending is None:
            return (self._record(e,'uart_consumption_match',status='incomplete',
                reason='uart_empty_read' if entry is None else 'uart_unknown_entry_origin',
                proof_scope='uart_fifo_read_consumption',entry_id=entry['entry_id'] if entry else None,
                access_id=e['access_id'],source_transaction=e['source_transaction'],
                request_event=e['actual_request_event_id'],response_event=e['actual_response_event_id']),)
        if entry is None or entry['entry_id']!=pending['entry']['entry_id'] or value!=entry['value']:
            return self._fail(e,'uart_read_entry_identity_mismatch')
        pending['read']=dict(pop_event=pop['event_id'],access_event=e['event_id'],
            access_id=e['access_id'],source_transaction=deepcopy(e['source_transaction']),
            request_event=e['actual_request_event_id'],response_event=e['actual_response_event_id'],
            request_tick=e['request_tick'],response_tick=e['response_tick'],read_value=value,
            route_context_mode=mode,address=address,window_base=base,window_size=size,
            delivery_context=deepcopy(delivery))
        return tuple(self._promote(e,s,pending))

    @staticmethod
    def _frame_sequence(frame_id,epoch):
        if type(frame_id) is not str:return None
        match=re.fullmatch(r'uart-frame:(0|[1-9][0-9]*):([1-9][0-9]*)',frame_id)
        if match is None:return None
        try:frame_epoch,sequence=map(int,match.groups())
        except ValueError:return None
        return sequence if frame_epoch==epoch and sequence<(1<<64) else None

    def _reclaim(self,s):
        """Release terminal resources using bounded active roots, never journal data."""
        live_entries={tuple(entry['entry_id']) for entry in s['queue']}
        for key,pending in list(s['pending'].items()):
            if key in live_entries:continue
            ref=pending['token'].get('input_ref')
            frame=s['frames'].get(ref['frame_id']) if isinstance(ref,dict) else None
            source_terminal=frame is not None and (frame['validated'] or frame.get('finalized_unknown'))
            read_complete=pending.get('pop') is not None and pending.get('read_proven') is True
            cleared_complete=('clear_event' in pending and pending.get('pop') is None and source_terminal)
            if read_complete or cleared_complete:del s['pending'][key]
        roots=set()
        def bit_ref(ref):
            if isinstance(ref,dict) and type(ref.get('frame_id')) is str:roots.add(ref['frame_id'])
        for ref in s['stages']:bit_ref(ref)
        for receiver in (s['receiver'],s['completed']):
            if receiver is not None:
                bit_ref(receiver.get('input_ref'))
                for sample in receiver['samples']:bit_ref(sample.get('input_ref'))
        for entry in s['queue']:
            if type(entry.get('frame_id')) is str:roots.add(entry['frame_id'])
        for pending in s['pending'].values():
            bit_ref(pending['token'].get('input_ref'))
            for sample in pending['token']['samples']:bit_ref(sample.get('input_ref'))
        for tick in s['access_ticks'].values():
            entry=tick.get('fifo_pop_entry')
            if isinstance(entry,dict) and type(entry.get('frame_id')) is str:roots.add(entry['frame_id'])
        for frame_id,frame in list(s['frames'].items()):
            if (frame_id not in roots and (frame['validated'] or frame.get('finalized_unknown'))
                and self._frame_sequence(frame_id,s['epoch']) is not None):
                del s['frames'][frame_id]
