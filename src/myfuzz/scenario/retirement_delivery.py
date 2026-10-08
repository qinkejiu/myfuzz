"""Bounded exact-key retirement to measured target delivery associations.

This establishes transaction delivery only, never operand, FIFO or IRQ origin.
Capacity loss and conflicting evidence persist as certainty barriers until a
strictly advanced physical CPU reset; finalize cannot restore certainty.
"""
from copy import deepcopy
from .cpu_retirement import _KEY, _IDENTITY, _uint, _valid_frozen_instruction, _valid_transaction, _address_triplet
from .source_provenance import AdmissionRegistry, SourceAdmission
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract, PULP_GPIO_PROBES


def _key(value):
    if not isinstance(value, dict) or set(value) != set(_KEY):
        return None
    if any(type(value[n]) is not str or not value[n].strip() for n in _KEY if n not in ('source_epoch', 'source_sequence')):
        return None
    if value['channel_id'] != 'data' or not _uint(value['source_epoch'], 64) or not _uint(value['source_sequence'], 64) or value['source_sequence']==0:
        return None
    return tuple(value[n] for n in _KEY)


def _scope(value):
    if not isinstance(value, dict) or set(value)!=set(_IDENTITY):
        return None
    if any(type(value[n]) is not str or not value[n].strip() for n in _IDENTITY[:2]) or not _uint(value['source_epoch'],64):
        return None
    return tuple(value[n] for n in _IDENTITY)


def _ks(k):
    return k[0], k[2], k[3]


def _sequence(value):
    if isinstance(value,(list,tuple)):
        return tuple(_sequence(item) for item in value)
    return value


def _frozen_match(m):
    responses, cells = m.get('instruction_responses'), m.get('byte_cells')
    if not isinstance(responses,list) or not isinstance(cells,list) or not responses or len(responses)!=len(cells):
        return False
    for response, cell in zip(responses,cells):
        if (not isinstance(response,dict) or not isinstance(cell,dict)
                or not _valid_transaction(response,'instr')
                or response.get('error')!=0 or response.get('address')!=m.get('pc')
                or response.get('rdata')!=m.get('insn')
                or response.get('event_id') is None
                or not _valid_frozen_instruction(response)
                or any(response['transaction'].get(n)!=m['cpu_scope'].get(n) for n in _IDENTITY)
                or any(_sequence(cell.get(n))!=_sequence(response['snapshot'].get(n)) for n in ('writer_event_ids','writer_kinds','versions'))):
            return False
    return True


def _target_witness(d):
    req, rsp, access = (d.get(name) for name in
                        ('target_request', 'target_response', 'target_apb_access'))
    if not all(isinstance(item, dict) for item in (req, rsp, access)):
        return False
    if d['write'] and d['byte_enable']!=15:
        return False
    contract = pulp_gpio_observation_contract()
    for item, schema in ((req, 'gpio_target_transport.v1'),
                         (rsp, 'gpio_target_transport.v1'),
                         (access, 'gpio_target_observation.v1')):
        if (item.get('schema_version') != schema
                or item.get('status') != 'observed' or item.get('phase') != 'pre'
                or item.get('source_transaction') != d['source_transaction']
                or item.get('access_id') != d.get('target_access_id')
                or item.get('raw_offset') != d['offset']
                or item.get('decoded_offset') != ((d['offset'] >> 2) & 31) << 2
                or type(item.get('write')) is not bool or item['write'] != d['write']
                or item.get('wdata') != (d['write_value'] if d['write'] else None)
                or item.get('observation_contract') != contract
                or not isinstance(item.get('command_scope'), dict)
                or not _uint(item.get('local_tick'), 64)):
            return False
    scope = req['command_scope']
    if (scope != rsp['command_scope'] or scope != access['command_scope']
            or set(scope) != {'component', 'reset_epoch', 'command_sequence'}
            or scope['component'] != d['device_id']
            or not _uint(scope['reset_epoch'], 64)
            or not _uint(scope['command_sequence'], 64) or scope['command_sequence'] == 0
            or not req['local_tick'] < access['local_tick'] < rsp['local_tick']
            or type(d.get('target_access_id')) is not str or not d['target_access_id'].strip()
            or access.get('kind') != 'gpio_apb_access'):
        return False
    r, t, apb = req.get('backend'), rsp.get('backend'), access.get('pre')
    if not all(isinstance(item, dict) for item in (r, t, apb, access.get('post'), access.get('target_response'))):
        return False
    if any(not _uint(access[phase].get('gpio_probe_'+name),width)
           for phase in ('pre','post') for name,(width,_) in PULP_GPIO_PROBES.items()):
        return False
    request_fields = {'gpio_req_valid': (1,1), 'gpio_req_ready': (1,1),
        'gpio_req_addr': (32,d['offset']), 'gpio_req_write': (1,int(d['write'])),
        'gpio_req_be': (4,d['byte_enable']), 'gpio_req_wdata': (32,d['write_value'] if d['write'] else 0)}
    apb_fields = {'gpio_probe_psel': (1,1), 'gpio_probe_penable': (1,1),
        'gpio_probe_apb_addr': (32,d['offset']), 'gpio_probe_pwrite': (1,int(d['write'])),
        'gpio_probe_pready': (1,1), 'gpio_probe_pslverr': (1,0),
        'gpio_probe_decoded_word': (5,(d['offset'] >> 2) & 31)}
    if d['write']:
        apb_fields['gpio_probe_pwdata'] = (32,d['write_value'])
    else:
        apb_fields['gpio_probe_prdata'] = (32,d['read_value'])
    if any(not _uint(r.get(n),width) or r[n]!=value for n,(width,value) in request_fields.items()):
        return False
    if any(not _uint(apb.get(n),width) or apb[n]!=value for n,(width,value) in apb_fields.items()):
        return False
    receipt=access['target_response']
    return (all(_uint(t.get(n),1) and t[n]==value for n,value in
                (('gpio_rsp_valid',1),('gpio_rsp_ready',1),('gpio_rsp_error',0)))
            and _uint(t.get('gpio_rsp_rdata'),32)
            and _uint(receipt.get('error'),1) and receipt['error']==0
            and _uint(receipt.get('rdata'),32) and receipt['rdata']==t['gpio_rsp_rdata']
            and (d['write'] or t['gpio_rsp_rdata']==d['read_value']))


def _producer_target(m, d, k):
    """Missing legacy producer evidence remains incomplete; conflicts reject."""
    beats=m.get('data_beats')
    if beats is None:
        return 'missing_retired_producer_beats'
    if not isinstance(beats,list) or len(beats)!=len(m['transaction_keys']):
        return 'malformed_retired_producer_beats'
    if any(not isinstance(beat,dict) or _key(beat.get('transaction')) != _key(raw)
           for beat,raw in zip(beats,m['transaction_keys'])):
        return 'malformed_retired_producer_beats'
    beat=beats[m['transaction_keys'].index(dict(zip(_KEY,k)))]
    response=beat.get('response')
    if (not _address_triplet(beat) or not _uint(beat.get('write'),1)
            or not _uint(beat.get('be'),4) or not _uint(beat.get('wdata'),32)
            or beat.get('event_id') is None or not isinstance(response,dict)
            or _key(response.get('transaction'))!=k or response.get('event_id') is None
            or not _uint(response.get('rdata'),32) or not _uint(response.get('error'),1)
            or response['error']!=0):
        return 'malformed_retired_producer_beats'
    if (d['address'] != beat['aligned_address'] or d['byte_enable'] != beat['be']
            or int(d['write']) != beat['write']):
        return 'producer_target_payload_conflict'
    producer=beat['wdata'] if d['write'] else response['rdata']
    target=d['write_value'] if d['write'] else d['read_value']
    if any((producer >> (8*lane)) & 255 != (target >> (8*lane)) & 255
           for lane in range(4) if beat['be'] & (1 << lane)):
        return 'producer_target_payload_conflict'
    return None


class RetirementRouterLinker:
    def __init__(self, *, max_pending_transactions=256, max_completed_keys=256, admission_registry=None):
        for n in (max_pending_transactions,max_completed_keys):
            if type(n) is not int or n<1:
                raise ValueError('capacities must be positive')
        if admission_registry is not None and not isinstance(admission_registry,AdmissionRegistry):
            raise ValueError('admission_registry must be an AdmissionRegistry')
        self.admission_registry=admission_registry
        self.max_pending_transactions=max_pending_transactions
        self.max_completed_keys=max_completed_keys
        self.retire_by_key={}; self.delivery_by_key={}; self._completed={}; self._linked=set()
        self._uncertain=False; self._restored={}; self._epochs={};self._observed_epochs={};self._epoch_overflow=False

    @property
    def pending_transaction_count(self):
        return len(self.retire_by_key)+len(self.delivery_by_key)

    def _barrier(self):
        self._uncertain=True;self._restored.clear()

    def _report(self,k,status,reason,m=None,d=None,all_beats=False):
        m=m or {};d=d or {}
        provenance=m.get('provenance',{})
        if not isinstance(provenance,dict):provenance={}
        cpu_scope=m.get('cpu_scope',{})
        if not isinstance(cpu_scope,dict):cpu_scope={}
        return deepcopy(dict(schema_version='cpu_retired_transaction_target_delivery.v1',
            kind='cpu_retired_transaction_target_delivery', status=status,reason=reason,
            cpu_scope=m.get('cpu_scope'), component=cpu_scope.get('source_component'),
            proof_scope='retired_instruction_transaction_delivery',
            fullkey=dict(zip(_KEY,k)) if k else None,
            retirement_event_id=m.get('event_id'), raw_rvfi_event_id=m.get('producer_event_id'),
            delivery_event_id=d.get('event_id'), raw_delivery_event_id=d.get('producer_event_id'),
            instruction_all_beats_linked=all_beats,
            producer_resource={n:m.get(n) for n in ('cpu_scope','order','pc','insn','byte_cells','instruction_responses','data_beats')},
            consumer_resource={n:d.get(n) for n in ('device_id','address','offset','beat_bytes','byte_enable','write','write_value','read_value','target_access_id','target_request','target_response','target_apb_access','delivery_order','target_delivery_order')},
            registered_origin=provenance, source_refs=m.get('source_refs',[]),
            registered_origin_status=provenance.get('origin_status','unknown'),
            registered_origins=m.get('registered_origins',[]),
            known_fuzz_origin=(status=='linked_raw' and m.get('_known_fuzz_origin',False))))


    def _remember(self,k,m,d):
        self._completed[k]=(m,d)
        if len(self._completed)>self.max_completed_keys:
            old=next(iter(self._completed));self._completed.pop(old);self._linked.discard(old);self._barrier()

    def _consume(self,event,is_match):
        event=deepcopy(event)
        if not isinstance(event,dict):
            self._barrier();return (self._report(None,'rejected','malformed_event'),)
        keys=event.get('transaction_keys') if is_match else [event.get('source_transaction')]
        if not isinstance(keys,list) or len(keys)>2 or any(_key(k) is None for k in keys) or len({_key(k) for k in keys})!=len(keys):
            self._barrier();return (self._report(None,'rejected','malformed_transaction_identity'),)
        if not keys:return ()
        if is_match:
            scope=_scope(event.get('cpu_scope'))
            valid=(scope is not None and all(_ks(_key(k))==scope for k in keys)
                   and _uint(event.get('order'),64) and _uint(event.get('pc'),32)
                   and _uint(event.get('insn'),32) and event.get('event_id') is not None
                   and event.get('producer_event_id') is not None
                   and isinstance(event.get('instruction_responses'),list)
                   and len(event['instruction_responses'])<=self.max_pending_transactions
                   and isinstance(event.get('provenance',{}),dict)
                   and isinstance(event.get('source_refs',[]),list)
                   and _frozen_match(event))
        else:
            valid=(event.get('event_id') is not None and type(event.get('device_id')) is str
                   and bool(event['device_id']) and _uint(event.get('address'),32)
                   and _uint(event.get('offset'),32) and event.get('beat_bytes')==4
                   and _uint(event.get('byte_enable'),4) and type(event.get('write')) is bool
                   and _uint(event.get('write_value') if event.get('write') else event.get('read_value'),32))
        if not valid:self._barrier()
        reports=[]
        own=self.retire_by_key if is_match else self.delivery_by_key
        for raw in keys:
            k=_key(raw);scope=_ks(k)
            if scope[2]<self._epochs.get(scope[:2],0):
                reports.append(self._report(k,'rejected','event_precedes_reset_epoch',event if is_match else None,event if not is_match else None));continue
            if scope[:2] not in self._observed_epochs:
                if len(self._observed_epochs)>=self.max_completed_keys:
                    self._observed_epochs.pop(next(iter(self._observed_epochs)))
                    self._epoch_overflow=True;self._barrier()
                self._observed_epochs[scope[:2]]=scope[2]
            else:
                self._observed_epochs[scope[:2]]=max(scope[2],self._observed_epochs[scope[:2]])
            old=self._completed.get(k)
            previous=(old[0 if is_match else 1] if old else own.get(k))
            if old is not None and previous is None:
                self._barrier()
                reports.append(self._report(k,'incomplete','terminal_key_missing_counterpart',event if is_match else None,event if not is_match else None))
                continue
            if previous is not None:
                if previous==event:continue
                self._barrier();reports.append(self._report(k,'ambiguous','conflicting_duplicate_payload',event if is_match else None,event if not is_match else None));continue
            if not valid or is_match and event.get('status')!='accepted':
                self._barrier();reports.append(self._report(k,'ambiguous' if valid else 'rejected','nonaccepted_retirement' if valid else 'malformed_evidence',event if is_match else None,event if not is_match else None));continue
            own[k]=event
            m=self.retire_by_key.get(k);d=self.delivery_by_key.get(k)
            if m is not None and d is not None:
                self.retire_by_key.pop(k);self.delivery_by_key.pop(k)
                if self._uncertain and scope not in self._restored:
                    status,reason='ambiguous','incomplete_evidence_stream'
                elif _producer_target(m,d,k) is not None:
                    reason=_producer_target(m,d,k)
                    status='incomplete' if reason=='missing_retired_producer_beats' else 'rejected'
                    self._barrier()
                elif not _target_witness(d):
                    status,reason='incomplete','missing_actual_target_witness'
                else:status,reason='linked_raw','matched_fullkey_actual_delivery'
                self._remember(k,m,d)
                if status=='linked_raw':self._linked.add(k)
                all_beats=all(_key(x) in self._linked and _key(x) in self._completed and self._completed[_key(x)][0]==m and self._completed[_key(x)][1] is not None for x in m['transaction_keys'])
                reports.append(self._report(k,status,reason,m,d,all_beats and status=='linked_raw'))
            while self.pending_transaction_count>self.max_pending_transactions:
                victim=next(iter(self.delivery_by_key or self.retire_by_key))
                vm=self.retire_by_key.pop(victim,None);vd=self.delivery_by_key.pop(victim,None)
                self._barrier();self._remember(victim,vm,vd)
                reports.append(self._report(victim,'incomplete','pending_capacity_exceeded',vm,vd))
        return tuple(reports)

    def consume_match(self,match, *, registered_origins=()):
        if not isinstance(match,dict):return self._consume(match,True)
        match=deepcopy(match)
        match.pop('registered_origins',None)
        match['_known_fuzz_origin']=False
        docs=[]
        try:
            admissions=[SourceAdmission.from_document(doc) for doc in registered_origins]
            refs=match.get('source_refs',[])
            cells=match.get('byte_cells',[])
            typed=(bool(cells) and all(len(cell.get('writer_kinds',[]))==4
                and len(cell.get('writer_event_ids',[]))==4
                and all(kind=='INSTRUCTION_SOURCE' for kind in cell['writer_kinds']) for cell in cells))
            writers={ref for cell in cells for ref in cell.get('writer_event_ids',[])}
            verified=(typed and bool(refs) and set(refs)==writers
                and self.admission_registry is not None
                and {a.action_id for a in admissions}==writers
                and all(self.admission_registry.get(a.action_id)==a for a in admissions)
                and all(a.input_kind=='instruction' and a.component==match.get('cpu_scope',{}).get('source_component') for a in admissions)
                and match.get('provenance',{}).get('origin_status')=='known'
                and set(match.get('provenance',{}).get('origin_admission_ids',[]))=={a.admission_id for a in admissions})
            if verified:
                docs=[a.document() for a in admissions]
                match['_known_fuzz_origin']=all(a.role=='fuzz_source' for a in admissions)
        except (ValueError,TypeError,KeyError,AttributeError):
            pass
        match['registered_origins']=docs
        return self._consume(match,True)

    def consume_cancel(self,transaction):
        k=_key(transaction)
        self._barrier()
        if k is None:return (self._report(None,'rejected','malformed_cancel_identity'),)
        m=self.retire_by_key.pop(k,None);d=self.delivery_by_key.pop(k,None)
        self._linked.discard(k);self._remember(k,m,d)
        return (self._report(k,'incomplete','cancelled_transaction',m,d),)
    def consume_delivery(self,delivery):return self._consume(delivery,False)

    def consume_reset(self,cpu_scope):
        scope=_scope(cpu_scope)
        observed=[_ks(k)[2] for mapping in (self.retire_by_key,self.delivery_by_key,self._completed) for k in mapping if _ks(k)[:2]==(scope[:2] if scope else None)]
        if (scope is None
                or self._epoch_overflow and scope[:2] not in self._observed_epochs
                or scope[2]<=max(observed+[self._epochs.get(scope[:2],-1),self._observed_epochs.get(scope[:2],-1)])):

            self._barrier();return (self._report(None,'rejected','reset_epoch_did_not_advance'),)
        reports=[]
        for mapping in (self.retire_by_key,self.delivery_by_key):
            for k in list(mapping):
                if _ks(k)[:2]==scope[:2]:
                    e=mapping.pop(k);reports.append(self._report(k,'incomplete','reset_cancelled_pending',e if mapping is self.retire_by_key else None,e if mapping is self.delivery_by_key else None))
        if len(self._epochs)>=self.max_completed_keys and scope[:2] not in self._epochs:
            self._epochs.pop(next(iter(self._epochs)));self._barrier()
        self._epochs[scope[:2]]=scope[2]
        if len(self._restored)>=self.max_completed_keys:self._restored.pop(next(iter(self._restored)))
        self._restored[scope]=True
        return tuple(reports)

    def finalize(self):
        reports=[]
        for mapping in (self.retire_by_key,self.delivery_by_key):
            for k,e in list(mapping.items()):
                m=e if mapping is self.retire_by_key else None;d=e if mapping is self.delivery_by_key else None
                reports.append(self._report(k,'incomplete','missing_counterpart',m,d));self._remember(k,m,d)
            mapping.clear()
        if reports:self._barrier()
        return tuple(reports)
