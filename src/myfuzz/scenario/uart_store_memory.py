"""Raw UART SW operand -> actual installed modeled host memory lane0 version.

Only an actual live MemoryCommitAuthority token authorizes a commit. Saved
accepted labels, matching bytes and nearby events cannot authorize this scope.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
from .cpu_retirement import CpuRetirementMatcher
from .ledger import TransactionLedger,TransactionKey
from .memory_commit_authority import MemoryCommitAuthority
from .uart_operand_use import UartOperandUseTracker
from .uart_operand_seed import _uint,_wire

_KEY=('execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence')


def _key(doc):
    if type(doc) is not dict or set(doc)!=set(_KEY):return None
    if any(type(doc[n]) is not str or not doc[n] for n in _KEY[:3]+('channel_id',)):return None
    if not _uint(doc['source_epoch']) or not _uint(doc['source_sequence']) or doc['source_sequence']==0:return None
    return tuple(doc[n] for n in _KEY)


class UartStoreMemoryJoin:
    def __init__(self, *, memory_commit_authority=None,admission_registry=None,ownership=None,edge_index=None,
                 max_pending_commits=256,max_components=16,max_instruction_witnesses=2048,max_event_refs=4096):
        if memory_commit_authority is not None and type(memory_commit_authority) is not MemoryCommitAuthority:
            raise ValueError('actual installed memory commit authority required')
        if any(type(n) is not int or n<1 for n in (max_pending_commits,max_components,max_event_refs)):
            raise ValueError('invalid store memory join capacity')
        self._authority=memory_commit_authority
        self._uses=UartOperandUseTracker(admission_registry=admission_registry,ownership=ownership,
            edge_index=edge_index,max_components=max_components,max_instruction_witnesses=max_instruction_witnesses)
        self._retire=CpuRetirementMatcher(max_pending=max_instruction_witnesses)
        self.max_pending=max_pending_commits;self.max_components=max_components;self.max_event_refs=max_event_refs
        self._slots=OrderedDict();self._by_retirement={};self._closed_floors={};self._epochs={}
        self._seen=OrderedDict();self._event_floor=-1;self._bad=False
        self._global_bad=False;self._bad_scopes=set()

    @property
    def pending_count(self):return len(self._slots)
    @property
    def degraded(self):return self._bad or self._authority is not None and self._authority.degraded

    def _report(self,event,status='incomplete',reason=None,**fields):
        return deepcopy(dict(kind='uart_store_memory_match',schema_version='uart_store_memory_match.v1',
            status=status,reason=reason,proof_scope='uart_operand_store_host_memory_byte',
            observation_event_id=event.get('event_id'),memory_kind='modeled_host_persistent_memory',
            rtl_ram_origin='unknown',later_ram_read_origin='unknown',whole_word_store_origin='unknown',
            generic_isr_origin='unknown',upper_bits_origin='unknown',**fields))

    def _fail(self,event,reason):
        key=_key(event.get('transaction'))
        c=key[2] if key else event.get('source_component',event.get('component'))
        ep=key[3] if key else event.get('source_epoch',event.get('reset_epoch'))
        if (type(c) is str and _uint(ep) and self._uses._seed._linker._role_allowed(c,'cpu')
                and ((c,self._epochs.get(c,ep)) in self._bad_scopes
                     or len(self._bad_scopes)<self.max_components)):
            self._bad_scopes.add((c,self._epochs.get(c,ep)))
        else:self._global_bad=True
        self._bad=True;return (self._report(event,reason=reason),)

    def _scope(self,key):return (key[0],key[2],key[3])

    def _slot(self,key,event):
        if key in self._slots:return self._slots[key]
        component,epoch=key[2],key[3]
        if component in self._epochs and epoch!=self._epochs[component]:return None
        if component not in self._epochs:
            if len(self._epochs)>=self.max_components:return None
            self._epochs[component]=epoch
        scope=self._scope(key)
        if key[5]<=self._closed_floors.get(scope,0):return None
        if scope not in self._closed_floors and len(self._closed_floors)>=self.max_components:return None
        if len(self._slots)>=self.max_pending:return None
        self._closed_floors.setdefault(scope,0)
        return self._slots.setdefault(key,{})

    def _close(self,key):
        slot=self._slots.pop(key,None)
        if slot and 'raw' in slot:self._by_retirement.pop(slot['raw']['event_id'],None)
        scope=self._scope(key)
        if scope not in self._closed_floors and len(self._closed_floors)>=self.max_components:
            self._bad=True;self._global_bad=True;return
        self._closed_floors[scope]=max(self._closed_floors.get(scope,0),key[5])

    def consume(self,event,*,commit_token=None):
        if type(event) is not dict:return self._fail({},'malformed_store_memory_event')
        kind=event.get('kind')
        if kind is None:return ()
        if type(kind) is not str:return self._fail(event,'malformed_store_memory_kind')
        relevant={'memory_write_commit','cpu_retire','cpu_reset','cpu_flush','instr_response',
            'data_accept','data_response','cpu_retirement_match','uart_tick_observation','uart_frame_validation',
            'uart_rdata_access','uart_reset','uart_consumption_match'}
        if kind not in relevant:return ()
        if kind=='uart_consumption_match' and event.get('proof_scope') not in (
            'uart_fifo_retention','uart_fifo_read_consumption'):return ()
        try:event=json.loads(_wire(event))
        except (TypeError,ValueError,RecursionError):return self._fail({},'malformed_store_memory_event')
        eid=event.get('event_id')
        if type(eid) not in (int,str) or type(eid) is int and eid<0 or eid=='':
            return self._fail(event,'missing_store_memory_event_identity')
        signature=hashlib.sha256(_wire(event).encode()).hexdigest()
        if eid in self._seen:
            return () if self._seen[eid]==signature else self._fail(event,'conflicting_store_memory_event')
        if type(eid) is int:
            if eid<=self._event_floor:return self._fail(event,'stale_store_memory_event')
            self._event_floor=eid
        if len(self._seen)>=self.max_event_refs:
            if type(next(iter(self._seen))) is str:return self._fail(event,'store_memory_identity_capacity')
            self._seen.popitem(last=False)
        self._seen[eid]=signature
        if self.degraded and kind!='cpu_reset':return ()
        if kind=='memory_write_commit':
            if self._authority is None or commit_token is None:
                return (self._report(event,status='unknown',reason='unregistered_host_memory_commit'),)
            certificate=self._authority.resolve(commit_token)
            if certificate is None:return self._fail(event,'unproven_live_memory_commit_token')
            key=_key(certificate.get('fullkey'))
            if (key is None or key[4]!='data' or event.get('schema_version')!='memory_write_commit.v1'
                    or _wire(event.get('transaction'))!=_wire(certificate['fullkey'])
                    or _wire(event.get('commit_document'))!=_wire(certificate['commit_document'])
                    or _wire(event.get('commit_id'))!=_wire(certificate['commit_id'])
                    or _wire(event.get('service_commit_sequence'))!=_wire(certificate['service_commit_sequence'])
                    or event.get('component',key[2])!=key[2]):
                return self._fail(event,'issued_memory_commit_witness_conflict')
            if key[2] in self._epochs and self._epochs[key[2]]!=key[3]:
                return self._fail(event,'stale_store_memory_commit_epoch')
            if key not in self._slots and key[5]<=self._closed_floors.get(self._scope(key),0):
                return (self._report(event,status='unknown',reason='closed_or_unrelated_host_store'),)
            slot=self._slot(key,event)
            if slot is None:return self._fail(event,'store_memory_pending_capacity')
            if 'commit' in slot:return self._fail(event,'duplicate_store_memory_commit')
            slot.update(commit=certificate,commit_event_id=eid)
        else:
            uses=self._uses.consume(event)
            cpu_kinds={'instr_response','data_accept','data_response','cpu_retire','cpu_reset','cpu_flush'}
            matches=self._retire.consume(event) if kind in cpu_kinds else ()
            if any(r.get('status')=='incomplete' for r in uses) or any(r.get('status')=='incomplete' for r in matches):
                return self._fail(event,'raw_store_memory_certainty_barrier')
            if kind=='cpu_reset':
                c=event.get('component',event.get('source_component'));ep=event.get('reset_epoch')
                state=self._uses._seed._states.get(c) if type(c) is str else None
                if state and state['epoch']==ep and not state['bad'] and not self._uses._global_bad:
                    for k in list(self._slots):
                        if k[2]==c:self._close(k)
                    self._closed_floors={k:v for k,v in self._closed_floors.items() if k[1]!=c}
                    self._epochs[c]=ep
                    self._bad_scopes={s for s in self._bad_scopes if s[0]!=c}
                    self._bad=self._global_bad or bool(self._bad_scopes)
                return ()
            if self.degraded:return ()
            for match in matches:
                if (kind!='cpu_retire' or match.get('status')!='accepted'
                        or type(match.get('insn')) is not int or match['insn']&0x707f!=0x2023):continue
                keys=match.get('transaction_keys');key=_key(keys[0]) if type(keys) is list and len(keys)==1 else None
                if key is None:return self._fail(event,'invalid_store_retired_transaction')
                use=next((u for u in uses if u.get('status')=='accepted' and u.get('operand_retirement_event_id')==eid),None)
                if use is None and eid not in self._uses._pending:
                    self._close(key);continue
                slot=self._slot(key,event)
                if slot is None:return self._fail(event,'store_memory_pending_capacity')
                slot.update(match=match,raw=deepcopy(event));self._by_retirement[eid]=key
                if use:slot['use']=use
            for use in uses:
                if use.get('status')!='accepted':continue
                key=self._by_retirement.get(use.get('operand_retirement_event_id'))
                if key in self._slots:self._slots[key]['use']=use
        output=[]
        for key,slot in list(self._slots.items()):
            if not {'commit','match','use','raw'}<=set(slot):continue
            proof=self._join(key,slot,event)
            if proof is None:return self._fail(event,'store_memory_exact_join_conflict')
            output.append(proof);self._close(key)
        return tuple(deepcopy(output))

    def _join(self,key,slot,event):
        use=slot['use'];match=slot['match'];raw=slot['raw'];commit=slot['commit'];doc=commit['commit_document']
        beats=match.get('data_beats')
        if type(beats) is not list or len(beats)!=1:return None
        beat=beats[0];response=beat.get('response');address=use.get('measured_mem_addr');value=use.get('operand_value')
        if (not _uint(address,32) or address&3 or not _uint(value,32)
                or type(response) is not dict or not _uint(response.get('error'),1) or response['error']!=0
                or not _uint(response.get('rdata'),32)
                or any(_key(x.get('transaction'))!=key for x in (beat,response))
                or any(not _uint(beat.get(n),w) for n,w in (('write',1),('be',4),('wdata',32),('raw_address',32),('aligned_address',32)))
                or beat['write']!=1 or beat['be']!=15 or beat['wdata']!=value
                or beat['raw_address']!=address or beat['aligned_address']!=address
                or match.get('cpu_scope')!=use.get('cpu_scope') or match.get('order')!=use.get('operand_order')
                or match.get('insn')!=use.get('decoded_insn') or use.get('operand_retirement_event_id')!=raw['event_id']
                or any(base<=address<limit for _,_,base,limit in self._uses._seed._linker._routes)):
            return None
        payload=dict(op='write',address=address,value=value,width_bytes=4,byte_enable=15)
        if doc.get('payload_sha256')!=TransactionLedger._digest(payload):return None
        cells=doc.get('enabled_byte_cells');version=doc.get('version');offset=doc.get('byte_offset')
        if (doc.get('width_bytes')!=4 or doc.get('byte_enable')!=15 or doc.get('performed_effect') is not True
                or not _uint(offset) or type(version) is not list or len(version)!=2
                or not all(_uint(n) for n in version) or version[0]!=doc.get('generation')
                or type(cells) is not list or len(cells)!=4):return None
        writer=str(TransactionKey(**dict(zip(_KEY,key))))
        for lane,cell in enumerate(cells):
            if (type(cell) is not dict or not _uint(cell.get('byte_offset')) or cell['byte_offset']!=offset+lane
                    or not _uint(cell.get('value'),8) or cell['value']!=(value>>(8*lane))&255
                    or _wire(cell.get('version'))!=_wire(version) or cell.get('writer_kind')!='STORE'
                    or cell.get('writer_event_id')!=writer):return None
        return self._report(event,status='accepted',reason='matched_actual_host_memory_store_low_byte',
            store_fullkey=dict(zip(_KEY,key)),store_retirement_event_id=raw['event_id'],store_order=raw['order'],
            request_event_id=beat['event_id'],response_event_id=response['event_id'],
            source_register_version_key=use['source_register_version_key'],source_seed_certificate_ref=use['source_seed_certificate_ref'],
            source_load_fullkey=use['source_load_fullkey'],source_entry_id=use['source_entry_id'],source_admission=use['source_admission'],
            memory_id=doc['memory_id'],generation=doc['generation'],byte_offset=offset,byte_value=cells[0]['value'],
            byte_version=version,writer_event_id=writer,commit_id=commit['commit_id'],commit_event_id=slot['commit_event_id'],
            service_commit_sequence=commit['service_commit_sequence'],unknown_written_lanes=[1,2,3],influenced_bits=[0,8],
            source_path_id=use['path_id'],source_path_certified=use['graph_path_certified'],store_memory_path_certified=False)
