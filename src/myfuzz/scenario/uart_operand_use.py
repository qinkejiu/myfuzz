"""Exact prior UART-seeded register version read as retired SW rs2.

This scope is operand consumption only. RAM delivery, upper-word influence,
store-origin propagation and generic ISR identity remain unknown.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from .uart_operand_seed import UartOperandSeedTracker, _uint, _wire
from .uart_retired_read import UartRetiredReadLinker


class UartOperandUseTracker:
    def __init__(self, *, admission_registry=None,ownership=None,edge_index=None,
                 max_pending_uses=256,**seed_limits):
        if type(max_pending_uses) is not int or max_pending_uses<1:
            raise ValueError('invalid UART operand-use capacity')
        self._seed=UartOperandSeedTracker(admission_registry=admission_registry,
            ownership=ownership,edge_index=edge_index,**seed_limits)
        self.max_pending_uses=max_pending_uses;self._pending=OrderedDict()
        self._native={};self._bad=set();self._global_bad=False

    @property
    def pending_count(self):return len(self._pending)

    def _report(self,event,reason=None,status='incomplete',**fields):
        return deepcopy(dict(kind='uart_operand_use',schema_version='uart_operand_use.v1',
            status=status,reason=reason,proof_scope='uart_seed_register_operand_read',
            observation_event_id=event.get('event_id'),ram_delivery_origin='unknown',
            whole_word_store_origin='unknown',generic_isr_origin='unknown',
            upper_bits_origin='unknown',**fields))

    def _fail(self,event,reason):
        c=event.get('source_component',event.get('component'));ep=event.get('source_epoch',event.get('reset_epoch'))
        state=self._seed._states.get(c) if type(c) is str else None
        if (not self._global_bad and state is not None and _uint(ep) and state['epoch']==ep
                and ((c,ep) in self._bad or len(self._bad)<self._seed.max_components)):self._bad.add((c,ep))
        else:self._global_bad=True
        return (self._report(event,reason=reason),)

    def _healthy(self,c,epoch):
        return not self._global_bad and (c,epoch) not in self._bad

    def _valid_store(self,event):
        insn=event.get('insn')
        if not _uint(insn,32) or insn&0x707f!=0x2023:return False
        fields={'rs1_addr':5,'rs2_addr':5,'rs1_rdata':32,'rs2_rdata':32,'mem_addr':32,
            'mem_wdata':32,'mem_wmask':4,'mem_rmask':4,'mode':2,'rd_addr':5,
            'trap':1,'ext_rf_wr_suppress':1,'mem_is_cap':1,'mem_wcap':1,'rs1_rcap':1,'rs2_rcap':1}
        if any(not _uint(event.get(k),w) for k,w in fields.items()):return False
        imm=((insn>>25)<<5)|((insn>>7)&31)
        if imm&0x800:imm-=0x1000
        return (event['rs1_addr']==(insn>>15)&31 and event['rs2_addr']==(insn>>20)&31
            and event['mem_addr']==(event['rs1_rdata']+imm)&0xffffffff
            and event['mem_wmask']==15 and event['mem_rmask']==0
            and event['mem_wdata']==event['rs2_rdata'] and event['mode']==3 and event['rd_addr']==0
            and all(event[k]==0 for k in ('trap','ext_rf_wr_suppress','mem_is_cap','mem_wcap','rs1_rcap','rs2_rcap')))

    def _accepted(self,raw,version,seed):
        return self._report(raw,status='accepted',reason='matched_prior_uart_register_version_read',
            cpu_scope=seed['cpu_scope'],source_register_version_key=version,
            source_seed_certificate_ref=hashlib.sha256(_wire(seed).encode()).hexdigest(),
            source_load_fullkey=seed['fullkey'],source_entry_id=seed['entry_id'],
            source_admission=seed['source_admission'],operand_retirement_event_id=raw['event_id'],
            operand_order=raw['order'],actual_post_ref=raw['actual_post_ref'],
            operand_role='rs2_store_data',operand_register=raw['rs2_addr'],operand_value=raw['rs2_rdata'],
            decoded_insn=raw['insn'],measured_mem_addr=raw['mem_addr'],measured_mem_wmask=raw['mem_wmask'],
            influenced_bits=[0,8],graph_path_certified=seed['graph_path_certified'],path_id=seed['path_id'])

    def consume(self,event):
        if type(event) is not dict:return self._fail({},'malformed_uart_operand_use_event')
        kind=event.get('kind')
        if kind is None:return ()
        if type(kind) is not str:return self._fail(event,'malformed_uart_operand_use_kind')
        # Other phase certificates and externally supplied seed labels are not
        # part of the independently regenerated raw/read witness stream.
        if kind=='uart_consumption_match' and event.get('proof_scope') not in (
                'uart_fifo_retention','uart_fifo_read_consumption'):return ()
        relevant={'cpu_retire','cpu_reset','cpu_flush','instr_response','data_accept','data_response',
            'cpu_retirement_match','uart_tick_observation','uart_frame_validation','uart_rdata_access',
            'uart_reset','uart_consumption_match'}
        if kind not in relevant:return ()
        try:event=json.loads(_wire(event))
        except (TypeError,ValueError,RecursionError):return self._fail({},'malformed_uart_operand_use_event')
        eid=event.get('event_id')
        # The embedded seed's strict receipt/event floors are authoritative for
        # raw replay detection; already-seen events cannot allocate new uses.
        repeated=type(eid) in (int,str) and eid in self._seed._seen
        c=event.get('source_component');ep=event.get('source_epoch')
        prior=None
        if kind=='cpu_retire' and type(c) is str and _uint(ep) and _uint(event.get('rs2_addr'),5):
            prior=self._seed.register_at(c,ep,event['rs2_addr'])
        seed_reports=self._seed.consume(event)
        output=[]
        if any(p.get('status')=='incomplete' for p in seed_reports):
            output.extend(self._fail(event,'raw_uart_operand_use_certainty_barrier'))
        if kind=='cpu_reset':
            component=event.get('component',event.get('source_component'))
            state=self._seed._states.get(component) if type(component) is str else None
            if state and state['epoch']==event.get('reset_epoch') and not state['bad'] and not output:
                self._pending=OrderedDict((k,v) for k,v in self._pending.items() if v['raw']['source_component']!=component)
                self._native={k:v for k,v in self._native.items() if k[1]!=component}
                self._bad={k for k in self._bad if k[0]!=component}
            return tuple(output)
        if kind=='uart_reset' and not output:
            component=event.get('component',event.get('source_component'));epoch=event.get('reset_epoch')
            if (type(component) is str and _uint(epoch) and event.get('physical_reset') is True
                    and self._seed._linker._epochs.get(('uart',component))==epoch):
                cancelled=set()
                for key,raw in list(self._seed._pending.items()):
                    if any(raw['source_component']==cpu and device==component and raw.get('mem_addr')==base+24
                           for cpu,device,base,_ in self._seed._linker._routes):
                        cancelled.add(tuple((raw['source_component'],raw['source_epoch'],raw['order'],raw['rd_addr'])))
                        del self._seed._pending[key]
                self._pending=OrderedDict((k,v) for k,v in self._pending.items() if tuple(v['version']) not in cancelled)
            return tuple(output)
        if kind=='cpu_retire' and not repeated:
            if type(c) is not str or not _uint(ep):return self._fail(event,'malformed_uart_operand_use_scope')
            if not self._healthy(c,ep):return tuple(output)
            if not UartRetiredReadLinker._native_retire(SimpleNamespace(_native=self._native),event):
                return self._fail(event,'unproven_uart_operand_use_post')
            if event.get('insn',0)&0x707f==0x2023:
                if not self._valid_store(event):return self._fail(event,'invalid_uart_operand_use_store')
                if prior and self._seed.register_at(c,ep,event['rs2_addr']) is not None:
                    if prior['measured_value']!=event['rs2_rdata']:
                        return self._fail(event,'uart_operand_use_version_value_conflict')
                    version=prior['register_version_key'];seed=prior.get('seed')
                    if seed:
                        output.append(self._accepted(event,version,seed))
                    elif prior['retirement_event_id'] in self._seed._pending:
                        if len(self._pending)>=self.max_pending_uses:
                            return self._fail(event,'uart_operand_use_pending_capacity')
                        self._pending[eid]=dict(raw=deepcopy(event),version=deepcopy(version))
        for seed in seed_reports:
            if seed.get('status')!='accepted':continue
            for key,candidate in list(self._pending.items()):
                raw=candidate['raw'];component=raw['source_component'];epoch=raw['source_epoch']
                if (self._healthy(component,epoch) and not self._seed._global_bad
                        and self._seed._states.get(component,{}).get('bad') is False
                        and candidate['version']==seed['register_version_key']):
                    output.append(self._accepted(raw,candidate['version'],seed));del self._pending[key]
        return tuple(deepcopy(output))
