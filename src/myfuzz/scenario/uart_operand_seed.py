"""Restricted actual UART retired LW -> register-version seeds.

No caller-supplied accepted label is authority. An independent raw read linker
regenerates certificates. A seed authenticates a historical destination write;
it never proves a later operand, copy, store or generic ISR origin.
"""
from collections import OrderedDict
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace
from .uart_retired_read import UartRetiredReadLinker


def _wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def _uint(value,width=64):
    return type(value) is int and 0<=value<1<<width


class UartOperandSeedTracker:
    def __init__(self, *, admission_registry=None,ownership=None,edge_index=None,
                 max_pending=256,max_components=16,max_instruction_witnesses=2048,
                 max_event_refs=4096,max_read_pending=256):
        if any(type(n) is not int or n<1 for n in (max_pending,max_event_refs,max_read_pending)):
            raise ValueError('invalid UART operand capacity')
        self._linker=UartRetiredReadLinker(admission_registry=admission_registry,
            ownership=ownership,edge_index=edge_index,max_pending=max_read_pending,
            max_components=max_components,max_instruction_witnesses=max_instruction_witnesses)
        self.max_pending=max_pending;self.max_components=max_components;self.max_event_refs=max_event_refs
        self._event_floor=-1
        self._states={};self._pending=OrderedDict();self._seen=OrderedDict()
        self._receipt_floors={};self._global_bad=False

    @property
    def pending_count(self):return len(self._pending)

    def register_at(self,component,epoch,register):
        if type(component) is not str or not _uint(epoch) or not _uint(register,5):return None
        state=self._states.get(component)
        if state is None or state['epoch']!=epoch or state['bad'] or self._global_bad:return None
        return deepcopy(state['registers'].get(register))

    def _report(self,event,status='incomplete',reason=None,**fields):
        return deepcopy(dict(kind='uart_operand_seed',schema_version='uart_operand_seed.v1',
            status=status,reason=reason,proof_scope='uart_retired_load_register_seed',
            observation_event_id=event.get('event_id'),operand_origin='unknown',
            generic_isr_origin='unknown',subsequent_store_origin='unknown',**fields))

    def _fail(self,event,reason):
        component=event.get('source_component',event.get('component'))
        if type(component) is str and component in self._states:self._states[component]['bad']=True
        else:self._global_bad=True
        return (self._report(event,reason=reason),)

    def _reset(self,event):
        component=event.get('component',event.get('source_component'));epoch=event.get('reset_epoch')
        prior=self._states.get(component) if type(component) is str else None
        if (not self._linker._role_allowed(component,'cpu') or not _uint(epoch)
                or event.get('physical_reset') is not True
                or event.get('source_component',component)!=component
                or event.get('source_epoch',epoch)!=epoch
                or prior is not None and epoch<=prior['epoch']):
            return self._fail(event,'unproven_uart_operand_reset')
        if prior is None and len(self._states)>=self.max_components:
            return self._fail(event,'uart_operand_component_capacity')
        reports=self._linker.consume(event)
        if any(r.get('status')=='incomplete' for r in reports):return self._fail(event,'unproven_uart_operand_reset')
        self._states[component]=dict(epoch=epoch,execution=None,process=None,order=None,
            registers={},bad=False)
        self._pending={k:v for k,v in self._pending.items() if v['source_component']!=component}
        self._receipt_floors={k:v for k,v in self._receipt_floors.items() if k[1]!=component}
        # Global uncertainty cannot be repaired by a reset of one guessed CPU.
        return ()

    def _retire(self,event):
        component=event.get('source_component');epoch=event.get('source_epoch');execution=event.get('execution_id')
        if (type(component) is not str or not self._linker._role_allowed(component,'cpu')
                or not _uint(epoch) or type(execution) is not str or not execution):
            return self._fail(event,'malformed_uart_operand_retirement')
        state=self._states.get(component)
        if state is None:
            if len(self._states)>=self.max_components:return self._fail(event,'uart_operand_component_capacity')
            state=self._states[component]=dict(epoch=epoch,execution=execution,process=None,
                order=None,registers={},bad=False)
        if state['bad'] or self._global_bad:return ()
        if epoch!=state['epoch'] or state['execution'] not in (None,execution):
            return self._fail(event,'uart_operand_scope_changed')
        validator=SimpleNamespace(_native=self._receipt_floors)
        if (not UartRetiredReadLinker._native_retire(validator,event)
                or not _uint(event.get('order')) or not _uint(event.get('rd_addr'),5)
                or not _uint(event.get('rd_wdata'),32) or not _uint(event.get('insn'),32)
                or any(not _uint(event.get(k),1) for k in ('trap','ext_rf_wr_suppress','rd_wcap','mem_is_cap'))
                or state['order'] is not None and event['order']!=state['order']+1):
            return self._fail(event,'unproven_uart_operand_retirement')
        state['execution']=execution;state['order']=event['order']
        rd=event['rd_addr']
        if not rd:return ()
        version=dict(register_version_key=[component,epoch,event['order'],rd],
            retirement_event_id=event['event_id'],measured_value=event['rd_wdata'],origin_status='unknown')
        state['registers'][rd]=version
        insn=event['insn']
        # Only an actual normal RV32 LW to the compiled UART RDATA window can
        # wait for a seed. Unknown writes still replace their destination version.
        eligible=(insn&0x707f==0x2003 and (insn>>7)&31==rd
            and event['trap']==event['ext_rf_wr_suppress']==event['rd_wcap']==event['mem_is_cap']==0
            and any(component==cpu and event.get('mem_addr')==base+24
                for cpu,_,base,_ in self._linker._routes))
        if eligible:
            if len(self._pending)>=self.max_pending:return self._fail(event,'uart_operand_pending_capacity')
            self._pending[event['event_id']]=deepcopy(event)
        return ()

    def consume(self,event):
        if type(event) is not dict:return self._fail({},'malformed_uart_operand_event')
        relevant={'cpu_retire','cpu_reset','cpu_flush','instr_response','data_accept','data_response',
            'cpu_retirement_match','uart_tick_observation','uart_frame_validation','uart_rdata_access',
            'uart_reset','uart_consumption_match'}
        if event.get('kind') is None:return ()
        if type(event.get('kind')) is not str:return self._fail(event,'malformed_uart_operand_event')
        if event['kind'] not in relevant:return ()
        try:event=json.loads(_wire(event))
        except (TypeError,ValueError,RecursionError):return self._fail({},'malformed_uart_operand_event')
        eid=event.get('event_id')
        if type(eid) not in (int,str) or type(eid) is int and eid<0 or eid=='':
            return self._fail(event,'missing_uart_operand_event_identity')
        signature=hashlib.sha256(_wire(event).encode()).hexdigest()
        if eid in self._seen:
            return () if self._seen[eid]==signature else self._fail(event,'conflicting_uart_operand_event_identity')
        if type(eid) is int:
            if eid<=self._event_floor:return self._fail(event,'stale_uart_operand_event_identity')
            self._event_floor=eid
        if len(self._seen)>=self.max_event_refs:
            oldest=next(iter(self._seen))
            if type(oldest) is str:return self._fail(event,'uart_operand_event_identity_capacity')
            self._seen.popitem(last=False)
        self._seen[eid]=signature
        kind=event['kind']
        if kind=='cpu_reset':return self._reset(event)
        output=[]
        if kind=='cpu_retire':output.extend(self._retire(event))
        if kind=='cpu_flush':
            # No physical register reset is established by flush alone. Retain
            # historical known versions but cancel pending certainty.
            output.extend(self._fail(event,'uart_operand_flush_certainty_barrier'))
        reports=self._linker.consume(event)
        for report in reports:
            if report.get('status')=='incomplete':
                output.extend(self._fail(event,'raw_uart_operand_certainty_barrier'));continue
            if report.get('status')!='accepted':continue
            raw=self._pending.get(report.get('retirement_event_id'))
            if raw is None:continue
            state=self._states.get(raw['source_component'])
            if self._global_bad or state is None or state['bad'] or state['epoch']!=raw['source_epoch']:continue
            if (report.get('destination_register')!=raw['rd_addr'] or report.get('order')!=raw['order']
                    or report.get('read_value')!=raw['rd_wdata'] or not _uint(report.get('read_value'),8)):
                output.extend(self._fail(raw,'uart_operand_seed_witness_conflict'));continue
            version_key=[raw['source_component'],raw['source_epoch'],raw['order'],raw['rd_addr']]
            proof=self._report(event,status='accepted',reason='matched_uart_load_destination_version',
                cpu_scope=report['cpu_scope'],register_version_key=version_key,
                retirement_event_id=raw['event_id'],actual_post_ref=raw['actual_post_ref'],
                fullkey=report['fullkey'],retired_read_certificate_ref=hashlib.sha256(_wire(report).encode()).hexdigest(),
                entry_id=report['entry_id'],source_admission=report['source_admission'],
                measured_rd_wdata=raw['rd_wdata'],influenced_bits=[0,8],upper_bits_origin='unknown',
                graph_path_certified=report['graph_path_certified'],path_id=report['path_id'])
            current=state['registers'].get(raw['rd_addr'])
            if current and current['register_version_key']==version_key:
                current.update(origin_status='known_uart_load',seed=deepcopy(proof))
            del self._pending[raw['event_id']]
            output.append(proof)
        return tuple(deepcopy(output))
