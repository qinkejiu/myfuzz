"""Bounded raw-evidence UART RDATA to one architectural RV32 LW join.

Logged accepted certificates are checked against independently reconstructed raw
UART and CPU models. Instruction origin is separate from load data provenance.
"""
from copy import deepcopy
import hashlib
import json
from .cpu_retirement import CpuRetirementMatcher, _KEY, _IDENTITY, _uint
from .retirement_delivery import _key, _frozen_match
from .uart_consumption import UartConsumptionTracker


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _same(a, b):
    return _wire(a) == _wire(b)


def _id(value):
    return type(value) is int and value >= 0 or type(value) is str and bool(value.strip())


_RVFI_NAMES = frozenset('valid order insn trap halt intr mode ixl rs1_addr rs2_addr rs3_addr rs1_rdata rs2_rdata rs3_rdata rs1_rcap rs2_rcap rd_wcap rd_addr rd_wdata pc_rdata pc_wdata mem_addr mem_rmask mem_wmask mem_rdata mem_wdata mem_is_cap mem_rcap mem_wcap ext_pre_mip ext_post_mip ext_nmi ext_nmi_int ext_debug_req ext_debug_mode ext_rf_wr_suppress ext_mcycle ext_mhpmcounters ext_mhpmcountersh ext_ic_scr_key_valid ext_irq_valid ext_expanded_insn_valid ext_expanded_insn ext_expanded_insn_last'.split())
_ENVELOPE = frozenset(('event_id', 'producer_event_id', 'provenance', 'kind',
    'registered_origins', '_known_fuzz_origin', 'component', 'origin_relation'))


class UartRetiredReadLinker:
    def __init__(self, *, admission_registry=None, ownership=None, edge_index=None,
                 max_pending=256, max_components=16, max_instruction_witnesses=2048):
        from .source_provenance import AdmissionRegistry
        from .ownership import OwnershipMap
        from .runtime_edge_index import RuntimeEdgeIndex
        for n in (max_pending, max_components, max_instruction_witnesses):
            if type(n) is not int or n < 1: raise ValueError('capacities must be positive')
        for value, cls in ((admission_registry, AdmissionRegistry), (ownership, OwnershipMap),
                           (edge_index, RuntimeEdgeIndex)):
            if value is not None and not isinstance(value, cls): raise ValueError('invalid authority')
        self.registry, self.ownership, self.edge_index = admission_registry, ownership, edge_index
        self.max_pending, self.max_components = max_pending, max_components
        self._uart = UartConsumptionTracker(admission_registry=admission_registry,
            ownership=ownership, edge_index=edge_index, max_pending=max_pending,
            max_components=max_components)
        self._cpu = CpuRetirementMatcher(max_pending=max_instruction_witnesses)
        self._slots = {}; self._floor = {}; self._epochs = {}
        self._bad = set(); self._global_bad = False; self._execution = {}
        self._native = {}; self._closed_receipts = {}
        # RuntimeEdgeIndex validates these windows against the actual compiled
        # router topology. Its public event matcher does not expose base/limit.
        self._routes=frozenset((initiator,device,base,limit)
            for (initiator,device),windows in (edge_index._mmio.items() if edge_index else ())
            for base,limit,_ in windows if self._role_allowed(device,'uart'))
        if len(self._routes)>max_components*max_components:
            raise ValueError('UART route capacity exceeded')

    @property
    def pending_count(self):
        return len(self._slots)

    @property
    def degraded(self):
        return self._global_bad or bool(self._bad)

    def _component(self, e):
        scope = e.get('cpu_scope') if isinstance(e.get('cpu_scope'), dict) else e
        tx = e.get('transaction') if isinstance(e.get('transaction'), dict) else {}
        c = e.get('component', scope.get('source_component', tx.get('source_component')))
        epoch = e.get('reset_epoch', scope.get('source_epoch', tx.get('source_epoch')))
        return (c, epoch) if type(c) is str and c and _uint(epoch, 64) else None

    def _fail(self, e, reason):
        scope = self._component(e)
        if scope is None: self._global_bad = True
        else:
            current={(component,epoch) for (_,component),epoch in self._epochs.items()
                     if component==scope[0]}
            additions=current or {scope}
            if len(self._bad | additions)>self.max_components: self._global_bad=True
            else: self._bad.update(additions)
        return (dict(kind='uart_retired_read_match', schema_version='uart_retired_read_match.v1',
            status='incomplete', reason=reason, proof_scope='cpu_retired_uart_rdata_read',
            observation_event_id=e.get('event_id')),)

    def _role_allowed(self, component, role):
        try:
            if self.ownership is None: raise ValueError('missing role authority')
            if role=='uart':
                declared=self.ownership.mutation_source(component,'uart_rx_byte',0,8,direction='IP_TO_CPU')
                valid_role=type(declared) is str and bool(declared)
            else:
                declared=self.ownership.binding_producer(component,'irq',0,1)
                valid_role=type(declared) is str and declared.endswith('.uart_rx_watermark')
        except (ValueError,TypeError,KeyError): valid_role=False
        return valid_role

    def _observe(self, e, role):
        scope=self._component(e)
        if scope is None: return self._fail(e,'missing_retired_uart_scope')
        component, epoch=scope; identity=(role,component)
        if not self._role_allowed(component,role): return self._fail(e,'wrong_retired_uart_component_role')
        if identity not in self._epochs:
            if len(self._epochs)>=self.max_components:
                self._global_bad=True
                return self._fail(e,'retired_uart_scope_capacity_exceeded')
            self._epochs[identity]=epoch
        elif self._epochs[identity]!=epoch:
            return self._fail(e,'unwitnessed_retired_uart_epoch_transition')
        execution=e.get('execution_id')
        if role=='cpu' and execution is None:
            execution=(e.get('transaction') or e.get('cpu_scope') or {}).get('execution_id')
        if role=='cpu':
            if type(execution) is not str or not execution:
                return self._fail(e,'missing_retired_uart_execution')
            if identity in self._execution and self._execution[identity]!=execution:
                return self._fail(e,'retired_uart_execution_scope_changed')
            self._execution[identity]=execution
        return ()

    def _slot(self, key, e):
        cpu_scope = (key[0], key[2], key[3])
        if key not in self._slots:
            if key[5] <= self._floor.get(cpu_scope, 0): return None
            if len(self._slots) >= self.max_pending: return None
            self._slots[key] = {}
        return self._slots[key]

    def _put(self, key, field, value, e):
        slot = self._slot(key, e)
        if slot is None:
            if key[5] <= self._floor.get((key[0],key[2],key[3]), 0):
                return self._fail(e, 'stale_retired_uart_transaction')
            return self._fail(e, 'retired_uart_pending_capacity_exceeded')
        if field in slot and not _same(slot[field], value):
            return self._fail(e, 'conflicting_retired_uart_witness')
        slot[field] = deepcopy(value)
        return ()

    def _could_be_uart_read(self, match):
        beats=match.get('data_beats')
        if type(beats) is not list or len(beats)!=1 or type(beats[0]) is not dict: return False
        beat=beats[0];key=_key(beat.get('transaction'))
        if key is None or beat.get('write')!=0 or beat.get('be')!=15: return False
        return any(key[2]==cpu and beat.get('raw_address')==base+24
            and beat.get('aligned_address')==base+24 and base+28<=limit
            for cpu,_,base,limit in self._routes)

    def _certificate(self, observed, reconstructed):
        return (set(observed) <= set(reconstructed) | _ENVELOPE
            and all(k in observed and _same(observed[k], v) for k,v in reconstructed.items()))

    def _native_retire(self, e):
        if e.get('schema_version') != 'cpu_retire.v2':
            return False
        from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
        c, ep = e.get('source_component'), e.get('source_epoch')
        scope, receipt, ticks = e.get('command_scope'), e.get('receipt_id'), e.get('receipt_ticks')
        if (not _same(e.get('observation_contract'), ibex_irq_receipt_contract())
                or e.get('phase') != 'post' or not _uint(e.get('local_tick'),64)
                or type(scope) is not dict or set(scope) != {'component','reset_epoch','command_sequence'}
                or scope['component'] != c or not _uint(scope['reset_epoch'],64) or scope['reset_epoch'] != ep
                or not _uint(scope['command_sequence'],64) or scope['command_sequence'] == 0
                or type(receipt) is not dict or set(receipt) != {'execution','sequence'}
                or type(receipt['execution']) is not str or not receipt['execution']
                or type(receipt['sequence']) is not int or receipt['sequence'] != scope['command_sequence']
                or not _same(e.get('actual_post_ref'), dict(command_scope=scope,local_tick=e['local_tick'],phase='post'))
                or type(ticks) is not dict or set(ticks) != {'tick_before','tick_after','new_ticks','local_tick_base'}
                or any(not _uint(v,64) for v in ticks.values())
                or ticks['new_ticks'] != 1 or ticks['tick_after'] != ticks['tick_before']+1
                or ticks['local_tick_base']+ticks['tick_after'] != e['local_tick']): return False
        observation=e.get('observation'); physical=observation.get('physical') if isinstance(observation,dict) else None
        if (type(physical) is not dict or observation.get('sampling_edge') != 'post_rising'
                or set(physical) != {'rvfi_'+n for n in _RVFI_NAMES}
                or any(type(physical['rvfi_'+n]) is not int or physical['rvfi_'+n] < 0
                    or not _same(e.get(n), physical['rvfi_'+n]) for n in _RVFI_NAMES)
                or physical['rvfi_valid'] != 1): return False
        scope_key=(e.get('execution_id'),c,ep); previous=self._native.get(scope_key)
        current=(receipt['execution'],receipt['sequence'],e['local_tick'])
        if previous and (current[0] != previous[0] or current[1] <= previous[1] or current[2] <= previous[2]): return False
        self._native[scope_key]=current
        return True

    def _reset(self, e):
        kind=e['kind'];component=e.get('component',e.get('source_component'))
        epoch=e.get('reset_epoch',e.get('source_epoch'))
        role='cpu' if kind=='cpu_reset' else 'uart'
        if not self._role_allowed(component,role): return self._fail(e,'wrong_retired_uart_reset_role')
        if ('source_component' in e and e['source_component']!=component
                or 'source_epoch' in e and not _same(e['source_epoch'],epoch)):
            return self._fail(e,'conflicting_retired_uart_reset_identity')
        if (type(component) is not str or not component or not _uint(epoch,64)
                or e.get('physical_reset') is not True): return self._fail(e,'unproven_retired_uart_reset')
        prior=self._epochs.get((role,component),-1)
        if epoch <= prior: return self._fail(e,'retired_uart_reset_did_not_advance')
        if (role,component) not in self._epochs and len(self._epochs)>=self.max_components:
            self._global_bad=True
            return self._fail(e,'retired_uart_scope_capacity_exceeded')
        self._epochs[(role,component)]=epoch
        self._execution.pop((role,component),None)
        for key, slot in list(self._slots.items()):
            source=(slot.get('uart') or slot.get('uart_logged') or {})
            if (role=='cpu' and key[2]==component or role=='uart' and (not source or source.get('component')==component)):
                self._slots.pop(key)
        self._native={k:v for k,v in self._native.items() if not (role=='cpu' and k[1]==component)}
        self._closed_receipts={k:v for k,v in self._closed_receipts.items()
            if not (role=='cpu' and k[1]==component or role=='uart')}
        self._bad={s for s in self._bad if s[0]!=component}
        if role=='cpu':
            self._floor={k:v for k,v in self._floor.items() if k[1]!=component}
        return ()

    def consume(self, event):
        if not isinstance(event,dict): return self._fail({},'malformed_retired_uart_event')
        try: e=json.loads(_wire(event))
        except (TypeError,ValueError,RecursionError): return self._fail({},'malformed_retired_uart_event')
        kind=e.get('kind'); known={'instr_response','data_accept','data_response','cpu_retire',
            'cpu_retirement_match','cpu_reset','cpu_flush','uart_tick_observation',
            'uart_frame_validation','uart_rdata_access','uart_reset','uart_consumption_match'}
        if type(kind) is not str or kind not in known: return ()
        if not _id(e.get('event_id')): return self._fail(e,'missing_retired_uart_event_identity')
        out=[]
        fingerprint=hashlib.sha256(_wire(e).encode()).hexdigest()
        if any(fingerprint in hashes for hashes in self._closed_receipts.values()): return ()
        if kind in ('cpu_reset','uart_reset'):
            out.extend(self._reset(e))
            if out: return tuple(out)
        if kind not in ('cpu_reset','uart_reset'):
            role='uart' if kind.startswith('uart_') else 'cpu'
            observed=self._observe(e,role)
            if observed: return observed
        if kind.startswith('uart_') and kind!='uart_consumption_match':
            for report in self._uart.consume(e):
                if report.get('status')=='incomplete' and report.get('reason') not in (
                    'unproven_uart_source_authority','uart_unknown_entry_origin','uart_empty_read','unrouted_uart_access'):
                    out.extend(self._fail(e,'raw_uart_certainty_barrier'))
                if report.get('status')=='accepted' and report.get('proof_scope')=='uart_fifo_read_consumption':
                    key=_key(report.get('source_transaction'))
                    if key is None: out.extend(self._fail(e,'malformed_uart_read_key'))
                    else: out.extend(self._put(key,'uart',report,e))
        elif kind in ('instr_response','data_accept','data_response','cpu_retire','cpu_reset','cpu_flush'):
            if kind=='cpu_retire' and not self._native_retire(e):
                return self._fail(e,'unproven_native_retirement_receipt')
            # Final journal overlays are annotations, never physical authority.
            # Runner's matcher freezes receipts before that overlay is applied.
            modeled=deepcopy(e);modeled.pop('provenance',None)
            for report in self._cpu.consume(modeled):
                if report.get('status') in ('incomplete','ambiguous'):
                    out.extend(self._fail(e,'raw_cpu_certainty_barrier'))
                if kind=='cpu_retire' and report.get('status')=='accepted' and report.get('reason')=='matched_ordered_retired_transaction':
                    insn=report['insn']
                    if insn & 127 == 3 and (insn>>12)&7 == 2 and self._could_be_uart_read(report):
                        keys=report.get('transaction_keys',[])
                        if len(keys)==1 and _key(keys[0]) is not None:
                            out.extend(self._put(_key(keys[0]),'cpu',dict(raw=e,match=report),e))
        elif kind=='cpu_retirement_match':
            if e.get('status')!='accepted' or e.get('reason')!='matched_ordered_retired_transaction': return ()
            if not _uint(e.get('insn'),32) or e['insn'] & 127 != 3 or (e['insn']>>12)&7 != 2: return ()
            if not self._could_be_uart_read(e): return ()
            keys=e.get('transaction_keys')
            if type(keys) is not list or len(keys)!=1 or _key(keys[0]) is None:
                return self._fail(e,'unsupported_retired_uart_beat_count')
            out.extend(self._put(_key(keys[0]),'cpu_logged',e,e))
        elif kind=='uart_consumption_match':
            if e.get('status')!='accepted' or e.get('proof_scope')!='uart_fifo_read_consumption': return ()
            key=_key(e.get('source_transaction'))
            if key is None: return self._fail(e,'malformed_uart_read_key')
            out.extend(self._put(key,'uart_logged',e,e))
        out.extend(self._promote(e))
        return tuple(deepcopy(out))

    def _promote(self, event):
        out=[]
        for key, slot in list(self._slots.items()):
            if not all(n in slot for n in ('uart','uart_logged','cpu','cpu_logged')): continue
            u, ul, c, cl=(slot[n] for n in ('uart','uart_logged','cpu','cpu_logged'))
            raw,m=c['raw'],c['match'];cpu_scope=(key[2],key[3]);uart_scope=(u['component'],u['reset_epoch'])
            if self._global_bad or cpu_scope in self._bad or uart_scope in self._bad: continue
            if (not self._certificate(ul,u) or not self._certificate(cl,m)
                    or cl.get('producer_event_id') != raw['event_id']
                    or 'component' in cl and cl['component'] != key[2]
                    or 'origin_relation' in cl and cl['origin_relation'] != 'retired_instruction_bytes'):
                out.extend(self._fail(event,'untrusted_retired_uart_certificate'));continue
            if not self._valid(key,raw,m,u):
                out.extend(self._fail(event,'retired_uart_load_witness_conflict'));continue
            out.append(dict(kind='uart_retired_read_match',schema_version='uart_retired_read_match.v1',
                status='accepted',proof_scope='cpu_retired_uart_rdata_read',fullkey=dict(zip(_KEY,key)),
                cpu_scope=m['cpu_scope'],order=m['order'],pc=m['pc'],insn=m['insn'],
                retirement_event_id=raw['event_id'],retirement_match_event_id=cl['event_id'],
                uart_read_proof_event_id=ul['event_id'],uart_access_event_id=u['access_event'],
                uart_request_event_id=u['request_event'],uart_response_event_id=u['response_event'],
                entry_id=u['entry_id'],frame_id=u['frame_id'],source_admission=u['source_admission'],
                path_id=u['path_id'],graph_path_certified=True,read_value=u['read_value'],
                destination_register=raw['rd_addr'],register_write_observed=raw['rd_addr']!=0,
                instruction_origin_status=m['instruction_origin_status'],operand_origin='unknown',
                subsequent_store_origin='unknown',generic_isr_origin='unknown',
                observation_event_id=event['event_id']))
            scope=(key[0],key[2],key[3]);self._floor[scope]=max(self._floor.get(scope,0),key[5])
            self._closed_receipts[scope]=frozenset(hashlib.sha256(_wire(v).encode()).hexdigest()
                for v in (raw,cl,ul))
            self._slots.pop(key)
        return out

    def _valid(self, key, raw, m, u):
        if self.registry is None or self.ownership is None or self.edge_index is None: return False
        from .source_provenance import SourceAdmission
        try:
            a=SourceAdmission.from_document(u['source_admission'])
            owner=self.ownership.mutation_source(u['component'],'uart_rx_byte',0,8,direction=a.direction)
            if (a!=self.registry.get(a.action_id) or a.component!=u['component']
                    or a.input_kind!='source_event' or a.direction!='IP_TO_CPU'
                    or self.edge_index.source_owner_ref(a.source_id,a.path_id,a.direction,
                        a.component,'uart_rx_byte',0,8)!=owner or owner is None): return False
            if (key[2],u['component'],u['window_base'],u['window_base']+u['window_size']) not in self._routes: return False
            if self.ownership.binding_producer(key[2],'irq',0,1)!=u['component']+'.uart_rx_watermark': return False
            edges=self.edge_index.match_event(dict(kind='dataflow_delivery',
                source=(u['component'],'uart_rx_watermark'),target=(key[2],'irq'),
                width=1,source_bit_offset=0,target_bit_offset=0))
            if not any(a.path_id in row['path_ids'] for row in edges): return False
            beats=m['data_beats'];beat=beats[0];rsp=beat['response'];ctx=u['delivery_context']
            if (len(beats)!=1 or not _frozen_match(m) or _key(beat.get('transaction'))!=key
                    or _key(rsp.get('transaction'))!=key or _key(u.get('source_transaction'))!=key
                    or _key(ctx.get('source_transaction'))!=key
                    or u.get('graph_path_certified') is not True or u.get('path_id')!=a.path_id
                    or u.get('route_context_mode')!='router' or u['read_value']!=rsp['rdata']
                    or u['address']!=u['window_base']+24 or u['window_size']<=24
                    or ctx['address']!=u['address'] or ctx['offset']!=24 or ctx['write'] is not False
                    or ctx['be']!=15 or ctx['window_base']!=u['window_base'] or ctx['window_size']!=u['window_size']
                    or beat['write']!=0 or beat['be']!=15 or beat['raw_address']!=u['address']
                    or beat['aligned_address']!=u['address'] or beat['address']!=u['address']
                    or u['address']&3 or rsp['error']!=0 or not _id(beat.get('event_id')) or not _id(rsp.get('event_id'))
                    or raw['trap']!=0 or raw['mem_rmask']!=15 or raw['mem_wmask']!=0
                    or raw['mem_addr']!=u['address'] or raw['mem_rdata']!=u['read_value']): return False
            return True
        except (ValueError,TypeError,KeyError,IndexError): return False
