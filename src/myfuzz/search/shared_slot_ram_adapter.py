"""One typed six-flow catalog, policy and clock over shared sealed slots."""
from copy import deepcopy
from dataclasses import asdict
from time import perf_counter_ns
from .actions import Action,Catalog
from .model import Condition,Goal,Snapshot
from .ram_actions import RamActionSpace,RamCredit,ram_view,ram_identity,semantic_relation
from .ram_case_adapter import RamRecordSelector
from .pin_case_adapter import PinCredit,pin_view,semantic_relation as pin_relation
from .policy import Policy
from .shared_slot_ram import install_shared_slot_ram_consumer
from .shared_slot_pin_read import install_shared_slot_pin_consumer,authenticated_report


def shared_slot_records(records):
    if not records or len(records)>64:return False
    for row in records:
        if type(row) is not str or ':' not in row:return False
        family,raw=row.split(':',1)
        if family not in ('F1','F2','F3','F4','F5','F6') or not raw or len(raw)%2:return False
        try:bytes.fromhex(raw)
        except ValueError:return False
        if len(raw) not in {'F1':(8,),'F2':(8,),'F3':(8,),'F4':(8,10),'F5':(16,),'F6':(16,)}[family]:return False
        if family=='F1' and row!='F1:03200000':return False
    return {'F1','F2','F3','F5'}<=set(r.split(':',1)[0] for r in records)


def _pin_feedback_applicable(f2, f5):
    pin = f5.get('pin')
    read = f2['execution_contract']
    return (isinstance(pin, dict) and read['register'] == 'PADIN'
            and read['target_component'] == pin.get('component'))


class SharedSlotSelector(RamRecordSelector):
    """Only F3/F1 and F5/F2 certified relations receive delayed credit.

    Other legal records remain in the same catalog and are explored without
    inferred rewards. Native execution remains entirely in the existing loop.
    """
    def __init__(self,descriptor,*,flow,records,policy,seed,cases):
        if flow!='mixed' or not shared_slot_records(records):raise ValueError('typed shared RAM/PIN catalog required')
        self.rows=list(dict.fromkeys(records))
        values=tuple(dict.fromkeys(int.from_bytes(bytes.fromhex(r[3:]),'little') for r in self.rows if r.startswith('F3:')))
        self.space=RamActionSpace(values=values,write_source='F3',read_source='F1')
        self.values=tuple(dict.fromkeys(bytes.fromhex(r[3:])[3]&1 for r in self.rows if r.startswith('F5:')))
        actions=[];self._records={}
        for i,row in enumerate(self.rows):
            family=row[:2];value=int.from_bytes(bytes.fromhex(row[3:]),'little') if family=='F3' else i
            aid=f'ram:write:{value:08x}' if family=='F3' else 'ram:read' if family=='F1' else f'shared-record:{i}'
            produces=(('ram:written',) if family=='F3' else ('ram:consumed',) if family=='F1' else
                (f'pin:written:{bytes.fromhex(row[3:])[3]&1}',) if family=='F5' else
                tuple(f'pin:consumed:{v}' for v in self.values) if family=='F2' else ('shared:explored',))
            actions.append(Action(aid,family,family,produces,(),(value,)))
            self._records[aid]=row
        self.catalog=Catalog(tuple(actions));self.scheduler=Policy(seed=seed,mode=policy,max_decisions=max(1,cases))
        self.credit=RamCredit(self.scheduler)
        self.pin_credit=PinCredit(self.scheduler,authenticator=authenticated_report)
        self.sequence=[];self.decisions=[];self.transitions=[];self.pending=None
        self._runtime=self._handle=self._pin_handle=None
        self._pin_mode=True
        self._report=dict(relations=[]);self._completed_values=set();self._pin_relations=[]
        self._replay_costs=None;self._measured_costs=[];self._terminal=None;self._bound_sources=None
        self._clock=self._clock_started=self._clock_finished=None
        self._certified_events=[];self._useful_events=[];self._decision_seconds=[];self._certified_seen=set()

    def attach_runtime(self,runtime):
        if self._runtime is not None:raise ValueError('shared runtime already attached')
        from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
        from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
        paths=runtime.compiled_inputs['compiled']['paths']
        f2,=[r for r in paths if r['flow_id']=='F2' and r['status']=='executable']
        f4,=[r for r in paths if r['flow_id']=='F4' and r['status']=='executable']
        read_layout=compile_f2_candidate_layout(f2);write_layout=compile_candidate_layout(f4)
        for row in self.rows:
            raw=bytes.fromhex(row[3:])
            if row.startswith('F2:') and not read_layout.classify(raw).accepted:
                raise ValueError('shared F2 candidate is outside the declared target')
            if row.startswith('F4:'):
                write_layout.decode(raw)
        f5=runtime.runtime_path_admission['shared_flow_paths']['F5']
        self._pin_mode=_pin_feedback_applicable(f2, f5)
        self._handle=install_shared_slot_ram_consumer(runtime)
        if self._pin_mode:self._pin_handle=install_shared_slot_pin_consumer(runtime)
        self._runtime=runtime
        self._bound_sources=deepcopy(runtime.runtime_path_admission['shared_flow_paths'])

    def view(self,ram,pin):
        rg,rs=ram_view(ram,self._report,values=self.space.values)
        if not self._pin_mode:
            return rg,rs
        # Historical semantic novelty never certifies the currently installed
        # writer version. Only an authenticated read of this exact resource can
        # satisfy the current consumption frontier.
        current_values=set()
        if (pin.get('status')=='observed' and pin.get('enabled') is True
                and pin.get('writer_attributed') is True and pin.get('resource_identity')):
            keys=('component','pin','reset_epoch','value','resource_identity','writer_case_id')
            current_values={r['value'] for r in self._pin_relations
                if r.get('status')=='verified' and r.get('reward_eligible') is True
                and all(r.get(k)==pin.get(k) for k in keys)}
        pg,ps=pin_view(pin,values=self.values,completed_values=current_values)
        # Never relabel either component's epoch. An unaligned domain stays
        # unknown under Snapshot.get rather than claiming a shared horizon.
        epoch=max(rs.epoch,ps.epoch)
        goal=Goal('shared:RAM-PADIN','shared:consumed',rg.conditions+pg.conditions+(
            Condition('shared:consumed',(rg.root,pg.root),'all'),))
        observations={k:v for s in (rs,ps) for k,v in s.observations.items()}
        return goal,Snapshot(epoch,observations)

    def choose(self):
        if self.pending is not None or self._handle is None:raise ValueError('attached idle shared selector required')
        self._started=perf_counter_ns()
        self._before=self._handle.current_state();self._pin_before=(self._pin_handle.current_state()
            if self._pin_mode else {'status':'unknown'})
        goal,snapshot=self.view(self._before,self._pin_before)
        decision=self.scheduler.choose(goal,snapshot,self.catalog)
        row=self._records[decision.action_id]
        self._decision_seconds.append(max(0,perf_counter_ns()-self._started)/1e9)
        self.pending=(row,decision)
        return row

    def checkpoint(self):
        return deepcopy((self.scheduler,self.credit,self.pin_credit))

    def restore(self,checkpoint):
        self.scheduler,self.credit,self.pin_credit=checkpoint;self.pending=None

    def invalidate_ram(self,current):
        identity=ram_identity(current);settlements=[]
        for key,row in list(self.credit.pending.items()):
            if identity is None or row['resource']!=identity:
                settlements.append(self.scheduler.settle(key,{},self.credit.costs[key],censored=True))
                del self.credit.pending[key]
        self.credit.writers={k:r for k,r in self.credit.writers.items() if identity is not None and r['resource']==identity}
        return settlements

    def settle(self,row):
        from myfuzz.integration.shared_f6_slots import flow_records
        if self.pending is None or self.pending[0]!=row:raise ValueError('unexpected shared completed record')
        records=flow_records(self._runtime);sealed=records[-1]
        if (sealed['status']!='passed' or sealed['flow']!=row[:2]
                or sealed['raw_hex']!=row[3:] or len(records)!=len(self.sequence)+1):
            raise ValueError('sealed shared record required')
        case_id=sealed['case_id'];decision=self.pending[1];family=row[:2]
        current=self._handle.current_state();pin=(self._pin_handle.current_state()
            if self._pin_mode else {'status':'unknown'})
        measured=max(1,perf_counter_ns()-self._started)
        cost=measured if self._replay_costs is None else self._replay_costs[len(self.sequence)][0]
        invalidated=self.invalidate_ram(current)
        relations=[]
        if family in ('F1','F3'):
            report=self._handle.observe_case(case_id)
            settlement=self.credit.observe(decision,case_id,current,report,cost)
            self._report=report;relations=report['relations']
            keys={semantic_relation(r) for r in relations if r.get('reward_eligible') is True}
        elif family in ('F2','F5') and self._pin_mode:
            opaque=self._pin_handle.observe_case(case_id)
            document,settlement=self.pin_credit.observe(self._pin_handle,decision,case_id,opaque,cost)
            relations=document['relations']
            if relations:self._pin_relations=deepcopy(relations)
            keys={pin_relation(r) for r in relations if r.get('reward_eligible') is True}
            self._completed_values.update(r['value'] for r in relations if r.get('reward_eligible') is True)
        else:
            settlement=dict(settlements=[self.scheduler.settle(decision.id,{},cost,censored=True)],credited_relations=[],pending=[])
            keys=set()
        settlement['settlements']=invalidated+settlement['settlements']
        final_measured=max(measured,perf_counter_ns()-self._started)
        final_cost=final_measured if self._replay_costs is None else self._replay_costs[len(self.sequence)][1]
        self.scheduler.finalize_cost(decision.id,final_cost)
        if family in ('F1','F3'):self.credit.costs[decision.id]=final_cost
        elif family in ('F2','F5') and self._pin_mode:self.pin_credit.costs[decision.id]=final_cost
        if self._clock is None:raise ValueError('actual campaign clock missing')
        seconds=max(0,self._clock()-self._clock_started);new=keys-self._certified_seen
        self._certified_seen.update(keys)
        self._certified_events.extend(dict(seconds=seconds,semantic_key=k) for k in sorted(new))
        if new:self._useful_events.append(dict(seconds=seconds,case_id=case_id))
        self.transitions.append(dict(case_id=case_id,flow=family,state_status=current['status'],
            value=current.get('value'),writer_case_ids=current.get('writer_case_ids',[]),
            writer_attributed=current.get('writer_attributed',False),pin_state_status=pin['status'],
            pin_value=pin.get('value'),pin_writer_case_id=pin.get('writer_case_id'),
            policy_cost_ns=final_cost,settlement_cost_ns=cost,credited_relations=settlement['credited_relations'],
            settlements=settlement['settlements'],pending=sorted(self.credit.pending)+sorted(self.pin_credit.pending),
            **({'target_consumption':deepcopy(sealed['certificate'].get('current_version_consumption'))}
               if family=='F2' and not self._pin_mode else {})))
        self._measured_costs.append(final_measured);self.sequence.append(row);self.decisions.append(decision.document());self.pending=None

    def finish(self):
        if self._terminal is None:self._terminal=dict(RAM=self.credit.finish(),PIN=self.pin_credit.finish())
        return deepcopy(self._terminal)

    def document(self):
        doc=super().document()
        doc.update(search_backend='live-shared-ram-pin' if self._pin_mode else 'live-shared-ram-target',
            provider='installed_shared_slot_ram_and_PADIN.v1' if self._pin_mode else 'installed_shared_slot_ram.v1',
            proof_scope='host_RAM_versions_over_native_OBI_and_native_GPIO_PADIN' if self._pin_mode else 'host_RAM_versions_over_native_OBI',
            irq_consumption='unknown',compiled_source_bindings=deepcopy(self._bound_sources))
        return doc

    def measurements(self,*,mode):
        result=super().measurements(mode=mode)
        result.update(schema_version='shared_slot_search_measurements.v1',
            proof_scope='host_RAM_versions_over_native_OBI_and_native_GPIO_PADIN' if self._pin_mode else 'host_RAM_versions_over_native_OBI')
        return result
