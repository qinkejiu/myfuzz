"""Live pin selection and delayed two-case credit in the common campaign."""
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
from time import perf_counter_ns

from .actions import Action,Catalog
from .model import Condition,Goal,Observation,Snapshot,canonical
from .policy import Policy
from .pin_read import install_pin_consumer,authenticated_report
from .ram_case_adapter import RamRecordSelector


def pin_records(records):
    if not records or any(type(r) is not str or ':' not in r for r in records):return False
    flows=[]
    for row in records:
        flow,raw=row.split(':',1);flows.append(flow)
        if flow not in ('F2','F4','F5') or len(raw)!={'F2':8,'F4':10,'F5':16}[flow]:return False
        if any(c not in '0123456789abcdefABCDEF' for c in raw):return False
    return 'F2' in flows and 'F5' in flows


def semantic_relation(row):
    return 'gpio-pin-PADIN:' + sha256(canonical([row['component'],row['pin'],row['value']])).hexdigest()


def pin_view(field,*,values,completed_values):
    """Pure three-valued pin goal; safe to AND with a separate RAM goal."""
    values=tuple(values)
    if not values or any(type(v) is not int or v not in (0,1) for v in values):
        raise ValueError('bounded pin values required')
    value=next((v for v in values if v not in completed_values),values[0])
    goal=Goal(f'pin:consume:{value}',f'pin:consumed:{value}',(
        Condition('pin:enabled'),Condition(f'pin:written:{value}',('pin:enabled',)),
        Condition(f'pin:consumed:{value}',(f'pin:written:{value}',))))
    observed=field.get('status')=='observed';epoch=field.get('reset_epoch',0)
    snapshot=Snapshot(epoch,{
        'pin:enabled':Observation('satisfied' if observed and field.get('enabled') else 'refuted' if observed and field.get('enabled') is False else 'unknown','enabled' if field.get('enabled') else 'unknown',('installed-PADIN-current',) if observed else (),epoch),
        f'pin:written:{value}':Observation('satisfied' if observed and field.get('writer_attributed') and field.get('value')==value else 'refuted' if observed and field.get('writer_attributed') else 'unknown',str(field.get('value')) if observed else 'unknown',('installed-PADIN-current',) if observed else (),epoch),
        f'pin:consumed:{value}':Observation('satisfied' if value in completed_values else 'unknown','consumed' if value in completed_values else 'unknown',('installed-PADIN-consumption',) if value in completed_values else (),epoch)})
    return goal,snapshot


class PinCredit:
    def __init__(self,policy,*,authenticator=None):
        if authenticator is not None and not callable(authenticator):raise ValueError('pin report authenticator must be callable')
        self.authenticator=authenticator
        self.policy=policy;self.pending={};self.writers={};self.costs={};self.case_decisions={}

    def observe(self,handle,decision,case_id,report,cost):
        document=(authenticated_report if self.authenticator is None else self.authenticator)(handle,report)
        if document.get('read_case_id') not in (None,case_id):raise ValueError('pin report case mismatch')
        self.costs[decision.id]=cost;self.case_decisions[case_id]=decision.id
        writer=document.get('writer')
        if writer is not None:
            self.pending[decision.id]=writer;self.writers[decision.id]=writer
        settlements=[];accepted=[];joined=False
        while len(self.pending)>64:
            oldest=next(iter(self.pending))
            settlements.append(self.policy.settle(oldest,{},self.costs[oldest],censored=True))
            self.pending.pop(oldest);self.writers.pop(oldest,None)
        for row in document['relations']:
            key=self.case_decisions.get(row['writer_case_id'])
            if (row.get('reward_eligible') is not True or row.get('status')!='verified' or row['read_case_id']!=case_id
                    or key not in self.writers or self.writers[key]['resource_identity']!=row['resource_identity']):continue
            participants=(key,decision.id);feature=semantic_relation(row)
            result=self.policy.settle_relation_group(participants,{'relation':(feature,)},{k:self.costs[k] for k in participants})
            if result is None:continue
            settlements.extend(result)
            for k in participants:self.pending.pop(k,None)
            if any(['relation',feature] in r.get('novel_features',()) for r in result):accepted.append(feature)
            joined=True
        if decision.id not in self.pending and not joined:
            settlements.append(self.policy.settle(decision.id,{},cost,censored=document['status']!='verified'))
        return document,dict(settlements=settlements,credited_relations=accepted,pending=sorted(self.pending))

    def finish(self):
        rows=[self.policy.settle(k,{},self.costs[k],censored=True) for k in sorted(self.pending)]
        self.pending.clear()
        return dict(settlements=rows,relation_observation='budget-ended',irq_consumption='unknown')


class PinRecordSelector(RamRecordSelector):
    """Reuse the same clock, budget rollback and fresh cost replay protocol."""
    def __init__(self,descriptor,*,flow,records,policy,seed,cases):
        if flow!='mixed' or not pin_records(records) or not 1<=cases<=4096:
            raise ValueError('bounded typed pin/PADIN catalog required')
        self.rows=list(dict.fromkeys(records));self.values=tuple(sorted({bytes.fromhex(r[3:])[3]&1 for r in self.rows if r.startswith('F5:')}))
        actions=[]
        for i,row in enumerate(self.rows):
            family=row[:2]
            produces=(('pin:enabled',) if family=='F4' else
                (f'pin:written:{bytes.fromhex(row[3:])[3]&1}',) if family=='F5' else tuple(f'pin:consumed:{v}' for v in self.values))
            actions.append(Action(f'pin-record:{i}',family,family,produces,(),(i,)))
        self.catalog=Catalog(tuple(actions));self.scheduler=Policy(seed=seed,mode=policy,max_decisions=cases)
        self.credit=PinCredit(self.scheduler);self.sequence=[];self.decisions=[];self.transitions=[];self.pending=None
        self._runtime=self._handle=None;self._replay_costs=None;self._measured_costs=[];self._terminal=None
        self._clock=self._clock_started=self._clock_finished=None
        self._certified_events=[];self._useful_events=[];self._decision_seconds=[];self._certified_seen=set();self._completed_values=set()
        self._bound_sources=None

    def attach_runtime(self,runtime):
        if self._runtime is not None:raise ValueError('pin runtime already attached')
        self._handle=install_pin_consumer(runtime);self._runtime=runtime
        self._bound_sources=dict(pin_path=deepcopy(runtime.f5_binding.path['runtime_path_identity']),
            PADIN=deepcopy(runtime.producer_binding_f2.document()['register']))

    def choose(self):
        if self.pending is not None or self._handle is None:raise ValueError('attached idle pin selector required')
        self._started=perf_counter_ns();field=self._handle.current_state()
        goal,snapshot=pin_view(field,values=self.values,completed_values=self._completed_values)
        decision=self.scheduler.choose(goal,snapshot,self.catalog);row=self.rows[decision.value]
        self._decision_seconds.append(max(0,perf_counter_ns()-self._started)/1e9);self.pending=(row,decision)
        return row

    def settle(self,row):
        if self.pending is None or row!=self.pending[0]:raise ValueError('unexpected pin completed record')
        decision=self.pending[1];case_id=self._runtime.records[-1]['certificate']['case_id']
        current=self._handle.current_state();report=self._handle.observe_case(case_id)
        measured=max(1,perf_counter_ns()-self._started)
        cost=measured if self._replay_costs is None else self._replay_costs[len(self.sequence)][0]
        document,settlement=self.credit.observe(self._handle,decision,case_id,report,cost)
        final_measured=max(measured,perf_counter_ns()-self._started)
        final_cost=final_measured if self._replay_costs is None else self._replay_costs[len(self.sequence)][1]
        self.scheduler.finalize_cost(decision.id,final_cost);self.credit.costs[decision.id]=final_cost
        if self._clock is None:raise ValueError('actual pin campaign clock missing')
        seconds=max(0,self._clock()-self._clock_started);keys=set()
        for relation in document['relations']:
            key=semantic_relation(relation);self._completed_values.add(relation['value'])
            if key not in self._certified_seen:keys.add(key)
        self._certified_seen.update(keys)
        self._certified_events.extend(dict(seconds=seconds,semantic_key=k) for k in sorted(keys))
        if keys:self._useful_events.append(dict(seconds=seconds,case_id=case_id))
        self.transitions.append(dict(case_id=case_id,state_status=current['status'],value=current.get('value'),
            writer_case_id=current.get('writer_case_id'),writer_attributed=current.get('writer_attributed',False),
            policy_cost_ns=final_cost,settlement_cost_ns=cost,credited_relations=settlement['credited_relations'],
            settlements=settlement['settlements'],pending=settlement['pending'],relation_status=document['status']))
        self._measured_costs.append(final_measured);self.sequence.append(row);self.decisions.append(decision.document());self.pending=None

    def measurements(self,*,mode):
        result=super().measurements(mode=mode)
        result.update(schema_version='pin_search_measurements.v1',proof_scope='native_pin_PADIN_OBI_dependent_RAM',
                      source_origin='actual_F5_admission',irq_consumption='unknown')
        return result

    def document(self):
        return dict(sequence=list(self.sequence),decisions=list(self.decisions),catalog_sha256=self.catalog.identity,
            catalog=[asdict(a) for a in self.catalog.actions],state_observation='live',live_state_conditioned=True,
            search_backend='live-gpio-pin',compiled_source_bindings=deepcopy(self._bound_sources),
            provider='installed_GPIO_PADIN_native_read.v1',proof_scope='native_pin_PADIN_OBI_dependent_RAM',
            irq_consumption='unknown',transitions=deepcopy(self.transitions),terminal_credit=deepcopy(self._terminal),
            statistics=self.scheduler.statistics())

    def evidence(self):return self._handle.audit() if self._handle is not None else []
