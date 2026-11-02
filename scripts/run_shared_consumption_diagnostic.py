#!/usr/bin/env python3
"""Directed native RAM/PIN credit diagnostics on the existing shared executor.

This is a fixed-action diagnostic, never a uniform-policy comparison. The
original Policy still creates every decision and performs every settlement;
only its action-selection entropy is explicitly scripted.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))
from myfuzz.search.shared_slot_ram_adapter import SharedSlotSelector

RAM_WRITE='F3:55000000';RAM_READ='F1:03200000'
PIN_HIGH='F5:0000000100000000';PIN_LOW='F5:0000000000000000';PIN_READ='F2:08100040'
PLANS=dict(ram=(RAM_WRITE,RAM_READ,'F3:aa000000',RAM_WRITE,RAM_READ,RAM_WRITE,RAM_READ),
    pin=('F4:0001000000',PIN_HIGH,PIN_READ,PIN_HIGH,PIN_READ,PIN_LOW,PIN_READ,PIN_READ),
    **{'reset-ram':(RAM_WRITE,RAM_READ),'reset-pin':('F4:0001000000',PIN_HIGH,PIN_READ)})
CATALOG=(RAM_WRITE,'F3:aa000000',RAM_READ,'F4:0001000000',PIN_HIGH,PIN_LOW,PIN_READ,'F6:0110c00008000000')


def save(path,document):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(document,indent=2,sort_keys=True)+'\n')


class _DirectedEntropy:
    def __init__(self,value):self.value=value
    def getrandbits(self,bits):
        if bits!=128:raise ValueError('diagnostic requires original policy entropy width')
        return self.value


class ResetProbeComplete(RuntimeError):pass


def validate_step(step,*,last_ram,last_pin):
    family=step['record'][:2];case_id=step['case_id'];ram=step['RAM'];pin=step['PIN']
    if family=='F3':
        if (ram.get('status')!='observed' or ram.get('writer_attributed') is not True
                or ram.get('writer_case_ids')!=[case_id]*4):
            raise ValueError('native_RAM_writer_current_required')
    elif family=='F1':
        relations=step['report'].get('relations',[])
        if len(relations)!=1 or step['report'].get('status')!='verified':
            raise ValueError('native_RAM_read_relation_required')
        if relations[0].get('writer_case_ids')!=[last_ram]*4 or relations[0].get('read_case_id')!=case_id:
            raise ValueError('latest_RAM_writer_required')
    elif family=='F5':
        if (pin.get('status')!='observed' or pin.get('writer_attributed') is not True
                or pin.get('writer_case_id')!=case_id):
            raise ValueError('native_PIN_writer_current_required')
    elif family=='F2':
        relations=step['report'].get('relations',[])
        if len(relations)!=1 or step['report'].get('status')!='verified':
            raise ValueError('native_PIN_read_relation_required')
        if relations[0].get('writer_case_id')!=last_pin or relations[0].get('read_case_id')!=case_id:
            raise ValueError('latest_PIN_writer_required')


class DirectedConsumptionSelector(SharedSlotSelector):
    def __init__(self,name,*,output=None,reset_policy='warm_all'):
        self.plan=PLANS[name];self.name=name;self.output=Path(output) if output else None
        self.steps=[];self._last_ram=self._last_pin=None;self._semantic_seen=set()
        self.reset_policy=reset_policy;self.reset_report=None
        super().__init__(None,flow='mixed',records=CATALOG,policy='uniform',seed=7,cases=len(self.plan))

    def attach_runtime(self,runtime):
        program=runtime.contract['program_contract']
        if program['slot_count']<len(self.plan):raise ValueError('diagnostic_actual_slot_capacity')
        # Runtime contract compilation already validates instruction/ISR/image
        # disjointness. Keep the concrete accepted layout in diagnostic evidence.
        self.accepted_layout=deepcopy(program)
        super().attach_runtime(runtime)

    def choose(self):
        index=len(self.sequence)
        if index>=len(self.plan):raise ValueError('diagnostic sequence exhausted')
        record=self.plan[index]
        action_id,= [key for key,value in self._records.items() if value==record]
        eligible=sorted(self.catalog.actions,key=lambda a:a.id)
        position=next(i for i,a in enumerate(eligible) if a.id==action_id)
        self.scheduler._rng=_DirectedEntropy(position<<64)
        chosen=super().choose()
        if chosen!=record:raise ValueError('diagnostic source selection mismatch')
        return chosen

    def settle(self,record):
        before=deepcopy(dict(RAM=self._before,PIN=self._pin_before))
        old_pending=deepcopy(self.credit.pending)
        super().settle(record)
        case_id=self.transitions[-1]['case_id'];family=record[:2]
        report=(deepcopy(self._report) if family in ('F1','F3') else
            self._pin_handle.audit()[-1] if family in ('F2','F5') else {'relations':[]})
        step=dict(record=record,case_id=case_id,before=before,
            RAM=self._handle.current_state(),PIN=self._pin_handle.current_state(),
            report=report,transition=deepcopy(self.transitions[-1]))
        # Preserve the actual failing state before any diagnostic assertion.
        self.steps.append(step)
        self._export()
        validate_step(step,last_ram=self._last_ram,last_pin=self._last_pin)
        from myfuzz.search.ram_actions import ram_identity
        current_identity=ram_identity(step['RAM'])
        for key,prior in old_pending.items():
            if prior['resource']!=current_identity:
                censored=[r for r in step['transition']['settlements']
                    if r['decision_id']==key and r['censored'] is True and r['reward'] is None]
                if key in self.credit.pending or len(censored)!=1:
                    raise ValueError('overwritten_RAM_writer_must_be_censored')
        if family=='F3':self._last_ram=case_id
        if family=='F5':self._last_pin=case_id
        credited=set(step['transition']['credited_relations'])
        if family in ('F1','F2'):
            from myfuzz.search.ram_actions import semantic_relation as ram_feature
            from myfuzz.search.pin_case_adapter import semantic_relation as pin_feature
            feature=ram_feature if family=='F1' else pin_feature
            certified={feature(r) for r in report['relations']
                if r.get('status')=='verified' and r.get('reward_eligible') is True}
            if credited!=certified-self._semantic_seen:
                raise ValueError('native_relation_must_settle_once_with_actual_credit')
        if credited & self._semantic_seen:raise ValueError('duplicate semantic relation rewarded')
        self._semantic_seen.update(credited)
        # Same-value writes must acquire a new actual version/admission identity.
        if family=='F3' and before['RAM'].get('status')=='observed':
            if before['RAM'].get('byte_resources')==step['RAM'].get('byte_resources'):
                raise ValueError('RAM_overwrite_must_change_actual_version')
        if family=='F5' and before['PIN'].get('writer_attributed'):
            if before['PIN'].get('resource_identity')==step['PIN'].get('resource_identity'):
                raise ValueError('PIN_new_writer_must_change_actual_admission')
        self._export()
        if self.name.startswith('reset-') and len(self.sequence)==len(self.plan):self._reset_probe()

    def _export(self):
        if self.output is not None:
            save(self.output,dict(schema_version='shared_consumption_diagnostic.v1',
                diagnostic='directed-native-consumption',plan=list(self.plan),
                random_strategy_experiment=False,selection=self.document(),steps=self.steps,
                accepted_program=getattr(self,'accepted_layout',None),reset=self.reset_report))

    def _apply_reset(self):
        return self._runtime.runner.reset_all(self.reset_policy)

    def _reset_probe(self):
        runner=self._runtime.runner
        before=dict(RAM=self._handle.current_state(),PIN=self._pin_handle.current_state())
        start=runner.event_count
        epochs_before={name:local.reset_epoch for name,local in runner.sessions.items()}
        reset=self._apply_reset()
        after=dict(RAM=self._handle.current_state(),PIN=self._pin_handle.current_state())
        ram=self._handle.observe_case(self.steps[-1]['case_id'])
        from myfuzz.search.shared_slot_pin_read import authenticated_report
        # Reset may invalidate the opaque provider entirely; that is a refusal,
        # not permission to project an old certificate into the new epoch.
        try:pin=authenticated_report(self._pin_handle,self._pin_handle.observe_case(self.steps[-1]['case_id']))
        except ValueError:pin={'status':'unknown','relations':[]}
        if after['RAM'].get('writer_attributed') or after['PIN'].get('writer_attributed'):
            raise ValueError('reset_retained_old_writer')
        if ram.get('relations') or pin.get('relations'):raise ValueError('reset_retained_consumption')
        events=list(runner.events_since(start))
        epochs_after={name:local.reset_epoch for name,local in runner.sessions.items()}
        if (not any(e.get('kind')=='reset_barrier' and e.get('policy')==self.reset_policy for e in events)
                or not all(epochs_after[k]>v for k,v in epochs_before.items())):
            raise ValueError('actual_native_reset_barrier_required')
        self.reset_report=dict(policy=self.reset_policy,result=repr(reset),before=before,after=after,
            epochs_before=epochs_before,epochs_after=epochs_after,
            RAM_report=ram,PIN_report=pin,events=events,
            terminal_probe=True,normal_campaign_completion=False)
        self._export()
        raise ResetProbeComplete('real reset invalidated old writer/consumption; terminal diagnostic')

    def document(self):
        doc=super().document()
        doc['diagnostic']=dict(kind='directed-native-consumption',actions=list(self.plan),
            action_selection='scripted entropy through original Policy.choose',random_strategy_experiment=False)
        return doc


def run(args):
    from myfuzz.runtime.generic_campaign import load_descriptor,run_descriptor
    descriptor=load_descriptor(ROOT/'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json',base_dir=ROOT)
    if args.fresh and args.scenario.startswith('reset-'):raise ValueError('reset probes are terminal; use ram/pin --fresh for strict replay')
    original=None;original_prefix=None
    for mode in ('original','fresh') if args.fresh else ('original',):
        selector=DirectedConsumptionSelector(args.scenario,
            output=args.output/mode/'consumption-diagnostic.json',reset_policy=args.reset_policy)
        if original is not None:selector.replay_costs(original.transitions)
        try:
            summary=run_descriptor(descriptor,flow='mixed',mode=mode,case_root=args.output,
                base_dir=ROOT,cache_dir=args.cache,sequence=list(selector.plan),record_selector=selector,
                selected_count=len(selector.plan),execution_case_capacity=8,rounds=args.rounds,
                execution_mode='acceptance')
        except ResetProbeComplete:
            if selector.reset_report is None:raise
            print('verified terminal reset diagnostic:',selector.output)
            return
        from myfuzz.search.descriptor_search import _prefix_identity
        prefix_identity=_prefix_identity(args.output/mode,'mixed',summary)
        if original_prefix is not None and prefix_identity!=original_prefix:
            raise ValueError('fresh independently observed prefix differs')
        original_prefix=prefix_identity
        save(args.output/mode/'diagnostic-prefix-identity.json',prefix_identity)
        selector._export()
        save(args.output/mode/'selection.json',selector.document())
        if summary.get('case_count')!=len(selector.plan):raise ValueError('incomplete_native_diagnostic')
        if original is not None and selector.document()!=original.document():
            raise ValueError('fresh semantic selection or settlement differs')
        original=selector
    print('verified directed native consumption diagnostic:',args.output)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario',choices=tuple(PLANS),required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path)
    parser.add_argument('--rounds',type=int,default=1024)
    parser.add_argument('--reset-policy',choices=('warm_all','cold_all'),default='warm_all')
    parser.add_argument('--fresh',action='store_true')
    parser.add_argument('--native',action='store_true',required=True)
    run(parser.parse_args())

if __name__=='__main__':main()
