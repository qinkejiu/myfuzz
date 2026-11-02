#!/usr/bin/env python3
"""Run the opt-in shared F1/F3/F4/F5 session and an actual full fresh replay."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


def require_full_fresh_match(replay):
    if (type(replay) is not dict or replay.get('matches') is not True
            or replay.get('verification_scope') != 'full'
            or not replay.get('expected_semantic_hash')
            or replay.get('expected_semantic_hash') != replay.get('actual_semantic_hash')):
        raise ValueError('shared-F5-full-fresh-prefix-mismatch')
    return {key:replay.get(key) for key in ('matches','verification_scope','first_difference',
        'expected_semantic_hash','actual_semantic_hash')}


def save_raw_trace(path,trace):
    import gzip
    with gzip.open(path,'wt',encoding='utf-8') as stream:
        stream.write('{"status":'+json.dumps(trace.status)+',"local_ticks":'+json.dumps(trace.local_ticks)+',"events":[')
        for index,event in enumerate(trace.events):
            if index:stream.write(',')
            json.dump(event,stream,sort_keys=True,separators=(',',':'))
        stream.write(']}')


def require_irq_chain(plan):
    """Accept either registered anchor: an exact serial or a real IRQ acceptance.

    A full-RVFI CPU binds the take to a passive serial token; a partial-RVFI CPU
    (only valid/order/insn/pc_rdata) has no serial, so its anchor is the real
    pre-edge acceptance plus the entry retirement it must also produce.  Both
    shapes still require the exact provider acceptance and real bootstrap MMIO.
    """
    evidence=plan.get('irq_dependency_evidence',{})
    counts=evidence.get('counts',{})
    verified=[r for r in plan['records'] if r.get('flow')=='F5'
        and r['certificate'].get('irq_isr',{}).get('status')=='verified'
        and r['certificate']['irq_isr'].get('certificates')]
    limited=any(type(c.get('entry_retirement')) is dict for r in verified
        for c in r['certificate']['irq_isr']['certificates'])
    serial=counts.get('cpu_retirement_serial',0)>=1
    accepted=counts.get('irq_acceptance',0)>=1
    if (not verified or not accepted or not (serial or limited)
            or not plan.get('irq_bootstrap',{}).get('actual_MMIO_events')):
        raise ValueError('shared-F5-native-IRQ-ISR-chain-not-verified')
    return dict(status='verified',certified_cases=[r['certificate']['case_id'] for r in verified],
        native_provider_counts=counts,proof_scope='single_GPIO_native_IRQ_ISR',reward_eligible=False,
        acceptance_anchor='exact_serial_token' if serial else 'native_pre_edge_acceptance_and_entry_retirement')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=Path,required=True)
    parser.add_argument('--cache',type=Path,default=Path('/tmp/myfuzz-shared-f5-cache'))
    parser.add_argument('--config',type=Path,
        default=ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared',
        help='scenario directory holding compose/compose_irq and execution_supplement.json')
    parser.add_argument('--sequence',choices=('F4-F5-F4','F1-F5'),default='F4-F5-F4')
    parser.add_argument('--record',action='append',default=[],help='explicit FLOW:hex in execution order')
    parser.add_argument('--rounds',type=int,default=128)
    parser.add_argument('--fresh',action='store_true')
    parser.add_argument('--irq-firmware',action='store_true',help='explicit authenticated CPU bootstrap and single-GPIO ISR')
    parser.add_argument('--enable-f2',action='store_true',help='explicitly prepare the GPIO PADIN read consumer')
    args=parser.parse_args()
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    try:
        with host_source_discovery_scope(reuse_nested=True), harness_validation_scope(), execution_validation_scope():
            summary=run(args)
    except BaseException as error:
        if args.case.is_dir():
            (args.case/'failure.json').write_text(json.dumps(
                {'type':type(error).__name__,'error':str(error)},sort_keys=True,indent=2)+'\n')
        raise
    # Scope exit revalidates the pinned producers before publishing success.
    (args.case/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print(json.dumps(summary,sort_keys=True))
    return 0


def run(args):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f4 import CompiledF4Runtime
    config=getattr(args,'config',None) or ROOT/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    config=Path(config).resolve()
    if not config.is_relative_to(ROOT) or not config.is_dir():
        raise ValueError('shared-F5-scenario-directory-required')
    args.case.mkdir(parents=True,exist_ok=False)
    context=runtime=None
    def save(name,value):
        (args.case/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    try:
        context=create_preparation(base_dir=ROOT,compose_path=config/('compose_irq.json' if getattr(args,'irq_firmware',False) else 'compose.json'),
            capability_paths=(ROOT/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
            supplement_path=config/'execution_supplement.json',generated_dir=args.case/'generated',
            flow_ids=('F1','F2','F3','F4','F5') if args.enable_f2 else ('F1','F3','F4','F5'))
        records=[]
        for row in args.record:
            flow,raw=row.split(':',1)
            if flow not in (('F1','F2','F3','F4','F5') if args.enable_f2 else ('F1','F3','F4','F5')):
                raise ValueError('shared GPIO F2/F6 consumer is unsupported')
            records.append((flow,bytes.fromhex(raw)))
        count=len(records) or len(args.sequence.split('-'))
        runtime=CompiledF4Runtime(artifacts=context.artifacts,compiled_inputs=context.compiled_inputs(),
            base_dir=ROOT,cache_dir=args.cache,run_id='shared-f5',rounds_per_case=args.rounds,
            max_cases=count,mixed_flows=True,memory_flows=True,f5_preparation=context,
            irq_firmware=getattr(args,'irq_firmware',False))
        if not records:
            values={s.source_id:(0x100 if s.kind=='cpu_mmio_stream' else 0) for s in runtime.layout.slices}
            f4=runtime.layout.encode(values)
            defaults={'F4':f4,'F5':bytes.fromhex('0000000100000000'),'F1':bytes.fromhex('13000000')}
            records=[(flow,defaults[flow]) for flow in args.sequence.split('-')]
        save('records.json',[flow+':'+raw.hex() for flow,raw in records])
        save('topology.json',runtime.f5_crosswalk)
        for index,(flow,raw) in enumerate(records):
            runtime.submit(raw,flow=flow,testcase_id=f'shared-case-{index}')
        plan=runtime.finish()
        save('prefix.json',plan)
        if getattr(args,'irq_firmware',False):save_raw_trace(args.case/'trace.json.gz',runtime.trace)
        save('execution-audit.json',runtime.execution_audit())
        summary={'status':'complete','flows':[flow for flow,_ in records],
                 'case_count':len(runtime.records),'irq_consumption':'unknown',
                 'unsupported_flows':['F6'] if args.enable_f2 else ['F2','F6']}
        if getattr(args,'irq_firmware',False):
            summary['irq_chain']=require_irq_chain(plan)
            summary['irq_consumption']='verified'
        if args.fresh:
            replay=runtime.replay(plan,audit_sink=lambda value:save('fresh-audit.json',value))
            save('fresh.json',replay)
            summary['fresh']=require_full_fresh_match(replay)
        return summary
    except BaseException as error:
        save('failure.json',{'type':type(error).__name__,'error':str(error)})
        raise
    finally:
        if runtime is not None and not runtime.finished:
            runtime.session.finish()
        if context is not None:context.close()


if __name__=='__main__':
    raise SystemExit(main())
