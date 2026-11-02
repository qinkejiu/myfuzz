#!/usr/bin/env python3
"""Observe the unchanged eight-case all-flow descriptor and complete fresh replay."""
import argparse
import json
import os
from pathlib import Path
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path)
    parser.add_argument('--base-root',type=Path,default=Path.cwd())
    parser.add_argument('--descriptor',type=Path,
        default=Path('configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared/generic_scenario.json'),
        help='Scenario descriptor for the same eight-case workload.')
    parser.add_argument('--native',action='store_true',required=True)
    parser.add_argument('--fetch-scan-mode',choices=('legacy','snapshot'),default='snapshot',
        help='Same-source A/B journal reading mode; all proof checks remain enabled.')
    parser.add_argument('--topology-validation-mode',choices=('legacy','boundary'),default='boundary',
        help='Same-source A/B topology validation policy; full boundary checks remain enabled.')
    parser.add_argument('--dut-eval',action='store_true',help='Enable existing native eval counters/timers; use the same option for both compared runs.')
    args=parser.parse_args();base=args.base_root.resolve()
    sys.path.insert(0,str(base/'src'));sys.path.insert(0,str(base))
    from myfuzz.integration.runtime_benchmark import RuntimeTimings,workload_identity
    from scripts.run_shared_all_flows import AllFlowWitness,RECORDS
    from myfuzz.runtime.generic_campaign import load_descriptor,run_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime,f6_topology_validation_scope
    from myfuzz.scenario.f6_instruction_fetch_receipt import f6_instruction_fetch_scan_scope
    if args.output.exists():raise ValueError('benchmark output must not exist')
    args.output.mkdir(parents=True)
    native_dir=args.output/'native-eval'
    prior=os.environ.get('MYFUZZ_DUT_TIMING_DIR')
    if args.dut_eval:
        native_dir.mkdir();os.environ['MYFUZZ_DUT_TIMING_DIR']=str(native_dir.resolve())
    timing=RuntimeTimings();started=time.monotonic();summary=None;failure=None
    try:
        descriptor=load_descriptor(base/args.descriptor,base_dir=base)
        targets=dict(preparation=create_preparation,construct=CompiledF6Runtime.__init__,
            begin=CompiledF6Runtime.begin,submit=CompiledF6Runtime.submit,finish=CompiledF6Runtime.finish,
            fresh_replay=CompiledF6Runtime.replay,selector_settle=AllFlowWitness.settle)
        with f6_topology_validation_scope(args.topology_validation_mode), f6_instruction_fetch_scan_scope(args.fetch_scan_mode), timing.observe(targets):
            summary=run_descriptor(descriptor,flow='mixed',mode='original',case_root=args.output/'workload',
                base_dir=base,cache_dir=args.cache,sequence=list(RECORDS),record_selector=AllFlowWitness(),
                selected_count=len(RECORDS),execution_case_capacity=len(RECORDS))
        if (summary['case_count']!=len(RECORDS) or summary['f6_case_count']!=2
                or set(summary['flow_case_counts'])!={'F1','F2','F3','F4','F5','F6'}
                or summary['replay_matches'] is not True):
            raise ValueError('unchanged eight-case all-flow workload and full fresh replay required')
    except BaseException as error:
        failure=dict(type=type(error).__name__,reason=str(error));raise
    finally:
        wall=time.monotonic()-started
        if args.dut_eval:
            if prior is None:os.environ.pop('MYFUZZ_DUT_TIMING_DIR',None)
            else:os.environ['MYFUZZ_DUT_TIMING_DIR']=prior
        report=timing.document(wall_seconds=wall)
        report.update(status='failed' if failure else 'complete',failure=failure,
            summary=summary,requested_records=list(RECORDS),workload='scripts.run_shared_all_flows.RECORDS',
            native_eval_timers_enabled=args.dut_eval,fetch_scan_mode=args.fetch_scan_mode,
            topology_validation_mode=args.topology_validation_mode,
            wall_timing_scope='descriptor_load_through_scope_exit_before_identity_export',
            invocation_note='fresh marks enclosing replay scope, including replay validation and its nested initialization/finish; spans overlap.')
        try:
            evidence=args.output/'workload/original'
            if (evidence/'prefix.json').is_file():
                prefix=json.loads((evidence/'prefix.json').read_text());report['original_identity']=workload_identity(prefix)
                phases={'original':prefix.get('original_execution_audit',{}).get('identities',{})}
                if (evidence/'replay.json').is_file():
                    replay=json.loads((evidence/'replay.json').read_text())
                    actual=replay.get('actual_prefix')
                    if actual is not None:report['fresh_identity']=workload_identity(actual)
                    report['fresh_matches']=replay.get('matches')
                    phases['fresh']=replay.get('execution_audit',{}).get('identities',{})
                evals={}
                for phase,identities in phases.items():
                    evals[phase]={}
                    for component,identity in identities.items():
                        pid=identity.get('pid');file=native_dir/f'dut-timing-{pid}.json'
                        if args.dut_eval and type(pid) is int and file.is_file():
                            doc=json.loads(file.read_text())
                            if doc.get('schema_version')!='dut_eval_timing.v1' or doc.get('pid')!=pid:
                                raise ValueError('native eval counter/process identity mismatch')
                            evals[phase][component]=dict(status='observed',**doc)
                        else:evals[phase][component]=dict(status='unavailable',reason='counter not emitted or native eval timing disabled')
                report['native_eval']=evals
        except (OSError,ValueError,KeyError,TypeError) as diagnostic:
            report['identity_export_error']=dict(type=type(diagnostic).__name__,reason=str(diagnostic))
        (args.output/'performance.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(status='complete',report=str(args.output/'performance.json'),wall_seconds=wall)))


if __name__=='__main__':main()
