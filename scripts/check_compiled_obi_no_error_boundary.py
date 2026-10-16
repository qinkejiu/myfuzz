#!/usr/bin/env python3
"""Explicit native diagnostic: inject backend ERR at generated CPU boundary.

This command builds/runs native RTL, requires the canonical project heavy lock,
and never serves as an F4 semantic success gate. No network operation occurs.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from myfuzz.integration.compiled_execution_files import (
    prepare_compiled_execution_files,_worker_lock,_source_paths,_hashes,_unchanged,_save)
from myfuzz.integration.compiled_f4 import admit_f4,_cpu_error_policy,_cpu_traces
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.local_harness.wire import MAX_REPLY_LINE_BYTES,parse_driver_ready,parse_driver_receipt,parse_driver_ack
from myfuzz.scenario.protocol_io import BoundedLineReader,command_deadline,write_local_command


def run(args):
    base=Path(args.base_dir).resolve();output=Path(args.output_dir)
    if output.exists() or output.is_symlink():raise ValueError('output-directory-must-be-new')
    output.mkdir(parents=True);output=output.resolve();marker=output/'.incomplete';marker.touch()
    arguments=(base,Path(args.compose),tuple(Path(p) for p in args.ip_capability),Path(args.supplement),None)
    paths=_source_paths(*arguments);hashes=_hashes(paths)
    diagnostic_path=Path(__file__).resolve();diagnostic_hashes=_hashes([diagnostic_path])
    _save(output/'source_input_hashes.json',hashes|diagnostic_hashes)
    def unchanged():
        _unchanged(paths,hashes,arguments)
        if _hashes([diagnostic_path])!=diagnostic_hashes:raise ValueError('diagnostic-source-changed')
    report=dict(status='incomplete',scope='generated_no_error_CPU_boundary_backend_ERR_fail_stop_only',
        heavy_lock=str(Path(args.heavy_lock).resolve()),native_executed=False)
    proc=None;transcript=[]
    try:
        with _worker_lock(Path(args.heavy_lock)):
            unchanged()
            artifacts,inputs,_=prepare_compiled_execution_files(base_dir=base,compose_path=args.compose,
                capability_paths=args.ip_capability,supplement_path=args.supplement,generated_dir=output/'generated')
            path=admit_f4(artifacts=artifacts,compiled_inputs=inputs)
            image=next(s for s in path['sources'] if s['kind']=='instruction_image')
            stream=next(s for s in path['sources'] if s['kind']=='cpu_mmio_stream')
            artifact=artifacts[image['component']];policy=_cpu_error_policy(artifact,image,stream)
            if policy['mode']!='fail_stop_no_error_pin':raise ValueError('no-error-ABI-required')
            report['policy']=policy
            signals=_cpu_traces(artifact,image,stream)['instr']
            binary=build_local_harness(artifact,base_dir=base,cache_dir=Path(args.cache_dir))
            unchanged()
            digest,asserted,released,kind=GeneratedLocalSession(artifact,base_dir=base,
                cache_dir=Path(args.cache_dir))._expected_ready()
            execution=uuid.uuid4().hex;reader=BoundedLineReader(max_line_bytes=MAX_REPLY_LINE_BYTES)
            with (output/'native.stderr').open('w') as stderr:
                proc=subprocess.Popen([str(binary)],cwd=base,stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=stderr,text=True,bufsize=1)
                report.update(native_executed=True,pid=proc.pid,execution_nonce=execution)
                try:
                    with command_deadline(time.monotonic()+args.command_timeout):ready=reader.readline(proc.stdout)
                    transcript.append(dict(direction='stdout',line=ready));parse_driver_ready(ready.strip(),
                        digest=digest,assert_ticks=asserted,release_ticks=released)
                    accepted=None;current_tick=0
                    for sequence in range(1,args.max_rounds+1):
                        unchanged()
                        # Accept a real first instruction request, then inject ERR for that backend response.
                        values=(0,1 if accepted is None else 0,0 if accepted is None else 1,0,
                            0 if accepted is None else 1,0,0,0,0)
                        line=f'CMD {execution} {sequence:x} STEP_CPU '+' '.join(f'{v:x}' for v in values)+'\n'
                        transcript.append(dict(direction='stdin',line=line))
                        if accepted is not None:
                            report['injection']=dict(sequence=sequence,accepted=accepted,backend='instruction',error=1)
                        with command_deadline(time.monotonic()+args.command_timeout):
                            write_local_command(proc.stdin,line);reply=reader.readline(proc.stdout)
                        transcript.append(dict(direction='stdout',line=reply))
                        if accepted is not None:
                            # Any successful STEP reply after ERR violates the expected fail-stop boundary.
                            if reply.startswith('RESULT '):raise ValueError('backend-ERR-returned-success-receipt')
                            break
                        receipt=parse_driver_receipt(reply.strip(),execution=execution,sequence=sequence,
                            current_tick=current_tick,kind=kind,clock_schedule=artifact.runtime_document['clock_schedule'])
                        current_tick=receipt.tick_after
                        if receipt.status!='result':raise ValueError('pre-injection-driver-error')
                        pre=receipt.payload['pre_backend']
                        if pre['i_req_valid']==1 and pre['i_req_ready']==1:
                            taps=receipt.payload['samples'][0]['pre']['protocol_taps']
                            if (taps.get(signals['req'])!=1 or taps.get(signals['gnt'])!=1
                                    or taps.get(signals['addr'])!=pre['i_req_addr']):
                                raise ValueError('backend-acceptance-missing-native-CPU-handshake')
                            accepted=dict(sequence=sequence,address=pre['i_req_addr'],tick_before=receipt.tick_before,
                                protocol_taps=receipt.payload['samples'][0]['pre']['protocol_taps'])
                        _save(output/'raw_transcript.json',transcript)
                        if sequence%16==0:
                            ack=f'ACK {execution} {sequence:x}\n'
                            transcript.append(dict(direction='stdin',line=ack))
                            with command_deadline(time.monotonic()+args.command_timeout):
                                write_local_command(proc.stdin,ack);reply=reader.readline(proc.stdout)
                            transcript.append(dict(direction='stdout',line=reply))
                            parse_driver_ack(reply.strip(),execution=execution,sequence=sequence,current_tick=current_tick)
                    else:raise ValueError('no-native-instruction-acceptance-within-budget')
                    report['returncode']=proc.wait(timeout=args.command_timeout)
                    while True:
                        with command_deadline(time.monotonic()+args.command_timeout):tail=reader.readline(proc.stdout)
                        if not tail:break
                        transcript.append(dict(direction='stdout_tail',line=tail))
                    _save(output/'raw_transcript.json',transcript)
                    fatal='OBI backend error cannot be represented'
                    text=''.join(row['line'] for row in transcript)+(output/'native.stderr').read_text()
                    if report['returncode']==0 or fatal not in text:raise ValueError('missing-native-fatal-or-nonzero-exit')
                    unchanged()
                    report.update(status='completed',fail_stop_observed=True)
                finally:
                    if proc.poll() is None:proc.kill();proc.wait()
                    report['actual_close_returncode']=proc.poll()
                    _save(output/'raw_transcript.json',transcript)
                    _save(output/'report.json',report)
        marker.unlink();return report
    except BaseException as error:
        report.update(error_type=type(error).__name__,error=str(error))
        _save(output/'report.json',report)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('base-dir','compose','supplement','output-dir','cache-dir','heavy-lock'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--ip-capability',action='append',required=True)
    parser.add_argument('--max-rounds',type=int,default=256)
    parser.add_argument('--command-timeout',type=float,default=30)
    args=parser.parse_args()
    if not 1<=args.max_rounds<=4096 or not 0<args.command_timeout<=300:parser.error('bounded budgets required')
    run(args)
