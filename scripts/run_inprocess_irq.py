#!/usr/bin/env python3
"""Build and run one profile-selected OBI CPU + APB IRQ exploration."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT))

from scripts.prepare_inprocess_irq_bindings import render_bindings
from scripts.inprocess_build import build_link_run
from scripts.inprocess_feedback import F5_RULE, F5TimerFeedback, feedback_line, trigger_roles
from scripts.run_declared_irq_f5 import case_program
from myfuzz.integration.declared_irq_consumption import build_declared_irq_firmware


def explicit_timing(config, key):
    timing=config.get(key)
    names=('reset_assert_ticks','reset_release_ticks','max_wait_cycles')
    if not isinstance(timing,dict) or any(type(timing.get(name)) is not int for name in names):
        raise ValueError(key+' requires explicit reset_assert_ticks, reset_release_ticks and max_wait_cycles')
    return {name:timing[name] for name in names}


def cpu_request_from_config(config):
    return dict(schema_version='local_harness.v1',profile_path=config['cpu_profile'],
                instance_id='cpu',**explicit_timing(config,'cpu_timing'))


def request_from_profile(config, profile):
    """Make the existing APB request from a profile and explicit timing."""
    timing=explicit_timing(config,'source_timing')
    endpoints=[row for row in profile['endpoints'] if row.get('function')=='mmio_slave'
               and row.get('protocol')==['apb','3']]
    if len(endpoints)!=1:
        raise ValueError('source_profile requires one APB3 MMIO endpoint')
    tuning=dict(config.get('source_tuning', {}))
    tuning.setdefault('endpoint_policies',[dict(endpoint_id=endpoints[0]['endpoint_id'],
        template_id='target.apb3',template_version='1',variant_id='full-word',max_outstanding=1)])
    return dict(schema_version='local_harness.v2',profile_path=config['source_profile'],
                instance_id=config['active_id'],**timing,
                tuning=tuning)


def apply_irq_behavior(config, behavior, *, root):
    """Use an IP's existing IRQ behavior only with its own declared profile."""
    keys=('source_port','source_bit_offset','pulse_width_ticks','trigger_writes',
          'status_offsets','status_registers','clear_writes','status_cause_bits')
    if (behavior.get('schema_version')!='declared_irq_behavior.v1'
            or any(key not in behavior for key in (*keys,'source_request','window_size'))):
        raise ValueError('IRQ behavior description is incomplete')
    request=json.loads((root/behavior['source_request']).read_text())
    profile=config.get('source_profile')
    if profile is None and config.get('source_request'):
        profile=json.loads((root/config['source_request']).read_text())['profile_path']
    if profile!=request['profile_path']:
        raise ValueError('IRQ behavior does not belong to the selected IP profile')
    result=dict(config)
    for key in keys:
        if key in result and result[key]!=behavior[key]:
            raise ValueError('IRQ behavior conflicts with config: '+key)
        result[key]=behavior[key]
    window=dict(base=config['active_base'],size=behavior['window_size'])
    if 'target_window' in result and result['target_window']!=window:
        raise ValueError('IRQ behavior conflicts with target window')
    result['target_window']=window
    return result


def build_case(config, cpu_profile, target_profile, *, boot, behavior=None):
    """Generate the existing firmware using declared CPU/IP behavior."""
    cpu=cpu_profile.cpu
    if (cpu is None or cpu.family.lower()!='riscv' or cpu.xlen!=32
            or 'I' not in {name.upper() for name in cpu.extensions}
            or cpu.irq_semantics!='machine_external' or cpu.irq_entry_polarity!='active_high'):
        raise ValueError('requires RV32I CPU with active-high machine external IRQ')
    if config.get('single_source') is not True:
        raise ValueError('in-process IRQ exploration requires single_source=true')
    address=target_profile.address
    window=config['target_window']
    if address is None or window['base']!=config['active_base'] or window['size']!=address.window_size:
        raise ValueError('target window must match the component profile')
    registers={row.offset:row for row in address.registers}
    offsets=config['status_offsets']
    if len(offsets)!=1 or config.get('clear_writes'):
        raise ValueError('requires one declared status register and no clear writes')
    status=registers.get(offsets[0])
    if status is None or status.width!=32 or status.access not in ('ro','rw'):
        raise ValueError('status register is not declared readable')
    if config.get('status_registers') and config['status_registers'] != [status.name]:
        raise ValueError('status register name differs from the component profile')
    trigger=tuple(tuple(row) for row in config['trigger_writes'])
    if any(offset not in registers or registers[offset].width!=32
           or registers[offset].access not in ('wo','rw') for offset,_ in trigger):
        raise ValueError('trigger register is not declared writable')
    bit=config['source_bit_offset']
    irq=[source for source in target_profile.interrupts
         if (source.bit if source.bit is not None else 0)==bit
         and source.trigger=='pulse' and source.polarity=='active_high']
    endpoints={endpoint.endpoint_id:endpoint for endpoint in target_profile.endpoints}
    irq=[source for source in irq if source.endpoint_id in endpoints
         and any(field.role==source.role and config['source_port'] in field.aliases
                 for field in endpoints[source.endpoint_id].fields)]
    if len(irq)!=1 and (behavior is None or target_profile.interrupts):
        raise ValueError('source IRQ must be declared as one active-high pulse')
    options=dict(active_id=config['active_id'],idle_id=None,trigger_writes=trigger)
    fields=dict(image_start=config['image_start'],image_end=config['image_end'],
                result_address=config['result_address'],target_base=window['base'],
                window_size=window['size'],status_offsets=offsets,clear_writes=())
    firmware=build_declared_irq_firmware(
        image_start=fields['image_start'],image_end=fields['image_end'],first_fetch=boot,
        target_base=fields['target_base'],status_offsets=fields['status_offsets'],
        result_address=fields['result_address'],clear_writes=fields['clear_writes'])
    program=case_program(firmware,options,fields)
    return options,dict(firmware=firmware,program=program)


def build_online_program(firmware, config):
    """A fixed RV32 polling loop reads future MMIO values from RAM."""
    from myfuzz.integration.rv32_fixed_firmware import _lui_addi_load, _lw, _sw, _branch, _jal
    entry=firmware['dynamic_start'];mailbox=entry+0x800
    if mailbox+4*(1+len(config['trigger_writes'])) > firmware['image_end']:
        raise ValueError('online mailbox exceeds RAM')
    words=[*_lui_addi_load(8,config['active_base']),*_lui_addi_load(10,mailbox)]
    poll=entry+4*len(words)
    words.append(_lw(9,10,0))
    words.append(_branch(9,0,poll-(entry+4*len(words))))
    words.append(_sw(0,10,0))
    for index,(offset,_) in enumerate(config['trigger_writes']):
        words.append(_lw(9,10,4+4*index))
        if offset<2048:
            words.append(_sw(9,8,offset))
        else:
            words.extend((*_lui_addi_load(11,config['active_base']+offset),_sw(9,11,0)))
    words.append(_jal(entry+4*len(words),poll))
    if entry+4*len(words)>mailbox:
        raise ValueError('online mailbox overlaps program')
    images={str(row['address']):row['data_hex'] for row in firmware['segments']}
    images[str(entry)]=b''.join(word.to_bytes(4,'little') for word in words).hex()
    return dict(images=images,case_entry=entry,mailbox=mailbox)


def online_runner(count, submitted, feedback=None):
    """Forward on-demand values without restarting either model.

    With a feedback loop the values for every case after the first are derived
    from the previous case's real report; the interactive pipe is then unused
    and the loop stops after the requested number of cases.
    """
    def run(command, log_path):
        with log_path.open('w') as log:
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT,text=True,bufsize=1)
            ending=False
            try:
                for line in process.stdout:
                    log.write(line);log.flush();print(line,end='',flush=True)
                    if feedback is not None: feedback.note(line)
                    if not line.startswith('NEED_RECORD '): continue
                    index=int(line.split()[1])
                    if index!=len(submitted): raise RuntimeError('out-of-order F5 input request')
                    if feedback is not None:
                        if index>=feedback.cases:
                            if not ending:
                                process.stdin.write('END\n');process.stdin.flush();ending=True
                            continue
                        values=feedback.values(index)
                        if feedback.records:
                            note=feedback_line(feedback.records[-1])
                            log.write(note);log.flush();print(note,end='',flush=True)
                        process.stdin.write('CASE '+' '.join(f'{value:08x}' for value in values)+'\n')
                        process.stdin.flush();submitted.append(values);continue
                    while True:
                        user_line=sys.stdin.readline()
                        if not user_line or user_line.strip().upper()=='END':
                            process.stdin.write('END\n');process.stdin.flush();break
                        try:
                            values=[int(part,0) for part in user_line.strip().split(',')]
                            if len(values)!=count or any(not 0<=value<2**32 for value in values):
                                raise ValueError('wrong value count or out-of-range value')
                        except ValueError as error:
                            print('invalid F5 record: '+str(error),file=sys.stderr,flush=True);continue
                        process.stdin.write('CASE '+' '.join(f'{value:08x}' for value in values)+'\n')
                        process.stdin.flush();submitted.append(values);break
                return process.wait()
            finally:
                if process.poll() is None: process.terminate();process.wait()
    return run


def feedback_seed(config, args, trigger_offsets, roles):
    """Resolve the first input: explicit --seed, declared role values, or stdin."""
    declared=config.get('feedback_seed')
    if args.seed is not None:
        values=[int(part,0) for part in args.seed.split(',')]
    elif declared is not None:
        if set(declared)!={'ctrl','cmp','count'}:
            raise ValueError('declared feedback seed requires ctrl, cmp and count')
        if any(type(value) is not int or not 0<=value<2**32 for value in declared.values()):
            raise ValueError('declared feedback seed values must be 32-bit integers')
        role_by_offset={offset:name for name,offset in roles.items()}
        values=[declared[role_by_offset[offset]] for offset in trigger_offsets]
    else:
        user_line=sys.stdin.readline()
        if not user_line: raise ValueError('feedback requires a seed input')
        values=[int(part,0) for part in user_line.strip().split(',')]
    if len(values)!=len(trigger_offsets) or any(not 0<=value<2**32 for value in values):
        raise ValueError('feedback seed must hold one 32-bit value per trigger')
    return values


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--cache',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--max-ticks',type=int,default=3000)
    p.add_argument('--online',action='store_true',help='read comma-separated trigger values per case until END')
    p.add_argument('--feedback',action='store_true',
                   help='derive every case after the first from the previous real report')
    p.add_argument('--seed',help='first feedback case as comma-separated trigger values')
    p.add_argument('--cases',type=int,help='number of feedback cases to run')
    a=p.parse_args()
    if a.max_ticks < 1: p.error('--max-ticks must be positive')
    if a.feedback:
        a.online=True
    elif a.seed is not None or a.cases is not None:
        p.error('--seed and --cases require --feedback')
    if a.output.exists(): raise ValueError('output directory already exists')
    a.output.mkdir(parents=True)
    config=json.loads(a.config.read_text())
    behavior=None
    if 'irq_behavior' in config:
        behavior=json.loads((ROOT/config['irq_behavior']).read_text())
        config=apply_irq_behavior(config,behavior,root=ROOT)
    if 'source_request' not in config and 'source_profile' in config:
        request=request_from_profile(config,json.loads((ROOT/config['source_profile']).read_text()))
        request_path=(a.output/'source_request.json').resolve()
        request_path.write_text(json.dumps(request,indent=2)+'\n')
        config=dict(config,source_request=str(request_path),target_profile=config['source_profile'])
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_timer_irq_smoke import timer_artifact

    started=time.monotonic()
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        cpu_request_path=(a.output/'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config),indent=2)+'\n')
        cpu=timer_artifact(ROOT,str(cpu_request_path),'cpu')
        target=timer_artifact(ROOT,config['source_request'],config['active_id'])
        boot=source_backed_boot_fetch(cpu.plan.profile,base_dir=ROOT,
            configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        _,prefix=build_case(config,cpu.plan.profile,target.plan.profile,boot=boot,behavior=behavior)
        feedback=None
        if a.feedback:
            if config.get('feedback_rule')!=F5_RULE:
                raise ValueError('--feedback requires the declared rule '+F5_RULE)
            offsets=[offset for offset,_ in config['trigger_writes']]
            roles=trigger_roles(target.plan.profile.address.registers,offsets)
            cases=a.cases if a.cases is not None else config.get('feedback_cases',2)
            feedback=F5TimerFeedback(offsets,roles,feedback_seed(config,a,offsets,roles),cases=cases)
        if a.online:
            prefix['program']=build_online_program(prefix['firmware'],config)
        profile=json.loads((ROOT/config['cpu_profile']).read_text())
        header,firmware=render_bindings(config,prefix,cpu.runtime_document,target.runtime_document,profile)
        (a.output/'spike_config.h').write_text(header)
        (a.output/'firmware.txt').write_text(firmware)
        submitted=[]
        argv=[(a.output/'firmware.txt').resolve()]
        if a.online: argv.append('--online')
        argv.append(a.max_ticks)
        summary=build_link_run((cpu,target),ROOT/'scripts/inprocess_obi_apb_irq_spike.cpp',
            a.output,a.cache,argv,root=ROOT,
            runner=online_runner(len(config['trigger_writes']),submitted,feedback) if a.online else None)
        if a.online:
            summary['submitted']=submitted
            summary['source_causality']='unknown'
            summary['input_mode']='feedback' if feedback is not None else 'operator'
        if feedback is not None:
            summary.update(feedback_rule=F5_RULE,cases_requested=feedback.cases,
                           feedback=feedback.records,feedback_observations=feedback.observations)
        summary.update(scope='single OBI CPU + APB target; compact observations; no full F5 certification or replay',
                       total_seconds=time.monotonic()-started)
        (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps({'status':summary['status'],'output':str(a.output),
                          'run_seconds':summary['run_seconds'],'total_seconds':summary['total_seconds']}))
        return summary['returncode']


if __name__=='__main__': raise SystemExit(main())
