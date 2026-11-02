#!/usr/bin/env python3
"""Offline sampled-retirement/fetched-byte consistency; no IRQ/F5/F6 authority."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'src')]


def require(value,reason):
    if not value:raise ValueError('CPU-retirement-audit:'+reason)


def retirement_fields(artifact):
    rows=[row for row in artifact['physical_exports'] if row['physical_port'].startswith('rvfi_')
        and row['direction']=='output' and row['disposition']=='observe']
    fields={row['physical_port']:row for row in rows}
    require(len(fields)==len(rows),'ambiguous-RVFI-export')
    for name,width in {'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32}.items():
        require(name in fields and fields[name]['width']==width,'missing-essential-RVFI-export')
    require(all(r['bit_lo']==0 and r['bit_hi']==r['width']-1 for r in rows),'sliced-RVFI-export')
    return fields


def parsed_POST_samples(recording,component,fields):
    from myfuzz.local_harness.wire import parse_driver_receipt
    session=recording['sessions'][component];require(session['complete'],'incomplete-wire-recording')
    identity=session['identity'];samples=[]
    for record in session['records']:
        payload=json.loads(bytes.fromhex(record['reply'].split()[5]))
        receipt=parse_driver_receipt(record['reply'],execution=identity['execution_nonce'],
            sequence=record['sequence'],current_tick=record['tick_before'],kind=payload['kind'])
        require(receipt.tick_after==record['tick_after'],'wire-tick')
        if payload['kind']!='obi_cpu':continue
        for sample in receipt.payload['samples']:
            physical=sample['post']['physical']
            values={name:physical[row['runtime_name']] for name,row in fields.items()}
            require(all(type(values[name]) is int and 0<=values[name]<1<<row['width']
                for name,row in fields.items()),'invalid-actual-POST-field')
            samples.append(dict(tick=sample['local_tick'],sequence=receipt.sequence,fields=values))
    require(samples,'missing-native-POST-samples')
    return samples


def check_retirements(events,samples,fields,fetches,*,component):
    """Match actual POST samples and emitted rows, then actual fetched bytes."""
    unique=[];previous=None
    for sample in samples:
        row=sample['fields']
        if not row['rvfi_valid']:continue
        value=(row['rvfi_order'],row['rvfi_pc_rdata'],row['rvfi_insn'])
        if previous is not None:
            require(value[0]>=previous[0],'retirement-order-regressed')
            if value[0]==previous[0]:
                require(value==previous,'held-order-changed-instruction')
                continue
        previous=value;unique.append(sample)
    retired=[e for e in events if e.get('component')==component and e.get('kind')=='cpu_retire']
    require(bool(unique) and len(unique)==len(retired),'retirement-stream-count')
    result=[]
    for event,sample in zip(retired,unique):
        observed=sample['fields'];tick=event.get('local_tick',event.get('tick'))
        require(tick==sample['tick'],'retirement-native-tick')
        require(event.get('observation',{}).get('sampling_edge')=='post_rising'
            and event['observation'].get('physical')==observed,'actual-POST-observation')
        require(all(event.get(name.removeprefix('rvfi_'))==value for name,value in observed.items()),'retirement-field-projection')
        for absent in ('intr','pc_wdata'):
            require('rvfi_'+absent in fields or absent not in event,'undriven-field-was-fabricated')
        require('irq_serial_observation' not in event and 'take_key' not in event,'unexpected-native-IRQ-authority')
        pc=observed['rvfi_pc_rdata'];insn=observed['rvfi_insn'];length=4 if insn&3==3 else 2
        fetched=[]
        for address in range(pc,pc+length):
            choices=[f for f in fetches if f['address']<=address<f['address']+4 and f['tick']<=tick]
            require(choices,'retired-instruction-not-fetched')
            source=max(choices,key=lambda f:(f['tick'],f['event_id']))
            fetched.append(source['data'][address-source['address']])
        require(int.from_bytes(bytes(fetched),'little')==insn,'retired-instruction-differs-from-fetched-bytes')
        result.append(dict(order=observed['rvfi_order'],pc_rdata=pc,insn=insn,tick=tick))
    return result


def actual_fetches(prefix,artifact,component):
    from scripts.verify_generic_apb_mmio import collect_saved_cpu
    protocol,beats=collect_saved_cpu(prefix['actual_events'],component,artifact,prefix['execution_binding'],None)
    require(protocol=='obi','this-retirement-audit-requires-OBI-fetch')
    fetched=[]
    for event in prefix['actual_events']:
        if event.get('component')!=component or event.get('kind')!='instr_response':continue
        key=event['transaction'];beat=beats.get(('instr',key['source_sequence']))
        require(beat is not None and beat['address']==event['address'] and beat['rdata']==event['rdata']
            and event['error']==0,'actual-native-instruction-response')
        data=bytes.fromhex(event['snapshot']['data_hex'])
        require(len(data)==4 and int.from_bytes(data,'little')==event['rdata'],'source-snapshot-bytes')
        fetched.append(dict(address=event['aligned_address'],data=data,
            tick=event['response_tick'],event_id=event['event_id']))
    require(fetched,'missing-instruction-source-responses')
    return fetched


def main():
    from scripts.verify_generic_apb_mmio import check_recordings,check_saved_cross
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',type=Path,required=True);parser.add_argument('--cpu',default='cpu')
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    read=lambda path:json.loads(path.read_text());phases={};prefixes=[];identities=[]
    for phase in ('original','fresh'):
        directory=args.case/phase;prefix=read(directory/'prefix.json')
        artifact=read(directory/'generated'/args.cpu/'artifact.json');recording=read(directory/'local_commands.json')
        audit=read(directory/'execution_audit.json');commands=check_recordings(recording,audit)
        require(artifact['artifact_digest']==prefix['execution_binding']['artifacts'][args.cpu],'actual-CPU-artifact-binding')
        fields=retirement_fields(artifact);samples=parsed_POST_samples(recording,args.cpu,fields)
        rows=check_retirements(prefix['actual_events'],samples,fields,actual_fetches(prefix,artifact,args.cpu),component=args.cpu)
        phases[phase]=dict(fields={name:row['width'] for name,row in fields.items()},retirements=rows,commands=commands)
        prefixes.append(prefix);identities.append(audit['identities'])
    require(phases['original']==phases['fresh'],'fresh-retirement-or-work-difference')
    for component,old in identities[0].items():
        new=identities[1][component]
        require(old['pid']!=new['pid'] and old['execution_nonce']!=new['execution_nonce'],'fresh-process-not-independent')
    cross=check_saved_cross(*prefixes,read(args.case/'fresh'/'summary.json'))
    report=dict(status='verified',authority=False,scope='actual_POST_retirement_and_native_fetched_bytes',
        phases=phases,cross_invocation=cross,grants_F5=False,grants_F6=False,
        unavailable_fields=[name for name in ('rvfi_intr','rvfi_pc_wdata') if name not in phases['original']['fields']])
    args.output.write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(dict(status='verified',retirements=len(rows))))


if __name__=='__main__':main()
