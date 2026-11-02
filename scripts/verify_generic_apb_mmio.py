#!/usr/bin/env python3
"""Offline MMIO record consistency checks; never issue storage/source authority."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))


def require(value,reason):
    if not value:raise ValueError('generic-MMIO-audit:'+reason)


def check_unknown_effects(prefix):
    require(prefix.get('schema_version')=='compiled_mmio_prefix.v1','prefix-schema')
    records=prefix.get('records');require(type(records) is list and bool(records),'records')
    for row in records:
        cert=row.get('certificate',{})
        require(cert.get('schema_version')=='compiled_mmio_case.v1' and cert.get('status')=='observed'
            and cert.get('flow_id')==row.get('flow') and row.get('flow') in ('F2','F4'),'case-schema')
        require(cert.get('internal_storage_version')=='unknown' and cert.get('cross_case_origin')=='unknown'
            and cert.get('reward_eligible') is False and cert.get('component_semantic_effect')=='unsupported','strong-storage-or-effect-claim')
        protocol=cert.get('native_cpu_protocol','obi')  # compatibility for the original OBI-only artifacts
        scopes={'obi':'native_OBI_APB_MMIO_return_dependent_RAM_no_internal_version',
            'wishbone':'actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version',
            'ahb-lite':'actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version',
            'axi4-lite':'actual_CPU_native_MMIO_return_dependent_RAM_no_internal_version'}
        exact=cert.get('exact_hops',{})
        require(protocol in scopes and exact.get('native_protocol',protocol)==protocol
            and exact.get('proof_scope')==scopes[protocol],'proof-scope')
    feedback=prefix.get('feedback',{})
    require(feedback.get('certified')==0 and feedback.get('storage_reward')==0,'storage-reward')
    return records


def native_beat_reference(hop,protocol):
    require(protocol in ('obi','wishbone','ahb-lite','axi4-lite'),'unknown-native-CPU-protocol')
    if protocol!='obi':
        require('native_cpu' in hop and 'native_obi' not in hop,'non-OBI-is-not-OBI')
        return hop['native_cpu']
    require('native_cpu' in hop or 'native_obi' in hop,'missing-native-CPU-beat')
    if 'native_cpu' in hop and 'native_obi' in hop:
        require(hop['native_cpu']==hop['native_obi'],'OBI-alias-mismatch')
    return hop.get('native_cpu',hop.get('native_obi'))


def collect_saved_cpu(events,component,document,binding,error_policy):
    from myfuzz.integration.mmio_cpu_adapter import collect_native_cpu_beats,native_cpu_protocol
    protocol=native_cpu_protocol(document)
    adapter=binding.get('cpu_adapter')
    if adapter is not None:
        require(adapter.get('protocol')==protocol,'actual-CPU-protocol-mismatch')
        traces,policy=adapter['traces'],adapter['error_policy']
    else:
        require(protocol=='obi','missing-CPU-adapter-declaration')
        traces={('data' if 'we' in t['signals'] else 'instr'):t['signals']
            for t in document['base_protocol_traces']['traces']}
        policy=error_policy
    return protocol,collect_native_cpu_beats(events,component,runtime_document=document,traces=traces,error_policy=policy)


def check_actual_hops(prefix,artifacts):
    records=check_unknown_effects(prefix);events=prefix['actual_events'];by_id={e['event_id']:e for e in events}
    require(len(by_id)==len(events),'duplicate-event-id')
    require([e['event_id'] for e in events]==list(range(1,len(events)+1)),'event-order')
    beat_cache={};protocols={};read_values=[]
    for record in records:
        cert=record['certificate'];exact=cert['exact_hops'];joins=cert['joins']
        require(len(joins)==(2 if record['flow']=='F4' else 1),'native-transfer-count')
        for join in joins:
            delivery=by_id[join['delivery_event']];accept=by_id[join['acceptance_event']];raw=by_id[join['native_APB_event']]
            tx=join['source_transaction'];cpu=tx['source_component'];target=raw['component']
            require(delivery.get('kind')=='mmio_delivery' and accept.get('kind')=='mmio_acceptance'
                and delivery.get('source_transaction')==accept.get('source_transaction')==tx
                and accept['event_id']<delivery['event_id'] and delivery.get('write') is join['write'],'route-reference')
            require(raw.get('kind')=='local_tick_sample' and raw.get('phase')=='pre'
                and raw.get('producer_event_id')==delivery.get('producer_event_id'),'native-APB-reference')
            signals=artifacts[target]['base_protocol_trace']['signals'];backend=raw['outputs']['backend']
            fields=dict(psel=1,penable=1,pready=1,pslverr=0,pwrite=int(join['write']),paddr=delivery['offset'])
            fields['pwdata' if join['write'] else 'prdata']=join['value']
            require(all(backend.get(signals[role])==value for role,value in fields.items()),'native-APB-fields')
            if cpu not in beat_cache:
                protocols[cpu],beat_cache[cpu]=collect_saved_cpu(events,cpu,artifacts[cpu],prefix['execution_binding'],exact.get('cpu_error_policy'))
            protocol=protocols[cpu]
            require(cert.get('native_cpu_protocol','obi')==prefix.get('native_cpu_protocol',protocol)==protocol,'certificate-CPU-protocol')
            hop=next((h for h in exact['data_hops'] if h['delivery_event']==join['delivery_event']),None)
            require(hop is not None,'CPU-return-hop')
            beat=beat_cache[cpu].get(('data',tx['source_sequence']))
            require(beat==native_beat_reference(hop,protocol) and beat['acceptance_event']==hop['native_acceptance_event']
                and beat['response_event']==hop['native_response_event'] and beat['address']==delivery['address'],'actual-CPU-native-beat')
            require((beat['value'] if join['write'] else beat['rdata'])==join['value'],'actual-CPU-value')
        reads=[j for j in joins if j['write'] is False];require(len(reads)==1,'one-read-return')
        value=reads[0]['value'];expected=value^(0x5a5 if record['flow']=='F2' else 0)
        ram=by_id[cert['RAM_event']];ram_hop=exact['ram_write_hop']
        require(ram.get('kind')=='memory_write' and ram.get('value')==cert['result_value']==expected
            and ram.get('byte_enable')==15 and ram['event_id']>reads[0]['delivery_event'],'dependent-RAM')
        require(native_beat_reference(ram_hop,protocols[ram['component']])==beat_cache[ram['component']][('data',ram['transaction']['source_sequence'])]
            and ram_hop['address']==ram['address'] and ram_hop['value']==expected,'actual-RAM-native-hop')
        read_values.append(value)
    return dict(case_count=len(records),records=[r['flow']+':'+r['raw'] for r in records],read_values=read_values,
        event_count=len(events),local_ticks=prefix['trace_local_ticks'])


def check_recordings(recording,audit):
    from myfuzz.local_harness.wire import parse_driver_receipt
    require(audit.get('closed') is True,'process-audit-not-closed')
    sessions=recording.get('sessions',{})
    require(set(sessions)==set(audit['identities'])==set(audit['exits']),'recording-process-set')
    counts={}
    for component,session in sessions.items():
        identity=audit['identities'][component];exit_row=audit['exits'][component]
        require(session.get('complete') is True and session.get('identity')==identity,'incomplete-wire-recording')
        require(exit_row.get('reaped') is True and exit_row.get('returncode')==0,'native-process-exit')
        require(type(identity.get('pid')) is int and bool(identity.get('execution_nonce')),'native-process-identity')
        rows=session.get('records');require(bool(rows),'empty-wire-recording')
        for index,row in enumerate(rows,start=1):
            require(row['sequence']==index,'wire-command-sequence')
            parts=row['reply'].split();require(parts[0]=='RESULT' and len(parts)==6,'wire-result')
            payload=json.loads(bytes.fromhex(parts[5]))
            receipt=parse_driver_receipt(row['reply'],execution=identity['execution_nonce'],sequence=index,
                current_tick=row['tick_before'],kind=payload['kind'])
            require(receipt.tick_after==row['tick_after'],'wire-tick')
        counts[component]=len(rows)
    return counts


def read_phase_recordings(directory,audit,*,allow_missing=False):
    path=directory/'local_commands.json'
    if allow_missing and not path.exists():
        return dict(status='unavailable',reason='local_commands.json missing')
    counts=check_recordings(json.loads(path.read_text()),audit)
    return dict(status='verified',counts=counts)


def check_saved_cross(original,fresh,summary):
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix,_first_difference
    decisions=lambda prefix:[(r['flow'],r['raw'],r['value']) for r in prefix['records']]
    require(decisions(original)==decisions(fresh),'fresh-decisions-or-raw-records')
    left,right=map(_normalized_f6_prefix,(original,fresh))
    require(left.get('online_plan')==right.get('online_plan'),'fresh-plan-or-raw-source')
    require(_first_difference(left,right) is None,'full-fresh-prefix-difference')
    return dict(status='verified',matches=True,method='independent_full_saved_prefix_recomputation',
        summary_cross_invocation=summary.get('verification',{}).get('cross_invocation',{}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--case',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--allow-missing-recordings',action='store_true',
        help='report absent command recordings as unavailable and the audit as partial')
    args=parser.parse_args()
    def read(root,name):return json.loads((root/name).read_text())
    phases={};prefixes=[];audits=[]
    for phase in ('original','fresh'):
        directory=args.case/phase;prefix=read(directory,'prefix.json');audit=read(directory,'execution_audit.json')
        artifacts={name:read(directory/'generated'/name,'artifact.json') for name in audit['identities']}
        for name,artifact in artifacts.items():
            require(artifact['artifact_digest']==prefix['execution_binding']['artifacts'][name],'generated-artifact-binding')
        phases[phase]=dict(work=check_actual_hops(prefix,artifacts),
            commands=read_phase_recordings(directory,audit,allow_missing=args.allow_missing_recordings))
        prefixes.append(prefix);audits.append(audit)
    require(phases['original']['work']==phases['fresh']['work'],'fresh-work')
    commands=[phases[name]['commands'] for name in ('original','fresh')]
    if all(row['status']=='verified' for row in commands):
        require(commands[0]==commands[1],'fresh-wire-count')
    require(set(audits[0]['identities'])==set(audits[1]['identities']),'fresh-process-set')
    for name,old in audits[0]['identities'].items():
        new=audits[1]['identities'][name]
        require(old['pid']!=new['pid'] and old['execution_nonce']!=new['execution_nonce'],'fresh-process-not-independent')
    summary=read(args.case/'fresh','summary.json')
    cross=check_saved_cross(*prefixes,summary)
    report=dict(schema_version='generic_apb_MMIO_offline_audit.v1',
        status='verified' if all(row['status']=='verified' for row in commands) else 'partial',
        authority=False,phases=phases,
        cross_invocation=cross,
        internal_storage_version='unknown',cross_case_origin='unknown',reward_eligible=False,
        coverage_scope=('recordings available; coverage measurement is a separate native replay'
            if all(row['status']=='verified' for row in commands)
            else 'recordings incomplete; coverage measurement is a separate native replay'))
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
