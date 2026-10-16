"""Read-only post-exit audit; saved JSON is never runtime authority."""
from pathlib import Path
import json,sys
base=Path(__file__).resolve().parent;project=base/'project';gate=sys.argv[1]
load=lambda p:json.loads(p.read_text())
if int((base/'logs'/f'{gate}.exit').read_text())!=0:raise SystemExit('actual command exit was nonzero')
if gate=='adapter':
    text=(base/'logs/adapter.log').read_text()
    if 'PASSED' not in text or 'SKIPPED' in text or '1 passed' not in text:
        raise SystemExit('adapter gate must actually pass, not skip')
elif gate=='boundary':
    report=load(base/'outputs/boundary/report.json')
    assert report['status']=='completed' and report['native_executed'] is True
    assert report['fail_stop_observed'] is True and report['returncode']!=0
    assert report['actual_close_returncode']==report['returncode']
    assert report['policy']['mode']=='fail_stop_no_error_pin'
    assert report['injection']['error']==1 and report['injection']['accepted']['address']>=0
    assert not (base/'outputs/boundary/.incomplete').exists()
else:
    from myfuzz.integration.compiled_f4 import _compare_prefixes
    output=base/'outputs'/gate;report=load(output/'report.json');prefix=load(output/'prefix.json')
    config='compiled-f4-obi-apb-ibex' if gate=='ibex' else 'compiled-f4-obi-apb'
    records=load(project/'configs/scenarios'/config/'example_records.json')
    assert report['status']=='completed' and report['certified_cases']==3 and report['replays']==2
    assert not (output/'.incomplete').exists() and len(load(output/'events.json'))>0
    assert [row['raw'] for row in prefix['records']]==records and len(records)==3
    assert all(len(bytes.fromhex(row))==8 for row in records)
    assert prefix['candidate_layout']['byte_length']==8
    assert prefix['cpu_error_policy']['mode']==('native_error_role' if gate=='ibex' else 'fail_stop_no_error_pin')
    manifest=load(base/'source_manifest.json')['files']
    assert prefix['source_files']=={k:v for k,v in manifest.items() if k.startswith('src/myfuzz/') and k.endswith('.py')}
    pids=set();nonces=set()
    for index in range(3):
        directory=output if index==0 else output/f'fresh-{index}'
        audit=load(directory/'execution_audit.json')
        assert audit['closed'] is True and set(audit['identities'])==set(audit['exits'])
        for component,identity in audit['identities'].items():
            assert identity['component']==component and identity['role'] in {'cpu','bound_target'}
            assert identity['pid'] not in pids and identity['execution_nonce'] not in nonces
            pids.add(identity['pid']);nonces.add(identity['execution_nonce'])
            assert audit['exits'][component]==dict(returncode=0,reaped=True)
            assert identity['artifact_digest']==prefix['artifact_digests'][component]
        if index:
            actual=load(directory/'prefix.json');assert len(load(directory/'events.json'))>0
            assert load(directory/'comparison.json')['matches'] is True
            assert _compare_prefixes(prefix,actual)['matches'] is True
    assert len(pids)==6 and len(nonces)==6
print(json.dumps(dict(gate=gate,post_exit_audit='passed'),sort_keys=True))
