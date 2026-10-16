import gzip,hashlib,json,tarfile
from pathlib import Path
from myfuzz.scenario.boom_gpio_irq_verification import validate_transport,validate_pulse,qualified_return
base=Path('.superpowers/boom-irq-runtime-attempt2-20261017')
archive=base/'native-attempt2-evidence.tar.gz'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(archive.read_bytes())=='8e0a8f1e85e2e122ef052a83cd9d86fe46baea3f6c36926aa5a0ce3f6f671393'
manifest=json.loads((base/'native-file-manifest.json').read_text())
with tarfile.open(archive) as t:
 members={m.name:t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
assert len(members)==396 and set(members)==set(manifest)
for name,b in members.items():assert manifest[name]==dict(bytes=len(b),sha256=sha(b)),name
raw=lambda n:members[n]
doc=lambda n:json.loads(raw(n))
d=json.loads(gzip.decompress(raw('gate-output/first.json.gz')))
assert raw('gate-output/first.json.gz')==(base/'native-first.json.gz').read_bytes()
assert d['status']=='budget_exhausted' and d['error'] is None
assert doc('gate-output/summary.json')['status']=='failed'
assert not any(n.startswith(('gate-output/fresh','gate-output/suppressed')) for n in members)
assert raw('state/native.exit').strip()==raw('state/worker.exit').strip()==b'1'
assert doc('state/child.json')['pid']==268183 and doc('state/child.json')['poll']==doc('state/child.json')['exit']==1
assert doc('state/before.json')==doc('state/after.json')
after=doc('state/after.json');assert [len(after[k]) for k in ('project_files','original_source_files','original_artifact_files')]==[2567,2567,88]
assert after['shared_source_inodes']==[] and doc('state/tools-after.json')['equal_before'] is True
assert sha(raw('gate-output/irq-session-artifact.json'))=='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'
validate_transport(d)
start,end=validate_pulse(d['events'],d['cpu_samples'],suppressed=False)
assert (start,end)==(221,285)
last=d['events'][-1];assert last['kind']=='budget_exhausted' and last['limit']=='max_scheduler_steps'
print(json.dumps(last,indent=2))
assert len(d['cpu_samples'])==2988 and len(d['gpio_samples'])==3012
assert len(d['lifecycles']['cpu'])==2 and len(d['lifecycles']['gpio'])==1
assert all(r['closed'] is True and r['exit']==0 for rows in d['lifecycles'].values() for r in rows)
returns=[s['cycle'] for s in d['cpu_samples'] if qualified_return(s['probes_pre'],d['last_cpu_outputs']['ram_3018'])]
assert returns==[429]
report=d['coherent_report'];assert not report['structural_error'] and not report['normalization_poisoned'] and report['stream_closed'] and not d['uncertain_keys']
result=dict(archive_files=396,all_file_hashes_match=True,controller_pid=268173,gate_pid=268183,controller_exit=1,gate_exit=1,
 actual_status=d['status'],actual_error=d['error'],full_gate_pass=False,fresh_and_suppression_executed=False,
 source_artifact_tools_unchanged=True,cpu_samples=2988,gpio_samples=3012,total_actual_steps=6000,
 actual_pulse=[start,end],actual_qualified_mret_ticks=returns,transport_streams_validated=True,
 scope='independent_saved_observations_only_no_source_or_retirement_authority')
Path('.superpowers/boom-irq-attempt2-independent-audit/result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
