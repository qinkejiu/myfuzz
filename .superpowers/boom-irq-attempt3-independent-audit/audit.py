import copy,gzip,hashlib,json,tarfile
from pathlib import Path
from myfuzz.scenario import boom_gpio_irq_verification as gate
base=Path('.superpowers/boom-irq-runtime-attempt3-20261017')
archive=base/'native-attempt3-evidence.tar.gz'
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(archive.read_bytes())=='df3ad507ca27e1f07e1493eeae6bdb87ec02e697f4e53b398027ba7b1f25583b'
manifest=json.loads((base/'native-file-manifest.json').read_text())
with tarfile.open(archive) as t:members={m.name:t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
assert len(members)==403 and set(members)==set(manifest)
for n,b in members.items():assert manifest[n]==dict(bytes=len(b),sha256=sha(b)),n
raw=lambda n:members[n]
doc=lambda n:json.loads(raw(n))
assert raw('state/native.exit').strip()==raw('state/worker.exit').strip()==b'0'
child=doc('state/child.json');assert child['pid']==269888 and child['poll']==child['exit']==0
before=doc('state/before.json');after=doc('state/after.json');assert before==after
assert [len(after[k]) for k in ('project_files','original_source_files','original_artifact_files')]==[2567,2567,88]
assert after['shared_source_inodes']==[] and doc('state/tools-after.json')['equal_before'] is True
assert sha(raw('gate-output/irq-session-artifact.json'))=='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'
assert sha(raw('source-freeze.json'))=='d0eb71f1cfaa7a6db158f3c9211249c03e7703b89519a94db42cfd8317f0803e'
summary=doc('gate-output/summary.json');assert summary['status']=='pass' and summary['full_fresh_prefix_equal'] and summary['suppressed_delivery_rejected']
assert all(summary[k] is False for k in ('source_authority','isa_retirement_authority','full_P6','new_cpp_build'))
runs={n:json.loads(gzip.decompress(raw('gate-output/'+n+'.json.gz'))) for n in ('first','fresh','suppressed')}
checks={n:gate.validate_run(d,suppressed=n=='suppressed') for n,d in runs.items()}
gate.compare_fresh(runs['first'],runs['fresh'])
# Compare every top-level field, additionally covering fields outside gate comparator.
def normalize_all(d):
 out=copy.deepcopy(d);ids=d['identities'];out['identities']={k:'declared:'+k for k in ids}
 for side,rows in out['lifecycles'].items():
  out['lifecycles'][side]=gate.normalize_rows([{k:v for k,v in r.items() if k!='pid'} for r in rows],ids)
 for n in ('events','runtime_events','source_events','gpio_events','router_deliveries','cpu_commands','gpio_commands','cpu_transport_reads'):
  out[n]=gate.normalize_rows(out[n],ids)
 out['gpio_transport_reads']=gate.normalize_gpio_wire(out['gpio_transport_reads'],ids)
 for n in ('coherent_report','coherent_coverage'):out[n]=gate.normalize_rows([out[n]],ids)[0]
 return out
assert normalize_all(runs['first'])==normalize_all(runs['fresh'])
pids=[];nonces=[];result={}
for n,d in runs.items():
 assert d['status']=='complete' and d['error'] is None
 expected=6024 if n!='suppressed' else 6016
 acc=d['step_accounting'];assert acc['total_local_steps']==expected<=6512 and acc['main_direct_steps']==6000 and acc['quiesce_direct_steps']==0
 assert acc==gate.step_accounting(d['events'],acc['local_ticks'])
 for side,rows in d['lifecycles'].items():
  for row in rows:
   assert row['closed'] is True and row['exit']==0
   pids.append(row['pid']);nonces.append(row['execution_id'])
   if side=='cpu':assert row['binary_sha256']=='6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90'
 result[n]=dict(cpu_samples=len(d['cpu_samples']),gpio_samples=len(d['gpio_samples']),runner_events=len(d['events']),runtime_events=len(d['runtime_events']),step_accounting=acc,check=checks[n])
assert len(pids)==len(set(pids))==len(set(nonces))==9
out=dict(archive_files=403,all_file_lengths_and_hashes_match=True,controller_pid=269878,gate_pid=269888,controller_exit=0,gate_exit=0,
 all_nine_model_pids_distinct_reaped0=True,whole_first_fresh_document_equal_with_only_declared_identity_and_pid_normalization=True,
 protected_source_artifact_tools_unchanged=True,source_authority=False,isa_retirement_authority=False,full_P6=False,runs=result)
Path('.superpowers/boom-irq-attempt3-independent-audit/result.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items() if k!='runs'},indent=2))
print({n:{k:v for k,v in d.items() if k!='check'} for n,d in result.items()})
