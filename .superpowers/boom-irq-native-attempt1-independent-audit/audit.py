import gzip,hashlib,json,tarfile
from pathlib import Path
p=Path('docs/reports/evidence/boom-irq-native-attempt1-20261017/evidence.tar.gz')
sha=lambda b:hashlib.sha256(b).hexdigest()
assert sha(p.read_bytes())=='349026ceeb07f9fa74fc9c8daee707d7e978caf6f7e7ef84045d0e0adc471118'
with tarfile.open(p) as t:
 raw=lambda n:t.extractfile(n).read()
 doc=lambda n:json.loads(raw(n))
 d=json.loads(gzip.decompress(raw('gate-output/first.json.gz')))
 assert d['error']=={'detail':'binding producer does not match input ownership','type':'ValueError'}
 assert d['status'] is None and d['lifecycles']=={'cpu':[],'gpio':[]}
 for k in ('cpu_commands','cpu_samples','cpu_transport_reads','gpio_commands','gpio_samples','gpio_transport_reads','events','runtime_events','source_events','router_deliveries'):
  assert d[k]==[],k
 assert d['identities']=={}
 before=doc('state/before.json');after=doc('state/after.json');assert before==after
 assert [len(after[k]) for k in ('project_files','original_source_files','original_artifact_files')]==[2566,2564,88]
 assert after['shared_source_inodes']==[] and doc('state/tools-after.json')['equal_before'] is True
 assert raw('state/native.exit').strip()==raw('state/worker.exit').strip()==b'1'
 assert doc('state/child.json')['pid']==265033 and doc('state/child.json')['poll']==doc('state/child.json')['exit']==1
 assert doc('gate-output/summary.json')['status']=='failed'
 assert 'gate-output/incomplete.json' in t.getnames()
 assert sha(raw('gate-output/irq-session-artifact.json'))=='ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737'
 freeze=doc('source-freeze.json')['files']
 assert len(freeze)==389 and all(after['project_files'][n]==v for n,v in freeze.items())
 print(json.dumps({'archive_sha256':sha(p.read_bytes()),'status':'failed_before_native_session_start','gate_python_pid':265033,'controller_pid':265026,'gate_exit':1,'controller_exit':1,'cpu_gpio_harness_lifecycles':0,'cpu_gpio_commands':0,'actual_error':d['error'],'protected_source_artifact_and_runtime_unchanged':True,'file_counts':[2566,2564,88],'freeze_files':389,'tools_unchanged':True,'incomplete_preserved':True,'irq_semantics_tested':False},indent=2))
