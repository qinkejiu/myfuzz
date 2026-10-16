"""Read only saved metadata/archive receipts; invokes no project modules/model."""
import ast,hashlib,io,json,tarfile
from pathlib import Path
base=Path('.superpowers/boom-irq-metadata-recovery-20261017')
archive=base/'metadata-recovery-evidence.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='ee8d388bfe132d00f8a7a38771b066b7753e56d04ea037fae7990e5f17439421'
def digest(b):return hashlib.sha256(b).hexdigest()
with tarfile.open(archive) as t:
 def raw(n):return t.extractfile(n).read()
 def doc(n):return json.loads(raw(n))
 result=doc('state/result.json');artifact=doc('artifact-finalized/irq-session-artifact.json')
 assert raw('state/worker.exit').strip()==b'0' and result['worker_exit']==0
 assert result['metadata_only_recovery_audit_pass']
 assert all(result[k] is False for k in ('runtime_verified','source_authority','new_cpp_build','native_model_executed'))
 assert result['shared_source_inodes']==result['shared_artifact_inodes']==[]
 source=doc('state/source-before.json')['files'];assert len(source)==2564
 assert source==doc('state/source-after.json')['files']==doc('state/copied-source.json')['files']
 original=doc('state/original-before.json')['files'];assert len(original)==84
 assert original==doc('state/original-after.json')['files']
 assert doc('state/tools-before.json')==doc('state/tools-after.json')['actual']
 assert digest(raw('artifact-finalized/irq-session-artifact.json'))==result['final_manifest_sha256']
 tree=ast.parse(Path('src/myfuzz/local_harness/boom_irq_recovery.py').read_text())
 pins=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(a,ast.Name) and a.id=='ARCHIVES' for a in n.targets)))
 files={}
 for name,want in pins.items():
  data=raw('artifact-finalized/recovery-receipts/'+name);assert digest(data)==want
  assert artifact['session_files']['recovery-receipts/'+name]==want
  with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as nested:
   for m in nested:
    if m.isfile():
     value=nested.extractfile(m).read()
     if m.name in files:assert files[m.name]==value
     files[m.name]=value
 assert digest(files['artifact/obj/VBoomTile'])==result['binary_sha256']==artifact['session_files']['obj/VBoomTile']
 assert files['artifact/build.exit'].strip()==files['artifact/probe-describe.exit'].strip()==b'0'
 assert files['attempt2/state/build-and-probes.exit'].strip()==b'1'
 origin=artifact['build_origin'];assert origin==doc('state/archive-origin.json')
 assert artifact['metadata_finalization']['reused_binary'] is True and artifact['metadata_finalization']['new_cpp_build'] is False
 assert artifact['runtime_verified'] is artifact['source_authority'] is False
 assert len(origin['inventory'])==16 and artifact['generated_probes']==origin['inventory']
 for name,h in origin['historical_receipt_hashes'].items():assert digest(files[name])==h,name
 audit={'scope':'independent saved metadata/archive audit, no model or constructor',
  'source_files_equal_before_after_copy':len(source),'original_files_equal_before_after':len(original),
  'tools_equal_before_after':True,'historical_archive_hashes_match':pins,
  'actual_original_binary_sha256':result['binary_sha256'],'final_manifest_sha256':result['final_manifest_sha256'],
  'actual_inventory_rows':len(origin['inventory']),'old_build_probe_failedstage_exits':[0,0,1],
  'worker_exit':0,'native_irq_runtime_proven':False,'new_cpp_build':False,'source_authority':False}
 print(json.dumps(audit,indent=2))
