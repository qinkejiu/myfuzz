"""Read only saved metadata/archive receipts; invokes no project modules/model."""
import ast,hashlib,io,json,tarfile
from pathlib import Path
base=Path('.superpowers/boom-irq-factory-fix-20261017')
archive=base/'metadata-recovery-evidence.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()=='b8562f7f5dcd7945d0cb53d21230d3349734b485092647eb4b1e54aa25da42e0'
def digest(b):return hashlib.sha256(b).hexdigest()
with tarfile.open(archive) as t:
 def raw(n):return t.extractfile(n).read()
 def doc(n):return json.loads(raw(n))
 result=doc('state/result.json');artifact=doc('artifact-finalized/irq-session-artifact.json')
 assert raw('state/worker.exit').strip()==b'0' and result['worker_exit']==0
 assert result['metadata_only_recovery_audit_pass']
 assert all(result[k] is False for k in ('runtime_verified','source_authority','new_cpp_build','native_model_executed'))
 assert result['shared_source_inodes']==result['shared_artifact_inodes']==[]
 source=doc('state/source-before.json')['files'];assert len(source)==2567
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
 protected=doc('state/protected-before.json')
 assert protected==doc('state/protected-after.json')['actual']
 assert [len(protected[k]) for k in ('old_metadata','old_finalized_project','failed_runtime_project')]==[88,2564,2566]
 assert protected['failed_first_sha256']=='152348fde794d39237a26e207c04f290a32a056654943a2ce6a395415b3578bc'
 change=doc('state/host-factory-change.json')
 old_factory='1de87df95d1f10b44dd5848cc19afd9432527cf3b088103fa67f0883db8b0e09'
 new_factory='0af5037e8282c232c672a0251e2c8f579d4f1f6edde793bc51e20854f8f1e77e'
 factory_raw=raw('project-finalized/src/myfuzz/scenario/boom_gpio_irq_runner.py')
 assert digest(factory_raw)==new_factory==artifact['scenario_factory_sha256']==change['new_factory_sha256']
 assert digest(factory_raw.replace(b"'bound','gpio.irq'",b"'bound','gpio_irq'"))==old_factory==change['old_factory_sha256']
 assert source['src/myfuzz/scenario/boom_gpio_irq_runner.py']==new_factory
 assert artifact['implementation_source_hashes']==change['implementation_source_hashes_unchanged']
 assert artifact['metadata_finalization']['current_python_hashes']==artifact['implementation_source_hashes']
 assert len(artifact['implementation_source_hashes'])==8
 for name,h in artifact['implementation_source_hashes'].items():assert source['src/myfuzz/local_harness/'+name]==h
 assert change['effective_inputs']==origin['effective_inputs'] and len(origin['effective_inputs'])==12
 for name,h in origin['effective_inputs'].items():assert artifact['session_files'][name]==h==digest(files['artifact/'+name])
 assert result['final_manifest_sha256']=='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'
 assert raw('state/PID').strip()==b'267241'
 assert digest(raw('ready.json'))=='20ad6eb738b67db8640f7e21299259fbc04f017f948960eddfa306e1dee0d211'
 assert not any('incomplete' in n for n in t.getnames())
 audit={'scope':'independent saved metadata/archive audit, no model or constructor',
  'source_files_equal_before_after_copy':len(source),'original_files_equal_before_after':len(original),
  'tools_equal_before_after':True,'historical_archive_hashes_match':pins,
  'actual_original_binary_sha256':result['binary_sha256'],'final_manifest_sha256':result['final_manifest_sha256'],
  'actual_inventory_rows':len(origin['inventory']),'old_build_probe_failedstage_exits':[0,0,1],
  'archive_sha256':digest(archive.read_bytes()),'protected_source_artifacts_failed_prefix_unchanged':True,'old_host_factory_sha256':old_factory,'new_host_factory_sha256':new_factory,'actual_effective_input_count':12,'worker_exit':0,'native_irq_runtime_proven':False,'new_cpp_build':False,'source_authority':False}
 print(json.dumps(audit,indent=2))
