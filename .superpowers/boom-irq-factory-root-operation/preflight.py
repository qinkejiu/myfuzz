import hashlib,json,os,sys
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-factory-fix-20261017')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sys.flags.optimize==0
expected_ready='20ad6eb738b67db8640f7e21299259fbc04f017f948960eddfa306e1dee0d211'
assert sha(base/'ready.json')==expected_ready
assert sha(base/'control.py')=='2d1879526d53d7159dc9001491a6f2a2742cdd75ad12a9968a13d63b1c57824b'
assert sha(base/'run-control.sh')=='b3d43ecfbae4480fbe960e4d5ff7f7fb89386bd1ad8313d4ab77248f7f9ac2df'
ready=json.loads((base/'ready.json').read_text())
for name,digest in ready['control_hashes'].items():
 p=base/name
 assert p.resolve().is_relative_to(base) and not any(q.is_symlink() for q in (p,*p.parents))
 assert sha(p)==digest,name
for name in ('state/PID','state/launcher-PID','state/worker.exit','state/operation.claim','state/stage','state/result.json','state/failure.json','state/imports.json','project-finalized','artifact-finalized','logs/controller.log'):
 p=base/name;assert not p.exists() and not p.is_symlink(),name
def tree(root):
 assert not any(q.is_symlink() for q in (root,*root.parents))
 result={}
 for p in root.rglob('*'):
  assert not p.is_symlink()
  if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':
   assert p.stat().st_nlink==1
   result[p.relative_to(root).as_posix()]=sha(p)
 return result
source=json.loads((base/'source-destination.json').read_text())['files']
assert len(source)==2567 and tree(base/'source')==source
old=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017')
failed=Path('/root/fanzehui/boom-irq-runtime-gate-20261017')
protected=json.loads((base/'protected-preparation-pins.json').read_text())
actual=dict(old_metadata=tree(old/'artifact-finalized'),old_finalized_project=tree(old/'project-finalized'),failed_runtime_project=tree(failed/'project'),failed_first_sha256=sha(failed/'gate-output/first.json.gz'))
assert actual==protected
original=Path('/root/fanzehui/boom-irq-verification-20261017/artifact')
assert tree(original)==json.loads((base/'original-build-pins.json').read_text())['files']
assert all(not os.path.samestat((base/'source'/n).stat(),(failed/'project'/n).stat()) for n in actual['failed_runtime_project'])
assert sha(base/'source/src/myfuzz/scenario/boom_gpio_irq_runner.py')=='0af5037e8282c232c672a0251e2c8f579d4f1f6edde793bc51e20854f8f1e77e'
print(json.dumps({'root_live_preflight':'pass','ready_sha256':expected_ready,'source_files':len(source),'protected_counts':{k:len(v) for k,v in actual.items() if isinstance(v,dict)},'old_failed_prefix_unchanged':True,'metadata_operation_unused':True,'model_executed':False}))
