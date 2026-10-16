import fcntl,hashlib,json,os
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-runtime-attempt3-20261017')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(base/'ready.json')=='96f5e22f37ccc574f5b8ba55b46a132afb4d0f845949d394ff76fedce0d39685'
ready=json.loads((base/'ready.json').read_text())
assert sha(base/'control/controller.py')=='2d73918bf98a7f2317948dc82e642d30f1bec58fce1c9e69cd24d949028af92a'
assert sha(base/'control/launch.sh')=='6716b2be1b6d9a2787b358c066881a647e29342cd61b3ea02a140333968e7164'
assert sha(base/'source-freeze.json')=='d0eb71f1cfaa7a6db158f3c9211249c03e7703b89519a94db42cfd8317f0803e'
for name,digest in ready['control_hashes'].items():
 p=base/name;assert p.resolve().is_relative_to(base) and not any(x.is_symlink() for x in (p,*p.parents));assert sha(p)==digest,name
for name in ('PID','launcher-PID','worker.exit','operation.claim','native-PID','native.exit'):
 p=base/'state'/name;assert not p.exists() and not p.is_symlink(),name
for name in ('gate-output','gpio-cache','logs/controller.log'):
 p=base/name;assert not p.exists() and not p.is_symlink(),name
counts={}
for mapname,root in (('project-files.json',base/'project'),('original-source-files.json',Path('/root/fanzehui/boom-irq-factory-fix-20261017/project-finalized')),('original-artifact-files.json',Path('/root/fanzehui/boom-irq-factory-fix-20261017/artifact-finalized'))):
 expected=json.loads((base/mapname).read_text())['files'];actual={}
 for p in root.rglob('*'):
  assert not p.is_symlink()
  if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':
   assert p.stat().st_nlink==1;actual[p.relative_to(root).as_posix()]=sha(p)
 assert actual==expected,mapname;counts[mapname]=len(actual)
original=Path('/root/fanzehui/boom-irq-factory-fix-20261017')
assert sha(original/'artifact-finalized/irq-session-artifact.json')=='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'
expected=json.loads((base/'original-source-files.json').read_text())['files']
assert all(not os.path.samestat((base/'project'/n).stat(),(original/'project-finalized'/n).stat()) for n in expected)
with Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock').open('rb') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print(json.dumps({'root_preflight':'pass','ready_sha256':sha(base/'ready.json'),'counts':counts,'zero_shared_inodes':True,'canonical_lock_nonblocking_probe':0,'native_operation_unused':True}))
