import fcntl,hashlib,json,os
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-runtime-gate-20261017')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(base/'ready.json')=='5bde90ac4bc6ae3fe6ffb9bba549421073484b5b515f02d28bf7ee0d40bc7449'
ready=json.loads((base/'ready.json').read_text())
assert sha(base/'control/controller.py')=='8eeb849023137d0319bfa0ccc3f8ffb8f4763b58e4f952881239a6a357be8f36'
assert sha(base/'control/launch.sh')=='98766db3336248fb150b1449ee26e4fcd3be988dcf178296ae23e1dfd1c6ec1c'
assert sha(base/'source-freeze.json')=='ff5470d2345868bb6f7452b58e38e2ad279c3fc99a66573a3e13cee2e8870167'
for name,digest in ready['control_hashes'].items():
 p=base/name;assert p.resolve().is_relative_to(base) and not any(x.is_symlink() for x in (p,*p.parents));assert sha(p)==digest,name
for name in ('PID','launcher-PID','worker.exit','operation.claim','native-PID','native.exit'):
 p=base/'state'/name;assert not p.exists() and not p.is_symlink(),name
for name in ('gate-output','gpio-cache','logs/controller.log'):
 p=base/name;assert not p.exists() and not p.is_symlink(),name
counts={}
for mapname,root in (('project-files.json',base/'project'),('original-source-files.json',Path('/root/fanzehui/boom-irq-metadata-recovery-20261017/project-finalized')),('original-artifact-files.json',Path('/root/fanzehui/boom-irq-metadata-recovery-20261017/artifact-finalized'))):
 expected=json.loads((base/mapname).read_text())['files'];actual={}
 for p in root.rglob('*'):
  assert not p.is_symlink()
  if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':
   assert p.stat().st_nlink==1;actual[p.relative_to(root).as_posix()]=sha(p)
 assert actual==expected,mapname;counts[mapname]=len(actual)
original=Path('/root/fanzehui/boom-irq-metadata-recovery-20261017')
assert sha(original/'artifact-finalized/irq-session-artifact.json')=='ec4431b9aa2b75932d9a689d5e5bc1041f6bd25158919bd16e240a428bbd5737'
expected=json.loads((base/'original-source-files.json').read_text())['files']
assert all(not os.path.samestat((base/'project'/n).stat(),(original/'project-finalized'/n).stat()) for n in expected)
with Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock').open('rb') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print(json.dumps({'root_preflight':'pass','ready_sha256':sha(base/'ready.json'),'counts':counts,'zero_shared_inodes':True,'canonical_lock_nonblocking_probe':0,'native_operation_unused':True}))
