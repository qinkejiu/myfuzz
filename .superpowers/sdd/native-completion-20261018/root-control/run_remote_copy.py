"""Remote pure-copy parent receipt; no Git, frontend, compiler or model child."""
import datetime, hashlib, json, os, subprocess, sys
from pathlib import Path
ROOT=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt1')
if Path(__file__).resolve()!=ROOT/'run_remote_copy.py':raise ValueError('unexpected-controller-location')
if any(p.is_symlink() for p in (ROOT,*ROOT.parents)):raise ValueError('symlink-input')
pins={'overlay-map.json':'dc2e13a12e5fe3b92cb3b7ef4ae476bc566af89c61a65f94ce900717eeb55d06',
      'overlay-paths.json':'95aa801ae01dd3696e93cfec85bac16eeebd1c48bd8792421709c6cb9bf104d7'}
for name,pin in pins.items():
 if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=pin:raise ValueError('control-pin')
argv=['/usr/bin/python3',str(ROOT/'prepare_copy.py'),'--baseline-files',str(ROOT/'baseline-files.json'),
 '--baseline-directories',str(ROOT/'baseline-directories.json'),'--overlay-tree',str(ROOT/'overlay'),
 '--overlay-map',str(ROOT/'overlay-map.json'),'--overlay-paths',str(ROOT/'overlay-paths.json'),
 '--overlay-map-sha256',pins['overlay-map.json'],'--overlay-paths-sha256',pins['overlay-paths.json']]
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
receipt=dict(schema_version='native_completion_pure_copy_parent.v1',pid=os.getpid(),argv=argv,cwd=str(ROOT),
 started_at=now(),native_execution=False,controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 preparer_sha256=hashlib.sha256((ROOT/'prepare_copy.py').read_bytes()).hexdigest())
primary=None
with (ROOT/'copy.stdout').open('xb') as out,(ROOT/'copy.stderr').open('xb') as err:
 child=subprocess.Popen(argv,cwd=ROOT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout=out,stderr=err)
 receipt['child_pid']=child.pid
 try:
  with (ROOT/'copy-parent-start.json').open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2)
 except BaseException as error:
  primary=error
 finally:
  # Never leave the actual copy unobserved because recording failed. An
  # observation interruption is not permission to terminate or relaunch it.
  while True:
   try:
    receipt['returncode']=child.wait()
    break
   except BaseException as error:
    if primary is None:primary=error
receipt['ended_at']=now()
if primary is not None:receipt['primary_error']=repr(primary)
try:
 for name in ('copy.stdout','copy.stderr'):
  data=(ROOT/name).read_bytes();receipt[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
 with (ROOT/'copy-parent-terminal.json').open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2)
except BaseException as error:
 if primary is None:primary=error
 else:primary.add_note('copy evidence collection failed: '+repr(error))
print(json.dumps(receipt,sort_keys=True))
if primary is not None:raise primary
sys.exit(receipt['returncode'])
