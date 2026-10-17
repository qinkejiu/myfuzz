import sys
sys.dont_write_bytecode=True
import os,json,hashlib,subprocess,time
from pathlib import Path
base=Path('/root/fanzehui/myfuzz/operations/p7-i5-independent-601964f-20261018-attempt2')
inputs=Path('/root/fanzehui/myfuzz/operations/p7-i5-attempt2-inputs-20261018')
control=base/'control';root=base/'project';run=base/'run-attempt2'
def write(name,obj):
 with (control/name).open('x') as f:json.dump(obj,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def child(name,argv):
 receipt={'argv':argv,'cwd':str(root),'started_unix':time.time(),'returncode':None}
 with (control/(name+'.stdout')).open('xb') as out,(control/(name+'.stderr')).open('xb') as err:
  p=subprocess.Popen(argv,cwd=root,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONOPTIMIZE='0'),stdin=subprocess.DEVNULL,stdout=out,stderr=err)
  primary=None
  try:receipt['pid']=p.pid;write(name+'.launch.json',receipt)
  except BaseException as e:primary=e
  while True:
   try:code=p.wait(timeout=30);break
   except subprocess.TimeoutExpired:continue
   except BaseException as e:
    if primary is None:primary=e
  receipt.update(returncode=code,ended_unix=time.time(),stdout_sha256=sha(control/(name+'.stdout')),stderr_sha256=sha(control/(name+'.stderr')))
  write(name+'.terminal.json',receipt)
  if primary is not None:raise primary
 return code
verify=[sys.executable,str(inputs/'verify_layout.py'),'--root',str(root),'--receipt',str(control/'final-copy-receipt.json'),'--freeze',str(control/'final-file-freeze.json')]
if child('layout-before-gate',verify):raise ValueError('pre-gate-layout-refused')
freeze_sha=sha(control/'final-file-freeze.json')
if freeze_sha!='e3d2eaa2937fd665ad816250e976e7745cefe220a71e51a5815a892bd35a13fa':raise ValueError('root-reviewed-file-freeze-drift')
if json.loads((control/'final-copy-receipt.json').read_bytes())['directory_manifest_sha256']!='9e055be358785fdd196c3be6e35dd0e61fb4d986643430cc77c9d766577c750c':raise ValueError('root-reviewed-directory-freeze-drift')
argv=[sys.executable,str(root/'scripts/run_p7_i5_acceptance.py'),'--base-dir',str(root),'--freeze-map',str(control/'final-file-freeze.json'),'--freeze-sha256',freeze_sha,'--expected-commit','6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941','--output',str(run),'--client-binary',str(base/'client/kfuzz'),'--client-sha256','16434544a4a0712fa7716f6f3e3ff8e0dd949139f6a047780f4d08694ff31dcc','--lock-file','/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock','--pythonlib','/root/fanzehui/myfuzz/pythonlib','--tool-freeze','/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/tool-freeze.json','--tool-freeze-sha256','6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b','--execute']
code=None
try:code=child('i5-attempt2-controller',argv)
finally:
 layoutcode=child('layout-after-gate',verify)
 write('attempt2-operation-result.json',{'runner_returncode':code,'layout_returncode':layoutcode,'formal_p7_complete':False,'status':'collected_pending_independent_audit' if code==0 and layoutcode==0 else 'failed'})
raise SystemExit(0 if code==0 and layoutcode==0 else 1)
