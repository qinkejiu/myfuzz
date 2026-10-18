"""Root-selected single offline ZipCPU metadata operation; no model execution."""
import datetime,hashlib,json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/'materialize_snapshot.py'
PIN='f8c4f32f58629864133db59eceadf1b66452931b8896c3657e00e637ff45a1fe'
data=SOURCE.read_bytes()
if hashlib.sha256(data).hexdigest()!=PIN:raise ValueError('unreviewed-materializer')
remote=r'''
import hashlib,json,os,sys
from pathlib import Path
root=Path('/root/fanzehui/myfuzz/operations/p8-source-metadata-inputs-20261018-attempt1')
if any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('input-symlink')
if root.exists():raise ValueError('inputs-already-exist')
data=sys.stdin.buffer.read()
if hashlib.sha256(data).hexdigest()!='f8c4f32f58629864133db59eceadf1b66452931b8896c3657e00e637ff45a1fe':raise ValueError('materializer-pin')
root.mkdir(mode=0o755)
path=root/'materialize_snapshot.py'
with path.open('xb') as f:f.write(data)
argv=['/usr/bin/python3',str(path),'--component','zipcpu',
 '--output','/root/fanzehui/myfuzz/operations/p8-source-zipcpu-metadata-20261018-attempt1',
 '--git','/usr/bin/git','--git-sha256','2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668']
with (root/'selected-launch.json').open('x') as f:json.dump(dict(argv=argv,controller_sha256=hashlib.sha256(data).hexdigest(),pid=os.getpid()),f,sort_keys=True)
os.environ['PYTHONDONTWRITEBYTECODE']='1'
with (root/'parent.stdout').open('xb') as out,(root/'parent.stderr').open('xb') as err:
 os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
 os.execv(argv[0],argv)
'''
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
record=dict(schema_version='p8_zipcpu_offline_root_launch.v1',started_at=now(),controller_sha256=PIN,
 component='zipcpu',network_fallback=False,models=False)
primary=None
with (HERE/'zipcpu-launch.stdout').open('xb') as out,(HERE/'zipcpu-launch.stderr').open('xb') as err:
 proc=subprocess.Popen(['ssh','jumpserver',cmd],stdin=subprocess.PIPE,stdout=out,stderr=err)
 try:
  record['ssh_pid']=proc.pid
  with (HERE/'zipcpu-launch-start.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
  proc.stdin.write(data);proc.stdin.close()
 except BaseException as error:primary=error
 finally:
  # Same actual SSH/remote job remains owned through observation interruption.
  if proc.stdin is not None and not proc.stdin.closed:proc.stdin.close()
  while True:
   try:record['returncode']=proc.wait(timeout=30);break
   except subprocess.TimeoutExpired:continue
   except BaseException as error:
    if primary is None:primary=error
record['ended_at']=now()
if primary is not None:record['primary_error']=repr(primary)
for name in ('zipcpu-launch.stdout','zipcpu-launch.stderr'):
 body=(HERE/name).read_bytes();record[name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
with (HERE/'zipcpu-launch-terminal.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps(record,sort_keys=True))
if primary is not None:raise primary
raise SystemExit(record['returncode'])
