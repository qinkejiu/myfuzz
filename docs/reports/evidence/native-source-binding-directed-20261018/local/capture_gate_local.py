import hashlib,json,os,shlex,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
source=HERE/'collect_gate_readonly.py'
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='1ef0741cc875b91f96f104cd4e09278a1d7cefd7a843af8884a3ab4738b5f10f'
remote='PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -c '+shlex.quote(raw.decode())
argv=['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote(remote)]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):
 with p.open('x') as f:json.dump(v,f,sort_keys=True,indent=2);f.flush();os.fsync(f.fileno())
r=dict(argv=argv,source_sha256=sha(source),started_unix=time.time(),pid=os.getpid());proc=None;primary=None
try:
 with (HERE/'gate-capture.stdout').open('xb') as out,(HERE/'gate-capture.stderr').open('xb') as err:
  try:
   proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err);r['child_pid']=proc.pid;write(HERE/'gate-capture-start.json',r)
  except BaseException as e:primary=e
  finally:
   if proc is not None:
    while True:
     try:r['returncode']=proc.wait(timeout=30);break
     except subprocess.TimeoutExpired:continue
     except BaseException as e:
      if primary is None:primary=e
finally:
 r['ended_unix']=time.time();r['error']=repr(primary) if primary else None
 for name in ('stdout','stderr'):
  p=HERE/('gate-capture.'+name)
  if p.exists():r[name+'_sha256']=sha(p)
 r['source_unchanged']=sha(source)==r['source_sha256'];write(HERE/'gate-capture-terminal.json',r)
if primary:raise primary
if not r['source_unchanged']:raise ValueError('collector-source-drift')
raise SystemExit(r.get('returncode',1))
