import hashlib,json,os,shlex,subprocess,time
from pathlib import Path
S=Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2/transport-drafts/collect_remote_root_readonly.py')
D=Path('/home/qinkejiu/myfuzz/docs/reports/evidence/p8-root-remote-input-20261018')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,r):
 with p.open('x') as f:json.dump(r,f,indent=2);f.flush();os.fsync(f.fileno())
need='fb5e57728cad8b293fb1771d48012f68b16992bbd6336dd098dd13f3ffe0b734'
assert sha(S)==need
D.mkdir(exist_ok=True)
code=S.read_text();argv=['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote('PYTHONOPTIMIZE=0 PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(code))]
r=dict(started_unix=time.time(),collector_sha256=need,argv=argv,returncode=None);child=None;primary=None
with (D/'actual-remote.tar').open('xb') as out,(D/'download.stderr').open('xb') as err:
 try:
  child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err);r['pid']=child.pid;write(D/'download-start.json',r)
 except BaseException as e:primary=e
 finally:
  if child is not None:
   while True:
    try:r['returncode']=child.wait(timeout=30);break
    except subprocess.TimeoutExpired:continue
    except BaseException as e:
     if primary is None:primary=e
r.update(ended_unix=time.time(),error=repr(primary) if primary else None,archive_bytes=(D/'actual-remote.tar').stat().st_size,archive_sha256=sha(D/'actual-remote.tar'),stderr_bytes=(D/'download.stderr').stat().st_size,stderr_sha256=sha(D/'download.stderr'))
write(D/'download-terminal.json',r)
print(json.dumps({k:v for k,v in r.items() if k!='argv'}))
if primary:raise primary
raise SystemExit(r['returncode'] if r['returncode'] is not None else 1)
