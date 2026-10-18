import hashlib,json,os,subprocess,time
from pathlib import Path
C=Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2/transport-drafts')
D=Path('/home/qinkejiu/myfuzz/docs/reports/evidence/p8-root-remote-input-20261018')
A=D/'actual-remote.tar'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,r):
 with p.open('x') as f:json.dump(r,f,indent=2);f.flush();os.fsync(f.fileno())
def run(stem,argv,pin):
 assert sha(Path(argv[2]))==pin
 r=dict(started_unix=time.time(),argv=argv,source_sha256=pin,returncode=None);child=None;primary=None
 with (D/(stem+'.stdout')).open('xb') as out,(D/(stem+'.stderr')).open('xb') as err:
  try:
   child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err);r['pid']=child.pid;write(D/(stem+'-start.json'),r)
  except BaseException as e:primary=e
  finally:
   if child:
    while True:
     try:r['returncode']=child.wait(timeout=30);break
     except subprocess.TimeoutExpired:continue
     except BaseException as e:
      if primary is None:primary=e
 r.update(ended_unix=time.time(),error=repr(primary) if primary else None,stdout_sha256=sha(D/(stem+'.stdout')),stderr_sha256=sha(D/(stem+'.stderr')))
 write(D/(stem+'-terminal.json'),r);print(json.dumps(r),flush=True)
 if primary:raise primary
 if r['returncode']!=0:raise SystemExit(r['returncode'])
run('safe-extract',['/usr/bin/python3','-B',str(C/'extract_remote_root_saved.py'),'--archive',str(A),'--archive-sha256','40341bc81f8de8afc0787185d2dde2317b0660762c4e0cdb4a958f4872915ff8','--archive-bytes','16445440','--target','/home/qinkejiu/myfuzz/.superpowers/sdd/p8-source-metadata-20261018/offline-remote-root-attempt1','--receipt',str(D/'safe-extract-receipt.json'),'--member-index',str(D/'safe-extract-member-index.json')],'4c0af797ad53fed8a9a752c40ce766abf45b47f96e95e96ab535665bee23e849')
# Reviewed auditor consumes the original saved tar bytes plus pinned local controls; no extracted script is imported.
run('independent-audit',['/usr/bin/python3','-B',str(C/'audit_remote_root_saved.py'),'--archive',str(A),'--archive-sha256','40341bc81f8de8afc0787185d2dde2317b0660762c4e0cdb4a958f4872915ff8'],'31f07ab84385afa191fd88796d488fbdf3520e55c82abf4000b42a72fdd5911b')
