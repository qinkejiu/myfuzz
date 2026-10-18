import hashlib,json,os,stat,tarfile,time
from pathlib import Path,PurePosixPath
B=Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2')
A=B/'root-input.tar.gz'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(v,m):
 if not v:raise ValueError(m)
def main():
 need(A.stat().st_size==413926054 and sha(A)=='01e2d7740d8606ff67beec557d3e56e0fb771db0117826b291f02b96275bb321','archive pin before')
 need(sha(B/'transfer-manifest.json')=='2e749cb696b5ac001176a453de2471f3d3d5f22d4949f16caee1e40c57530c05','manifest pin')
 need(sha(B/'control-inputs.json')=='646948b9fc633fbdc192627c85a3a10f3edd7c8085e8b747110f332307c1c504','control manifest pin')
 m=json.loads((B/'transfer-manifest.json').read_bytes()); c=json.loads((B/'control-inputs.json').read_bytes())
 need(m['schema_version']=='p8_root_transfer_manifest.v1','schema')
 files,dirs=m['files'],m['directories']; seen=set();actualf={};actuald={}; saved={}
 wanted={'root/.git/HEAD','root/.git/refs/heads/codex/system-completion-20261016','control/freeze.json','control/prepare-receipt.json'}
 with tarfile.open(A,'r|gz') as t:
  for v in t:
   n=v.name;p=PurePosixPath(n)
   need(n and n!='.' and str(p)==n and not p.is_absolute() and '..' not in p.parts and p.parts[0] in ('root','control'),'canonical')
   need(n not in seen and not v.pax_headers,'duplicate or pax');seen.add(n)
   # USTAR emits only ordinary directory and regular records; reject all extension/link/special types.
   need(v.type in (tarfile.REGTYPE,tarfile.DIRTYPE) and not v.issparse(),'type')
   if v.isdir():
    need(n in dirs and v.size==0 and v.mode==dirs[n]['mode'],'directory')
    actuald[n]={'mode':v.mode}
   else:
    need(n in files,'unknown file');pin=files[n];need(v.size==pin['bytes'] and v.mode==pin['mode'],'file header')
    h=hashlib.sha256();size=0;parts=[]
    with t.extractfile(v) as f:
     while b:=f.read(1024*1024):
      h.update(b);size+=len(b)
      if n in wanted:parts.append(b)
    actualf[n]={'bytes':size,'mode':v.mode,'sha256':h.hexdigest()}
    need(actualf[n]==pin,'payload hash')
    if n in wanted:saved[n]=b''.join(parts)
 need(actualf==files and actuald==dirs and seen==set(files)|set(dirs),'complete sets')
 rootf={n[5:]:p for n,p in actualf.items() if n.startswith('root/')}; rootd={n[5:]:p for n,p in actuald.items() if n.startswith('root/')}
 need(rootf==m['frozen_root_files'] and rootd==m['frozen_root_directories'],'root maps')
 need(hashlib.sha256(saved['control/freeze.json']).hexdigest()=='27ec3b8a97d22b3272acf3dd90bf44f05a20f7ffd8c984be9b6b49054a2a6ba5','freeze pin')
 need(rootf==json.loads(saved['control/freeze.json']) and rootd==json.loads(saved['control/prepare-receipt.json'])['directories'],'actual freeze dirs')
 need(len(rootf)==10347 and len(rootd)==524,'root counts')
 controls={n[8:]:p for n,p in actualf.items() if n.startswith('control/')}
 need(controls=={n:{k:p[k] for k in ('bytes','mode','sha256')} for n,p in c['files'].items()} and len(controls)==20,'closed controls')
 need(saved['root/.git/HEAD']==b'ref: refs/heads/codex/system-completion-20261016\n' and saved['root/.git/refs/heads/codex/system-completion-20261016'].strip()==b'269717b7e9cc7c92da5e427ac950bc82446b3ac6','HEAD ref')
 need(sha(A)=='01e2d7740d8606ff67beec557d3e56e0fb771db0117826b291f02b96275bb321' and A.stat().st_size==413926054,'archive pin after')
 return dict(status='independent_saved_archive_verified',root_files=len(rootf),root_directories=len(rootd),control_files=len(controls),all_files=len(actualf),all_directories=len(actuald),archive_bytes=A.stat().st_size,archive_sha256=sha(A),manifest_sha256=sha(B/'transfer-manifest.json'),control_inputs_sha256=sha(B/'control-inputs.json'),archive_before_after_unchanged=True,root_HEAD='269717b7e9cc7c92da5e427ac950bc82446b3ac6',scope='local_saved_archive_only_no_remote_adapter_or_P8_grant')
if __name__=='__main__':
 result={'started_unix':time.time(),'pid':os.getpid(),'script_sha256':sha(Path(__file__))};rc=0
 try:result.update(main())
 except BaseException as e:rc=1;result.update(status='failed',error=repr(e))
 result.update(ended_unix=time.time(),returncode=rc)
 with (B/'independent-archive-audit.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
 print(json.dumps(result));raise SystemExit(rc)
