"""Unexecuted draft pinned to actual raw plan; independent saved audit/GO still required."""
import argparse,hashlib,json,shlex,subprocess,os,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ACTUAL_PLAN_SHA256='aca9b2582f64e08a793853c5f9d2c143ed927b822d170204c56c47f2c027e201'
COPIER='b3bb05ef870551045539a1626690b2987fe08f362ef4c04ba58f2d3d2b342cf6'
REMOTE=r'''
import hashlib,json,os,stat,subprocess,time,sys,tarfile,io,fcntl
from pathlib import Path
root=Path('/root/fanzehui/myfuzz/operations/p8-full-project-inputs-20261018-attempt1');plan_pin=PLANPIN;pins=PINS
lock=Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock')
def need(v,m):
 if not v:raise ValueError(m)
def safe(p):
 need(p.is_absolute() and p.is_relative_to('/root/fanzehui') and '..' not in p.parts,'path-outside-fan')
 for q in (p,*p.parents):need(not q.is_symlink(),'path-symlink')
def sha(p):
 safe(p)
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(n,row):
 safe(root/n)
 with (root/n).open('x') as f:json.dump(row,f,sort_keys=True,indent=2);f.flush();os.fsync(f.fileno())
def census(source):
 safe(source);files={};dirs={}
 for parent,children,names in os.walk(source,followlinks=False):
  for name in list(children):
   path=Path(parent)/name;info=path.lstat();rel=path.relative_to(source).as_posix()
   if stat.S_ISLNK(info.st_mode):children.remove(name);names.append(name)
   else:need(stat.S_ISDIR(info.st_mode),'source-dir-type');dirs[rel]={'mode':stat.S_IMODE(info.st_mode)}
  for name in names:
   path=Path(parent)/name;info=path.lstat();rel=path.relative_to(source).as_posix()
   if stat.S_ISLNK(info.st_mode):
    raw=os.fsencode(os.readlink(path));files[rel]=dict(kind='symlink',mode=stat.S_IMODE(info.st_mode),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),linkbytes_hex=raw.hex(),git_oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())
   else:need(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'source-file-type');files[rel]=dict(kind='regular',mode=stat.S_IMODE(info.st_mode),bytes=info.st_size,sha256=sha(path))
 return dict(files=files,directories=dirs)
record=dict(schema_version='p8_actual_prepare_parent.v1',pid=os.getpid(),started_unix=time.time(),returncode=None,plan_sha256=plan_pin,pins=pins);primary=None;child=None
try:
 safe(root);safe(lock)
 need(sha(root/'project-plan.json')==plan_pin,'actual-reviewed-plan-pin')
 need(sha(root/'project-plan-receipt.json')=='8799c03770c074df8cdae5dc448ddf505cfd42a2eed51fa9fbb5f1302e7be37f','actual-raw-plan-receipt-pin')
 need(pins['prepare_p8_project.py']['sha256']=='b3bb05ef870551045539a1626690b2987fe08f362ef4c04ba58f2d3d2b342cf6','copier-pin')
 plan=json.loads((root/'project-plan.json').read_bytes());receipt=json.loads((root/'project-plan-receipt.json').read_bytes());prior=json.loads((root/'plan-parent-terminal.json').read_bytes())
 need(receipt['status']=='planned_pending_explicit_prepare' and receipt['source_unchanged'] is True and prior['returncode']==0 and prior['error'] is None and prior['pins']==pins,'actual-plan-receipt-chain')
 selection=json.loads((root/'selection.json').read_bytes())
 argv=['/usr/bin/python3','-B',str(root/'prepare_p8_project.py'),'prepare','--selection',str(root/'selection.json'),'--selection-sha256',pins['selection.json']['sha256'],'--plan',str(root/'project-plan.json'),'--plan-sha256',plan_pin,'--destination',plan['destination'],'--receipt',str(root/'project-prepare-receipt.json')]
 record['argv']=argv;record['cwd']=str(root)
 with lock.open('a+b') as held:
  fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   for name,pin in pins.items():
    path=root/name;s=path.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==pin['bytes'] and stat.S_IMODE(s.st_mode)==pin['mode'] and sha(path)==pin['sha256'],'latest-eleven-input-pins')
   before={row['id']:census(Path(row['source'])) for row in selection['inputs']};write('prepare-source-before.json',before);need(before==plan['source_maps'],'latest-whole-source-map')
   write('prepare-parent-start.json',record)
   with (root/'prepare.stdout').open('xb') as out,(root/'prepare.stderr').open('xb') as err:
    try:child=subprocess.Popen(argv,cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err);record['child_pid']=child.pid;write('prepare-child-start.json',dict(pid=child.pid,argv=argv))
    except BaseException as error:primary=error
    finally:
     if child is not None:
      while True:
       try:record['returncode']=child.wait(timeout=30);break
       except subprocess.TimeoutExpired:continue
       except BaseException as error:
        if primary is None:primary=error
  finally:
   try:
    after={row['id']:census(Path(row['source'])) for row in selection['inputs']};write('prepare-source-after.json',after);need(after==plan['source_maps'],'whole-source-after-map')
    for name,pin in pins.items():
     path=root/name;info=path.lstat();need(not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==pin['bytes'] and stat.S_IMODE(info.st_mode)==pin['mode'] and sha(path)==pin['sha256'],'post-eleven-source-pins')
   except BaseException as error:
    if primary is None:primary=error
    else:primary.add_note('after collection: '+repr(error))
except BaseException as error:
 if primary is None:primary=error
 else:primary.add_note('outer: '+repr(error))
finally:
 record.update(ended_unix=time.time(),error=repr(primary) if primary else None,status='prepared_pending_independent_audit' if primary is None and record['returncode']==0 else 'failed')
 for name in ('stdout','stderr'):
  path=root/('prepare.'+name)
  try:
   if path.exists():record[name+'_sha256']=sha(path)
  except BaseException as error:
   if primary is None:primary=error
   else:primary.add_note('stream collection: '+repr(error))
 record.update(error=repr(primary) if primary else None,status='prepared_pending_independent_audit' if primary is None and record['returncode']==0 else 'failed')
 try:write('prepare-parent-terminal.json',record)
 except BaseException as error:
  if primary is None:primary=error
  else:primary.add_note('terminal write: '+repr(error))
 blobs={name:p.read_bytes() for name in ('prepare-parent-start.json','prepare-parent-terminal.json','prepare-child-start.json','prepare.stdout','prepare.stderr','project-prepare-receipt.json','prepare-source-before.json','prepare-source-after.json') if (p:=root/name).exists()}
 blobs['returned-member-pins.json']=json.dumps({n:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()) for n,b in blobs.items()},sort_keys=True).encode()
 with tarfile.open(fileobj=sys.stdout.buffer,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
  for name,raw in blobs.items():m=tarfile.TarInfo(name);m.mode=0o644;m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
if primary:raise primary
raise SystemExit(record['returncode'] if record['returncode'] is not None else 1)
'''
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 if not isinstance(ACTUAL_PLAN_SHA256,str) or len(ACTUAL_PLAN_SHA256)!=64:raise ValueError('closed-until-root-pins-independently-reviewed-actual-plan')
 audit_terminal=HERE/'actual-plan-audit.terminal.json';audit_stdout=HERE/'actual-plan-audit.stdout';audit_stderr=HERE/'actual-plan-audit.stderr'
 if sha(audit_terminal)!='642262989c8627156e2405cadbd94585cb3a18aba055d9ff8e65accdb7eda680' or sha(audit_stdout)!='5d75d80a464ff1992034331b5226966cdaa6737b87c984dc3875b5118b57e575':raise ValueError('actual-independent-plan-audit-pins')
 actual=json.loads(audit_terminal.read_bytes());verified=json.loads(audit_stdout.read_bytes())
 if actual['returncode']!=0 or actual['error'] is not None or sha(audit_stderr)!=actual['stderr_sha256'] or sha(audit_stdout)!=actual['stdout_sha256'] or verified['plan_sha256']!=ACTUAL_PLAN_SHA256 or verified['status']!='independent_saved_plan_verified_pending_root_prepare_decision':raise ValueError('actual-independent-plan-audit-status')
 if sha(HERE/'audit_saved_plan.py')!='c1c138b1bf4a95f312a5a67a6a3d91023453e6c5d6f5607ee536393ab1450550':raise ValueError('actual-auditor-source-drift')
 p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--inputs-sha256',required=True);a=p.parse_args()
 if a.inputs_sha256!='671239187ae35ad61c21693870ceaad1a2cb1d376a8121e9f37b23ea89c49280' or sha(a.inputs)!=a.inputs_sha256:raise ValueError('actual-reviewed-input-manifest-pin')
 descriptors=json.loads(a.inputs.read_bytes());pins={name:{key:row[key] for key in ('bytes','mode','sha256')} for name,row in sorted(descriptors.items())}
 if len(pins)!=11 or pins['prepare_p8_project.py']['sha256']!=COPIER:raise ValueError('eleven-copier-pins')
 code=REMOTE.replace('PLANPIN',repr(ACTUAL_PLAN_SHA256)).replace('PINS',repr(pins));command='ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(code))
 # Reuse the already reviewed same-process SSH wait helper as source, not the
 # actual uploader/plan entry. This draft is closed before the import/launch.
 if sha(HERE/'full_project_controls.py')!='e3b5ac67e0123db6bc7fcd26b565d49d62d5c21b65130179f02733cce34cefae':raise ValueError('actual-reviewed-wait-helper-source-pin')
 from full_project_controls import owned
 owned('full-input-prepare',['ssh','jumpserver',command])
if __name__=='__main__':main()
