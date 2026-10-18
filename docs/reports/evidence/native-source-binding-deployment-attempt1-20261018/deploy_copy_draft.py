"""UNEXECUTED fixed pure-file deployment draft; no model/Git/tool query."""
import hashlib, io, json, os, shlex, stat, subprocess, sys, tarfile, time
from pathlib import Path
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TARGET = '/root/fanzehui/myfuzz/operations/p6-native-source-binding-inputs-20261018-attempt1'
PINS = {
 'copy-inputs.tar.gz': '272a3b0cd8713aa7cc3b0b27fbf7ae05aa9be0e8f0e588509ba50601c37e56c7',
 'run_native_gate.py': '04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717',
 'launch-native-gate.sh': 'dbc7b7fe1ff78461fe79ca4b1925401e9ab28cde05bcbeb3d9c91faca89027ac',
}
def digest(data): return hashlib.sha256(data).hexdigest()
def write(path, value):
 with path.open('x') as stream:
  json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
def inputs():
 result = {}
 for name, pin in PINS.items():
  path=HERE/name; info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise ValueError('local-input-type')
  data=path.read_bytes()
  if digest(data)!=pin: raise ValueError('local-input-pin:'+name)
  result[name]=dict(bytes=len(data),sha256=pin,mode=stat.S_IMODE(info.st_mode))
 self_data=Path(__file__).read_bytes()
 result['deploy_copy_draft.py']=dict(bytes=len(self_data),sha256=digest(self_data),mode=stat.S_IMODE(Path(__file__).stat().st_mode))
 return result
REMOTE = r'''
import hashlib,io,json,os,stat,subprocess,sys,tarfile,time
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
ROOT=Path('/root/fanzehui/myfuzz/operations/p6-native-source-binding-inputs-20261018-attempt1')
STAGE=ROOT.with_name(ROOT.name+'.unpublished')
def digest(b):return hashlib.sha256(b).hexdigest()
def write(p,v):
 with p.open('x') as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def safe(p):
 if not p.is_absolute() or not p.is_relative_to('/root/fanzehui'):raise ValueError('outside-fan')
 for q in (p,*p.parents):
  if q.is_symlink():raise ValueError('symlink-ancestor')
def parse(data):
 t=tarfile.open(fileobj=io.BytesIO(data),mode='r:*');files={};dirs={}
 for m in t.getmembers():
  p=PurePosixPath(m.name)
  if not p.parts or p.is_absolute() or '..' in p.parts or str(p)!=m.name or str(p)=='.' or m.name in files or m.name in dirs:raise ValueError('tar-path')
  if m.mode&~0o777 or not(m.isfile() or m.isdir()):raise ValueError('tar-type-mode')
  if m.isdir():dirs[m.name]={'mode':m.mode}
  else:
   b=t.extractfile(m).read()
   if len(b)!=m.size:raise ValueError('tar-size')
   files[m.name]=(b,{'bytes':len(b),'mode':m.mode,'sha256':digest(b)})
 for n in [*files,*dirs]:
  for parent in PurePosixPath(n).parents:
   if str(parent)!='.' and str(parent) not in dirs:raise ValueError('tar-parent')
 return files,dirs
def census(root):
 f={};d={}
 for folder,ds,ns in os.walk(root,followlinks=False):
  for n in ds:
   p=Path(folder)/n;s=p.lstat()
   if not stat.S_ISDIR(s.st_mode):raise ValueError('directory-type')
   d[p.relative_to(root).as_posix()]={'mode':stat.S_IMODE(s.st_mode)}
  for n in ns:
   p=Path(folder)/n;s=p.lstat()
   if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('file-type')
   b=p.read_bytes();f[p.relative_to(root).as_posix()]={'bytes':len(b),'mode':stat.S_IMODE(s.st_mode),'sha256':digest(b)}
 return f,d
safe(ROOT);safe(STAGE)
if ROOT.exists() or STAGE.exists():raise ValueError('exclusive-inputs-exist')
envelope=json.loads(sys.stdin.buffer.read());import base64
archive=base64.b64decode(envelope['archive'],validate=True)
if digest(archive)!='272a3b0cd8713aa7cc3b0b27fbf7ae05aa9be0e8f0e588509ba50601c37e56c7':raise ValueError('archive-pin')
files,dirs=parse(archive)
pins=json.loads(files['selection.json'][0]);overlay=json.loads(files['overlay-map.json'][0]);paths=json.loads(files['overlay-paths.json'][0])
expected=envelope['archive_manifest']
if {k:v[1] for k,v in files.items()}!=expected['files'] or dirs!=expected['directories']:raise ValueError('exact-reviewed-archive-manifest')
for name,pin in {'run_native_gate.py':'04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717','launch-native-gate.sh':'dbc7b7fe1ff78461fe79ca4b1925401e9ab28cde05bcbeb3d9c91faca89027ac'}.items():
 b=base64.b64decode(envelope[name],validate=True)
 if digest(b)!=pin or name in files:raise ValueError('deployment-control-pin')
 files[name]=(b,{'bytes':len(b),'mode':420,'sha256':pin})
STAGE.mkdir(mode=0o755)
for name in sorted(dirs,key=lambda n:(len(PurePosixPath(n).parts),n)):(STAGE/name).mkdir()
for name,(b,row) in files.items():
 with (STAGE/name).open('xb') as stream:stream.write(b)
 (STAGE/name).chmod(row['mode'])
for name in sorted(dirs,key=lambda n:len(PurePosixPath(n).parts),reverse=True):(STAGE/name).chmod(dirs[name]['mode'])
if census(STAGE)!=({k:v[1] for k,v in files.items()},dirs):raise ValueError('whole-inputs-census')
STAGE.rename(ROOT)
write(ROOT/'deployment-receipt.json',dict(pid=os.getpid(),status='inputs_published_no_gate',archive_sha256=digest(archive),files={k:v[1] for k,v in files.items()},directories=dirs,native_execution=False))
argv=['/usr/bin/python3','-B',str(ROOT/'prepare_copy.py'),'--baseline-files',str(ROOT/'baseline-files.json'),'--baseline-directories',str(ROOT/'baseline-directories.json'),'--overlay-tree',str(ROOT/'overlay'),'--overlay-map',str(ROOT/'overlay-map.json'),'--overlay-paths',str(ROOT/'overlay-paths.json'),'--overlay-map-sha256','3f0404498e11a4d1e9e5dadca72df9973e9778c4e4bcb4f097c6be4042429f24','--overlay-paths-sha256','551491be43df4fbdb540cb204bdb67428b7e4456dba25649ebf7934ca1700860']
record=dict(pid=os.getpid(),argv=argv,started_unix=time.time(),native_execution=False);proc=None;primary=None
try:
 with (ROOT/'copy.stdout').open('xb') as out,(ROOT/'copy.stderr').open('xb') as err:
  try:
   proc=subprocess.Popen(argv,cwd=ROOT,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL,stdout=out,stderr=err);record['child_pid']=proc.pid;write(ROOT/'copy-parent-start.json',record)
  except BaseException as e:primary=e
  finally:
   if proc is not None:
    while True:
     try:record['returncode']=proc.wait(timeout=30);break
     except subprocess.TimeoutExpired:continue
     except BaseException as e:
      if primary is None:primary=e
finally:
 record['ended_unix']=time.time();record['error']=repr(primary) if primary else None
 for n in ('copy.stdout','copy.stderr'):
  if (ROOT/n).exists():b=(ROOT/n).read_bytes();record[n]={'bytes':len(b),'sha256':digest(b)}
 write(ROOT/'copy-parent-terminal.json',record)
print(json.dumps(record,sort_keys=True))
if primary is not None:raise primary
sys.exit(record.get('returncode',1))
'''
def main():
 import base64
 before=inputs(); files={};dirs={}
 with tarfile.open(HERE/'copy-inputs.tar.gz') as archive:
  for m in archive.getmembers():
   if m.isdir():dirs[m.name]={'mode':m.mode}
   else:
    b=archive.extractfile(m).read();files[m.name]={'bytes':len(b),'mode':m.mode,'sha256':digest(b)}
 envelope={'archive_manifest':{'files':files,'directories':dirs}}
 for n in PINS:envelope['archive' if n=='copy-inputs.tar.gz' else n]=base64.b64encode((HERE/n).read_bytes()).decode()
 remote_command='/usr/bin/python3 -B -c '+shlex.quote(REMOTE)
 # Jump writes no file: its actual SSH child receipt is emitted into local stderr.
 jump="import subprocess,sys,json,os,time\nr={};p=None;primary=None\ntry:\n r.update(pid=os.getpid(),started_unix=time.time())\n p=subprocess.Popen(ARGV,stdin=sys.stdin.buffer)\n r['child_pid']=p.pid\nexcept BaseException as error:\n primary=error\nfinally:\n if p is not None:\n  while True:\n   try:r['returncode']=p.wait(timeout=30);break\n   except subprocess.TimeoutExpired:continue\n   except BaseException as error:\n    if primary is None:primary=error\n r['ended_unix']=time.time();r['error']=repr(primary) if primary else None\n r.setdefault('returncode',1)\n print(json.dumps(r,sort_keys=True),file=sys.stderr)\nif primary is not None:raise primary\nsys.exit(r['returncode'])\n".replace("ARGV", repr(["ssh", "root@192.168.5.70", remote_command]), 1)
 argv=['ssh','jumpserver','/usr/bin/python3 -B -c '+shlex.quote(jump)]
 record=dict(argv=argv,started_unix=time.time(),local_before=before,native_execution=False);proc=None;primary=None
 try:
  with (HERE/'deployment.stdout').open('xb') as out,(HERE/'deployment.stderr').open('xb') as err:
   try:
    proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=out,stderr=err);record['child_pid']=proc.pid;write(HERE/'deployment-start.json',record)
    proc.stdin.write(json.dumps(envelope).encode());proc.stdin.close()
   except BaseException as e:primary=e
   finally:
    if proc is not None:
     if proc.stdin and not proc.stdin.closed:
      try:proc.stdin.close()
      except BaseException as e:
       if primary is None:primary=e
     while True:
      try:record['returncode']=proc.wait(timeout=30);break
      except subprocess.TimeoutExpired:continue
      except BaseException as e:
       if primary is None:primary=e
 finally:
  record['ended_unix']=time.time()
  try:
   record['local_after']=inputs();record['local_unchanged']=record['local_after']==before
   if not record['local_unchanged']:raise ValueError('local-input-drift')
  except BaseException as e:
   if primary is None:primary=e
  for n in ('deployment.stdout','deployment.stderr'):
   if (HERE/n).exists():b=(HERE/n).read_bytes();record[n]={'bytes':len(b),'sha256':digest(b)}
  record['error']=repr(primary) if primary else None;write(HERE/'deployment-terminal.json',record)
 if primary is not None:raise primary
 sys.exit(record.get('returncode',1))
if __name__=='__main__':main()
