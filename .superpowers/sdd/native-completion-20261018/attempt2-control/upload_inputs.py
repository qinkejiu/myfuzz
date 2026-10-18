"""One explicit pure data transfer through jumpserver; no project/tool execution."""
import hashlib, json, shlex, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ARCHIVE=HERE/'copy-inputs.tar.gz'
PIN='3760aad022d262732c0b7782d25cce59d3b1a59a3b5c3aae2f49729d6c6b87a8'
REMOTE=r'''
import hashlib,io,json,os,stat,sys,tarfile
from pathlib import Path,PurePosixPath
root=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt2')
if any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('symlink-path')
if root.exists():raise ValueError('inputs-already-exist')
data=sys.stdin.buffer.read()
if hashlib.sha256(data).hexdigest()!='3760aad022d262732c0b7782d25cce59d3b1a59a3b5c3aae2f49729d6c6b87a8':raise ValueError('archive-pin')
tar=tarfile.open(fileobj=io.BytesIO(data),mode='r:gz')
seen=set();members=tar.getmembers()
for member in members:
 p=PurePosixPath(member.name)
 if not p.parts or p.is_absolute() or '..' in p.parts or str(p)!=member.name or member.name in seen:raise ValueError('archive-path')
 if not(member.isfile() or member.isdir()) or member.mode&~0o777:raise ValueError('archive-type-mode')
 seen.add(member.name)
root.mkdir(mode=0o755)
files={}
for member in members:
 path=root/member.name
 if member.isdir():path.mkdir(parents=True,exist_ok=True)
 else:
  path.parent.mkdir(parents=True,exist_ok=True)
  with tar.extractfile(member) as source,path.open('xb') as target:
   while chunk:=source.read(1024*1024):target.write(chunk)
  path.chmod(member.mode)
  files[member.name]=dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
for member in reversed(members):
 if member.isdir():(root/member.name).chmod(member.mode)
receipt=dict(status='pure_inputs_uploaded_only',archive_sha256=hashlib.sha256(data).hexdigest(),files=files,remote_root=str(root),pid=os.getpid(),native_execution=False)
with (root/'upload-receipt.json').open('x') as f:json.dump(receipt,f,sort_keys=True)
print(json.dumps(receipt,sort_keys=True))
'''
data=ARCHIVE.read_bytes()
if hashlib.sha256(data).hexdigest()!=PIN:raise ValueError('local-pin')
remote_command='python3 -c '+shlex.quote(REMOTE)
jump_command='ssh root@192.168.5.70 '+shlex.quote(remote_command)
p=subprocess.run(['ssh','jumpserver',jump_command],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
(HERE/'upload.stdout').write_bytes(p.stdout);(HERE/'upload.stderr').write_bytes(p.stderr)
receipt=dict(returncode=p.returncode,stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),stderr_sha256=hashlib.sha256(p.stderr).hexdigest(),archive_sha256=PIN)
with (HERE/'upload-terminal.json').open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2)
print(json.dumps(receipt,sort_keys=True))
if p.returncode:raise SystemExit(p.returncode)
