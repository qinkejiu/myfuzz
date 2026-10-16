from pathlib import Path
import subprocess,shlex,json
archive=Path('/tmp/cvw-ahb-reviewed-preparation-20261017.tar.gz')
receiver=r'''
import os,sys,hashlib,tarfile,posixpath,copy,json
from pathlib import Path,PurePosixPath
base=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1')
assert not any(p.is_symlink() for p in (base,*base.parents))
base.mkdir(mode=0o755)
(base/'tmp').mkdir(mode=0o755)
path=base/'prepared-source-control.tar.gz'
with path.open('xb') as output:
 while True:
  data=sys.stdin.buffer.read(1024*1024)
  if not data:break
  output.write(data)
actual=hashlib.sha256(path.read_bytes()).hexdigest()
assert actual=='dc4dc8f32e93655d8bea529b5f851638b4932ce232581fa0e189cf0578f9d8c4',actual
with tarfile.open(path,'r:gz') as archive:
 members=archive.getmembers();links={m.name for m in members if m.issym()}
 for member in members:
  name=PurePosixPath(member.name)
  assert not name.is_absolute() and '..' not in name.parts and name.parts[0] in ('project','control')
  assert member.isdir() or member.isfile() or member.issym()
  assert not member.islnk()
  assert not any(str(parent) in links for parent in name.parents)
  if member.issym():
   target=PurePosixPath(posixpath.normpath(str(name.parent/member.linkname)))
   assert not PurePosixPath(member.linkname).is_absolute() and target.parts[0]=='project' and '..' not in target.parts
 def reviewed_filter(member,destination):
  member=copy.copy(member);member.uid=os.getuid();member.gid=os.getgid();member.uname='';member.gname=''
  return member
 archive.extractall(base,filter=reviewed_filter)
(base/'transfer-receipt.json').write_text(json.dumps(dict(source_only=True,native_run=False,archive_sha256=actual,archive_bytes=path.stat().st_size,exclusive_base_created=True,tar_hardlinks=False),indent=2)+'\n')
print(json.dumps({'copied':True,'archive_sha256':actual,'base':str(base)}))
'''
command='cd /root/fanzehui && '+shlex.join(['python3','-c',receiver])
outer='ssh root@192.168.5.70 '+shlex.quote(command)
with archive.open('rb') as data:
 process=subprocess.Popen(['ssh','jumpserver',outer],stdin=data,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 output,_=process.communicate()
print(output,end='')
receipt=Path('/home/qinkejiu/myfuzz/docs/reports/evidence/cvw-ahb-control-20261017/remote-transfer.log')
receipt.write_text(output+'\nactual_ssh_exit='+str(process.returncode)+'\n')
raise SystemExit(process.returncode)
