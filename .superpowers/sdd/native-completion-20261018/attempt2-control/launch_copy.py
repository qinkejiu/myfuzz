"""Transfer the reviewed pure-copy parent, then execute that one operation."""
import hashlib,json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
payload=(HERE/'run_remote_copy.py').read_bytes()
pin=hashlib.sha256(payload).hexdigest()
remote='''import hashlib,os,sys
from pathlib import Path
root=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt2')
if not root.is_dir() or any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('input-root')
data=sys.stdin.buffer.read()
if hashlib.sha256(data).hexdigest()!=PIN:raise ValueError('controller-pin')
path=root/'run_remote_copy.py'
with path.open('xb') as f:f.write(data)
os.environ['PYTHONDONTWRITEBYTECODE']='1'
os.execv('/usr/bin/python3',['/usr/bin/python3',str(path)])
'''.replace('PIN',repr(pin))
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
with (HERE/'copy-launch.stdout').open('xb') as out,(HERE/'copy-launch.stderr').open('xb') as err:
 p=subprocess.Popen(['ssh','jumpserver',cmd],stdin=subprocess.PIPE,stdout=out,stderr=err)
 p.communicate(payload)
receipt=dict(returncode=p.returncode,controller_sha256=pin,pid=p.pid)
for name in ('copy-launch.stdout','copy-launch.stderr'):
 data=(HERE/name).read_bytes();receipt[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
with (HERE/'copy-launch-terminal.json').open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2)
print(json.dumps(receipt,sort_keys=True))
raise SystemExit(p.returncode)
