"""Transfer only the independently reviewed native gate parent and launcher."""
import base64,hashlib,json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
PINS={'run_native_gate.py':'4e08528bbc01f587f888ba3de1fd3dfbb1af04b6824bcf776a105f2df259a8a5',
 'launch-native-gate.sh':'3e5f5560ac8e190c67c37818266da05f4ca31533c13fca3a799547923c245774'}
payload={}
for name,pin in PINS.items():
 data=(HERE/name).read_bytes()
 if hashlib.sha256(data).hexdigest()!=pin:raise ValueError('unreviewed-control:'+name)
 payload[name]=dict(base64=base64.b64encode(data).decode(),sha256=pin)
data=json.dumps(payload,sort_keys=True).encode()
remote='''import base64,hashlib,json,os,sys
from pathlib import Path
root=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt2')
if not root.is_dir() or any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('input-root')
payload=json.loads(sys.stdin.buffer.read())
if set(payload)!=set(PINS):raise ValueError('control-set')
for name,row in payload.items():
 data=base64.b64decode(row['base64'],validate=True)
 if hashlib.sha256(data).hexdigest()!=PINS[name]:raise ValueError('control-pin')
 if (root/name).exists():raise ValueError('control-already-exists')
for name,row in payload.items():
 path=root/name
 with path.open('xb') as f:f.write(base64.b64decode(row['base64'],validate=True))
 path.chmod(0o755 if name.endswith('.sh') else 0o644)
receipt=dict(status='gate_controls_uploaded_not_executed',pins=PINS,pid=os.getpid())
with (root/'gate-control-upload.json').open('x') as f:json.dump(receipt,f,sort_keys=True)
print(json.dumps(receipt,sort_keys=True))
'''.replace('PINS',repr(PINS))
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
p=subprocess.run(['ssh','jumpserver',cmd],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
for name,out in [('gate-upload.stdout',p.stdout),('gate-upload.stderr',p.stderr)]:
 with (HERE/name).open('xb') as f:f.write(out)
receipt=dict(returncode=p.returncode,pins=PINS,stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),stderr_sha256=hashlib.sha256(p.stderr).hexdigest())
with (HERE/'gate-upload-terminal.json').open('x') as f:json.dump(receipt,f,sort_keys=True,indent=2)
print(json.dumps(receipt,sort_keys=True))
raise SystemExit(p.returncode)
