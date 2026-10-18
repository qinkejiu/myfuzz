"""Read durable state and specific live process handles; never restart or kill."""
import hashlib,json,shlex,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
remote=r'''
import datetime,json,subprocess
from pathlib import Path
base=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt1')
control=base/'gate-control'
result=dict(observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),records={},processes={})
for name in ('parent-start.json','parent-terminal.json','native-directed-gate.launch.json','native-directed-gate.terminal.json'):
 p=control/name
 if p.is_file():
  try:result['records'][name]=json.loads(p.read_bytes())
  except Exception as e:result['records'][name]={'read_error':repr(e)}
for name,row in result['records'].items():
 if type(row.get('pid')) is int:
  process=subprocess.run(['ps','-p',str(row['pid']),'-o','pid,ppid,stat,etime,args'],capture_output=True,text=True)
  result['processes'][name]=dict(returncode=process.returncode,stdout=process.stdout)
for name in ('native-directed-gate.stdout','native-directed-gate.stderr'):
 p=control/name
 if p.is_file():
  with p.open('rb') as f:
   f.seek(max(0,p.stat().st_size-6000));tail=f.read()
  result[name]=dict(bytes=p.stat().st_size,tail=tail.decode(errors='replace'))
for name in ('positive','controlled-response'):
 d=base/'run-directed'/name
 if d.is_dir():result[name+'_files']=sorted(p.name for p in d.iterdir())
print(json.dumps(result,sort_keys=True))
'''
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
p=subprocess.run(['ssh','jumpserver',cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
record=json.loads(p.stdout) if p.returncode==0 else dict(error_stderr=p.stderr.decode(errors='replace'),returncode=p.returncode)
name='gate-observation-'+str(len(list(HERE.glob('gate-observation-*.json')))+1)+'.json'
with (HERE/name).open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps(record,sort_keys=True))
raise SystemExit(p.returncode)
