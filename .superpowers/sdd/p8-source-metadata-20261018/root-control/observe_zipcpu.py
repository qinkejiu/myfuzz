"""Read fixed ZipCPU attempt2 receipts and live process; never restarts it."""
import json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
remote=r'''
import datetime,json,subprocess
from pathlib import Path
base=Path('/root/fanzehui/myfuzz/operations/p8-source-zipcpu-metadata-20261018-attempt2')
control=base/'control'
inputs=Path('/root/fanzehui/myfuzz/operations/p8-source-metadata-inputs-20261018-attempt2')
result=dict(observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),records={})
for name in ('parent-start.json','parent-terminal.json'):
 p=control/name
 if p.is_file():result['records'][name]=json.loads(p.read_bytes())
children=sorted(control.glob('child-*.terminal.json')) if control.is_dir() else []
result['completed_git_children']=len(children)
for p in children[-2:]:result['records'][p.name]=json.loads(p.read_bytes())
start=result['records'].get('parent-start.json',{})
if type(start.get('pid')) is int:
 proc=subprocess.run(['ps','-p',str(start['pid']),'-o','pid,ppid,stat,etime,args'],capture_output=True,text=True)
 result['actual_parent_process']=dict(returncode=proc.returncode,stdout=proc.stdout)
for name in ('parent.stdout','parent.stderr'):
 p=inputs/name
 if p.is_file():result[name]=p.read_text()[-3000:]
print(json.dumps(result,sort_keys=True))
'''
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
p=subprocess.run(['ssh','jumpserver',cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
record=json.loads(p.stdout) if p.returncode==0 else dict(returncode=p.returncode,error=p.stderr.decode(errors='replace'))
name='zipcpu2-observation-'+str(len(list(HERE.glob('zipcpu2-observation-*.json')))+1)+'.json'
with (HERE/name).open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps(record,sort_keys=True))
raise SystemExit(p.returncode)
