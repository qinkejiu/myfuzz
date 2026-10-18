"""Read durable state and specific live process handles; never restart or kill."""
import hashlib,json,shlex,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
remote=r'''
import datetime,json,subprocess
from pathlib import Path
base=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt2')
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
gate=result['records'].get('native-directed-gate.launch.json',{}).get('pid')
if type(gate) is int:
 process=subprocess.run(['ps','-eo','pid,ppid,stat,etime,args'],capture_output=True,text=True,check=True)
 rows=[]
 for line in process.stdout.splitlines()[1:]:
  columns=line.strip().split(None,4)
  if len(columns)==5:rows.append((int(columns[0]),int(columns[1]),line.strip()))
 owned={gate};changed=True
 while changed:
  children={pid for pid,parent,_ in rows if parent in owned};changed=not children<=owned;owned|=children
 result['actual_gate_descendants']=[line for pid,parent,line in rows if pid in owned]
 cache=base/'cache-native'
 if cache.is_dir():result['cache_entries']=[str(p.relative_to(cache)) for p in cache.glob('*')]
for name in ('positive','controlled-response'):
 d=base/'run-directed'/name
 if d.is_dir():
  result[name+'_files']=sorted(p.name for p in d.iterdir())
  result[name+'_saved_cases']=[]
  import gzip,collections
  for case in sorted(d.glob('case-*.json.gz')):
   try:
    data=json.loads(gzip.decompress(case.read_bytes()))
    events=data['receipt']['events']
    counts=collections.Counter(e.get('kind') for e in events if e.get('schema_version')=='native_bus_observation.v1')
    result[name+'_saved_cases'].append(dict(file=case.name,source=data['selected_source'],native_counts=dict(counts),relation=data['relation']))
   except Exception as error:result[name+'_saved_cases'].append(dict(file=case.name,read_error=repr(error)))
print(json.dumps(result,sort_keys=True))
'''
cmd='ssh root@192.168.5.70 '+shlex.quote('python3 -c '+shlex.quote(remote))
p=subprocess.run(['ssh','jumpserver',cmd],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
record=json.loads(p.stdout) if p.returncode==0 else dict(error_stderr=p.stderr.decode(errors='replace'),returncode=p.returncode)
name='gate-observation-'+str(len(list(HERE.glob('gate-observation-*.json')))+1)+'.json'
with (HERE/name).open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps(record,sort_keys=True))
raise SystemExit(p.returncode)
