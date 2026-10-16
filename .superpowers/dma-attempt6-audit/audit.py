import json,gzip,hashlib,gc
from pathlib import Path
from normalize_fn import _normalize
root=Path('/root/fanzehui/system-20261016/dma-continuous-verification-20261017/attempt6')
def digest(v):
 h=hashlib.sha256()
 for r in v:
  h.update(json.dumps(r,sort_keys=True,separators=(',',':')).encode()); h.update(b'\n')
 return h.hexdigest()
report={'scope':'independent saved-data audit; no simulator commands','runs':{}}
for name in ('positive','fresh','failure','failure-fresh'):
 p=root/'evidence'/(name+'.json.gz'); raw=p.read_bytes(); x=json.loads(gzip.decompress(raw)); del raw
 row={k:x[k] for k in ('phase','case_index','cases','error','local_ticks','execution_ids','budget')}
 row.update(events=len(x['events']),normalized_event_sha256=digest(_normalize(x['events'],x['execution_ids'])),status=x['trace']['status'],commands=len(x['plan']['commands']),plan_sha256=digest([x['plan']]),source_pins_sha256=digest([x['source_pins']]),uncertain_sha256=digest([_normalize(x['uncertain_status'],x['execution_ids'])]))
 report['runs'][name]=row
 del x;gc.collect()
for a,b in [('positive','fresh'),('failure','failure-fresh')]:
 l,r=report['runs'][a],report['runs'][b]
 checks={k:l[k]==r[k] for k in ('events','normalized_event_sha256','local_ticks','cases','error','budget','status','source_pins_sha256','uncertain_sha256')}
 checks['distinct_execution_ids']=not(set(l['execution_ids'].values())&set(r['execution_ids'].values()))
 report[a+'-comparison']=checks
 assert all(checks.values()),checks
assert [c['source_byte'] for c in report['runs']['positive']['cases']]==[90,0,165,165]
assert report['runs']['failure']['error']['requested_source_bytes']==[51]
print(json.dumps(report,indent=2),flush=True)
