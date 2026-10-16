"""Read-only saved observation checks; does not change status or admit a run."""
import gzip,json,hashlib
from pathlib import Path
from myfuzz.scenario import boom_gpio_irq_verification as g
path=Path(__file__).with_name('native-first.json.gz');before=hashlib.sha256(path.read_bytes()).hexdigest()
run=json.load(gzip.open(path));out={'actual_status':run['status'],'gate_pass':False,'checks':{}}
def check(name,call):
    try:out['checks'][name]={'observations_match':True,'result':call()}
    except Exception as error:out['checks'][name]={'observations_match':False,'error':{'type':type(error).__name__,'detail':str(error)}}
check('transport',lambda:g.validate_transport(run))
check('pulse',lambda:g.validate_pulse(run['events'],run['cpu_samples'],suppressed=False))
start,end=g.validate_pulse(run['events'],run['cpu_samples'],suppressed=False)
rise=next(r for r in run['gpio_events'] if r.get('kind')=='gpio_tick_observation' and r['pre'].get('interrupt')==0 and r['post'].get('interrupt')==1)
check('source',lambda:g.source_witness(run,rise,start,end))
origin=g.source_witness(run,rise,start,end)
raw=[r for r in run['runtime_events'] if r.get('kind')=='coherent_accepted_raw']
links=[]
for access in run['gpio_events']:
 if access.get('kind')!='gpio_apb_access' or access['write'] or access['decoded_offset']!=0x24:continue
 key=access['source_transaction']
 q=next(r for r in run['source_events'] if r.get('kind')=='boom_external_a_queued' and r['source_transaction']==key)
 c=next(r for r in run['source_events'] if r.get('kind')=='boom_external_d_accepted' and r['source_transaction']==key)
 a=next(r for r in raw if r['local_tick']==q['local_tick'] and r['native_event']['channel']=='A')
 d=next(r for r in raw if r['local_tick']==c['local_tick'] and r['native_event']['channel']=='D')
 links.append(dict(source_transaction=key,target_access_id=access['access_id'],gpio_tick=access['local_tick'],gpio_phase=access['phase'],a_tick=a['local_tick'],d_tick=d['local_tick'],a_raw_event_id=a['raw_event_id'],d_raw_event_id=d['raw_event_id']))
probes=[(s['cycle'],i,s[p]) for s in run['cpu_samples'] for i,p in enumerate(('probes_pre','probes_post'))]
rob=min((t,i) for t,i,p in probes if p['rob_exception'] and p['rob_cause']==g.CAUSE)
csr=min((t,i) for t,i,p in probes if p['csr_exception'] and p['csr_cause']==g.CAUSE and p['csr_evec']==g.ISR)
mret=next(t for t,i,p in probes if i==0 and g.qualified_return(p,run['last_cpu_outputs']['ram_3018']))
check('temporal',lambda:g.temporal_witness(run,links,origin,mret,rob,csr))
last=next(r for r in reversed(run['events']) if r.get('kind')=='budget_exhausted')
out['step_accounting']=g.step_accounting(run['events'],last['local_ticks'])
assert run['status']=='budget_exhausted' and hashlib.sha256(path.read_bytes()).hexdigest()==before
out['saved_sha256_unchanged']=before
print(json.dumps(out,indent=2))
