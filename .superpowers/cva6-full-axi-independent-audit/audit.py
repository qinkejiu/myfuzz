import copy,gzip,hashlib,json,tarfile
from pathlib import Path
p=Path('docs/reports/evidence/cva6-full-axi-native-20261017/evidence.tar.gz')
sha=lambda b:hashlib.sha256(b).hexdigest()
with tarfile.open(p) as t:
 raw=lambda n:t.extractfile(n).read()
 first,fresh=[json.loads(gzip.decompress(raw('run/'+n+'.json.gz'))) for n in ('first','fresh')]
 summary=json.loads(raw('run/summary.json'))
 assert summary['status']=='pass' and first['native_execution']!=fresh['native_execution']
 def norm(events,execution):
  events=copy.deepcopy(events)
  for e in events:
   if e.get('schema_version')=='bounded_full_axi_observation.v1':
    assert e['scope']['execution_id']==execution
    e['scope']['execution_id']='normalized-execution'
  return events
 assert first['samples']==fresh['samples'] and len(first['samples'])==650
 for key in ('runtime_events','runner_events'):
  assert norm(first[key],first['native_execution'])==norm(fresh[key],fresh['native_execution'])
 for d in (first,fresh):
  assert d['status']=='complete' and d['ram_values']==[0x600dcafe]*2 and d['write_beats']==2
  assert d['post_drain_added_records']==0 and not d['source_authority'] and not d['retirement_verified']
  life=d['lifecycle'][0]
  assert life['closed'] and life['returncode']==life['poll_after_close']==0 and life['execution']==d['native_execution']
  assert sha(d['build_manifest_raw'].encode())==d['build_manifest_sha256']==life['build_manifest_sha256_at_capture']
  assert sha(raw('run/cache/'+Path(d['executable']['path']).parent.name+'/harness'))==life['binary_sha256_at_capture']
  for i,(s,r) in enumerate(zip(d['samples'],d['driver_receipts']),1):
   v=r['receipt'];assert v['status']=='result' and v['execution']==d['native_execution'] and v['sequence']==i
   assert v['tick_before']==i-1 and v['tick_after']==i and v['payload']['samples']==[s]
  imported=[{k:v for k,v in e.items() if k not in ('event_id','producer_event_id','component')} for e in d['runner_events'] if e.get('schema_version')=='bounded_full_axi_observation.v1']
  assert imported==d['runtime_events']
 receipts=[]
 for d in (first,fresh):
  rows=copy.deepcopy(d['driver_receipts'])
  for r in rows:r['receipt']['execution']='normalized-execution'
  receipts.append(rows)
 assert receipts[0]==receipts[1]
 assert first['lifecycle'][0]['pid']!=fresh['lifecycle'][0]['pid']
 for n in ('controller.exit','worker.exit'):assert raw('control/root-operation/'+n).strip()==b'0'
 for name,digest in summary['artifacts'].items():assert sha(raw('run/'+name))==digest
 print(json.dumps({'archive_sha256':sha(p.read_bytes()),'independent_saved_data_audit':True,'raw_samples_each':650,'runtime_events_each':len(first['runtime_events']),'runner_events_each':len(first['runner_events']),'whole_prefixes_equal_with_only_declared_typed_execution_normalization':True,'pids':[first['lifecycle'][0]['pid'],fresh['lifecycle'][0]['pid']],'accepted':first['accepted'],'pending':first['pending'],'binary_and_manifest_crosslinks':True,'source_authority':False,'retirement_verified':False,'protocol_completion_certified':False},indent=2))
