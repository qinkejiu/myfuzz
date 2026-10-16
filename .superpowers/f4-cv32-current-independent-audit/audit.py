"""Independent whole saved-prefix audit, never imports execution helpers."""
import copy,hashlib,json,tarfile
from pathlib import Path
path=Path('docs/reports/evidence/compiled-f4-cv32-current-20261017/evidence.tar.gz')
archive_sha=hashlib.sha256(path.read_bytes()).hexdigest()
assert archive_sha=='1b18b4774cb380a89098279dcf63d2393a4e000df7273bcf9bc605a9c8499267'
def digest(obj):return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def normalized(prefix):
 result=copy.deepcopy(prefix)
 for record in result['records']:
  for key in ('prerequisite','postcondition'):record['certificate'][key].pop('process_scope',None)
 return result
with tarfile.open(path) as t:
 def raw(name):return t.extractfile(name).read()
 def doc(name):return json.loads(raw('outputs/cv32/'+name))
 prefixes=[doc('prefix.json'),doc('fresh-1/prefix.json'),doc('fresh-2/prefix.json')]
 events=[doc('events.json'),doc('fresh-1/events.json'),doc('fresh-2/events.json')]
 audits=[doc('execution_audit.json'),doc('fresh-1/execution_audit.json'),doc('fresh-2/execution_audit.json')]
 primary=prefixes[0];pids=[];nonces=[]
 assert events[0]==events[1]==events[2] and len(events[0])==7351
 assert normalized(prefixes[0])==normalized(prefixes[1])==normalized(prefixes[2])
 assert primary['cpu_error_policy']['mode']=='fail_stop_no_error_pin'
 assert primary['cpu_error_policy']['native_error_observation'] is False
 def errors(value):
  if isinstance(value,dict):
   for k,v in value.items():
    if k=='error':yield v
    else:yield from errors(v)
  elif isinstance(value,list):
   for v in value:yield from errors(v)
 observed_errors=list(errors(primary['records'][0]['certificate']))
 assert len(observed_errors)==20 and all(v is None for v in observed_errors)
 assert primary['candidate_layout']==doc('candidate_layout.json')
 assert primary['candidate_layout']['byte_length']==8 and len(primary['records'])==3
 for record in primary['records']:
  assert record['certificate']['status']=='certified' and record['certificate']['first_fetch']['address']==0x10000
  bits=int.from_bytes(bytes.fromhex(record['raw']),'little')
  assert len(bytes.fromhex(record['raw']))==8
  for field in primary['candidate_layout']['slices']:
   decoded=bits>>field['raw_bit_offset'] & ((1<<field['width'])-1)
   assert decoded==record['source_values'][field['source_id']]
 for audit in audits:
  assert audit['closed'] is True
  for role,row in audit['identities'].items():
   assert row['artifact_digest']==primary['artifact_digests'][role]
   assert audit['exits'][role]['reaped'] is True and audit['exits'][role]['returncode']==0
   pids.append(row['pid']);nonces.append(row['execution_nonce'])
 assert len(set(pids))==len(set(nonces))==6
 for comparison in doc('replays.json'):
  assert comparison['matches'] is True and comparison['first_difference'] is None
  assert comparison['actual_semantic_hash']==comparison['expected_semantic_hash']==primary['semantic_hash']
 for side in ('before','after'):
  s=json.loads(raw('logs/cv32.source-'+side+'.json'))
  assert s['matches'] is True and s['symlinks_match'] is True and s['file_count']==37528 and s['mismatches']==[]
 for receipt in ('cv32.exit','cv32.source-after.exit','cv32.audit.exit'):assert raw('logs/'+receipt).strip()==b'0'
 result={'scope':'independent archive-only audit; no model/compiler/checker invoked',
  'archive_sha256':archive_sha,'events_per_run':[len(e) for e in events],
  'three_entire_saved_event_arrays_equal_without_further_normalization':True,'saved_events_canonical_sha256':digest(events[0]),
  'three_full_prefixes_equal_except_declared_certificate_process_scope':True,
  'full_normalized_prefix_sha256':digest(normalized(primary)),'semantic_hash':primary['semantic_hash'],
  'certified_cases':len(primary['records']),'first_fetch':0x10000,'declared_record_bytes':8,
  'all_declared_source_slices_match_raw_records':True,'actual_reaped_exit_codes':[0]*6,'distinct_pids':pids,
  'distinct_nonce_count':len(set(nonces)),'controlling_source_audit_exits':[0,0,0],
  'accepted_scope':'directed compiled OBI/APB GPIOEN F4 only; not generic APB or coverage-guided P7'}
 print(json.dumps(result,indent=2))
