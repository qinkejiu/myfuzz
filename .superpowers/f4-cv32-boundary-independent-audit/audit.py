"""Independent archive-only boundary audit; never launches a model."""
import hashlib,json,tarfile
from pathlib import Path
archive=Path('docs/reports/evidence/compiled-f4-cv32-no-error-boundary-20261017/evidence.tar.gz')
expected=Path(str(archive).replace('.tar.gz','.sha256')).read_text().split()[0]
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
with tarfile.open(archive) as tar:
 def read(name):return tar.extractfile(name).read()
 def doc(name):return json.loads(read(name))
 report=doc('outputs/boundary/report.json');rows=doc('outputs/boundary/raw_transcript.json')
 assert report['status']=='completed' and report['native_executed'] and report['fail_stop_observed']
 assert report['returncode']==report['actual_close_returncode']==1
 stdout=[r['line'] for r in rows if r['direction'].startswith('stdout')]
 ready=stdout[0].split();assert ready[0]=='READY'
 results=[s for s in stdout if s.startswith('RESULT ')]
 assert len(results)==1
 fields=results[0].split();assert fields[1]==report['execution_nonce'] and fields[2:5]==['1','0','1']
 payload=json.loads(bytes.fromhex(fields[-1]))
 pre=payload['pre_backend'];taps=payload['samples'][0]['pre']['protocol_taps']
 assert pre['i_req_valid']==pre['i_req_ready']==1 and pre['i_req_addr']==0x10000
 assert taps['trace_obi_i_req']==taps['trace_obi_i_gnt']==1 and taps['trace_obi_i_addr']==0x10000
 assert not any('error' in k for k in taps)
 commands=[r['line'].split() for r in rows if r['direction']=='stdin']
 assert len(commands)==2 and commands[1][1:4]==[report['execution_nonce'],'2','STEP_CPU']
 assert commands[1][4:]==['0','0','1','0','1','0','0','0','0']
 assert any('u_adapter_i: OBI backend error cannot be represented' in line for line in stdout)
 assert report['policy']['mode']=='fail_stop_no_error_pin' and report['policy']['native_error_observation'] is False
 assert report['injection']['accepted']['sequence']==1 and report['injection']['sequence']==2
 manifest=doc('build-receipts/manifest.json')
 assert manifest['identity']['artifact_digest']==ready[2]
 assert manifest['binary_sha256']==read('build-receipts/actual-binary.sha256').decode().split()[0]
 for name in ('boundary.exit','boundary.source-after.exit','boundary.audit.exit'):
  assert read('logs/'+name).strip()==b'0'
 for side in ('before','after'):
  source=doc('logs/boundary.source-'+side+'.json')
  assert source['matches'] and source['symlinks_match'] and source['file_count']==37528 and source['mismatches']==[]
 result={'audit_scope':'independent saved archive only','archive_sha256':expected,'accepted_address':pre['i_req_addr'],
  'accepted_sequence':1,'error_sequence':2,'result_reply_count':1,'native_pid':report['pid'],
  'actual_native_close_returncode':1,'physical_error_role_exposed':False,
  'artifact_digest':ready[2],'binary_sha256':manifest['binary_sha256'],
  'controlling_exit':0,'source_after_exit':0,'audit_exit':0,'source_file_count':37528,
  'native_or_compiler_invoked_by_audit':False}
 print(json.dumps(result,indent=2))
