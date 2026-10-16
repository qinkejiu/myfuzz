from pathlib import Path
import tarfile,gzip,json,hashlib,shutil
root=Path('/home/qinkejiu/myfuzz');out=root/'docs/reports/evidence/cvw-ahb-native-20261017'
def sha(data):return hashlib.sha256(data).hexdigest()
def encoded(d):return (json.dumps(d,sort_keys=True,indent=2)+'\n').encode()
with tarfile.open(out/'terminal-originals.tar.gz') as archive:
 members=archive.getmembers();catalog=[]
 for member in members:
  row=dict(path=member.name,mode=member.mode,size=member.size,type='file' if member.isfile() else 'directory' if member.isdir() else 'symlink' if member.issym() else 'other',linkname=member.linkname)
  if member.isfile():row['sha256']=sha(archive.extractfile(member).read())
  catalog.append(row)
 selected=['run/first.json.gz','run/failure.json','control/operation.claim.json','control/controller.claim.json','control/child.started.json','control/controller.terminal.json','control/operation.terminal.json','control/before-tools.json','control/after-tools.json','control/before-source-map.json.gz','control/after-source-map.json.gz','control/output-map.json.gz','root-preflight-bytecode/receipt.json']
 for name in selected:(out/name.replace('/','--')).write_bytes(archive.extractfile(name).read())
 d=json.loads(gzip.decompress(archive.extractfile('run/first.json.gz').read()))
 manifests=[]
 for member in members:
  if member.isfile() and member.name.startswith('run/cache/') and member.name.endswith('/manifest.json'):
   data=archive.extractfile(member).read();name=member.name.split('/')[2]
   (out/('cache-manifest-'+name+'.json')).write_bytes(data)
   manifests.append(dict(path=member.name,sha256=sha(data)))
 page=d['driver_receipts'][0]['receipt']['payload']['observations']['ahb_startup'];signals=d['artifact']['base_protocol_traces']['traces'][0]['signals']
 global_ready=next(r['runtime_name'] for r in d['artifact']['physical_exports'] if r['physical_port']=='HREADY')
 bus_reset_n=next(r['runtime_name'] for r in d['artifact']['physical_exports'] if r['physical_port']=='HRESETn')
 table=[]
 for record in page['records']:
  sample=record['sample'];table.append(dict(startup_edge=record['startup_edge_index'],external_reset_pre=record['reset_pre'],external_reset_post=record['reset_post'],
    **{phase:dict(roles={role:sample[phase]['protocol_taps'][name] for role,name in signals.items()},actual_global_hready=sample[phase]['physical'][global_ready],actual_bus_hresetn=sample[phase]['physical'][bus_reset_n]) for phase in ('pre','post')}))
 errors=[row for row in d['runtime_events'] if row['kind']=='ahb_failure']
 summary=dict(schema_version='cvw_ahb_attempt1_saved_failure_audit.v1',native_attempt=True,native_gate_pass=False,fresh_started=False,
 controller_pid=272511,gate_child_pid=272523,gate_child_actual_exit=1,original_error=d['error'],
 actual_cpu_lifecycle=d['binaries']['cpu']['lifecycle'],actual_target_lifecycle=d['binaries']['sha']['lifecycle'],
 native_command_steps=d['cpu_local_ticks'],target_command_ticks=d['target_local_ticks'],
 driver_receipts=len(d['driver_receipts']),target_driver_receipts=len(d['target_driver_receipts']),
 raw_startup_edges_in_original_receipt=len(page['records']),observer_raw_startup_edges=sum(row['kind']=='ahb_raw' for row in d['runtime_events']),
 observer_records=len(d['runtime_events']),observer_projected_counts_not_bus_truth=d['counts'],observer_pending_not_validated_master_transaction=d['pending'],
 observer_failures=errors,service_events=len(d['service_events']),router_deliveries=len(d['deliveries']),
 measured_reset_to_command_prefix=d['measured_reset_to_command_prefix'],prefix_state=d['prefix_state'],
 collection_errors=d['collection_errors'],capture_errors=d['capture_errors'],
 before_after_source_unchanged=json.loads(archive.extractfile('control/operation.terminal.json').read())['full_before_after_changes']==[],
 tools_unchanged=json.loads(archive.extractfile('control/operation.terminal.json').read())['tools_unchanged'],
 cache_manifests=manifests,first_original_sha256=sha(archive.extractfile('run/first.json.gz').read()),
 source_authority=False,retirement_verified=False,source_modified=False,native_rerun=False)
 (out/'saved-failure-summary.json').write_bytes(encoded(summary))
 (out/'startup-domain-edge-table.json').write_bytes(encoded(table))
 (out/'terminal-archive-catalog.json.gz').write_bytes(gzip.compress(encoded(catalog),mtime=0))
shutil.copy2('/tmp/archive_cvw_ahb_terminal.py',out/'archive_cvw_ahb_terminal.py')
shutil.copy2('/tmp/analyze_cvw_ahb_failed_attempt.py',out/'analyze_cvw_ahb_failed_attempt.py')
print(json.dumps({k:summary[k] for k in ['native_command_steps','target_command_ticks','driver_receipts','raw_startup_edges_in_original_receipt','observer_raw_startup_edges','observer_records','first_original_sha256']},indent=2))
