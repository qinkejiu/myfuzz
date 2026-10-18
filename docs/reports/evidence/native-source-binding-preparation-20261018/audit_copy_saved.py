"""UNEXECUTED local saved-byte auditor; stdlib only; no producer execution."""
import argparse,ast,base64,hashlib,json,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE='/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt2/project'
OP='/root/fanzehui/myfuzz/operations/p6-native-source-binding-20261018-attempt1'
INPUT='/root/fanzehui/myfuzz/operations/p6-native-source-binding-inputs-20261018-attempt2'
def require(v,m):
 if not v:raise ValueError(m)
def digest(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('capture',type=Path);a=p.parse_args();capture_bytes=a.capture.read_bytes();c=json.loads(capture_bytes)
 require(c['schema_version']=='native_binding_copy_readonly.v1' and c['source']==SOURCE and c['output']==OP+'/project' and c['inputs']==INPUT and c['native_execution']is False,'capture-scope')
 evidence={k:base64.b64decode(v,validate=True) for k,v in c['evidence'].items()}
 def doc(k):return json.loads(evidence[k])
 baseline=json.loads((HERE/'references/baseline-files.json').read_bytes());dirs=json.loads((HERE/'references/baseline-directories.json').read_bytes());final=json.loads((HERE/'expected-final-files.json').read_bytes());fd=json.loads((HERE/'expected-final-directories.json').read_bytes());overlay=json.loads((HERE/'overlay-map.json').read_bytes())
 require(digest((HERE/'references/baseline-files.json').read_bytes())=='3c287137bfa7e98c6b28444b20b26fa2e6ab25d6a01c2262594408fa380e44be','baseline-pin')
 require(digest((HERE/'references/baseline-directories.json').read_bytes())=='861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36','dirs-pin')
 require(digest((HERE/'expected-final-files.json').read_bytes())=='d5ce57a590fc3f1668f9e1606c187818fffc66a78c7367f268e54884267c3024','final-pin')
 require(c['source_census']==dict(files=baseline,directories=dirs) and c['output_census']==dict(files=final,directories=fd) and fd==dirs,'complete-later-census')
 require(len(final)==8892 and len(fd)==601 and len(overlay['files'])==12,'counts')
 for name in ('source-before-files.json','source-after-files.json'):require(doc('operation/'+name)==baseline,'source-file-map')
 for name in ('source-before-directories.json','source-after-directories.json'):require(doc('operation/'+name)==dirs,'source-dir-map')
 require(doc('operation/final-file-freeze.json')==final and doc('operation/final-directories.json')==fd,'published-maps')
 require(doc('operation/reviewed-overlay-files.json')==overlay['files'] and doc('operation/reviewed-overlay-directories.json')==overlay['directories'],'overlay')
 require(final=={**baseline,**overlay['files']} and all(k.startswith(('src/','scripts/')) for k in overlay['files']) and not any(k.startswith('src/myfuzz/frontend/') for k in overlay['files']),'unchanged-outside-overlay-frontend')
 hostpath=Path('src/myfuzz/scenario/host_identity.py');hostbytes=hostpath.read_bytes()
 require(digest(hostbytes)==final[str(hostpath)]['sha256'],'reviewed-host-source-pin')
 declarations={}
 for node in ast.parse(hostbytes).body:
  if isinstance(node,ast.Assign):
   for target in node.targets:
    if isinstance(target,ast.Name) and target.id in ('HOST_SOURCE_PATHS','HARNESS_HOST_SOURCE_PATHS'):
     require(target.id not in declarations,'duplicate-host-declaration');v=node.value
     declarations[target.id]=declarations['HOST_SOURCE_PATHS']+ast.literal_eval(v.right) if isinstance(v,ast.BinOp) and isinstance(v.op,ast.Add) and isinstance(v.left,ast.Name) and v.left.id=='HOST_SOURCE_PATHS' else ast.literal_eval(v)
 require(len(declarations['HOST_SOURCE_PATHS'])==34 and len(declarations['HARNESS_HOST_SOURCE_PATHS'])==70,'actual-host-declarations')
 hosts=doc('operation/explicit-host-files.json');require(hosts=={k:final[k] for k in declarations['HARNESS_HOST_SOURCE_PATHS']},'exact-host70-members')
 receipt=doc('operation/copy-receipt.json');require(receipt['status']=='prepared_pending_independent_review_no_execution' and receipt['source']==SOURCE and receipt['destination']==OP+'/project' and receipt['source_unchanged']is True and receipt['native_run']is False and receipt['host_paths']==70 and receipt['files']==8892 and receipt['directories']==601 and receipt['freeze_sha256']==digest(evidence['operation/final-file-freeze.json']),'copy-receipt')
 start=doc('inputs/copy-parent-start.json');terminal=doc('inputs/copy-parent-terminal.json')
 require(terminal['returncode']==0 and terminal['error']is None and terminal['native_execution']is False and terminal['ended_unix']>=terminal['started_unix'],'actual-child-terminal')
 for k,v in start.items():require(terminal.get(k)==v,'start-terminal-join')
 expected_argv=['/usr/bin/python3','-B',INPUT+'/prepare_copy.py']
 for flag,name in [('baseline-files','baseline-files.json'),('baseline-directories','baseline-directories.json'),('overlay-tree','overlay'),('overlay-map','overlay-map.json'),('overlay-paths','overlay-paths.json')]:expected_argv.extend(['--'+flag,INPUT+'/'+name])
 expected_argv.extend(['--overlay-map-sha256','3f0404498e11a4d1e9e5dadca72df9973e9778c4e4bcb4f097c6be4042429f24','--overlay-paths-sha256','551491be43df4fbdb540cb204bdb67428b7e4456dba25649ebf7934ca1700860'])
 require(terminal['argv']==expected_argv,'exact-copy-argv')
 for n in ('copy.stdout','copy.stderr'):
  b=evidence['inputs/'+n];require(terminal[n]==dict(bytes=len(b),sha256=digest(b)),'stdio-pin')
 require(json.loads(evidence['inputs/copy.stdout'])==receipt,'raw-copy-stdout')
 deployment=doc('inputs/deployment-receipt.json');require(deployment['status']=='inputs_published_no_gate' and deployment['native_execution']is False and deployment['archive_sha256']=='2ae9df9e13c51b6e985809093e4071192404080e36b9fc74a32574a953398539','deployment')
 expected_files={};expected_dirs={}
 archive_bytes=(HERE/'copy-inputs.tar.gz').read_bytes()
 require(digest(archive_bytes)=='2ae9df9e13c51b6e985809093e4071192404080e36b9fc74a32574a953398539','reviewed-archive-pin')
 with tarfile.open(HERE/'copy-inputs.tar.gz') as archive:
  for member in archive.getmembers():
   if member.isdir():expected_dirs[member.name]={'mode':member.mode}
   else:
    raw=archive.extractfile(member).read();expected_files[member.name]=dict(bytes=len(raw),mode=member.mode,sha256=digest(raw))
 for name,pin in [('run_native_gate.py','04d32a34b9795a32d19f1628acfdb1bf595467dada4bc0fc7a07b4957cea5717'),('launch-native-gate.sh','ba69f47e08e2563f1e1f2d07334d544dd657fa176164e013521544fda21b3e92')]:
  raw=(HERE/name).read_bytes();require(digest(raw)==pin,'control-pin');expected_files[name]=dict(bytes=len(raw),mode=420,sha256=pin)
 require(deployment['files']==expected_files and deployment['directories']==expected_dirs,'complete-deployed-input-manifest')
 runtime_names=['deployment-receipt.json','copy-parent-start.json','copy-parent-terminal.json','copy.stdout','copy.stderr']
 actual_expected=dict(expected_files)
 for name in runtime_names:
  raw=evidence['inputs/'+name];actual_expected[name]=dict(bytes=len(raw),mode=420,sha256=digest(raw))
 require(c['inputs_census']==dict(files=actual_expected,directories=expected_dirs),'actual-complete-inputs-census-and-raw-receipts')
 for name in ('pid','child_pid'):
  require(type(terminal.get(name)) is int and terminal[name]>0,'strict-positive-pid')
 require(type(deployment.get('pid')) is int and deployment['pid']==terminal['pid'],'actual-deployment-parent-join')
 require(all(type(row.get('pid')) is int and row['pid']>0 and type(row.get('proc_exists_later')) is bool for row in c['later_process_observations']),'strict-later-observation-types')
 require(c['later_process_observations']==[dict(field=name,pid=terminal[name],proc_exists_later=False) for name in ('pid','child_pid')],'later-process-observations-only')
 require(c['started_unix']>=terminal['ended_unix'] and c['ended_unix']>=c['started_unix'],'later-collection-time')
 print(json.dumps(dict(status='saved_copy_checks_passed',capture_sha256=digest(capture_bytes),files=len(final),directories=len(fd),host_paths=len(hosts),scope='pure-copy saved bytes; later census distinct from terminal receipts; no gate pass'),sort_keys=True))
if __name__=='__main__':main()
