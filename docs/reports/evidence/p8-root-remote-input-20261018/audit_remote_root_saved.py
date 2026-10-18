"""Prepared saved-byte auditor. Never imports producer/project code or executes subprocesses."""
import argparse,ast,hashlib,json,shlex,tarfile
from pathlib import Path,PurePosixPath
CONTROL=Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2')
TRANSPORT=CONTROL/'transport-drafts'
INBOX='/root/fanzehui/myfuzz/operations/p8-root-input-transfer-20261018-attempt1'
DEST='/root/fanzehui/myfuzz/operations/p8-root-input-20261018-attempt1'
def need(v,m):
 if not v:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def local(n):return (CONTROL/n).read_bytes()
def constant(path,name):
 for n in ast.parse(path.read_bytes()).body:
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets):return ast.literal_eval(n.value)
 raise ValueError('missing constant')
def main():
 p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--archive-sha256',required=True);a=p.parse_args()
 with a.archive.open('rb') as f:need(hashlib.file_digest(f,'sha256').hexdigest()==a.archive_sha256,'collection archive pin')
 data={}
 with tarfile.open(a.archive,'r|') as t:
  for v in t:
   n=v.name;q=PurePosixPath(n);need(n and str(q)==n and not q.is_absolute() and '..' not in q.parts and n not in data and v.type==tarfile.REGTYPE and not v.pax_headers,'saved member type/path')
   data[n]=t.extractfile(v).read();need(len(data[n])==v.size,'saved size')
 def j(n):return json.loads(data[n])
 index=j('member-index.json');need(set(index)==set(data)-{'member-index.json'},'member index set')
 for n,b in data.items():
  if n!='member-index.json':need(index[n]=={'bytes':len(b),'sha256':sha(b)},'member index hash')
 m=j('inbox/transfer-manifest.json');c=j('inbox/control-inputs.json');o=j('observed.json');r=j('inbox/extraction-receipt.json');parent=j('inbox/extract-parent-terminal.json');start=j('inbox/extract-parent-start.json');upload=j('inbox/upload-receipt.json')
 for name,pin in [('transfer-manifest.json','2e749cb696b5ac001176a453de2471f3d3d5f22d4949f16caee1e40c57530c05'),('control-inputs.json','646948b9fc633fbdc192627c85a3a10f3edd7c8085e8b747110f332307c1c504'),('extract_remote_root_input.py','a91faf9603cb639f16413fed30dd9b2d69d2a4814c9adf0c730614dd7f63b343'),('upload-receipt.json','160307bf4c4233e982df3cf2cb3a42753100abd025602b8894edf1a89e8787b4')]:need(sha(data['inbox/'+name])==pin,'remote input pin')
 need(o['schema_version']=='p8_root_readonly_collection.v1' and o['remote_destination']==DEST and o['remote_inbox']==INBOX,'collection binding')
 need(o['parent_gone'] is True and o['child_gone'] is True and o['parent_pid']==parent['pid'] and o['child_pid']==parent['child_pid']==r['pid'],'actual pid binding')
 need(parent['returncode']==o['parent_actual_returncode']==r['returncode']==o['extraction_actual_returncode']==0 and parent['error'] is None,'actual rc')
 need(parent['status']=='actual_extractor_terminal_pending_independent_audit' and r['status']=='copied_pending_independent_remote_audit' and r['source_prepared'] is True and r['maps_equal'] is True and r['git_or_model_execution'] is False,'status scope')
 need(o['started_unix']>=parent['ended_unix']>=r['ended_unix'] and o['ended_unix']>=o['started_unix'],'later capture times')
 for k in ['argv','pid','cwd','started_unix','pins','child_pid','local_step1_terminal_sha256','local_step1_postcheck_sha256']:need(parent[k]==start[k],'parent start terminal binding')
 need(parent['cwd']==INBOX and parent['pins']==upload['pins'] and upload['status']=='uploaded_four_inputs_pending_separate_extract_launch','upload parent join')
 pins=upload['pins'];expectedargv=['/usr/bin/python3','-B',INBOX+'/extract_remote_root_input.py','--archive',INBOX+'/root-input.tar.gz','--archive-sha256',pins['root-input.tar.gz']['sha256'],'--archive-bytes',str(pins['root-input.tar.gz']['bytes']),'--manifest',INBOX+'/transfer-manifest.json','--manifest-sha256',pins['transfer-manifest.json']['sha256']]
 need(parent['argv']==expectedargv,'actual child argv')
 for n in ['stdout','stderr']:need(parent[n+'_sha256']==sha(data['inbox/extract-parent.'+n]),'child stream hash')
 for n,h in [('upload-root-inputs.terminal.json','20a811f7ccc6ee92126bed67bba7f123ce388bc6edb5f88891e2da9ecd31b9e7'),('upload-root-inputs.postcheck.json','725255f43a97c3c97e9e1a82e745164886f50e0e1329dde1ae19b1aac9b25e9f')]:need(sha((TRANSPORT/n).read_bytes())==h,'local step1 receipt pin')
 terminal=json.loads((TRANSPORT/'upload-root-inputs.terminal.json').read_bytes());post=json.loads((TRANSPORT/'upload-root-inputs.postcheck.json').read_bytes())
 need(terminal['returncode']==0 and terminal['error'] is None and post['status']=='local_upload_terminal_and_all_post_input_checks_passed' and post['pins']==pins,'local upload success')
 need(post['schema_version']=='p8_local_upload_postcheck.v1','local upload postcheck schema')
 upload_source=(TRANSPORT/'upload_root_inputs.py').read_bytes();common_source=(TRANSPORT/'transport_common.py').read_bytes()
 need(sha(upload_source)==post['upload_controller_sha256']=='5d680a265985445f64ecc4e8ae1adc1bb6d3546025855007667c56880b7b832a' and sha(common_source)==post['common_controller_sha256']=='2b2d1a97b5bf11936b0a28494e13a6f0231cff18384647a2b48081628d20e4ac','step1 reviewed source pins')
 canonical_pins=dict(sorted(pins.items()))
 need(set(canonical_pins)=={'root-input.tar.gz','transfer-manifest.json','control-inputs.json','extract_remote_root_input.py'},'step1 four input set')
 upload_code=constant(TRANSPORT/'upload_root_inputs.py','BOOT').replace('PINS',repr(canonical_pins))
 upload_argv=['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(upload_code))]
 need(terminal['argv']==post['argv']==upload_argv,'step1 exact canonical twohop argv')
 for stream in ['stdout','stderr']:need(sha((TRANSPORT/('upload-root-inputs.'+stream)).read_bytes())==terminal[stream+'_sha256'],'step1 actual stream hashes')
 local_upload_start=json.loads((TRANSPORT/'upload-root-inputs.start.json').read_bytes())
 for key in ['pid','argv','started_unix']:need(local_upload_start[key]==terminal[key],'step1 actual start terminal identity')
 need(local_upload_start['returncode'] is None and type(terminal['pid']) is int and terminal['pid']>1 and terminal['ended_unix']>=terminal['started_unix'],'step1 actual lifecycle')
 need(parent['local_step1_terminal_sha256']==post['terminal_sha256']==sha((TRANSPORT/'upload-root-inputs.terminal.json').read_bytes()) and parent['local_step1_postcheck_sha256']==sha((TRANSPORT/'upload-root-inputs.postcheck.json').read_bytes()),'parent local chain')
 launch=(TRANSPORT/'launch_extract_root_input.py').read_bytes();need(sha(launch)=='e8864ace7a4916c9725faffa3ff7be0f6a1aaf97ff2440b583f3b4c6a46bae74','launch source')
 remote=constant(TRANSPORT/'launch_extract_root_input.py','REMOTE').replace('EXPECTED',repr(dict(upload_receipt_sha256=sha(data['inbox/upload-receipt.json']),pins=pins,terminal_sha256=parent['local_step1_terminal_sha256'],postcheck_sha256=parent['local_step1_postcheck_sha256'])))
 lt=json.loads((TRANSPORT/'extract-root-inputs.terminal.json').read_bytes());need(lt['returncode']==0 and lt['error'] is None and lt['argv']==['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(remote))],'actual local extractor SSH')
 for n in ['stdout','stderr']:need(sha((TRANSPORT/('extract-root-inputs.'+n)).read_bytes())==lt[n+'_sha256'],'local extraction stream')
 rootf=m['frozen_root_files'];rootd=m['frozen_root_directories'];need(len(rootf)==10347 and len(rootd)==524 and o['root']['files']==rootf and o['root']['directories']==rootd,'root exact maps')
 need(o['destination']['files']==m['files'] and o['destination']['directories']==m['directories'],'whole destination map')
 need(sha(data['control/freeze.json'])=='27ec3b8a97d22b3272acf3dd90bf44f05a20f7ffd8c984be9b6b49054a2a6ba5' and j('control/freeze.json')==rootf and j('control/prepare-receipt.json')['directories']==rootd,'actual freeze map')
 need(len(c['files'])==20 and o['control']['files']=={n:{k:p[k] for k in ('bytes','mode','sha256')} for n,p in c['files'].items()},'20 controls')
 for n,pin in c['files'].items():need(data['control/'+n]==Path(pin['path']).read_bytes() and sha(data['control/'+n])==pin['sha256'],'local remote control bytes')
 need(data['root-small/.git/HEAD']==b'ref: refs/heads/codex/system-completion-20261016\n' and data['root-small/.git/refs/heads/codex/system-completion-20261016'].strip()==b'269717b7e9cc7c92da5e427ac950bc82446b3ac6','HEAD269')
 expectedinbox=set(pins)|{'upload-receipt.json','extract-parent-start.json','extract-parent-terminal.json','extract-parent.stdout','extract-parent.stderr','extraction-receipt.json'}
 need(set(o['inbox']['files'])==expectedinbox and not o['inbox']['directories'],'inbox exact set')
 for n,pin in pins.items():need(o['inbox']['files'][n]==pin,'inbox original input unchanged')
 for n in expectedinbox-set(pins):need(o['inbox']['files'][n]['sha256']==sha(data['inbox/'+n]),'inbox capture joins')
 need(r['archive_sha256']==pins['root-input.tar.gz']['sha256'] and r['archive_bytes']==413926054 and r['manifest_sha256']==pins['transfer-manifest.json']['sha256'] and r['destination']==DEST and r['root_files']==10347 and r['root_directories']==524,'extraction receipt binding')
 print(json.dumps({'status':'independent_remote_regular_root_copy_verified','scope':'regular_root_only_no_component_adapter_or_P8_grant','root_files':10347,'root_directories':524,'control_files':20,'parent_pid':parent['pid'],'child_pid':parent['child_pid'],'archive_sha256':a.archive_sha256},sort_keys=True))
if __name__=='__main__':main()
