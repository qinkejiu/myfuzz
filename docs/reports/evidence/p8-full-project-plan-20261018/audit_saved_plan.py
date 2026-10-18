"""Unexecuted source draft: independently reduce saved pure copier plan evidence."""
import argparse,hashlib,json,os,stat,ast,shlex
from pathlib import Path,PurePosixPath
R='/root/fanzehui/myfuzz/operations/p8-full-project-inputs-20261018-attempt1'
D='/root/fanzehui/myfuzz/operations/p8-scalar-20261018-attempt1/project'
COPIER='b3bb05ef870551045539a1626690b2987fe08f362ef4c04ba58f2d3d2b342cf6'
def need(v,m):
 if not v:raise ValueError(m)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def j(p):return json.loads(p.read_bytes())
def main():
 p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,required=True);p.add_argument('--extract-receipt',type=Path,required=True);p.add_argument('--extract-receipt-sha256',required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--inputs-sha256',required=True);p.add_argument('--actual-local-terminal',type=Path,required=True);p.add_argument('--actual-local-terminal-sha256',required=True);p.add_argument('--actual-local-stdout',type=Path,required=True);p.add_argument('--actual-local-stderr',type=Path,required=True);p.add_argument('--wrapper-source',type=Path,required=True);p.add_argument('--wrapper-source-sha256',required=True);a=p.parse_args()
 need(sha(a.inputs)==a.inputs_sha256 and sha(a.extract_receipt)==a.extract_receipt_sha256 and sha(a.actual_local_terminal)==a.actual_local_terminal_sha256,'actual-audit-input-pins')
 ex=j(a.extract_receipt);lt=j(a.actual_local_terminal)
 need(ex['status']=='safely_extracted_pending_independent_audit' and lt['returncode']==0 and lt['error'] is None,'actual-plan-local-rc')
 need(sha(a.actual_local_stdout)==lt['stdout_sha256']==ex['archive_sha256'] and sha(a.actual_local_stderr)==lt['stderr_sha256'],'actual-SSH-stdout-tar-stream-pins')
 expectednames={'upload-receipt.json','plan-parent-start.json','plan-parent-terminal.json','plan.stdout','plan.stderr','project-plan.json','project-plan-receipt.json','returned-member-pins.json'}
 need(set(p.name for p in a.evidence.iterdir())==expectednames and set(ex['members'])==expectednames,'exact-success-members')
 for name,pin in ex['members'].items():
  path=a.evidence/name;info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==pin['bytes'] and sha(path)==pin['sha256'],'saved-original-member-pin')
 descriptors=j(a.inputs);pins={name:{k:row[k] for k in ('bytes','mode','sha256')} for name,row in descriptors.items()}
 need(len(pins)==11 and pins['prepare_p8_project.py']['sha256']==COPIER,'eleven-source-pins')
 for name,row in descriptors.items():need(sha(Path(row['path']))==row['sha256'],'actual-qualified-local-input')
 need(sha(a.wrapper_source)==a.wrapper_source_sha256,'actual-reviewed-wrapper-source-pin')
 remote=None
 for node in ast.parse(a.wrapper_source.read_bytes()).body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PLAN' for t in node.targets):remote=ast.literal_eval(node.value)
 need(isinstance(remote,str),'actual-wrapper-plan-body')
 upload_sha=sha(a.evidence/'upload-receipt.json')
 code=remote.replace('REMOTE',repr(R)).replace('EXPECTED',repr(dict(upload_receipt_sha256=upload_sha,pins=pins)))
 command='ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(code))
 need(lt['argv']==['ssh','jumpserver',command],'actual-local-plan-exact-argv')
 selection=j(Path(descriptors['selection.json']['path']));plan=j(a.evidence/'project-plan.json');receipt=j(a.evidence/'project-plan-receipt.json');parent=j(a.evidence/'plan-parent-terminal.json');start=j(a.evidence/'plan-parent-start.json');upload=j(a.evidence/'upload-receipt.json')
 argv=['/usr/bin/python3','-B',R+'/prepare_p8_project.py','plan','--selection',R+'/selection.json','--selection-sha256',pins['selection.json']['sha256'],'--plan',R+'/project-plan.json','--destination',D,'--receipt',R+'/project-plan-receipt.json']
 need(parent['argv']==argv and parent['cwd']==R and parent['pins']==upload['pins']==pins and parent['returncode']==0 and parent['error'] is None and parent['status']=='actual_plan_terminal_pending_independent_review','actual-remote-plan-parent')
 for key in ('pid','argv','cwd','started_unix','pins','child_pid'):need(start[key]==parent[key],'actual-parent-start-terminal')
 need(start['returncode'] is None and parent['ended_unix']>=parent['started_unix'] and all(type(parent[k]) is int and parent[k]>1 for k in ('pid','child_pid')),'actual-lifecycle')
 need(parent['post_input_checks']=={name:'unchanged' for name in pins},'actual-latest-eleven-post-pins')
 for stream in ('stdout','stderr'):need(sha(a.evidence/('plan.'+stream))==parent[stream+'_sha256'],'actual-copier-stream')
 need(plan['schema_version']=='p8_project_copy_plan.v1' and plan['selection_sha256']==pins['selection.json']['sha256'] and plan['destination']==D,'actual-plan-schema-selection')
 need(receipt['schema_version']=='p8_project_copy_receipt.v1' and receipt['mode']=='plan' and receipt['status']=='planned_pending_explicit_prepare' and receipt['source_prepared'] is False and receipt['runtime_grant'] is False and receipt['destination']==D and receipt['source_unchanged'] is True,'actual-plan-only-receipt')
 before={};merged={'files':{},'directories':{}}
 need({row['id'] for row in selection['inputs']}=={'root','zipcpu','opentitan','ibex'} and len(selection['inputs'])==4,'four-inputs')
 for row in selection['inputs']:
  identity=row['id'];mapname=identity+'-qualified-map.json';auditname=identity+'-input-audit.json';mapping=j(Path(descriptors[mapname]['path']));audit=j(Path(descriptors[auditname]['path']))
  need(row['qualified_map']==dict(path=R+'/'+mapname,sha256=pins[mapname]['sha256']) and row['audit_receipt']==dict(path=R+'/'+auditname,sha256=pins[auditname]['sha256']),'actual-adapter-selection-pins')
  need(audit['schema_version']=='p8_copy_input_audit.v1' and audit['status']=='independent_audit_passed' and audit['source']==row['source'] and audit['qualified_map_sha256']==pins[mapname]['sha256'],'actual-adapter-map-source')
  before[identity]=mapping
  for category in ('files','directories'):
   for name,pin in mapping[category].items():
    target=name if row['mount']=='.' else row['mount']+'/'+name
    need(target==str(PurePosixPath(target)) and '..' not in PurePosixPath(target).parts and not target.startswith('/'),'merged-path')
    if target in merged[category]:need(category=='directories' and merged[category][target]==pin,'unexpected-overlay-collision')
    merged[category][target]=pin
    if category=='files' and pin['kind']=='symlink':
     link=row['tracked_links'][name];raw=bytes.fromhex(pin['linkbytes_hex'])
     need(link==dict(git_mode='120000',git_oid=pin['git_oid'],linkbytes_hex=raw.hex()) and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin['git_oid'] and hashlib.sha256(raw).hexdigest()==pin['sha256'],'exact-mounted-tracked-link')
  if row['mount']!='.':
   for parentpath in [PurePosixPath(row['mount']),*PurePosixPath(row['mount']).parents]:
    if str(parentpath)=='.':continue
    mode=selection['mount_directories'][str(parentpath)];need(mode=={'mode':0o755},'explicit-mount-parent0755')
    if str(parentpath) in merged['directories']:need(merged['directories'][str(parentpath)]==mode,'mount-parent-conflict')
    merged['directories'][str(parentpath)]=mode
 need(plan['source_maps']==receipt['source_before']==receipt['source_after']==before,'actual-four-full-before-after-maps')
 need(plan['final_map']==merged,'independent-complete-postoverlay-map')
 for name in merged['files']:need(name not in merged['directories'] and not any(str(parent) in merged['files'] for parent in PurePosixPath(name).parents if str(parent)!='.'),'merged-leaf-ancestor-conflict')
 print(json.dumps(dict(status='independent_saved_plan_verified_pending_root_prepare_decision',scope='pure_plan_no_prepare_or_runtime_grant',plan_sha256=sha(a.evidence/'project-plan.json'),files=len(merged['files']),directories=len(merged['directories']),actual_parent_pid=parent['pid'],actual_copier_pid=parent['child_pid']),sort_keys=True))
if __name__=='__main__':main()
