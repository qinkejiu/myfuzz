"""Unexecuted source draft: upload eleven exact files, then separately run plan only."""
import argparse,hashlib,json,os,shlex,stat,subprocess,time
from pathlib import Path
BASE=Path('/home/qinkejiu/myfuzz-p8-qualified-inputs-20261018-attempt1')
HERE=Path(__file__).resolve().parent
REMOTE='/root/fanzehui/myfuzz/operations/p8-full-project-inputs-20261018-attempt1'
COPIER='b3bb05ef870551045539a1626690b2987fe08f362ef4c04ba58f2d3d2b342cf6'
NAMES={'selection.json','selected-copy-paths.json','prepare_p8_project.py'}|{n+s for n in ('root','zipcpu','opentitan','ibex') for s in ('-input-audit.json','-qualified-map.json')}
def need(v,m):
 if not v:raise ValueError(m)
def sha(path):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(path,row):
 with path.open('x') as f:json.dump(row,f,sort_keys=True,indent=2);f.flush();os.fsync(f.fileno())
def owned(stem,argv,data=None):
 row=dict(argv=argv,started_unix=time.time(),returncode=None);proc=None;primary=None
 with (HERE/(stem+'.stdout')).open('xb') as out,(HERE/(stem+'.stderr')).open('xb') as err:
  try:
   proc=subprocess.Popen(argv,stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,stdout=out,stderr=err);row['pid']=proc.pid;write(HERE/(stem+'.start.json'),row)
   if data is not None:proc.stdin.write(data)
  except BaseException as e:primary=e
  finally:
   if proc is not None:
    try:
     if proc.stdin is not None and not proc.stdin.closed:proc.stdin.close()
    except BaseException as e:
     if primary is None:primary=e
    while True:
     try:row['returncode']=proc.wait(timeout=30);break
     except subprocess.TimeoutExpired:continue
     except BaseException as e:
      if primary is None:primary=e
 row.update(ended_unix=time.time(),stdout_sha256=sha(HERE/(stem+'.stdout')),stderr_sha256=sha(HERE/(stem+'.stderr')),error=repr(primary) if primary else None)
 try:write(HERE/(stem+'.terminal.json'),row)
 except BaseException as error:
  if primary is None:primary=error
  else:primary.add_note('terminal evidence: '+repr(error))
 if primary:raise primary
 need(row['returncode']==0,'actual-SSH-failed')
 return row
UPLOAD=r'''
import hashlib,json,os,stat,sys,time
from pathlib import Path
root=Path(REMOTE);stage=root.with_name(root.name+'.upload-stage');pins=PINS
for p in (root,stage):
 if any(q.is_symlink() for q in (p,*p.parents)) or p.exists():raise ValueError('new-nofollow-destination-required')
body=json.load(sys.stdin);files=body['files']
if set(files)!=set(pins):raise ValueError('exact-eleven-inputs')
stage.mkdir();primary=None;record=dict(schema_version='p8_full_input_upload.v1',status='failed',pid=os.getpid(),started_unix=time.time(),pins=pins)
def maps(path):
 result={}
 for p in path.iterdir():
  s=p.lstat()
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('nonregular-input')
  with p.open('rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
  result[p.name]=dict(bytes=s.st_size,mode=stat.S_IMODE(s.st_mode),sha256=h)
 return result
try:
 for name,pin in pins.items():
  if '/' in name or name in ('','.','..') or '\\' in name:raise ValueError('flat-name-required')
  raw=bytes.fromhex(files[name])
  if len(raw)!=pin['bytes'] or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise ValueError('input-pin')
  with (stage/name).open('xb') as f:f.write(raw)
  (stage/name).chmod(pin['mode'])
 if maps(stage)!=pins:raise ValueError('actual-full-input-census')
 stage.rename(root);record['status']='uploaded_eleven_inputs_pending_separate_plan'
except BaseException as error:primary=error;record['error']=repr(error)
finally:
 record['ended_unix']=time.time()
 destination=root if root.exists() else stage
 try:
  with (destination/'upload-receipt.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2);f.flush();os.fsync(f.fileno())
 except BaseException as error:
  if primary is None:primary=error
  else:primary.add_note('upload receipt: '+repr(error))
try:
 path=destination/'upload-receipt.json'
 if path.exists():sys.stdout.buffer.write(path.read_bytes());sys.stdout.buffer.flush()
except BaseException as error:
 if primary is None:primary=error
 else:primary.add_note('return raw upload receipt: '+repr(error))
if primary:raise primary
'''
PLAN=r'''
import hashlib,json,os,stat,subprocess,sys,tarfile,time,io
from pathlib import Path
root=Path(REMOTE);expected=EXPECTED
if any(p.is_symlink() for p in (root,*root.parents)):raise ValueError('input-symlink')
def sha(p):
 if p.is_symlink():raise ValueError('input-link')
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(name,row):
 with (root/name).open('x') as f:json.dump(row,f,sort_keys=True,indent=2);f.flush();os.fsync(f.fileno())
if sha(root/'upload-receipt.json')!=expected['upload_receipt_sha256']:raise ValueError('actual-upload-receipt-pin')
upload=json.loads((root/'upload-receipt.json').read_bytes());pins=expected['pins']
if upload['status']!='uploaded_eleven_inputs_pending_separate_plan' or upload['pins']!=pins or set(p.name for p in root.iterdir())!=set(pins)|{'upload-receipt.json'}:raise ValueError('actual-upload-chain')
for name,pin in pins.items():
 s=(root/name).lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=pin['bytes'] or stat.S_IMODE(s.st_mode)!=pin['mode'] or sha(root/name)!=pin['sha256']:raise ValueError('preplan-input-drift')
if pins['prepare_p8_project.py']['sha256']!='b3bb05ef870551045539a1626690b2987fe08f362ef4c04ba58f2d3d2b342cf6':raise ValueError('copier-source-pin')
paths=json.loads((root/'selected-copy-paths.json').read_bytes())
if paths!=dict(copier_sha256=pins['prepare_p8_project.py']['sha256'],remote_control=str(root),destination='/root/fanzehui/myfuzz/operations/p8-scalar-20261018-attempt1/project',plan=str(root/'project-plan.json'),plan_receipt=str(root/'project-plan-receipt.json'),prepare_receipt=str(root/'project-prepare-receipt.json'),runtime_grant=False):raise ValueError('selected-paths')
argv=['/usr/bin/python3','-B',str(root/'prepare_p8_project.py'),'plan','--selection',str(root/'selection.json'),'--selection-sha256',pins['selection.json']['sha256'],'--plan',paths['plan'],'--destination',paths['destination'],'--receipt',paths['plan_receipt']]
record=dict(schema_version='p8_actual_plan_parent.v1',pid=os.getpid(),argv=argv,cwd=str(root),started_unix=time.time(),pins=pins,returncode=None);primary=None;child=None
with (root/'plan.stdout').open('xb') as out,(root/'plan.stderr').open('xb') as err:
 try:
  child=subprocess.Popen(argv,cwd=root,stdin=subprocess.DEVNULL,stdout=out,stderr=err);record['child_pid']=child.pid;write('plan-parent-start.json',record)
 except BaseException as e:primary=e
 finally:
  if child is not None:
   while True:
    try:record['returncode']=child.wait(timeout=30);break
    except subprocess.TimeoutExpired:continue
    except BaseException as e:
     if primary is None:primary=e
record['ended_unix']=time.time();record['post_input_checks']={}
try:
 for stream in ('stdout','stderr'):
  try:record[stream+'_sha256']=sha(root/('plan.'+stream))
  except BaseException as error:
   if primary is None:primary=error
   else:primary.add_note('stream collection: '+repr(error))
 for name,pin in pins.items():
  try:
   path=root/name;info=path.lstat()
   if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=pin['bytes'] or stat.S_IMODE(info.st_mode)!=pin['mode'] or sha(path)!=pin['sha256']:raise ValueError('postplan-input-drift:'+name)
   record['post_input_checks'][name]='unchanged'
  except BaseException as error:
   record['post_input_checks'][name]=repr(error)
   if primary is None:primary=error
   else:primary.add_note('post input: '+repr(error))
finally:
 record.update(error=repr(primary) if primary else None,status='actual_plan_terminal_pending_independent_review' if primary is None and record['returncode']==0 else 'failed')
 try:write('plan-parent-terminal.json',record)
 except BaseException as error:
  if primary is None:primary=error
  else:primary.add_note('plan terminal receipt: '+repr(error))
# Return original plan/receipt/stream/parent bytes, even on actual plan failure.
names=['upload-receipt.json','plan-parent-start.json','plan-parent-terminal.json','plan.stdout','plan.stderr','project-plan.json','project-plan-receipt.json'];blobs={name:(root/name).read_bytes() for name in names if (root/name).exists()}
blobs['returned-member-pins.json']=json.dumps({name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()) for name,raw in blobs.items()},sort_keys=True).encode()
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|',format=tarfile.USTAR_FORMAT) as archive:
 for name,raw in blobs.items():
  m=tarfile.TarInfo(name);m.size=len(raw);m.mode=0o644;archive.addfile(m,io.BytesIO(raw))
if primary:raise primary
raise SystemExit(record['returncode'] if record['returncode'] is not None else 1)
'''
def main():
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('upload','plan'));p.add_argument('--inputs',type=Path,required=True);p.add_argument('--inputs-sha256',required=True);p.add_argument('--upload-receipt-sha256');p.add_argument('--upload-terminal-sha256');p.add_argument('--upload-postcheck-sha256');a=p.parse_args()
 need(sha(a.inputs)==a.inputs_sha256,'reviewed-input-manifest-pin');descriptors=json.loads(a.inputs.read_bytes());need(set(descriptors)==NAMES,'exact-eleven-input-manifest')
 pins={};files={}
 for name,descriptor in sorted(descriptors.items()):
  source=Path(descriptor['path']);need(source.is_absolute() and not any(q.is_symlink() for q in (source,*source.parents)),'local-input-link')
  if name!='prepare_p8_project.py':need(source.parent==BASE,'fixed-qualified-output-source')
  s=source.lstat();pin={k:descriptor[k] for k in ('bytes','mode','sha256')};need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==pin['bytes'] and stat.S_IMODE(s.st_mode)==pin['mode'] and sha(source)==pin['sha256'],'actual-local-input-pin');pins[name]=pin
  if a.mode=='upload':files[name]=source.read_bytes().hex()
 need(pins['prepare_p8_project.py']['sha256']==COPIER,'copier-b3bb')
 if a.mode=='upload':
  code=UPLOAD.replace('REMOTE',repr(REMOTE)).replace('PINS',repr(pins));data=json.dumps(dict(files=files)).encode()
 else:
  need(a.upload_receipt_sha256 and a.upload_terminal_sha256 and a.upload_postcheck_sha256,'actual-upload-chain-pins-required')
  tp=HERE/'full-input-upload.terminal.json';pp=HERE/'full-input-upload.postcheck.json'
  need(sha(tp)==a.upload_terminal_sha256 and sha(pp)==a.upload_postcheck_sha256,'actual-local-upload-receipt-pins')
  uploadterm=json.loads(tp.read_bytes());uploadpost=json.loads(pp.read_bytes())
  need(uploadterm['returncode']==0 and uploadterm['error'] is None and uploadpost['status']=='actual_ssh_terminal0_and_local_inputs_unchanged' and uploadpost['pins']==pins and uploadpost['terminal_sha256']==a.upload_terminal_sha256,'actual-local-upload-status')
  need(uploadpost['controller_sha256']==sha(Path(__file__)),'local-upload-source-drift')
  need(uploadpost['remote_upload_receipt_sha256']==a.upload_receipt_sha256==sha(HERE/'full-input-upload.stdout'),'returned-upload-receipt-exact-sha')
  returned=json.loads((HERE/'full-input-upload.stdout').read_bytes());need(returned['schema_version']=='p8_full_input_upload.v1' and returned['status']=='uploaded_eleven_inputs_pending_separate_plan' and returned['pins']==pins,'returned-upload-receipt-binding')
  for stream in ('stdout','stderr'):need(sha(HERE/('full-input-upload.'+stream))==uploadterm[stream+'_sha256'],'local-upload-stream-pin')
  uploadcode=UPLOAD.replace('REMOTE',repr(REMOTE)).replace('PINS',repr(pins))
  uploadcommand='ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(uploadcode))
  need(uploadterm['argv']==['ssh','jumpserver',uploadcommand],'actual-local-upload-exact-argv')
  code=PLAN.replace('REMOTE',repr(REMOTE)).replace('EXPECTED',repr(dict(upload_receipt_sha256=a.upload_receipt_sha256,pins=pins)));data=None
 command='ssh root@192.168.5.70 '+shlex.quote('PYTHONDONTWRITEBYTECODE=1 python3 -B -c '+shlex.quote(code))
 primary=None;terminal=None
 post=dict(status='failed',mode=a.mode,pins=pins,controller_sha256=sha(Path(__file__)),input_checks={})
 try:
  terminal=owned('full-input-'+a.mode,['ssh','jumpserver',command],data)
 except BaseException as error:primary=error
 finally:
  for name,row in descriptors.items():
   try:
    path=Path(row['path']);info=path.lstat();pin=pins[name]
    need(not any(q.is_symlink() for q in (path,*path.parents)) and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==pin['bytes'] and stat.S_IMODE(info.st_mode)==pin['mode'] and sha(path)==pin['sha256'],'local-input-post-drift:'+name)
    post['input_checks'][name]='unchanged'
   except BaseException as error:
    post['input_checks'][name]=repr(error)
    if primary is None:primary=error
    else:primary.add_note('local postcheck: '+repr(error))
  try:
   terminal_path=HERE/('full-input-'+a.mode+'.terminal.json')
   post['terminal_sha256']=sha(terminal_path)
   actual=json.loads(terminal_path.read_bytes())
   post['actual_returncode']=actual['returncode'];post['actual_error']=actual['error']
   need(actual['returncode']==0 and actual['error'] is None,'actual-terminal-not-successful')
   for stream in ('stdout','stderr'):need(sha(HERE/('full-input-'+a.mode+'.'+stream))==actual[stream+'_sha256'],'actual-stream-drift')
   if a.mode=='upload':
    raw_receipt=HERE/'full-input-upload.stdout';uploaded=json.loads(raw_receipt.read_bytes())
    need(uploaded['schema_version']=='p8_full_input_upload.v1' and uploaded['status']=='uploaded_eleven_inputs_pending_separate_plan' and uploaded['pins']==pins,'returned-actual-upload-receipt')
    post['remote_upload_receipt_sha256']=sha(raw_receipt)
  except BaseException as error:
   if primary is None:primary=error
   else:primary.add_note('actual terminal/receipt check: '+repr(error))
  if primary is None:post['status']='actual_ssh_terminal0_and_local_inputs_unchanged'
  else:post['primary_error']=repr(primary)
  try:write(HERE/('full-input-'+a.mode+'.postcheck.json'),post)
  except BaseException as error:
   if primary is None:primary=error
   else:primary.add_note('postcheck receipt write: '+repr(error))
 if primary:raise primary
if __name__=='__main__':main()
