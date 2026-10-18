import sys
sys.dont_write_bytecode=True
import os,json,hashlib,subprocess,time,fcntl,argparse,shutil
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--freeze-sha256',required=True);p.add_argument('--receipt-sha256',required=True);a=p.parse_args()
base=Path('/root/fanzehui/myfuzz/operations/p6-native-online-c924aac-20261018-attempt2');root=base/'project';copy_control=base/'control';control=base/'gate-attempt3-control';inputs=Path('/root/fanzehui/myfuzz/operations/p6-native-inputs-20261018');lock=Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock');envbase=Path('/root/fanzehui/myfuzz/operations/environment-20261018-attempt3')
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def require(value,message):
 if not value:raise ValueError(message)
def write(name,obj):
 with (control/name).open('x') as f:json.dump(obj,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
def child(name,argv):
 rec={'argv':[str(x) for x in argv],'cwd':str(root),'started_unix':time.time(),'returncode':None};primary=None
 with (control/(name+'.stdout')).open('xb') as out,(control/(name+'.stderr')).open('xb') as err:
  proc=subprocess.Popen(rec['argv'],cwd=root,env=os.environ.copy(),stdin=subprocess.DEVNULL,stdout=out,stderr=err)
  try:rec['pid']=proc.pid;write(name+'.launch.json',rec)
  except BaseException as e:primary=e
  while True:
   try:code=proc.wait(timeout=30);break
   except subprocess.TimeoutExpired:continue
   except BaseException as e:
    if primary is None:primary=e
  rec.update(returncode=code,ended_unix=time.time())
  try:
   rec.update(stdout_sha256=sha(control/(name+'.stdout')),stderr_sha256=sha(control/(name+'.stderr')));write(name+'.terminal.json',rec)
  except BaseException as e:
   if primary is None:primary=e
  if primary is not None:raise primary
 return code
require(sha(copy_control/'final-file-freeze.json')==a.freeze_sha256,'caller-file-freeze-mismatch');require(sha(copy_control/'copy-receipt.json')==a.receipt_sha256,'caller-copy-receipt-mismatch')
require(sha(root/'scripts/verify_picorv32_native_online.py')=='7180463cc397b7c0be6a1c9ab25a9b5e0db01e2587b4c8bcd6f8a33db0ae9184','gate-script-drift')
require(sha(envbase/'tool-freeze.json')=='6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b','tool-manifest-drift');require(sha(envbase/'environment.sh')=='9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c','environment-drift')
tools=json.loads((envbase/'tool-freeze.json').read_bytes())
require(str(Path(sys.executable).resolve())==tools['python3']['path'] and sha(Path(sys.executable).resolve())==tools['python3']['sha256'],'actual-interpreter-drift')
require(sha(inputs/'verify_layout.py')=='fde48b5432820af601c1387ab89bd79f5db1a324821dac833092f43529f02837','layout-verifier-drift')
inventory_path=Path('/root/fanzehui/myfuzz/operations/p7-i5-independent-6b40ef4-20261018-attempt1/control/tool-inventory.json')
require(sha(inventory_path)=='9672f2b6ab65a587c8533e574851cf8990ead9867e0d089d0c3f030af1470d10','inventory-drift')
inventory=json.loads(inventory_path.read_bytes())
def tool_check(phase):
 for name,pin in tools.items():
  actual=shutil.which(name);require(actual is not None and str(Path(actual).resolve())==pin['path'] and sha(Path(actual).resolve())==pin['sha256'],'selected-tool-drift:'+name)
 for section in ('verilator_share','system_entrypoints'):
  for name,pin in inventory[section].items():
   require(sha(Path(pin['resolved']))==pin['sha256'],'tool-dependency-drift:'+name)
 share_root=Path('/root/fanzehui/myfuzz/tools/verilator-5.051');share_actual={}
 for parent,dirs,names in os.walk(share_root/'share/verilator',followlinks=False):
  for name in dirs:require(not (Path(parent)/name).is_symlink(),'verilator-share-directory-link')
  for name in names:
   q=Path(parent)/name;require(q.is_file() and not q.is_symlink(),'verilator-share-file-link');share_actual[q.relative_to(share_root).as_posix()]={'bytes':q.stat().st_size,'sha256':sha(q)}
 require(share_actual=={k:{f:v[f] for f in ('bytes','sha256')} for k,v in inventory['verilator_share'].items()},'verilator-share-set-drift')
 lib=Path('/root/fanzehui/myfuzz/pythonlib');actual={}
 for parent,dirs,names in os.walk(lib,followlinks=False):
  for name in dirs:require(not (Path(parent)/name).is_symlink(),'pythonlib-directory-link')
  for name in names:
   q=Path(parent)/name;require(q.is_file() and not q.is_symlink(),'pythonlib-file-link');actual[q.relative_to(lib).as_posix()]={'bytes':q.stat().st_size,'sha256':sha(q)}
 require(actual==inventory['pythonlib_files'],'python-dependency-directory-drift')
 write(phase+'-tools.json',{'entrypoints':tools,'inventory_sha256':sha(inventory_path),'share_files':len(inventory['verilator_share']),'pythonlib_files':len(actual)})
verify=[sys.executable,inputs/'verify_layout.py','--root',root,'--receipt',copy_control/'copy-receipt.json','--freeze',copy_control/'final-file-freeze.json']
control.mkdir(exist_ok=False)
primary=None;code=None;layoutcode=None;metadata=[]
try:
 tool_check('before')
 require(child('layout-before-native',verify)==0,'layout-preflight-failed')
 with lock.open('a+b') as f:
  fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  commands=[('git-root-head',['git','rev-parse','HEAD']),('git-closures-tracked',['git','ls-files','--error-unmatch','configs/soc/closures/picorv32.json','configs/soc/closures/pulp_gpio.json'])]
  for component in ('picorv32_upstream_reference','soc-pulp-apb-gpio'):
   commands.append(('git-'+component+'-connectivity',['git','-C',root/'third_party'/component,'fsck','--connectivity-only','--no-dangling']))
  for name,argv in commands:
   rc=child(name,argv);metadata.append({'name':name,'returncode':rc});require(rc==0,'git-preflight-failed:'+name)
  require((control/'git-root-head.stdout').read_text().strip()=='6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941','root-head-drift')
 (base/'native-cache-attempt3').mkdir(exist_ok=False)
 code=child('native-directed-gate',[sys.executable,root/'scripts/verify_picorv32_native_online.py','--output',base/'run-attempt3','--cache-dir',base/'native-cache-attempt3','--heavy-lock',lock])
except BaseException as e:primary=e
finally:
 try:
  layoutcode=child('layout-after-native',verify);tool_check('after')
 except BaseException as e:
  if primary is None:primary=e
 result={'status':'collected_pending_independent_audit' if primary is None and code==0 and layoutcode==0 else 'failed','gate_returncode':code,'layout_returncode':layoutcode,'git_metadata':metadata,'error':repr(primary) if primary else None,'formal_p6_complete':False}
 try:write('native-operation-result.json',result)
 except BaseException as e:
  if primary is None:primary=e
if primary is not None:raise primary
raise SystemExit(0 if code==0 and layoutcode==0 else 1)
