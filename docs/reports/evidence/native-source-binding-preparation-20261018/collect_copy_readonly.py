"""UNEXECUTED read-only target collector. No subprocess, Git or project imports."""
import base64,hashlib,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
INPUT=Path('/root/fanzehui/myfuzz/operations/p6-native-source-binding-inputs-20261018-attempt2')
OP=Path('/root/fanzehui/myfuzz/operations/p6-native-source-binding-20261018-attempt1')
SOURCE=Path('/root/fanzehui/myfuzz/operations/p6-native-completion-20261018-attempt2/project')
def safe(path):
 if not path.is_relative_to('/root/fanzehui'):raise ValueError('outside-fan')
 for p in (path,*path.parents):
  if p.is_symlink():raise ValueError('link-path')
def raw(path):
 safe(path);s=path.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:raise ValueError('nonregular')
 return path.read_bytes()
def census(root):
 safe(root);files={};dirs={}
 for folder,ds,ns in os.walk(root,followlinks=False):
  for n in ds:
   p=Path(folder)/n;s=p.lstat()
   if not stat.S_ISDIR(s.st_mode):raise ValueError('directory-type')
   dirs[p.relative_to(root).as_posix()]={'mode':stat.S_IMODE(s.st_mode)}
  for n in ns:
   p=Path(folder)/n;s=p.lstat();b=raw(p)
   files[p.relative_to(root).as_posix()]={'bytes':len(b),'mode':stat.S_IMODE(s.st_mode),'sha256':hashlib.sha256(b).hexdigest()}
 return {'files':files,'directories':dirs}
def main():
 started=time.time();evidence={}
 for prefix,root,names in (
  ('inputs',INPUT,['deployment-receipt.json','copy-parent-start.json','copy-parent-terminal.json','copy.stdout','copy.stderr']),
  ('operation',OP/'control',['copy-receipt.json','source-before-files.json','source-before-directories.json','source-after-files.json','source-after-directories.json','final-file-freeze.json','final-directories.json','explicit-host-files.json','reviewed-overlay-files.json','reviewed-overlay-directories.json'])):
  for n in names:evidence[prefix+'/'+n]=base64.b64encode(raw(root/n)).decode()
 source=census(SOURCE);output=census(OP/'project');inputs=census(INPUT)
 # Later observations only: /proc absence is never a child exit receipt.
 terminal=json.loads(base64.b64decode(evidence['inputs/copy-parent-terminal.json']))
 observations=[]
 for key in ('pid','child_pid'):
  pid=terminal.get(key)
  if type(pid)is not int or pid<=0:raise ValueError('pid-type')
  observations.append({'field':key,'pid':pid,'proc_exists_later':Path('/proc',str(pid)).exists()})
 # Repeat evidence and maps to refuse collection-time drift.
 for k,v in evidence.items():
  root=INPUT if k.startswith('inputs/') else OP/'control'
  if base64.b64encode(raw(root/k.split('/',1)[1])).decode()!=v:raise ValueError('evidence-drift')
 if source!=census(SOURCE) or output!=census(OP/'project') or inputs!=census(INPUT):raise ValueError('tree-drift')
 print(json.dumps({'schema_version':'native_binding_copy_readonly.v1','started_unix':started,'ended_unix':time.time(),'source':str(SOURCE),'output':str(OP/'project'),'inputs':str(INPUT),'source_census':source,'output_census':output,'inputs_census':inputs,'evidence':evidence,'later_process_observations':observations,'native_execution':False},sort_keys=True))
if __name__=='__main__':main()
