import sys
sys.dont_write_bytecode=True
import os,json,stat,hashlib,argparse
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--freeze',type=Path,required=True);a=p.parse_args()
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def require(value,message):
 if not value:raise ValueError(message)
r=a.root;expected=json.loads(a.freeze.read_bytes());receipt=json.loads(a.receipt.read_bytes());dirs={};files={}
require(not r.is_symlink() and r.is_dir(),'root-link-or-missing')
for parent,names,leaves in os.walk(r,followlinks=False):
 for name in names:
  q=Path(parent)/name;s=q.lstat();require(stat.S_ISDIR(s.st_mode),'directory-link-or-special:'+str(q));dirs[q.relative_to(r).as_posix()]={'mode':stat.S_IMODE(s.st_mode)}
 for name in leaves:
  q=Path(parent)/name;s=q.lstat();require(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'file-link-or-special:'+str(q));files[q.relative_to(r).as_posix()]={'mode':stat.S_IMODE(s.st_mode),'bytes':s.st_size,'sha256':sha(q)}
require(files==expected,'whole-file-map-drift')
require(dirs==receipt['directories'],'whole-directory-map-drift')
digest=hashlib.sha256(json.dumps(dirs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
require(digest==receipt['directory_manifest_sha256'],'directory-digest-mismatch')
require(sha(a.freeze)==receipt['freeze_sha256'],'freeze-receipt-mismatch')
print(json.dumps({'status':'verified_files_and_directories','root':str(r),'files':len(files),'directories':len(dirs),'directory_manifest_sha256':digest,'freeze_sha256':sha(a.freeze),'pid':os.getpid(),'native_or_tests_run':False}))
