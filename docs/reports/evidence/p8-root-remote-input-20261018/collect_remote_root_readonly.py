"""Prepared only: read-only remote saved root/transport evidence collector; stdout tar."""
import hashlib,io,json,os,stat,sys,tarfile,time
from pathlib import Path
FAN=Path('/root/fanzehui')
OP=FAN/'myfuzz/operations'
DEST=OP/'p8-root-input-20261018-attempt1'
INBOX=OP/'p8-root-input-transfer-20261018-attempt1'

def need(v,m):
 if not v:raise ValueError(m)
def safe(p):
 need(p.is_absolute() and p.is_relative_to(FAN) and '..' not in p.parts,'outside fan')
 for a in (p,*p.parents):need(not a.is_symlink(),'symlink ancestor')
 return p
def read(p):
 safe(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'nonregular input');return f.read()
def pin(p):
 safe(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_nlink==1,'file type/link')
  return dict(bytes=s.st_size,mode=stat.S_IMODE(s.st_mode),sha256=hashlib.file_digest(f,'sha256').hexdigest())
def maps(p):
 safe(p);need(stat.S_ISDIR(p.lstat().st_mode),'not directory');files={};dirs={}
 for parent,ds,fs in os.walk(p,followlinks=False):
  for n in ds:
   q=Path(parent)/n;s=q.lstat();need(stat.S_ISDIR(s.st_mode),'directory special/link');dirs[q.relative_to(p).as_posix()]={'mode':stat.S_IMODE(s.st_mode)}
  for n in fs:
   q=Path(parent)/n;files[q.relative_to(p).as_posix()]=pin(q)
 return {'files':files,'directories':dirs,'root_mode':stat.S_IMODE(p.lstat().st_mode)}
def gone(pid):
 need(type(pid)is int and pid>1,'pid shape')
 return not Path('/proc',str(pid)).exists()
def main():
 start=time.time();blobs={}
 for name in ['transfer-manifest.json','control-inputs.json','extract_remote_root_input.py','upload-receipt.json','extract-parent-start.json','extract-parent-terminal.json','extract-parent.stdout','extract-parent.stderr','extraction-receipt.json']:
  blobs['inbox/'+name]=read(INBOX/name)
 parent=json.loads(blobs['inbox/extract-parent-terminal.json']);child=json.loads(blobs['inbox/extraction-receipt.json'])
 # No success is inferred here: actual raw receipts and process absence are saved for separate audit.
 observed={'schema_version':'p8_root_readonly_collection.v1','started_unix':start,'remote_destination':str(DEST),'remote_inbox':str(INBOX),'root':maps(DEST/'root'),'control':maps(DEST/'control'),'destination':maps(DEST),'inbox':maps(INBOX),'parent_pid':parent['pid'],'child_pid':parent['child_pid'],'parent_gone':gone(parent['pid']),'child_gone':gone(parent['child_pid']),'parent_actual_returncode':parent['returncode'],'extraction_actual_returncode':child['returncode']}
 for name in observed['control']['files']:blobs['control/'+name]=read(DEST/'control'/name)
 for name in ['.git/HEAD','.git/refs/heads/codex/system-completion-20261016']:blobs['root-small/'+name]=read(DEST/'root'/name)
 # A second full census detects mutation across the observation, including inbox archive bytes.
 need(observed['root']==maps(DEST/'root') and observed['control']==maps(DEST/'control') and observed['destination']==maps(DEST) and observed['inbox']==maps(INBOX),'collection map drift')
 observed['ended_unix']=time.time();observed['collection_time_scope']='later_readonly_not_terminal_time';observed['remote_write_or_git_or_model_execution']=False
 blobs['observed.json']=(json.dumps(observed,sort_keys=True,indent=2)+'\n').encode()
 index={n:{'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in blobs.items()}
 blobs['member-index.json']=(json.dumps(index,sort_keys=True,indent=2)+'\n').encode()
 with tarfile.open(fileobj=sys.stdout.buffer,mode='w|',format=tarfile.USTAR_FORMAT) as t:
  for n,b in sorted(blobs.items()):
   m=tarfile.TarInfo(n);m.mode=0o644;m.size=len(b);t.addfile(m,io.BytesIO(b))
if __name__=='__main__':main()
