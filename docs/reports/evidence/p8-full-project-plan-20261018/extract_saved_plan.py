"""Unexecuted source draft: exclusively unpack the original flat plan-evidence tar."""
import argparse,hashlib,json,os,stat,tarfile
from pathlib import Path,PurePosixPath
NAMES={'upload-receipt.json','plan-parent-start.json','plan-parent-terminal.json','plan.stdout','plan.stderr','project-plan.json','project-plan-receipt.json','returned-member-pins.json'}
def need(v,m):
 if not v:raise ValueError(m)
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def safe(p):
 need(p.is_absolute() and '..' not in p.parts,'absolute-normalized-output')
 for q in (p,*p.parents):need(not q.is_symlink(),'path-link')
def main():
 p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--archive-sha256',required=True);p.add_argument('--target',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args()
 for path in (a.archive,a.target,a.receipt):safe(path)
 need(sha(a.archive)==a.archive_sha256,'actual-stdout-archive-pin');need(not a.target.exists() and not a.receipt.exists(),'exclusive-output')
 need(not a.receipt.is_relative_to(a.target) and not a.target.is_relative_to(a.archive) and not a.archive.is_relative_to(a.target),'output-conflict')
 a.target.mkdir();seen={};primary=None;result=dict(schema_version='p8_safe_saved_plan_extract.v1',status='failed',archive_sha256=a.archive_sha256)
 try:
  with tarfile.open(a.archive,'r|') as archive:
   for m in archive:
    n=m.name;need(n in NAMES and n==str(PurePosixPath(n)) and '/' not in n and n not in seen and m.type==tarfile.REGTYPE and not m.issparse() and not m.pax_headers and m.mode==0o644,'member-type-path-duplicate')
    h=hashlib.sha256();total=0;source=archive.extractfile(m)
    with source,(a.target/n).open('xb') as out:
     while block:=source.read(1048576):h.update(block);total+=len(block);out.write(block)
    need(total==m.size,'member-size');(a.target/n).chmod(m.mode);need((a.target/n).stat().st_nlink==1,'member-hardlink')
    seen[n]=dict(bytes=total,sha256=h.hexdigest())
  need('returned-member-pins.json' in seen,'returned-index-missing')
  index=json.loads((a.target/'returned-member-pins.json').read_bytes())
  need(index=={n:p for n,p in seen.items() if n!='returned-member-pins.json'},'returned-exact-index-hashes')
  need(sha(a.archive)==a.archive_sha256,'actual-archive-drift')
  result.update(status='safely_extracted_pending_independent_audit',members=seen,member_count=len(seen))
 except BaseException as error:primary=error;result['error']=repr(error)
 finally:
  with a.receipt.open('x') as f:json.dump(result,f,indent=2,sort_keys=True)
 if primary:raise primary
if __name__=='__main__':main()
