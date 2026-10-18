import subprocess,tarfile,json,hashlib,argparse,shlex
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument('--remote-base',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();b=a.output;b.mkdir(exist_ok=False)
remote=PurePosixPath(a.remote_base)
if not str(remote).startswith('/root/fanzehui/myfuzz/operations/') or '..' in remote.parts:raise ValueError('remote-path-invalid')
cmd='ssh root@192.168.5.70 tar -C '+shlex.quote(str(remote/'control'))+' -czf - .'
with (b/'remote-copy-control.tar.gz').open('xb') as f:r=subprocess.run(['ssh','jumpserver',cmd],stdout=f,stderr=subprocess.PIPE)
(b/'download.stderr').write_bytes(r.stderr)
if r.returncode:raise SystemExit(r.returncode)
with tarfile.open(b/'remote-copy-control.tar.gz','r:gz') as t:
 data={m.name.removeprefix('./'):t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
receipt=json.loads(data['copy-receipt.json']);actual=json.loads(data['final-file-freeze.json']);old=json.loads(Path('/tmp/myfuzz-independent-preparation-20261018/ready-freeze.json').read_bytes());overlay=json.loads(Path('/tmp/p6-native-online-inputs-20261018/unpacked-map.json').read_bytes());prefixes=receipt['explicit_prefixes']
def selected(k):return any(k==p or k.startswith(p+'/') for p in prefixes)
expected={k:v for k,v in old.items() if selected(k)};expected.update({k:{f:v[f] for f in ('bytes','mode','sha256')} for k,v in overlay['files'].items()})
if expected!=actual:raise ValueError('independent-selected-file-map-differs')
if data['source-before-files.json']!=data['source-after-files.json'] or data['source-before-directories.json']!=data['source-after-directories.json']:raise ValueError('old-source-drift')
source=json.loads(data['source-before-directories.json']);dirs={k:v for k,v in source.items() if selected(k)}
for k in [*dirs,*[k for k in old if selected(k)]]:
 for p in PurePosixPath(k).parents:
  if str(p)!='.':dirs[str(p)]=source[str(p)]
dirs.update(overlay['directories'])
if dirs!=receipt['directories'] or dirs!=json.loads(data['final-directories.json']):raise ValueError('independent-directory-map-differs')
sha=hashlib.sha256(json.dumps(dirs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if sha!=receipt['directory_manifest_sha256']:raise ValueError('independent-directory-digest-differs')
report={'status':'independent_file_directory_review_passed','files':len(actual),'directories':len(dirs),'file_freeze_sha256':hashlib.sha256(data['final-file-freeze.json']).hexdigest(),'receipt_sha256':hashlib.sha256(data['copy-receipt.json']).hexdigest(),'directory_sha256':sha,'old_source_unchanged':True,'static_host_source_count':len(receipt.get('static_host_source_paths',[]))}
(b/'independent-copy-review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
