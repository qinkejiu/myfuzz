from pathlib import Path
from hashlib import sha256
import json,tarfile,tempfile,os
base=Path('/root/fanzehui/f4-filelist-verification-20261017-b370e3d')
old=Path('/root/fanzehui/f4-abi-verification-20261017-59f6fa4')
archive=base/'reviewed-overlay.tar.gz'
if sha256(archive.read_bytes()).hexdigest()!='595c5b43e89ad9ef675f61859492013d2e2e6074c3dac82dee59cab60e672186':raise SystemExit('overlay archive mismatch')
paths=['src/myfuzz/integration/compiled_execution_files.py','scripts/check_compiled_obi_no_error_boundary.py','tests/integration/test_compiled_execution_files.py','tests/integration/test_compiled_filelist_sources.py']
allowed={'project/'+name for name in paths}|{'source_manifest.json','run_gate.sh','verify_snapshot.py','validate_gate.py','launch-files.sha256'}
with tarfile.open(archive) as tar:
    if {m.name for m in tar.getmembers()}!=allowed or any(not m.isfile() for m in tar.getmembers()):raise SystemExit('unexpected overlay members')
    for member in tar.getmembers():
        target=base/member.name;target.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as handle:
            handle.write(tar.extractfile(member).read());temporary=Path(handle.name)
        temporary.replace(target)
manifest=json.loads((base/'source_manifest.json').read_text());prior=json.loads((old/'source_manifest.json').read_text())
shared=[]
for name in set(manifest['files'])&set(prior['files']):
    a=(base/'project'/name).stat();b=(old/'project'/name).stat()
    if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino):shared.append(name)
changes=sorted(name for name in set(manifest['files'])|set(prior['files']) if manifest['files'].get(name)!=prior['files'].get(name))
result=dict(shared_inodes=shared,reviewed_overlay=changes,overlay_matches=changes==sorted(paths),file_count=len(manifest['files']))
(base/'logs/remote-copy-proof.json').write_text(json.dumps(result,sort_keys=True)+'\n')
print(json.dumps(result,sort_keys=True))
if shared or changes!=sorted(paths):raise SystemExit(2)
