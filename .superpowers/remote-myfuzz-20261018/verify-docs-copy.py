import hashlib,json,tarfile
from pathlib import Path
base=Path('/root/fanzehui/myfuzz/evidence/docs-followup-dd9684a-20261018')
archive=base/'docs-current.tar.gz'
expected='7745cdc45429f5a99593a7e52c4b2a8e0558d0596c7069e9e9a2d5d5c7f3bd40'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
with tarfile.open(archive) as t:
    members=t.getmembers()
    assert all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
    manifest=json.load(t.extractfile('docs-manifest.json'))
    assert set(m.name for m in members)==set(manifest['files'])|{'docs-manifest.json'}
    for name,row in manifest['files'].items():
        data=t.extractfile(name).read()
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    t.extractall(base/'contents',filter='data')
receipt={'status':'copied-and-hash-verified','scope':'documentation only; project/source/cache unchanged','archive_sha256':expected,'files':len(manifest['files']),'manifest_local_head':manifest['local_head'],'remote_directory':str(base),'tests_build_models_executed':False}
(base/'copy-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
