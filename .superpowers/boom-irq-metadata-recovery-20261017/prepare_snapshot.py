"""Prepare only: copy source scopes independently, hash before/after/destination."""
import hashlib,io,json,os,subprocess,tarfile
from pathlib import Path
from myfuzz.local_harness.boom_irq_recovery import SCOPES,_tree_files
root=Path.cwd().resolve()
base=root/'.superpowers/boom-irq-metadata-recovery-20261017'
stage=base/'source-staging';stage.mkdir()
def inventory(directory):
    return {str(file.relative_to(directory)):hashlib.sha256(file.read_bytes()).hexdigest()
            for scope in SCOPES for file in sorted(_tree_files(directory/scope))}
git=root/'third_party/soc-pulp-apb-gpio/.git'
assert git.is_dir() and not git.is_symlink()
assert not (git/'commondir').exists() and not (git/'objects/info/alternates').exists()
pins=json.loads((root/'.superpowers/boom-irq-verification-20261017/recovery-helper-source-pins.json').read_text())
before=inventory(root)
for name,expected in pins.items(): assert before[name]==expected,name
for scope in SCOPES:
    destination=stage/scope;destination.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run(['cp','-a',str(root/scope),str(destination)],check=True)
after=inventory(root);destination=inventory(stage)
assert before==after==destination,'source/destination drift'
shared=[name for name in before if os.path.samestat((root/name).stat(),(stage/name).stat())]
assert not shared,shared
assert all((stage/name).stat().st_nlink==1 for name in before)
for name,rows in [('source-before.json',before),('source-after.json',after),('source-destination.json',destination)]:
    (base/name).write_text(json.dumps({'schema_version':'boom_irq_metadata_source_snapshot.v1','scopes':SCOPES,'files':rows},indent=2)+'\n')
with tarfile.open(base/'source.tar.gz','w:gz') as archive:
    for name in sorted(destination):
        data=(stage/name).read_bytes();assert hashlib.sha256(data).hexdigest()==destination[name]
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=(stage/name).stat().st_mode&0o777
        archive.addfile(info,io.BytesIO(data))
report={'stage':'prepared_local_only','files':len(before),'owned_pins_checked':len(pins),
    'before_after_destination_equal':True,'shared_inodes':shared,'all_destination_links_one':True,
    'pulp_git_directory_preserved':True,'pulp_git_files':sum(name.startswith('third_party/soc-pulp-apb-gpio/.git/') for name in before),
    'pulp_external_object_refs_absent':True,'clean_checkout_claim':False,
    'source_authority':False,'source_archive_sha256':hashlib.sha256((base/'source.tar.gz').read_bytes()).hexdigest()}
(base/'local-preparation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
