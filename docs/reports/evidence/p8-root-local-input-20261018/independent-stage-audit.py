"""Actual local regular-root copy audit; stdlib reads only, no Git/project code."""
from pathlib import Path, PurePosixPath
import datetime
import hashlib
import json
import os
import stat

CONTROL=Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2')
SOURCE=Path('/home/qinkejiu/myfuzz')
STAGE=Path('/home/qinkejiu/myfuzz-p8-root-input-20261018-attempt2')
PIN='11e1e298379b54973836de4ec57d4383ab84f9302081e688db0edf1cb7a908f8'
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
def load(path):return json.loads(path.read_bytes())
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def selected(name,prefixes):return any(name==prefix or name.startswith(prefix+'/') for prefix in prefixes)
def file_row(path):
    st=path.lstat()
    assert stat.S_ISREG(st.st_mode) and st.st_nlink==1
    return dict(bytes=st.st_size,mode=stat.S_IMODE(st.st_mode),sha256=sha(path))
def maps(root,includes=None,excludes=()):
    assert not any(path.is_symlink() for path in (root,*root.parents))
    files,dirs={},{}
    for prefix in includes if includes is not None else ['']:
        path=root/prefix
        if path.is_file():files[prefix]=file_row(path);continue
        for folder,children,names in os.walk(path,followlinks=False):
            children[:]=[name for name in children if not selected((Path(folder)/name).relative_to(root).as_posix(),excludes)]
            for current in [Path(folder),*[Path(folder)/name for name in children]]:
                if current==root:continue
                st=current.lstat();assert stat.S_ISDIR(st.st_mode)
                dirs[current.relative_to(root).as_posix()]={'mode':stat.S_IMODE(st.st_mode)}
            for name in names:
                current=Path(folder)/name;relative=current.relative_to(root).as_posix()
                if not selected(relative,excludes):files[relative]=file_row(current)
    return dict(sorted(files.items())),dict(sorted(dirs.items()))
assert sha(CONTROL/'selection.json')==PIN
manifest=load(CONTROL/'selection.json');receipt=load(CONTROL/'prepare-receipt.json');terminal=load(CONTROL/'prepare-launch-terminal.json')
assert manifest['source']==str(SOURCE) and manifest['destination']==str(STAGE)
assert terminal['returncode']==0 and terminal['pid']==43547 and terminal['manifest_sha256']==PIN
for name in ('prepare.stdout','prepare.stderr'):
    path=CONTROL/name;assert terminal[name]==dict(bytes=path.stat().st_size,sha256=sha(path))
assert terminal['preparer_sha256']==sha(SOURCE/'scripts/prepare_p7_i5_snapshot.py')=='89a7c42963aac5c7761d76c9e0f80776209645cc2876e56743f96a0df0e83e02'
expected_files={**manifest['files'],**manifest['generated_files']}
expected_dirs={**manifest['directories'],**manifest['generated_directories']}
actual_files,actual_dirs=maps(STAGE)
assert actual_files==expected_files==load(CONTROL/'freeze.json')
assert actual_dirs==expected_dirs==receipt['directories']
assert receipt['status']=='copied_pending_closure_and_tool_review'
assert receipt['source']==str(SOURCE) and receipt['destination']==str(STAGE) and receipt['manifest_sha256']==PIN
assert receipt['native_run'] is receipt['formal_p7_complete'] is False
assert receipt['freeze_sha256']==sha(CONTROL/'freeze.json')
assert receipt['files']==len(actual_files)==10347 and receipt['bytes']==sum(r['bytes'] for r in actual_files.values())==493088962
canonical_dirs=hashlib.sha256(json.dumps(actual_dirs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert receipt['directory_manifest_sha256']==canonical_dirs
for root in (SOURCE,STAGE):
    head=(root/'.git/HEAD').read_text().strip();assert head.startswith('ref: ')
    assert manifest['git_head_files']=={'.git':head}
    assert (root/'.git'/head.removeprefix('ref: ')).read_text().strip()=='269717b7e9cc7c92da5e427ac950bc82446b3ac6'
front={p:r for p,r in actual_files.items() if p.startswith('src/myfuzz/frontend/')}
prior=load(SOURCE/'.superpowers/sdd/native-completion-20261018/attempt2-control/local-current-src-scripts.json')
assert front=={p:r for p,r in prior.items() if p.startswith('src/myfuzz/frontend/')} and len(front)==387
elf=0
for name in front:
    with (STAGE/name).open('rb') as stream:elf+=stream.read(4)==b'\x7fELF'
assert elf==58
assert not any('__pycache__' in PurePosixPath(p).parts or PurePosixPath(p).suffix in ('.pyc','.pyo') for p in actual_files)
assert not any(p=='.git/modules' or p.startswith('.git/modules/') for p in [*actual_files,*actual_dirs])
assert '.gitmodules' in actual_files
# Last full original selection re-read occurs after all stage inspection.
source_files,source_dirs=maps(SOURCE,manifest['includes'],manifest['excludes'])
assert source_files==manifest['files'] and source_dirs==manifest['directories']
assert sha(CONTROL/'selection.json')==PIN
for name,value in [('independent-stage-files.json',actual_files),('independent-stage-directories.json',actual_dirs),('independent-source-final-files.json',source_files),('independent-source-final-directories.json',source_dirs)]:
    with (CONTROL/name).open('x') as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
report=dict(schema_version='independent_actual_regular_root_stage_audit.v1',status='actual_regular_root_copy_verified',
    scope='local_regular_root_prepared_only_no_remote_or_whole_project_or_adapter_or_P7_or_P8_grant',
    audit_started_at=started,audit_ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    manifest_sha256=PIN,source_HEAD='269717b7e9cc7c92da5e427ac950bc82446b3ac6',stage_HEAD='269717b7e9cc7c92da5e427ac950bc82446b3ac6',
    source=str(SOURCE),stage=str(STAGE),actual_copy_pid=43547,actual_copy_returncode=0,
    original_selected_files=10346,generated_empty_lock_files=1,actual_stage_files=len(actual_files),
    actual_stage_directories=len(actual_dirs),actual_stage_bytes=sum(r['bytes'] for r in actual_files.values()),
    complete_file_and_directory_sets_modes_nlink1_sha_verified=True,freeze_sha256=sha(CONTROL/'freeze.json'),
    prepare_receipt_sha256=sha(CONTROL/'prepare-receipt.json'),directory_canonical_sha256=canonical_dirs,
    frontend_files_unchanged=387,frontend_ELF_files_unchanged=58,remaining_cache_files=0,
    last_full_original_source_selection_rehashed_unchanged=True,source_modified=False,
    preparer_or_Git_or_project_imports_or_models_executed_by_audit=False,remote_or_adapter_or_whole_project_grant=False,
    audit_script_sha256=sha(CONTROL/'independent-stage-audit.py'))
with (CONTROL/'independent-stage-audit.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
print(json.dumps(report,sort_keys=True))
