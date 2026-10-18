"""Independent source-selection read only; no preparer/project imports or Git."""
from pathlib import Path, PurePosixPath
import datetime
import hashlib
import json
import os
import stat

CONTROL = Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2')
ROOT = Path('/home/qinkejiu/myfuzz')
PIN = '11e1e298379b54973836de4ec57d4383ab84f9302081e688db0edf1cb7a908f8'
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
raw = (CONTROL / 'selection.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == PIN
document = json.loads(raw)
old = json.loads(Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt1/selection.json').read_bytes())
assert document['source'] == str(ROOT) and document['closure_reviewed'] is False
assert document['schema_version'] == 'p7_i5_snapshot_selection.v2'
assert set(document) == {'closure_reviewed','destination','directories','excludes','files','generated_directories','generated_files','git_head_files','includes','schema_version','source'}
assert document['destination'] == '/home/qinkejiu/myfuzz-p8-root-input-20261018-attempt2'
assert document['includes'] == old['includes']

def cache(name):
    path = PurePosixPath(name)
    return '__pycache__' in path.parts or path.suffix in ('.pyc', '.pyo')

def selected(name, prefixes):
    return any(name == prefix or name.startswith(prefix + '/') for prefix in prefixes)

removed = set(old['files']) - set(document['files'])
assert len(removed) == 518 and all(cache(name) for name in removed)
assert not set(document['files']) - set(old['files'])
assert all(document['files'][name] == old['files'][name] for name in document['files'])
files, directories = {}, {}
for prefix in document['includes']:
    path = ROOT / prefix
    assert not any(parent.is_symlink() for parent in (path, *path.parents))
    if path.is_file():
        items = [path]
    else:
        items = []
        for folder, children, names in os.walk(path, followlinks=False):
            children[:] = [name for name in children if not selected((Path(folder)/name).relative_to(ROOT).as_posix(), document['excludes'])]
            for child in [Path(folder), *[Path(folder)/name for name in children]]:
                info = child.lstat()
                assert stat.S_ISDIR(info.st_mode)
                directories[child.relative_to(ROOT).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
            items.extend(Path(folder)/name for name in names if not selected((Path(folder)/name).relative_to(ROOT).as_posix(), document['excludes']))
    for path in items:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        files[path.relative_to(ROOT).as_posix()] = {'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'sha256': digest}
assert files == document['files'] and directories == document['directories']
assert len(files) == 10346 and sum(row['bytes'] for row in files.values()) == 493088962 and len(directories) == 522
assert not any(cache(name) for name in files)
head = (ROOT / '.git/HEAD').read_text().strip()
assert head.startswith('ref: ')
reference = head.removeprefix('ref: ')
commit = (ROOT / '.git' / reference).read_text().strip()
assert commit == '269717b7e9cc7c92da5e427ac950bc82446b3ac6'
assert document['git_head_files'] == {'.git': head}
assert '.gitmodules' in files and '.git/' + reference in files
assert '.git/objects' in directories and '.git/refs' in directories
assert not any(name == '.git/modules' or name.startswith('.git/modules/') for name in [*files,*directories])
counts = {}
for prefix in ('src', 'scripts', 'configs'):
    expected = set()
    for folder, children, names in os.walk(ROOT / prefix, followlinks=False):
        children[:] = [name for name in children if name != '__pycache__']
        for name in names:
            path = Path(folder) / name
            relative = path.relative_to(ROOT).as_posix()
            if not cache(relative):
                assert path.is_file() and not path.is_symlink()
                expected.add(relative)
    actual = {name for name in files if name.startswith(prefix + '/')}
    assert actual == expected
    counts[prefix] = len(actual)
frontend = {name: row for name,row in files.items() if name.startswith('src/myfuzz/frontend/')}
prior = json.loads((ROOT / '.superpowers/sdd/native-completion-20261018/attempt2-control/local-current-src-scripts.json').read_bytes())
assert frontend == {name:row for name,row in prior.items() if name.startswith('src/myfuzz/frontend/')} and len(frontend) == 387
elf_count = 0
for name in frontend:
    with (ROOT / name).open('rb') as stream:
        elf_count += stream.read(4) == b'\x7fELF'
assert elf_count == 58
empty = hashlib.sha256(b'').hexdigest()
assert document['generated_files'] == {'.superpowers/sdd/stage2-heavy-worker.lock': {'bytes':0,'mode':0o600,'sha256':empty}}
assert document['generated_directories'] == {'.superpowers':{'mode':0o755},'.superpowers/sdd':{'mode':0o755}}
required = ['src/myfuzz/integration/compiled_f4.py','src/myfuzz/integration/compiled_execution_files.py','src/myfuzz/integration/compiled_storage_producer.py','src/myfuzz/integration/generated_storage_consumer.py','src/myfuzz/local_harness/compiled_artifact_admission.py','src/myfuzz/local_harness/build.py','src/myfuzz/scenario/memory.py','src/myfuzz/scenario/memory_service.py','src/myfuzz/scenario/native_instruction_source_binding.py','scripts/run_compiled_dataflow.py']
assert all(name in files for name in required)
result = dict(schema_version='independent_regular_root_selection_review.v1',
    scope='regular_root_selection_only_no_adapter_or_entire_P8_or_P7_grant',
    status='selected_source_bytes_and_modes_verified',
    review_started_at=started, review_ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    timestamp_scope='this_actual_repeat_readonly_review_not_a_backdated_timestamp_of_the_earlier_inline_review',
    manifest_path=str(CONTROL/'selection.json'),manifest_sha256=PIN,source=str(ROOT),source_HEAD=commit,
    files=len(files),directories=len(directories),bytes=sum(row['bytes'] for row in files.values()),
    all_selected_source_files_read_and_hashed=True,all_selected_directory_modes_verified=True,
    removed_cache_leaves=518,removed_cache_bytes=sum(old['files'][name]['bytes'] for name in removed),
    remaining_cache_leaves=0,noncache_prefix_counts=counts,
    complete_src_scripts_noncache_files=counts['src']+counts['scripts'],
    frontend_files_unchanged_from_prior_frozen_bytes_and_modes=387,frontend_ELF_files_unchanged=elf_count,
    root_git_ref_and_objects_refs_dirs_verified=True,root_gitmodules_declaration_present=True,
    excluded_git_modules_store_entries=0,generated_empty_private_lock_and_parent_modes_verified=True,
    required_compiled_host_source_examples_present=required,closure_reviewed_manifest_flag=False,
    preparer_or_Git_or_project_imports_or_models_executed=False,source_modified=False,
    stage_examined=False,adapter_or_entire_P8_or_P7_pass=False,
    review_script=str(CONTROL/'independent-selection-review.py'),
    review_script_sha256=hashlib.sha256((CONTROL/'independent-selection-review.py').read_bytes()).hexdigest())
with (CONTROL / 'independent-selection-review.json').open('x') as stream:
    json.dump(result,stream,sort_keys=True,indent=2)
    stream.write('\n')
print(json.dumps(result,sort_keys=True))
