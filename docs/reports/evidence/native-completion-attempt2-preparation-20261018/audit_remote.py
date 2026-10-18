"""Read-only remote preparation audit. No project imports or child tools."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

ALLOWED = Path('/root/fanzehui')
OPS = ALLOWED / 'myfuzz/operations'
BASE = OPS / 'p6-native-completion-20261018-attempt2'
INPUTS = OPS / 'p6-native-completion-inputs-20261018-attempt2'
SOURCE = OPS / 'p6-native-completion-20261018-attempt1/project'
PROJECT, CONTROL = BASE / 'project', BASE / 'control'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def maps(root):
    assert root.is_relative_to(ALLOWED)
    assert not any(p.is_symlink() for p in (root, *root.parents))
    files, directories = {}, {}
    for folder, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            p = Path(folder) / name
            st = p.lstat()
            assert stat.S_ISDIR(st.st_mode), str(p)
            directories[p.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(st.st_mode)}
        for name in names:
            p = Path(folder) / name
            st = p.lstat()
            assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1, str(p)
            files[p.relative_to(root).as_posix()] = dict(bytes=st.st_size,
                mode=stat.S_IMODE(st.st_mode), sha256=sha(p))
    return dict(sorted(files.items())), dict(sorted(directories.items()))


baseline = load(INPUTS / 'baseline-files.json')
baseline_dirs = load(INPUTS / 'baseline-directories.json')
assert sha(INPUTS / 'baseline-files.json') == '94de100ab2ab50f3674f179378c9138d73cec873c68ae401bc43f9cb63e76cd1'
assert sha(INPUTS / 'baseline-directories.json') == '861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36'
assert sha(INPUTS / 'overlay-map.json') == 'e2a604e5614213d5a4be40fd170ff952d7db6f78304e2f64370493f204318a22'
assert sha(INPUTS / 'overlay-paths.json') == '4334de1c667b6ceadecff1d95d73b155c23e0a7c3020e4e0a6828845e9b4699a'
overlay = load(INPUTS / 'overlay-map.json')
assert maps(INPUTS / 'overlay') == (overlay['files'], overlay['directories'])
assert sorted(overlay['files']) == load(INPUTS / 'overlay-paths.json') == ['src/myfuzz/local_harness/plan.py']
expected_files = {**baseline, **overlay['files']}
expected_dirs = {**baseline_dirs, **overlay['directories']}
actual_files, actual_dirs = maps(PROJECT)
assert actual_files == expected_files == load(CONTROL / 'final-file-freeze.json')
assert actual_dirs == expected_dirs == load(CONTROL / 'final-directories.json')
assert maps(SOURCE) == (baseline, baseline_dirs)
assert baseline == load(CONTROL / 'source-before-files.json') == load(CONTROL / 'source-after-files.json')
assert baseline_dirs == load(CONTROL / 'source-before-directories.json') == load(CONTROL / 'source-after-directories.json')
current = load(INPUTS / 'local-current-src-scripts.json')
assert len(current) == 1111
src_scripts = {p: r for p, r in actual_files.items() if p.startswith(('src/', 'scripts/'))}
assert src_scripts == current
assert load(CONTROL / 'full-scripts.json') == {p: r for p, r in current.items() if p.startswith('scripts/')}
assert not {p for p in baseline if p.startswith(('src/', 'scripts/'))} - set(current)
metadata = {}
for node in ast.parse((PROJECT / 'src/myfuzz/scenario/host_identity.py').read_bytes()).body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in ('HOST_SOURCE_PATHS', 'HARNESS_HOST_SOURCE_PATHS'):
                value = node.value
                metadata[target.id] = (metadata['HOST_SOURCE_PATHS'] + ast.literal_eval(value.right)
                    if isinstance(value, ast.BinOp) else ast.literal_eval(value))
assert len(metadata['HOST_SOURCE_PATHS']) == 34
hosts = metadata['HARNESS_HOST_SOURCE_PATHS']
assert len(hosts) == len(set(hosts)) == 69
assert load(CONTROL / 'explicit-host-files.json') == {p: actual_files[p] for p in hosts}
selection = load(INPUTS / 'selection.json')
assert selection['source_revision'] == '68f81b6adfb72d201a47804b26ca57a78a3d1fba'
assert selection['host_files'] == {p: actual_files[p] for p in hosts}
parent = load(INPUTS / 'copy-parent-terminal.json')
start = load(INPUTS / 'copy-parent-start.json')
receipt = load(CONTROL / 'copy-receipt.json')
upload = load(INPUTS / 'upload-receipt.json')
assert parent['returncode'] == 0 and parent['native_execution'] is False
assert (parent['pid'], parent['child_pid']) == (3308461, 3308542)
assert (start['pid'], start['child_pid']) == (parent['pid'], parent['child_pid'])
assert receipt['source_unchanged'] is True and receipt['native_run'] is False
assert receipt['status'] == 'prepared_pending_independent_review_no_execution'
assert upload['native_execution'] is False
assert upload['archive_sha256'] == '3760aad022d262732c0b7782d25cce59d3b1a59a3b5c3aae2f49729d6c6b87a8'
for name in ('copy.stdout', 'copy.stderr'):
    path = INPUTS / name
    assert parent[name] == dict(bytes=path.stat().st_size, sha256=sha(path))
copy_output = load(INPUTS / 'copy.stdout')
assert copy_output == receipt
assert receipt['freeze_sha256'] == sha(CONTROL / 'final-file-freeze.json')
# Exact full-tree equality excludes every new output/cache file or directory;
# frontend build artifacts already in the pinned baseline are preserved.
new_files = set(actual_files) - set(baseline)
new_dirs = set(actual_dirs) - set(baseline_dirs)
assert new_files <= set(overlay['files']) and new_dirs <= set(overlay['directories'])
assert not any(part in ('__pycache__', '.pytest_cache', 'node_modules') for p in new_files | new_dirs for part in Path(p).parts)
frontend = [p for p in actual_files if p.startswith('src/myfuzz/frontend/')]
assert all(actual_files[p] == baseline[p] for p in frontend)
git_files = [p for p in baseline if '.git' in Path(p).parts]
assert all(actual_files[p] == baseline[p] for p in git_files)
key_names = ('final-file-freeze.json', 'final-directories.json', 'copy-receipt.json',
             'explicit-host-files.json', 'full-scripts.json', 'source-before-files.json',
             'source-after-files.json', 'source-before-directories.json', 'source-after-directories.json')
report = dict(status='independent_readonly_preparation_review_passed',
    source=str(SOURCE), project=str(PROJECT), source_revision=selection['source_revision'],
    files=len(actual_files), directories=len(actual_dirs), src_scripts_files=len(current),
    explicit_host_paths=len(hosts), overlay_files=len(overlay['files']),
    baseline_old_src_scripts_extra=0, original_source_unchanged=True,
    no_unmanifested_output_or_cache=True, frontend_files_unchanged=len(frontend),
    git_metadata_files_unchanged=len(git_files), new_files=sorted(new_files), new_directories=sorted(new_dirs),
    directory_canonical_sha256=canonical_sha(actual_dirs),
    control_pins={name: dict(bytes=(CONTROL/name).stat().st_size, sha256=sha(CONTROL/name)) for name in key_names},
    parent=parent, upload=upload,
    audit_native_execution=False, project_imports=False, tests_or_gate_run=False)
print(json.dumps(report, sort_keys=True, indent=2))
