"""Read-only successful metadata capture. Never starts Git or follows links."""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

OPS = Path('/root/fanzehui/myfuzz/operations')
BASE = OPS / 'p8-source-zipcpu-metadata-20261018-attempt2'
INPUTS = OPS / 'p8-source-metadata-inputs-20261018-attempt2'
SOURCE = Path('/root/fanzehui/myfuzz/project/third_party/soc-zipcpu')


def maps(root):
    assert not any(p.is_symlink() for p in (root, *root.parents))
    files, dirs = {}, {}
    for folder, children, names in os.walk(root, followlinks=False):
        for name in list(children):
            path = Path(folder) / name; info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                children.remove(name); names.append(name)
            else:
                assert stat.S_ISDIR(info.st_mode)
                dirs[path.relative_to(root).as_posix()] = dict(mode=stat.S_IMODE(info.st_mode))
        for name in names:
            path = Path(folder) / name; info = path.lstat(); relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                assert relative != '.git' and not relative.startswith('.git/')
                raw = os.fsencode(os.readlink(path))
                files[relative] = dict(kind='symlink', bytes=len(raw), mode=stat.S_IMODE(info.st_mode),
                                       linkbytes_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
            else:
                assert stat.S_ISREG(info.st_mode)
                with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                files[relative] = dict(kind='regular', bytes=info.st_size, mode=stat.S_IMODE(info.st_mode), sha256=digest)
    return files, dirs


source_files, source_dirs = maps(SOURCE)
stage_files, stage_dirs = maps(BASE / 'stage')
load = lambda name: json.loads((BASE / 'control' / name).read_bytes())
assert source_files == load('source-before-files.json') == load('source-after-files.json')
assert source_dirs == load('source-before-directories.json') == load('source-after-directories.json')
assert stage_files == load('stage-files.json') and stage_dirs == load('stage-directories.json')
parent = load('parent-terminal.json')
terminals = [json.loads(p.read_bytes()) for p in sorted((BASE / 'control').glob('child-*.terminal.json'))]
observation = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    parent_pid=parent['pid'], parent_returncode=parent['returncode'], parent_proc_present=Path('/proc', str(parent['pid'])).exists(),
    actual_children=len(terminals), child_returncodes=sorted({row['returncode'] for row in terminals}),
    actual_source_matches_beforeafter=True, actual_stage_matches_saved=True,
    original_source_symlinks=sum(row['kind'] == 'symlink' for row in source_files.values()),
    stage_symlinks=sum(row['kind'] == 'symlink' for row in stage_files.values()),
    remote_read_only=True, link_targets_followed=False, git_or_models_reexecuted=False)
members = []
control = BASE / 'control'
for p in [control, *sorted(control.rglob('*'))]:
    members.append((p.relative_to(BASE).as_posix(), p))
for name in ('materialize_snapshot.py', 'selected-launch.json', 'parent.stdout', 'parent.stderr'):
    members.append(('inputs/' + name, INPUTS / name))
pack_bytes = 0
for label, root in (('clean', BASE / 'clean.git'), ('stage-git', BASE / 'stage/.git')):
    for p in sorted(root.rglob('*')):
        info = p.lstat(); assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        if p.is_dir(): continue
        name = p.relative_to(root).as_posix()
        if (name in ('HEAD', 'config', 'shallow', 'packed-refs', 'index')
                or name.startswith('refs/') or name.startswith('objects/pack/') and p.suffix in ('.pack', '.idx')):
            if p.suffix in ('.pack', '.idx'): pack_bytes += info.st_size
            members.append(('metadata/' + label + '/' + name, p))
assert pack_bytes <= 64 * 1024 * 1024
synthetic = {'observed/source-files.json': source_files, 'observed/source-directories.json': source_dirs,
             'observed/stage-files.json': stage_files, 'observed/stage-directories.json': stage_dirs,
             'readonly-live-review.json': observation}
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as tar:
    for name, path in members:
        info = path.lstat(); assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        assert not any(p.is_symlink() for p in (path, *path.parents))
        entry = tar.gettarinfo(str(path), arcname=name)
        if entry.isfile():
            with path.open('rb') as stream: tar.addfile(entry, stream)
        else: tar.addfile(entry)
    for name, value in synthetic.items():
        raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
        entry = tarfile.TarInfo(name); entry.size = len(raw); tar.addfile(entry, io.BytesIO(raw))
