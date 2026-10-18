"""Stream actual terminal evidence only; no project imports or process launch."""
import datetime
import io
import json
from pathlib import Path
import stat
import sys
import tarfile

OPS = Path('/root/fanzehui/myfuzz/operations')
BASE = OPS / 'p6-native-completion-20261018-attempt2'
INPUTS = OPS / 'p6-native-completion-inputs-20261018-attempt2'
ENV = OPS / 'environment-20261018-attempt3'
INVENTORY = OPS / 'p7-i5-independent-6b40ef4-20261018-attempt1/control/tool-inventory.json'
members = []


def add_tree(root, prefix):
    assert root.is_relative_to('/root/fanzehui')
    assert not any(p.is_symlink() for p in (root, *root.parents))
    for path in [root, *sorted(root.rglob('*'))]:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
        if path.is_file(): assert info.st_nlink == 1
        name = prefix + ('/' + path.relative_to(root).as_posix() if path != root else '')
        members.append((name, path))


for prefix in ('gate-control', 'control', 'run-directed'):
    add_tree(BASE / prefix, prefix)
for name in ('gate-parent.stdout', 'gate-parent.stderr'):
    members.append((name, BASE / name))
for name in ('run_native_gate.py', 'launch-native-gate.sh', 'selection.json', 'local-current-src-scripts.json',
             'overlay-map.json', 'overlay-paths.json', 'copy-parent-terminal.json'):
    members.append(('inputs/' + name, INPUTS / name))
for name, path in (('inventory.json', INVENTORY), ('tool-freeze.json', ENV / 'tool-freeze.json'),
                   ('environment.sh', ENV / 'environment.sh')):
    members.append(('tool-inputs/' + name, path))
# Retain only small JSON build receipts, never compiled outputs or binaries.
cache = BASE / 'cache-native'
cache_files = []
for path in sorted(cache.rglob('*')):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
    if path.is_file():
        assert info.st_nlink == 1
        relative = path.relative_to(cache).as_posix()
        cache_files.append(dict(path=relative, bytes=info.st_size))
        if path.suffix == '.json' and info.st_size <= 1024 * 1024:
            members.append(('build-receipts/' + relative, path))
observation = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    operation=str(BASE), remote_read_only=True, model_execution_by_collection=False,
    specified_pid_presence={str(pid): Path('/proc', str(pid)).exists() for pid in (3454454, 3469032)},
    cache_inventory=cache_files, compiled_cache_bytes_archived=False)
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as tar:
    seen = set()
    for name, path in members:
        assert name not in seen; seen.add(name)
        assert path.is_relative_to('/root/fanzehui') and not any(p.is_symlink() for p in (path, *path.parents))
        info = tar.gettarinfo(str(path), arcname=name)
        if info.isfile():
            with path.open('rb') as stream: tar.addfile(info, stream)
        else: tar.addfile(info)
    data = json.dumps(observation, sort_keys=True, indent=2).encode() + b'\n'
    info = tarfile.TarInfo('readonly-terminal-observation.json'); info.size = len(data)
    tar.addfile(info, io.BytesIO(data))
