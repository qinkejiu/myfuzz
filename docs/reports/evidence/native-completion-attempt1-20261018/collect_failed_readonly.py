"""Read-only terminal collection; no project imports, tools or process launch."""
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
BASE = OPS / 'p6-native-completion-20261018-attempt1'
INPUTS = OPS / 'p6-native-completion-inputs-20261018-attempt1'


def inventory(root):
    assert not any(p.is_symlink() for p in (root, *root.parents))
    files, dirs = {}, {}
    for folder, children, names in os.walk(root, followlinks=False):
        for name in children:
            p = Path(folder) / name; info = p.lstat()
            assert stat.S_ISDIR(info.st_mode)
            dirs[p.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            p = Path(folder) / name; info = p.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            with p.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            files[p.relative_to(root).as_posix()] = dict(bytes=info.st_size, sha256=digest,
                                                       mode=stat.S_IMODE(info.st_mode))
    return dict(files=files, directories=dirs, exists=root.exists())


report = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    operation=str(BASE), cache=inventory(BASE / 'cache-native'),
    run_directed=inventory(BASE / 'run-directed'),
    specified_pid_presence={str(pid): Path('/proc', str(pid)).exists() for pid in (3107064, 3130216)},
    remote_read_only=True, native_execution_by_collection=False)
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as tar:
    for prefix in ('gate-control', 'run-directed'):
        root = BASE / prefix
        for p in [root, *sorted(root.rglob('*'))]:
            info = p.lstat(); assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
            member = tar.gettarinfo(str(p), arcname=p.relative_to(BASE).as_posix())
            if p.is_file():
                with p.open('rb') as stream: tar.addfile(member, stream)
            else: tar.addfile(member)
    for p, name in [(BASE / ('gate-parent.' + s), 'gate-parent.' + s) for s in ('stdout', 'stderr')] + [
            (INPUTS / 'run_native_gate.py', 'inputs/run_native_gate.py'),
            (INPUTS / 'launch-native-gate.sh', 'inputs/launch-native-gate.sh')]:
        info = p.lstat(); assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        member = tar.gettarinfo(str(p), arcname=name)
        with p.open('rb') as stream: tar.addfile(member, stream)
    data = json.dumps(report, sort_keys=True, indent=2).encode() + b'\n'
    member = tarfile.TarInfo('readonly-terminal-observation.json'); member.size = len(data)
    tar.addfile(member, io.BytesIO(data))
