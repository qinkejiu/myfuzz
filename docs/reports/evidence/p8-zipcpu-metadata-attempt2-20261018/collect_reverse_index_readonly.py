"""Read only the two explicitly missing reverse-index files; no Git execution."""
import datetime
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tarfile

BASE = Path('/root/fanzehui/myfuzz/operations/p8-source-zipcpu-metadata-20261018-attempt2')
NAME = 'objects/pack/pack-104b395e65458215c1b98692a068c689164cf1c5.rev'
PIN = 'b738d526e48cefa8f2eb559c7b02c7eb171d7f70cbb754ae312bf4893206a2e9'
rows, payloads = [], []
for label, store in (('clean', BASE / 'clean.git'), ('stage-git', BASE / 'stage/.git')):
    path = store / NAME
    assert not any(p.is_symlink() for p in (path, *path.parents))
    info = path.lstat(); assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    raw = path.read_bytes()
    assert len(raw) == 1628 and stat.S_IMODE(info.st_mode) == 0o444 and hashlib.sha256(raw).hexdigest() == PIN
    rows.append(dict(store=label, remote_path=str(path), relative_path=NAME,
                     bytes=len(raw), mode=stat.S_IMODE(info.st_mode), sha256=PIN))
    payloads.append(('metadata/' + label + '/' + NAME, raw, stat.S_IMODE(info.st_mode)))
observation = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    remote_read_only=True, original_archive_member=False, separate_later_capture=True,
    git_or_models_reexecuted=False, files=rows)
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as tar:
    for name, raw, mode in payloads:
        info = tarfile.TarInfo(name); info.size = len(raw); info.mode = mode
        tar.addfile(info, io.BytesIO(raw))
    raw = json.dumps(observation, sort_keys=True, indent=2).encode() + b'\n'
    info = tarfile.TarInfo('readonly-reverse-index-observation.json'); info.size = len(raw)
    tar.addfile(info, io.BytesIO(raw))
