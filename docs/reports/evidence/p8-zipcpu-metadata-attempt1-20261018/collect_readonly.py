"""Read only failed ZipCPU metadata controls and one known symlink itself."""
import datetime
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile

OPS = Path('/root/fanzehui/myfuzz/operations')
BASE = OPS / 'p8-source-zipcpu-metadata-20261018-attempt1'
INPUTS = OPS / 'p8-source-metadata-inputs-20261018-attempt1'
LINK = Path('/root/fanzehui/myfuzz/project/third_party/soc-zipcpu/sim/verilator/zipelf.h')
for root in (BASE, INPUTS, LINK.parent):
    assert not any(p.is_symlink() for p in (root, *root.parents))
info = LINK.lstat()
observation = dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    parent_pid=3940481, parent_proc_present=Path('/proc/3940481').exists(),
    link_path=str(LINK), link_is_symlink=stat.S_ISLNK(info.st_mode),
    link_mode=stat.S_IMODE(info.st_mode), link_lstat_bytes=info.st_size,
    link_text=os.readlink(LINK), link_target_followed=False,
    remote_read_only=True, git_or_models_or_network_fallback_executed=False)
with tarfile.open(fileobj=sys.stdout.buffer, mode='w|gz') as tar:
    control = BASE / 'control'
    for path in [control, *sorted(control.rglob('*'))]:
        st = path.lstat()
        assert stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
        name = path.relative_to(BASE).as_posix()
        member = tar.gettarinfo(str(path), arcname=name)
        if member.isfile():
            assert st.st_nlink == 1
            with path.open('rb') as stream: tar.addfile(member, stream)
        else: tar.addfile(member)
    for name in ('materialize_snapshot.py', 'selected-launch.json', 'parent.stdout', 'parent.stderr'):
        path = INPUTS / name; st = path.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1
        member = tar.gettarinfo(str(path), arcname='inputs/' + name)
        with path.open('rb') as stream: tar.addfile(member, stream)
    data = json.dumps(observation, sort_keys=True, indent=2).encode() + b'\n'
    member = tarfile.TarInfo('readonly-observation.json'); member.size = len(data)
    tar.addfile(member, io.BytesIO(data))
